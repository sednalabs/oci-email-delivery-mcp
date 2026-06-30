use crate::{
    config::OciEmailConfig,
    error::OciEmailError,
    redact::{email_domain, is_host_token, redact_sensitive_text, short_hash},
    response::{
        Evidence, LedgerRowSummary, LedgerWindowFilters, LedgerWindowReport, LedgerWindowRequest,
        LedgerWindowTotals, ReadinessFinding, DEFAULT_LEDGER_LIMIT, HARD_LEDGER_LIMIT,
    },
};
use serde_json::Value;
use std::{
    collections::BTreeSet,
    fs::File,
    io::{BufRead, BufReader},
};

pub fn ledger_window(
    config: &OciEmailConfig,
    request: &LedgerWindowRequest,
) -> Result<LedgerWindowReport, OciEmailError> {
    let start_key = validate_time(&request.start_time, "start_time")?;
    let end_key = validate_time(&request.end_time, "end_time")?;
    if start_key >= end_key {
        return Err(OciEmailError::InvalidInput(
            "start_time must be before end_time".to_string(),
        ));
    }
    if let Some(domain) = request.sender_domain.as_deref() {
        validate_domain(domain, "sender_domain")?;
    }
    let Some(path) = &config.ledger_path else {
        return Err(OciEmailError::Config(
            "OCI_MCP_LEDGER_PATH is not configured; local send-ledger reads are disabled"
                .to_string(),
        ));
    };
    let file = File::open(path).map_err(|err| {
        OciEmailError::Config(format!(
            "failed to open configured send ledger: {}",
            redact_sensitive_text(&err.to_string())
        ))
    })?;
    let limit = cap_limit(
        request.limit.unwrap_or(DEFAULT_LEDGER_LIMIT),
        HARD_LEDGER_LIMIT,
    );
    let campaign_filter = request.campaign_id.as_deref();
    let batch_filter = request.batch_id.as_deref();
    let sender_filter = request
        .sender_domain
        .as_deref()
        .map(|value| value.to_ascii_lowercase());

    let mut scanned_rows = 0usize;
    let mut invalid_rows = 0usize;
    let mut matched_rows = 0usize;
    let mut missing_trace_key_count = 0usize;
    let mut missing_recipient_key_count = 0usize;
    let mut rows = Vec::new();
    let mut sender_domains = BTreeSet::new();
    let mut campaigns = BTreeSet::new();
    let mut batches = BTreeSet::new();

    for line in BufReader::new(file).lines() {
        let line = line.map_err(|err| {
            OciEmailError::Config(format!(
                "failed to read configured send ledger: {}",
                redact_sensitive_text(&err.to_string())
            ))
        })?;
        if line.trim().is_empty() {
            continue;
        }
        scanned_rows += 1;
        let Ok(value) = serde_json::from_str::<Value>(&line) else {
            invalid_rows += 1;
            continue;
        };
        if !value.is_object() {
            invalid_rows += 1;
            continue;
        };
        let Some(row_time_key) = ledger_time_sort_key(&value) else {
            invalid_rows += 1;
            continue;
        };
        if row_time_key < start_key || row_time_key >= end_key {
            continue;
        }
        if !matches_optional_identifier(
            campaign_filter,
            string_any(&value, &["campaign_id", "campaignId"]),
            string_any(
                &value,
                &[
                    "campaign_hash",
                    "campaignHash",
                    "campaign_id_hash",
                    "campaignIdHash",
                ],
            ),
        ) {
            continue;
        }
        if !matches_optional_identifier(
            batch_filter,
            string_any(&value, &["batch_id", "batchId"]),
            string_any(
                &value,
                &["batch_hash", "batchHash", "batch_id_hash", "batchIdHash"],
            ),
        ) {
            continue;
        }
        let Some(row) = ledger_row_summary(&value) else {
            invalid_rows += 1;
            continue;
        };
        if let Some(filter) = sender_filter.as_deref() {
            if row.sender_domain.as_deref() != Some(filter) {
                continue;
            }
        }

        matched_rows += 1;
        if row.message_id_hash.is_none() && row.correlation_id_hash.is_none() {
            missing_trace_key_count += 1;
        }
        if row.recipient_address_hash.is_none() && row.recipient_id_hash.is_none() {
            missing_recipient_key_count += 1;
        }
        if let Some(domain) = &row.sender_domain {
            sender_domains.insert(domain.clone());
        }
        if let Some(value) = &row.campaign_hash {
            campaigns.insert(value.clone());
        }
        if let Some(value) = &row.batch_hash {
            batches.insert(value.clone());
        }
        if rows.len() < limit as usize {
            rows.push(row);
        }
    }

    let rows_capped = matched_rows > rows.len();
    let mut findings = Vec::new();
    if matched_rows == 0 {
        findings.push(finding(
            "warning",
            "ledger_no_rows_matched",
            "No local send-ledger rows matched this window and filter set.",
        ));
    }
    if invalid_rows > 0 {
        findings.push(finding(
            "warning",
            "ledger_invalid_rows",
            "One or more local send-ledger rows were not valid JSON objects or lacked a valid UTC submitted_at/timestamp value.",
        ));
    }
    if rows_capped {
        findings.push(finding(
            "warning",
            "ledger_results_capped",
            "Local send-ledger rows exceeded the requested limit; narrow the window before treating the result set as complete.",
        ));
    }
    if missing_trace_key_count > 0 {
        findings.push(finding(
            "warning",
            "ledger_missing_trace_keys",
            "One or more local send-ledger rows are missing both message and correlation identifiers.",
        ));
    }
    if missing_recipient_key_count > 0 {
        findings.push(finding(
            "warning",
            "ledger_missing_recipient_keys",
            "One or more local send-ledger rows are missing both recipient address hash and recipient id hash.",
        ));
    }

    let status = if findings.is_empty() {
        "ok"
    } else {
        "degraded"
    };
    Ok(LedgerWindowReport {
        status: status.to_string(),
        start_time: request.start_time.clone(),
        end_time: request.end_time.clone(),
        filters: LedgerWindowFilters {
            sender_domain: sender_filter,
            campaign_hash: campaign_filter.map(redacted_hash),
            batch_hash: batch_filter.map(redacted_hash),
        },
        limit,
        totals: LedgerWindowTotals {
            scanned_rows,
            matched_rows,
            returned_rows: rows.len(),
            invalid_rows,
            rows_capped,
            missing_trace_key_count,
            missing_recipient_key_count,
        },
        sender_domains: sender_domains.into_iter().collect(),
        campaigns: campaigns.into_iter().collect(),
        batches: batches.into_iter().collect(),
        rows,
        findings,
        evidence: vec![Evidence::new(
            "local_jsonl_send_ledger",
            "read configured send ledger window",
            rows_capped,
        )],
        raw_payload_returned: false,
    })
}

fn ledger_row_summary(value: &Value) -> Option<LedgerRowSummary> {
    if !value.is_object() {
        return None;
    }
    let submitted_at = string_any(value, &["submitted_at", "submittedAt", "time", "timestamp"])
        .map(ToString::to_string);
    let sender_domain = string_any(value, &["sender_domain", "senderDomain"])
        .and_then(domain_from_address_or_domain)
        .or_else(|| {
            string_any(value, &["sender", "approved_sender", "approvedSender"])
                .and_then(email_domain)
        });
    let recipient_email = string_any(
        value,
        &[
            "recipient",
            "recipient_email",
            "recipientEmail",
            "email",
            "email_address",
            "emailAddress",
        ],
    );
    let recipient_domain = recipient_email
        .and_then(email_domain)
        .or_else(|| validated_domain_any(value, &["recipient_domain", "recipientDomain"]));
    let recipient_address_hash = redacted_hash_any(
        value,
        &[
            "recipient",
            "recipient_email",
            "recipientEmail",
            "email",
            "email_address",
            "emailAddress",
        ],
        &[
            "recipient_address_hash",
            "recipientAddressHash",
            "recipient_hash",
            "recipientHash",
        ],
    );
    let recipient_id_hash = redacted_hash_any(
        value,
        &["recipient_id", "recipientId"],
        &["recipient_id_hash", "recipientIdHash"],
    );
    Some(LedgerRowSummary {
        submitted_at,
        provider_hash: redacted_hash_any(value, &["provider"], &["provider_hash", "providerHash"]),
        campaign_hash: redacted_hash_any(
            value,
            &["campaign_id", "campaignId"],
            &[
                "campaign_hash",
                "campaignHash",
                "campaign_id_hash",
                "campaignIdHash",
            ],
        ),
        batch_hash: redacted_hash_any(
            value,
            &["batch_id", "batchId"],
            &["batch_hash", "batchHash", "batch_id_hash", "batchIdHash"],
        ),
        sender_domain,
        recipient_domain,
        recipient_address_hash,
        recipient_id_hash,
        message_id_hash: redacted_hash_any(
            value,
            &[
                "message_id",
                "messageId",
                "provider_message_id",
                "providerMessageId",
            ],
            &[
                "message_id_hash",
                "messageIdHash",
                "provider_message_id_hash",
                "providerMessageIdHash",
            ],
        ),
        correlation_id_hash: redacted_hash_any(
            value,
            &[
                "correlation_id",
                "correlationId",
                "header_value",
                "headerValue",
                "x_campaign_correlation_id",
                "xCampaignCorrelationId",
            ],
            &[
                "correlation_id_hash",
                "correlationIdHash",
                "header_value_hash",
                "headerValueHash",
                "x_campaign_correlation_id_hash",
                "xCampaignCorrelationIdHash",
            ],
        ),
        template_version_hash: redacted_hash_any(
            value,
            &["template_version", "templateVersion"],
            &["template_version_hash", "templateVersionHash"],
        ),
        subject_hash: redacted_hash_any(value, &["subject"], &["subject_hash", "subjectHash"]),
        raw_recipient_returned: false,
    })
}

fn matches_optional_identifier(
    filter: Option<&str>,
    raw_value: Option<&str>,
    hash_value: Option<&str>,
) -> bool {
    match filter {
        Some(filter) => {
            raw_value == Some(filter)
                || hash_value
                    .map(redacted_hash)
                    .is_some_and(|value| value == redacted_hash(filter))
        }
        None => true,
    }
}

fn string_any<'a>(value: &'a Value, keys: &[&str]) -> Option<&'a str> {
    keys.iter()
        .find_map(|key| value.get(*key).and_then(Value::as_str))
}

fn domain_from_address_or_domain(value: &str) -> Option<String> {
    if value.contains('@') {
        return email_domain(value);
    }
    is_host_token(value).then(|| value.to_ascii_lowercase())
}

fn validated_domain_any(value: &Value, keys: &[&str]) -> Option<String> {
    string_any(value, keys).and_then(domain_from_address_or_domain)
}

fn redacted_hash_any(value: &Value, raw_keys: &[&str], hash_keys: &[&str]) -> Option<String> {
    string_any(value, hash_keys)
        .map(redacted_hash)
        .or_else(|| string_any(value, raw_keys).map(short_hash))
}

fn redacted_hash(value: &str) -> String {
    let trimmed = value.trim();
    if is_short_hash(trimmed) {
        trimmed.to_ascii_lowercase()
    } else {
        short_hash(trimmed)
    }
}

fn is_short_hash(value: &str) -> bool {
    value.len() == 20 && value.chars().all(|ch| ch.is_ascii_hexdigit())
}

fn validate_domain(value: &str, label: &str) -> Result<(), OciEmailError> {
    if is_host_token(value) {
        Ok(())
    } else {
        Err(labelled_invalid_input_error(
            label,
            " must be a valid domain token",
        ))
    }
}

fn validate_time(value: &str, label: &str) -> Result<String, OciEmailError> {
    utc_timestamp_key(value).ok_or_else(|| {
        labelled_invalid_input_error(label, " must be an RFC3339 UTC timestamp ending in Z")
    })
}

fn labelled_invalid_input_error(label: &str, suffix: &str) -> OciEmailError {
    OciEmailError::InvalidInput([label, suffix].concat())
}

fn cap_limit(value: u32, hard_limit: u32) -> u32 {
    value.clamp(1, hard_limit)
}

fn ledger_time_sort_key(value: &Value) -> Option<String> {
    string_any(value, &["submitted_at", "submittedAt", "time", "timestamp"])
        .and_then(utc_timestamp_key)
}

fn utc_timestamp_key(value: &str) -> Option<String> {
    let trimmed = value.trim();
    let core = trimmed.strip_suffix('Z')?;
    let bytes = core.as_bytes();
    if bytes.len() < 19 {
        return None;
    }
    if bytes.get(4) != Some(&b'-')
        || bytes.get(7) != Some(&b'-')
        || bytes.get(10) != Some(&b'T')
        || bytes.get(13) != Some(&b':')
        || bytes.get(16) != Some(&b':')
    {
        return None;
    }
    for range in [0..4, 5..7, 8..10, 11..13, 14..16, 17..19] {
        if !bytes[range].iter().all(u8::is_ascii_digit) {
            return None;
        }
    }
    let month = parse_two_digits(bytes, 5)?;
    let day = parse_two_digits(bytes, 8)?;
    let hour = parse_two_digits(bytes, 11)?;
    let minute = parse_two_digits(bytes, 14)?;
    let second = parse_two_digits(bytes, 17)?;
    if !(1..=12).contains(&month)
        || day == 0
        || day > days_in_month(bytes, month)
        || hour > 23
        || minute > 59
        || second > 59
    {
        return None;
    }
    let fraction = match bytes.get(19) {
        None => "000000000".to_string(),
        Some(b'.') => {
            let digits = &core[20..];
            if digits.is_empty()
                || digits.len() > 9
                || !digits.as_bytes().iter().all(u8::is_ascii_digit)
            {
                return None;
            }
            format!("{digits:0<9}")
        }
        _ => return None,
    };
    Some(format!("{}.{fraction}Z", &core[..19]))
}

fn parse_two_digits(bytes: &[u8], start: usize) -> Option<u32> {
    let tens = *bytes.get(start)?;
    let ones = *bytes.get(start + 1)?;
    if !tens.is_ascii_digit() || !ones.is_ascii_digit() {
        return None;
    }
    Some(((tens - b'0') as u32 * 10) + (ones - b'0') as u32)
}

fn days_in_month(bytes: &[u8], month: u32) -> u32 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if is_leap_year(parse_year(bytes)) => 29,
        2 => 28,
        _ => 0,
    }
}

fn parse_year(bytes: &[u8]) -> u32 {
    bytes[..4]
        .iter()
        .fold(0, |year, digit| (year * 10) + u32::from(digit - b'0'))
}

fn is_leap_year(year: u32) -> bool {
    year.is_multiple_of(4) && (!year.is_multiple_of(100) || year.is_multiple_of(400))
}

fn finding(severity: &str, code: &str, message: &str) -> ReadinessFinding {
    ReadinessFinding {
        severity: severity.to_string(),
        code: code.to_string(),
        message: message.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{fs, path::PathBuf};

    #[test]
    fn ledger_window_redacts_rows_and_hashes_private_ids() {
        let path = PathBuf::from("target/oci-email-ledger-tests/redacts.jsonl");
        fs::create_dir_all(path.parent().expect("ledger fixture parent"))
            .expect("create ledger fixture dir");
        fs::write(
            &path,
            concat!(
                "{\"submitted_at\":\"2026-06-30T00:10:00Z\",\"provider\":\"Private Provider\",\"campaign_id\":\"campaign-private\",\"batch_id\":\"batch-private\",\"sender\":\"news@example.com\",\"recipient\":\"person@example.net\",\"message_id\":\"message@example.com\",\"correlation_id\":\"corr-private\",\"template_version\":\"template-a\",\"subject\":\"Private Subject\"}\n",
                "{\"submitted_at\":\"2026-06-29T00:10:00Z\",\"recipient\":\"old@example.net\",\"message_id\":\"old@example.com\"}\n"
            ),
        )
        .expect("write ledger fixture");
        let config = config_with_ledger(path.clone());

        let report = ledger_window(
            &config,
            &LedgerWindowRequest {
                start_time: "2026-06-30T00:00:00Z".to_string(),
                end_time: "2026-06-30T01:00:00Z".to_string(),
                sender_domain: Some("example.com".to_string()),
                campaign_id: Some("campaign-private".to_string()),
                batch_id: Some("batch-private".to_string()),
                limit: Some(20),
            },
        )
        .expect("ledger report");
        let payload = serde_json::to_string(&report).expect("serialize report");

        assert_eq!(report.status, "ok");
        assert_eq!(report.totals.matched_rows, 1);
        assert_eq!(report.sender_domains, vec!["example.com".to_string()]);
        assert_eq!(
            report.rows[0].recipient_domain,
            Some("example.net".to_string())
        );
        assert!(report.rows[0].message_id_hash.is_some());
        assert!(report.rows[0].correlation_id_hash.is_some());
        assert!(report.rows[0].provider_hash.is_some());
        assert!(!report.raw_payload_returned);
        assert!(!report.rows[0].raw_recipient_returned);
        assert!(!payload.contains("Private Provider"));
        assert!(!payload.contains("person@example.net"));
        assert!(!payload.contains("message@example.com"));
        assert!(!payload.contains("campaign-private"));
        assert!(!payload.contains("batch-private"));
        assert!(!payload.contains("Private Subject"));

        let _ = fs::remove_file(&path);
    }

    #[test]
    fn ledger_window_degrades_on_invalid_rows_and_missing_trace_keys() {
        let path = PathBuf::from("target/oci-email-ledger-tests/degraded.jsonl");
        fs::create_dir_all(path.parent().expect("ledger fixture parent"))
            .expect("create ledger fixture dir");
        fs::write(
            &path,
            concat!(
                "{\"submitted_at\":\"2026-06-30T00:10:00Z\",\"recipient_id_hash\":\"known-recipient\"}\n",
                "not-json\n"
            ),
        )
        .expect("write ledger fixture");
        let config = config_with_ledger(path.clone());

        let report = ledger_window(
            &config,
            &LedgerWindowRequest {
                start_time: "2026-06-30T00:00:00Z".to_string(),
                end_time: "2026-06-30T01:00:00Z".to_string(),
                sender_domain: None,
                campaign_id: None,
                batch_id: None,
                limit: Some(20),
            },
        )
        .expect("ledger report");

        assert_eq!(report.status, "degraded");
        assert_eq!(report.totals.invalid_rows, 1);
        assert_eq!(report.totals.missing_trace_key_count, 1);
        assert!(report
            .findings
            .iter()
            .any(|finding| finding.code == "ledger_invalid_rows"));
        assert!(report
            .findings
            .iter()
            .any(|finding| finding.code == "ledger_missing_trace_keys"));

        let _ = fs::remove_file(&path);
    }

    #[test]
    fn ledger_window_preserves_prehashed_rows_for_event_correlation() {
        let path = PathBuf::from("target/oci-email-ledger-tests/prehashed.jsonl");
        let campaign_hash = short_hash("campaign-private");
        let batch_hash = short_hash("batch-private");
        let recipient_hash = short_hash("person@example.net");
        let message_hash = short_hash("message@example.com");
        let correlation_hash = short_hash("corr-private");
        fs::create_dir_all(path.parent().expect("ledger fixture parent"))
            .expect("create ledger fixture dir");
        fs::write(
            &path,
            format!(
                "{{\"submittedAt\":\"2026-06-30T00:10:00.123Z\",\"provider_hash\":\"{}\",\"campaign_hash\":\"{}\",\"batchHash\":\"{}\",\"sender_domain\":\"example.com\",\"recipient_domain\":\"example.net\",\"recipient_hash\":\"{}\",\"message_id_hash\":\"{}\",\"correlationIdHash\":\"{}\"}}\n",
                short_hash("oci"),
                campaign_hash,
                batch_hash,
                recipient_hash,
                message_hash,
                correlation_hash
            ),
        )
        .expect("write ledger fixture");
        let config = config_with_ledger(path.clone());

        let report = ledger_window(
            &config,
            &LedgerWindowRequest {
                start_time: "2026-06-30T00:10:00Z".to_string(),
                end_time: "2026-06-30T00:11:00Z".to_string(),
                sender_domain: Some("example.com".to_string()),
                campaign_id: Some("campaign-private".to_string()),
                batch_id: Some(batch_hash.clone()),
                limit: Some(20),
            },
        )
        .expect("ledger report");

        assert_eq!(report.status, "ok");
        assert_eq!(report.totals.matched_rows, 1);
        assert_eq!(report.totals.missing_trace_key_count, 0);
        assert_eq!(report.totals.missing_recipient_key_count, 0);
        assert_eq!(report.filters.campaign_hash, Some(campaign_hash));
        assert_eq!(report.filters.batch_hash, Some(batch_hash));
        assert_eq!(report.rows[0].recipient_address_hash, Some(recipient_hash));
        assert_eq!(report.rows[0].message_id_hash, Some(message_hash));
        assert_eq!(report.rows[0].correlation_id_hash, Some(correlation_hash));

        let _ = fs::remove_file(&path);
    }

    #[test]
    fn ledger_window_rejects_invalid_or_inverted_utc_windows() {
        let config = config_with_no_ledger();

        let invalid_time = ledger_window(
            &config,
            &LedgerWindowRequest {
                start_time: "yesterday".to_string(),
                end_time: "2026-06-30T01:00:00Z".to_string(),
                sender_domain: None,
                campaign_id: None,
                batch_id: None,
                limit: Some(20),
            },
        )
        .expect_err("invalid start time should fail before config");
        assert_eq!(invalid_time.code(), "invalid_input");

        let inverted = ledger_window(
            &config,
            &LedgerWindowRequest {
                start_time: "2026-06-30T01:00:00Z".to_string(),
                end_time: "2026-06-30T00:00:00Z".to_string(),
                sender_domain: None,
                campaign_id: None,
                batch_id: None,
                limit: Some(20),
            },
        )
        .expect_err("inverted window should fail before config");
        assert_eq!(inverted.code(), "invalid_input");

        let impossible_date = ledger_window(
            &config,
            &LedgerWindowRequest {
                start_time: "2026-02-31T00:00:00Z".to_string(),
                end_time: "2026-03-01T00:00:00Z".to_string(),
                sender_domain: None,
                campaign_id: None,
                batch_id: None,
                limit: Some(20),
            },
        )
        .expect_err("impossible UTC date should fail before config");
        assert_eq!(impossible_date.code(), "invalid_input");
    }

    #[test]
    fn ledger_window_requires_configured_path() {
        let config = config_with_no_ledger();
        let error = ledger_window(
            &config,
            &LedgerWindowRequest {
                start_time: "2026-06-30T00:00:00Z".to_string(),
                end_time: "2026-06-30T01:00:00Z".to_string(),
                sender_domain: None,
                campaign_id: None,
                batch_id: None,
                limit: Some(20),
            },
        )
        .expect_err("ledger path should be required");

        assert_eq!(error.code(), "configuration_error");
    }

    fn config_with_ledger(path: PathBuf) -> OciEmailConfig {
        OciEmailConfig {
            cli_bin: "oci".to_string(),
            profile: "TEST".to_string(),
            compartment_id: Some("ocid1.tenancy.oc1..fixture".to_string()),
            region: Some("example-region-1".to_string()),
            config_file: None,
            ledger_path: Some(path),
            warn_hard_bounce_percent: 0.5,
            pause_hard_bounce_percent: 0.55,
            throttle_hard_bounce_percent: 0.75,
            hard_stop_hard_bounce_percent: 1.0,
        }
    }

    fn config_with_no_ledger() -> OciEmailConfig {
        OciEmailConfig {
            ledger_path: None,
            ..config_with_ledger(PathBuf::from("/unused"))
        }
    }
}

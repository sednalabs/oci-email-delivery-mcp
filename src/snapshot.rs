use crate::{
    config::OciEmailConfig,
    error::OciEmailError,
    live::OciEmailBackend,
    redact::{redact_sensitive_text, short_hash},
    response::{
        Evidence, ReadinessFinding, SendReadinessRequest, SnapshotArtifactReport,
        SnapshotArtifactRequest, SnapshotArtifactSummary, ToolCallOutcome,
        TraceabilityAuditRequest, WatchWindowReport, WatchWindowRequest, DEFAULT_SNAPSHOT_PREFIX,
    },
};
use serde::Serialize;
use serde_json::json;
use sha2::{Digest, Sha256};
use std::{
    fs::{self, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

const SNAPSHOT_SCHEMA: &str = "oci_email_monitoring_snapshot.v1";

pub fn snapshot_artifact<B: OciEmailBackend + ?Sized>(
    config: &OciEmailConfig,
    backend: &B,
    request: &SnapshotArtifactRequest,
) -> Result<SnapshotArtifactReport, OciEmailError> {
    let root = validate_snapshot_root(config)?;
    let receipt_kind = snapshot_receipt_kind(request)?;
    validate_snapshot_window(request)?;
    let artifact_prefix = sanitize_artifact_prefix(request.artifact_prefix.as_deref())?;

    let mut findings = Vec::new();
    let mut evidence = Vec::new();
    let (
        receipt_value,
        receipt_status,
        receipt_decision,
        summary,
        receipt_findings,
        receipt_evidence,
    ) = match receipt_kind.as_str() {
        "send_readiness" => {
            let report = backend.send_readiness(&send_readiness_request(request)?)?;
            let summary = summary_from_send_readiness(request, &report);
            (
                to_json_value(&report)?,
                report.status.clone(),
                report.decision.clone(),
                summary,
                report.findings.clone(),
                report.evidence.clone(),
            )
        }
        "traceability_audit" => {
            let report = backend.traceability_audit(&traceability_audit_request(request));
            let report = report?;
            let summary = summary_from_traceability_audit(request, &report);
            (
                to_json_value(&report)?,
                report.status.clone(),
                report.decision.clone(),
                summary,
                report.findings.clone(),
                report.evidence.clone(),
            )
        }
        _ => {
            let mut report = backend.watch_window(&watch_window_request(request));
            redact_watch_trace_header_names(&mut report);
            let report = report?;
            let summary = summary_from_watch(request, &report);
            (
                to_json_value(&report)?,
                report.status.clone(),
                report.decision.clone(),
                summary,
                report.findings.clone(),
                report.evidence.clone(),
            )
        }
    };

    findings.extend(receipt_findings);
    evidence.extend(receipt_evidence);
    let created_at_unix = now_unix();
    let filename_nonce = now_unix_nanos();
    let mut artifact = summary;
    artifact.filename = snapshot_filename(request, &receipt_kind, &artifact_prefix, filename_nonce);
    artifact.root_hash = short_hash(root.to_string_lossy().as_ref());
    let payload = json!({
        "schema": SNAPSHOT_SCHEMA,
        "created_at_unix": created_at_unix,
        "receipt_kind": receipt_kind,
        "artifact": {
            "schema": artifact.schema,
            "filename": artifact.filename,
            "root_hash": artifact.root_hash,
            "start_time": artifact.start_time,
            "end_time": artifact.end_time,
            "resource_domain": artifact.resource_domain,
            "source_domain": artifact.source_domain,
            "campaign_hash": artifact.campaign_hash,
            "batch_hash": artifact.batch_hash,
            "expected_ledger_rows": artifact.expected_ledger_rows,
            "trace_requested": artifact.trace_requested
        },
        "receipt": receipt_value,
        "raw_payload_returned": false
    });
    let bytes = serde_json::to_vec_pretty(&payload).map_err(|err| OciEmailError::Json {
        context: "snapshot artifact".to_string(),
        message: err.to_string(),
    })?;
    let sha256 = hex::encode(Sha256::digest(&bytes));
    let path = root.join(&artifact.filename);
    write_new_snapshot_file(&path, &bytes)?;
    artifact.bytes = bytes.len() as u64;
    artifact.sha256 = sha256;
    evidence.push(Evidence::new(
        "local_snapshot_artifact",
        "write redacted monitoring snapshot",
        false,
    ));
    findings.push(ReadinessFinding {
        severity: "info".to_string(),
        code: "snapshot_artifact_written".to_string(),
        message:
            "A redacted private monitoring snapshot artifact was written under the configured root."
                .to_string(),
    });

    let status = if receipt_status == "blocked" {
        "blocked"
    } else if receipt_status == "degraded" {
        "degraded"
    } else {
        "ok"
    }
    .to_string();

    Ok(SnapshotArtifactReport {
        status,
        decision: receipt_decision.clone(),
        send_authorized: false,
        receipt_kind,
        receipt_status,
        receipt_decision,
        artifact,
        findings,
        evidence,
        raw_payload_returned: false,
    })
}

fn validate_snapshot_root(config: &OciEmailConfig) -> Result<PathBuf, OciEmailError> {
    let Some(root) = &config.snapshot_root else {
        return Err(OciEmailError::Config(
            "OCI_MCP_SNAPSHOT_ROOT is not configured; private monitoring snapshots are disabled"
                .to_string(),
        ));
    };
    if !root.is_absolute() {
        return Err(OciEmailError::Config(
            "OCI_MCP_SNAPSHOT_ROOT must be an absolute private directory".to_string(),
        ));
    }
    let metadata = fs::symlink_metadata(root).map_err(|err| {
        OciEmailError::Config(format!(
            "configured snapshot root must already exist and be readable: {}",
            redact_sensitive_text(&err.to_string())
        ))
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(OciEmailError::Config(
            "configured snapshot root must be a real directory, not a symlink or file".to_string(),
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if metadata.mode() & 0o077 != 0 {
            return Err(OciEmailError::Config(
                "configured snapshot root must be private on Unix; run chmod 700 on the directory"
                    .to_string(),
            ));
        }
    }
    Ok(root.clone())
}

fn snapshot_receipt_kind(request: &SnapshotArtifactRequest) -> Result<String, OciEmailError> {
    let value = request
        .receipt_kind
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or("watch_window");
    match value {
        "watch_window" | "send_readiness" | "traceability_audit" => Ok(value.to_string()),
        _ => Err(OciEmailError::InvalidInput(
            "receipt_kind must be watch_window, send_readiness, or traceability_audit".to_string(),
        )),
    }
}

fn watch_window_request(request: &SnapshotArtifactRequest) -> WatchWindowRequest {
    WatchWindowRequest {
        start_time: request.start_time.clone(),
        end_time: request.end_time.clone(),
        interval: request.interval.clone(),
        resource_domain: request.resource_domain.clone(),
        source_domain: request.source_domain.clone(),
        resource_id: request.resource_id.clone(),
        message_id: request.message_id.clone(),
        header_name: request.header_name.clone(),
        header_value: request.header_value.clone(),
        limit: request.limit,
        compartment_id: request.compartment_id.clone(),
    }
}

fn send_readiness_request(
    request: &SnapshotArtifactRequest,
) -> Result<SendReadinessRequest, OciEmailError> {
    let campaign_id = required_snapshot_value(&request.campaign_id, "campaign_id")?;
    let batch_id = required_snapshot_value(&request.batch_id, "batch_id")?;
    let expected_ledger_rows = request.expected_ledger_rows.ok_or_else(|| {
        OciEmailError::InvalidInput(
            "send_readiness snapshots require expected_ledger_rows".to_string(),
        )
    })?;
    Ok(SendReadinessRequest {
        start_time: request.start_time.clone(),
        end_time: request.end_time.clone(),
        interval: request.interval.clone(),
        resource_domain: request.resource_domain.clone(),
        source_domain: request.source_domain.clone(),
        resource_id: request.resource_id.clone(),
        sender_domain: request.sender_domain.clone(),
        campaign_id,
        batch_id,
        expected_ledger_rows,
        message_id: request.message_id.clone(),
        header_name: request.header_name.clone(),
        header_value: request.header_value.clone(),
        limit: request.limit,
        compartment_id: request.compartment_id.clone(),
    })
}

fn traceability_audit_request(request: &SnapshotArtifactRequest) -> TraceabilityAuditRequest {
    TraceabilityAuditRequest {
        start_time: request.start_time.clone(),
        end_time: request.end_time.clone(),
        interval: request.interval.clone(),
        resource_domain: request.resource_domain.clone(),
        source_domain: request.source_domain.clone(),
        resource_id: request.resource_id.clone(),
        sender_domain: request.sender_domain.clone(),
        campaign_id: request.campaign_id.clone(),
        batch_id: request.batch_id.clone(),
        expected_ledger_rows: request.expected_ledger_rows,
        message_id: request.message_id.clone(),
        header_name: request.header_name.clone(),
        header_value: request.header_value.clone(),
        limit: request.limit,
        compartment_id: request.compartment_id.clone(),
    }
}

fn required_snapshot_value(value: &Option<String>, name: &str) -> Result<String, OciEmailError> {
    value
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToString::to_string)
        .ok_or_else(|| {
            OciEmailError::InvalidInput(format!("send_readiness snapshots require {}", name))
        })
}

fn validate_snapshot_window(request: &SnapshotArtifactRequest) -> Result<(), OciEmailError> {
    let start = snapshot_time_key(&request.start_time, "start_time")?;
    let end = snapshot_time_key(&request.end_time, "end_time")?;
    if start < end {
        Ok(())
    } else {
        Err(OciEmailError::InvalidInput(
            "start_time must be before end_time".to_string(),
        ))
    }
}

fn snapshot_time_key(value: &str, label: &str) -> Result<String, OciEmailError> {
    let trimmed = value.trim();
    if trimmed != value || trimmed.len() > 40 {
        return Err(snapshot_time_error(label));
    }
    let core = trimmed
        .strip_suffix('Z')
        .ok_or_else(|| snapshot_time_error(label))?;
    let bytes = core.as_bytes();
    if bytes.len() < 19
        || bytes.get(4) != Some(&b'-')
        || bytes.get(7) != Some(&b'-')
        || bytes.get(10) != Some(&b'T')
        || bytes.get(13) != Some(&b':')
        || bytes.get(16) != Some(&b':')
    {
        return Err(snapshot_time_error(label));
    }
    for range in [0..4, 5..7, 8..10, 11..13, 14..16, 17..19] {
        if !bytes[range].iter().all(u8::is_ascii_digit) {
            return Err(snapshot_time_error(label));
        }
    }
    let month = parse_two_digits(bytes, 5).ok_or_else(|| snapshot_time_error(label))?;
    let day = parse_two_digits(bytes, 8).ok_or_else(|| snapshot_time_error(label))?;
    let hour = parse_two_digits(bytes, 11).ok_or_else(|| snapshot_time_error(label))?;
    let minute = parse_two_digits(bytes, 14).ok_or_else(|| snapshot_time_error(label))?;
    let second = parse_two_digits(bytes, 17).ok_or_else(|| snapshot_time_error(label))?;
    if !(1..=12).contains(&month)
        || day == 0
        || day > days_in_month(bytes, month)
        || hour > 23
        || minute > 59
        || second > 59
    {
        return Err(snapshot_time_error(label));
    }
    let fraction = match bytes.get(19) {
        None => "000000000".to_string(),
        Some(b'.') => {
            let digits = &core[20..];
            if digits.is_empty()
                || digits.len() > 9
                || !digits.as_bytes().iter().all(u8::is_ascii_digit)
            {
                return Err(snapshot_time_error(label));
            }
            format!("{digits:0<9}")
        }
        _ => return Err(snapshot_time_error(label)),
    };
    Ok(format!("{}.{fraction}Z", &core[..19]))
}

fn snapshot_time_error(label: &str) -> OciEmailError {
    OciEmailError::InvalidInput(format!(
        "{label} must be an RFC3339 UTC timestamp ending in Z"
    ))
}

fn parse_two_digits(bytes: &[u8], start: usize) -> Option<u32> {
    let tens = *bytes.get(start)?;
    let ones = *bytes.get(start + 1)?;
    Some((tens - b'0') as u32 * 10 + (ones - b'0') as u32)
}

fn days_in_month(bytes: &[u8], month: u32) -> u32 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if is_leap_year(bytes) => 29,
        2 => 28,
        _ => 0,
    }
}

fn is_leap_year(bytes: &[u8]) -> bool {
    let year = bytes[0..4]
        .iter()
        .fold(0u32, |acc, digit| (acc * 10) + (digit - b'0') as u32);
    (year.is_multiple_of(4) && !year.is_multiple_of(100)) || year.is_multiple_of(400)
}

fn summary_from_watch(
    request: &SnapshotArtifactRequest,
    report: &WatchWindowReport,
) -> SnapshotArtifactSummary {
    SnapshotArtifactSummary {
        schema: SNAPSHOT_SCHEMA.to_string(),
        filename: String::new(),
        root_hash: String::new(),
        bytes: 0,
        sha256: String::new(),
        start_time: report.start_time.clone(),
        end_time: report.end_time.clone(),
        resource_domain: report.resource_domain.clone(),
        source_domain: report.source_domain.clone(),
        campaign_hash: request.campaign_id.as_deref().map(short_hash),
        batch_hash: request.batch_id.as_deref().map(short_hash),
        expected_ledger_rows: request.expected_ledger_rows,
        trace_requested: report.trace_requested,
    }
}

fn summary_from_send_readiness(
    _request: &SnapshotArtifactRequest,
    report: &crate::response::SendReadinessReport,
) -> SnapshotArtifactSummary {
    SnapshotArtifactSummary {
        schema: SNAPSHOT_SCHEMA.to_string(),
        filename: String::new(),
        root_hash: String::new(),
        bytes: 0,
        sha256: String::new(),
        start_time: report.start_time.clone(),
        end_time: report.end_time.clone(),
        resource_domain: report.resource_domain.clone(),
        source_domain: report.source_domain.clone(),
        campaign_hash: report.campaign_hash.clone(),
        batch_hash: report.batch_hash.clone(),
        expected_ledger_rows: Some(report.expected_ledger_rows),
        trace_requested: report.trace_requested,
    }
}

fn summary_from_traceability_audit(
    request: &SnapshotArtifactRequest,
    report: &crate::response::TraceabilityAuditReport,
) -> SnapshotArtifactSummary {
    SnapshotArtifactSummary {
        schema: SNAPSHOT_SCHEMA.to_string(),
        filename: String::new(),
        root_hash: String::new(),
        bytes: 0,
        sha256: String::new(),
        start_time: report.start_time.clone(),
        end_time: report.end_time.clone(),
        resource_domain: report.resource_domain.clone(),
        source_domain: report.source_domain.clone(),
        campaign_hash: request.campaign_id.as_deref().map(short_hash),
        batch_hash: request.batch_id.as_deref().map(short_hash),
        expected_ledger_rows: report.expected_ledger_rows,
        trace_requested: report.trace_requested,
    }
}

fn snapshot_filename(
    request: &SnapshotArtifactRequest,
    receipt_kind: &str,
    prefix: &str,
    filename_nonce: u128,
) -> String {
    let start = compact_time(&request.start_time);
    let end = compact_time(&request.end_time);
    let fingerprint = short_hash(&format!(
        "{}|{}|{}|{:?}|{:?}|{:?}|{}",
        receipt_kind,
        request.start_time,
        request.end_time,
        request.resource_domain,
        request.source_domain,
        request.resource_id,
        filename_nonce
    ));
    format!("{prefix}-{receipt_kind}-{start}-{end}-{fingerprint}.json")
}

fn sanitize_artifact_prefix(value: Option<&str>) -> Result<String, OciEmailError> {
    let prefix = value
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or(DEFAULT_SNAPSHOT_PREFIX);
    if prefix == "." || prefix == ".." || prefix.len() > 48 {
        return Err(OciEmailError::InvalidInput(
            "artifact_prefix must be 1-48 safe filename characters".to_string(),
        ));
    }
    if prefix
        .chars()
        .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.'))
    {
        return Ok(prefix.to_string());
    }
    Err(OciEmailError::InvalidInput(
        "artifact_prefix must contain only ASCII letters, digits, dot, dash, or underscore"
            .to_string(),
    ))
}

fn compact_time(value: &str) -> String {
    let compact = value
        .chars()
        .filter(|ch| ch.is_ascii_alphanumeric())
        .collect::<String>();
    if compact.is_empty() {
        "time".to_string()
    } else {
        compact.chars().take(32).collect()
    }
}

fn write_new_snapshot_file(path: &Path, bytes: &[u8]) -> Result<(), OciEmailError> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path).map_err(|err| {
        OciEmailError::Config(format!(
            "failed to create snapshot artifact as a new direct child file: {}",
            redact_sensitive_text(&err.to_string())
        ))
    })?;
    file.write_all(bytes).map_err(|err| {
        OciEmailError::Config(format!(
            "failed to write snapshot artifact: {}",
            redact_sensitive_text(&err.to_string())
        ))
    })?;
    file.sync_all().map_err(|err| {
        OciEmailError::Config(format!(
            "failed to sync snapshot artifact: {}",
            redact_sensitive_text(&err.to_string())
        ))
    })
}

fn to_json_value<T: Serialize>(value: &T) -> Result<serde_json::Value, OciEmailError> {
    serde_json::to_value(value).map_err(|err| OciEmailError::Json {
        context: "snapshot receipt".to_string(),
        message: err.to_string(),
    })
}

fn redact_watch_trace_header_names(report: &mut Result<WatchWindowReport, OciEmailError>) {
    let Ok(report) = report else {
        return;
    };
    let Some(trace) = report.components.trace.as_mut() else {
        return;
    };
    redact_trace_header_names(trace);
}

fn redact_trace_header_names(trace: &mut ToolCallOutcome<crate::response::TraceMessageReport>) {
    let Some(trace_report) = trace.report.as_mut() else {
        return;
    };
    trace_report.criteria.header_name = trace_report
        .criteria
        .header_name
        .take()
        .map(|_| "[redacted]".to_string());
    trace_report.events.filters.header_name = trace_report
        .events
        .filters
        .header_name
        .take()
        .map(|_| "[redacted]".to_string());
}

fn now_unix() -> u64 {
    match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(duration) => duration.as_secs(),
        Err(_) => 0,
    }
}

fn now_unix_nanos() -> u128 {
    match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(duration) => duration.as_nanos(),
        Err(_) => 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests_support::FixtureBackend;

    #[test]
    fn watch_snapshot_writes_redacted_private_artifact() {
        let root = unique_snapshot_root("watch");
        let config = config_with_snapshot_root(root.clone());
        let request = SnapshotArtifactRequest {
            start_time: "2026-06-30T00:00:00Z".to_string(),
            end_time: "2026-06-30T01:00:00Z".to_string(),
            interval: Some("1h".to_string()),
            resource_domain: Some("example.com".to_string()),
            source_domain: Some("example.com".to_string()),
            resource_id: None,
            sender_domain: None,
            campaign_id: Some("campaign-token-123".to_string()),
            batch_id: Some("batch-token-456".to_string()),
            expected_ledger_rows: None,
            message_id: Some("message-token-789".to_string()),
            header_name: Some("X-Trace-Example".to_string()),
            header_value: Some("trace-token-example".to_string()),
            limit: Some(20),
            compartment_id: None,
            receipt_kind: Some("watch_window".to_string()),
            artifact_prefix: Some("proof".to_string()),
        };

        let report = snapshot_artifact(&config, &FixtureBackend, &request)
            .unwrap_or_else(|err| panic!("snapshot artifact: {err}"));
        let output = serde_json::to_string(&report).expect("serialize report");
        let artifact_path = root.join(&report.artifact.filename);
        let artifact = fs::read_to_string(&artifact_path).expect("read artifact");

        assert_eq!(report.receipt_kind, "watch_window");
        assert_eq!(report.artifact.schema, SNAPSHOT_SCHEMA);
        assert!(report.artifact.filename.starts_with("proof-watch_window-"));
        assert!(report.artifact.bytes > 0);
        assert_eq!(report.artifact.sha256.len(), 64);
        assert!(!report.send_authorized);
        assert!(!output.contains(root.to_string_lossy().as_ref()));
        for raw in [
            "message-token-789",
            "X-Trace-Example",
            "trace-token-example",
            "campaign-token-123",
            "batch-token-456",
            "person@example.net",
            "person@example.com",
        ] {
            assert!(!output.contains(raw), "report leaked {raw}");
            assert!(!artifact.contains(raw), "artifact leaked {raw}");
        }
        assert!(artifact.contains("\"schema\": \"oci_email_monitoring_snapshot.v1\""));
        assert!(artifact.contains("\"header_name\": \"[redacted]\""));
    }

    #[test]
    fn send_readiness_snapshot_persists_ledger_receipt_without_raw_identifiers() {
        let root = unique_snapshot_root("readiness");
        let config = config_with_snapshot_root(root.clone());
        let request = SnapshotArtifactRequest {
            start_time: "2026-06-30T00:00:00Z".to_string(),
            end_time: "2026-06-30T01:00:00Z".to_string(),
            interval: Some("1h".to_string()),
            resource_domain: Some("example.com".to_string()),
            source_domain: Some("example.com".to_string()),
            resource_id: None,
            sender_domain: Some("example.com".to_string()),
            campaign_id: Some("campaign-token-123".to_string()),
            batch_id: Some("batch-token-456".to_string()),
            expected_ledger_rows: Some(1),
            message_id: Some("message-token-789".to_string()),
            header_name: None,
            header_value: None,
            limit: Some(20),
            compartment_id: None,
            receipt_kind: Some("send_readiness".to_string()),
            artifact_prefix: None,
        };

        let report = snapshot_artifact(&config, &FixtureBackend, &request)
            .unwrap_or_else(|err| panic!("snapshot artifact: {err}"));
        let artifact = fs::read_to_string(root.join(&report.artifact.filename))
            .expect("read readiness artifact");

        assert_eq!(report.receipt_kind, "send_readiness");
        assert_eq!(report.artifact.expected_ledger_rows, Some(1));
        assert!(report.artifact.campaign_hash.is_some());
        assert!(report.artifact.batch_hash.is_some());
        assert!(!artifact.contains("campaign-token-123"));
        assert!(!artifact.contains("batch-token-456"));
        assert!(!artifact.contains("message-token-789"));
        assert!(!artifact.contains("person@example.net"));
        assert!(artifact.contains("\"receipt_kind\": \"send_readiness\""));
        assert!(artifact.contains("\"raw_payload_returned\": false"));
    }

    #[test]
    fn traceability_snapshot_persists_exact_audit_without_raw_identifiers() {
        let root = unique_snapshot_root("traceability");
        let config = config_with_snapshot_root(root.clone());
        let request = SnapshotArtifactRequest {
            start_time: "2026-06-30T00:00:00Z".to_string(),
            end_time: "2026-06-30T01:00:00Z".to_string(),
            interval: Some("1h".to_string()),
            resource_domain: Some("example.com".to_string()),
            source_domain: Some("example.com".to_string()),
            resource_id: None,
            sender_domain: Some("example.com".to_string()),
            campaign_id: Some("campaign-token-123".to_string()),
            batch_id: Some("batch-token-456".to_string()),
            expected_ledger_rows: Some(1),
            message_id: Some("message-token-789".to_string()),
            header_name: Some("X-Trace-Example".to_string()),
            header_value: Some("trace-token-example".to_string()),
            limit: Some(20),
            compartment_id: None,
            receipt_kind: Some("traceability_audit".to_string()),
            artifact_prefix: Some("proof".to_string()),
        };

        let report = snapshot_artifact(&config, &FixtureBackend, &request)
            .unwrap_or_else(|err| panic!("traceability snapshot artifact: {err}"));
        let artifact = fs::read_to_string(root.join(&report.artifact.filename))
            .expect("read traceability artifact");

        assert_eq!(report.receipt_kind, "traceability_audit");
        assert_eq!(report.receipt_status, "degraded");
        assert_eq!(report.artifact.expected_ledger_rows, Some(1));
        assert!(report.artifact.trace_requested);
        for raw in [
            "message-token-789",
            "X-Trace-Example",
            "trace-token-example",
            "campaign-token-123",
            "batch-token-456",
            "person@example.net",
            "person@example.com",
        ] {
            assert!(!artifact.contains(raw), "artifact leaked {raw}");
        }
        assert!(artifact.contains("\"receipt_kind\": \"traceability_audit\""));
        assert!(artifact.contains("\"exact_message_traceable\": true"));
        assert!(artifact.contains("\"raw_payload_returned\": false"));
    }

    #[test]
    fn snapshot_artifact_requires_configured_private_root() {
        let config = OciEmailConfig {
            snapshot_root: None,
            ..config_with_snapshot_root(unique_snapshot_root("unused"))
        };
        let error = snapshot_artifact(
            &config,
            &FixtureBackend,
            &SnapshotArtifactRequest {
                start_time: "2026-06-30T00:00:00Z".to_string(),
                end_time: "2026-06-30T01:00:00Z".to_string(),
                interval: Some("1h".to_string()),
                resource_domain: Some("example.com".to_string()),
                source_domain: Some("example.com".to_string()),
                resource_id: None,
                sender_domain: None,
                campaign_id: None,
                batch_id: None,
                expected_ledger_rows: None,
                message_id: None,
                header_name: None,
                header_value: None,
                limit: Some(20),
                compartment_id: None,
                receipt_kind: None,
                artifact_prefix: None,
            },
        )
        .expect_err("snapshot root should be required");

        assert_eq!(error.code(), "configuration_error");
    }

    #[test]
    fn snapshot_artifact_rejects_unsafe_prefix() {
        let root = unique_snapshot_root("prefix");
        let config = config_with_snapshot_root(root);
        let error = snapshot_artifact(
            &config,
            &FixtureBackend,
            &SnapshotArtifactRequest {
                start_time: "2026-06-30T00:00:00Z".to_string(),
                end_time: "2026-06-30T01:00:00Z".to_string(),
                interval: Some("1h".to_string()),
                resource_domain: Some("example.com".to_string()),
                source_domain: Some("example.com".to_string()),
                resource_id: None,
                sender_domain: None,
                campaign_id: None,
                batch_id: None,
                expected_ledger_rows: None,
                message_id: None,
                header_name: None,
                header_value: None,
                limit: Some(20),
                compartment_id: None,
                receipt_kind: None,
                artifact_prefix: Some("../escape".to_string()),
            },
        )
        .expect_err("unsafe prefix should fail");

        assert_eq!(error.code(), "invalid_input");
    }

    #[test]
    fn snapshot_artifact_rejects_invalid_or_reversed_windows_before_write() {
        let root = unique_snapshot_root("time");
        let config = config_with_snapshot_root(root.clone());
        let request = SnapshotArtifactRequest {
            start_time: "2026-06-30T01:00:00Z".to_string(),
            end_time: "2026-06-30T00:00:00Z".to_string(),
            interval: Some("1h".to_string()),
            resource_domain: Some("example.com".to_string()),
            source_domain: Some("example.com".to_string()),
            resource_id: None,
            sender_domain: None,
            campaign_id: None,
            batch_id: None,
            expected_ledger_rows: None,
            message_id: None,
            header_name: None,
            header_value: None,
            limit: Some(20),
            compartment_id: None,
            receipt_kind: None,
            artifact_prefix: None,
        };
        let error = snapshot_artifact(&config, &FixtureBackend, &request)
            .expect_err("reversed window should fail");

        assert_eq!(error.code(), "invalid_input");
        assert!(fs::read_dir(&root).expect("read root").next().is_none());
    }

    #[cfg(unix)]
    #[test]
    fn snapshot_artifact_rejects_symlink_root() {
        use std::os::unix::fs::symlink;

        let target = unique_snapshot_root("symlink-target");
        let link = target.with_file_name(format!(
            "{}-link",
            target
                .file_name()
                .expect("target basename")
                .to_string_lossy()
        ));
        let _ = fs::remove_file(&link);
        symlink(&target, &link).expect("create snapshot root symlink");
        let config = config_with_snapshot_root(link);
        let error = snapshot_artifact(
            &config,
            &FixtureBackend,
            &SnapshotArtifactRequest {
                start_time: "2026-06-30T00:00:00Z".to_string(),
                end_time: "2026-06-30T01:00:00Z".to_string(),
                interval: Some("1h".to_string()),
                resource_domain: Some("example.com".to_string()),
                source_domain: Some("example.com".to_string()),
                resource_id: None,
                sender_domain: None,
                campaign_id: None,
                batch_id: None,
                expected_ledger_rows: None,
                message_id: None,
                header_name: None,
                header_value: None,
                limit: Some(20),
                compartment_id: None,
                receipt_kind: None,
                artifact_prefix: None,
            },
        )
        .expect_err("symlink root should fail");

        assert_eq!(error.code(), "configuration_error");
    }

    #[test]
    fn snapshot_artifact_rejects_relative_root() {
        let config = OciEmailConfig {
            snapshot_root: Some(PathBuf::from("relative/snapshots")),
            ..config_with_snapshot_root(unique_snapshot_root("unused"))
        };
        let error = snapshot_artifact(&config, &FixtureBackend, &watch_snapshot_request(None))
            .expect_err("relative root should fail");

        assert_eq!(error.code(), "configuration_error");
    }

    #[cfg(unix)]
    #[test]
    fn snapshot_artifact_rejects_world_readable_root() {
        use std::os::unix::fs::PermissionsExt;

        let root = unique_snapshot_root("world-readable");
        fs::set_permissions(&root, fs::Permissions::from_mode(0o755))
            .expect("relax snapshot root permissions");
        let config = config_with_snapshot_root(root);
        let error = snapshot_artifact(&config, &FixtureBackend, &watch_snapshot_request(None))
            .expect_err("world-readable root should fail");

        assert_eq!(error.code(), "configuration_error");
    }

    #[test]
    fn snapshot_artifact_rejects_unsupported_receipt_kind() {
        let root = unique_snapshot_root("kind");
        let config = config_with_snapshot_root(root);
        let error = snapshot_artifact(
            &config,
            &FixtureBackend,
            &watch_snapshot_request(Some("full_send".to_string())),
        )
        .expect_err("unsupported receipt kind should fail");

        assert_eq!(error.code(), "invalid_input");
    }

    #[test]
    fn send_readiness_snapshot_requires_campaign_batch_and_expected_rows() {
        let root = unique_snapshot_root("missing-readiness-fields");
        let config = config_with_snapshot_root(root);

        let mut request = watch_snapshot_request(Some("send_readiness".to_string()));
        request.batch_id = Some("batch-token-456".to_string());
        request.expected_ledger_rows = Some(1);
        let error = snapshot_artifact(&config, &FixtureBackend, &request)
            .expect_err("campaign id should be required");
        assert_eq!(error.code(), "invalid_input");

        let mut request = watch_snapshot_request(Some("send_readiness".to_string()));
        request.campaign_id = Some("campaign-token-123".to_string());
        request.expected_ledger_rows = Some(1);
        let error = snapshot_artifact(&config, &FixtureBackend, &request)
            .expect_err("batch id should be required");
        assert_eq!(error.code(), "invalid_input");

        let mut request = watch_snapshot_request(Some("send_readiness".to_string()));
        request.campaign_id = Some("campaign-token-123".to_string());
        request.batch_id = Some("batch-token-456".to_string());
        let error = snapshot_artifact(&config, &FixtureBackend, &request)
            .expect_err("expected rows should be required");
        assert_eq!(error.code(), "invalid_input");
    }

    #[test]
    fn snapshot_report_carries_receipt_findings() {
        let root = unique_snapshot_root("findings");
        let config = config_with_snapshot_root(root);
        let report = snapshot_artifact(&config, &FixtureBackend, &watch_snapshot_request(None))
            .unwrap_or_else(|err| panic!("snapshot artifact: {err}"));

        assert!(report
            .findings
            .iter()
            .any(|finding| finding.code == "metric_unavailable_hard_bounced"));
        assert!(report
            .findings
            .iter()
            .any(|finding| finding.code == "snapshot_artifact_written"));
    }

    #[test]
    fn snapshot_file_creation_refuses_collisions() {
        let root = unique_snapshot_root("collision");
        let path = root.join("collision.json");
        write_new_snapshot_file(&path, br#"{"ok":true}"#).expect("first write");
        let error = write_new_snapshot_file(&path, br#"{"ok":false}"#)
            .expect_err("second write should fail");

        assert_eq!(error.code(), "configuration_error");
    }

    fn config_with_snapshot_root(snapshot_root: PathBuf) -> OciEmailConfig {
        OciEmailConfig {
            cli_bin: "oci".to_string(),
            profile: "TEST".to_string(),
            compartment_id: Some("ocid1.tenancy.oc1..fixture".to_string()),
            region: Some("example-region-1".to_string()),
            config_file: None,
            ledger_path: None,
            snapshot_root: Some(snapshot_root),
            warn_hard_bounce_percent: 0.5,
            pause_hard_bounce_percent: 0.55,
            throttle_hard_bounce_percent: 0.75,
            hard_stop_hard_bounce_percent: 1.0,
        }
    }

    fn watch_snapshot_request(receipt_kind: Option<String>) -> SnapshotArtifactRequest {
        SnapshotArtifactRequest {
            start_time: "2026-06-30T00:00:00Z".to_string(),
            end_time: "2026-06-30T01:00:00Z".to_string(),
            interval: Some("1h".to_string()),
            resource_domain: Some("example.com".to_string()),
            source_domain: Some("example.com".to_string()),
            resource_id: None,
            sender_domain: None,
            campaign_id: None,
            batch_id: None,
            expected_ledger_rows: None,
            message_id: None,
            header_name: None,
            header_value: None,
            limit: Some(20),
            compartment_id: None,
            receipt_kind,
            artifact_prefix: None,
        }
    }

    fn unique_snapshot_root(label: &str) -> PathBuf {
        let path = match label {
            "watch" => PathBuf::from("/tmp/oci-email-delivery-mcp-snapshot-watch"),
            "readiness" => PathBuf::from("/tmp/oci-email-delivery-mcp-snapshot-readiness"),
            "traceability" => PathBuf::from("/tmp/oci-email-delivery-mcp-snapshot-traceability"),
            "unused" => PathBuf::from("/tmp/oci-email-delivery-mcp-snapshot-unused"),
            "prefix" => PathBuf::from("/tmp/oci-email-delivery-mcp-snapshot-prefix"),
            "time" => PathBuf::from("/tmp/oci-email-delivery-mcp-snapshot-time"),
            "kind" => PathBuf::from("/tmp/oci-email-delivery-mcp-snapshot-kind"),
            "missing-readiness-fields" => {
                PathBuf::from("/tmp/oci-email-delivery-mcp-snapshot-missing-readiness-fields")
            }
            "findings" => PathBuf::from("/tmp/oci-email-delivery-mcp-snapshot-findings"),
            "collision" => PathBuf::from("/tmp/oci-email-delivery-mcp-snapshot-collision"),
            "symlink-target" => {
                PathBuf::from("/tmp/oci-email-delivery-mcp-snapshot-symlink-target")
            }
            "world-readable" => {
                PathBuf::from("/tmp/oci-email-delivery-mcp-snapshot-world-readable")
            }
            _ => panic!("unexpected snapshot fixture label"),
        };
        let _ = fs::remove_dir_all(&path);
        fs::create_dir_all(&path).expect("create snapshot test root");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700))
                .expect("lock down snapshot test root");
        }
        path
    }
}

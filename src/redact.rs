use sha2::{Digest, Sha256};

pub fn short_hash(value: &str) -> String {
    let normalized = value.trim().to_ascii_lowercase();
    let digest = Sha256::digest(normalized.as_bytes());
    hex::encode(&digest[..10])
}

pub fn redact_email(value: &str) -> String {
    let trimmed = value.trim();
    let Some((_local, domain)) = trimmed.split_once('@') else {
        return "[redacted]".to_string();
    };
    if domain.contains('@') || !is_host_token(domain) {
        return "[redacted-email]".to_string();
    }
    format!("[redacted]@{}", domain.to_ascii_lowercase())
}

pub fn email_domain(value: &str) -> Option<String> {
    let (_local, domain) = value.trim().split_once('@')?;
    is_host_token(domain).then(|| domain.to_ascii_lowercase())
}

pub fn redact_ocid(value: &str) -> String {
    let mut parts = value.trim().split('.');
    if parts
        .next()
        .is_some_and(|part| part.eq_ignore_ascii_case("ocid1"))
    {
        let resource_type = parts
            .next()
            .map(|part| part.to_ascii_lowercase())
            .filter(|part| is_safe_ocid_resource_type(part))
            .unwrap_or_else(|| "resource".to_string());
        format!("[redacted-ocid:{resource_type}:{}]", short_hash(value))
    } else {
        format!("[redacted-id:{}]", short_hash(value))
    }
}

pub fn redact_sensitive_text(value: &str) -> String {
    let mut output = redact_urls(value);
    output = redact_private_paths(&output);
    output = redact_email_addresses(&output);
    output = redact_ocids(&output);
    output = redact_ip_addresses(&output);
    for marker in [
        "password",
        "passwd",
        "token",
        "fingerprint",
        "key_file",
        "private_key",
        "secret",
        "authorization",
    ] {
        output = redact_marker(&output, marker);
    }
    output
}

fn redact_marker(input: &str, marker: &str) -> String {
    let mut redact_following = 0usize;
    let mut output = Vec::new();
    for part in input.split_whitespace() {
        if redact_following > 0 {
            output.push("[redacted]".to_string());
            if !is_separator_token(part) {
                redact_following -= 1;
            }
            continue;
        }

        let lowered = part.to_ascii_lowercase();
        if lowered.contains(marker) {
            output.push("[redacted]".to_string());
            redact_following = marker_following_value_count(part, marker);
        } else {
            output.push(part.to_string());
        }
    }
    output.join(" ")
}

fn marker_following_value_count(part: &str, marker: &str) -> usize {
    let has_inline_value = (part.contains('=') && !part.ends_with('='))
        || (part.contains(':') && !part.ends_with(':'));
    if has_inline_value {
        0
    } else if marker == "authorization" {
        2
    } else {
        1
    }
}

fn is_separator_token(part: &str) -> bool {
    matches!(part, "=" | ":")
}

fn redact_urls(input: &str) -> String {
    input
        .split_whitespace()
        .map(|part| {
            if part.starts_with("http://") || part.starts_with("https://") {
                "[redacted-url]".to_string()
            } else {
                part.to_string()
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

fn redact_private_paths(input: &str) -> String {
    redact_tokens(input, is_private_path_token, "[redacted-path]")
}

fn redact_email_addresses(input: &str) -> String {
    redact_tokens(input, is_email_token, "[redacted-email]")
}

fn redact_ocids(input: &str) -> String {
    redact_tokens(input, is_ocid_token, "[redacted-ocid]")
}

fn redact_ip_addresses(input: &str) -> String {
    redact_tokens(input, is_ip_token, "[redacted-ip]")
}

fn redact_tokens(input: &str, predicate: fn(&str) -> bool, replacement: &str) -> String {
    let mut output = String::with_capacity(input.len());
    let mut token = String::new();
    for ch in input.chars() {
        if is_token_char(ch) {
            token.push(ch);
            continue;
        }
        flush_token(&mut output, &mut token, predicate, replacement);
        output.push(ch);
    }
    flush_token(&mut output, &mut token, predicate, replacement);
    output
}

fn flush_token(
    output: &mut String,
    token: &mut String,
    predicate: fn(&str) -> bool,
    replacement: &str,
) {
    if token.is_empty() {
        return;
    }
    if predicate(token) {
        output.push_str(replacement);
    } else {
        output.push_str(token);
    }
    token.clear();
}

fn is_token_char(ch: char) -> bool {
    ch.is_ascii_alphanumeric() || matches!(ch, '@' | '.' | '_' | '-' | '+' | ':' | '/' | '\\' | '~')
}

fn is_email_token(value: &str) -> bool {
    let Some((local, domain)) = value.split_once('@') else {
        return false;
    };
    !local.is_empty() && is_host_token(domain)
}

fn is_ocid_token(value: &str) -> bool {
    value
        .get(..6)
        .is_some_and(|prefix| prefix.eq_ignore_ascii_case("ocid1."))
}

fn is_ip_token(value: &str) -> bool {
    let bracket_trimmed = value.trim_matches(|ch| matches!(ch, '[' | ']'));
    if bracket_trimmed.parse::<std::net::IpAddr>().is_ok() {
        return true;
    }
    if value.parse::<std::net::IpAddr>().is_ok() {
        return true;
    }
    if let Some((host, cidr)) = value.split_once('/') {
        return is_ascii_digits(cidr) && host.parse::<std::net::IpAddr>().is_ok();
    }
    if let Some((host, port)) = value.rsplit_once(':') {
        if is_ascii_digits(port) && host.contains('.') {
            return host.parse::<std::net::IpAddr>().is_ok();
        }
    }
    if let Some((host, port)) = value
        .strip_prefix('[')
        .and_then(|value| value.split_once("]:"))
    {
        return is_ascii_digits(port) && host.parse::<std::net::IpAddr>().is_ok();
    }
    false
}

fn is_private_path_token(value: &str) -> bool {
    value.starts_with('/')
        || value.starts_with("~/")
        || value.starts_with("~\\")
        || value
            .get(1..3)
            .is_some_and(|prefix| prefix == ":\\" || prefix == ":/")
}

fn is_safe_ocid_resource_type(value: &str) -> bool {
    !value.is_empty()
        && value
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || ch == '-' || ch == '_')
}

fn is_ascii_digits(value: &str) -> bool {
    !value.is_empty() && value.chars().all(|ch| ch.is_ascii_digit())
}

pub fn is_host_token(value: &str) -> bool {
    let without_port = value
        .rsplit_once(':')
        .and_then(|(host, port)| port.chars().all(|ch| ch.is_ascii_digit()).then_some(host))
        .unwrap_or(value);

    if is_ip_token(without_port) {
        return false;
    }

    let candidate = without_port
        .strip_prefix("www.")
        .unwrap_or(without_port)
        .trim_end_matches('.');
    let labels = candidate.split('.').collect::<Vec<_>>();
    if labels.len() < 2 {
        return false;
    }
    let Some(tld) = labels.last() else {
        return false;
    };
    if tld.len() < 2 || !tld.chars().all(|ch| ch.is_ascii_alphabetic()) {
        return false;
    }

    labels.iter().all(|label| {
        !label.is_empty()
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label
                .chars()
                .all(|ch| ch.is_ascii_alphanumeric() || ch == '-')
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redacts_email_local_part() {
        assert_eq!(redact_email("Person@Example.COM"), "[redacted]@example.com");
    }

    #[test]
    fn hashes_are_stable_and_short() {
        assert_eq!(
            short_hash("User@Example.com"),
            short_hash("user@example.com")
        );
        assert_eq!(short_hash("user@example.com").len(), 20);
    }

    #[test]
    fn redacted_ocids_keep_type_without_ocid_shape() {
        let redacted = redact_ocid("OCID1.EmailDomain.oc1.ap-melbourne-1.example");

        assert!(redacted.starts_with("[redacted-ocid:emaildomain:"));
        assert!(redacted.ends_with(']'));
        assert!(!redacted.to_ascii_lowercase().contains("ocid1."));
    }

    #[test]
    fn redacts_sensitive_text_tokens() {
        let output =
            redact_sensitive_text("token abc user@example.com OCID1.tenancy.oc1..example 203.0.113.4 203.0.113.5:25 [2001:db8::1]:25 198.51.100.0/24 /home/me/.oci/config C:\\Users\\me\\.oci\\key.pem");
        assert!(!output.contains("abc"));
        assert!(!output.contains("user@example.com"));
        assert!(!output.to_ascii_lowercase().contains("ocid1.tenancy"));
        assert!(!output.contains("203.0.113.4"));
        assert!(!output.contains("203.0.113.5"));
        assert!(!output.contains("2001:db8::1"));
        assert!(!output.contains("198.51.100.0"));
        assert!(!output.contains("/home/me"));
        assert!(!output.contains("C:\\Users"));
        assert!(output.contains("[redacted]"));
        assert!(output.contains("[redacted-ip]"));
        assert!(output.contains("[redacted-path]"));
    }

    #[test]
    fn redacts_secret_values_after_markers() {
        let output = redact_sensitive_text(
            "private_key: VERYSECRET authorization: Bearer TOKENVALUE password=INLINESECRET token = SPACEDSECRET authorization : Bearer OTHERSECRET",
        );
        assert!(!output.contains("VERYSECRET"));
        assert!(!output.contains("Bearer"));
        assert!(!output.contains("TOKENVALUE"));
        assert!(!output.contains("INLINESECRET"));
        assert!(!output.contains("SPACEDSECRET"));
        assert!(!output.contains("OTHERSECRET"));
    }

    #[test]
    fn ip_literals_are_not_valid_host_tokens() {
        assert!(!is_host_token("203.0.113.4"));
        assert!(!is_host_token("203.0.113.4:25"));
        assert!(!is_host_token("[2001:db8::1]:25"));
        assert!(is_host_token("mail.example.com"));
    }
}

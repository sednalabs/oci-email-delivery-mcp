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
    let kind = value.split('.').take(2).collect::<Vec<_>>().join(".");
    if kind.starts_with("ocid1.") {
        format!("{kind}:{}", short_hash(value))
    } else {
        format!("id:{}", short_hash(value))
    }
}

pub fn redact_sensitive_text(value: &str) -> String {
    let mut output = redact_urls(value);
    output = redact_email_addresses(&output);
    output = redact_ocids(&output);
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
    input
        .split_whitespace()
        .map(|part| {
            if part.to_ascii_lowercase().contains(marker) {
                "[redacted]".to_string()
            } else {
                part.to_string()
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
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

fn redact_email_addresses(input: &str) -> String {
    redact_tokens(input, is_email_token, "[redacted-email]")
}

fn redact_ocids(input: &str) -> String {
    redact_tokens(
        input,
        |value| value.starts_with("ocid1."),
        "[redacted-ocid]",
    )
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
    ch.is_ascii_alphanumeric() || matches!(ch, '@' | '.' | '_' | '-' | '+' | ':' | '/')
}

fn is_email_token(value: &str) -> bool {
    let Some((local, domain)) = value.split_once('@') else {
        return false;
    };
    !local.is_empty() && is_host_token(domain)
}

pub fn is_host_token(value: &str) -> bool {
    let without_port = value
        .rsplit_once(':')
        .and_then(|(host, port)| port.chars().all(|ch| ch.is_ascii_digit()).then_some(host))
        .unwrap_or(value);

    if without_port.parse::<std::net::IpAddr>().is_ok() {
        return true;
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
    fn redacts_sensitive_text_tokens() {
        let output = redact_sensitive_text("token abc user@example.com ocid1.tenancy.oc1..example");
        assert!(!output.contains("user@example.com"));
        assert!(!output.contains("ocid1.tenancy"));
        assert!(output.contains("[redacted]"));
    }
}

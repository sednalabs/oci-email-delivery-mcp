use crate::redact::redact_sensitive_text;
use serde::Serialize;

#[derive(Debug, thiserror::Error)]
pub enum OciEmailError {
    #[error("missing OCI compartment id; set OCI_MCP_COMPARTMENT_ID or configure tenancy in the selected OCI profile")]
    MissingCompartment,
    #[error("invalid input: {0}")]
    InvalidInput(String),
    #[error("OCI CLI command failed: {command}; status={status:?}; stderr={stderr}")]
    Cli {
        command: String,
        status: Option<i32>,
        stderr: String,
    },
    #[error("failed to parse OCI CLI JSON for {context}: {message}")]
    Json { context: String, message: String },
    #[error("configuration error: {0}")]
    Config(String),
}

impl OciEmailError {
    pub fn code(&self) -> &'static str {
        match self {
            Self::MissingCompartment => "missing_compartment",
            Self::InvalidInput(_) => "invalid_input",
            Self::Cli { stderr, .. } if is_rate_limited(stderr) => "oci_cli_rate_limited",
            Self::Cli { .. } => "oci_cli_failed",
            Self::Json { .. } => "oci_json_parse_failed",
            Self::Config(_) => "configuration_error",
        }
    }

    pub fn redacted_message(&self) -> String {
        redact_sensitive_text(&self.to_string())
    }
}

fn is_rate_limited(stderr: &str) -> bool {
    let compact = stderr
        .to_ascii_lowercase()
        .chars()
        .filter(|ch| !ch.is_whitespace())
        .collect::<String>();
    compact.contains("toomanyrequests")
        || compact.contains("\"status\":429")
        || compact.contains("status:429")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cli_429_errors_are_classified_as_rate_limited() {
        let error = OciEmailError::Cli {
            command: "email suppression list".to_string(),
            status: Some(1),
            stderr: r#"TransientServiceError: { "code": "TooManyRequests", "status": 429 }"#
                .to_string(),
        };

        assert_eq!(error.code(), "oci_cli_rate_limited");
    }

    #[test]
    fn cli_429_status_matching_tolerates_spacing_variants() {
        let error = OciEmailError::Cli {
            command: "email suppression list".to_string(),
            status: Some(1),
            stderr: r#"TransientServiceError: {"status":429}"#.to_string(),
        };

        assert_eq!(error.code(), "oci_cli_rate_limited");
    }
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct ToolErrorReport {
    pub status: &'static str,
    pub error: &'static str,
    pub message: String,
    pub raw_payload_returned: bool,
}

impl From<OciEmailError> for ToolErrorReport {
    fn from(error: OciEmailError) -> Self {
        Self {
            status: "blocked",
            error: error.code(),
            message: error.redacted_message(),
            raw_payload_returned: false,
        }
    }
}

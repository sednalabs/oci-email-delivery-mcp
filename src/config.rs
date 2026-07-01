use crate::error::OciEmailError;
use std::{env, fs, path::PathBuf};

#[derive(Debug, Clone, PartialEq)]
pub struct OciEmailConfig {
    pub cli_bin: String,
    pub profile: String,
    pub compartment_id: Option<String>,
    pub region: Option<String>,
    pub config_file: Option<PathBuf>,
    pub ledger_path: Option<PathBuf>,
    pub snapshot_root: Option<PathBuf>,
    pub warn_hard_bounce_percent: f64,
    pub pause_hard_bounce_percent: f64,
    pub throttle_hard_bounce_percent: f64,
    pub hard_stop_hard_bounce_percent: f64,
}

impl OciEmailConfig {
    pub fn from_env() -> Result<Self, OciEmailError> {
        let profile = env::var("OCI_MCP_PROFILE")
            .or_else(|_| env::var("OCI_CLI_PROFILE"))
            .unwrap_or_else(|_| "DEFAULT".to_string());
        let config_file = env::var("OCI_CONFIG_FILE").ok().map(PathBuf::from);
        let warn_hard_bounce_percent = env_f64("OCI_MCP_WARN_HARD_BOUNCE_PERCENT", 0.5)?;
        let pause_hard_bounce_percent = env_f64("OCI_MCP_PAUSE_HARD_BOUNCE_PERCENT", 0.55)?;
        let throttle_hard_bounce_percent = env_f64("OCI_MCP_THROTTLE_HARD_BOUNCE_PERCENT", 0.75)?;
        let hard_stop_hard_bounce_percent = env_f64("OCI_MCP_HARD_STOP_HARD_BOUNCE_PERCENT", 1.0)?;
        validate_threshold_order(
            warn_hard_bounce_percent,
            pause_hard_bounce_percent,
            throttle_hard_bounce_percent,
            hard_stop_hard_bounce_percent,
        )?;

        Ok(Self {
            cli_bin: env::var("OCI_MCP_CLI_BIN").unwrap_or_else(|_| "oci".to_string()),
            profile,
            compartment_id: env::var("OCI_MCP_COMPARTMENT_ID").ok(),
            region: env::var("OCI_MCP_REGION").ok(),
            config_file,
            ledger_path: env::var("OCI_MCP_LEDGER_PATH").ok().map(PathBuf::from),
            snapshot_root: env::var("OCI_MCP_SNAPSHOT_ROOT").ok().map(PathBuf::from),
            warn_hard_bounce_percent,
            pause_hard_bounce_percent,
            throttle_hard_bounce_percent,
            hard_stop_hard_bounce_percent,
        })
    }

    pub fn resolve_compartment_id(&self) -> Result<String, OciEmailError> {
        if let Some(value) = self
            .compartment_id
            .as_deref()
            .filter(|value| !value.is_empty())
        {
            return Ok(value.to_string());
        }
        let Some(value) = self.read_profile_value("tenancy")? else {
            return Err(OciEmailError::MissingCompartment);
        };
        Ok(value)
    }

    pub fn read_profile_value(&self, key: &str) -> Result<Option<String>, OciEmailError> {
        let path = self.config_path()?;
        let Ok(contents) = fs::read_to_string(&path) else {
            return Ok(None);
        };
        Ok(read_ini_value(&contents, &self.profile, key))
    }

    fn config_path(&self) -> Result<PathBuf, OciEmailError> {
        if let Some(path) = &self.config_file {
            return Ok(path.clone());
        }
        let home =
            env::var("HOME").map_err(|_| OciEmailError::Config("HOME is not set".to_string()))?;
        Ok(PathBuf::from(home).join(".oci").join("config"))
    }
}

fn env_f64(name: &str, default: f64) -> Result<f64, OciEmailError> {
    let Ok(value) = env::var(name) else {
        return Ok(default);
    };
    parse_threshold_value(name, &value)
}

fn parse_threshold_value(name: &str, value: &str) -> Result<f64, OciEmailError> {
    value
        .parse::<f64>()
        .map_err(|_| threshold_config_error(name, " must be a number"))
        .and_then(|parsed| {
            if parsed.is_finite() && parsed >= 0.0 {
                Ok(parsed)
            } else {
                Err(threshold_config_error(
                    name,
                    " must be a finite non-negative number",
                ))
            }
        })
}

fn threshold_config_error(name: &str, suffix: &str) -> OciEmailError {
    OciEmailError::Config([name, suffix].concat())
}

fn validate_threshold_order(
    warn: f64,
    pause: f64,
    throttle: f64,
    hard_stop: f64,
) -> Result<(), OciEmailError> {
    if warn <= pause && pause <= throttle && throttle <= hard_stop {
        return Ok(());
    }
    Err(OciEmailError::Config(
        "hard-bounce thresholds must be ordered warn <= pause <= throttle <= hard-stop".to_string(),
    ))
}

fn read_ini_value(contents: &str, profile: &str, key: &str) -> Option<String> {
    let mut in_section = false;
    let wanted = format!("[{profile}]");
    for line in contents.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with('[') && trimmed.ends_with(']') {
            in_section = trimmed == wanted;
            continue;
        }
        if !in_section {
            continue;
        }
        let Some((candidate, value)) = trimmed.split_once('=') else {
            continue;
        };
        if candidate.trim() == key {
            return Some(value.trim().to_string());
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_selected_profile_value() {
        let contents = "[DEFAULT]\ntenancy = root\n[TEAM]\ntenancy = team\nregion = here\n";

        assert_eq!(
            read_ini_value(contents, "TEAM", "tenancy"),
            Some("team".into())
        );
        assert_eq!(
            read_ini_value(contents, "DEFAULT", "tenancy"),
            Some("root".into())
        );
        assert_eq!(read_ini_value(contents, "TEAM", "missing"), None);
    }

    #[test]
    fn rejects_invalid_threshold_values() {
        assert!(parse_threshold_value("X", "0.5").is_ok());
        assert!(parse_threshold_value("X", "-1").is_err());
        assert!(parse_threshold_value("X", "NaN").is_err());
        assert!(parse_threshold_value("X", "not-number").is_err());
    }

    #[test]
    fn rejects_out_of_order_thresholds() {
        assert!(validate_threshold_order(0.5, 0.55, 0.75, 1.0).is_ok());
        assert!(validate_threshold_order(0.6, 0.55, 0.75, 1.0).is_err());
        assert!(validate_threshold_order(0.5, 0.55, 1.2, 1.0).is_err());
    }
}

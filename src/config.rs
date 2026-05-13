use anyhow::Result;
use serde::Deserialize;
use std::collections::HashMap;

#[derive(Debug, Deserialize, Clone)]
pub struct Config {
    pub log_level: Option<String>,
    pub log_file: Option<String>,

    #[serde(rename = "SSL")]
    pub ssl: Option<SslConfig>,

    #[serde(rename = "PortForward")]
    pub port_forward: Option<HashMap<String, PortForwardServer>>,

    #[serde(rename = "WebServices")]
    pub web_services: Option<HashMap<String, WebServer>>,
}

impl Config {
    pub fn load(path: &str) -> Result<Self> {
        let content = std::fs::read_to_string(path)?;
        let config: Config = serde_yaml::from_str(&content)?;
        Ok(config)
    }
}

// ── SSL ──────────────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize, Clone)]
pub struct SslConfig {
    pub email: String,
    pub cloudflare_api_token: String,
    pub certs: HashMap<String, CertEntry>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct CertEntry {
    pub domains: Vec<String>,
    pub crt_path: String,
    pub key_path: String,
}

// ── Port Forward ──────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize, Clone)]
pub struct PortForwardServer {
    pub enable: bool,
    pub listen_port: u16,
    pub forward_address: String,
    pub forward_port: u16,
}

// ── Web Services ──────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct WebServer {
    pub enable: bool,
    pub listen_port: u16,
    pub tls_enable: bool,
    pub crt_path: Option<String>,
    pub key_path: Option<String>,
    pub sub_rules: HashMap<String, SubRule>,
}

impl<'de> serde::Deserialize<'de> for WebServer {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        use serde::de::Error;
        let mut map: HashMap<String, serde_yaml::Value> =
            HashMap::deserialize(deserializer)?;

        let enable = map
            .remove("enable")
            .and_then(|v| v.as_bool())
            .ok_or_else(|| D::Error::missing_field("enable"))?;
        let listen_port = map
            .remove("listen_port")
            .and_then(|v| v.as_u64())
            .ok_or_else(|| D::Error::missing_field("listen_port"))? as u16;
        let tls_enable = map
            .remove("tls_enable")
            .and_then(|v| v.as_bool())
            .ok_or_else(|| D::Error::missing_field("tls_enable"))?;
        let crt_path = map
            .remove("crt_path")
            .and_then(|v| v.as_str().map(|s| s.to_string()));
        let key_path = map
            .remove("key_path")
            .and_then(|v| v.as_str().map(|s| s.to_string()));

        // All remaining keys are treated as sub-rules
        let mut sub_rules = HashMap::new();
        for (k, v) in map {
            match serde_yaml::from_value::<SubRule>(v) {
                Ok(rule) => {
                    sub_rules.insert(k, rule);
                }
                Err(_) => {} // Skip unrecognized entries
            }
        }

        Ok(WebServer {
            enable,
            listen_port,
            tls_enable,
            crt_path,
            key_path,
            sub_rules,
        })
    }
}

#[derive(Debug, Deserialize, Clone)]
pub struct SubRule {
    pub name: String,
    pub enable: bool,
    pub front_web: String,
    pub backend_address: String,
    pub backend_port: u16,
}

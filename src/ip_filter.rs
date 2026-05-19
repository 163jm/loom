use anyhow::{anyhow, Result};
use std::net::IpAddr;
use std::sync::Arc;
use tracing::{info, warn};

use crate::config::IpFilterConfig;

// ── IP / CIDR 表示 ────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
enum IpEntry {
    Single(IpAddr),
    Cidr { base: u128, mask: u128, is_v6: bool },
}

impl IpEntry {
    fn matches(&self, ip: &IpAddr) -> bool {
        match self {
            IpEntry::Single(a) => a == ip,
            IpEntry::Cidr { base, mask, is_v6 } => {
                let addr = match ip {
                    IpAddr::V4(v4) if !is_v6 => u32::from_be_bytes(v4.octets()) as u128,
                    IpAddr::V6(v6) if *is_v6 => u128::from_be_bytes(v6.octets()),
                    _ => return false,
                };
                (addr & mask) == *base
            }
        }
    }
}

fn parse_entry(s: &str) -> Result<IpEntry> {
    let s = s.trim();
    if s.contains('/') {
        // CIDR
        let mut parts = s.splitn(2, '/');
        let ip_str = parts.next().unwrap();
        let prefix_len: u32 = parts
            .next()
            .unwrap()
            .parse()
            .map_err(|_| anyhow!("invalid prefix length in '{}'", s))?;

        let ip: IpAddr = ip_str
            .parse()
            .map_err(|_| anyhow!("invalid IP in CIDR '{}'", s))?;

        match ip {
            IpAddr::V4(v4) => {
                if prefix_len > 32 {
                    return Err(anyhow!("IPv4 prefix length > 32 in '{}'", s));
                }
                let base = (u32::from_be_bytes(v4.octets()) as u128)
                    & (!0u32 << (32 - prefix_len)) as u128;
                let mask = (!0u32 << (32 - prefix_len)) as u128;
                Ok(IpEntry::Cidr {
                    base,
                    mask,
                    is_v6: false,
                })
            }
            IpAddr::V6(v6) => {
                if prefix_len > 128 {
                    return Err(anyhow!("IPv6 prefix length > 128 in '{}'", s));
                }
                let addr = u128::from_be_bytes(v6.octets());
                let mask = if prefix_len == 0 {
                    0u128
                } else {
                    !0u128 << (128 - prefix_len)
                };
                let base = addr & mask;
                Ok(IpEntry::Cidr {
                    base,
                    mask,
                    is_v6: true,
                })
            }
        }
    } else {
        let ip: IpAddr = s
            .parse()
            .map_err(|_| anyhow!("invalid IP address '{}'", s))?;
        Ok(IpEntry::Single(ip))
    }
}

// ── 公开的 IpFilter 结构 ──────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct IpFilter {
    pub enabled: bool,
    pub whitelist: bool, // true = whitelist, false = blacklist
    pub entries: Vec<IpEntry>,
}

impl IpFilter {
    /// 从配置加载，disabled 时返回一个空的 allow-all 实例
    pub fn load(cfg: &IpFilterConfig) -> Result<Arc<Self>> {
        if !cfg.enable {
            return Ok(Arc::new(IpFilter {
                enabled: false,
                whitelist: true,
                entries: vec![],
            }));
        }

        let mode = cfg.mode.trim().to_lowercase();
        let whitelist = match mode.as_str() {
            "white" => true,
            "black" => false,
            other => {
                return Err(anyhow!(
                    "IPFilter.mode must be 'white' or 'black', got '{}'",
                    other
                ))
            }
        };

        let content = std::fs::read_to_string(&cfg.iplist_path)
            .map_err(|e| anyhow!("failed to read iplist '{}': {}", cfg.iplist_path, e))?;

        let mut entries = Vec::new();
        for (lineno, line) in content.lines().enumerate() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            match parse_entry(line) {
                Ok(entry) => entries.push(entry),
                Err(e) => warn!(
                    "IPFilter: skipping line {} ('{}') — {}",
                    lineno + 1,
                    line,
                    e
                ),
            }
        }

        info!(
            "IPFilter loaded: mode={}, {} entries from '{}'",
            mode,
            entries.len(),
            cfg.iplist_path
        );

        Ok(Arc::new(IpFilter {
            enabled: true,
            whitelist,
            entries,
        }))
    }

    /// 判断某个 IP 是否被允许通过
    pub fn is_allowed(&self, ip: &IpAddr) -> bool {
        if !self.enabled {
            return true;
        }
        let matched = self.entries.iter().any(|e| e.matches(ip));
        if self.whitelist {
            matched // 白名单：命中才放行
        } else {
            !matched // 黑名单：命中则拒绝
        }
    }
}

// ── 无过滤器时的默认值（allow-all）────────────────────────────────────────────

impl Default for IpFilter {
    fn default() -> Self {
        IpFilter {
            enabled: false,
            whitelist: true,
            entries: vec![],
        }
    }
}

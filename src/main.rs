mod config;
mod ip_filter;
mod port_forward;
mod web_service;
mod ssl;
mod logger;

use anyhow::Result;
use clap::Parser;
use std::sync::Arc;
use tokio::signal;
use tracing::{info, error, warn};

use config::Config;
use ip_filter::IpFilter;

#[derive(Parser, Debug)]
#[command(name = "loom", about = "TCP port forwarder, reverse proxy and SSL manager")]
struct Args {
    #[arg(short = 'c', long = "config", help = "Path to config file")]
    config: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    let config = Config::load(&args.config)?;
    let config = Arc::new(config);

    // Init logger
    logger::init(&config)?;

    info!("loom starting, config: {}", args.config);

    // ── 加载 IP 过滤器 ────────────────────────────────────────────────────────
    // 根据 range 字段决定哪些模块启用过滤
    let (pf_filter, ws_filter) = match &config.ip_filter {
        Some(cfg) => {
            let filter = IpFilter::load(cfg)?;
            let range = cfg.range.trim().to_lowercase();
            let (apply_pf, apply_ws) = match range.as_str() {
                "portforward" => (true, false),
                "webservices" => (false, true),
                "both"        => (true, true),
                other => {
                    warn!(
                        "IPFilter.range '{}' unrecognized, defaulting to 'both'. \
                         Valid values: PortForward / WebServices / both",
                        other
                    );
                    (true, true)
                }
            };
            let disabled = Arc::new(IpFilter::default()); // allow-all
            (
                if apply_pf { filter.clone() } else { disabled.clone() },
                if apply_ws { filter.clone() } else { disabled.clone() },
            )
        }
        None => {
            let disabled = Arc::new(IpFilter::default());
            (disabled.clone(), disabled.clone())
        }
    };

    let mut tasks = Vec::new();

    // ── Start port forwarders ─────────────────────────────────────────────────
    if let Some(ref pf) = config.port_forward {
        for (name, server) in pf {
            if !server.enable {
                continue;
            }
            let name = name.clone();
            let server = server.clone();
            let filter = pf_filter.clone();
            let handle = tokio::spawn(async move {
                if let Err(e) = port_forward::run(name.clone(), server, filter).await {
                    error!("PortForward [{}] error: {}", name, e);
                }
            });
            tasks.push(handle);
        }
    }

    // ── Start web services ────────────────────────────────────────────────────
    if let Some(ref ws) = config.web_services {
        for (name, server) in ws {
            if !server.enable {
                continue;
            }
            let name = name.clone();
            let server = server.clone();
            let cfg = config.clone();
            let filter = ws_filter.clone();
            let handle = tokio::spawn(async move {
                if let Err(e) = web_service::run(name.clone(), server, cfg, filter).await {
                    error!("WebService [{}] error: {}", name, e);
                }
            });
            tasks.push(handle);
        }
    }

    // ── Start SSL manager ─────────────────────────────────────────────────────
    if let Some(ref ssl_cfg) = config.ssl {
        let ssl_cfg = ssl_cfg.clone();
        let handle = tokio::spawn(async move {
            ssl::run_manager(ssl_cfg).await;
        });
        tasks.push(handle);
    }

    info!("loom running. Press Ctrl+C to stop.");

    signal::ctrl_c().await?;
    info!("loom shutting down.");

    Ok(())
}

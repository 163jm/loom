mod config;
mod port_forward;
mod web_service;
mod ssl;
mod logger;

use anyhow::Result;
use clap::Parser;
use std::sync::Arc;
use tokio::signal;
use tracing::{info, error};

use config::Config;

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

    let mut tasks = Vec::new();

    // Start port forwarders
    if let Some(ref pf) = config.port_forward {
        for (name, server) in pf {
            if !server.enable {
                continue;
            }
            let name = name.clone();
            let server = server.clone();
            let handle = tokio::spawn(async move {
                if let Err(e) = port_forward::run(name.clone(), server).await {
                    error!("PortForward [{}] error: {}", name, e);
                }
            });
            tasks.push(handle);
        }
    }

    // Start web services
    if let Some(ref ws) = config.web_services {
        for (name, server) in ws {
            if !server.enable {
                continue;
            }
            let name = name.clone();
            let server = server.clone();
            let cfg = config.clone();
            let handle = tokio::spawn(async move {
                if let Err(e) = web_service::run(name.clone(), server, cfg).await {
                    error!("WebService [{}] error: {}", name, e);
                }
            });
            tasks.push(handle);
        }
    }

    // Start SSL manager (cert check + renewal loop)
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

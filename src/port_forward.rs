use anyhow::Result;
use std::sync::Arc;
use tokio::net::{TcpListener, TcpStream};
use tokio::io;
use tracing::{info, warn, error};

use crate::config::PortForwardServer;
use crate::ip_filter::IpFilter;

pub async fn run(name: String, server: PortForwardServer, filter: Arc<IpFilter>) -> Result<()> {
    let listen_addr = format!("0.0.0.0:{}", server.listen_port);
    let listener = TcpListener::bind(&listen_addr).await?;
    info!(
        "PortForward [{}] listening on {} -> {}:{}",
        name, listen_addr, server.forward_address, server.forward_port
    );

    loop {
        match listener.accept().await {
            Ok((inbound, peer)) => {
                let peer_ip = peer.ip();

                // IP 过滤检查
                if !filter.is_allowed(&peer_ip) {
                    warn!("PortForward [{}] blocked {} (IP filter)", name, peer_ip);
                    continue; // 直接丢弃连接，不 spawn 任务
                }

                let target = format!("{}:{}", server.forward_address, server.forward_port);
                let name = name.clone();
                tokio::spawn(async move {
                    if let Err(e) = forward(inbound, target.clone()).await {
                        warn!("PortForward [{}] {} -> {}: {}", name, peer, target, e);
                    }
                });
            }
            Err(e) => {
                error!("PortForward [{}] accept error: {}", name, e);
            }
        }
    }
}

async fn forward(mut inbound: TcpStream, target: String) -> Result<()> {
    let mut outbound = TcpStream::connect(&target).await?;
    let (mut ri, mut wi) = inbound.split();
    let (mut ro, mut wo) = outbound.split();

    let client_to_server = io::copy(&mut ri, &mut wo);
    let server_to_client = io::copy(&mut ro, &mut wi);

    tokio::select! {
        r = client_to_server => { r?; }
        r = server_to_client => { r?; }
    }

    Ok(())
}

use anyhow::{anyhow, Result};
use arc_swap::ArcSwap;
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode, Uri};
use hyper_util::rt::{TokioExecutor, TokioIo};
use rustls::ServerConfig;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;
use tracing::{error, info, warn};

use crate::config::{Config, SubRule, WebServer};
use crate::ip_filter::IpFilter;

// ── TLS helpers ───────────────────────────────────────────────────────────────

fn load_tls_config(crt_path: &str, key_path: &str) -> Result<Arc<ServerConfig>> {
    use rustls::pki_types::{CertificateDer, PrivateKeyDer};
    use rustls_pemfile::{certs, private_key};
    use std::fs::File;
    use std::io::BufReader;

    let cert_file = File::open(crt_path)?;
    let key_file = File::open(key_path)?;

    let cert_chain: Vec<CertificateDer<'static>> = certs(&mut BufReader::new(cert_file))
        .collect::<std::result::Result<Vec<_>, _>>()?;

    let key = private_key(&mut BufReader::new(key_file))?
        .ok_or_else(|| anyhow!("no private key found in {}", key_path))?;

    let key = PrivateKeyDer::try_from(key)?;

    let config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(cert_chain, key)?;

    Ok(Arc::new(config))
}

// ── Route table ───────────────────────────────────────────────────────────────

#[derive(Clone)]
struct RouteEntry {
    backend_address: String,
    backend_port: u16,
}

type RouteTable = Arc<HashMap<String, RouteEntry>>;

fn build_routes(server: &WebServer) -> RouteTable {
    let mut map = HashMap::new();
    for (key, rule) in &server.sub_rules {
        if !is_sub_rule_key(key) {
            continue;
        }
        if !rule.enable {
            continue;
        }
        map.insert(
            rule.front_web.to_lowercase(),
            RouteEntry {
                backend_address: rule.backend_address.clone(),
                backend_port: rule.backend_port,
            },
        );
    }
    Arc::new(map)
}

/// Keys that look like sub-rule entries (not the reserved WebServer fields)
fn is_sub_rule_key(key: &str) -> bool {
    !matches!(
        key,
        "enable" | "listen_port" | "tls_enable" | "crt_path" | "key_path"
    )
}

// ── HTTP-only redirect server (port 80) ──────────────────────────────────────

async fn run_http_redirect(name: String, filter: Arc<IpFilter>) {
    let addr: SocketAddr = "0.0.0.0:80".parse().unwrap();
    let listener = match TcpListener::bind(addr).await {
        Ok(l) => l,
        Err(e) => {
            error!("WebService [{}] failed to bind port 80 for redirect: {}", name, e);
            return;
        }
    };
    info!("WebService [{}] HTTP->HTTPS redirect listening on :80", name);

    loop {
        let (stream, peer) = match listener.accept().await {
            Ok(v) => v,
            Err(e) => {
                warn!("WebService [{}] redirect accept error: {}", name, e);
                continue;
            }
        };

        // IP 过滤
        if !filter.is_allowed(&peer.ip()) {
            warn!("WebService [{}] redirect blocked {} (IP filter)", name, peer.ip());
            continue;
        }

        let name2 = name.clone();
        tokio::spawn(async move {
            let io = TokioIo::new(stream);
            if let Err(e) = hyper::server::conn::http1::Builder::new()
                .serve_connection(
                    io,
                    service_fn(move |req: Request<Incoming>| {
                        let name3 = name2.clone();
                        async move { redirect_to_https(req, name3).await }
                    }),
                )
                .await
            {
                warn!("WebService redirect [{}] conn error from {}: {}", name2, peer, e);
            }
        });
    }
}

async fn redirect_to_https(
    req: Request<Incoming>,
    _name: String,
) -> Result<Response<Full<Bytes>>, hyper::Error> {
    let host = req
        .headers()
        .get(hyper::header::HOST)
        .and_then(|h| h.to_str().ok())
        .unwrap_or("localhost");

    // Strip any port from host header
    let host = host.split(':').next().unwrap_or(host);

    let path_and_query = req
        .uri()
        .path_and_query()
        .map(|pq| pq.as_str())
        .unwrap_or("/");

    let redirect_url = format!("https://{}{}", host, path_and_query);

    let response = Response::builder()
        .status(StatusCode::MOVED_PERMANENTLY)
        .header(hyper::header::LOCATION, redirect_url)
        .body(Full::new(Bytes::new()))
        .unwrap();

    Ok(response)
}

// ── Proxy handler ─────────────────────────────────────────────────────────────

async fn handle_request(
    req: Request<Incoming>,
    routes: RouteTable,
    server_name: String,
) -> Result<Response<Full<Bytes>>, hyper::Error> {
    let host = req
        .headers()
        .get(hyper::header::HOST)
        .and_then(|h| h.to_str().ok())
        .map(|h| h.split(':').next().unwrap_or(h).to_lowercase());

    let host = match host {
        Some(h) => h,
        None => {
            return Ok(Response::builder()
                .status(StatusCode::BAD_REQUEST)
                .body(Full::new(Bytes::from("Missing Host header")))
                .unwrap());
        }
    };

    let route = match routes.get(&host) {
        Some(r) => r.clone(),
        None => {
            warn!("WebService [{}] no route for host: {}", server_name, host);
            return Ok(Response::builder()
                .status(StatusCode::NOT_FOUND)
                .body(Full::new(Bytes::from(format!(
                    "No backend configured for host: {}",
                    host
                ))))
                .unwrap());
        }
    };

    let backend_url = format!(
        "http://{}:{}{}",
        route.backend_address,
        route.backend_port,
        req.uri()
            .path_and_query()
            .map(|pq| pq.as_str())
            .unwrap_or("/")
    );

    // Build outgoing request
    let (mut parts, body) = req.into_parts();

    let uri: Uri = match backend_url.parse() {
        Ok(u) => u,
        Err(e) => {
            error!("WebService [{}] bad backend URI {}: {}", server_name, backend_url, e);
            return Ok(Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .body(Full::new(Bytes::from("Bad backend URI")))
                .unwrap());
        }
    };
    parts.uri = uri;

    // Collect body
    let body_bytes = match body.collect().await {
        Ok(b) => b.to_bytes(),
        Err(_) => {
            return Ok(Response::builder()
                .status(StatusCode::BAD_GATEWAY)
                .body(Full::new(Bytes::from("Failed to read request body")))
                .unwrap());
        }
    };

    let out_req = Request::from_parts(parts, Full::new(body_bytes));

    // Forward to backend
    let backend_addr = format!("{}:{}", route.backend_address, route.backend_port);
    let stream = match tokio::net::TcpStream::connect(&backend_addr).await {
        Ok(s) => s,
        Err(e) => {
            error!(
                "WebService [{}] cannot connect to backend {}: {}",
                server_name, backend_addr, e
            );
            return Ok(Response::builder()
                .status(StatusCode::BAD_GATEWAY)
                .body(Full::new(Bytes::from(format!(
                    "Cannot connect to backend: {}",
                    e
                ))))
                .unwrap());
        }
    };

    let io = TokioIo::new(stream);
    let (mut sender, conn) = match hyper::client::conn::http1::handshake(io).await {
        Ok(v) => v,
        Err(e) => {
            error!("WebService [{}] backend handshake error: {}", server_name, e);
            return Ok(Response::builder()
                .status(StatusCode::BAD_GATEWAY)
                .body(Full::new(Bytes::from("Backend handshake failed")))
                .unwrap());
        }
    };

    tokio::spawn(async move {
        if let Err(e) = conn.await {
            warn!("Backend connection error: {}", e);
        }
    });

    match sender.send_request(out_req).await {
        Ok(resp) => {
            let (parts, body) = resp.into_parts();
            let body_bytes = match body.collect().await {
                Ok(b) => b.to_bytes(),
                Err(e) => {
                    error!("WebService [{}] failed to read backend response: {}", server_name, e);
                    return Ok(Response::builder()
                        .status(StatusCode::BAD_GATEWAY)
                        .body(Full::new(Bytes::from("Failed to read backend response")))
                        .unwrap());
                }
            };
            Ok(Response::from_parts(parts, Full::new(body_bytes)))
        }
        Err(e) => {
            error!("WebService [{}] backend request error: {}", server_name, e);
            Ok(Response::builder()
                .status(StatusCode::BAD_GATEWAY)
                .body(Full::new(Bytes::from(format!("Backend error: {}", e))))
                .unwrap())
        }
    }
}

// ── Main entry point ──────────────────────────────────────────────────────────

pub async fn run(name: String, server: WebServer, _cfg: Arc<Config>, filter: Arc<IpFilter>) -> Result<()> {
    let routes = build_routes(&server);

    // If TLS is enabled on port 443, also spin up HTTP->HTTPS redirect on port 80
    if server.tls_enable && server.listen_port == 443 {
        let name2 = name.clone();
        let filter2 = filter.clone();
        tokio::spawn(async move {
            run_http_redirect(name2, filter2).await;
        });
    }

    let listen_addr: SocketAddr = format!("0.0.0.0:{}", server.listen_port).parse()?;

    if server.tls_enable {
        run_tls(name, server, listen_addr, routes, filter).await
    } else {
        run_plain(name, listen_addr, routes, filter).await
    }
}

// ── Plain HTTP ────────────────────────────────────────────────────────────────

async fn run_plain(name: String, addr: SocketAddr, routes: RouteTable, filter: Arc<IpFilter>) -> Result<()> {
    let listener = TcpListener::bind(addr).await?;
    info!("WebService [{}] listening on {} (plain HTTP)", name, addr);

    loop {
        let (stream, peer) = match listener.accept().await {
            Ok(v) => v,
            Err(e) => {
                warn!("WebService [{}] accept error: {}", name, e);
                continue;
            }
        };

        // IP 过滤
        if !filter.is_allowed(&peer.ip()) {
            warn!("WebService [{}] blocked {} (IP filter)", name, peer.ip());
            continue;
        }

        let routes = routes.clone();
        let name2 = name.clone();
        tokio::spawn(async move {
            let io = TokioIo::new(stream);
            if let Err(e) = hyper::server::conn::http1::Builder::new()
                .serve_connection(
                    io,
                    service_fn(move |req| {
                        let r = routes.clone();
                        let n = name2.clone();
                        async move { handle_request(req, r, n).await }
                    }),
                )
                .await
            {
                warn!("WebService [{}] conn error from {}: {}", name2, peer, e);
            }
        });
    }
}

// ── TLS HTTPS ─────────────────────────────────────────────────────────────────

async fn run_tls(
    name: String,
    server: WebServer,
    addr: SocketAddr,
    routes: RouteTable,
    filter: Arc<IpFilter>,
) -> Result<()> {
    let crt = server
        .crt_path
        .as_deref()
        .ok_or_else(|| anyhow!("crt_path missing for TLS server [{}]", name))?;
    let key = server
        .key_path
        .as_deref()
        .ok_or_else(|| anyhow!("key_path missing for TLS server [{}]", name))?;

    // Wrap in ArcSwap so we can hot-reload later
    let tls_cfg = Arc::new(ArcSwap::from_pointee(load_tls_config(crt, key)?));

    // Spawn a watcher task that reloads TLS certs when the file changes
    {
        let crt = crt.to_string();
        let key = key.to_string();
        let tls_cfg = tls_cfg.clone();
        let name2 = name.clone();
        tokio::spawn(async move {
            cert_reload_watcher(name2, crt, key, tls_cfg).await;
        });
    }

    let listener = TcpListener::bind(addr).await?;
    info!("WebService [{}] listening on {} (TLS)", name, addr);

    loop {
        let (stream, peer) = match listener.accept().await {
            Ok(v) => v,
            Err(e) => {
                warn!("WebService [{}] accept error: {}", name, e);
                continue;
            }
        };

        // IP 过滤（在 TLS 握手前就丢弃，节省资源）
        if !filter.is_allowed(&peer.ip()) {
            warn!("WebService [{}] blocked {} (IP filter)", name, peer.ip());
            continue;
        }

        let current_tls = tls_cfg.load();
        let acceptor = TlsAcceptor::from((**current_tls).clone());
        let routes = routes.clone();
        let name2 = name.clone();

        tokio::spawn(async move {
            let tls_stream = match acceptor.accept(stream).await {
                Ok(s) => s,
                Err(e) => {
                    warn!("WebService [{}] TLS accept error from {}: {}", name2, peer, e);
                    return;
                }
            };
            let io = TokioIo::new(tls_stream);
            if let Err(e) = hyper_util::server::conn::auto::Builder::new(TokioExecutor::new())
                .serve_connection(
                    io,
                    service_fn(move |req| {
                        let r = routes.clone();
                        let n = name2.clone();
                        async move { handle_request(req, r, n).await }
                    }),
                )
                .await
            {
                warn!("WebService [{}] TLS conn error from {}: {}", name2, peer, e);
            }
        });
    }
}

// ── Certificate hot-reload watcher ────────────────────────────────────────────

async fn cert_reload_watcher(
    name: String,
    crt: String,
    key: String,
    tls_cfg: Arc<ArcSwap<Arc<ServerConfig>>>,
) {
    use std::time::Duration;
    use tokio::time::sleep;

    let mut last_mtime = get_mtime(&crt);

    loop {
        sleep(Duration::from_secs(60)).await; // check every minute
        let mtime = get_mtime(&crt);
        if mtime != last_mtime {
            info!("WebService [{}] cert file changed, reloading TLS config...", name);
            match load_tls_config(&crt, &key) {
                Ok(new_cfg) => {
                    tls_cfg.store(Arc::new(new_cfg));
                    info!("WebService [{}] TLS config reloaded successfully", name);
                    last_mtime = mtime;
                }
                Err(e) => {
                    error!("WebService [{}] failed to reload TLS config: {}", name, e);
                }
            }
        }
    }
}

fn get_mtime(path: &str) -> Option<std::time::SystemTime> {
    std::fs::metadata(path).ok()?.modified().ok()
}

# loom

TCP port forwarder + reverse proxy + Let's Encrypt SSL manager, written in Rust.

## Features

- **TCP Port Forwarding** — forward any TCP port to another host/port
- **Reverse Proxy** — domain-based routing (Host header) to backend services
- **TLS/HTTPS** — rustls-powered TLS termination
- **HTTP→HTTPS redirect** — when `listen_port: 443`, automatically listens on port 80 and redirects all traffic to HTTPS
- **Let's Encrypt** — DNS-01 challenge via Cloudflare API; issues and auto-renews certificates
- **Auto-renewal** — checks daily, renews certs with ≤30 days remaining
- **Hot-reload TLS** — cert files are watched; new certs are loaded without restarting
- **systemd-ready** — runs in the foreground, works as a systemd service

## Usage

```bash
./loom -c config.yaml
```

## Configuration

See [`config.example.yaml`](config.example.yaml) for a full example.

```yaml
log_level: info        # debug / info / warn / error
log_file: /tmp/loom.log

SSL:
  email: you@example.com
  cloudflare_api_token: YOUR_TOKEN
  certs:
    cert1:
      domains:
        - example.com
        - "*.example.com"
      crt_path: /etc/loom/certs/example.crt
      key_path: /etc/loom/certs/example.key

PortForward:
  server1:
    enable: true
    listen_port: 8080
    forward_address: 127.0.0.1
    forward_port: 9090

WebServices:
  server1:
    enable: true
    listen_port: 443
    tls_enable: true
    crt_path: /etc/loom/certs/example.crt
    key_path: /etc/loom/certs/example.key
    sub-rule1:
      name: site_a
      enable: true
      front_web: a.example.com
      backend_address: 127.0.0.1
      backend_port: 8001
```

## systemd

```bash
sudo cp loom /usr/local/bin/
sudo mkdir -p /etc/loom
sudo cp config.yaml /etc/loom/config.yaml
sudo cp loom.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now loom
sudo journalctl -u loom -f
```

## Building

```bash
cargo build --release
# binary at: target/release/loom
```

Pre-built binaries are available on the [Releases](../../releases) page:
- `loom-linux-x86_64` — glibc, 64-bit x86
- `loom-linux-aarch64` — glibc, 64-bit ARM
- `loom-linux-x86_64-musl` — static musl, no libc dependency

## Notes

- ACME account credentials are cached at `/tmp/loom_acme_account.json`
- DNS TXT records are cleaned up after each successful certificate issuance
- Port 80 redirect is only activated when a WebService has `tls_enable: true` **and** `listen_port: 443`
- Sub-rules are matched by the `Host` header (case-insensitive)

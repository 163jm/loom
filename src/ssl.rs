use anyhow::{anyhow, Result};
use instant_acme::{
    Account, AccountCredentials, ChallengeType, Identifier, LetsEncrypt, NewAccount, NewOrder,
    OrderStatus,
};
use rcgen::{CertificateParams, DistinguishedName, KeyPair, PKCS_ECDSA_P256_SHA256};
use std::time::Duration;
use tokio::time::sleep;
use tracing::{error, info, warn};

use crate::config::{CertEntry, SslConfig};

// ── Public manager loop ───────────────────────────────────────────────────────

pub async fn run_manager(cfg: SslConfig) {
    info!("SSL manager started, checking certificates daily");
    loop {
        check_and_renew_all(&cfg).await;
        sleep(Duration::from_secs(86400)).await;
    }
}

async fn check_and_renew_all(cfg: &SslConfig) {
    for (name, cert) in &cfg.certs {
        match needs_renewal(&cert.crt_path) {
            Ok(true) => {
                info!("SSL [{}] certificate needs renewal, starting...", name);
                match renew_cert(cfg, cert).await {
                    Ok(_) => info!("SSL [{}] certificate renewed successfully", name),
                    Err(e) => error!("SSL [{}] renewal failed: {}", name, e),
                }
            }
            Ok(false) => {
                info!("SSL [{}] certificate is valid, no renewal needed", name);
            }
            Err(e) => {
                warn!(
                    "SSL [{}] cannot read cert ({}), attempting fresh issuance...",
                    name, e
                );
                match renew_cert(cfg, cert).await {
                    Ok(_) => info!("SSL [{}] certificate issued successfully", name),
                    Err(e2) => error!("SSL [{}] issuance failed: {}", name, e2),
                }
            }
        }
    }
}

// ── Certificate expiry check ──────────────────────────────────────────────────

fn needs_renewal(crt_path: &str) -> Result<bool> {
    use x509_parser::prelude::*;

    let pem_data = std::fs::read(crt_path)?;
    let (_, pem) = x509_parser::pem::parse_x509_pem(&pem_data)
        .map_err(|e| anyhow!("PEM parse error: {}", e))?;
    let (_, cert) = X509Certificate::from_der(&pem.contents)
        .map_err(|e| anyhow!("X509 parse error: {}", e))?;

    let not_after = cert.validity().not_after.timestamp();
    let now = chrono::Utc::now().timestamp();
    let days_left = (not_after - now) / 86400;

    info!("Certificate {} expires in {} days", crt_path, days_left);
    Ok(days_left <= 30)
}

// ── ACME renewal ─────────────────────────────────────────────────────────────

async fn renew_cert(cfg: &SslConfig, entry: &CertEntry) -> Result<()> {
    let account = create_or_load_account(&cfg.email).await?;

    let identifiers: Vec<Identifier> = entry
        .domains
        .iter()
        .map(|d| Identifier::Dns(d.clone()))
        .collect();

    info!("Ordering certificate for domains: {:?}", entry.domains);

    let mut order = account
        .new_order(&NewOrder {
            identifiers: &identifiers,
        })
        .await?;

    let authorizations = order.authorizations().await?;

    for authz in &authorizations {
        let challenge = authz
            .challenges
            .iter()
            .find(|c| c.r#type == ChallengeType::Dns01)
            .ok_or_else(|| anyhow!("No DNS-01 challenge found in authorization"))?;

        let key_auth = order.key_authorization(challenge);
        let digest = key_auth.dns_value();

        let domain = match &authz.identifier {
            Identifier::Dns(d) => d.clone(),
        };

        info!("Setting DNS TXT _acme-challenge.{} = {}", domain, digest);
        set_cloudflare_txt(&cfg.cloudflare_api_token, &domain, &digest).await?;

        info!("Waiting 30s for DNS propagation...");
        sleep(Duration::from_secs(30)).await;

        order.set_challenge_ready(&challenge.url).await?;
    }

    // Poll for Ready state
    let deadline = std::time::Instant::now() + Duration::from_secs(300);
    loop {
        sleep(Duration::from_secs(5)).await;
        let state = order.refresh().await?;
        match state.status {
            OrderStatus::Ready => break,
            OrderStatus::Invalid => return Err(anyhow!("ACME order became invalid")),
            _ => {}
        }
        if std::time::Instant::now() > deadline {
            return Err(anyhow!("Timed out waiting for ACME order Ready state"));
        }
    }

    // Generate key + CSR
    let key_pair = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)?;
    let mut params = CertificateParams::new(entry.domains.clone())?;
    params.distinguished_name = DistinguishedName::new();
    let csr = params.serialize_request(&key_pair)?;

    order.finalize(csr.der()).await?;

    // Poll for certificate
    let deadline = std::time::Instant::now() + Duration::from_secs(300);
    let cert_chain_pem = loop {
        sleep(Duration::from_secs(5)).await;
        if let Some(cert) = order.certificate().await? {
            break cert;
        }
        if std::time::Instant::now() > deadline {
            return Err(anyhow!("Timed out waiting for ACME certificate"));
        }
    };

    // Write cert + key files
    ensure_parent_dir(&entry.crt_path)?;
    ensure_parent_dir(&entry.key_path)?;

    std::fs::write(&entry.crt_path, cert_chain_pem.as_bytes())?;
    std::fs::write(&entry.key_path, key_pair.serialize_pem().as_bytes())?;

    info!(
        "Certificate written to {} and {}",
        entry.crt_path, entry.key_path
    );

    // Clean up DNS TXT records
    for domain in &entry.domains {
        if let Err(e) = delete_cloudflare_txt(&cfg.cloudflare_api_token, domain).await {
            warn!("Failed to clean up DNS TXT for {}: {}", domain, e);
        }
    }

    Ok(())
}

fn ensure_parent_dir(path: &str) -> Result<()> {
    if let Some(parent) = std::path::Path::new(path).parent() {
        std::fs::create_dir_all(parent)?;
    }
    Ok(())
}

// ── ACME account ─────────────────────────────────────────────────────────────

async fn create_or_load_account(email: &str) -> Result<Account> {
    let account_path = "/tmp/loom_acme_account.json";

    if let Ok(data) = std::fs::read_to_string(account_path) {
        if let Ok(creds) = serde_json::from_str::<AccountCredentials>(&data) {
            match Account::from_credentials(creds).await {
                Ok(account) => {
                    info!("Loaded ACME account from {}", account_path);
                    return Ok(account);
                }
                Err(e) => {
                    warn!("Cached ACME account invalid ({}), creating new one", e);
                }
            }
        }
    }

    info!("Creating new ACME account for {}", email);
    let (account, credentials) = Account::create(
        &NewAccount {
            contact: &[&format!("mailto:{}", email)],
            terms_of_service_agreed: true,
            only_return_existing: false,
        },
        LetsEncrypt::Production.url(),
        None,
    )
    .await?;

    let creds_json = serde_json::to_string(&credentials)?;
    if let Err(e) = std::fs::write(account_path, &creds_json) {
        warn!("Failed to save ACME account credentials: {}", e);
    } else {
        info!("ACME account saved to {}", account_path);
    }

    Ok(account)
}

// ── Cloudflare DNS API ────────────────────────────────────────────────────────

async fn get_zone_id(token: &str, domain: &str) -> Result<String> {
    let bare = domain.trim_start_matches("*.").trim_start_matches('*');
    let parts: Vec<&str> = bare.split('.').collect();
    let root = if parts.len() >= 2 {
        format!("{}.{}", parts[parts.len() - 2], parts[parts.len() - 1])
    } else {
        bare.to_string()
    };

    let client = reqwest::Client::new();
    let resp: serde_json::Value = client
        .get("https://api.cloudflare.com/client/v4/zones")
        .bearer_auth(token)
        .query(&[("name", &root)])
        .send()
        .await?
        .json()
        .await?;

    let zone_id = resp["result"][0]["id"]
        .as_str()
        .ok_or_else(|| anyhow!("Cloudflare zone not found for domain: {}", domain))?
        .to_string();

    Ok(zone_id)
}

fn challenge_record_name(domain: &str) -> String {
    let bare = domain.trim_start_matches("*.").trim_start_matches('*');
    format!("_acme-challenge.{}", bare)
}

pub async fn set_cloudflare_txt(token: &str, domain: &str, value: &str) -> Result<()> {
    let zone_id = get_zone_id(token, domain).await?;
    let record_name = challenge_record_name(domain);
    let client = reqwest::Client::new();

    delete_txt_records(&client, token, &zone_id, &record_name).await?;

    let body = serde_json::json!({
        "type": "TXT",
        "name": record_name,
        "content": value,
        "ttl": 60
    });

    let resp: serde_json::Value = client
        .post(format!(
            "https://api.cloudflare.com/client/v4/zones/{}/dns_records",
            zone_id
        ))
        .bearer_auth(token)
        .json(&body)
        .send()
        .await?
        .json()
        .await?;

    if resp["success"].as_bool() != Some(true) {
        return Err(anyhow!("Cloudflare API error: {:?}", resp["errors"]));
    }

    info!("DNS TXT record set: {} = {}", record_name, value);
    Ok(())
}

pub async fn delete_cloudflare_txt(token: &str, domain: &str) -> Result<()> {
    let zone_id = get_zone_id(token, domain).await?;
    let record_name = challenge_record_name(domain);
    let client = reqwest::Client::new();
    delete_txt_records(&client, token, &zone_id, &record_name).await
}

async fn delete_txt_records(
    client: &reqwest::Client,
    token: &str,
    zone_id: &str,
    record_name: &str,
) -> Result<()> {
    let resp: serde_json::Value = client
        .get(format!(
            "https://api.cloudflare.com/client/v4/zones/{}/dns_records",
            zone_id
        ))
        .bearer_auth(token)
        .query(&[("type", "TXT"), ("name", record_name)])
        .send()
        .await?
        .json()
        .await?;

    if let Some(records) = resp["result"].as_array() {
        for rec in records {
            if let Some(id) = rec["id"].as_str() {
                client
                    .delete(format!(
                        "https://api.cloudflare.com/client/v4/zones/{}/dns_records/{}",
                        zone_id, id
                    ))
                    .bearer_auth(token)
                    .send()
                    .await?;
                info!("Deleted DNS TXT record: {}", record_name);
            }
        }
    }

    Ok(())
}

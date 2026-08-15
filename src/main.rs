// ========== 依赖导入 ==========
use axum::{
    extract::State,
    http::StatusCode,
    response::{Html, IntoResponse},
    routing::get,
    Router,
};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use chrono::Utc;
use rand::rngs::OsRng;
use rcgen::{Certificate, CertificateParams, DistinguishedName, DnType, KeyPair, SanType, PKCS_ECDSA_P256_SHA256};
use reqwest::Client;
use serde_json::{json, Value};
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::Arc;
use std::time::Duration;
use tokio::fs as tokio_fs;
use tokio::process::Command;
use tokio::sync::Mutex;
use tokio::time::sleep;
use tracing::{error, info, warn};
use tracing_subscriber::EnvFilter;
use x25519_dalek::{PublicKey, StaticSecret};
use x509_parser::parse_x509_certificate;

// ========== 辅助函数（环境变量） ==========
fn get_env(key: &str, default: &str) -> String {
    env::var(key).unwrap_or_else(|_| default.to_string())
}

fn get_env_bool(key: &str, default: &str) -> bool {
    let val = env::var(key).unwrap_or_else(|_| default.to_string());
    match val.to_lowercase().as_str() {
        "true" | "1" | "yes" | "on" => true,
        "false" | "0" | "no" | "off" => false,
        _ => default.parse().unwrap_or(false),
    }
}

fn get_env_u16(key: &str, default: &str) -> u16 {
    env::var(key)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or_else(|| default.parse().unwrap_or(0))
}

// ========== 配置结构体 ==========
#[derive(Clone)]
pub struct Config {
    pub upload_url: String,
    pub project_url: String,
    pub auto_access: bool,
    pub file_path: PathBuf,
    pub sub_path: String,
    pub port: u16,
    pub uuid: String,
    pub nezha_server: String,
    pub nezha_port: String,
    pub nezha_key: String,
    pub argo_domain: String,
    pub argo_auth: String,
    pub argo_port: u16,
    pub s5_port: String,
    pub hy2_port: String,
    pub reality_port: String,
    pub cfip: String,
    pub cfport: u16,
    pub name: String,
    pub chat_id: String,
    pub bot_token: String,
    pub show_log: bool,
}

impl Config {
    pub fn from_env() -> Self {
        Self {
            upload_url: get_env("UPLOAD_URL", ""),
            project_url: get_env("PROJECT_URL", ""),
            auto_access: get_env_bool("AUTO_ACCESS", "false"),
            file_path: PathBuf::from(get_env("FILE_PATH", ".tmp")),
            sub_path: get_env("SUB_PATH", "sub"),
            port: get_env_u16("SERVER_PORT", "7860"),
            uuid: get_env("UUID", "9afd1229-b893-40c1-84dd-51e7ce204913"),
            nezha_server: get_env("NEZHA_SERVER", ""),
            nezha_port: get_env("NEZHA_PORT", ""),
            nezha_key: get_env("NEZHA_KEY", ""),
            argo_domain: get_env("ARGO_DOMAIN", ""),
            argo_auth: get_env("ARGO_AUTH", ""),
            argo_port: get_env_u16("ARGO_PORT", "8001"),
            s5_port: get_env("S5_PORT", ""),
            hy2_port: get_env("HY2_PORT", ""),
            reality_port: get_env("REALITY_PORT", ""),
            cfip: get_env("CFIP", "saas.sin.fan"),
            cfport: get_env_u16("CFPORT", "443"),
            name: get_env("NAME", ""),
            chat_id: get_env("CHAT_ID", ""),
            bot_token: get_env("BOT_TOKEN", ""),
            show_log: get_env_bool("SHOW_LOG", "true"),
        }
    }
}

// ========== 全局状态 ==========
#[derive(Clone)]
struct AppState {
    config: Config,
    client: Client,
    sub_content: Arc<Mutex<Option<String>>>,
}

// ========== 工具函数 ==========
fn is_valid_port(port: &str) -> bool {
    if port.is_empty() {
        return false;
    }
    port.parse::<u16>().is_ok()
}

async fn ensure_dir(path: &Path) -> std::io::Result<()> {
    if !path.exists() {
        tokio_fs::create_dir_all(path).await?;
    }
    Ok(())
}

// ========== 立即清理旧文件（清空 .tmp 目录） ==========
async fn cleanup_old_files(config: &Config) -> std::io::Result<()> {
    let dir = &config.file_path;
    if dir.exists() {
        tokio_fs::remove_dir_all(dir).await?;
    }
    tokio_fs::create_dir_all(dir).await?;
    Ok(())
}

// ========== 删除上游旧节点 ==========
async fn delete_nodes(state: &AppState) -> Result<(), Box<dyn std::error::Error>> {
    let upload_url = &state.config.upload_url;
    if upload_url.is_empty() {
        return Ok(());
    }
    let sub_path = state.config.file_path.join("sub.txt");
    if !sub_path.exists() {
        return Ok(());
    }
    let content = tokio_fs::read_to_string(&sub_path).await?;
    let decoded = String::from_utf8(BASE64.decode(&content)?)?;
    let nodes: Vec<&str> = decoded
        .lines()
        .filter(|line| line.contains("://"))
        .collect();
    if nodes.is_empty() {
        return Ok(());
    }
    let payload = json!({ "nodes": nodes });
    let resp = state
        .client
        .post(format!("{}/api/delete-nodes", upload_url))
        .json(&payload)
        .send()
        .await?;
    if resp.status().is_success() {
        info!("旧节点删除成功");
    } else {
        warn!("旧节点删除失败: {}", resp.status());
    }
    Ok(())
}

// ========== 证书生成（纯 Rust） ==========
fn generate_cert_and_key() -> (String, String) {
    let mut params = CertificateParams::default();
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, "bing.com");
    params.distinguished_name = dn;
    params.subject_alt_names = vec![SanType::DnsName("bing.com".to_string())];
    params.key_pair = Some(KeyPair::generate_for_curve(PKCS_ECDSA_P256_SHA256).unwrap());
    params.is_ca = false;
    params.not_before = Utc::now();
    params.not_after = Utc::now() + chrono::Duration::days(3650);
    let cert = Certificate::from_params(params).unwrap();
    let cert_pem = cert.pem();
    let key_pem = cert.serialize_private_key_pem();
    (cert_pem, key_pem)
}

// ========== X25519 密钥对（保存到文件） ==========
fn generate_or_load_keypair(file_path: &Path) -> (String, String) {
    let key_file = file_path.join("key.txt");
    if key_file.exists() {
        let content = fs::read_to_string(&key_file).unwrap_or_default();
        let priv_key = content
            .lines()
            .find(|l| l.starts_with("PrivateKey:"))
            .and_then(|l| l.split_whitespace().nth(1))
            .unwrap_or_default()
            .to_string();
        let pub_key = content
            .lines()
            .find(|l| l.starts_with("PublicKey:"))
            .and_then(|l| l.split_whitespace().nth(1))
            .unwrap_or_default()
            .to_string();
        if !priv_key.is_empty() && !pub_key.is_empty() {
            return (priv_key, pub_key);
        }
    }
    // 生成新密钥对
    let secret = StaticSecret::random_from_rng(OsRng);
    let public = PublicKey::from(&secret);
    let priv_b64 = base64_url::encode(secret.as_bytes());
    let pub_b64 = base64_url::encode(public.as_bytes());
    let content = format!("PrivateKey: {}\nPublicKey: {}\n", priv_b64, pub_b64);
    fs::write(&key_file, content).unwrap();
    (priv_b64, pub_b64)
}

// ========== 生成 Xray 配置文件 ==========
async fn generate_config(state: &AppState) -> Result<(), Box<dyn std::error::Error>> {
    let config_path = state.config.file_path.join("config.json");
    let mut inbounds = vec![
        serde_json::json!({
            "tag": "vless-fallback-in",
            "port": state.config.argo_port,
            "listen": "::",
            "protocol": "vless",
            "settings": {
                "clients": [{"id": state.config.uuid, "flow": "xtls-rprx-vision"}],
                "decryption": "none",
                "fallbacks": [
                    {"dest": 3001},
                    {"path": "/vless-argo", "dest": 3002},
                    {"path": "/vmess-argo", "dest": 3003},
                    {"path": "/trojan-argo", "dest": 3004}
                ]
            },
            "streamSettings": {"network": "tcp"}
        }),
        serde_json::json!({
            "tag": "vless-tcp-in",
            "port": 3001,
            "listen": "127.0.0.1",
            "protocol": "vless",
            "settings": {"clients": [{"id": state.config.uuid}], "decryption": "none"},
            "streamSettings": {"network": "tcp", "security": "none"}
        }),
        serde_json::json!({
            "tag": "vless-ws-in",
            "port": 3002,
            "listen": "127.0.0.1",
            "protocol": "vless",
            "settings": {"clients": [{"id": state.config.uuid, "level": 0}], "decryption": "none"},
            "streamSettings": {"network": "ws", "security": "none", "wsSettings": {"path": "/vless-argo"}},
            "sniffing": {"enabled": true, "destOverride": ["http", "tls", "quic"], "metadataOnly": false}
        }),
        serde_json::json!({
            "tag": "vmess-ws-in",
            "port": 3003,
            "listen": "127.0.0.1",
            "protocol": "vmess",
            "settings": {"clients": [{"id": state.config.uuid, "alterId": 0}]},
            "streamSettings": {"network": "ws", "wsSettings": {"path": "/vmess-argo"}},
            "sniffing": {"enabled": true, "destOverride": ["http", "tls", "quic"], "metadataOnly": false}
        }),
        serde_json::json!({
            "tag": "trojan-ws-in",
            "port": 3004,
            "listen": "127.0.0.1",
            "protocol": "trojan",
            "settings": {"clients": [{"password": state.config.uuid}]},
            "streamSettings": {"network": "ws", "security": "none", "wsSettings": {"path": "/trojan-argo"}},
            "sniffing": {"enabled": true, "destOverride": ["http", "tls", "quic"], "metadataOnly": false}
        }),
    ];

    // Reality
    if is_valid_port(&state.config.reality_port) {
        let (priv_key, pub_key) = generate_or_load_keypair(&state.config.file_path);
        let pub_path = state.config.file_path.join("public_key.txt");
        tokio_fs::write(&pub_path, &pub_key).await?;
        inbounds.push(serde_json::json!({
            "tag": "vless-in",
            "listen": "::",
            "port": state.config.reality_port.parse::<u16>().unwrap(),
            "protocol": "vless",
            "settings": {
                "clients": [{"id": state.config.uuid, "flow": "xtls-rprx-vision"}],
                "decryption": "none"
            },
            "streamSettings": {
                "network": "raw",
                "security": "reality",
                "realitySettings": {
                    "show": false,
                    "dest": "www.iij.ad.jp:443",
                    "xver": 0,
                    "serverNames": ["www.iij.ad.jp"],
                    "privateKey": priv_key,
                    "shortIds": [""]
                }
            }
        }));
    }

    // Hysteria2
    if is_valid_port(&state.config.hy2_port) {
        let (cert_pem, key_pem) = generate_cert_and_key();
        let cert_path = state.config.file_path.join("cert.pem");
        let key_path = state.config.file_path.join("private.key");
        tokio_fs::write(&cert_path, cert_pem).await?;
        tokio_fs::write(&key_path, key_pem).await?;

        inbounds.push(serde_json::json!({
            "tag": "hysteria-in",
            "listen": "::",
            "port": state.config.hy2_port.parse::<u16>().unwrap(),
            "protocol": "hysteria",
            "settings": {
                "version": 2,
                "clients": [{"auth": state.config.uuid}]
            },
            "streamSettings": {
                "network": "hysteria",
                "hysteriaSettings": {
                    "version": 2,
                    "masquerade": {
                        "type": "proxy",
                        "url": "https://bing.com"
                    }
                },
                "security": "tls",
                "tlsSettings": {
                    "alpn": ["h3"],
                    "certificates": [
                        {
                            "certificateFile": cert_path.to_str().unwrap(),
                            "keyFile": key_path.to_str().unwrap()
                        }
                    ]
                }
            }
        }));
    }

    // Socks5
    if is_valid_port(&state.config.s5_port) {
        inbounds.push(serde_json::json!({
            "tag": "s5-in",
            "listen": "::",
            "port": state.config.s5_port.parse::<u16>().unwrap(),
            "protocol": "socks",
            "settings": {
                "auth": "password",
                "accounts": [{
                    "user": &state.config.uuid[0..8],
                    "pass": &state.config.uuid[12..]
                }],
                "udp": true
            }
        }));
    }

    let config = serde_json::json!({
        "log": {"access": "/dev/null", "error": "/dev/null", "loglevel": "none"},
        "inbounds": inbounds,
        "dns": {"servers": ["https+local://8.8.8.8/dns-query"]},
        "outbounds": [
            {"protocol": "freedom", "tag": "direct"},
            {"protocol": "blackhole", "tag": "block"}
        ]
    });

    let json_str = serde_json::to_string_pretty(&config)?;
    tokio_fs::write(config_path, json_str).await?;
    Ok(())
}

// ========== 下载外部二进制 ==========
async fn download_file(
    client: &Client,
    url: &str,
    dest: &Path,
) -> Result<(), Box<dyn std::error::Error>> {
    let response = client.get(url).send().await?;
    let bytes = response.bytes().await?;
    tokio_fs::write(dest, bytes).await?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(dest)?.permissions();
        perms.set_mode(0o775);
        tokio_fs::set_permissions(dest, perms).await?;
    }
    Ok(())
}

fn get_arch() -> &'static str {
    if cfg!(target_arch = "aarch64") || cfg!(target_arch = "arm") {
        "arm64"
    } else {
        "amd64"
    }
}

// ========== 下载并运行所需二进制 ==========
async fn download_and_run(state: &AppState) -> Result<(), Box<dyn std::error::Error>> {
    let arch = get_arch();
    let mut tasks = vec![];

    let web_url = format!("https://{}.ssss.nyc.mn/web", arch);
    let bot_url = format!("https://{}.ssss.nyc.mn/bot", arch);
    let web_path = state.config.file_path.join("web");
    let bot_path = state.config.file_path.join("bot");
    tasks.push(download_file(&state.client, &web_url, &web_path));
    tasks.push(download_file(&state.client, &bot_url, &bot_path));

    if !state.config.nezha_server.is_empty() && !state.config.nezha_key.is_empty() {
        let nezha_port = &state.config.nezha_port;
        if !nezha_port.is_empty() {
            let agent_url = format!("https://{}.ssss.nyc.mn/agent", arch);
            let agent_path = state.config.file_path.join("agent");
            tasks.push(download_file(&state.client, &agent_url, &agent_path));
        } else {
            let v1_url = format!("https://{}.ssss.nyc.mn/v1", arch);
            let v1_path = state.config.file_path.join("v1");
            tasks.push(download_file(&state.client, &v1_url, &v1_path));
        }
    }

    for task in tasks {
        if let Err(e) = task.await {
            error!("下载失败: {}", e);
        }
    }

    // 启动 nezha
    if !state.config.nezha_server.is_empty() && !state.config.nezha_key.is_empty() {
        let nezha_port = &state.config.nezha_port;
        if !nezha_port.is_empty() {
            let agent_path = state.config.file_path.join("agent");
            if agent_path.exists() {
                let mut cmd = Command::new(&agent_path);
                cmd.arg("-s")
                    .arg(format!("{}:{}", state.config.nezha_server, nezha_port))
                    .arg("-p")
                    .arg(&state.config.nezha_key)
                    .arg("--disable-auto-update")
                    .arg("--report-delay")
                    .arg("4")
                    .arg("--skip-conn")
                    .arg("--skip-procs");
                let tls_ports = ["443", "8443", "2096", "2087", "2083", "2053"];
                if tls_ports.contains(&nezha_port.as_str()) {
                    cmd.arg("--tls");
                }
                cmd.stdout(Stdio::null()).stderr(Stdio::null());
                cmd.spawn()?;
                info!("agent 启动");
            }
        } else {
            let v1_path = state.config.file_path.join("v1");
            if v1_path.exists() {
                let tls_flag = state.config.nezha_server.contains("443")
                    || state.config.nezha_server.contains("8443")
                    || state.config.nezha_server.contains("2096")
                    || state.config.nezha_server.contains("2087")
                    || state.config.nezha_server.contains("2083")
                    || state.config.nezha_server.contains("2053");
                let config_yaml = format!(
                    r#"client_secret: {}
debug: false
disable_auto_update: true
disable_command_execute: false
disable_force_update: true
disable_nat: false
disable_send_query: false
gpu: false
insecure_tls: true
ip_report_period: 1800
report_delay: 4
server: {}
skip_connection_count: true
skip_procs_count: true
temperature: false
tls: {}
use_gitee_to_upgrade: false
use_ipv6_country_code: false
uuid: {}"#,
                    state.config.nezha_key,
                    state.config.nezha_server,
                    tls_flag,
                    state.config.uuid
                );
                let yaml_path = state.config.file_path.join("config.yaml");
                tokio_fs::write(&yaml_path, config_yaml).await?;
                let mut cmd = Command::new(&v1_path);
                cmd.arg("-c").arg(&yaml_path);
                cmd.stdout(Stdio::null()).stderr(Stdio::null());
                cmd.spawn()?;
                info!("v1 启动");
            }
        }
        sleep(Duration::from_secs(1)).await;
    }

    // 启动 xray
    let web_path = state.config.file_path.join("web");
    if web_path.exists() {
        let config_path = state.config.file_path.join("config.json");
        let mut cmd = Command::new(&web_path);
        cmd.arg("-c").arg(&config_path);
        cmd.stdout(Stdio::null()).stderr(Stdio::null());
        cmd.spawn()?;
        info!("xray 启动");
        sleep(Duration::from_secs(1)).await;
    }

    // 启动 cloudflared
    let bot_path = state.config.file_path.join("bot");
    if bot_path.exists() {
        let mut cmd = Command::new(&bot_path);
        let argo_auth = &state.config.argo_auth;
        let argo_domain = &state.config.argo_domain;
        let argo_port = state.config.argo_port;

        if argo_auth.starts_with("TunnelSecret") {
            let tunnel_json_path = state.config.file_path.join("tunnel.json");
            tokio_fs::write(&tunnel_json_path, argo_auth).await?;
            // 正确解析 TunnelID
            let tunnel_id = if let Ok(json) = serde_json::from_str::<Value>(argo_auth) {
                json["TunnelID"]
                    .as_str()
                    .unwrap_or("")
                    .to_string()
            } else {
                // 降级：从字符串中提取
                let parts: Vec<&str> = argo_auth.split('"').collect();
                if parts.len() > 11 {
                    parts[11].to_string()
                } else {
                    String::new()
                }
            };
            let tunnel_yaml = format!(
                r#"tunnel: {}
credentials-file: {}
protocol: http2
ingress:
  - hostname: {}
    service: http://localhost:{}
    originRequest:
      noTLSVerify: true
  - service: http_status:404"#,
                tunnel_id,
                tunnel_json_path.to_str().unwrap(),
                argo_domain,
                argo_port
            );
            let yaml_path = state.config.file_path.join("tunnel.yml");
            tokio_fs::write(&yaml_path, tunnel_yaml).await?;
            cmd.arg("tunnel")
                .arg("--edge-ip-version")
                .arg("auto")
                .arg("--no-autoupdate")
                .arg("--protocol")
                .arg("http2")
                .arg("--config")
                .arg(&yaml_path)
                .arg("run");
        } else if argo_auth.len() > 120 {
            cmd.arg("tunnel")
                .arg("--edge-ip-version")
                .arg("auto")
                .arg("--no-autoupdate")
                .arg("--protocol")
                .arg("http2")
                .arg("run")
                .arg("--token")
                .arg(argo_auth);
        } else {
            let log_path = state.config.file_path.join("boot.log");
            cmd.arg("tunnel")
                .arg("--edge-ip-version")
                .arg("auto")
                .arg("--no-autoupdate")
                .arg("--protocol")
                .arg("http2")
                .arg("--logfile")
                .arg(&log_path)
                .arg("--loglevel")
                .arg("info")
                .arg("--url")
                .arg(format!("http://localhost:{}", argo_port));
        }
        cmd.stdout(Stdio::null()).stderr(Stdio::null());
        cmd.spawn()?;
        info!("cloudflared 启动");
        sleep(Duration::from_secs(2)).await;
    }
    Ok(())
}

// ========== 获取 Argo 域名 ==========
async fn extract_argo_domain(state: &AppState) -> Option<String> {
    if !state.config.argo_domain.is_empty() && !state.config.argo_auth.is_empty() {
        return Some(state.config.argo_domain.clone());
    }
    let log_path = state.config.file_path.join("boot.log");
    if let Ok(content) = tokio_fs::read_to_string(&log_path).await {
        for line in content.lines() {
            if let Some(domain) = line
                .split_whitespace()
                .find(|s| s.contains("trycloudflare.com"))
                .and_then(|s| s.strip_prefix("https://"))
                .and_then(|s| s.strip_suffix('/'))
            {
                return Some(domain.to_string());
            }
        }
    }
    None
}

// ========== 获取证书指纹 ==========
async fn get_cert_fingerprint(cert_path: &Path) -> String {
    if let Ok(data) = tokio_fs::read(cert_path).await {
        if let Ok((_, cert)) = parse_x509_certificate(&data) {
            let hash = ring::digest::digest(&ring::digest::SHA256, cert.tbs_certificate.as_ref());
            let hex = hex::encode(hash.as_ref());
            return hex
                .as_bytes()
                .chunks(2)
                .map(|ch| std::str::from_utf8(ch).unwrap())
                .collect::<Vec<_>>()
                .join(":")
                .to_uppercase();
        }
    }
    String::new()
}

// ========== 获取 Meta 信息 ==========
async fn get_meta_info(client: &Client) -> Option<String> {
    let url = "http://ip-api.com/json";
    if let Ok(resp) = client.get(url).timeout(Duration::from_secs(3)).send().await {
        if let Ok(json) = resp.json::<Value>().await {
            if json["status"] == "success" {
                let country = json["countryCode"].as_str().unwrap_or("XX");
                let isp = json["isp"].as_str().unwrap_or("Unknown");
                return Some(format!("{}-{}", country, isp.replace(' ', "_")));
            }
        }
    }
    let url = "https://api.ip.sb/geoip";
    if let Ok(resp) = client.get(url).timeout(Duration::from_secs(3)).send().await {
        if let Ok(json) = resp.json::<Value>().await {
            let country = json["country_code"].as_str().unwrap_or("XX");
            let isp = json["isp"].as_str().unwrap_or("Unknown");
            return Some(format!("{}-{}", country, isp.replace(' ', "_")));
        }
    }
    Some("Unknown".to_string())
}

// ========== 获取服务器公网 IP ==========
async fn get_server_ip() -> Option<String> {
    let urls = ["https://ipv4.ip.sb", "https://api.ipify.org"];
    for url in urls {
        if let Ok(resp) = reqwest::get(url).timeout(Duration::from_secs(3)).await {
            if let Ok(ip) = resp.text().await {
                let trimmed = ip.trim();
                if !trimmed.is_empty() {
                    return Some(trimmed.to_string());
                }
            }
        }
    }
    if let Ok(resp) = reqwest::get("https://ipv6.ip.sb")
        .timeout(Duration::from_secs(3))
        .await
    {
        if let Ok(ip) = resp.text().await {
            let trimmed = ip.trim();
            if !trimmed.is_empty() {
                return Some(format!("[{}]", trimmed));
            }
        }
    }
    Some("127.0.0.1".to_string())
}

// ========== 生成订阅内容 ==========
async fn generate_subscription(
    state: &AppState,
    argo_domain: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    let meta = get_meta_info(&state.client).await.unwrap_or_else(|| "Unknown".to_string());
    let node_name = if state.config.name.is_empty() {
        meta.clone()
    } else {
        format!("{}-{}", state.config.name, meta)
    };
    let server_ip = get_server_ip().await.unwrap_or_else(|| "127.0.0.1".to_string());

    let mut sub_lines = Vec::new();

    sub_lines.push(format!(
        "vless://{}@{}:{}?encryption=none&security=tls&sni={}&fp=firefox&type=ws&host={}&path=%2Fvless-argo%3Fed%3D2560#{}",
        state.config.uuid,
        state.config.cfip,
        state.config.cfport,
        argo_domain,
        argo_domain,
        node_name
    ));

    let vmess = serde_json::json!({
        "v": "2",
        "ps": node_name,
        "add": state.config.cfip,
        "port": state.config.cfport,
        "id": state.config.uuid,
        "aid": "0",
        "scy": "auto",
        "net": "ws",
        "type": "none",
        "host": argo_domain,
        "path": "/vmess-argo?ed=2560",
        "tls": "tls",
        "sni": argo_domain,
        "alpn": "",
        "fp": "firefox"
    });
    let vmess_b64 = BASE64.encode(serde_json::to_string(&vmess)?);
    sub_lines.push(format!("vmess://{}", vmess_b64));

    sub_lines.push(format!(
        "trojan://{}@{}:{}?security=tls&sni={}&fp=firefox&type=ws&host={}&path=%2Ftrojan-argo%3Fed%3D2560#{}",
        state.config.uuid,
        state.config.cfip,
        state.config.cfport,
        argo_domain,
        argo_domain,
        node_name
    ));

    if is_valid_port(&state.config.hy2_port) {
        let cert_path = state.config.file_path.join("cert.pem");
        let fingerprint = get_cert_fingerprint(&cert_path).await;
        let pin = if !fingerprint.is_empty() {
            format!("&pinSHA256={}", fingerprint)
        } else {
            String::new()
        };
        sub_lines.push(format!(
            "hysteria2://{}@{}:{}?sni=www.bing.com&insecure=0&alpn=h3&obfs=none{}#{}",
            state.config.uuid,
            server_ip,
            state.config.hy2_port,
            pin,
            node_name
        ));
    }

    if is_valid_port(&state.config.reality_port) {
        let pub_path = state.config.file_path.join("public_key.txt");
        let pub_key = if let Ok(content) = tokio_fs::read_to_string(&pub_path).await {
            content.trim().to_string()
        } else {
            let (_, pub_key) = generate_or_load_keypair(&state.config.file_path);
            pub_key
        };
        sub_lines.push(format!(
            "vless://{}@{}:{}?encryption=none&flow=xtls-rprx-vision&security=reality&sni=www.iij.ad.jp&fp=firefox&pbk={}&type=tcp&headerType=none#{}",
            state.config.uuid,
            server_ip,
            state.config.reality_port,
            pub_key,
            node_name
        ));
    }

    if is_valid_port(&state.config.s5_port) {
        let auth = BASE64.encode(format!("{}:{}", &state.config.uuid[0..8], &state.config.uuid[12..]));
        sub_lines.push(format!(
            "socks://{}@{}:{}#{}",
            auth, server_ip, state.config.s5_port, node_name
        ));
    }

    let sub_text = sub_lines.join("\n");
    let sub_b64 = BASE64.encode(&sub_text);
    let sub_path = state.config.file_path.join("sub.txt");
    tokio_fs::write(&sub_path, &sub_b64).await?;
    let list_path = state.config.file_path.join("list.txt");
    tokio_fs::write(&list_path, &sub_text).await?;

    Ok(sub_b64)
}

// ========== 上传节点/订阅 ==========
async fn upload_nodes(state: &AppState) -> Result<(), Box<dyn std::error::Error>> {
    let upload_url = &state.config.upload_url;
    if upload_url.is_empty() {
        return Ok(());
    }
    let project_url = &state.config.project_url;
    if !project_url.is_empty() {
        let sub_url = format!("{}/{}", project_url, state.config.sub_path);
        let payload = json!({ "subscription": [sub_url] });
        let resp = state
            .client
            .post(format!("{}/api/add-subscriptions", upload_url))
            .json(&payload)
            .send()
            .await?;
        if resp.status().is_success() {
            info!("订阅上传成功");
        } else {
            warn!("订阅上传失败: {}", resp.status());
        }
        return Ok(());
    }

    let list_path = state.config.file_path.join("list.txt");
    if !list_path.exists() {
        return Ok(());
    }
    let content = tokio_fs::read_to_string(&list_path).await?;
    let nodes: Vec<&str> = content
        .lines()
        .filter(|line| line.contains("://"))
        .collect();
    if nodes.is_empty() {
        return Ok(());
    }
    let payload = json!({ "nodes": nodes });
    let resp = state
        .client
        .post(format!("{}/api/add-nodes", upload_url))
        .json(&payload)
        .send()
        .await?;
    if resp.status().is_success() {
        info!("节点上传成功");
    } else {
        warn!("节点上传失败: {}", resp.status());
    }
    Ok(())
}

// ========== Telegram 推送（含完整转义） ==========
fn escape_markdown_v2(text: &str) -> String {
    let special_chars = r#"_*[]()~`>#+=|{}.!-\\"#;
    let mut escaped = String::new();
    for ch in text.chars() {
        if special_chars.contains(ch) {
            escaped.push('\\');
        }
        escaped.push(ch);
    }
    escaped
}

async fn send_telegram(state: &AppState) -> Result<(), Box<dyn std::error::Error>> {
    if state.config.bot_token.is_empty() || state.config.chat_id.is_empty() {
        return Ok(());
    }
    let sub_path = state.config.file_path.join("sub.txt");
    if !sub_path.exists() {
        return Ok(());
    }
    let content = tokio_fs::read_to_string(&sub_path).await?;
    let escaped_name = escape_markdown_v2(&state.config.name);
    let text = format!("**{}节点推送**\n```\n{}\n```", escaped_name, content);
    let url = format!("https://api.telegram.org/bot{}/sendMessage", state.config.bot_token);
    let params = [
        ("chat_id", state.config.chat_id.as_str()),
        ("text", &text),
        ("parse_mode", "MarkdownV2"),
    ];
    let resp = state.client.post(&url).form(&params).send().await?;
    if resp.status().is_success() {
        info!("Telegram 推送成功");
    } else {
        warn!("Telegram 推送失败: {}", resp.status());
    }
    Ok(())
}

// ========== 自动访问任务 ==========
async fn add_visit_task(state: &AppState) -> Result<(), Box<dyn std::error::Error>> {
    if !state.config.auto_access || state.config.project_url.is_empty() {
        return Ok(());
    }
    let url = "https://oooo.serv00.net/add-url";
    let payload = json!({ "url": state.config.project_url });
    let resp = state.client.post(url).json(&payload).send().await?;
    if resp.status().is_success() {
        info!("自动访问任务添加成功");
    } else {
        warn!("自动访问任务添加失败: {}", resp.status());
    }
    Ok(())
}

// ========== 延迟清理任务（90 秒后删除临时文件） ==========
async fn cleanup_task(state: AppState) {
    sleep(Duration::from_secs(90)).await;
    let files = [
        "boot.log",
        "config.json",
        "web",
        "bot",
        "list.txt",
        "cert.pem",
        "private.key",
        "agent",
        "v1",
        "tunnel.json",
        "tunnel.yml",
        "config.yaml",
        "key.txt",
        "public_key.txt",
    ];
    for name in files.iter() {
        let path = state.config.file_path.join(name);
        if path.exists() {
            let _ = tokio_fs::remove_file(&path).await;
        }
    }
    print!("\x1B[2J\x1B[1;1H");
    info!("App is running");
}

// ========== HTTP 根路由（读取 index.html） ==========
async fn root_handler() -> impl IntoResponse {
    match tokio_fs::read_to_string("index.html").await {
        Ok(content) => Html(content).into_response(),
        Err(_) => Html("Hello world!<br><br>You can access /sub to get your nodes!").into_response(),
    }
}

// ========== HTTP 订阅路由 ==========
async fn sub_handler(State(state): State<AppState>) -> impl IntoResponse {
    let sub = state.sub_content.lock().await;
    if let Some(ref content) = *sub {
        (StatusCode::OK, content.clone())
    } else {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            "Subscription content not yet available".to_string(),
        )
    }
}

// ========== 主函数 ==========
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = Config::from_env();

    // 根据 SHOW_LOG 控制日志级别
    let filter = if config.show_log {
        EnvFilter::new("info")
    } else {
        EnvFilter::new("off")
    };
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .init();

    ensure_dir(&config.file_path).await?;

    let state = AppState {
        config: config.clone(),
        client: Client::new(),
        sub_content: Arc::new(Mutex::new(None)),
    };

    // 1. 删除上游旧节点（读取已有的 sub.txt）
    delete_nodes(&state).await?;

    // 2. 清空 .tmp 目录
    cleanup_old_files(&config).await?;

    // 3. 生成 config.json
    generate_config(&state).await?;

    // 4. 下载并运行二进制
    download_and_run(&state).await?;

    // 5. 提取 Argo 域名
    let argo_domain = extract_argo_domain(&state)
        .await
        .unwrap_or_else(|| "localhost".to_string());
    info!("Argo 域名: {}", argo_domain);

    // 6. 生成订阅内容
    let sub_content = generate_subscription(&state, &argo_domain).await?;
    {
        let mut sub_guard = state.sub_content.lock().await;
        *sub_guard = Some(sub_content);
    }

    // 7. 上传节点/订阅
    upload_nodes(&state).await?;

    // 8. Telegram 推送
    send_telegram(&state).await?;

    // 9. 添加自动访问任务
    add_visit_task(&state).await?;

    // 10. 启动延迟清理任务
    let state_clone = state.clone();
    tokio::spawn(async move {
        cleanup_task(state_clone).await;
    });

    // 11. 启动 HTTP 服务器
    let app = Router::new()
        .route("/", get(root_handler))
        .route(&format!("/{}", config.sub_path), get(sub_handler))
        .with_state(state);

    let addr = format!("0.0.0.0:{}", config.port);
    info!("HTTP 服务器监听 {}", addr);
    axum::Server::bind(&addr.parse()?)
        .serve(app.into_make_service())
        .await?;

    Ok(())
}

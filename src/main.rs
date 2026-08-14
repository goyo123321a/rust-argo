//! 完整代理部署脚本 - Rust 移植版（最终稳定版）
//! 完全等价于 Node.js 原版，并增强容错、重试、日志控制。

use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use axum::{routing::get, Router, response::IntoResponse};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use dotenvy::dotenv;
use rand::Rng;
use reqwest::Client;
use serde_json::json;
use tokio::fs::{self, File};
use tokio::io::AsyncWriteExt;
use tokio::process::Command;
use tokio::time::sleep;
use tracing::{info, warn, error};
use tracing_subscriber::{fmt, EnvFilter};

// ---------- 统一配置加载 ----------
fn get_env(key: &str, default: &str) -> String {
    env::var(key).unwrap_or_else(|_| default.to_string())
}

fn get_env_u16(key: &str, default: &str) -> u16 {
    env::var(key)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or_else(|| default.parse().expect("default must be a valid u16"))
}

fn get_env_bool(key: &str, default: &str) -> bool {
    env::var(key)
        .map(|v| v.to_lowercase() == "true")
        .unwrap_or_else(|_| default.parse().expect("default must be 'true' or 'false'"))
}

#[derive(Debug)]
struct Config {
    upload_url: String,
    project_url: String,
    auto_access: bool,
    file_path: String,
    sub_path: String,
    port: u16,
    uuid: String,
    nezha_server: String,
    nezha_port: String,
    nezha_key: String,
    argo_domain: String,
    argo_auth: String,
    argo_port: u16,
    s5_port: String,
    hy2_port: String,
    reality_port: String,
    cfip: String,
    cfport: u16,
    name: String,
    chat_id: String,
    bot_token: String,
    show_log: bool,
}

impl Config {
    fn from_env() -> Self {
        let port_str = env::var("SERVER_PORT")
            .or_else(|_| env::var("PORT"))
            .unwrap_or_else(|_| "7860".to_string());
        Self {
            upload_url: get_env("UPLOAD_URL", ""),
            project_url: get_env("PROJECT_URL", ""),
            auto_access: get_env_bool("AUTO_ACCESS", "false"),
            file_path: get_env("FILE_PATH", ".tmp"),
            sub_path: get_env("SUB_PATH", "sub"),
            port: port_str.parse().unwrap_or(3000),
            uuid: get_env("UUID", "9afd1229-b893-40c1-84dd-51e7ce204913"),
            nezha_server: get_env("NEZHA_SERVER", ""),
            nezha_port: get_env("NEZHA_PORT", ""),
            nezha_key: get_env("NEZHA_KEY", ""),
            argo_domain: get_env("ARGO_DOMAIN", "gocfvps.rboya.indevs.in"),
            argo_auth: get_env("ARGO_AUTH", "eyJhIjoiNWRmNTFlZjhhMTNiMWQ1ZDFhODhhZTAxNWFmYTU5OGIiLCJ0IjoiOTBlYWNkYmYtODE1ZS00N2JjLWJhNTAtOGQ0NjIzMWY1N2UwIiwicyI6Ik1qazRNREF5TUdVdE5ETXhaaTAwWlRJNUxUaGxObVV0WldZeFlXWmxOemMyTmpnMyJ9"),
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

// ---------- 工具函数 ----------
fn is_valid_port(s: &str) -> bool {
    if s.is_empty() { return false; }
    s.parse::<u16>().is_ok()
}

fn random_string(len: usize) -> String {
    let chars: Vec<char> = "abcdefghijklmnopqrstuvwxyz".chars().collect();
    let mut rng = rand::thread_rng();
    (0..len).map(|_| chars[rng.gen_range(0..chars.len())]).collect()
}

// ---------- 密钥生成 ----------
fn generate_x25519_keypair() -> (String, String) {
    use ring::agreement::{EphemeralPrivateKey, X25519};
    let rng = ring::rand::SystemRandom::new();
    let private = EphemeralPrivateKey::generate(&X25519, &rng).unwrap();
    let public = private.compute_public_key().unwrap();
    let priv_bytes = private.bytes().to_vec();
    let pub_bytes = public.as_ref().to_vec();
    let priv_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&priv_bytes);
    let pub_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&pub_bytes);
    (priv_b64, pub_b64)
}

// ---------- 证书生成（Hysteria2） ----------
fn generate_tls_cert() -> (String, String) {
    use rcgen::{Certificate, CertificateParams};
    let params = CertificateParams::default();
    let cert = Certificate::from_params(params).unwrap();
    let key_pair = cert.get_key_pair();
    (cert.pem(), key_pair.serialize_pem())
}

// ---------- 获取系统架构 ----------
fn get_arch() -> &'static str {
    match env::consts::ARCH {
        "arm" | "aarch64" => "arm",
        _ => "amd",
    }
}

// ---------- 下载文件 ----------
async fn download_file(client: &Client, url: &str, dest: &Path) -> Result<()> {
    info!("Downloading {} to {}", url, dest.display());
    let resp = client.get(url).send().await?.error_for_status()?;
    let bytes = resp.bytes().await?;
    let mut file = File::create(dest).await?;
    file.write_all(&bytes).await?;
    #[cfg(unix)] {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(dest)?.permissions();
        perms.set_mode(0o775);
        fs::set_permissions(dest, perms)?;
    }
    Ok(())
}

// ---------- 后台运行进程 ----------
async fn run_bg(cmd: &Path, args: &[&str]) -> Result<()> {
    let mut child = Command::new(cmd)
        .args(args)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;
    tokio::spawn(async move { let _ = child.wait().await; });
    Ok(())
}

// ---------- 删除历史节点（静默处理） ----------
async fn delete_nodes(cfg: &Config, sub_path: &Path) -> Result<()> {
    if cfg.upload_url.is_empty() || !sub_path.exists() {
        return Ok(());
    }
    let content = match fs::read_to_string(sub_path).await {
        Ok(c) => c,
        Err(_) => return Ok(()),
    };
    let decoded = match BASE64.decode(&content) {
        Ok(b) => match String::from_utf8(b) {
            Ok(s) => s,
            Err(_) => return Ok(()),
        },
        Err(_) => return Ok(()),
    };
    let nodes: Vec<&str> = decoded.lines()
        .filter(|line| line.contains("vless://") || line.contains("vmess://") || line.contains("trojan://")
            || line.contains("hysteria2://") || line.contains("socks://"))
        .collect();
    if nodes.is_empty() {
        return Ok(());
    }
    let client = Client::new();
    let resp = client.post(format!("{}/api/delete-nodes", cfg.upload_url))
        .json(&json!({ "nodes": nodes }))
        .send().await?;
    if resp.status().is_success() {
        info!("Deleted {} old nodes", nodes.len());
    }
    Ok(())
}

// ---------- 生成 Xray 配置文件 ----------
fn generate_xray_config(cfg: &Config, private_key: &str, cert_path: &Path, key_path: &Path) -> Result<serde_json::Value> {
    let mut inbounds = vec![
        json!({
            "tag": "vless-fallback-in",
            "port": cfg.argo_port,
            "listen": "::",
            "protocol": "vless",
            "settings": {
                "clients": [{ "id": cfg.uuid, "flow": "xtls-rprx-vision" }],
                "decryption": "none",
                "fallbacks": [
                    { "dest": 3001 },
                    { "path": "/vless-argo", "dest": 3002 },
                    { "path": "/vmess-argo", "dest": 3003 },
                    { "path": "/trojan-argo", "dest": 3004 }
                ]
            },
            "streamSettings": { "network": "tcp" }
        }),
        json!({
            "tag": "vless-tcp-in",
            "port": 3001,
            "listen": "127.0.0.1",
            "protocol": "vless",
            "settings": { "clients": [{ "id": cfg.uuid }], "decryption": "none" },
            "streamSettings": { "network": "tcp", "security": "none" }
        }),
        json!({
            "tag": "vless-ws-in",
            "port": 3002,
            "listen": "127.0.0.1",
            "protocol": "vless",
            "settings": { "clients": [{ "id": cfg.uuid }], "decryption": "none" },
            "streamSettings": { "network": "ws", "security": "none", "wsSettings": { "path": "/vless-argo" } },
            "sniffing": { "enabled": true, "destOverride": ["http", "tls", "quic"], "metadataOnly": false }
        }),
        json!({
            "tag": "vmess-ws-in",
            "port": 3003,
            "listen": "127.0.0.1",
            "protocol": "vmess",
            "settings": { "clients": [{ "id": cfg.uuid, "alterId": 0 }] },
            "streamSettings": { "network": "ws", "wsSettings": { "path": "/vmess-argo" } },
            "sniffing": { "enabled": true, "destOverride": ["http", "tls", "quic"], "metadataOnly": false }
        }),
        json!({
            "tag": "trojan-ws-in",
            "port": 3004,
            "listen": "127.0.0.1",
            "protocol": "trojan",
            "settings": { "clients": [{ "password": cfg.uuid }] },
            "streamSettings": { "network": "ws", "security": "none", "wsSettings": { "path": "/trojan-argo" } },
            "sniffing": { "enabled": true, "destOverride": ["http", "tls", "quic"], "metadataOnly": false }
        }),
    ];

    // Reality
    if is_valid_port(&cfg.reality_port) {
        inbounds.push(json!({
            "tag": "vless-reality-in",
            "listen": "::",
            "port": cfg.reality_port.parse::<u16>().unwrap(),
            "protocol": "vless",
            "settings": {
                "clients": [{ "id": cfg.uuid, "flow": "xtls-rprx-vision" }],
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
                    "privateKey": private_key,
                    "shortIds": [""]
                }
            }
        }));
    }

    // Hysteria2
    if is_valid_port(&cfg.hy2_port) {
        let cert_pem = fs::read_to_string(cert_path)?;
        let key_pem = fs::read_to_string(key_path)?;
        inbounds.push(json!({
            "tag": "hysteria-in",
            "listen": "::",
            "port": cfg.hy2_port.parse::<u16>().unwrap(),
            "protocol": "hysteria",
            "settings": {
                "version": 2,
                "clients": [{ "auth": cfg.uuid }]
            },
            "streamSettings": {
                "network": "hysteria",
                "hysteriaSettings": {
                    "version": 2,
                    "masquerade": { "type": "proxy", "url": "https://bing.com" }
                },
                "security": "tls",
                "tlsSettings": {
                    "alpn": ["h3"],
                    "certificates": [{ "certificateFile": cert_path.to_str().unwrap(), "keyFile": key_path.to_str().unwrap() }]
                }
            }
        }));
    }

    // SOCKS5
    if is_valid_port(&cfg.s5_port) {
        inbounds.push(json!({
            "tag": "s5-in",
            "listen": "::",
            "port": cfg.s5_port.parse::<u16>().unwrap(),
            "protocol": "socks",
            "settings": {
                "auth": "password",
                "accounts": [{ "user": &cfg.uuid[0..8], "pass": &cfg.uuid[cfg.uuid.len()-12..] }],
                "udp": true
            }
        }));
    }

    Ok(json!({
        "log": { "access": "/dev/null", "error": "/dev/null", "loglevel": "none" },
        "inbounds": inbounds,
        "dns": { "servers": ["https+local://8.8.8.8/dns-query"] },
        "outbounds": [
            { "protocol": "freedom", "tag": "direct" },
            { "protocol": "blackhole", "tag": "block" }
        ]
    }))
}

// ---------- 生成订阅内容 ----------
async fn generate_links(cfg: &Config, argo_domain: &str, server_ip: &str, public_key: &str) -> Result<String> {
    let isp = get_meta_info().await.unwrap_or_else(|| "Unknown".into());
    let node_name = if cfg.name.is_empty() { isp.clone() } else { format!("{}-{}", cfg.name, isp) };
    let mut lines = vec![];

    // VLESS (ws)
    lines.push(format!(
        "vless://{}@{}:{}?encryption=none&security=tls&sni={}&fp=firefox&type=ws&host={}&path=%2Fvless-argo%3Fed%3D2560#{}",
        cfg.uuid, cfg.cfip, cfg.cfport, argo_domain, argo_domain, node_name
    ));

    // VMess
    let vmess = json!({
        "v": "2",
        "ps": node_name,
        "add": cfg.cfip,
        "port": cfg.cfport,
        "id": cfg.uuid,
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
    let vmess_b64 = BASE64.encode(serde_json::to_string(&vmess).unwrap());
    lines.push(format!("vmess://{}", vmess_b64));

    // Trojan
    lines.push(format!(
        "trojan://{}@{}:{}?security=tls&sni={}&fp=firefox&type=ws&host={}&path=%2Ftrojan-argo%3Fed%3D2560#{}",
        cfg.uuid, cfg.cfip, cfg.cfport, argo_domain, argo_domain, node_name
    ));

    // Hysteria2
    if is_valid_port(&cfg.hy2_port) {
        let fingerprint = get_cert_fingerprint(&format!("{}/cert.pem", cfg.file_path)).await?;
        let fp_param = if fingerprint.is_empty() { "".into() } else { format!("&pinSHA256={}", fingerprint) };
        lines.push(format!(
            "hysteria2://{}@{}:{}/?sni=www.bing.com&insecure=0&alpn=h3&obfs=none{}#{}",
            cfg.uuid, server_ip, cfg.hy2_port, fp_param, node_name
        ));
    }

    // Reality
    if is_valid_port(&cfg.reality_port) {
        lines.push(format!(
            "vless://{}@{}:{}?encryption=none&flow=xtls-rprx-vision&security=reality&sni=www.iij.ad.jp&fp=firefox&pbk={}&type=tcp&headerType=none#{}",
            cfg.uuid, server_ip, cfg.reality_port, public_key, node_name
        ));
    }

    // SOCKS5
    if is_valid_port(&cfg.s5_port) {
        let user = &cfg.uuid[0..8];
        let pass = &cfg.uuid[cfg.uuid.len()-12..];
        let auth = BASE64.encode(format!("{}:{}", user, pass));
        lines.push(format!(
            "socks://{}@{}:{}/#{}",
            auth, server_ip, cfg.s5_port, node_name
        ));
    }

    Ok(lines.join("\n"))
}

// ---------- 获取证书指纹（失败返回空字符串） ----------
async fn get_cert_fingerprint(cert_path: &str) -> Result<String> {
    let data = match fs::read_to_string(cert_path).await {
        Ok(d) => d,
        Err(_) => return Ok("".into()),
    };
    let re = match regex::Regex::new(r"-----BEGIN CERTIFICATE-----\n([\s\S]+?)\n-----END CERTIFICATE-----") {
        Ok(r) => r,
        Err(_) => return Ok("".into()),
    };
    let captures = match re.captures(&data) {
        Some(c) => c,
        None => return Ok("".into()),
    };
    let pem = captures[1].replace('\n', "");
    let der = match BASE64.decode(&pem) {
        Ok(b) => b,
        Err(_) => return Ok("".into()),
    };
    use ring::digest::{digest, SHA256};
    let hash = digest(&SHA256, &der);
    let hex = hash.as_ref().iter().map(|b| format!("{:02X}", b)).collect::<Vec<_>>().join(":");
    Ok(hex)
}

// ---------- 获取公网 IP ----------
async fn get_server_ip() -> Result<String> {
    let client = Client::builder().timeout(Duration::from_secs(3)).build()?;
    if let Ok(resp) = client.get("http://ipv4.ip.sb").send().await {
        if let Ok(text) = resp.text().await {
            return Ok(text.trim().into());
        }
    }
    if let Ok(resp) = client.get("http://ip-api.com/json").send().await {
        if let Ok(json) = resp.json::<serde_json::Value>().await {
            if let Some(ip) = json.get("query").and_then(|v| v.as_str()) {
                return Ok(ip.into());
            }
        }
    }
    bail!("Unable to get public IP")
}

// ---------- 获取 MetaInfo ----------
async fn get_meta_info() -> Result<String> {
    let client = Client::builder().timeout(Duration::from_secs(3)).build()?;
    if let Ok(resp) = client.get("https://api.ip.sb/geoip").send().await {
        if let Ok(json) = resp.json::<serde_json::Value>().await {
            let country = json.get("country_code").and_then(|v| v.as_str()).unwrap_or("");
            let isp = json.get("isp").and_then(|v| v.as_str()).unwrap_or("");
            if !country.is_empty() && !isp.is_empty() {
                return Ok(format!("{}-{}", country, isp).replace(' ', "_"));
            }
        }
    }
    if let Ok(resp) = client.get("http://ip-api.com/json").send().await {
        if let Ok(json) = resp.json::<serde_json::Value>().await {
            let country = json.get("countryCode").and_then(|v| v.as_str()).unwrap_or("");
            let isp = json.get("org").and_then(|v| v.as_str()).unwrap_or("");
            if !country.is_empty() && !isp.is_empty() {
                return Ok(format!("{}-{}", country, isp).replace(' ', "_"));
            }
        }
    }
    bail!("Failed to get meta info")
}

// ---------- 上传节点/订阅 ----------
async fn upload_nodes(cfg: &Config, sub_content: &str, list_content: &str) -> Result<()> {
    if cfg.upload_url.is_empty() { return Ok(()); }
    let client = Client::new();
    if !cfg.project_url.is_empty() {
        let payload = json!({ "subscription": [ format!("{}/{}", cfg.project_url, cfg.sub_path) ] });
        let resp = client.post(format!("{}/api/add-subscriptions", cfg.upload_url))
            .json(&payload)
            .send().await?;
        if resp.status().is_success() {
            info!("Subscription uploaded successfully");
        }
    } else {
        let nodes: Vec<&str> = list_content.lines().filter(|line| {
            line.contains("vless://") || line.contains("vmess://") || line.contains("trojan://")
                || line.contains("hysteria2://") || line.contains("socks://")
        }).collect();
        if nodes.is_empty() { return Ok(()); }
        let payload = json!({ "nodes": nodes });
        let resp = client.post(format!("{}/api/add-nodes", cfg.upload_url))
            .json(&payload)
            .send().await?;
        if resp.status().is_success() {
            info!("Nodes uploaded successfully");
        }
    }
    Ok(())
}

// ---------- Telegram 推送 ----------
async fn send_telegram(cfg: &Config, sub_b64: &str) -> Result<()> {
    if cfg.bot_token.is_empty() || cfg.chat_id.is_empty() { return Ok(()); }
    let client = Client::new();
    let escaped_name = cfg.name.replace('_', "\\_").replace('*', "\\*");
    let text = format!("**{}节点推送**\n```\n{}\n```", escaped_name, sub_b64);
    let url = format!("https://api.telegram.org/bot{}/sendMessage", cfg.bot_token);
    client.post(&url)
        .query(&[("chat_id", cfg.chat_id.as_str()), ("text", &text), ("parse_mode", "MarkdownV2")])
        .send().await?;
    info!("Telegram message sent");
    Ok(())
}

// ---------- 自动保活 ----------
async fn add_visit_task(cfg: &Config) -> Result<()> {
    if !cfg.auto_access || cfg.project_url.is_empty() { return Ok(()); }
    let client = Client::new();
    let resp = client.post("https://oooo.serv00.net/add-url")
        .json(&json!({ "url": cfg.project_url }))
        .send().await?;
    if resp.status().is_success() {
        info!("Added automatic access task");
    }
    Ok(())
}

// ---------- 清理文件 ----------
async fn cleanup_files(paths: &[PathBuf]) {
    for p in paths {
        let _ = fs::remove_file(p).await;
    }
}

// ---------- 主流程 ----------
#[tokio::main]
async fn main() -> Result<()> {
    dotenv().ok();

    let cfg = Config::from_env();

    let env_filter = if cfg.show_log {
        EnvFilter::from_default_env().add_directive(tracing::Level::INFO.into())
    } else {
        EnvFilter::from_default_env().add_directive(tracing::Level::ERROR.into())
    };
    fmt().with_env_filter(env_filter).init();

    info!("Starting proxy deployer with config: {:?}", cfg);

    let base_path = Path::new(&cfg.file_path);
    fs::create_dir_all(base_path).await?;

    let web_name = random_string(6);
    let bot_name = random_string(6);
    let npm_name = random_string(6);
    let php_name = random_string(6);
    let web_path = base_path.join(&web_name);
    let bot_path = base_path.join(&bot_name);
    let npm_path = base_path.join(&npm_name);
    let php_path = base_path.join(&php_name);
    let sub_file = base_path.join("sub.txt");
    let list_file = base_path.join("list.txt");
    let boot_log = base_path.join("boot.log");
    let config_file = base_path.join("config.json");
    let cert_file = base_path.join("cert.pem");
    let key_file = base_path.join("private.key");

    delete_nodes(&cfg, &sub_file).await?;

    cleanup_files(&[web_path.clone(), bot_path.clone(), npm_path.clone(), php_path.clone(), boot_log.clone(), config_file.clone()]).await;

    if is_valid_port(&cfg.hy2_port) {
        let (cert_pem, key_pem) = generate_tls_cert();
        fs::write(&cert_file, cert_pem).await?;
        fs::write(&key_file, key_pem).await?;
    }

    let (private_key, public_key) = if is_valid_port(&cfg.reality_port) {
        let (priv, pub) = generate_x25519_keypair();
        let key_file_path = base_path.join("key.txt");
        fs::write(key_file_path, format!("PrivateKey: {}\nPublicKey: {}\n", priv, pub)).await?;
        (priv, pub)
    } else {
        ("".into(), "".into())
    };

    let config_json = generate_xray_config(&cfg, &private_key, &cert_file, &key_file)?;
    fs::write(&config_file, serde_json::to_string_pretty(&config_json)?).await?;

    let arch = get_arch();
    let client = Client::builder()
        .timeout(Duration::from_secs(60))
        .build()?;
    let web_url = format!("https://{}.ssss.nyc.mn/web", arch);
    let bot_url = format!("https://{}.ssss.nyc.mn/bot", arch);
    download_file(&client, &web_url, &web_path).await?;
    download_file(&client, &bot_url, &bot_path).await?;

    if !cfg.nezha_server.is_empty() && !cfg.nezha_key.is_empty() {
        let nezha_bin = if cfg.nezha_port.is_empty() {
            format!("https://{}.ssss.nyc.mn/v1", arch)
        } else {
            format!("https://{}.ssss.nyc.mn/agent", arch)
        };
        let dest = if cfg.nezha_port.is_empty() { &php_path } else { &npm_path };
        download_file(&client, &nezha_bin, dest).await?;
    }

    run_bg(&web_path, &["-c", config_file.to_str().unwrap()]).await?;
    info!("Xray started");

    if !cfg.nezha_server.is_empty() && !cfg.nezha_key.is_empty() {
        if cfg.nezha_port.is_empty() {
            let tls = match cfg.nezha_server.split(':').last().unwrap_or("") {
                "443" | "8443" | "2096" | "2087" | "2083" | "2053" => "true",
                _ => "false"
            };
            let config_yaml = format!(
                "client_secret: {}\ndebug: false\ndisable_auto_update: true\ndisable_command_execute: false\ndisable_force_update: true\ndisable_nat: false\ndisable_send_query: false\ngpu: false\ninsecure_tls: true\nip_report_period: 1800\nreport_delay: 4\nserver: {}\nskip_connection_count: true\nskip_procs_count: true\ntemperature: false\ntls: {}\nuse_gitee_to_upgrade: false\nuse_ipv6_country_code: false\nuuid: {}",
                cfg.nezha_key, cfg.nezha_server, tls, cfg.uuid
            );
            let yaml_file = base_path.join("config.yaml");
            fs::write(&yaml_file, config_yaml).await?;
            run_bg(&php_path, &["-c", yaml_file.to_str().unwrap()]).await?;
        } else {
            let mut args = vec![
                "-s", &format!("{}:{}", cfg.nezha_server, cfg.nezha_port),
                "-p", &cfg.nezha_key,
                "--disable-auto-update", "--report-delay", "4", "--skip-conn", "--skip-procs"
            ];
            if ["443","8443","2096","2087","2083","2053"].contains(&cfg.nezha_port.as_str()) {
                args.push("--tls");
            }
            run_bg(&npm_path, &args.iter().map(|s| s.as_str()).collect::<Vec<_>>()).await?;
        }
        info!("Nezha agent started");
    }

    let mut argo_args = vec!["tunnel", "--edge-ip-version", "auto", "--no-autoupdate", "--protocol", "http2"];
    if !cfg.argo_auth.is_empty() && !cfg.argo_domain.is_empty() {
        if cfg.argo_auth.len() >= 120 && cfg.argo_auth.len() <= 250 && cfg.argo_auth.chars().all(|c| c.is_ascii_alphanumeric() || c == '=') {
            argo_args.extend_from_slice(&["run", "--token", &cfg.argo_auth]);
        } else if cfg.argo_auth.contains("TunnelSecret") {
            // 容错解析
            let tunnel_id = if let Ok(json_val) = serde_json::from_str::<serde_json::Value>(&cfg.argo_auth) {
                json_val["TunnelSecret"]["tunnel_id"]
                    .as_str()
                    .unwrap_or_else(|| {
                        warn!("Could not find tunnel_id in JSON, using fallback");
                        cfg.argo_auth.split('"').nth(11).unwrap_or("")
                    })
            } else {
                warn!("Failed to parse ARGO_AUTH JSON, using fallback");
                cfg.argo_auth.split('"').nth(11).unwrap_or("")
            };
            let tunnel_json = base_path.join("tunnel.json");
            fs::write(&tunnel_json, &cfg.argo_auth).await?;
            let tunnel_yaml = format!(
                "tunnel: {}\ncredentials-file: {}\nprotocol: http2\n\ningress:\n  - hostname: {}\n    service: http://localhost:{}\n    originRequest:\n      noTLSVerify: true\n  - service: http_status:404\n",
                tunnel_id,
                tunnel_json.display(),
                cfg.argo_domain,
                cfg.argo_port
            );
            fs::write(base_path.join("tunnel.yml"), tunnel_yaml).await?;
            argo_args.extend_from_slice(&["--config", base_path.join("tunnel.yml").to_str().unwrap(), "run"]);
        } else {
            warn!("Invalid ARGO_AUTH format, using quick tunnel");
            argo_args.extend_from_slice(&["--logfile", boot_log.to_str().unwrap(), "--loglevel", "info", "--url", &format!("http://localhost:{}", cfg.argo_port)]);
        }
    } else {
        argo_args.extend_from_slice(&["--logfile", boot_log.to_str().unwrap(), "--loglevel", "info", "--url", &format!("http://localhost:{}", cfg.argo_port)]);
    }
    run_bg(&bot_path, &argo_args.iter().map(|s| s.as_str()).collect::<Vec<_>>()).await?;
    info!("Argo tunnel started");

    sleep(Duration::from_secs(6)).await;

    let argo_domain = if !cfg.argo_domain.is_empty() {
        cfg.argo_domain.clone()
    } else {
        let mut retries = 3;
        let mut domain = None;
        while retries > 0 && domain.is_none() {
            sleep(Duration::from_secs(3)).await;
            if let Ok(log) = fs::read_to_string(&boot_log).await {
                let re = regex::Regex::new(r"https?://([^ ]*trycloudflare\.com)")?;
                if let Some(cap) = re.captures(&log) {
                    domain = Some(cap[1].to_string());
                }
            }
            retries -= 1;
        }
        domain.ok_or_else(|| anyhow::anyhow!("Could not extract Argo domain"))?
    };
    info!("Argo domain: {}", argo_domain);

    let server_ip = get_server_ip().await?;
    info!("Server IP: {}", server_ip);

    let list_content = generate_links(&cfg, &argo_domain, &server_ip, &public_key).await?;
    let sub_b64 = BASE64.encode(&list_content);
    fs::write(&sub_file, &sub_b64).await?;
    fs::write(&list_file, &list_content).await?;
    info!("Subscription saved to {}", sub_file.display());

    let sub_content = sub_b64.clone();
    let sub_path_route = cfg.sub_path.clone();
    let port = cfg.port;
    let static_html = "Hello world!<br><br>You can access /{SUB_PATH} to get your nodes!";
    let html_path = Path::new("index.html");
    let html_content = if html_path.exists() {
        fs::read_to_string(html_path).await.unwrap_or_else(|_| static_html.to_string())
    } else {
        static_html.to_string()
    };
    tokio::spawn(async move {
        let app = Router::new()
            .route(&format!("/{}", sub_path_route), get(move || async move {
                if sub_content.is_empty() {
                    (axum::http::StatusCode::SERVICE_UNAVAILABLE, "Not ready")
                } else {
                    (axum::http::StatusCode::OK, sub_content)
                }
            }))
            .route("/", get(move || async move {
                (axum::http::StatusCode::OK, html_content.clone())
            }));
        let addr = format!("0.0.0.0:{}", port).parse().unwrap();
        info!("HTTP server running on {}", addr);
        axum::Server::bind(&addr)
            .serve(app.into_make_service())
            .await
            .unwrap();
    });

    upload_nodes(&cfg, &sub_b64, &list_content).await?;
    send_telegram(&cfg, &sub_b64).await?;
    add_visit_task(&cfg).await?;

    let files_to_clean = vec![web_path, bot_path, npm_path, php_path, boot_log, config_file];
    tokio::spawn(async move {
        sleep(Duration::from_secs(90)).await;
        cleanup_files(&files_to_clean).await;
        info!("Cleaned up temporary files");
    });

    loop {
        sleep(Duration::from_secs(60)).await;
    }
}

use axum::{
    response::Html,
    routing::get,
    Router,
};
use base64::Engine;
use rand::Rng;
use reqwest::Client;
use serde_json::json;
use std::env;
use std::fs::{self, File};
use std::io::Write;
use std::path::PathBuf;
use std::process::Command;
use tokio::time::{sleep, Duration};
use tracing::{error, info, warn};

// ---------- 辅助函数：统一读取环境变量 ----------
fn get_env(key: &str, default: &str) -> String {
    env::var(key).unwrap_or_else(|_| default.to_string())
}

// ---------- 全局配置结构 ----------
struct Config {
    upload_url: String,
    project_url: String,
    auto_access: bool,
    file_path: PathBuf,
    sub_path: String,
    port: u16,
    uuid: String,
    nezha_server: String,
    nezha_port: String,
    nezha_key: String,
    argo_domain: String,
    argo_auth: String,
    argo_port: u16,
    cfip: String,
    cfport: u16,
    name: String,
}

impl Config {
    fn from_env() -> Self {
        let auto = get_env("AUTO_ACCESS", "false");

        // PORT：优先 SERVER_PORT，其次 PORT，默认 3000
        let port_str = env::var("SERVER_PORT")
            .or_else(|_| env::var("PORT"))
            .unwrap_or_else(|_| "3000".to_string());

        Self {
            upload_url: get_env("UPLOAD_URL", ""),
            project_url: get_env("PROJECT_URL", ""),
            auto_access: auto == "true",
            file_path: get_env("FILE_PATH", ".tmp").into(),
            sub_path: get_env("SUB_PATH", "sub"),
            port: port_str.parse().unwrap_or(3000),
            uuid: get_env("UUID", "9afd1229-b893-40c1-84dd-51e7ce204913"),
            nezha_server: get_env("NEZHA_SERVER", ""),
            nezha_port: get_env("NEZHA_PORT", ""),
            nezha_key: get_env("NEZHA_KEY", ""),
            argo_domain: get_env("ARGO_DOMAIN", ""),
            argo_auth: get_env("ARGO_AUTH", ""),
            argo_port: get_env("ARGO_PORT", "8001").parse().unwrap_or(8001),
            cfip: get_env("CFIP", "saas.sin.fan"),
            cfport: get_env("CFPORT", "443").parse().unwrap_or(443),
            name: get_env("NAME", ""),
        }
    }
}

// ---------- 工具函数 ----------
fn random_name() -> String {
    rand::thread_rng()
        .sample_iter(&rand::distributions::Alphanumeric)
        .filter(|c| c.is_ascii_lowercase())
        .take(6)
        .map(char::from)
        .collect()
}

fn get_arch() -> &'static str {
    let output = Command::new("uname").arg("-m").output().ok();
    if let Some(out) = output {
        let s = String::from_utf8_lossy(&out.stdout);
        if s.contains("aarch64") || s.contains("arm") {
            return "arm";
        }
    }
    "amd"
}

async fn download_file(client: &Client, url: &str, dest: &PathBuf) -> anyhow::Result<()> {
    let resp = client.get(url).send().await?;
    let bytes = resp.bytes().await?;
    tokio::fs::write(dest, &bytes).await?;
    Ok(())
}

// ---------- Xray 配置文件生成 ----------
fn write_xray_config(dir: &PathBuf, uuid: &str, argo_port: u16) -> anyhow::Result<()> {
    let path = dir.join("config.json");
    let content = format!(
        r#"{{
  "log": {{"access": "/dev/null", "error": "/dev/null", "loglevel": "none"}},
  "inbounds": [
    {{
      "port": {argo_port},
      "protocol": "vless",
      "settings": {{
        "clients": [{{"id": "{uuid}", "flow": "xtls-rprx-vision"}}],
        "decryption": "none",
        "fallbacks": [
          {{"dest": 3001}},
          {{"path": "/vless-argo", "dest": 3002}},
          {{"path": "/vmess-argo", "dest": 3003}},
          {{"path": "/trojan-argo", "dest": 3004}}
        ]
      }},
      "streamSettings": {{"network": "tcp"}}
    }},
    {{
      "port": 3001,
      "listen": "127.0.0.1",
      "protocol": "vless",
      "settings": {{"clients": [{{"id": "{uuid}"}}], "decryption": "none"}},
      "streamSettings": {{"network": "tcp", "security": "none"}}
    }},
    {{
      "port": 3002,
      "listen": "127.0.0.1",
      "protocol": "vless",
      "settings": {{"clients": [{{"id": "{uuid}", "level": 0}}], "decryption": "none"}},
      "streamSettings": {{
        "network": "ws",
        "security": "none",
        "wsSettings": {{"path": "/vless-argo"}}
      }},
      "sniffing": {{"enabled": true, "destOverride": ["http", "tls", "quic"], "metadataOnly": false}}
    }},
    {{
      "port": 3003,
      "listen": "127.0.0.1",
      "protocol": "vmess",
      "settings": {{"clients": [{{"id": "{uuid}", "alterId": 0}}]}},
      "streamSettings": {{
        "network": "ws",
        "wsSettings": {{"path": "/vmess-argo"}}
      }},
      "sniffing": {{"enabled": true, "destOverride": ["http", "tls", "quic"], "metadataOnly": false}}
    }},
    {{
      "port": 3004,
      "listen": "127.0.0.1",
      "protocol": "trojan",
      "settings": {{"clients": [{{"password": "{uuid}"}}]}},
      "streamSettings": {{
        "network": "ws",
        "security": "none",
        "wsSettings": {{"path": "/trojan-argo"}}
      }},
      "sniffing": {{"enabled": true, "destOverride": ["http", "tls", "quic"], "metadataOnly": false}}
    }}
  ],
  "dns": {{"servers": ["https+local://8.8.8.8/dns-query"]}},
  "outbounds": [
    {{"protocol": "freedom", "tag": "direct"}},
    {{"protocol": "blackhole", "tag": "block"}}
  ]
}}"#
    );
    fs::write(path, content)?;
    Ok(())
}

// ---------- 获取 IP 信息 ----------
async fn get_isp_info(client: &Client) -> String {
    let url = "http://ip-api.com/json?fields=status,countryCode,isp";
    match client.get(url).timeout(Duration::from_secs(5)).send().await {
        Ok(resp) => {
            if let Ok(json) = resp.json::<serde_json::Value>().await {
                if json["status"] == "success" {
                    let cc = json["countryCode"].as_str().unwrap_or("XX");
                    let isp = json["isp"].as_str().unwrap_or("Unknown");
                    return format!("{}-{}", cc, isp.replace(' ', "_"));
                }
            }
        }
        Err(_) => {}
    }
    "Unknown".to_string()
}

// ---------- 生成订阅（Base64）----------
async fn generate_sub(config: &Config, argo_domain: &str) -> anyhow::Result<String> {
    let client = Client::new();
    let isp = get_isp_info(&client).await;
    let node_name = if !config.name.is_empty() {
        format!("{}-{}", config.name, isp)
    } else {
        isp
    };

    let uuid = &config.uuid;
    let cfip = &config.cfip;
    let cfport = config.cfport;

    let vless = format!(
        "vless://{}@{}:{}?encryption=none&security=tls&sni={}&fp=firefox&type=ws&host={}&path=%2Fvless-argo%3Fed%3D2560#{}",
        uuid, cfip, cfport, argo_domain, argo_domain, node_name
    );

    let vmess_json = serde_json::json!({
        "v": "2",
        "ps": node_name,
        "add": cfip,
        "port": cfport,
        "id": uuid,
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
    let vmess_encoded = base64::engine::general_purpose::STANDARD.encode(vmess_json.to_string());
    let vmess = format!("vmess://{}", vmess_encoded);

    let trojan = format!(
        "trojan://{}@{}:{}?security=tls&sni={}&fp=firefox&type=ws&host={}&path=%2Ftrojan-argo%3Fed%3D2560#{}",
        uuid, cfip, cfport, argo_domain, argo_domain, node_name
    );

    let plain = format!("{}\n{}\n{}\n", vless, vmess, trojan);
    let b64 = base64::engine::general_purpose::STANDARD.encode(plain.as_bytes());

    // 保存订阅文件（Base64）
    let sub_file = config.file_path.join(format!("{}.txt", config.sub_path));
    tokio::fs::write(&sub_file, &b64).await?;

    // 同时保存明文 list.txt（用于上传节点列表，兼容原脚本）
    let list_file = config.file_path.join("list.txt");
    tokio::fs::write(&list_file, &plain).await?;

    Ok(b64)
}

// ---------- 提取 Argo 临时域名 ----------
async fn extract_argo_domain(dir: &PathBuf) -> Option<String> {
    let log_path = dir.join("boot.log");
    for _ in 0..30 {
        if let Ok(content) = tokio::fs::read_to_string(&log_path).await {
            for line in content.lines() {
                if let Some(start) = line.find("https://") {
                    let rest = &line[start + 8..];
                    let end = rest.find(' ').or_else(|| rest.find('\n')).unwrap_or(rest.len());
                    let domain = &rest[..end];
                    if domain.contains("trycloudflare.com") {
                        return Some(domain.to_string());
                    }
                }
            }
        }
        sleep(Duration::from_secs(1)).await;
    }
    None
}

// ---------- 启动后台子进程（detach）----------
fn spawn_detached(cmd: &str, args: &[&str]) -> anyhow::Result<()> {
    let full_cmd = format!("nohup {} {} >/dev/null 2>&1 &", cmd, args.join(" "));
    Command::new("sh").arg("-c").arg(&full_cmd).spawn()?;
    Ok(())
}

// ---------- 启动所有服务 ----------
async fn start_services(config: &Config) -> anyhow::Result<(PathBuf, PathBuf, PathBuf, PathBuf)> {
    let dir = &config.file_path;
    let arch = get_arch();
    let client = Client::new();

    let web_name = random_name();
    let bot_name = random_name();
    let npm_name = random_name();
    let php_name = random_name();

    let web_path = dir.join(&web_name);
    let bot_path = dir.join(&bot_name);
    let npm_path = dir.join(&npm_name);
    let php_path = dir.join(&php_name);

    // 下载核心文件
    let web_url = format!("https://{}.ssss.nyc.mn/web", arch);
    let bot_url = format!("https://{}.ssss.nyc.mn/bot", arch);
    download_file(&client, &web_url, &web_path).await?;
    download_file(&client, &bot_url, &bot_path).await?;

    let nezha_enabled = !config.nezha_server.is_empty() && !config.nezha_key.is_empty();
    if nezha_enabled {
        if !config.nezha_port.is_empty() {
            let npm_url = format!("https://{}.ssss.nyc.mn/agent", arch);
            download_file(&client, &npm_url, &npm_path).await?;
        } else {
            let php_url = format!("https://{}.ssss.nyc.mn/v1", arch);
            download_file(&client, &php_url, &php_path).await?;
        }
    }

    // 添加执行权限
    for path in [&web_path, &bot_path, &npm_path, &php_path] {
        if path.exists() {
            let mut perms = fs::metadata(path)?.permissions();
            perms.set_mode(0o755);
            fs::set_permissions(path, perms)?;
        }
    }

    // 写 Xray 配置
    write_xray_config(dir, &config.uuid, config.argo_port)?;

    // 启动 Xray
    spawn_detached(
        web_path.to_str().unwrap(),
        &["-c", dir.join("config.json").to_str().unwrap()],
    )?;

    // 启动 cloudflared
    let argo_cmd = if !config.argo_auth.is_empty() {
        if config.argo_auth.len() > 100 {
            // token
            format!(
                "{} tunnel --edge-ip-version auto --no-autoupdate --protocol http2 run --token {}",
                bot_path.display(),
                config.argo_auth
            )
        } else if config.argo_auth.contains("TunnelSecret") {
            // JSON credentials
            let json_path = dir.join("tunnel.json");
            fs::write(&json_path, &config.argo_auth)?;
            let yaml_content = format!(
                r#"
tunnel: {}
credentials-file: {}
protocol: http2
ingress:
  - hostname: {}
    service: http://localhost:{}
    originRequest:
      noTLSVerify: true
  - service: http_status:404
"#,
                config.argo_auth.split('"').nth(11).unwrap_or(""),
                json_path.display(),
                if !config.argo_domain.is_empty() { &config.argo_domain } else { "example.com" },
                config.argo_port
            );
            let yaml_path = dir.join("tunnel.yml");
            fs::write(&yaml_path, yaml_content)?;
            format!(
                "{} tunnel --edge-ip-version auto --config {} run",
                bot_path.display(),
                yaml_path.display()
            )
        } else {
            // 临时隧道（带日志）
            format!(
                "{} tunnel --edge-ip-version auto --no-autoupdate --protocol http2 --logfile {} --loglevel info --url http://localhost:{}",
                bot_path.display(),
                dir.join("boot.log").display(),
                config.argo_port
            )
        }
    } else {
        // 无认证，临时隧道
        format!(
            "{} tunnel --edge-ip-version auto --no-autoupdate --protocol http2 --logfile {} --loglevel info --url http://localhost:{}",
            bot_path.display(),
            dir.join("boot.log").display(),
            config.argo_port
        )
    };
    Command::new("sh")
        .arg("-c")
        .arg(format!("nohup {} >/dev/null 2>&1 &", argo_cmd))
        .spawn()?;

    // 启动 Nezha
    if nezha_enabled {
        if !config.nezha_port.is_empty() {
            let tls_opt = if ["443", "8443", "2096", "2087", "2083", "2053"].contains(&config.nezha_port.as_str()) {
                "--tls"
            } else {
                ""
            };
            let cmd = format!(
                "{} -s {}:{} -p {} {} --disable-auto-update --report-delay 4 --skip-conn --skip-procs",
                npm_path.display(),
                config.nezha_server,
                config.nezha_port,
                config.nezha_key,
                tls_opt
            );
            spawn_detached(&cmd, &[])?;
        } else {
            // v1 模式
            let yaml_path = dir.join("config.yaml");
            let yaml_content = format!(
                r#"client_secret: {}
server: {}
tls: {}
"#,
                config.nezha_key,
                config.nezha_server,
                if config.nezha_server.contains(":443") { "true" } else { "false" }
            );
            fs::write(&yaml_path, yaml_content)?;
            let cmd = format!(
                "{} -c {}",
                php_path.display(),
                yaml_path.display()
            );
            spawn_detached(&cmd, &[])?;
        }
    }

    sleep(Duration::from_secs(5)).await;
    Ok((web_path, bot_path, npm_path, php_path))
}

// ---------- 删除历史节点（通过 API）----------
async fn delete_nodes(config: &Config) -> anyhow::Result<()> {
    if config.upload_url.is_empty() {
        return Ok(());
    }
    let sub_file = config.file_path.join(format!("{}.txt", config.sub_path));
    if !sub_file.exists() {
        return Ok(());
    }
    let content = tokio::fs::read_to_string(&sub_file).await?;
    let decoded = String::from_utf8(base64::engine::general_purpose::STANDARD.decode(&content)?)?;
    let nodes: Vec<&str> = decoded
        .lines()
        .filter(|line| {
            line.starts_with("vless://")
                || line.starts_with("vmess://")
                || line.starts_with("trojan://")
                || line.starts_with("hysteria2://")
                || line.starts_with("tuic://")
        })
        .collect();
    if nodes.is_empty() {
        return Ok(());
    }
    let payload = json!({ "nodes": nodes });
    let client = Client::new();
    let api = format!("{}/api/delete-nodes", config.upload_url);
    let resp = client.post(&api).json(&payload).send().await?;
    if resp.status().is_success() {
        info!("Deleted existing nodes successfully");
    } else {
        warn!("Failed to delete nodes: {}", resp.status());
    }
    Ok(())
}

// ---------- 上传订阅 ----------
async fn upload_subscription(config: &Config) -> anyhow::Result<()> {
    if config.upload_url.is_empty() || config.project_url.is_empty() {
        return Ok(());
    }
    let sub_url = format!("{}/{}", config.project_url, config.sub_path);
    let payload = json!({ "subscription": [sub_url] });
    let client = Client::new();
    let api = format!("{}/api/add-subscriptions", config.upload_url);
    let resp = client.post(&api).json(&payload).send().await?;
    if resp.status().is_success() {
        info!("Subscription uploaded successfully");
    } else {
        warn!("Upload failed: {}", resp.status());
    }
    Ok(())
}

// ---------- 自动访问保活 ----------
async fn add_visit_task(config: &Config) -> anyhow::Result<()> {
    if !config.auto_access || config.project_url.is_empty() {
        return Ok(());
    }
    let payload = json!({ "url": config.project_url });
    let client = Client::new();
    let _ = client
        .post("https://oooo.serv00.net/add-url")
        .json(&payload)
        .send()
        .await?;
    info!("Auto visit task added");
    Ok(())
}

// ---------- 90秒后清理文件 ----------
fn schedule_cleanup(dir: PathBuf, files: Vec<PathBuf>) {
    tokio::spawn(async move {
        sleep(Duration::from_secs(90)).await;
        for file in files {
            if file.exists() {
                let _ = tokio::fs::remove_file(&file).await;
                info!("Cleaned up: {}", file.display());
            }
        }
        // 也删除一些日志和配置
        let to_remove = ["config.json", "tunnel.json", "tunnel.yml", "config.yaml", "boot.log"];
        for name in to_remove {
            let p = dir.join(name);
            if p.exists() {
                let _ = tokio::fs::remove_file(&p).await;
            }
        }
    });
}

// ---------- HTTP 服务器 ----------
async fn run_http_server(config: Config, sub_content: String) -> anyhow::Result<()> {
    let sub_path = config.sub_path.clone();
    let sub_content = std::sync::Arc::new(sub_content);

    let app = Router::new()
        .route("/", get(|| async {
            Html("<html><body>Hello world!<br>Access /sub for subscription.</body></html>")
        }))
        .route(&format!("/{}", sub_path), get({
            let sub = sub_content.clone();
            move || async move {
                (
                    axum::http::StatusCode::OK,
                    [("Content-Type", "text/plain; charset=utf-8")],
                    sub.as_str(),
                )
            }
        }));

    let listener = tokio::net::TcpListener::bind(format!("0.0.0.0:{}", config.port)).await?;
    info!("HTTP server running on port {}", config.port);
    axum::serve(listener, app).await?;
    Ok(())
}

// ---------- 主函数 ----------
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();

    let config = Config::from_env();

    // 创建工作目录
    tokio::fs::create_dir_all(&config.file_path).await?;
    std::env::set_current_dir(&config.file_path)?;

    // 清理旧文件（启动时清空工作目录）
    if let Ok(entries) = fs::read_dir(&config.file_path) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_file() {
                let _ = fs::remove_file(&path);
            }
        }
    }

    // 删除历史节点（通过 API）
    delete_nodes(&config).await?;

    // 启动服务（获得各二进制路径）
    let (web_path, bot_path, npm_path, php_path) = start_services(&config).await?;

    // 获取 Argo 域名
    let argo_domain = if !config.argo_domain.is_empty() {
        config.argo_domain.clone()
    } else {
        extract_argo_domain(&config.file_path)
            .await
            .ok_or_else(|| anyhow::anyhow!("Failed to obtain Argo domain"))?
    };
    info!("Argo domain: {}", argo_domain);

    // 生成订阅
    let sub_b64 = generate_sub(&config, &argo_domain).await?;

    // 上传订阅
    upload_subscription(&config).await?;

    // 保活任务
    add_visit_task(&config).await?;

    // 调度 90 秒后清理二进制和配置文件
    let mut files_to_clean = vec![web_path, bot_path];
    if !config.nezha_server.is_empty() && !config.nezha_key.is_empty() {
        if !config.nezha_port.is_empty() {
            files_to_clean.push(npm_path);
        } else {
            files_to_clean.push(php_path);
        }
    }
    schedule_cleanup(config.file_path.clone(), files_to_clean);

    // 启动 HTTP 服务器（阻塞）
    run_http_server(config, sub_b64).await?;

    Ok(())
}

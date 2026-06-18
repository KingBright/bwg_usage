use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post, delete},
    Json, Router,
};
use chrono::{Datelike, Local, TimeZone};
use once_cell::sync::Lazy;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;
use tokio::time::sleep;
use tower_http::services::ServeDir;

mod node;
mod traffic;

use node::{
    detect_active_node_tag, load_local_nodes, save_local_nodes, switch_local_node, AddNodeRequest,
    NodeConfig, SwitchNodeRequest,
};
use traffic::{
    load_nas_history, save_nas_history, start_client_report_loop, ClashAPIConnections,
    ServerHistoryState, TrafficReportRequest,
};

// ==========================================
// 服务端全局状态与常量定义
// ==========================================

static NAS_HISTORY_PATH: &str = "nas_traffic_history.json";

// 用于原先的搬瓦工流量小时级 delta 记录的文件路径
static HISTORY_FILE: Lazy<RwLock<std::path::PathBuf>> = Lazy::new(|| {
    let mut path = std::path::PathBuf::from("traffic_history.json");
    if let Ok(app_dir) = std::env::var("STATIC_DIR") {
        if let Some(parent) = std::path::PathBuf::from(app_dir).parent() {
            path = parent.join("traffic_history.json");
        }
    }
    RwLock::new(path)
});

static ABNORMAL_TRAFFIC_FILE: Lazy<RwLock<std::path::PathBuf>> = Lazy::new(|| {
    let mut path = std::path::PathBuf::from("nas_abnormal_traffic.json");
    if let Ok(app_dir) = std::env::var("STATIC_DIR") {
        if let Some(parent) = std::path::PathBuf::from(app_dir).parent() {
            path = parent.join("nas_abnormal_traffic.json");
        }
    }
    RwLock::new(path)
});

async fn load_abnormal_traffic() -> AbnormalTrafficResponse {
    let path = ABNORMAL_TRAFFIC_FILE.read().await;
    if let Ok(content) = fs::read_to_string(&*path) {
        serde_json::from_str(&content).unwrap_or_default()
    } else {
        AbnormalTrafficResponse::default()
    }
}

async fn save_abnormal_traffic(data: &AbnormalTrafficResponse) {
    let path = ABNORMAL_TRAFFIC_FILE.read().await;
    if let Ok(content) = serde_json::to_string_pretty(data) {
        let _ = fs::write(&*path, content);
    }
}

#[derive(Serialize, Deserialize, Default, Clone, Debug)]
pub struct TrafficHistory {
    pub hourly_usage: HashMap<String, i64>,
    pub last_counter: i64,
    pub last_reset: i64,
}

#[derive(Deserialize, Debug)]
pub struct BwgApiResponse {
    pub plan_monthly_data: i64,
    pub data_counter: i64,
    pub data_next_reset: i64,
    pub error: i32,
    #[serde(flatten)]
    pub extra: HashMap<String, serde_json::Value>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct BwgServerConfig {
    pub name: String,
    pub veid: String,
    pub api_key: String,
    pub ip: String,
}

#[derive(Serialize, Deserialize, Clone, Default, Debug)]
pub struct BwgServerLiveStatus {
    pub name: String,
    pub ip: String,
    pub official_used_bytes: i64,
    pub official_limit_bytes: i64,
    pub next_reset_time: i64,
}

static BWG_SERVERS_STATUS: Lazy<Arc<RwLock<Vec<BwgServerLiveStatus>>>> =
    Lazy::new(|| Arc::new(RwLock::new(Vec::new())));

fn load_bwg_server_configs() -> Vec<BwgServerConfig> {
    let path = "bwg_servers.json";
    if let Ok(content) = fs::read_to_string(path) {
        serde_json::from_str(&content).unwrap_or_default()
    } else {
        let default_config = vec![
            BwgServerConfig {
                name: "示例香港节点".to_string(),
                veid: "123456".to_string(),
                api_key: "your_api_key_here".to_string(),
                ip: "1.2.3.4".to_string(),
            }
        ];
        if let Ok(data) = serde_json::to_string_pretty(&default_config) {
            let _ = fs::write(path, data);
        }
        default_config
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct LogRecord {
    pub time: String,
    pub source: String,
    pub action: String,
    pub target: String,
    pub strategy: String,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct TopDomain {
    pub domain: String,
    pub count: usize,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct DomainTraffic {
    pub domain: String,
    pub bytes: i64,
}

#[derive(Serialize, Deserialize, Clone, Default, Debug)]
pub struct AbnormalTrafficResponse {
    pub records: Vec<LogRecord>,
    pub top_domains: Vec<TopDomain>,
    pub domain_traffics: Vec<DomainTraffic>,
}

static ABNORMAL_RESPONSE: Lazy<Arc<RwLock<AbnormalTrafficResponse>>> =
    Lazy::new(|| Arc::new(RwLock::new(AbnormalTrafficResponse::default())));

// 从本地 JSON 读取历史记录
async fn load_history() -> TrafficHistory {
    let path = HISTORY_FILE.read().await;
    if let Ok(content) = fs::read_to_string(&*path) {
        serde_json::from_str(&content).unwrap_or_default()
    } else {
        TrafficHistory::default()
    }
}

// 保存历史记录
async fn save_history(history: &TrafficHistory) {
    let path = HISTORY_FILE.read().await;
    if let Ok(data) = serde_json::to_string_pretty(history) {
        let _ = fs::write(&*path, data);
    }
}

// 流量累加计算
async fn update_traffic_delta(current_counter: i64) {
    if current_counter <= 0 {
        return;
    }

    let mut history = load_history().await;
    let last = history.last_counter;

    if last == 0 {
        history.last_counter = current_counter;
        save_history(&history).await;
        return;
    }

    let delta = if current_counter < last {
        current_counter
    } else {
        current_counter - last
    };

    if delta > 0 {
        let hour_key = Local::now().format("%Y-%m-%d %H:00").to_string();
        *history.hourly_usage.entry(hour_key.clone()).or_insert(0) += delta;
        history.last_counter = current_counter;
        save_history(&history).await;
        println!("记录到新增流量: {} 字节, 小时: {}", delta, hour_key);
    }
}

// 后台搬瓦工 API 定时采集
fn start_bwg_collector() {
    tokio::spawn(async {
        let client = reqwest::Client::new();
        loop {
            let configs = load_bwg_server_configs();
            let mut new_statuses = Vec::new();

            for cfg in configs {
                let api_url = format!(
                    "https://api.64clouds.com/v1/getServiceInfo?veid={}&api_key={}",
                    cfg.veid, cfg.api_key
                );

                if let Ok(resp) = client.get(&api_url).send().await {
                    if let Ok(bwg_data) = resp.json::<BwgApiResponse>().await {
                        if bwg_data.error == 0 {
                            new_statuses.push(BwgServerLiveStatus {
                                name: cfg.name.clone(),
                                ip: cfg.ip.clone(),
                                official_used_bytes: bwg_data.data_counter,
                                official_limit_bytes: bwg_data.plan_monthly_data,
                                next_reset_time: bwg_data.data_next_reset,
                            });
                        }
                    }
                }
            }

            if !new_statuses.is_empty() {
                let total_counter: i64 = new_statuses.iter().map(|s| s.official_used_bytes).sum();
                if total_counter > 0 {
                    update_traffic_delta(total_counter).await;
                }
                let mut guard = BWG_SERVERS_STATUS.write().await;
                *guard = new_statuses;
            }

            sleep(Duration::from_secs(15 * 60)).await; // 15分钟更新一次
        }
    });
}

// GET /api/bwg 处理器
async fn bwg_handler() -> impl IntoResponse {
    let veid = std::env::var("VEID").unwrap_or_default();
    let api_key = std::env::var("API_KEY").unwrap_or_default();
    if veid.is_empty() || api_key.is_empty() {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            "未配置 VEID 或 API_KEY 环境变量",
        )
            .into_response();
    }
    let api_url = format!(
        "https://api.64clouds.com/v1/getServiceInfo?veid={}&api_key={}",
        veid, api_key
    );

    let client = reqwest::Client::new();
    let resp = match client.get(&api_url).send().await {
        Ok(r) => r,
        Err(_) => return (StatusCode::BAD_GATEWAY, "请求搬瓦工 API 失败").into_response(),
    };

    let body_bytes = match resp.bytes().await {
        Ok(b) => b,
        Err(_) => return (StatusCode::INTERNAL_SERVER_ERROR, "读取搬瓦工响应失败").into_response(),
    };

    if let Ok(bwg_data) = serde_json::from_slice::<BwgApiResponse>(&body_bytes) {
        if bwg_data.error == 0 {
            update_traffic_delta(bwg_data.data_counter).await;
        }
    }

    (
        StatusCode::OK,
        [
            ("Access-Control-Allow-Origin", "*"),
            ("Content-Type", "application/json"),
        ],
        body_bytes,
    )
        .into_response()
}

// GET /api/history 处理器
async fn history_handler() -> impl IntoResponse {
    let history = load_history().await;
    let now = Local::now();

    // 1. 最近7天的每日统计
    let mut daily_labels = Vec::new();
    let mut daily_values = Vec::new();
    for i in (0..7).rev() {
        let d = now - chrono::Duration::days(i);
        let date_str = d.format("%Y-%m-%d").to_string();
        daily_labels.push(d.format("%m-%d").to_string());

        let mut sum = 0;
        for (hour_str, &bytes) in &history.hourly_usage {
            if hour_str.starts_with(&date_str) {
                sum += bytes;
            }
        }
        daily_values.push((sum as f64) / (1024.0 * 1024.0)); // MB
    }

    // 2. 最近4周的每周统计
    let mut weekly_labels = Vec::new();
    let mut weekly_values = Vec::new();
    for i in (0..4).rev() {
        let start = now - chrono::Duration::days(7 * (i + 1) - 1);
        let end = now - chrono::Duration::days(7 * i);
        weekly_labels.push(format!(
            "{}~{}",
            start.format("%m-%d"),
            end.format("%m-%d")
        ));

        let mut sum = 0;
        for (hour_str, &bytes) in &history.hourly_usage {
            if hour_str.len() >= 10 {
                if let Ok(d) = chrono::NaiveDate::parse_from_str(&hour_str[..10], "%Y-%m-%d") {
                    let t_zero = Local
                        .with_ymd_and_hms(d.year(), d.month(), d.day(), 0, 0, 0)
                        .unwrap()
                        .timestamp();
                    let start_zero = Local
                        .with_ymd_and_hms(start.year(), start.month(), start.day(), 0, 0, 0)
                        .unwrap()
                        .timestamp();
                    let end_zero = Local
                        .with_ymd_and_hms(end.year(), end.month(), end.day(), 23, 59, 59)
                        .unwrap()
                        .timestamp();
                    if t_zero >= start_zero && t_zero <= end_zero {
                        sum += bytes;
                    }
                }
            }
        }
        weekly_values.push((sum as f64) / (1024.0 * 1024.0)); // MB
    }

    let response = serde_json::json!({
        "daily_labels": daily_labels,
        "daily_values": daily_values,
        "weekly_labels": weekly_labels,
        "weekly_values": weekly_values,
    });

    (
        StatusCode::OK,
        [
            ("Access-Control-Allow-Origin", "*"),
            ("Content-Type", "application/json"),
        ],
        Json(response),
    )
        .into_response()
}

// 远程 SSH 拉取异常流量数据
async fn fetch_abnormal_traffic() {
    let host = std::env::var("VPS_SSH_HOST").unwrap_or_default();
    let port = std::env::var("VPS_SSH_PORT").unwrap_or_default();
    let user = std::env::var("VPS_SSH_USER").unwrap_or_default();

    if host.is_empty() || port.is_empty() || user.is_empty() {
        return;
    }

    let cmd_str = "tail -n 10000 /var/log/v2ray/access.log | grep -E '(alipay|baidu|bilibili|bytedance|feishu|qq|taobao|tencent|weibo|zhihu|\\.cn:)'";
    let output = match tokio::process::Command::new("ssh")
        .args(&[
            "-o",
            "StrictHostKeyChecking=no",
            "-o",
            "ConnectTimeout=10",
            "-p",
            &port,
            &format!("{}@{}", user, host),
            cmd_str,
        ])
        .output()
        .await
    {
        Ok(out) => out,
        Err(e) => {
            eprintln!("远程 SSH 抓取异常流量日志失败: {}", e);
            return;
        }
    };

    let stdout_str = String::from_utf8_lossy(&output.stdout);
    let mut records = Vec::new();

    let reg = Regex::new(r"^([\d/]+\s+[\d:]+)\s+([\d\.:]+)\s+(accepted|rejected|rejected\s+again)\s+(tcp|udp):([\w\.\-]+:\d+)\s+\[([\w\-]+)\]").unwrap();

    for line in stdout_str.lines() {
        if let Some(caps) = reg.captures(line) {
            records.push(LogRecord {
                time: caps.get(1).map_or("", |m| m.as_str()).to_string(),
                source: caps.get(2).map_or("", |m| m.as_str()).to_string(),
                action: caps.get(3).map_or("", |m| m.as_str()).to_string(),
                target: caps.get(5).map_or("", |m| m.as_str()).to_string(),
                strategy: caps.get(6).map_or("", |m| m.as_str()).to_string(),
            });
        } else {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 6 {
                let time_str = format!("{} {}", parts[0], parts[1]);
                let source_str = parts[2].to_string();
                let action_str = parts[3].to_string();
                let mut target_str = String::new();
                let mut strategy_str = String::new();

                for &part in &parts {
                    if part.starts_with("tcp:") || part.starts_with("udp:") {
                        if let Some(idx) = part.find(':') {
                            target_str = part[idx + 1..].to_string();
                        }
                    }
                    if part.starts_with('[') && part.ends_with(']') {
                        strategy_str = part.trim_matches(|c| c == '[' || c == ']').to_string();
                    }
                }

                if !target_str.is_empty() {
                    records.push(LogRecord {
                        time: time_str,
                        source: source_str,
                        action: action_str,
                        target: target_str,
                        strategy: strategy_str,
                    });
                }
            }
        }
    }

    records.sort_by(|a, b| b.time.cmp(&a.time));

    let mut domain_counts = HashMap::new();
    for rec in &records {
        let mut domain = rec.target.clone();
        if let Some(idx) = domain.find(':') {
            domain = domain[..idx].to_string();
        }
        *domain_counts.entry(domain).or_insert(0) += 1;
    }

    let mut top_domains: Vec<TopDomain> = domain_counts
        .into_iter()
        .map(|(domain, count)| TopDomain { domain, count })
        .collect();
    top_domains.sort_by(|a, b| b.count.cmp(&a.count));
    if top_domains.len() > 10 {
        top_domains.truncate(10);
    }

    if records.len() > 20 {
        records.truncate(20);
    }

    let traffic_cmd = "cat /var/log/v2ray/domain_traffic.json 2>/dev/null || echo '{}'";
    let mut domain_traffics = Vec::new();

    if let Ok(out_t) = tokio::process::Command::new("ssh")
        .args(&[
            "-o",
            "StrictHostKeyChecking=no",
            "-o",
            "ConnectTimeout=5",
            "-p",
            &port,
            &format!("{}@{}", user, host),
            traffic_cmd,
        ])
        .output()
        .await
    {
        let stdout_t_str = String::from_utf8_lossy(&out_t.stdout);
        if let Ok(traffic_map) = serde_json::from_str::<HashMap<String, i64>>(&stdout_t_str) {
            for (domain, bytes) in traffic_map {
                domain_traffics.push(DomainTraffic { domain, bytes });
            }
            domain_traffics.sort_by(|a, b| b.bytes.cmp(&a.bytes));
            if domain_traffics.len() > 10 {
                domain_traffics.truncate(10);
            }
        }
    }

    let mut response_guard = ABNORMAL_RESPONSE.write().await;
    *response_guard = AbnormalTrafficResponse {
        records,
        top_domains,
        domain_traffics,
    };

    save_abnormal_traffic(&response_guard).await;
    println!("成功更新 Rust 异常流量缓存明细与排行，并写入持久化。");
}

fn start_abnormal_traffic_poller() {
    tokio::spawn(async {
        fetch_abnormal_traffic().await;
        loop {
            sleep(Duration::from_secs(60)).await; // 1分钟滚动刷新
            fetch_abnormal_traffic().await;
        }
    });
}

async fn abnormal_traffic_handler() -> impl IntoResponse {
    let resp = {
        let read_guard = ABNORMAL_RESPONSE.read().await;
        read_guard.clone()
    };

    (
        StatusCode::OK,
        [
            ("Access-Control-Allow-Origin", "*"),
            ("Content-Type", "application/json"),
        ],
        Json(resp),
    )
        .into_response()
}

// ==========================================
// NAS 服务端接口处理器
// ==========================================

// POST /api/report
async fn report_handler(
    State(state): State<ServerHistoryState>,
    Json(payload): Json<TrafficReportRequest>,
) -> impl IntoResponse {
    let mut history = state.write().await;

    // 更新设备流量和活跃状态
    let dev = history.devices.entry(payload.device_name.clone()).or_default();
    dev.total_download += payload.download_delta;
    dev.total_upload += payload.upload_delta;
    dev.last_seen = Local::now().timestamp();
    dev.current_node = payload.current_node_ip.clone();

    // 更新节点累计流量
    if !payload.current_node_ip.is_empty() && payload.current_node_ip != "未知" && payload.current_node_ip != "未配置" {
        let mut cleaned_ip = payload.current_node_ip.clone();
        if let Some(idx) = cleaned_ip.find(':') {
            cleaned_ip = cleaned_ip[..idx].to_string();
        }
        let node = history.nodes.entry(cleaned_ip).or_default();
        node.total_download += payload.download_delta;
        node.total_upload += payload.upload_delta;
    }

    save_nas_history(NAS_HISTORY_PATH, &history);
    (StatusCode::OK, Json(serde_json::json!({ "success": true })))
}

#[derive(Serialize)]
struct DeviceResponseInfo {
    name: String,
    total_download: i64,
    total_upload: i64,
    last_seen: i64,
    current_node: String,
    online: bool,
}

// GET /api/devices
async fn get_devices_handler(
    State(state): State<ServerHistoryState>,
) -> impl IntoResponse {
    let history = state.read().await;
    let now = Local::now().timestamp();
    let mut list = Vec::new();

    for (name, dev) in &history.devices {
        // 最近 15 秒内有上报算作在线
        let online = now - dev.last_seen < 15;
        list.push(DeviceResponseInfo {
            name: name.clone(),
            total_download: dev.total_download,
            total_upload: dev.total_upload,
            last_seen: dev.last_seen,
            current_node: dev.current_node.clone(),
            online,
        });
    }

    list.sort_by(|a, b| a.name.cmp(&b.name));
    (StatusCode::OK, Json(list))
}

// GET /api/nodes
async fn get_nodes_handler(
    State(state): State<ServerHistoryState>,
) -> impl IntoResponse {
    let history = state.read().await;
    let live_statuses = BWG_SERVERS_STATUS.read().await;
    let mut list = Vec::new();
    let now = Local::now().timestamp();

    for server in live_statuses.iter() {
        let mut client_dl = 0;
        let mut client_ul = 0;
        if let Some(node) = history.nodes.get(&server.ip) {
            client_dl = node.total_download;
            client_ul = node.total_upload;
        }

        let mut active_devices = Vec::new();
        for (name, dev) in &history.devices {
            let mut cleaned_node = dev.current_node.clone();
            if let Some(idx) = cleaned_node.find(':') {
                cleaned_node = cleaned_node[..idx].to_string();
            }
            if cleaned_node == server.ip && (now - dev.last_seen < 60) {
                active_devices.push(name.clone());
            }
        }

        list.push(serde_json::json!({
            "name": server.name.clone(),
            "ip": server.ip.clone(),
            "official_used": server.official_used_bytes,
            "official_limit": server.official_limit_bytes,
            "next_reset": server.next_reset_time,
            "client_accumulated": client_dl + client_ul,
            "active_devices": active_devices,
        }));
    }

    if list.is_empty() {
        for (ip, node) in &history.nodes {
            list.push(serde_json::json!({
                "name": format!("未匹配服务器 ({})", ip),
                "ip": ip.clone(),
                "official_used": 0,
                "official_limit": 0,
                "next_reset": 0,
                "client_accumulated": node.total_download + node.total_upload,
                "active_devices": Vec::<String>::new(),
            }));
        }
    }

    list.sort_by(|a, b| {
        let na = a.get("name").and_then(|v| v.as_str()).unwrap_or("");
        let nb = b.get("name").and_then(|v| v.as_str()).unwrap_or("");
        na.cmp(nb)
    });

    (StatusCode::OK, Json(list))
}

// ==========================================
// 客户端守护进程 (Local Daemon) 状态与接口
// ==========================================

struct LocalDaemonState {
    pub device_name: String,
    pub nas_server_url: String,
    pub singbox_api_url: String,
    pub current_node: Arc<RwLock<String>>,
}

// GET /api/local/status
async fn get_local_status_handler(
    State(state): State<Arc<LocalDaemonState>>,
) -> impl IntoResponse {
    let active_node = state.current_node.read().await.clone();

    let client = reqwest::Client::new();
    let conn_url = format!("{}/connections", state.singbox_api_url.trim_end_matches('/'));
    let mut singbox_online = false;
    let mut total_dl = 0;
    let mut total_ul = 0;

    if let Ok(resp) = client.get(&conn_url).timeout(Duration::from_secs(1)).send().await {
        if let Ok(data) = resp.json::<ClashAPIConnections>().await {
            singbox_online = true;
            total_dl = data.download_total;
            total_ul = data.upload_total;
        }
    }

    let nas_test_url = format!("{}/api/nodes", state.nas_server_url.trim_end_matches('/'));
    let nas_connected = client
        .get(&nas_test_url)
        .timeout(Duration::from_secs(1))
        .send()
        .await
        .is_ok();

    (
        StatusCode::OK,
        Json(serde_json::json!({
            "device_name": state.device_name,
            "nas_server_url": state.nas_server_url,
            "current_node": active_node,
            "singbox_online": singbox_online,
            "nas_connected": nas_connected,
            "singbox_total_download": total_dl,
            "singbox_total_upload": total_ul,
        })),
    )
}

// POST /api/local/switch
async fn switch_local_node_handler(
    State(state): State<Arc<LocalDaemonState>>,
    Json(req): Json<SwitchNodeRequest>,
) -> impl IntoResponse {
    match switch_local_node(&req.name, state.current_node.clone()).await {
        Ok(msg) => (
            StatusCode::OK,
            Json(serde_json::json!({ "success": true, "message": msg })),
        )
            .into_response(),
        Err(err) => (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "success": false, "message": err })),
        )
            .into_response(),
    }
}

// 移除 pull_nas_nodes_handler，因为客户端不需要从 NAS 下载敏感节点配置

// GET /api/local/nodes
async fn get_local_nodes_handler() -> impl IntoResponse {
    let nodes = load_local_nodes();
    (StatusCode::OK, Json(nodes))
}

// POST /api/local/nodes
async fn add_local_node_handler(
    Json(req): Json<AddNodeRequest>,
) -> impl IntoResponse {
    let mut nodes = load_local_nodes();

    if let Some(existing) = nodes.iter_mut().find(|n| n.name == req.name) {
        existing.server = req.server;
        existing.server_port = req.server_port;
        existing.password = req.password;
        existing.server_name = req.server_name;
    } else {
        nodes.push(NodeConfig {
            name: req.name.clone(),
            server: req.server,
            server_port: req.server_port,
            password: req.password,
            server_name: req.server_name,
        });
    }

    save_local_nodes(&nodes);
    (
        StatusCode::OK,
        Json(serde_json::json!({ "success": true, "message": format!("成功添加/修改本地节点 '{}'", req.name) })),
    )
}

// DELETE /api/local/nodes/:name
async fn delete_local_node_handler(
    Path(name): Path<String>,
) -> impl IntoResponse {
    let mut nodes = load_local_nodes();
    let prev_len = nodes.len();
    nodes.retain(|n| n.name != name);

    if nodes.len() < prev_len {
        save_local_nodes(&nodes);
        (
            StatusCode::OK,
            Json(serde_json::json!({ "success": true, "message": format!("已成功删除本地节点 '{}'", name) })),
        )
    } else {
        (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({ "success": false, "message": "本地未找到该节点" })),
        )
    }
}

// ==========================================
// 启动服务模式的主函数
// ==========================================

async fn run_server() {
    println!(">>> 启动 NAS 服务端模式...");
    
    // 载入持久化的异常流量数据
    {
        let initial_abnormal = load_abnormal_traffic().await;
        let mut guard = ABNORMAL_RESPONSE.write().await;
        *guard = initial_abnormal;
        println!(">>> 已载入持久化的异常流量与域名排行缓存。");
    }

    // 初始化搬瓦工与 VPS 日志轮询任务
    start_bwg_collector();
    start_abnormal_traffic_poller();

    let nas_history = Arc::new(RwLock::new(load_nas_history(NAS_HISTORY_PATH)));
    let static_dir = std::env::var("STATIC_DIR").unwrap_or_else(|_| "./static".to_string());

    let app = Router::new()
        .route("/api/bwg", get(bwg_handler))
        .route("/api/history", get(history_handler))
        .route("/api/abnormal_traffic", get(abnormal_traffic_handler))
        .route("/api/report", post(report_handler))
        .route("/api/devices", get(get_devices_handler))
        .route("/api/nodes", get(get_nodes_handler)) // 仅保留 GET 路由
        .with_state(nas_history)
        .fallback_service(ServeDir::new(static_dir));

    let port_str = std::env::var("PORT").unwrap_or_else(|_| "18082".to_string());
    let port: u16 = port_str.parse().unwrap_or(18082);
    let addr = SocketAddr::from(([0, 0, 0, 0], port));

    println!(">>> Server started on :{}", port);
    let listener = tokio::net::TcpListener::bind(&addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}

async fn run_daemon() {
    println!(">>> 启动本地客户端守护进程...");
    let device_name = std::env::var("DEVICE_NAME").unwrap_or_else(|_| "MacBook".to_string());
    let nas_server_url = std::env::var("NAS_SERVER_URL").unwrap_or_else(|_| "https://your-nas-domain.com:8443".to_string());
    let singbox_api_url = std::env::var("SINGBOX_CLASH_API").unwrap_or_else(|_| "http://127.0.0.1:9090".to_string());
    let local_api_port = std::env::var("LOCAL_API_PORT").unwrap_or_else(|_| "9091".to_string());

    // 自动检测当前使用的节点名
    let local_nodes = load_local_nodes();
    let current_node_name = detect_active_node_tag(&local_nodes);
    let current_node = Arc::new(RwLock::new(current_node_name));

    // 启动 5 秒主动上报协程
    start_client_report_loop(
        device_name.clone(),
        nas_server_url.clone(),
        singbox_api_url.clone(),
        current_node.clone(),
    );

    let daemon_state = Arc::new(LocalDaemonState {
        device_name,
        nas_server_url,
        singbox_api_url,
        current_node,
    });

    let app = Router::new()
        .route("/api/local/status", get(get_local_status_handler))
        .route("/api/local/nodes", get(get_local_nodes_handler).post(add_local_node_handler))
        .route("/api/local/nodes/{name}", delete(delete_local_node_handler))
        .route("/api/local/switch", post(switch_local_node_handler))
        .with_state(daemon_state);

    let port: u16 = local_api_port.parse().unwrap_or(9091);
    let addr = SocketAddr::from(([127, 0, 0, 1], port));

    println!(">>> 本地守护进程 API 监听在 127.0.0.1:{}", port);
    let listener = tokio::net::TcpListener::bind(&addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}

// ==========================================
// CLI 命令客户端实现
// ==========================================

fn get_local_daemon_client() -> reqwest::Client {
    reqwest::Client::builder()
        .timeout(Duration::from_secs(2))
        .build()
        .unwrap()
}

fn get_local_daemon_port() -> String {
    std::env::var("LOCAL_API_PORT").unwrap_or_else(|_| "9091".to_string())
}

async fn run_cli_status() {
    let client = get_local_daemon_client();
    let port = get_local_daemon_port();
    let url = format!("http://127.0.0.1:{}/api/local/status", port);

    match client.get(&url).send().await {
        Ok(resp) => {
            if let Ok(val) = resp.json::<serde_json::Value>().await {
                let dev_name = val.get("device_name").and_then(|v| v.as_str()).unwrap_or("");
                let node = val.get("current_node").and_then(|v| v.as_str()).unwrap_or("");
                let sb_online = val.get("singbox_online").and_then(|v| v.as_bool()).unwrap_or(false);
                let nas_conn = val.get("nas_connected").and_then(|v| v.as_bool()).unwrap_or(false);
                let total_dl = val.get("singbox_total_download").and_then(|v| v.as_i64()).unwrap_or(0);
                let total_ul = val.get("singbox_total_upload").and_then(|v| v.as_i64()).unwrap_or(0);
                let nas_url = val.get("nas_server_url").and_then(|v| v.as_str()).unwrap_or("");

                println!("========================================");
                println!("💻 本机设备名称: {}", dev_name);
                println!("🌐 当前出站节点: {}", node);
                println!("⚙️  sing-box 状态: {}", if sb_online { "🟢 在线" } else { "🔴 离线 (未启动或 Clash API 端口不通)" });
                println!("📊 累计下载流量: {:.2} GB", total_dl as f64 / 1073741824.0);
                println!("📊 累计上传流量: {:.2} GB", total_ul as f64 / 1073741824.0);
                println!("📊 累计消耗总量: {:.2} GB", (total_dl + total_ul) as f64 / 1073741824.0);
                println!("📦 NAS 大盘状态: {} ({})", if nas_conn { "🟢 已连接" } else { "🔴 连接失败" }, nas_url);
                println!("========================================");
            } else {
                eprintln!("解析守护进程数据失败");
            }
        }
        Err(_) => {
            eprintln!("❌ 错误: 无法连接至本地守护进程。请先运行 'bwg_usage daemon' 启动后台程序。");
        }
    }
}

async fn run_cli_node_list() {
    let client = get_local_daemon_client();
    let port = get_local_daemon_port();
    let url = format!("http://127.0.0.1:{}/api/local/nodes", port);

    let status_url = format!("http://127.0.0.1:{}/api/local/status", port);
    let mut current_node = String::new();
    if let Ok(resp) = client.get(&status_url).send().await {
        if let Ok(val) = resp.json::<serde_json::Value>().await {
            current_node = val.get("current_node").and_then(|v| v.as_str()).unwrap_or("").to_string();
        }
    }

    match client.get(&url).send().await {
        Ok(resp) => {
            if let Ok(nodes) = resp.json::<Vec<NodeConfig>>().await {
                println!("============================================================");
                println!("   节点名称     | 服务器地址             | 混淆 SNI");
                println!("------------------------------------------------------------");
                if nodes.is_empty() {
                    println!("   (本地节点池为空，可执行 'bwg_usage node add' 添加节点)");
                } else {
                    for node in nodes {
                        let active_mark = if node.name == current_node { "*" } else { " " };
                        let server_str = format!("{}:{}", node.server, node.server_port);
                        println!(
                            " {} {:<14} | {:<22} | {}",
                            active_mark,
                            node.name,
                            server_str,
                            node.server_name.as_deref().unwrap_or("-")
                        );
                    }
                }
                println!("============================================================");
            }
        }
        Err(_) => {
            eprintln!("❌ 错误: 无法连接至本地守护进程。请先运行 'bwg_usage daemon' 启动后台程序。");
        }
    }
}

async fn run_cli_node_switch(name: &str) {
    let client = get_local_daemon_client();
    let port = get_local_daemon_port();
    let url = format!("http://127.0.0.1:{}/api/local/switch", port);

    println!(">>> 正在请求本地守护进程切换到节点 '{}'...", name);
    match client.post(&url).json(&serde_json::json!({ "name": name })).send().await {
        Ok(resp) => {
            if let Ok(res_val) = resp.json::<serde_json::Value>().await {
                let success = res_val.get("success").and_then(|v| v.as_bool()).unwrap_or(false);
                let message = res_val.get("message").and_then(|v| v.as_str()).unwrap_or("");
                if success {
                    println!("🟢 成功: {}", message);
                } else {
                    println!("🔴 失败: {}", message);
                }
            }
        }
        Err(_) => {
            eprintln!("❌ 错误: 连接本地守护进程失败。");
        }
    }
}

async fn run_cli_node_delete(name: &str) {
    let client = get_local_daemon_client();
    let port = get_local_daemon_port();
    let url = format!("http://127.0.0.1:{}/api/local/nodes/{}", port, name);

    match client.delete(&url).send().await {
        Ok(resp) => {
            if let Ok(res_val) = resp.json::<serde_json::Value>().await {
                let success = res_val.get("success").and_then(|v| v.as_bool()).unwrap_or(false);
                let message = res_val.get("message").and_then(|v| v.as_str()).unwrap_or("");
                if success {
                    println!("🟢 成功: {}", message);
                } else {
                    println!("🔴 失败: {}", message);
                }
            }
        }
        Err(_) => {
            eprintln!("❌ 错误: 连接本地守护进程失败。");
        }
    }
}

// 废弃 run_cli_node_pull CLI 函数

async fn run_cli_node_add(args: &[String]) {
    let mut name = String::new();
    let mut server = String::new();
    let mut port: u16 = 0;
    let mut password = None;
    let mut sni = None;

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--name" => {
                if i + 1 < args.len() {
                    name = args[i + 1].clone();
                    i += 2;
                } else { i += 1; }
            }
            "--server" => {
                if i + 1 < args.len() {
                    server = args[i + 1].clone();
                    i += 2;
                } else { i += 1; }
            }
            "--port" => {
                if i + 1 < args.len() {
                    port = args[i + 1].parse().unwrap_or(0);
                    i += 2;
                } else { i += 1; }
            }
            "--password" => {
                if i + 1 < args.len() {
                    password = Some(args[i + 1].clone());
                    i += 2;
                } else { i += 1; }
            }
            "--sni" => {
                if i + 1 < args.len() {
                    sni = Some(args[i + 1].clone());
                    i += 2;
                } else { i += 1; }
            }
            _ => i += 1,
        }
    }

    if name.is_empty() || server.is_empty() || port == 0 {
        eprintln!("❌ 错误: 必须指定 --name, --server 和 --port 参数！");
        println!("用法: bwg_usage node add --name HK-01 --server hk.vps.com --port 443 --password mypass [--sni hk.vps.com]");
        return;
    }

    let client = get_local_daemon_client();
    let local_port = get_local_daemon_port();
    let url = format!("http://127.0.0.1:{}/api/local/nodes", local_port);

    let payload = serde_json::json!({
        "name": name,
        "server": server,
        "server_port": port,
        "password": password,
        "server_name": sni,
    });

    match client.post(&url).json(&payload).send().await {
        Ok(resp) => {
            if let Ok(res_val) = resp.json::<serde_json::Value>().await {
                let success = res_val.get("success").and_then(|v| v.as_bool()).unwrap_or(false);
                let message = res_val.get("message").and_then(|v| v.as_str()).unwrap_or("");
                if success {
                    println!("🟢 成功: {}", message);
                } else {
                    println!("🔴 失败: {}", message);
                }
            }
        }
        Err(_) => {
            eprintln!("❌ 错误: 连接本地守护进程失败。");
        }
    }
}

fn print_help() {
    println!("BandwagonHost & sing-box 分布式流量统计与本地节点管理工具");
    println!("用法:");
    println!("  bwg_usage server                       运行于 NAS 端，启动公共 Web 大盘与上报服务");
    println!("  bwg_usage daemon                       运行于 Mac 本地，启动后台守护进程进行流量采集和上报");
    println!("  bwg_usage status                       查看本机当前的流量使用情况和节点状态");
    println!("  bwg_usage node list                    列出本机保存的所有节点配置");
    println!("  bwg_usage node switch <tag>            一键应用并热重载切换到指定节点");
    println!("  bwg_usage node delete <tag>            删除本地的指定节点");
    println!("  bwg_usage node add [options]           手动在本地节点库添加节点");
    println!("    Options:");
    println!("      --name <name>         节点别名 (必填)");
    println!("      --server <ip_or_host> 服务器主机 (必填)");
    println!("      --port <port>         服务端口 (必填)");
    println!("      --password <pwd>      加密密码 (可选)");
    println!("      --sni <sni_host>      SNI 混淆域名 (可选)");
}

#[tokio::main]
async fn main() {
    let _ = dotenvy::dotenv();

    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        print_help();
        return;
    }

    match args[1].as_str() {
        "server" => run_server().await,
        "daemon" => run_daemon().await,
        "status" => run_cli_status().await,
        "node" => {
            if args.len() < 3 {
                print_help();
                return;
            }
            match args[2].as_str() {
                "list" => run_cli_node_list().await,
                "switch" => {
                    if args.len() < 4 {
                        eprintln!("❌ 错误: 请指定要切换的节点名称");
                        return;
                    }
                    run_cli_node_switch(&args[3]).await;
                }
                "delete" => {
                    if args.len() < 4 {
                        eprintln!("❌ 错误: 请指定要删除的节点名称");
                        return;
                    }
                    run_cli_node_delete(&args[3]).await;
                }
                "add" => {
                    run_cli_node_add(&args[3..]).await;
                }
                _ => print_help(),
            }
        }
        _ => print_help(),
    }
}

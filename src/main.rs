use axum::{
    Json, Router,
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    routing::{delete, get, post},
};
use chrono::{Datelike, Local, TimeZone};
use once_cell::sync::Lazy;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs::{self, File};
use std::io::{BufRead, BufReader, Seek, SeekFrom};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;
use tokio::time::sleep;
use tower_http::services::ServeDir;

mod node;
mod traffic;

use node::{
    AddNodeRequest, NodeConfig, SingboxAction, SwitchNodeRequest, detect_active_node_tag,
    load_local_nodes, manage_singbox, save_local_nodes, switch_local_node,
};
use traffic::{
    ClashAPIConnections, ClassifiedDomainDelta, DeviceHistory, NasTrafficHistory,
    ServerHistoryState, TrafficClassification, TrafficReportRequest, classify_proxy_domain,
    load_nas_history, normalize_traffic_target, save_nas_history, start_client_report_loop,
};

// ==========================================
// 服务端全局状态与常量定义
// ==========================================

static NAS_HISTORY_PATH: &str = "nas_traffic_history.json";

// 用于原先的搬瓦工流量小时级 delta 记录的文件路径
static HISTORY_FILE: Lazy<RwLock<std::path::PathBuf>> = Lazy::new(|| {
    let mut path = std::path::PathBuf::from("traffic_history.json");
    if let Ok(app_dir) = std::env::var("STATIC_DIR")
        && let Some(parent) = std::path::PathBuf::from(app_dir).parent()
    {
        path = parent.join("traffic_history.json");
    }
    RwLock::new(path)
});

static ABNORMAL_TRAFFIC_FILE: Lazy<RwLock<std::path::PathBuf>> = Lazy::new(|| {
    let mut path = std::path::PathBuf::from("nas_abnormal_traffic.json");
    if let Ok(app_dir) = std::env::var("STATIC_DIR")
        && let Some(parent) = std::path::PathBuf::from(app_dir).parent()
    {
        path = parent.join("nas_abnormal_traffic.json");
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
    #[serde(default)]
    pub server_last_counters: HashMap<String, i64>,
    #[serde(default)]
    pub server_last_resets: HashMap<String, i64>,
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
        let default_config = vec![BwgServerConfig {
            name: "示例香港节点".to_string(),
            veid: "123456".to_string(),
            api_key: "your_api_key_here".to_string(),
            ip: "1.2.3.4".to_string(),
        }];
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
    #[serde(default = "default_count")]
    pub count: usize,
    #[serde(default = "default_should_proxy")]
    pub should_proxy: bool,
    #[serde(default)]
    pub category: String,
    #[serde(default)]
    pub reason: String,
}

fn default_count() -> usize {
    1
}

fn default_should_proxy() -> bool {
    true
}

static REG_BYTES_SENT: Lazy<Regex> = Lazy::new(|| Regex::new(r"bytes_sent:(\d+)").unwrap());
static REG_BYTES_RECEIVED: Lazy<Regex> = Lazy::new(|| Regex::new(r"bytes_received:(\d+)").unwrap());

fn parse_ss_total_bytes(stats_line: &str) -> i64 {
    let sent = REG_BYTES_SENT
        .captures(stats_line)
        .and_then(|c| c.get(1))
        .and_then(|m| m.as_str().parse::<i64>().ok())
        .unwrap_or(0);
    let recv = REG_BYTES_RECEIVED
        .captures(stats_line)
        .and_then(|c| c.get(1))
        .and_then(|m| m.as_str().parse::<i64>().ok())
        .unwrap_or(0);
    sent + recv
}

fn validate_ssh_status(success: bool, stderr: &str, user: &str, host: &str) -> Result<(), String> {
    if success {
        return Ok(());
    }
    let message = stderr.trim();
    let message = if message.is_empty() {
        "无 stderr 输出".to_string()
    } else {
        message.chars().take(300).collect()
    };
    Err(format!("SSH 返回失败 ({}@{}): {}", user, host, message))
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

fn merge_classified_delta(
    map: &mut HashMap<String, ClassifiedDomainDelta>,
    domain: &str,
    bytes: i64,
    classification: &TrafficClassification,
) {
    let entry = map
        .entry(domain.to_string())
        .or_insert_with(|| ClassifiedDomainDelta {
            bytes: 0,
            should_proxy: classification.should_proxy,
            category: classification.category.clone(),
            reason: classification.reason.clone(),
        });
    entry.bytes += bytes;
    entry.should_proxy = classification.should_proxy;
    entry.category = classification.category.clone();
    entry.reason = classification.reason.clone();
}

fn report_token() -> Option<String> {
    std::env::var("REPORT_TOKEN")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

fn report_auth_required() -> bool {
    std::env::var("REPORT_AUTH_REQUIRED")
        .map(|v| v != "false" && v != "0")
        .unwrap_or(true)
}

fn dashboard_token() -> Option<String> {
    std::env::var("DASHBOARD_TOKEN")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .or_else(report_token)
}

fn read_auth_required() -> bool {
    std::env::var("READ_AUTH_REQUIRED")
        .map(|v| v != "false" && v != "0")
        .unwrap_or_else(|_| dashboard_token().is_some())
}

fn validate_bearer_auth(
    headers: &HeaderMap,
    expected: Option<String>,
    required: bool,
) -> Result<(), StatusCode> {
    let expected = match expected {
        Some(token) => token,
        None if required => return Err(StatusCode::SERVICE_UNAVAILABLE),
        None => return Ok(()),
    };

    let Some(header) = headers.get("authorization").and_then(|v| v.to_str().ok()) else {
        return Err(StatusCode::UNAUTHORIZED);
    };

    let token = header.strip_prefix("Bearer ").unwrap_or(header).trim();
    if token == expected {
        Ok(())
    } else {
        Err(StatusCode::UNAUTHORIZED)
    }
}

fn validate_report_auth(headers: &HeaderMap) -> Result<(), StatusCode> {
    validate_bearer_auth(headers, report_token(), report_auth_required())
}

fn validate_read_auth(headers: &HeaderMap) -> Result<(), StatusCode> {
    validate_bearer_auth(headers, dashboard_token(), read_auth_required())
}

fn auth_failure_response(status: StatusCode) -> axum::response::Response {
    (
        status,
        [
            ("Access-Control-Allow-Origin", "*"),
            ("Content-Type", "application/json"),
        ],
        Json(serde_json::json!({
            "success": false,
            "message": "authentication failed or token is not configured"
        })),
    )
        .into_response()
}

fn valid_public_label(value: &str, max_len: usize) -> bool {
    !value.trim().is_empty() && value.len() <= max_len && !value.chars().any(|c| c.is_control())
}

fn validate_report_payload(payload: &TrafficReportRequest) -> Result<(), String> {
    if !payload.report_id.is_empty() && !valid_public_label(&payload.report_id, 128) {
        return Err("report_id 包含非法字符或过长".to_string());
    }
    if !valid_public_label(&payload.device_name, 64) {
        return Err("device_name 不能为空，且长度不能超过 64 个字符".to_string());
    }
    if !payload.current_node_ip.is_empty() && !valid_public_label(&payload.current_node_ip, 255) {
        return Err("current_node_ip 包含非法字符或过长".to_string());
    }
    if payload.download_delta < 0 || payload.upload_delta < 0 {
        return Err("流量增量不能为负数".to_string());
    }

    let max_delta = std::env::var("MAX_REPORT_DELTA_BYTES")
        .ok()
        .and_then(|s| s.parse::<i64>().ok())
        .unwrap_or(10 * 1024 * 1024 * 1024 * 1024);
    if payload.download_delta > max_delta || payload.upload_delta > max_delta {
        return Err("单次上报流量超过保护阈值".to_string());
    }

    if payload.domain_deltas.len() > 2000 || payload.abnormal_domain_deltas.len() > 2000 {
        return Err("单次上报域名数量超过保护阈值".to_string());
    }

    for (domain, bytes) in &payload.domain_deltas {
        if *bytes < 0 || *bytes > max_delta {
            return Err(format!("域名 {} 的流量增量非法", domain));
        }
        if !valid_public_label(domain, 253) {
            return Err("域名包含非法字符或过长".to_string());
        }
    }

    for (domain, detail) in &payload.abnormal_domain_deltas {
        if detail.bytes < 0 || detail.bytes > max_delta {
            return Err(format!("异常域名 {} 的流量增量非法", domain));
        }
        if !valid_public_label(domain, 253)
            || !valid_public_label(&detail.category, 64)
            || !valid_public_label(&detail.reason, 256)
        {
            return Err("异常域名分类字段包含非法字符或过长".to_string());
        }
    }

    Ok(())
}

fn is_delta_report(payload: &TrafficReportRequest) -> bool {
    payload.report_kind == "delta"
        || payload.download_delta > 0
        || payload.upload_delta > 0
        || !payload.domain_deltas.is_empty()
        || !payload.abnormal_domain_deltas.is_empty()
}

fn remember_processed_report_id(dev: &mut DeviceHistory, report_id: &str) {
    if report_id.trim().is_empty()
        || dev
            .processed_report_ids
            .iter()
            .any(|existing| existing == report_id)
    {
        return;
    }

    dev.processed_report_ids.push(report_id.to_string());
    const MAX_PROCESSED_REPORT_IDS: usize = 500;
    if dev.processed_report_ids.len() > MAX_PROCESSED_REPORT_IDS {
        let overflow = dev.processed_report_ids.len() - MAX_PROCESSED_REPORT_IDS;
        dev.processed_report_ids.drain(0..overflow);
    }
}

fn effective_abnormal_deltas(
    payload: &TrafficReportRequest,
) -> HashMap<String, ClassifiedDomainDelta> {
    let mut effective_abnormal_deltas = HashMap::<String, ClassifiedDomainDelta>::new();
    for (domain, bytes) in &payload.domain_deltas {
        let classification = classify_proxy_domain(domain);
        if !classification.should_proxy && *bytes > 0 {
            merge_classified_delta(
                &mut effective_abnormal_deltas,
                domain,
                *bytes,
                &classification,
            );
        }
    }
    for (domain, detail) in &payload.abnormal_domain_deltas {
        if detail.bytes > 0 && !payload.domain_deltas.contains_key(domain) {
            let classification = classify_proxy_domain(domain);
            if !classification.should_proxy {
                merge_classified_delta(
                    &mut effective_abnormal_deltas,
                    domain,
                    detail.bytes,
                    &classification,
                );
            }
        }
    }
    effective_abnormal_deltas
}

fn apply_report_to_history(
    history: &mut NasTrafficHistory,
    payload: &TrafficReportRequest,
    now: chrono::DateTime<Local>,
) -> bool {
    let is_delta = is_delta_report(payload);
    let effective_abnormal_deltas = effective_abnormal_deltas(payload);

    {
        let dev = history
            .devices
            .entry(payload.device_name.clone())
            .or_default();

        if is_delta
            && !payload.report_id.is_empty()
            && dev
                .processed_report_ids
                .iter()
                .any(|existing| existing == &payload.report_id)
        {
            dev.last_seen = now.timestamp();
            dev.current_node = payload.current_node_ip.clone();
            return true;
        }

        dev.total_download += payload.download_delta;
        dev.total_upload += payload.upload_delta;
        dev.last_seen = now.timestamp();
        dev.current_node = payload.current_node_ip.clone();
        for (domain, bytes) in &payload.domain_deltas {
            *dev.domain_traffic.entry(domain.clone()).or_insert(0) += bytes;
        }
        for (domain, detail) in &effective_abnormal_deltas {
            dev.total_abnormal_proxy += detail.bytes;
            let classification = TrafficClassification {
                should_proxy: detail.should_proxy,
                category: detail.category.clone(),
                reason: detail.reason.clone(),
            };
            merge_classified_delta(
                &mut dev.abnormal_domain_traffic,
                domain,
                detail.bytes,
                &classification,
            );
        }
        if is_delta {
            remember_processed_report_id(dev, &payload.report_id);
        }
    }

    if !payload.current_node_ip.is_empty()
        && payload.current_node_ip != "未知"
        && payload.current_node_ip != "未配置"
    {
        let cleaned_ip = normalize_node_key(&payload.current_node_ip);
        let node = history.nodes.entry(cleaned_ip).or_default();
        node.total_download += payload.download_delta;
        node.total_upload += payload.upload_delta;
        for (domain, bytes) in &payload.domain_deltas {
            *node.domain_traffic.entry(domain.clone()).or_insert(0) += bytes;
        }
        for (domain, detail) in &effective_abnormal_deltas {
            let classification = TrafficClassification {
                should_proxy: detail.should_proxy,
                category: detail.category.clone(),
                reason: detail.reason.clone(),
            };
            merge_classified_delta(
                &mut node.abnormal_domain_traffic,
                domain,
                detail.bytes,
                &classification,
            );
        }
    }

    let today_str = now.format("%Y-%m-%d").to_string();
    let this_week = now.iso_week().week() as i32;

    if history.daily_api_date != today_str {
        history.daily_api_traffic.clear();
        history.daily_abnormal_traffic.clear();
        history.daily_api_date = today_str;
    }

    if history.weekly_api_week != this_week {
        history.weekly_api_traffic.clear();
        history.weekly_abnormal_traffic.clear();
        history.weekly_api_week = this_week;
    }

    for (domain, bytes) in &payload.domain_deltas {
        if *bytes > 0 {
            *history.daily_api_traffic.entry(domain.clone()).or_insert(0) += bytes;
            *history
                .weekly_api_traffic
                .entry(domain.clone())
                .or_insert(0) += bytes;
        }
    }

    for (domain, detail) in &effective_abnormal_deltas {
        if detail.bytes > 0 {
            let classification = TrafficClassification {
                should_proxy: detail.should_proxy,
                category: detail.category.clone(),
                reason: detail.reason.clone(),
            };
            merge_classified_delta(
                &mut history.daily_abnormal_traffic,
                domain,
                detail.bytes,
                &classification,
            );
            merge_classified_delta(
                &mut history.weekly_abnormal_traffic,
                domain,
                detail.bytes,
                &classification,
            );
        }
    }

    false
}

fn normalize_node_key(raw: &str) -> String {
    let trimmed = raw.trim();
    if trimmed.starts_with('[')
        && let Some(idx) = trimmed.find(']')
    {
        return trimmed[1..idx].to_string();
    }
    if let Some(idx) = trimmed.find(':') {
        trimmed[..idx].to_string()
    } else {
        trimmed.to_string()
    }
}

async fn update_traffic_delta_for_server(server_key: &str, current_counter: i64, reset_time: i64) {
    if current_counter <= 0 {
        return;
    }

    let mut history = load_history().await;
    let last = *history.server_last_counters.get(server_key).unwrap_or(&0);
    let last_reset = *history.server_last_resets.get(server_key).unwrap_or(&0);

    if last == 0 {
        history
            .server_last_counters
            .insert(server_key.to_string(), current_counter);
        history
            .server_last_resets
            .insert(server_key.to_string(), reset_time);
        history.last_counter = current_counter;
        history.last_reset = reset_time;
        save_history(&history).await;
        return;
    }

    let delta = if (reset_time > 0 && reset_time != last_reset) || current_counter < last {
        current_counter
    } else {
        current_counter - last
    };

    if delta > 0 {
        let hour_key = Local::now().format("%Y-%m-%d %H:00").to_string();
        *history.hourly_usage.entry(hour_key.clone()).or_insert(0) += delta;
        println!(
            "记录到官方新增流量: {} 字节, 服务器: {}, 小时: {}",
            delta, server_key, hour_key
        );
    }

    history
        .server_last_counters
        .insert(server_key.to_string(), current_counter);
    history
        .server_last_resets
        .insert(server_key.to_string(), reset_time);
    history.last_counter = history.server_last_counters.values().sum();
    history.last_reset = reset_time;
    save_history(&history).await;
}

// 后台搬瓦工 API 定时采集
fn start_bwg_collector() {
    tokio::spawn(async {
        let client = reqwest::Client::new();
        loop {
            let configs = load_bwg_server_configs();
            let mut new_statuses = Vec::new();

            for cfg in configs {
                if cfg.api_key == "your_api_key_here" || cfg.veid == "123456" {
                    continue;
                }
                let api_url = format!(
                    "https://api.64clouds.com/v1/getServiceInfo?veid={}&api_key={}",
                    cfg.veid, cfg.api_key
                );

                if let Ok(resp) = client.get(&api_url).send().await
                    && let Ok(bwg_data) = resp.json::<BwgApiResponse>().await
                    && bwg_data.error == 0
                {
                    update_traffic_delta_for_server(
                        &cfg.ip,
                        bwg_data.data_counter,
                        bwg_data.data_next_reset,
                    )
                    .await;
                    new_statuses.push(BwgServerLiveStatus {
                        name: cfg.name.clone(),
                        ip: cfg.ip.clone(),
                        official_used_bytes: bwg_data.data_counter,
                        official_limit_bytes: bwg_data.plan_monthly_data,
                        next_reset_time: bwg_data.data_next_reset,
                    });
                }
            }

            if !new_statuses.is_empty() {
                let mut guard = BWG_SERVERS_STATUS.write().await;
                *guard = new_statuses;
            }

            sleep(Duration::from_secs(15 * 60)).await; // 15分钟更新一次
        }
    });
}

// GET /api/bwg 处理器：保留兼容旧前端，只返回缓存后的脱敏状态。
async fn bwg_handler(headers: HeaderMap) -> axum::response::Response {
    if let Err(status) = validate_read_auth(&headers) {
        return auth_failure_response(status);
    }

    let statuses = BWG_SERVERS_STATUS.read().await.clone();

    (
        StatusCode::OK,
        [
            ("Access-Control-Allow-Origin", "*"),
            ("Content-Type", "application/json"),
        ],
        Json(statuses),
    )
        .into_response()
}

// GET /api/history 处理器
async fn history_handler(headers: HeaderMap) -> axum::response::Response {
    if let Err(status) = validate_read_auth(&headers) {
        return auth_failure_response(status);
    }

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
        weekly_labels.push(format!("{}~{}", start.format("%m-%d"), end.format("%m-%d")));

        let mut sum = 0;
        for (hour_str, &bytes) in &history.hourly_usage {
            if hour_str.len() >= 10
                && let Ok(d) = chrono::NaiveDate::parse_from_str(&hour_str[..10], "%Y-%m-%d")
            {
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

// 远程单个 VPS 数据拉取
async fn fetch_single_vps_data(
    host: String,
    port: String,
    user: String,
) -> Result<(Vec<LogRecord>, HashMap<String, i64>, HashMap<String, i64>), String> {
    let tail_lines = std::env::var("VPS_LOG_TAIL_LINES")
        .ok()
        .and_then(|s| s.parse::<u32>().ok())
        .unwrap_or(10000);
    let cmd_str = format!(
        "tail -n {} /var/log/v2ray/access.log 2>/dev/null || true; echo '===TRAFFIC_JSON==='; cat /var/log/v2ray/domain_traffic.json 2>/dev/null || echo '{{}}'",
        tail_lines
    );
    let strict_host_key =
        std::env::var("SSH_STRICT_HOST_KEY_CHECKING").unwrap_or_else(|_| "accept-new".to_string());
    let strict_host_key_arg = format!("StrictHostKeyChecking={}", strict_host_key);
    let destination = format!("{}@{}", user, host);

    let output = tokio::process::Command::new("ssh")
        .args([
            "-o",
            &strict_host_key_arg,
            "-o",
            "ConnectTimeout=10",
            "-p",
            &port,
            &destination,
            &cmd_str,
        ])
        .output()
        .await
        .map_err(|e| format!("执行 SSH 失败 ({}@{}): {}", user, host, e))?;

    validate_ssh_status(
        output.status.success(),
        &String::from_utf8_lossy(&output.stderr),
        &user,
        &host,
    )?;

    let stdout_str = String::from_utf8_lossy(&output.stdout);

    let mut records = Vec::new();
    let mut traffic_map = HashMap::new();
    let mut requests_map = HashMap::new();

    let mut in_json = false;
    let mut json_str = String::new();

    let reg = Regex::new(r"^([\d/]+\s+[\d:]+)\s+([\d\.:]+)\s+(accepted|rejected|rejected\s+again)\s+(tcp|udp):([\w\.\-]+:\d+)\s+\[([\w\-]+)\]").unwrap();

    #[derive(Deserialize)]
    struct VpsTrafficData {
        traffic: HashMap<String, i64>,
        requests: HashMap<String, i64>,
    }

    for line in stdout_str.lines() {
        if line == "===TRAFFIC_JSON===" {
            in_json = true;
            continue;
        }

        if in_json {
            json_str.push_str(line);
            json_str.push('\n');
        } else {
            // 解析 access.log 日志行 (只用于异常明细表格)
            if let Some(caps) = reg.captures(line) {
                let target = caps.get(5).map_or("", |m| m.as_str()).to_string();
                let classification = classify_proxy_domain(&target);
                if !classification.should_proxy {
                    records.push(LogRecord {
                        time: caps.get(1).map_or("", |m| m.as_str()).to_string(),
                        source: caps.get(2).map_or("", |m| m.as_str()).to_string(),
                        action: caps.get(3).map_or("", |m| m.as_str()).to_string(),
                        target,
                        strategy: caps.get(6).map_or("", |m| m.as_str()).to_string(),
                        count: 1,
                        should_proxy: classification.should_proxy,
                        category: classification.category,
                        reason: classification.reason,
                    });
                }
            } else {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 6 {
                    let time_str = format!("{} {}", parts[0], parts[1]);
                    let source_str = parts[2].to_string();
                    let action_str = parts[3].to_string();
                    let mut target_str = String::new();
                    let mut strategy_str = String::new();

                    for &part in &parts {
                        if (part.starts_with("tcp:") || part.starts_with("udp:"))
                            && let Some(idx) = part.find(':')
                        {
                            target_str = part[idx + 1..].to_string();
                        }
                        if part.starts_with('[') && part.ends_with(']') {
                            strategy_str = part.trim_matches(|c| c == '[' || c == ']').to_string();
                        }
                    }

                    if !target_str.is_empty() {
                        let classification = classify_proxy_domain(&target_str);
                        if !classification.should_proxy {
                            records.push(LogRecord {
                                time: time_str,
                                source: source_str,
                                action: action_str,
                                target: target_str,
                                strategy: strategy_str,
                                count: 1,
                                should_proxy: classification.should_proxy,
                                category: classification.category,
                                reason: classification.reason,
                            });
                        }
                    }
                }
            }
        }
    }

    if !json_str.trim().is_empty() {
        if let Ok(data) = serde_json::from_str::<VpsTrafficData>(&json_str) {
            traffic_map = data.traffic;
            requests_map = data.requests;
        } else if let Ok(map) = serde_json::from_str::<HashMap<String, i64>>(&json_str) {
            traffic_map = map;
        }
    }

    Ok((records, traffic_map, requests_map))
}

// 远程 SSH 拉取所有 VPS 流量与请求频次数据并进行合并
async fn fetch_abnormal_traffic() {
    let hosts_env = std::env::var("VPS_SSH_HOSTS").unwrap_or_default();
    let ports_env = std::env::var("VPS_SSH_PORTS").unwrap_or_default();
    let users_env = std::env::var("VPS_SSH_USERS").unwrap_or_default();

    let mut nodes = Vec::new();

    if !hosts_env.is_empty() {
        let hosts: Vec<&str> = hosts_env.split(',').collect();
        let ports: Vec<&str> = ports_env.split(',').collect();
        let users: Vec<&str> = users_env.split(',').collect();

        for (i, raw_host) in hosts.iter().enumerate() {
            let host = raw_host.trim().to_string();
            if host.is_empty() {
                continue;
            }
            let port = ports.get(i).unwrap_or(&"22").trim().to_string();
            let user = users.get(i).unwrap_or(&"root").trim().to_string();
            nodes.push((host, port, user));
        }
    } else {
        // 兼容单 VPS 配置
        let host = std::env::var("VPS_SSH_HOST").unwrap_or_default();
        let port = std::env::var("VPS_SSH_PORT").unwrap_or_default();
        let user = std::env::var("VPS_SSH_USER").unwrap_or_default();
        if !host.is_empty() {
            nodes.push((host, port, user));
        }
    }

    if nodes.is_empty() {
        return;
    }

    let mut tasks = Vec::new();
    for (host, port, user) in nodes {
        tasks.push(tokio::spawn(async move {
            match fetch_single_vps_data(host.clone(), port.clone(), user.clone()).await {
                Ok(data) => Some(data),
                Err(e) => {
                    eprintln!("拉取 VPS ({}:{}) 数据失败: {}", host, port, e);
                    None
                }
            }
        }));
    }

    let mut all_records = Vec::new();
    let mut all_domain_traffics = HashMap::new();
    let mut all_domain_requests = HashMap::new();
    let mut any_success = false;

    for task in tasks {
        if let Ok(Some((records, domain_traffics, domain_requests))) = task.await {
            any_success = true;
            all_records.extend(records);
            for (domain, bytes) in domain_traffics {
                *all_domain_traffics.entry(domain).or_insert(0) += bytes;
            }
            for (domain, count) in domain_requests {
                *all_domain_requests.entry(domain).or_insert(0) += count;
            }
        }
    }

    if !any_success {
        eprintln!("本轮 VPS 异常数据拉取全部失败，保留上一轮缓存。");
        return;
    }

    // 按网址（不含端口的域名/IP）对异常记录进行合并、计数并保留最新的一条状态
    let mut merged_records = HashMap::new();
    for rec in all_records {
        let key = normalize_traffic_target(&rec.target);
        if key.is_empty() {
            continue;
        }

        let existing = merged_records.entry(key).or_insert(LogRecord {
            time: String::new(),
            source: String::new(),
            action: String::new(),
            target: String::new(),
            strategy: String::new(),
            count: 0,
            should_proxy: true,
            category: String::new(),
            reason: String::new(),
        });

        existing.count += 1;
        if existing.time.is_empty() || rec.time > existing.time {
            existing.time = rec.time;
            existing.source = rec.source;
            existing.action = rec.action;
            existing.target = rec.target;
            existing.strategy = rec.strategy;
            existing.should_proxy = rec.should_proxy;
            existing.category = rec.category;
            existing.reason = rec.reason;
        }
    }

    let mut final_records: Vec<LogRecord> = merged_records.into_values().collect();
    // 按照最新时间降序排序
    final_records.sort_by(|a, b| b.time.cmp(&a.time));

    // 计算全局所有代理域名请求频次排行 Top 10
    let mut top_domains: Vec<TopDomain> = all_domain_requests
        .into_iter()
        .map(|(domain, count)| TopDomain {
            domain,
            count: count as usize,
        })
        .collect();
    top_domains.sort_by(|a, b| b.count.cmp(&a.count));
    if top_domains.len() > 10 {
        top_domains.truncate(10);
    }

    // 截取最新的 20 条日志
    if final_records.len() > 20 {
        final_records.truncate(20);
    }

    // 转换域名流量统计并排序 (所有代理域名流量排行 Top 10)
    let mut domain_traffics = Vec::new();
    for (domain, bytes) in all_domain_traffics {
        domain_traffics.push(DomainTraffic { domain, bytes });
    }
    domain_traffics.sort_by(|a, b| b.bytes.cmp(&a.bytes));
    if domain_traffics.len() > 10 {
        domain_traffics.truncate(10);
    }

    let mut response_guard = ABNORMAL_RESPONSE.write().await;
    *response_guard = AbnormalTrafficResponse {
        records: final_records,
        top_domains,
        domain_traffics,
    };

    save_abnormal_traffic(&response_guard).await;
    println!("成功更新全局合并后的异常明细与所有代理流量/频次排行缓存，并写入持久化。");
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

async fn abnormal_traffic_handler(headers: HeaderMap) -> axum::response::Response {
    if let Err(status) = validate_read_auth(&headers) {
        return auth_failure_response(status);
    }

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

#[derive(Serialize)]
struct ApiTrafficItem {
    domain: String,
    bytes: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    should_proxy: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    category: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    reason: Option<String>,
}

#[derive(Serialize)]
struct ApiTrafficResponse {
    daily: Vec<ApiTrafficItem>,
    weekly: Vec<ApiTrafficItem>,
    abnormal_daily: Vec<ApiTrafficItem>,
    abnormal_weekly: Vec<ApiTrafficItem>,
}

async fn api_traffic_handler(
    State(state): State<ServerHistoryState>,
    headers: HeaderMap,
) -> axum::response::Response {
    if let Err(status) = validate_read_auth(&headers) {
        return auth_failure_response(status);
    }

    let history = state.read().await;

    // 转换每日统计并排序 Top 10
    let mut daily: Vec<ApiTrafficItem> = history
        .daily_api_traffic
        .iter()
        .map(|(k, &v)| ApiTrafficItem {
            domain: k.clone(),
            bytes: v,
            should_proxy: None,
            category: None,
            reason: None,
        })
        .collect();
    daily.sort_by(|a, b| b.bytes.cmp(&a.bytes));
    if daily.len() > 10 {
        daily.truncate(10);
    }

    // 转换每周统计并排序 Top 10
    let mut weekly: Vec<ApiTrafficItem> = history
        .weekly_api_traffic
        .iter()
        .map(|(k, &v)| ApiTrafficItem {
            domain: k.clone(),
            bytes: v,
            should_proxy: None,
            category: None,
            reason: None,
        })
        .collect();
    weekly.sort_by(|a, b| b.bytes.cmp(&a.bytes));
    if weekly.len() > 10 {
        weekly.truncate(10);
    }

    let mut abnormal_daily: Vec<ApiTrafficItem> = history
        .daily_abnormal_traffic
        .iter()
        .map(|(domain, detail)| ApiTrafficItem {
            domain: domain.clone(),
            bytes: detail.bytes,
            should_proxy: Some(detail.should_proxy),
            category: Some(detail.category.clone()),
            reason: Some(detail.reason.clone()),
        })
        .collect();
    abnormal_daily.sort_by(|a, b| b.bytes.cmp(&a.bytes));
    if abnormal_daily.len() > 10 {
        abnormal_daily.truncate(10);
    }

    let mut abnormal_weekly: Vec<ApiTrafficItem> = history
        .weekly_abnormal_traffic
        .iter()
        .map(|(domain, detail)| ApiTrafficItem {
            domain: domain.clone(),
            bytes: detail.bytes,
            should_proxy: Some(detail.should_proxy),
            category: Some(detail.category.clone()),
            reason: Some(detail.reason.clone()),
        })
        .collect();
    abnormal_weekly.sort_by(|a, b| b.bytes.cmp(&a.bytes));
    if abnormal_weekly.len() > 10 {
        abnormal_weekly.truncate(10);
    }

    let resp = ApiTrafficResponse {
        daily,
        weekly,
        abnormal_daily,
        abnormal_weekly,
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
    headers: HeaderMap,
    Json(payload): Json<TrafficReportRequest>,
) -> impl IntoResponse {
    if let Err(status) = validate_report_auth(&headers) {
        return (
            status,
            Json(serde_json::json!({
                "success": false,
                "message": "report authentication failed or REPORT_TOKEN is not configured"
            })),
        )
            .into_response();
    }

    if let Err(message) = validate_report_payload(&payload) {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "success": false, "message": message })),
        )
            .into_response();
    }

    let mut history = state.write().await;
    let now = Local::now();
    let duplicate = apply_report_to_history(&mut history, &payload, now);
    save_nas_history(NAS_HISTORY_PATH, &history);
    (
        StatusCode::OK,
        Json(serde_json::json!({ "success": true, "duplicate": duplicate })),
    )
        .into_response()
}

#[derive(Serialize)]
struct DeviceResponseInfo {
    name: String,
    total_download: i64,
    total_upload: i64,
    total_abnormal_proxy: i64,
    last_seen: i64,
    current_node: String,
    online: bool,
    top_abnormal_domains: Vec<ApiTrafficItem>,
}

fn device_online_threshold_secs() -> i64 {
    std::env::var("DEVICE_ONLINE_SECS")
        .ok()
        .and_then(|s| s.parse::<i64>().ok())
        .unwrap_or(90)
}

// GET /api/devices
async fn get_devices_handler(
    State(state): State<ServerHistoryState>,
    headers: HeaderMap,
) -> axum::response::Response {
    if let Err(status) = validate_read_auth(&headers) {
        return auth_failure_response(status);
    }

    let history = state.read().await;
    let now = Local::now().timestamp();
    let mut list = Vec::new();
    let online_threshold = device_online_threshold_secs();

    for (name, dev) in &history.devices {
        let online = now - dev.last_seen < online_threshold;
        let mut top_abnormal_domains: Vec<ApiTrafficItem> = dev
            .abnormal_domain_traffic
            .iter()
            .map(|(domain, detail)| ApiTrafficItem {
                domain: domain.clone(),
                bytes: detail.bytes,
                should_proxy: Some(detail.should_proxy),
                category: Some(detail.category.clone()),
                reason: Some(detail.reason.clone()),
            })
            .collect();
        top_abnormal_domains.sort_by(|a, b| b.bytes.cmp(&a.bytes));
        if top_abnormal_domains.len() > 5 {
            top_abnormal_domains.truncate(5);
        }
        list.push(DeviceResponseInfo {
            name: name.clone(),
            total_download: dev.total_download,
            total_upload: dev.total_upload,
            total_abnormal_proxy: dev.total_abnormal_proxy,
            last_seen: dev.last_seen,
            current_node: dev.current_node.clone(),
            online,
            top_abnormal_domains,
        });
    }

    list.sort_by(|a, b| a.name.cmp(&b.name));
    (StatusCode::OK, Json(list)).into_response()
}

// GET /api/nodes
async fn get_nodes_handler(
    State(state): State<ServerHistoryState>,
    headers: HeaderMap,
) -> axum::response::Response {
    if let Err(status) = validate_read_auth(&headers) {
        return auth_failure_response(status);
    }

    let history = state.read().await;
    let live_statuses = BWG_SERVERS_STATUS.read().await;
    let mut list = Vec::new();
    let now = Local::now().timestamp();
    let active_threshold = device_online_threshold_secs().max(60);

    for server in live_statuses.iter() {
        let mut client_dl = 0;
        let mut client_ul = 0;
        let mut abnormal_client = 0;
        if let Some(node) = history.nodes.get(&server.ip) {
            client_dl = node.total_download;
            client_ul = node.total_upload;
            abnormal_client = node.abnormal_domain_traffic.values().map(|v| v.bytes).sum();
        }

        let mut active_devices = Vec::new();
        for (name, dev) in &history.devices {
            let cleaned_node = normalize_node_key(&dev.current_node);
            if cleaned_node == server.ip && (now - dev.last_seen < active_threshold) {
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
            "client_abnormal": abnormal_client,
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
                "client_abnormal": node.abnormal_domain_traffic.values().map(|v| v.bytes).sum::<i64>(),
                "active_devices": Vec::<String>::new(),
            }));
        }
    }

    list.sort_by(|a, b| {
        let na = a.get("name").and_then(|v| v.as_str()).unwrap_or("");
        let nb = b.get("name").and_then(|v| v.as_str()).unwrap_or("");
        na.cmp(nb)
    });

    (StatusCode::OK, Json(list)).into_response()
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
async fn get_local_status_handler(State(state): State<Arc<LocalDaemonState>>) -> impl IntoResponse {
    let active_node = state.current_node.read().await.clone();

    let client = reqwest::Client::new();
    let conn_url = format!(
        "{}/connections",
        state.singbox_api_url.trim_end_matches('/')
    );
    let mut singbox_online = false;
    let mut total_dl = 0;
    let mut total_ul = 0;

    if let Ok(resp) = client
        .get(&conn_url)
        .timeout(Duration::from_secs(1))
        .send()
        .await
        && let Ok(data) = resp.json::<ClashAPIConnections>().await
    {
        singbox_online = true;
        total_dl = data.download_total;
        total_ul = data.upload_total;
    }

    let nas_test_url = format!("{}/api/nodes", state.nas_server_url.trim_end_matches('/'));
    let mut nas_request = client.get(&nas_test_url).timeout(Duration::from_secs(1));
    if let Some(token) = dashboard_token() {
        nas_request = nas_request.bearer_auth(token);
    }
    let nas_connected = nas_request
        .send()
        .await
        .map(|resp| resp.status().is_success())
        .unwrap_or(false);

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

// POST /api/local/singbox/{action}
async fn manage_singbox_handler(Path(action): Path<String>) -> impl IntoResponse {
    let Some(action) = SingboxAction::from_str(&action) else {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "success": false,
                "message": "action 只支持 start、stop、restart",
            })),
        )
            .into_response();
    };

    match manage_singbox(action).await {
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
async fn add_local_node_handler(Json(req): Json<AddNodeRequest>) -> impl IntoResponse {
    let mut nodes = load_local_nodes();

    if let Some(existing) = nodes.iter_mut().find(|n| n.name == req.name) {
        existing.server = req.server;
        existing.server_port = req.server_port;
        existing.password = req.password;
        existing.server_name = req.server_name;
        existing.outbound = req.outbound;
    } else {
        nodes.push(NodeConfig {
            name: req.name.clone(),
            server: req.server,
            server_port: req.server_port,
            password: req.password,
            server_name: req.server_name,
            outbound: req.outbound,
        });
    }

    save_local_nodes(&nodes);
    (
        StatusCode::OK,
        Json(
            serde_json::json!({ "success": true, "message": format!("成功添加/修改本地节点 '{}'", req.name) }),
        ),
    )
}

// DELETE /api/local/nodes/:name
async fn delete_local_node_handler(Path(name): Path<String>) -> impl IntoResponse {
    let mut nodes = load_local_nodes();
    let prev_len = nodes.len();
    nodes.retain(|n| n.name != name);

    if nodes.len() < prev_len {
        save_local_nodes(&nodes);
        (
            StatusCode::OK,
            Json(
                serde_json::json!({ "success": true, "message": format!("已成功删除本地节点 '{}'", name) }),
            ),
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
    if report_token().is_none() && report_auth_required() {
        eprintln!(
            "⚠️  REPORT_TOKEN 未配置：/api/report 将拒绝写入。请在 config.env 中设置 REPORT_TOKEN，或仅在临时内网调试时设置 REPORT_AUTH_REQUIRED=false。"
        );
    }

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
        .route("/api/api_traffic", get(api_traffic_handler))
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

    if let Err(e) = node::check_and_apply_control_domain_bypass().await {
        eprintln!("⚠️  自动配置 sing-box 大盘域名直连绕过失败: {}", e);
    }

    if env_flag("SINGBOX_RESTART_ON_DAEMON_START") {
        println!(">>> SINGBOX_RESTART_ON_DAEMON_START 已开启，正在通过 helper 重启 sing-box...");
        match manage_singbox(SingboxAction::Restart).await {
            Ok(msg) => println!(">>> {}", msg),
            Err(e) => eprintln!("⚠️  守护进程启动时重启 sing-box 失败: {}", e),
        }
    }

    let device_name = std::env::var("DEVICE_NAME").unwrap_or_else(|_| "MacBook".to_string());
    let nas_server_url = std::env::var("NAS_SERVER_URL")
        .unwrap_or_else(|_| "https://your-nas-domain.com:8443".to_string());
    let singbox_api_url =
        std::env::var("SINGBOX_CLASH_API").unwrap_or_else(|_| "http://127.0.0.1:9090".to_string());
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
        .route(
            "/api/local/nodes",
            get(get_local_nodes_handler).post(add_local_node_handler),
        )
        .route("/api/local/nodes/{name}", delete(delete_local_node_handler))
        .route("/api/local/switch", post(switch_local_node_handler))
        .route("/api/local/singbox/{action}", post(manage_singbox_handler))
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

fn env_flag(name: &str) -> bool {
    std::env::var(name)
        .map(|value| {
            matches!(
                value.trim().to_ascii_lowercase().as_str(),
                "1" | "true" | "yes" | "y" | "on"
            )
        })
        .unwrap_or(false)
}

async fn run_cli_status() {
    let client = get_local_daemon_client();
    let port = get_local_daemon_port();
    let url = format!("http://127.0.0.1:{}/api/local/status", port);

    match client.get(&url).send().await {
        Ok(resp) => {
            if let Ok(val) = resp.json::<serde_json::Value>().await {
                let dev_name = val
                    .get("device_name")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                let node = val
                    .get("current_node")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                let sb_online = val
                    .get("singbox_online")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false);
                let nas_conn = val
                    .get("nas_connected")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false);
                let total_dl = val
                    .get("singbox_total_download")
                    .and_then(|v| v.as_i64())
                    .unwrap_or(0);
                let total_ul = val
                    .get("singbox_total_upload")
                    .and_then(|v| v.as_i64())
                    .unwrap_or(0);
                let nas_url = val
                    .get("nas_server_url")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");

                println!("========================================");
                println!("💻 本机设备名称: {}", dev_name);
                println!("🌐 当前出站节点: {}", node);
                println!(
                    "⚙️  sing-box 状态: {}",
                    if sb_online {
                        "🟢 在线"
                    } else {
                        "🔴 离线 (未启动或 Clash API 端口不通)"
                    }
                );
                println!("📊 累计下载流量: {:.2} GB", total_dl as f64 / 1073741824.0);
                println!("📊 累计上传流量: {:.2} GB", total_ul as f64 / 1073741824.0);
                println!(
                    "📊 累计消耗总量: {:.2} GB",
                    (total_dl + total_ul) as f64 / 1073741824.0
                );
                println!(
                    "📦 NAS 大盘状态: {} ({})",
                    if nas_conn {
                        "🟢 已连接"
                    } else {
                        "🔴 连接失败"
                    },
                    nas_url
                );
                println!("========================================");
            } else {
                eprintln!("解析守护进程数据失败");
            }
        }
        Err(_) => {
            eprintln!(
                "❌ 错误: 无法连接至本地守护进程。请先运行 'bwg_usage daemon' 启动后台程序。"
            );
        }
    }
}

async fn run_cli_node_list() {
    let client = get_local_daemon_client();
    let port = get_local_daemon_port();
    let url = format!("http://127.0.0.1:{}/api/local/nodes", port);

    let status_url = format!("http://127.0.0.1:{}/api/local/status", port);
    let mut current_node = String::new();
    if let Ok(resp) = client.get(&status_url).send().await
        && let Ok(val) = resp.json::<serde_json::Value>().await
    {
        current_node = val
            .get("current_node")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
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
            eprintln!(
                "❌ 错误: 无法连接至本地守护进程。请先运行 'bwg_usage daemon' 启动后台程序。"
            );
        }
    }
}

async fn run_cli_node_switch(name: &str) {
    let client = get_local_daemon_client();
    let port = get_local_daemon_port();
    let url = format!("http://127.0.0.1:{}/api/local/switch", port);

    println!(">>> 正在请求本地守护进程切换到节点 '{}'...", name);
    match client
        .post(&url)
        .json(&serde_json::json!({ "name": name }))
        .send()
        .await
    {
        Ok(resp) => {
            if let Ok(res_val) = resp.json::<serde_json::Value>().await {
                let success = res_val
                    .get("success")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false);
                let message = res_val
                    .get("message")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
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

async fn run_cli_singbox_action(action: &str) {
    let Some(action) = SingboxAction::from_str(action) else {
        eprintln!("❌ 错误: singbox 只支持 start、stop、restart");
        return;
    };

    let client = get_local_daemon_client();
    let port = get_local_daemon_port();
    let url = format!(
        "http://127.0.0.1:{}/api/local/singbox/{}",
        port,
        action.as_str()
    );

    println!(
        ">>> 正在请求本地守护进程执行 sing-box {}...",
        action.as_str()
    );
    match client.post(&url).send().await {
        Ok(resp) => {
            if let Ok(res_val) = resp.json::<serde_json::Value>().await {
                let success = res_val
                    .get("success")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false);
                let message = res_val
                    .get("message")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                if success {
                    println!("🟢 成功: {}", message);
                } else {
                    println!("🔴 失败: {}", message);
                }
            }
        }
        Err(_) => {
            eprintln!("⚠️  无法连接本地守护进程，尝试由当前命令直接管理 sing-box...");
            match manage_singbox(action).await {
                Ok(msg) => println!("🟢 成功: {}", msg),
                Err(e) => eprintln!("🔴 失败: {}", e),
            }
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
                let success = res_val
                    .get("success")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false);
                let message = res_val
                    .get("message")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
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
                } else {
                    i += 1;
                }
            }
            "--server" => {
                if i + 1 < args.len() {
                    server = args[i + 1].clone();
                    i += 2;
                } else {
                    i += 1;
                }
            }
            "--port" => {
                if i + 1 < args.len() {
                    port = args[i + 1].parse().unwrap_or(0);
                    i += 2;
                } else {
                    i += 1;
                }
            }
            "--password" => {
                if i + 1 < args.len() {
                    password = Some(args[i + 1].clone());
                    i += 2;
                } else {
                    i += 1;
                }
            }
            "--sni" => {
                if i + 1 < args.len() {
                    sni = Some(args[i + 1].clone());
                    i += 2;
                } else {
                    i += 1;
                }
            }
            _ => i += 1,
        }
    }

    if name.is_empty() || server.is_empty() || port == 0 {
        eprintln!("❌ 错误: 必须指定 --name, --server 和 --port 参数！");
        println!(
            "用法: bwg_usage node add --name HK-01 --server hk.vps.com --port 443 --password mypass [--sni hk.vps.com]"
        );
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
                let success = res_val
                    .get("success")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false);
                let message = res_val
                    .get("message")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
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

// 纯 Rust 实现的 VPS 域名流量与频次统计分析逻辑
async fn run_v2ray_traffic_analyzer() {
    println!("纯 Rust VPS 域名流量与频次统计分析服务已启动...");

    let log_file_path = "/var/log/v2ray/access.log";
    let output_file = "/var/log/v2ray/domain_traffic.json";

    #[derive(Serialize, Deserialize, Clone, Default)]
    struct VpsTrafficData {
        traffic: HashMap<String, i64>,
        requests: HashMap<String, i64>,
    }

    // 1. 初始化，尝试读取历史域名流量与频次记录以保持数据连续性
    let domain_traffic = Arc::new(RwLock::new(HashMap::<String, i64>::new()));
    let domain_requests = Arc::new(RwLock::new(HashMap::<String, i64>::new()));

    if let Ok(content) = fs::read_to_string(output_file) {
        if let Ok(data) = serde_json::from_str::<VpsTrafficData>(&content) {
            let mut t_guard = domain_traffic.write().await;
            let mut r_guard = domain_requests.write().await;
            *t_guard = data.traffic;
            *r_guard = data.requests;

            println!(
                "已载入历史统计：{} 个域名的流量，{} 个域名的频次",
                t_guard.len(),
                r_guard.len()
            );
        } else if let Ok(map) = serde_json::from_str::<HashMap<String, i64>>(&content) {
            // 容错载入旧流量单 Map 格式
            let mut t_guard = domain_traffic.write().await;
            *t_guard = map;

            println!("已从旧格式载入历史流量统计：{} 个域名", t_guard.len());
        }
    }

    let port_to_domain = Arc::new(RwLock::new(HashMap::<u16, String>::new()));
    let active_connections = Arc::new(RwLock::new(HashMap::<u16, i64>::new()));

    // 2. 启动文件追加读取任务监控日志，统计所有域名请求频次并关联端口
    let p_to_d = Arc::clone(&port_to_domain);
    let d_reqs = Arc::clone(&domain_requests);
    tokio::spawn(async move {
        let mut check_count = 0;
        while !std::path::Path::new(log_file_path).exists() {
            if check_count % 30 == 0 {
                println!("等待日志文件 {} 创建...", log_file_path);
            }
            check_count += 1;
            sleep(Duration::from_secs(2)).await;
        }

        let file = match File::open(log_file_path) {
            Ok(f) => f,
            Err(e) => {
                eprintln!("错误: 无法打开日志文件: {}", e);
                return;
            }
        };
        let mut reader = BufReader::new(file);
        let _ = reader.seek(SeekFrom::End(0));

        let mut line = String::new();
        let reg = Regex::new(r"accepted\s+(?:tcp|udp):([\w\.\-]+:\d+)").unwrap();

        loop {
            line.clear();
            match reader.read_line(&mut line) {
                Ok(0) => {
                    // 没有新数据，睡眠 500ms
                    sleep(Duration::from_millis(500)).await;
                }
                Ok(_) => {
                    let parts: Vec<&str> = line.split_whitespace().collect();
                    if parts.len() >= 5 && line.contains("accepted") {
                        let source_str = parts[2];
                        if let Some(colon_idx) = source_str.rfind(':')
                            && let Ok(port) = source_str[colon_idx + 1..].parse::<u16>()
                            && let Some(caps) = reg.captures(&line)
                            && let Some(target) = caps.get(1)
                        {
                            let target_str = target.as_str();
                            let domain = normalize_traffic_target(target_str);
                            if domain.is_empty() {
                                continue;
                            }

                            // 记录端口到域名映射
                            let mut guard = p_to_d.write().await;
                            guard.insert(port, domain.clone());

                            // 累加所有域名请求频次
                            let mut req_guard = d_reqs.write().await;
                            *req_guard.entry(domain).or_insert(0) += 1;
                        }
                    }
                }
                Err(e) => {
                    eprintln!("读取日志新行出错: {}", e);
                    sleep(Duration::from_secs(1)).await;
                }
            }
        }
    });

    // 3. 主循环，每 3 秒运行 `ss` 扫描套接字流量并进行统计累加与持久化
    let reg_conn = Regex::new(r#"users:\(\("(?:v2ray|xray)""#).unwrap();

    loop {
        sleep(Duration::from_secs(3)).await;

        let output = match tokio::process::Command::new("ss")
            .args(["-t", "-p", "-i", "-H"])
            .output()
            .await
        {
            Ok(out) => out,
            Err(e) => {
                eprintln!("运行 ss 命令失败: {}", e);
                continue;
            }
        };

        let stdout_str = String::from_utf8_lossy(&output.stdout);
        let lines: Vec<&str> = stdout_str.lines().collect();
        let mut current_active_ports = std::collections::HashSet::new();

        let mut i = 0;
        while i < lines.len() {
            let line = lines[i];
            if reg_conn.is_match(line) {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 5 {
                    let remote_str = parts[4];
                    if let Some(colon_idx) = remote_str.rfind(':')
                        && let Ok(port) = remote_str[colon_idx + 1..].parse::<u16>()
                    {
                        current_active_ports.insert(port);

                        if i + 1 < lines.len() {
                            let next_line = lines[i + 1];
                            let total_bytes = parse_ss_total_bytes(next_line);

                            let p_to_d = port_to_domain.read().await;
                            if let Some(domain) = p_to_d.get(&port) {
                                let mut active_conns_guard = active_connections.write().await;
                                let mut domain_traffic_guard = domain_traffic.write().await;

                                if let Some(&last) = active_conns_guard.get(&port) {
                                    let delta = total_bytes - last;
                                    if delta > 0 {
                                        *domain_traffic_guard.entry(domain.clone()).or_insert(0) +=
                                            delta;
                                    }
                                }
                                active_conns_guard.insert(port, total_bytes);
                            }
                        }
                    }
                }
                i += 2;
            } else {
                i += 1;
            }
        }

        // 清理已断开的连接以防内存无限增长
        {
            let mut active_conns_guard = active_connections.write().await;
            let mut p_to_d = port_to_domain.write().await;
            active_conns_guard.retain(|port, _| current_active_ports.contains(port));
            p_to_d.retain(|port, _| current_active_ports.contains(port));
        }

        // 定期写入 JSON 持久化 (以双 Map 格式输出)
        let content = {
            let t_guard = domain_traffic.read().await;
            let r_guard = domain_requests.read().await;
            let data = VpsTrafficData {
                traffic: t_guard.clone(),
                requests: r_guard.clone(),
            };
            serde_json::to_string_pretty(&data).ok()
        };
        if let Some(json_str) = content {
            let _ = fs::write(output_file, json_str);
        }
    }
}

fn print_help() {
    println!("BandwagonHost & sing-box 分布式流量统计与本地节点管理工具");
    println!("用法:");
    println!("  bwg_usage server                       运行于 NAS 端，启动公共 Web 大盘与上报服务");
    println!(
        "  bwg_usage daemon                       运行于 Mac 本地，启动后台守护进程进行流量采集和上报"
    );
    println!(
        "  bwg_usage v2ray-traffic                运行于 VPS 端，纯 Rust 域名流量统计分析守护进程"
    );
    println!("  bwg_usage status                       查看本机当前的流量使用情况和节点状态");
    println!("  bwg_usage node list                    列出本机保存的所有节点配置");
    println!("  bwg_usage node switch <tag>            一键应用并热重载切换到指定节点");
    println!("  bwg_usage node delete <tag>            删除本地的指定节点");
    println!("  bwg_usage node add [options]           手动在本地节点库添加节点");
    println!("  bwg_usage singbox start|stop|restart   通过本地 helper 管理 sing-box 服务");
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
        "v2ray-traffic" => run_v2ray_traffic_analyzer().await,
        "status" => run_cli_status().await,
        "singbox" | "sing-box" => {
            if args.len() < 3 {
                eprintln!("❌ 错误: 请指定 sing-box 动作: start、stop 或 restart");
                return;
            }
            run_cli_singbox_action(&args[2]).await;
        }
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

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_report() -> TrafficReportRequest {
        TrafficReportRequest {
            report_id: "report-1".to_string(),
            device_name: "MacBookPro".to_string(),
            download_delta: 1024,
            upload_delta: 512,
            current_node_ip: "1.2.3.4".to_string(),
            domain_deltas: HashMap::from([("api.openai.com".to_string(), 1536)]),
            abnormal_domain_deltas: HashMap::new(),
            report_kind: "delta".to_string(),
        }
    }

    #[test]
    fn test_validate_report_payload_rejects_bad_values() {
        let mut report = sample_report();
        assert!(validate_report_payload(&report).is_ok());

        report.download_delta = -1;
        assert!(validate_report_payload(&report).is_err());

        let mut report = sample_report();
        report.device_name = "bad\nname".to_string();
        assert!(validate_report_payload(&report).is_err());

        let mut report = sample_report();
        report.domain_deltas.insert("bad<script>".to_string(), 1);
        assert!(validate_report_payload(&report).is_ok());

        report.domain_deltas.insert("bad\nhost".to_string(), 1);
        assert!(validate_report_payload(&report).is_err());

        let mut report = sample_report();
        report.report_id = "bad\nid".to_string();
        assert!(validate_report_payload(&report).is_err());
    }

    #[test]
    fn test_normalize_node_key_strips_port() {
        assert_eq!(normalize_node_key("1.2.3.4:443"), "1.2.3.4");
        assert_eq!(normalize_node_key("1.2.3.4"), "1.2.3.4");
        assert_eq!(normalize_node_key("[2001:db8::1]:443"), "2001:db8::1");
    }

    #[test]
    fn test_merge_classified_delta_accumulates_reason() {
        let classification = classify_proxy_domain("static.bilibili.com");
        let mut map = HashMap::new();
        merge_classified_delta(&mut map, "static.bilibili.com", 10, &classification);
        merge_classified_delta(&mut map, "static.bilibili.com", 15, &classification);

        let merged = map.get("static.bilibili.com").unwrap();
        assert_eq!(merged.bytes, 25);
        assert!(!merged.should_proxy);
        assert_eq!(merged.category, "should-direct");
    }

    #[test]
    fn test_parse_ss_total_bytes_ignores_bytes_acked() {
        let stats = " cubic bytes_sent:1000 bytes_acked:50000 bytes_received:250";
        assert_eq!(parse_ss_total_bytes(stats), 1250);

        let ack_only = " cubic bytes_sent:1000 bytes_acked:50000";
        assert_eq!(parse_ss_total_bytes(ack_only), 1000);
    }

    #[test]
    fn test_validate_ssh_status_treats_non_zero_as_error() {
        assert!(validate_ssh_status(true, "", "root", "1.2.3.4").is_ok());
        let err = validate_ssh_status(false, "Permission denied", "root", "1.2.3.4")
            .expect_err("non-zero ssh status should be an error");
        assert!(err.contains("Permission denied"));
    }

    #[test]
    fn test_apply_report_to_history_deduplicates_report_id() {
        let mut history = NasTrafficHistory::default();
        let report = sample_report();
        let now = Local::now();

        let duplicate = apply_report_to_history(&mut history, &report, now);
        assert!(!duplicate);
        let duplicate =
            apply_report_to_history(&mut history, &report, now + chrono::Duration::seconds(30));
        assert!(duplicate);

        let dev = history.devices.get("MacBookPro").unwrap();
        assert_eq!(dev.total_download, 1024);
        assert_eq!(dev.total_upload, 512);
        assert_eq!(dev.processed_report_ids, vec!["report-1".to_string()]);

        let node = history.nodes.get("1.2.3.4").unwrap();
        assert_eq!(node.total_download + node.total_upload, 1536);
        assert_eq!(
            *history.daily_api_traffic.get("api.openai.com").unwrap(),
            1536
        );
    }

    #[test]
    fn test_apply_report_to_history_reclassifies_client_abnormal_data() {
        let mut history = NasTrafficHistory::default();
        let mut report = sample_report();
        report.report_id = "report-cn".to_string();
        report.domain_deltas = HashMap::from([("static.bilibili.com".to_string(), 2048)]);
        report.abnormal_domain_deltas.clear();

        let duplicate = apply_report_to_history(&mut history, &report, Local::now());
        assert!(!duplicate);

        let dev = history.devices.get("MacBookPro").unwrap();
        assert_eq!(dev.total_abnormal_proxy, 2048);
        assert!(
            history
                .daily_abnormal_traffic
                .contains_key("static.bilibili.com")
        );
    }
}

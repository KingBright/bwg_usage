use axum::{
    Json,
    extract::Query,
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
};
use chrono::Local;
use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use tokio::time::sleep;

use crate::{BwgServerLiveStatus, auth_failure_response, report_auth_required, report_token};

const ZEPHYR_NODES_FILE: &str = "zephyr_nodes.json";
const ZEPHYR_POLICY_FILE: &str = "zephyr_policy.json";
const PROBE_INTERVAL_SECS: u64 = 60;
const PROBE_TIMEOUT_SECS: u64 = 5;
const MIN_QUOTA_REMAINING_PERCENT: f64 = 5.0;

fn default_hysteria2_port() -> u16 {
    4443
}

fn default_tls_port() -> u16 {
    443
}

fn default_base_weight() -> u32 {
    100
}

/// 无密码节点静态元数据（严格遵守“零密钥上云”，绝不包含任何密码或私钥）
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ZephyrNodeMeta {
    pub id: String,
    pub name: String,
    pub domain: String,
    pub ip: String,
    #[serde(default = "default_hysteria2_port")]
    pub hysteria2_port: u16,
    #[serde(default = "default_tls_port")]
    pub trojan_grpc_port: u16,
    pub trojan_grpc_service_name: String,
    #[serde(default = "default_tls_port")]
    pub trojan_ws_port: u16,
    pub trojan_ws_path: String,
    #[serde(default = "default_base_weight")]
    pub base_weight: u32,
}

#[derive(Clone, Debug, Default)]
pub struct NodeProbeResult {
    pub online: bool,
    pub latency_ms: Option<u64>,
    pub last_checked_at: i64,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ProfileNode {
    pub id: String,
    pub name: String,
    pub domain: String,
    pub ip: String,
    pub hysteria2_port: u16,
    pub trojan_grpc_port: u16,
    pub trojan_grpc_service_name: String,
    pub trojan_ws_port: u16,
    pub trojan_ws_path: String,
    pub online: bool,
    pub enabled: bool,
    pub quota_ok: bool,
    pub quota_remaining_percent: Option<f64>,
    pub official_used_bytes: Option<i64>,
    pub official_limit_bytes: Option<i64>,
    pub next_reset_time: Option<i64>,
    pub latency_ms: Option<u64>,
    pub weight: u32,
    pub last_checked_at: i64,
}

fn default_policy_version() -> u32 {
    1
}

fn default_auto_switch_interval() -> String {
    "3m".to_string()
}

fn default_auto_switch_tolerance_ms() -> u32 {
    120
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct GlobalPolicy {
    #[serde(default = "default_policy_version")]
    pub policy_version: u32,
    #[serde(default)]
    pub direct_domain_suffixes: Vec<String>,
    #[serde(default)]
    pub proxy_domain_suffixes: Vec<String>,
    #[serde(default)]
    pub reject_domain_suffixes: Vec<String>,
    #[serde(default)]
    pub default_bypass_apps: Vec<String>,
    #[serde(default)]
    pub bypass_app_keywords: Vec<String>,
    #[serde(default = "default_auto_switch_interval")]
    pub auto_switch_interval: String,
    #[serde(default = "default_auto_switch_tolerance_ms")]
    pub auto_switch_tolerance_ms: u32,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ProfileResponse {
    pub version: u32,
    pub generated_at: i64,
    pub source: String,
    pub nodes: Vec<ProfileNode>,
    pub policy: GlobalPolicy,
    pub policy_hash: String,
}

#[derive(Deserialize, Default)]
pub struct ProfileQuery {
    pub token: Option<String>,
}

static NODE_PROBE_STATE: Lazy<Arc<RwLock<HashMap<String, NodeProbeResult>>>> =
    Lazy::new(|| Arc::new(RwLock::new(HashMap::new())));

pub fn default_zephyr_nodes() -> Vec<ZephyrNodeMeta> {
    vec![
        ZephyrNodeMeta {
            id: "vps1".to_string(),
            name: "Node VPS1".to_string(),
            domain: "vps1.example.com".to_string(),
            ip: "203.0.113.1".to_string(),
            hysteria2_port: 4443,
            trojan_grpc_port: 443,
            trojan_grpc_service_name: "replace-with-grpc-service-name".to_string(),
            trojan_ws_port: 443,
            trojan_ws_path: "/replace-with-ws-path".to_string(),
            base_weight: 100,
        },
        ZephyrNodeMeta {
            id: "vps2".to_string(),
            name: "Node VPS2".to_string(),
            domain: "vps2.example.com".to_string(),
            ip: "203.0.113.2".to_string(),
            hysteria2_port: 4443,
            trojan_grpc_port: 443,
            trojan_grpc_service_name: "replace-with-grpc-service-name".to_string(),
            trojan_ws_port: 443,
            trojan_ws_path: "/replace-with-ws-path".to_string(),
            base_weight: 90,
        },
        ZephyrNodeMeta {
            id: "vps3".to_string(),
            name: "Node VPS3".to_string(),
            domain: "vps3.example.com".to_string(),
            ip: "203.0.113.3".to_string(),
            hysteria2_port: 4443,
            trojan_grpc_port: 443,
            trojan_grpc_service_name: "replace-with-grpc-service-name".to_string(),
            trojan_ws_port: 443,
            trojan_ws_path: "/replace-with-ws-path".to_string(),
            base_weight: 80,
        },
    ]
}

pub fn load_zephyr_nodes() -> Vec<ZephyrNodeMeta> {
    let path = std::env::var("ZEPHYR_NODES_FILE").unwrap_or_else(|_| ZEPHYR_NODES_FILE.to_string());
    if let Ok(content) = fs::read_to_string(&path)
        && let Ok(nodes) = serde_json::from_str::<Vec<ZephyrNodeMeta>>(&content)
        && !nodes.is_empty()
    {
        return nodes;
    }
    default_zephyr_nodes()
}

async fn probe_single_node(client: &reqwest::Client, node: &ZephyrNodeMeta) -> NodeProbeResult {
    let url = format!("https://{}:{}/", node.domain, node.trojan_grpc_port);
    let started = Instant::now();
    let now = Local::now().timestamp();

    match client.head(&url).send().await {
        Ok(_resp) => NodeProbeResult {
            online: true,
            latency_ms: Some(started.elapsed().as_millis() as u64),
            last_checked_at: now,
        },
        Err(err) => {
            eprintln!(
                ">>> [Profile Prober] 节点 {} ({}) TLS/TCP 探活失败: {}",
                node.id, node.domain, err
            );
            NodeProbeResult {
                online: false,
                latency_ms: None,
                last_checked_at: now,
            }
        }
    }
}

async fn run_probe_round(client: &reqwest::Client) {
    let nodes = load_zephyr_nodes();
    let mut handles = Vec::with_capacity(nodes.len());

    for node in nodes {
        let c = client.clone();
        handles.push(tokio::spawn(async move {
            let id = node.id.clone();
            let res = probe_single_node(&c, &node).await;
            (id, res)
        }));
    }

    let mut next_state = HashMap::new();
    for handle in handles {
        if let Ok((id, res)) = handle.await {
            next_state.insert(id, res);
        }
    }

    let mut guard = NODE_PROBE_STATE.write().await;
    *guard = next_state;
}

/// 启动后台 60 秒主动探活协程
pub fn start_node_health_prober() {
    tokio::spawn(async {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(PROBE_TIMEOUT_SECS))
            .build()
            .unwrap_or_else(|_| reqwest::Client::new());

        loop {
            run_probe_round(&client).await;
            sleep(Duration::from_secs(PROBE_INTERVAL_SECS)).await;
        }
    });
}

pub fn validate_profile_auth(
    headers: &HeaderMap,
    query_token: Option<&str>,
    expected: Option<String>,
    required: bool,
) -> Result<(), StatusCode> {
    let expected = match expected {
        Some(token) => token,
        None if required => return Err(StatusCode::SERVICE_UNAVAILABLE),
        None => return Ok(()),
    };

    if let Some(header) = headers.get("authorization").and_then(|v| v.to_str().ok()) {
        let token = header.strip_prefix("Bearer ").unwrap_or(header).trim();
        if token == expected {
            return Ok(());
        }
    }

    if let Some(qtok) = query_token
        && qtok.trim() == expected
    {
        return Ok(());
    }

    Err(StatusCode::UNAUTHORIZED)
}

pub fn build_profile_node(
    meta: &ZephyrNodeMeta,
    probe: Option<&NodeProbeResult>,
    bwg: Option<&BwgServerLiveStatus>,
) -> ProfileNode {
    // 刚启动尚未完成首次探活时默认视为 online，避免冷启动瞬间全部禁用
    let (online, latency_ms, last_checked_at) = match probe {
        Some(p) => (p.online, p.latency_ms, p.last_checked_at),
        None => (true, None, 0),
    };

    let (quota_remaining_percent, official_used_bytes, official_limit_bytes, next_reset_time, quota_ok) =
        match bwg {
            Some(status) if status.official_limit_bytes > 0 => {
                let remaining = (status.official_limit_bytes - status.official_used_bytes).max(0);
                let pct = ((remaining as f64 / status.official_limit_bytes as f64) * 10000.0)
                    .round()
                    / 100.0;
                (
                    Some(pct),
                    Some(status.official_used_bytes),
                    Some(status.official_limit_bytes),
                    Some(status.next_reset_time),
                    pct >= MIN_QUOTA_REMAINING_PERCENT,
                )
            }
            _ => (None, None, None, None, true),
        };

    let enabled = online && quota_ok;

    let weight = if !enabled {
        0
    } else {
        let mut w = meta.base_weight;
        if let Some(pct) = quota_remaining_percent
            && pct < 20.0
        {
            w = (w / 2).max(10);
        }
        if let Some(ms) = latency_ms {
            if ms > 1000 {
                w = w.saturating_sub(40).max(10);
            } else if ms > 500 {
                w = w.saturating_sub(20).max(10);
            }
        }
        w
    };

    ProfileNode {
        id: meta.id.clone(),
        name: meta.name.clone(),
        domain: meta.domain.clone(),
        ip: meta.ip.clone(),
        hysteria2_port: meta.hysteria2_port,
        trojan_grpc_port: meta.trojan_grpc_port,
        trojan_grpc_service_name: meta.trojan_grpc_service_name.clone(),
        trojan_ws_port: meta.trojan_ws_port,
        trojan_ws_path: meta.trojan_ws_path.clone(),
        online,
        enabled,
        quota_ok,
        quota_remaining_percent,
        official_used_bytes,
        official_limit_bytes,
        next_reset_time,
        latency_ms,
        weight,
        last_checked_at,
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct BootstrapResponse {
    pub version: u32,
    pub nas_url: String,
    pub report_token: String,
    pub node_secret: String,
    pub fallbacks: Vec<String>,
    pub profile: ProfileResponse,
}

fn env_non_empty(keys: &[&str]) -> Option<String> {
    for key in keys {
        if let Ok(val) = std::env::var(key) {
            let trimmed = val.trim().to_string();
            if !trimmed.is_empty() {
                return Some(trimmed);
            }
        }
    }
    None
}

/// 常量时间字节比对，防时序侧信道攻击
pub fn constant_time_eq(a: &str, b: &str) -> bool {
    let ab = a.as_bytes();
    let bb = b.as_bytes();
    let max_len = ab.len().max(bb.len());
    let mut diff: u8 = if ab.len() == bb.len() { 0 } else { 1 };
    for i in 0..max_len {
        let ca = ab.get(i).copied().unwrap_or(0);
        let cb = bb.get(i).copied().unwrap_or(0);
        diff |= ca ^ cb;
    }
    diff == 0
}

pub fn validate_access_password(
    headers: &HeaderMap,
    expected: Option<&str>,
) -> Result<(), StatusCode> {
    let expected = match expected {
        Some(p) if !p.is_empty() => p,
        _ => return Err(StatusCode::SERVICE_UNAVAILABLE),
    };

    if let Some(pwd) = headers
        .get("x-zephyr-password")
        .and_then(|v| v.to_str().ok())
    {
        if constant_time_eq(pwd.trim(), expected) {
            return Ok(());
        }
        return Err(StatusCode::UNAUTHORIZED);
    }

    if let Some(auth) = headers.get("authorization").and_then(|v| v.to_str().ok()) {
        let token = auth.strip_prefix("Bearer ").unwrap_or(auth).trim();
        if constant_time_eq(token, expected) {
            return Ok(());
        }
    }

    Err(StatusCode::UNAUTHORIZED)
}

pub fn default_global_policy() -> GlobalPolicy {
    GlobalPolicy {
        policy_version: 1,
        direct_domain_suffixes: vec!["cn".into()],
        proxy_domain_suffixes: Vec::new(),
        reject_domain_suffixes: Vec::new(),
        default_bypass_apps: Vec::new(),
        bypass_app_keywords: Vec::new(),
        auto_switch_interval: "3m".into(),
        auto_switch_tolerance_ms: 120,
    }
}

pub fn load_zephyr_policy() -> GlobalPolicy {
    let path =
        std::env::var("ZEPHYR_POLICY_FILE").unwrap_or_else(|_| ZEPHYR_POLICY_FILE.to_string());
    if let Ok(content) = fs::read_to_string(&path)
        && let Ok(policy) = serde_json::from_str::<GlobalPolicy>(&content)
    {
        return policy;
    }
    default_global_policy()
}

pub fn compute_policy_hash(policy: &GlobalPolicy) -> String {
    let canonical = serde_json::to_vec(policy).unwrap_or_default();
    let digest = ring::digest::digest(&ring::digest::SHA256, &canonical);
    let mut hex = String::with_capacity(16);
    for byte in &digest.as_ref()[..8] {
        use std::fmt::Write as _;
        let _ = write!(&mut hex, "{:02x}", byte);
    }
    hex
}

async fn build_live_profile_response() -> (Vec<ZephyrNodeMeta>, ProfileResponse) {
    let metas = load_zephyr_nodes();
    let probes = NODE_PROBE_STATE.read().await;
    let bwg_statuses = crate::BWG_SERVERS_STATUS.read().await;

    let nodes: Vec<ProfileNode> = metas
        .iter()
        .map(|meta| {
            let probe = probes.get(&meta.id);
            let bwg = bwg_statuses
                .iter()
                .find(|s| s.ip == meta.ip || s.name.eq_ignore_ascii_case(&meta.id));
            build_profile_node(meta, probe, bwg)
        })
        .collect();

    let policy = load_zephyr_policy();
    let policy_hash = compute_policy_hash(&policy);

    let resp = ProfileResponse {
        version: 1,
        generated_at: Local::now().timestamp(),
        source: "nas".to_string(),
        nodes,
        policy,
        policy_hash,
    };
    (metas, resp)
}

pub async fn profile_handler(
    headers: HeaderMap,
    Query(query): Query<ProfileQuery>,
) -> axum::response::Response {
    if let Err(status) = validate_profile_auth(
        &headers,
        query.token.as_deref(),
        report_token(),
        report_auth_required(),
    ) {
        return auth_failure_response(status);
    }

    let (_, resp) = build_live_profile_response().await;

    (
        StatusCode::OK,
        [
            ("Access-Control-Allow-Origin", "*"),
            ("Content-Type", "application/json; charset=utf-8"),
            ("Cache-Control", "no-store"),
        ],
        Json(resp),
    )
        .into_response()
}

/// GET /z — 短链 + 密码一键配置 Bootstrap 端点
pub async fn bootstrap_handler(headers: HeaderMap) -> axum::response::Response {
    let expected_pwd = env_non_empty(&["ZEPHYR_ACCESS_PASSWORD"]);
    if let Err(status) = validate_access_password(&headers, expected_pwd.as_deref()) {
        return (
            status,
            [
                ("Access-Control-Allow-Origin", "*"),
                ("Content-Type", "application/json; charset=utf-8"),
                ("Cache-Control", "no-store"),
            ],
            Json(serde_json::json!({
                "success": false,
                "message": if status == StatusCode::UNAUTHORIZED {
                    "invalid access password"
                } else {
                    "bootstrap service not configured"
                }
            })),
        )
            .into_response();
    }

    let Some(rep_token) = report_token() else {
        return auth_failure_response(StatusCode::SERVICE_UNAVAILABLE);
    };
    let Some(node_secret) = env_non_empty(&["ZEPHYR_NODE_SECRET"]) else {
        return auth_failure_response(StatusCode::SERVICE_UNAVAILABLE);
    };
    let nas_url = env_non_empty(&["ZEPHYR_NAS_URL", "NAS_SERVER_URL"])
        .unwrap_or_else(|| "https://your-nas.example.com:8443".to_string())
        .trim_end_matches('/')
        .to_string();
    let sub_token = env_non_empty(&["ZEPHYR_SUB_TOKEN", "SUB_TOKEN"]).unwrap_or_default();

    let (metas, profile) = build_live_profile_response().await;
    let fallbacks: Vec<String> = if sub_token.is_empty() {
        Vec::new()
    } else {
        metas
            .iter()
            .map(|m| {
                format!(
                    "https://{}:{}/{}/zephyr_profile.json",
                    m.domain, m.hysteria2_port, sub_token
                )
            })
            .collect()
    };

    let resp = BootstrapResponse {
        version: 1,
        nas_url,
        report_token: rep_token,
        node_secret,
        fallbacks,
        profile,
    };

    (
        StatusCode::OK,
        [
            ("Access-Control-Allow-Origin", "*"),
            ("Content-Type", "application/json; charset=utf-8"),
            ("Cache-Control", "no-store"),
        ],
        Json(resp),
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    #[test]
    fn test_quota_below_5_percent_disables_node() {
        let meta = &default_zephyr_nodes()[0];
        let probe = NodeProbeResult {
            online: true,
            latency_ms: Some(120),
            last_checked_at: 1700000000,
        };
        let bwg = BwgServerLiveStatus {
            name: "vps1".to_string(),
            ip: meta.ip.clone(),
            official_used_bytes: 960_000_000_000,
            official_limit_bytes: 1_000_000_000_000,
            next_reset_time: 1700100000,
        };

        let node = build_profile_node(meta, Some(&probe), Some(&bwg));
        assert!(node.online);
        assert!(!node.quota_ok);
        assert!(!node.enabled);
        assert_eq!(node.weight, 0);
        assert_eq!(node.quota_remaining_percent, Some(4.0));
    }

    #[test]
    fn test_offline_node_disabled() {
        let meta = &default_zephyr_nodes()[1];
        let probe = NodeProbeResult {
            online: false,
            latency_ms: None,
            last_checked_at: 1700000000,
        };
        let node = build_profile_node(meta, Some(&probe), None);
        assert!(!node.online);
        assert!(node.quota_ok);
        assert!(!node.enabled);
        assert_eq!(node.weight, 0);
    }

    #[test]
    fn test_profile_auth_bearer_and_query_token() {
        let mut headers = HeaderMap::new();
        headers.insert("authorization", HeaderValue::from_static("Bearer secret123"));
        assert!(validate_profile_auth(&headers, None, Some("secret123".into()), true).is_ok());

        let empty = HeaderMap::new();
        assert!(
            validate_profile_auth(&empty, Some("secret123"), Some("secret123".into()), true)
                .is_ok()
        );
        assert_eq!(
            validate_profile_auth(&empty, Some("wrong"), Some("secret123".into()), true),
            Err(StatusCode::UNAUTHORIZED)
        );
    }

    #[test]
    fn test_profile_json_contains_no_secret_fields() {
        let meta = &default_zephyr_nodes()[0];
        let node = build_profile_node(meta, None, None);
        let serialized = serde_json::to_string(&node).unwrap();
        assert!(!serialized.contains("password"));
        assert!(!serialized.contains("secret"));
    }

    #[test]
    fn test_constant_time_eq_and_bootstrap_auth() {
        assert!(constant_time_eq("test-secret-pass!", "test-secret-pass!"));
        assert!(!constant_time_eq("test-secret-pass!", "test-secret-pass?"));
        assert!(!constant_time_eq("short", "longer-password"));

        let empty = HeaderMap::new();
        assert_eq!(
            validate_access_password(&empty, Some("pw123")),
            Err(StatusCode::UNAUTHORIZED)
        );
        assert_eq!(
            validate_access_password(&empty, None),
            Err(StatusCode::SERVICE_UNAVAILABLE)
        );

        let mut h_custom = HeaderMap::new();
        h_custom.insert("x-zephyr-password", HeaderValue::from_static("pw123"));
        assert!(validate_access_password(&h_custom, Some("pw123")).is_ok());
        assert_eq!(
            validate_access_password(&h_custom, Some("wrong")),
            Err(StatusCode::UNAUTHORIZED)
        );

        let mut h_bearer = HeaderMap::new();
        h_bearer.insert("authorization", HeaderValue::from_static("Bearer pw123"));
        assert!(validate_access_password(&h_bearer, Some("pw123")).is_ok());
    }

    #[test]
    fn test_global_policy_and_hash() {
        let mut p = default_global_policy();
        assert_eq!(p.policy_version, 1);
        assert!(p.direct_domain_suffixes.contains(&"cn".to_string()));
        assert_eq!(p.auto_switch_interval, "3m");
        assert_eq!(p.auto_switch_tolerance_ms, 120);
        let h1 = compute_policy_hash(&p);
        let h2 = compute_policy_hash(&p);
        assert_eq!(h1.len(), 16);
        assert_eq!(h1, h2);
        p.default_bypass_apps.push("com.example.stream".to_string());
        let h3 = compute_policy_hash(&p);
        assert_ne!(h1, h3);
    }
}

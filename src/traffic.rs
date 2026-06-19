use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::RwLock;
use tokio::time::{Instant, sleep};

// ==========================================
// 1. 服务端数据定义与持久化逻辑
// ==========================================

#[derive(Serialize, Deserialize, Clone, Default, Debug)]
pub struct DeviceHistory {
    pub total_download: i64,
    pub total_upload: i64,
    pub last_seen: i64, // 秒级 Unix 时间戳
    pub current_node: String,
    #[serde(default)]
    pub processed_report_ids: Vec<String>,
    #[serde(default)]
    pub total_abnormal_proxy: i64,
    #[serde(default)]
    pub domain_traffic: HashMap<String, i64>,
    #[serde(default)]
    pub abnormal_domain_traffic: HashMap<String, ClassifiedDomainDelta>,
}

#[derive(Serialize, Deserialize, Clone, Default, Debug)]
pub struct NodeHistory {
    pub server: String,
    pub server_port: u16,
    pub total_download: i64,
    pub total_upload: i64,
    #[serde(default)]
    pub domain_traffic: HashMap<String, i64>,
    #[serde(default)]
    pub abnormal_domain_traffic: HashMap<String, ClassifiedDomainDelta>,
}

#[derive(Serialize, Deserialize, Clone, Default, Debug)]
pub struct NasTrafficHistory {
    pub devices: HashMap<String, DeviceHistory>,
    pub nodes: HashMap<String, NodeHistory>,
    // 每日代理 API / 域名流量累计
    #[serde(default)]
    pub daily_api_traffic: HashMap<String, i64>,
    #[serde(default)]
    pub daily_api_date: String,
    // 每周代理 API / 域名流量累计
    #[serde(default)]
    pub weekly_api_traffic: HashMap<String, i64>,
    #[serde(default)]
    pub weekly_api_week: i32,
    #[serde(default)]
    pub daily_abnormal_traffic: HashMap<String, ClassifiedDomainDelta>,
    #[serde(default)]
    pub weekly_abnormal_traffic: HashMap<String, ClassifiedDomainDelta>,
}

pub type ServerHistoryState = Arc<RwLock<NasTrafficHistory>>;

// 从持久化文件读取服务端流量与节点数据
pub fn load_nas_history(file_path: &str) -> NasTrafficHistory {
    if let Ok(content) = fs::read_to_string(file_path) {
        serde_json::from_str(&content).unwrap_or_default()
    } else {
        NasTrafficHistory {
            devices: HashMap::new(),
            nodes: HashMap::new(),
            daily_api_traffic: HashMap::new(),
            daily_api_date: String::new(),
            weekly_api_traffic: HashMap::new(),
            weekly_api_week: 0,
            daily_abnormal_traffic: HashMap::new(),
            weekly_abnormal_traffic: HashMap::new(),
        }
    }
}

// 保存数据到持久化文件
pub fn save_nas_history(file_path: &str, history: &NasTrafficHistory) {
    if let Ok(data) = serde_json::to_string_pretty(history) {
        let _ = fs::write(file_path, data);
    }
}

// ==========================================
// 2. 客户端流量上报协议与计算逻辑
// ==========================================

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct TrafficReportRequest {
    #[serde(default)]
    pub report_id: String,
    pub device_name: String,
    pub download_delta: i64,
    pub upload_delta: i64,
    pub current_node_ip: String,
    pub domain_deltas: HashMap<String, i64>,
    #[serde(default)]
    pub abnormal_domain_deltas: HashMap<String, ClassifiedDomainDelta>,
    #[serde(default)]
    pub report_kind: String,
}

#[derive(Serialize, Deserialize, Debug, Clone, Default, PartialEq, Eq)]
pub struct TrafficClassification {
    pub should_proxy: bool,
    pub category: String,
    pub reason: String,
}

#[derive(Serialize, Deserialize, Debug, Clone, Default, PartialEq, Eq)]
pub struct ClassifiedDomainDelta {
    pub bytes: i64,
    pub should_proxy: bool,
    pub category: String,
    pub reason: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ProxyDeltaBatch {
    pub download_delta: i64,
    pub upload_delta: i64,
    pub domain_deltas: HashMap<String, i64>,
    pub abnormal_domain_deltas: HashMap<String, ClassifiedDomainDelta>,
}

#[derive(Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct ClashConnectionMetadata {
    pub host: String,
    pub destination_ip: Option<String>,
}

#[derive(Deserialize, Debug, Clone)]
pub struct ClashConnection {
    pub id: String,
    pub metadata: ClashConnectionMetadata,
    pub upload: i64,
    pub download: i64,
    #[serde(default)]
    pub chains: Vec<String>,
}

// sing-box Clash Connections API 数据结构
#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct ClashAPIConnections {
    pub download_total: i64,
    pub upload_total: i64,
    pub connections: Option<Vec<ClashConnection>>,
}

// 客户端状态：用于记录活跃连接明细
#[derive(Default)]
pub struct ClientTrafficTracker {
    pub active_conns: HashMap<String, (String, i64, i64)>, // id -> (host, last_download, last_upload)
}

const DEFAULT_DIRECT_SUFFIXES: &[&str] = &[
    "cn",
    "baidu.com",
    "bdstatic.com",
    "bilibili.com",
    "bilivideo.com",
    "qq.com",
    "tencent.com",
    "gtimg.com",
    "taobao.com",
    "tmall.com",
    "alicdn.com",
    "alipay.com",
    "aliyun.com",
    "bytedance.com",
    "douyin.com",
    "feishu.cn",
    "larksuite.com",
    "weibo.com",
    "zhihu.com",
    "mi.com",
    "xiaomi.com",
    "tuna.tsinghua.edu.cn",
    "ustc.edu.cn",
];

pub fn normalize_traffic_target(target: &str) -> String {
    let mut value = target
        .trim()
        .trim_start_matches("tcp:")
        .trim_start_matches("udp:")
        .trim_end_matches('.')
        .to_lowercase();

    if value.starts_with('[')
        && let Some(idx) = value.find(']')
    {
        return value[1..idx].to_string();
    }

    if let Some(stripped) = value.strip_prefix("www.") {
        value = stripped.to_string();
    }

    if let Some(idx) = value.rfind(':') {
        let tail = &value[idx + 1..];
        if !tail.is_empty() && tail.chars().all(|c| c.is_ascii_digit()) {
            value.truncate(idx);
        }
    }

    value
}

fn domain_matches_suffix(domain: &str, suffix: &str) -> bool {
    let suffix = suffix.trim().trim_start_matches('.').to_lowercase();
    domain == suffix || domain.ends_with(&format!(".{}", suffix))
}

fn push_normalized_suffix(suffixes: &mut Vec<String>, suffix: &str) {
    let suffix = suffix.trim().trim_start_matches('.').to_lowercase();
    if suffix.is_empty() || suffix.chars().any(|c| c.is_control()) {
        return;
    }
    if !suffixes.iter().any(|existing| existing == &suffix) {
        suffixes.push(suffix);
    }
}

fn parse_direct_suffixes(content: &str) -> Vec<String> {
    let mut suffixes = Vec::new();
    if let Ok(values) = serde_json::from_str::<Vec<String>>(content) {
        for value in values {
            push_normalized_suffix(&mut suffixes, &value);
        }
        return suffixes;
    }

    for raw in content.split([',', '\n', '\r', '\t']) {
        let candidate = raw.split('#').next().unwrap_or("").trim();
        push_normalized_suffix(&mut suffixes, candidate);
    }
    suffixes
}

fn configured_direct_suffixes() -> Vec<String> {
    let mut suffixes = Vec::new();
    for suffix in DEFAULT_DIRECT_SUFFIXES {
        push_normalized_suffix(&mut suffixes, suffix);
    }

    if let Ok(extra) = std::env::var("DIRECT_SUFFIXES") {
        for suffix in parse_direct_suffixes(&extra) {
            push_normalized_suffix(&mut suffixes, &suffix);
        }
    }

    if let Ok(path) = std::env::var("DIRECT_SUFFIXES_FILE")
        && let Ok(content) = fs::read_to_string(path)
    {
        for suffix in parse_direct_suffixes(&content) {
            push_normalized_suffix(&mut suffixes, &suffix);
        }
    }

    suffixes
}

fn classify_proxy_domain_with_suffixes<I, S>(
    target: &str,
    direct_suffixes: I,
) -> TrafficClassification
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let domain = normalize_traffic_target(target);
    if domain.is_empty() || domain == "未知ip" {
        return TrafficClassification {
            should_proxy: true,
            category: "unknown".to_string(),
            reason: "目标为空或仅能识别为未知 IP，保守归入代理流量".to_string(),
        };
    }

    if domain.parse::<std::net::IpAddr>().is_ok() {
        let private_or_local = domain.starts_with("10.")
            || domain.starts_with("127.")
            || domain.starts_with("192.168.")
            || domain.starts_with("172.16.")
            || domain.starts_with("172.17.")
            || domain.starts_with("172.18.")
            || domain.starts_with("172.19.")
            || domain.starts_with("172.20.")
            || domain.starts_with("172.21.")
            || domain.starts_with("172.22.")
            || domain.starts_with("172.23.")
            || domain.starts_with("172.24.")
            || domain.starts_with("172.25.")
            || domain.starts_with("172.26.")
            || domain.starts_with("172.27.")
            || domain.starts_with("172.28.")
            || domain.starts_with("172.29.")
            || domain.starts_with("172.30.")
            || domain.starts_with("172.31.")
            || domain == "::1"
            || domain.starts_with("fc")
            || domain.starts_with("fd");

        if private_or_local {
            return TrafficClassification {
                should_proxy: false,
                category: "private-network".to_string(),
                reason: "局域网或本机地址不应消耗代理服务器流量".to_string(),
            };
        }

        return TrafficClassification {
            should_proxy: true,
            category: "public-ip".to_string(),
            reason: "公网 IP 无法仅凭地址判断，应结合规则继续观察".to_string(),
        };
    }

    for suffix in direct_suffixes {
        let suffix = suffix.as_ref();
        if domain_matches_suffix(&domain, suffix) {
            return TrafficClassification {
                should_proxy: false,
                category: "should-direct".to_string(),
                reason: format!("命中国内/本地服务后缀规则: {}", suffix),
            };
        }
    }

    TrafficClassification {
        should_proxy: true,
        category: "expected-proxy".to_string(),
        reason: "未命中直连候选规则，暂按正常代理流量统计".to_string(),
    }
}

pub fn classify_proxy_domain(target: &str) -> TrafficClassification {
    classify_proxy_domain_with_suffixes(target, configured_direct_suffixes())
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

impl ClientTrafficTracker {
    /// 增量计算当前所有活跃代理连接产生的流量 Delta 以及各个代理域名的流量 Delta
    pub fn calculate_proxy_deltas(&mut self, connections: &[ClashConnection]) -> ProxyDeltaBatch {
        let control_domains = configured_control_domain_suffixes();
        self.calculate_proxy_deltas_with_control_domains(connections, &control_domains)
    }

    fn calculate_proxy_deltas_with_control_domains(
        &mut self,
        connections: &[ClashConnection],
        control_domains: &[String],
    ) -> ProxyDeltaBatch {
        let mut batch = ProxyDeltaBatch::default();
        let mut current_ids = std::collections::HashSet::new();

        for conn in connections {
            let outbound = conn.chains.first().map(|s| s.as_str()).unwrap_or("direct");

            // 仅统计出站为 "proxy" 的代理流量
            if outbound != "proxy" {
                continue;
            }

            let id = &conn.id;
            let host = &conn.metadata.host;
            let host_to_use = if host.is_empty() {
                conn.metadata
                    .destination_ip
                    .clone()
                    .unwrap_or_else(|| "未知IP".to_string())
            } else {
                host.clone()
            };

            if host_to_use.is_empty() {
                continue;
            }

            // 排除对大盘控制层域名（直连）的流量统计上报
            if is_control_domain(&host_to_use, control_domains) {
                continue;
            }

            current_ids.insert(id.clone());

            let cur_dl = conn.download;
            let cur_ul = conn.upload;

            if let Some((_, last_dl, last_ul)) = self.active_conns.get(id) {
                let dl_delta = (cur_dl - last_dl).max(0);
                let ul_delta = (cur_ul - last_ul).max(0);
                let total = dl_delta + ul_delta;

                if total > 0 {
                    batch.download_delta += dl_delta;
                    batch.upload_delta += ul_delta;
                    *batch.domain_deltas.entry(host_to_use.clone()).or_insert(0) += total;

                    let classification = classify_proxy_domain(&host_to_use);
                    if !classification.should_proxy {
                        merge_classified_delta(
                            &mut batch.abnormal_domain_deltas,
                            &host_to_use,
                            total,
                            &classification,
                        );
                    }
                }
            } else {
                // 新连接：只保存其绝对流量值作为基准记录，本轮不计算增量
            }

            self.active_conns
                .insert(id.clone(), (host_to_use, cur_dl, cur_ul));
        }

        // 清理在当前活跃列表里已经不存在的连接
        self.active_conns.retain(|id, _| current_ids.contains(id));

        batch
    }
}

fn configured_control_domain_suffixes() -> Vec<String> {
    let mut domains = Vec::new();
    if let Ok(raw) = std::env::var("CONTROL_DOMAIN_SUFFIXES") {
        domains.extend(parse_domain_list(&raw));
    }
    if let Ok(raw) = std::env::var("NAS_SERVER_URL")
        && let Some(host) = extract_host(&raw)
    {
        domains.push(host);
    }
    domains.sort();
    domains.dedup();
    domains
}

fn parse_domain_list(raw: &str) -> Vec<String> {
    raw.split(',')
        .map(normalize_domain)
        .filter(|value| !value.is_empty())
        .collect()
}

fn normalize_domain(raw: &str) -> String {
    raw.trim()
        .trim_start_matches("http://")
        .trim_start_matches("https://")
        .trim_matches('/')
        .trim_start_matches('.')
        .to_ascii_lowercase()
}

fn extract_host(raw: &str) -> Option<String> {
    let without_scheme = raw
        .trim()
        .trim_start_matches("http://")
        .trim_start_matches("https://");
    let authority = without_scheme.split('/').next().unwrap_or("");
    let authority = authority.rsplit('@').next().unwrap_or(authority);
    let host = if authority.starts_with('[') {
        authority
            .split(']')
            .next()
            .map(|value| value.trim_start_matches('['))
            .unwrap_or("")
    } else {
        authority.split(':').next().unwrap_or("")
    };
    let host = normalize_domain(host);
    if host.is_empty() { None } else { Some(host) }
}

fn is_control_domain(host: &str, control_domains: &[String]) -> bool {
    let host = normalize_domain(host);
    control_domains.iter().any(|domain| {
        let domain = normalize_domain(domain);
        !domain.is_empty() && (host == domain || host.ends_with(&format!(".{}", domain)))
    })
}

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
struct PendingTrafficReport {
    #[serde(default)]
    report_id: String,
    download_delta: i64,
    upload_delta: i64,
    domain_deltas: HashMap<String, i64>,
    abnormal_domain_deltas: HashMap<String, ClassifiedDomainDelta>,
}

impl PendingTrafficReport {
    fn total_bytes(&self) -> i64 {
        self.download_delta + self.upload_delta
    }

    fn is_empty(&self) -> bool {
        self.download_delta == 0
            && self.upload_delta == 0
            && self.domain_deltas.is_empty()
            && self.abnormal_domain_deltas.is_empty()
    }

    fn ensure_report_id(&mut self, device_name: &str) -> String {
        if self.report_id.trim().is_empty() {
            self.report_id = generate_report_id(device_name);
        }
        self.report_id.clone()
    }

    fn merge_batch(&mut self, batch: ProxyDeltaBatch, device_name: &str) {
        self.ensure_report_id(device_name);
        self.download_delta += batch.download_delta;
        self.upload_delta += batch.upload_delta;
        for (domain, bytes) in batch.domain_deltas {
            *self.domain_deltas.entry(domain).or_insert(0) += bytes;
        }
        for (domain, delta) in batch.abnormal_domain_deltas {
            let classification = TrafficClassification {
                should_proxy: delta.should_proxy,
                category: delta.category,
                reason: delta.reason,
            };
            merge_classified_delta(
                &mut self.abnormal_domain_deltas,
                &domain,
                delta.bytes,
                &classification,
            );
        }
    }
}

fn generate_report_id(device_name: &str) -> String {
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis();
    let device_part: String = device_name
        .chars()
        .filter_map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.' {
                Some(c)
            } else if c.is_whitespace() {
                Some('-')
            } else {
                None
            }
        })
        .take(32)
        .collect();
    let device_part = if device_part.is_empty() {
        "device".to_string()
    } else {
        device_part
    };
    format!("{}-{}-{}", device_part, millis, std::process::id())
}

fn pending_report_path() -> String {
    std::env::var("CLIENT_PENDING_REPORT_PATH")
        .unwrap_or_else(|_| "client_pending_report.json".to_string())
}

fn load_pending_report() -> PendingTrafficReport {
    let path = pending_report_path();
    if let Ok(content) = fs::read_to_string(path) {
        serde_json::from_str(&content).unwrap_or_default()
    } else {
        PendingTrafficReport::default()
    }
}

fn save_pending_report(pending: &PendingTrafficReport) {
    let path = pending_report_path();
    if pending.is_empty() {
        let _ = fs::remove_file(path);
        return;
    }
    if let Ok(data) = serde_json::to_string_pretty(pending) {
        let _ = fs::write(path, data);
    }
}

// ==========================================
// 3. 客户端定时上报协程
// ==========================================

async fn resolve_server_ip(server: &str, port: u16) -> String {
    if server.parse::<std::net::IpAddr>().is_ok() {
        return server.to_string();
    }
    let host_port = format!("{}:{}", server, port);
    if let Ok(mut addrs) = tokio::net::lookup_host(&host_port).await
        && let Some(addr) = addrs.next()
    {
        return addr.ip().to_string();
    }
    server.to_string()
}

pub fn start_client_report_loop(
    device_name: String,
    nas_server_url: String,
    singbox_api_url: String,
    current_node_lock: Arc<RwLock<String>>,
) {
    tokio::spawn(async move {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(3))
            .build()
            .unwrap();

        let mut tracker = ClientTrafficTracker::default();
        let report_url = format!("{}/api/report", nas_server_url.trim_end_matches('/'));
        let report_token = std::env::var("REPORT_TOKEN")
            .ok()
            .filter(|s| !s.trim().is_empty());

        println!(
            "[Client] 流量上报协程已启动。设备名: {}, 上报至 NAS: {}, 监听本地 sing-box: {}",
            device_name, report_url, singbox_api_url
        );

        let report_interval = std::env::var("REPORT_INTERVAL")
            .ok()
            .and_then(|s| s.parse::<u64>().ok())
            .unwrap_or(600); // 默认 600 秒 (10分钟) 上报一次
        let heartbeat_interval = std::env::var("HEARTBEAT_INTERVAL")
            .ok()
            .and_then(|s| s.parse::<u64>().ok())
            .unwrap_or(30);

        let collect_interval = Duration::from_secs(2); // 固定 2 秒采集一次
        let mut next_report_due = Instant::now() + Duration::from_secs(report_interval);
        let mut next_heartbeat_due = Instant::now() + Duration::from_secs(heartbeat_interval);
        let mut retry_delay = Duration::from_secs(30);

        // 内存中缓存的待上报增量流量
        let mut pending = load_pending_report();
        if !pending.is_empty() {
            println!(
                "[Client] 已恢复未上报缓存: {}B, 域名数: {}",
                pending.total_bytes(),
                pending.domain_deltas.len()
            );
        }

        loop {
            sleep(collect_interval).await;

            let connections_url = format!("{}/connections", singbox_api_url.trim_end_matches('/'));
            let resp = match client.get(&connections_url).send().await {
                Ok(r) => r,
                Err(e) => {
                    eprintln!("[Client] 轮询本地 sing-box 失败: {}", e);
                    continue;
                }
            };

            let data = match resp.json::<ClashAPIConnections>().await {
                Ok(d) => d,
                Err(e) => {
                    eprintln!("[Client] 解析 sing-box connections 响应失败: {}", e);
                    continue;
                }
            };

            // 用这轮的 connections 更新 tracker，并返回这一轮 proxy 连接产生的 delta 流量
            if let Some(conns) = &data.connections {
                let batch = tracker.calculate_proxy_deltas(conns);
                if batch.download_delta > 0 || batch.upload_delta > 0 {
                    pending.merge_batch(batch, &device_name);
                    save_pending_report(&pending);
                }
            }

            let now = Instant::now();
            let should_report_delta = now >= next_report_due && !pending.is_empty();
            let should_heartbeat = now >= next_heartbeat_due;

            if should_report_delta || should_heartbeat {
                // 获取当前激活的节点
                let active_node = {
                    let guard = current_node_lock.read().await;
                    guard.clone()
                };

                // 查询本地 client_nodes.json 并尝试解析成 IP
                let local_nodes = crate::node::load_local_nodes();
                let node_ip =
                    if active_node == "未知" || active_node == "未配置" || active_node.is_empty()
                    {
                        active_node
                    } else if let Some(n) = local_nodes.iter().find(|n| n.name == active_node) {
                        resolve_server_ip(&n.server, n.server_port).await
                    } else {
                        active_node
                    };

                let (
                    report_id,
                    download_delta,
                    upload_delta,
                    domain_deltas,
                    abnormal_domain_deltas,
                    report_kind,
                ) = if should_report_delta {
                    let report_id = pending.ensure_report_id(&device_name);
                    save_pending_report(&pending);
                    (
                        report_id,
                        pending.download_delta,
                        pending.upload_delta,
                        pending.domain_deltas.clone(),
                        pending.abnormal_domain_deltas.clone(),
                        "delta".to_string(),
                    )
                } else {
                    (
                        String::new(),
                        0,
                        0,
                        HashMap::new(),
                        HashMap::new(),
                        "heartbeat".to_string(),
                    )
                };

                let req_body = TrafficReportRequest {
                    report_id,
                    device_name: device_name.clone(),
                    download_delta,
                    upload_delta,
                    current_node_ip: node_ip,
                    domain_deltas,
                    abnormal_domain_deltas,
                    report_kind,
                };

                println!(
                    "[Client] 发送{}。代理流量: 下载 {}B, 上传 {}B, 域名数: {}, 异常域名数: {}",
                    if should_report_delta {
                        "流量上报"
                    } else {
                        "心跳"
                    },
                    req_body.download_delta,
                    req_body.upload_delta,
                    req_body.domain_deltas.len(),
                    req_body.abnormal_domain_deltas.len(),
                );

                let mut request_builder = client.post(&report_url).json(&req_body);
                if let Some(token) = &report_token {
                    request_builder = request_builder.bearer_auth(token);
                }

                match request_builder.send().await {
                    Ok(resp) => {
                        if resp.status().is_success() {
                            if should_report_delta {
                                pending = PendingTrafficReport::default();
                                save_pending_report(&pending);
                                next_report_due =
                                    Instant::now() + Duration::from_secs(report_interval);
                                retry_delay = Duration::from_secs(30);
                            }
                            next_heartbeat_due =
                                Instant::now() + Duration::from_secs(heartbeat_interval);
                        } else {
                            eprintln!(
                                "[Client] 上报流量至 NAS 失败，服务器返回状态码: {}",
                                resp.status()
                            );
                            if should_report_delta {
                                next_report_due = Instant::now() + retry_delay;
                                retry_delay = (retry_delay * 2).min(Duration::from_secs(300));
                            } else {
                                next_heartbeat_due =
                                    Instant::now() + retry_delay.min(Duration::from_secs(60));
                            }
                        }
                    }
                    Err(e) => {
                        eprintln!("[Client] 上报流量至 NAS 失败: {}", e);
                        if should_report_delta {
                            next_report_due = Instant::now() + retry_delay;
                            retry_delay = (retry_delay * 2).min(Duration::from_secs(300));
                        } else {
                            next_heartbeat_due =
                                Instant::now() + retry_delay.min(Duration::from_secs(60));
                        }
                    }
                }
            }
        }
    });
}

// ==========================================
// 4. 单元测试
// ==========================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_calculate_proxy_deltas_basic() {
        let mut tracker = ClientTrafficTracker::default();

        // 1. 模拟第一轮：检测到几个连接
        let conns = vec![
            ClashConnection {
                id: "conn1".to_string(),
                metadata: ClashConnectionMetadata {
                    host: "google.com".to_string(),
                    destination_ip: None,
                },
                upload: 100,
                download: 200,
                chains: vec!["proxy".to_string()],
            },
            ClashConnection {
                id: "conn2".to_string(),
                metadata: ClashConnectionMetadata {
                    host: "baidu.com".to_string(),
                    destination_ip: None,
                },
                upload: 50,
                download: 150,
                chains: vec!["direct".to_string()], // 直连
            },
        ];

        // 首次运行，全都是新连接，记为基准，delta 应全为 0
        let batch = tracker.calculate_proxy_deltas(&conns);
        assert_eq!(batch.download_delta, 0);
        assert_eq!(batch.upload_delta, 0);
        assert!(batch.domain_deltas.is_empty());
        assert_eq!(tracker.active_conns.len(), 1); // 仅跟踪 proxy 连接 "conn1"

        // 2. 模拟第二轮：连接流量增加
        let conns2 = vec![
            ClashConnection {
                id: "conn1".to_string(),
                metadata: ClashConnectionMetadata {
                    host: "google.com".to_string(),
                    destination_ip: None,
                },
                upload: 150,   // 增加 50
                download: 300, // 增加 100
                chains: vec!["proxy".to_string()],
            },
            ClashConnection {
                id: "conn2".to_string(),
                metadata: ClashConnectionMetadata {
                    host: "baidu.com".to_string(),
                    destination_ip: None,
                },
                upload: 100,   // 增加 50，但它是直连，应该不累计
                download: 300, // 增加 150
                chains: vec!["direct".to_string()],
            },
            ClashConnection {
                id: "conn3".to_string(),
                metadata: ClashConnectionMetadata {
                    host: "control.example.invalid".to_string(),
                    destination_ip: None,
                },
                upload: 1000,
                download: 2000,
                chains: vec!["proxy".to_string()], // 控制流量虽然是 proxy，但被排除
            },
        ];

        let control_domains = vec!["control.example.invalid".to_string()];
        let batch2 = tracker.calculate_proxy_deltas_with_control_domains(&conns2, &control_domains);
        assert_eq!(batch2.download_delta, 100); // google.com 增加的 100
        assert_eq!(batch2.upload_delta, 50); // google.com 增加的 50
        assert_eq!(batch2.domain_deltas.len(), 1);
        assert_eq!(*batch2.domain_deltas.get("google.com").unwrap(), 150);

        // 此时 active_conns 应仅包含 conn1 (因为 conn3 是大本营域名被跳过了，conn2 是直连被跳过了)
        assert_eq!(tracker.active_conns.len(), 1);
        assert!(tracker.active_conns.contains_key("conn1"));
        assert!(!tracker.active_conns.contains_key("conn3"));

        // 3. 模拟第三轮：conn1 消失，只剩下 conn3 并且流量变化，新增 conn4 (destination_ip 兜底)
        let conns3 = vec![
            ClashConnection {
                id: "conn3".to_string(),
                metadata: ClashConnectionMetadata {
                    host: "control.example.invalid".to_string(),
                    destination_ip: None,
                },
                upload: 1500,   // 增量 500，但依然是大本营域名，应过滤
                download: 3000, // 增量 1000
                chains: vec!["proxy".to_string()],
            },
            ClashConnection {
                id: "conn4".to_string(),
                metadata: ClashConnectionMetadata {
                    host: "".to_string(), // host为空
                    destination_ip: Some("93.184.216.34".to_string()),
                },
                upload: 200,
                download: 400,
                chains: vec!["proxy".to_string()], // 新的代理连接，作为基准
            },
        ];

        let batch3 = tracker.calculate_proxy_deltas_with_control_domains(&conns3, &control_domains);
        assert_eq!(batch3.download_delta, 0); // 没有产生非排除代理连接的 delta 流量
        assert_eq!(batch3.upload_delta, 0);
        assert!(batch3.domain_deltas.is_empty());

        // 检查 active_conns 应自动清理 conn1，仅保留 conn4
        assert_eq!(tracker.active_conns.len(), 1);
        assert!(!tracker.active_conns.contains_key("conn1"));
        assert!(!tracker.active_conns.contains_key("conn3"));
        assert!(tracker.active_conns.contains_key("conn4"));
    }

    #[test]
    fn test_classify_proxy_domain_flags_domestic_and_private_targets() {
        let baidu = classify_proxy_domain("passport.baidu.com:443");
        assert!(!baidu.should_proxy);
        assert_eq!(baidu.category, "should-direct");

        let cn = classify_proxy_domain("api.example.cn");
        assert!(!cn.should_proxy);
        assert_eq!(cn.category, "should-direct");

        let private_ip = classify_proxy_domain("192.168.1.1:8080");
        assert!(!private_ip.should_proxy);
        assert_eq!(private_ip.category, "private-network");

        let overseas = classify_proxy_domain("api.openai.com");
        assert!(overseas.should_proxy);
        assert_eq!(overseas.category, "expected-proxy");
    }

    #[test]
    fn test_classify_proxy_domain_accepts_configured_direct_suffixes() {
        let suffixes = vec!["internal.example".to_string()];
        let internal =
            classify_proxy_domain_with_suffixes("cdn.internal.example:443", suffixes.clone());
        assert!(!internal.should_proxy);
        assert_eq!(internal.category, "should-direct");

        let overseas = classify_proxy_domain_with_suffixes("api.openai.com", suffixes);
        assert!(overseas.should_proxy);
    }

    #[test]
    fn test_pending_report_keeps_stable_id_across_merges() {
        let mut pending = PendingTrafficReport::default();
        pending.merge_batch(
            ProxyDeltaBatch {
                download_delta: 10,
                upload_delta: 5,
                domain_deltas: HashMap::from([("api.openai.com".to_string(), 15)]),
                abnormal_domain_deltas: HashMap::new(),
            },
            "Mac Book",
        );
        let first_id = pending.report_id.clone();
        assert!(!first_id.is_empty());

        pending.merge_batch(
            ProxyDeltaBatch {
                download_delta: 20,
                upload_delta: 0,
                domain_deltas: HashMap::from([("api.openai.com".to_string(), 20)]),
                abnormal_domain_deltas: HashMap::new(),
            },
            "Mac Book",
        );

        assert_eq!(pending.report_id, first_id);
        assert_eq!(pending.total_bytes(), 35);
    }

    #[test]
    fn test_calculate_proxy_deltas_marks_abnormal_proxy_domains() {
        let mut tracker = ClientTrafficTracker::default();
        let first = vec![ClashConnection {
            id: "cn1".to_string(),
            metadata: ClashConnectionMetadata {
                host: "static.bilibili.com".to_string(),
                destination_ip: None,
            },
            upload: 10,
            download: 10,
            chains: vec!["proxy".to_string()],
        }];
        let _ = tracker.calculate_proxy_deltas(&first);

        let second = vec![ClashConnection {
            id: "cn1".to_string(),
            metadata: ClashConnectionMetadata {
                host: "static.bilibili.com".to_string(),
                destination_ip: None,
            },
            upload: 20,
            download: 70,
            chains: vec!["proxy".to_string()],
        }];

        let batch = tracker.calculate_proxy_deltas(&second);
        assert_eq!(batch.download_delta, 60);
        assert_eq!(batch.upload_delta, 10);
        assert_eq!(*batch.domain_deltas.get("static.bilibili.com").unwrap(), 70);

        let abnormal = batch
            .abnormal_domain_deltas
            .get("static.bilibili.com")
            .unwrap();
        assert_eq!(abnormal.bytes, 70);
        assert!(!abnormal.should_proxy);
        assert_eq!(abnormal.category, "should-direct");
    }

    #[test]
    fn test_weekly_logic() {
        use chrono::{Datelike, Local, TimeZone};
        let now = Local::now();
        let hour_str = "2026-06-18 19:00";
        let d = chrono::NaiveDate::parse_from_str(&hour_str[..10], "%Y-%m-%d").unwrap();
        let t_zero = Local
            .with_ymd_and_hms(d.year(), d.month(), d.day(), 0, 0, 0)
            .unwrap()
            .timestamp();

        let start = now - chrono::Duration::days(6);
        let end = now - chrono::Duration::days(0);

        let start_zero = Local
            .with_ymd_and_hms(start.year(), start.month(), start.day(), 0, 0, 0)
            .unwrap()
            .timestamp();
        let end_zero = Local
            .with_ymd_and_hms(end.year(), end.month(), end.day(), 23, 59, 59)
            .unwrap()
            .timestamp();

        println!(
            "t_zero: {}, start_zero: {}, end_zero: {}",
            t_zero, start_zero, end_zero
        );
        assert!(t_zero >= start_zero && t_zero <= end_zero);
    }
}

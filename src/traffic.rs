use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;
use tokio::time::sleep;

// ==========================================
// 1. 服务端数据定义与持久化逻辑
// ==========================================

#[derive(Serialize, Deserialize, Clone, Default, Debug)]
pub struct DeviceHistory {
    pub total_download: i64,
    pub total_upload: i64,
    pub last_seen: i64,      // 秒级 Unix 时间戳
    pub current_node: String,
}

#[derive(Serialize, Deserialize, Clone, Default, Debug)]
pub struct NodeHistory {
    pub server: String,
    pub server_port: u16,
    pub password: Option<String>,
    pub server_name: Option<String>,
    pub total_download: i64,
    pub total_upload: i64,
}

#[derive(Serialize, Deserialize, Clone, Default, Debug)]
pub struct NasTrafficHistory {
    pub devices: HashMap<String, DeviceHistory>,
    pub nodes: HashMap<String, NodeHistory>,
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
    pub device_name: String,
    pub download_delta: i64,
    pub upload_delta: i64,
    pub current_node_ip: String,
    pub domain_deltas: HashMap<String, i64>,
}

#[derive(Deserialize, Debug, Clone)]
pub struct ClashConnectionMetadata {
    pub host: String,
}

#[derive(Deserialize, Debug, Clone)]
pub struct ClashConnection {
    pub id: String,
    pub metadata: ClashConnectionMetadata,
    pub upload: i64,
    pub download: i64,
}

// sing-box Clash Connections API 数据结构
#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct ClashAPIConnections {
    pub download_total: i64,
    pub upload_total: i64,
    pub connections: Option<Vec<ClashConnection>>,
}

// 客户端状态：用于记录上一次的绝对总流量以及活跃连接明细
#[derive(Default)]
pub struct ClientTrafficTracker {
    pub last_download: i64,
    pub last_upload: i64,
    pub active_conns: HashMap<String, (String, i64, i64)>, // id -> (host, last_download, last_upload)
}

impl ClientTrafficTracker {
    /// 计算新一轮轮询的 Delta 流量，并更新上一次的流量绝对值。
    /// 如果发现本轮总量小于历史总量，说明 sing-box 进程发生了重启，计数器清零，则直接以本轮总量作为增量 Delta。
    pub fn calculate_delta(&mut self, current_download: i64, current_upload: i64) -> (i64, i64) {
        let download_delta = if current_download < self.last_download {
            current_download
        } else {
            current_download - self.last_download
        };

        let upload_delta = if current_upload < self.last_upload {
            current_upload
        } else {
            current_upload - self.last_upload
        };

        self.last_download = current_download;
        self.last_upload = current_upload;

        (download_delta, upload_delta)
    }

    /// 增量计算当前所有活跃连接产生的各个域名的流量 Delta
    pub fn calculate_domain_deltas(&mut self, connections: &[ClashConnection]) -> HashMap<String, i64> {
        let mut deltas = HashMap::new();
        let mut current_ids = std::collections::HashSet::new();

        for conn in connections {
            let id = &conn.id;
            let host = &conn.metadata.host;
            if host.is_empty() {
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
                    *deltas.entry(host.clone()).or_insert(0) += total;
                }
            } else {
                // 新连接，将已经发生的流量做第一次计入
                let total = cur_dl + cur_ul;
                if total > 0 {
                    *deltas.entry(host.clone()).or_insert(0) += total;
                }
            }

            self.active_conns.insert(id.clone(), (host.clone(), cur_dl, cur_ul));
        }

        // 清理在当前活跃列表里已经不存在的连接
        self.active_conns.retain(|id, _| current_ids.contains(id));

        deltas
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
    if let Ok(mut addrs) = tokio::net::lookup_host(&host_port).await {
        if let Some(addr) = addrs.next() {
            return addr.ip().to_string();
        }
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

        println!(
            "[Client] 流量上报协程已启动。设备名: {}, 上报至 NAS: {}, 监听本地 sing-box: {}",
            device_name, report_url, singbox_api_url
        );

        loop {
            sleep(Duration::from_secs(5)).await;

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

            // 计算增量
            let (dl_delta, ul_delta) = tracker.calculate_delta(data.download_total, data.upload_total);

            // 增量计算各个域名的流量 Delta
            let domain_deltas = if let Some(conns) = &data.connections {
                tracker.calculate_domain_deltas(conns)
            } else {
                HashMap::new()
            };

            // 获取当前激活的节点
            let active_node = {
                let guard = current_node_lock.read().await;
                guard.clone()
            };

            // 查询本地 client_nodes.json 并尝试解析成 IP
            let local_nodes = crate::node::load_local_nodes();
            let node_ip = if active_node == "未知" || active_node == "未配置" || active_node.is_empty() {
                active_node
            } else if let Some(n) = local_nodes.iter().find(|n| n.name == active_node) {
                resolve_server_ip(&n.server, n.server_port).await
            } else {
                active_node
            };

            let req_body = TrafficReportRequest {
                device_name: device_name.clone(),
                download_delta: dl_delta,
                upload_delta: ul_delta,
                current_node_ip: node_ip,
                domain_deltas,
            };

            if let Err(e) = client.post(&report_url).json(&req_body).send().await {
                eprintln!("[Client] 上报流量至 NAS 失败: {}", e);
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
    fn test_calculate_delta_normal() {
        let mut tracker = ClientTrafficTracker::default();
        
        // 初始第一轮，上一次是0，本轮产生 1000 下载, 200 上传
        let (dl1, ul1) = tracker.calculate_delta(1000, 200);
        assert_eq!(dl1, 1000);
        assert_eq!(ul1, 200);
        assert_eq!(tracker.last_download, 1000);
        assert_eq!(tracker.last_upload, 200);

        // 第二轮，流量继续上涨，总量变为 1500 下载, 300 上传，增量应该为 500 和 100
        let (dl2, ul2) = tracker.calculate_delta(1500, 300);
        assert_eq!(dl2, 500);
        assert_eq!(ul2, 100);
        assert_eq!(tracker.last_download, 1500);
        assert_eq!(tracker.last_upload, 300);
    }

    #[test]
    fn test_calculate_delta_reset() {
        let mut tracker = ClientTrafficTracker {
            last_download: 2000,
            last_upload: 500,
        };

        // 模拟 sing-box 重启，流量计数清零，本轮获得 100 下载, 50 上传
        // 应直接以本轮总量作为 Delta
        let (dl, ul) = tracker.calculate_delta(100, 50);
        assert_eq!(dl, 100);
        assert_eq!(ul, 50);
        assert_eq!(tracker.last_download, 100);
        assert_eq!(tracker.last_upload, 50);
    }

    #[test]
    fn test_weekly_logic() {
        use chrono::{Local, Datelike, TimeZone};
        let now = Local::now();
        let hour_str = "2026-06-18 19:00";
        let d = chrono::NaiveDate::parse_from_str(&hour_str[..10], "%Y-%m-%d").unwrap();
        let t_zero = Local.with_ymd_and_hms(d.year(), d.month(), d.day(), 0, 0, 0).unwrap().timestamp();
        
        let start = now - chrono::Duration::days(6);
        let end = now - chrono::Duration::days(0);
        
        let start_zero = Local.with_ymd_and_hms(start.year(), start.month(), start.day(), 0, 0, 0).unwrap().timestamp();
        let end_zero = Local.with_ymd_and_hms(end.year(), end.month(), end.day(), 23, 59, 59).unwrap().timestamp();
        
        println!("t_zero: {}, start_zero: {}, end_zero: {}", t_zero, start_zero, end_zero);
        assert!(t_zero >= start_zero && t_zero <= end_zero);
    }
}

use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::fs;
use std::process::Command;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;
use tokio::time::sleep;

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct NodeConfig {
    pub name: String,
    pub server: String,
    pub server_port: u16,
    pub password: Option<String>,
    pub server_name: Option<String>,
}

#[derive(Deserialize)]
pub struct AddNodeRequest {
    pub name: String,
    pub server: String,
    pub server_port: u16,
    pub password: Option<String>,
    pub server_name: Option<String>,
}

#[derive(Deserialize)]
pub struct SwitchNodeRequest {
    pub name: String,
}

// 默认路径配置
const DEFAULT_CLIENT_NODES_FILE: &str = "client_nodes.json";

fn get_singbox_config_path() -> String {
    std::env::var("SINGBOX_CONFIG_PATH")
        .unwrap_or_else(|_| "/opt/homebrew/etc/sing-box/config.json".to_string())
}

fn get_singbox_bin() -> String {
    std::env::var("SINGBOX_BIN")
        .unwrap_or_else(|_| "/opt/homebrew/bin/sing-box".to_string())
}

fn get_temp_check_path() -> String {
    "/tmp/sing-box-check-config.json".to_string()
}

// 加载本地节点列表
pub fn load_local_nodes() -> Vec<NodeConfig> {
    if let Ok(content) = fs::read_to_string(DEFAULT_CLIENT_NODES_FILE) {
        serde_json::from_str(&content).unwrap_or_default()
    } else {
        Vec::new()
    }
}

// 保存本地节点列表
pub fn save_local_nodes(nodes: &[NodeConfig]) {
    if let Ok(data) = serde_json::to_string_pretty(nodes) {
        let _ = fs::write(DEFAULT_CLIENT_NODES_FILE, data);
    }
}

// 获取当前 sing-box 配置文件里 proxy 节点的服务器地址，用来匹配当前的 active node 名字
pub fn detect_active_node_tag(local_nodes: &[NodeConfig]) -> String {
    let config_path = get_singbox_config_path();
    let content = match fs::read_to_string(&config_path) {
        Ok(c) => c,
        Err(_) => return "未知".to_string(),
    };

    let json_val: Value = match serde_json::from_str(&content) {
        Ok(v) => v,
        Err(_) => return "未知".to_string(),
    };

    let outbounds = match json_val.get("outbounds").and_then(|o| o.as_array()) {
        Some(o) => o,
        None => return "未知".to_string(),
    };

    for ob in outbounds {
        if ob.get("tag").and_then(|t| t.as_str()) == Some("proxy") {
            let current_server = ob.get("server").and_then(|s| s.as_str()).unwrap_or("");
            let current_port = ob.get("server_port").and_then(|p| p.as_u64()).unwrap_or(0) as u16;

            // 在本地节点库匹配
            for node in local_nodes {
                if node.server == current_server && node.server_port == current_port {
                    return node.name.clone();
                }
            }
            return if !current_server.is_empty() {
                format!("{}:{}", current_server, current_port)
            } else {
                "未知".to_string()
            };
        }
    }

    "未配置".to_string()
}

/// 执行节点切换逻辑：
/// 1. 修改本地 sing-box 的配置文件中 tag = "proxy" 的出站。
/// 2. 进行配置 check，验证合法后覆盖写入正式文件。
/// 3. 重启 sing-box 服务。
pub async fn switch_local_node(node_name: &str, current_node_lock: Arc<RwLock<String>>) -> Result<String, String> {
    let nodes = load_local_nodes();
    let node = nodes.iter().find(|n| n.name == node_name)
        .ok_ok_or_else(|| format!("本地节点池中未找到名为 '{}' 的节点", node_name))?;

    let config_path = get_singbox_config_path();
    let content = fs::read_to_string(&config_path)
        .map_err(|e| format!("无法读取 sing-box 配置文件: {}", e))?;

    let mut json_val: Value = serde_json::from_str(&content)
        .map_err(|e| format!("解析 sing-box 配置文件失败: {}", e))?;

    let outbounds = json_val.get_mut("outbounds")
        .and_then(|o| o.as_array_mut())
        .ok_ok_or_else(|| "配置文件中未找到 outbounds 字段".to_string())?;

    let mut found = false;
    for ob in outbounds {
        if ob.get("tag").and_then(|t| t.as_str()) == Some("proxy") {
            ob["server"] = Value::String(node.server.clone());
            ob["server_port"] = Value::Number(node.server_port.into());
            if let Some(ref pwd) = node.password {
                ob["password"] = Value::String(pwd.clone());
            }
            if let Some(ref sni) = node.server_name {
                if let Some(tls) = ob.get_mut("tls").and_then(|t| t.as_object_mut()) {
                    tls.insert("server_name".to_string(), Value::String(sni.clone()));
                }
            }
            found = true;
            break;
        }
    }

    if !found {
        return Err("未能在配置文件中定位到 tag 为 'proxy' 的代理出口 outbound 项".to_string());
    }

    let new_data = serde_json::to_string_pretty(&json_val)
        .map_err(|e| format!("序列化新配置失败: {}", e))?;

    let temp_path = get_temp_check_path();
    fs::write(&temp_path, &new_data)
        .map_err(|e| format!("写入临时检查文件失败: {}", e))?;

    // 运行校验
    let check_output = Command::new(get_singbox_bin())
        .args(&["check", "-c", &temp_path])
        .output()
        .map_err(|e| format!("无法启动 sing-box 进行语法校验: {}", e))?;

    if !check_output.status.success() {
        let err_msg = String::from_utf8_lossy(&check_output.stderr).to_string();
        return Err(format!("新配置语法校验失败: {}", err_msg));
    }

    // 覆盖原正式配置
    fs::write(&config_path, &new_data)
        .map_err(|e| format!("配置通过语法校验，但在覆盖正式配置文件时失败（请检查读写权限）: {}", e))?;

    // 异步执行重启
    tokio::spawn(async {
        sleep(Duration::from_millis(500)).await;
        let restart_cmd = std::env::var("SINGBOX_RESTART_CMD")
            .unwrap_or_else(|_| "brew services restart sing-box".to_string());
        
        let parts: Vec<&str> = restart_cmd.split_whitespace().collect();
        if !parts.is_empty() {
            let _ = Command::new(parts[0])
                .args(&parts[1..])
                .output();
        }
    });

    // 更新内存中的当前节点名称
    let mut guard = current_node_lock.write().await;
    *guard = node_name.to_string();

    Ok(format!("成功切换到节点 '{}'，配置校验通过，代理服务重启中！", node_name))
}

// 辅助方法，将 Option 转为 Result
trait OptionExt<T> {
    fn ok_ok_or_else<F: FnOnce() -> String>(self, err_fn: F) -> Result<T, String>;
}

impl<T> OptionExt<T> for Option<T> {
    fn ok_ok_or_else<F: FnOnce() -> String>(self, err_fn: F) -> Result<T, String> {
        self.ok_or_else(err_fn)
    }
}

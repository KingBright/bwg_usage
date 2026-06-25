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
    #[serde(default)]
    pub outbound: Option<Value>,
}

#[derive(Deserialize)]
pub struct AddNodeRequest {
    pub name: String,
    pub server: String,
    pub server_port: u16,
    pub password: Option<String>,
    pub server_name: Option<String>,
    #[serde(default)]
    pub outbound: Option<Value>,
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
    std::env::var("SINGBOX_BIN").unwrap_or_else(|_| "/opt/homebrew/bin/sing-box".to_string())
}

fn get_temp_check_path() -> String {
    if cfg!(target_os = "windows") {
        std::env::var("TEMP")
            .map(|t| format!("{}\\sing-box-check-config.json", t))
            .unwrap_or_else(|_| "C:\\Program Files\\sing-box\\check-config.json".to_string())
    } else {
        "/tmp/sing-box-check-config.json".to_string()
    }
}


fn get_brew_bin() -> String {
    std::env::var("BREW_BIN").unwrap_or_else(|_| {
        if std::path::Path::new("/opt/homebrew/bin/brew").exists() {
            "/opt/homebrew/bin/brew".to_string()
        } else if std::path::Path::new("/usr/local/bin/brew").exists() {
            "/usr/local/bin/brew".to_string()
        } else {
            "brew".to_string()
        }
    })
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SingboxAction {
    Start,
    Stop,
    Restart,
}

impl SingboxAction {
    pub fn from_str(action: &str) -> Option<Self> {
        match action {
            "start" => Some(Self::Start),
            "stop" => Some(Self::Stop),
            "restart" => Some(Self::Restart),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Start => "start",
            Self::Stop => "stop",
            Self::Restart => "restart",
        }
    }
}

fn command_has_shell_metachar(value: &str) -> bool {
    value
        .chars()
        .any(|c| matches!(c, ';' | '&' | '|' | '>' | '<' | '`' | '$' | '\n' | '\r'))
}

fn command_name(program: &str) -> &str {
    std::path::Path::new(program)
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("")
}

fn valid_service_name(value: &str) -> bool {
    value.contains("sing-box")
        && value
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-' | '/' | '@'))
}

fn validate_service_command(parts: &[String], action: SingboxAction) -> Result<(), String> {
    let (mut command_idx, program) = parts
        .first()
        .map(|p| (0usize, command_name(p)))
        .ok_or_else(|| "命令为空".to_string())?;

    if program == "sudo" {
        if parts.get(1).map(|s| s.as_str()) != Some("-n") {
            return Err("sudo 管理命令必须使用 -n 以避免阻塞等待密码".to_string());
        }
        command_idx = 2;
    }

    let command = parts
        .get(command_idx)
        .ok_or_else(|| "sudo 后缺少实际管理命令".to_string())?;
    let command = command_name(command);
    let args = &parts[command_idx + 1..];

    match command {
        "brew" => {
            let expected = ["services", action.as_str(), "sing-box"];
            if args.iter().map(String::as_str).eq(expected) {
                Ok(())
            } else {
                Err(format!(
                    "brew 管理命令只允许: brew services {} sing-box",
                    action.as_str()
                ))
            }
        }
        "systemctl" => {
            if args.len() == 2
                && args[0] == action.as_str()
                && matches!(args[1].as_str(), "sing-box" | "sing-box.service")
            {
                Ok(())
            } else {
                Err(format!(
                    "systemctl 管理命令只允许: systemctl {} sing-box",
                    action.as_str()
                ))
            }
        }
        "launchctl" => match action {
            SingboxAction::Start | SingboxAction::Stop => {
                if args.len() == 2 && args[0] == action.as_str() && valid_service_name(&args[1]) {
                    Ok(())
                } else {
                    Err(format!(
                        "launchctl {} 只允许操作包含 sing-box 的服务标签",
                        action.as_str()
                    ))
                }
            }
            SingboxAction::Restart => {
                if args.len() == 3
                    && args[0] == "kickstart"
                    && args[1] == "-k"
                    && valid_service_name(&args[2])
                {
                    Ok(())
                } else {
                    Err(
                        "launchctl restart 只允许: launchctl kickstart -k <sing-box 服务标签>"
                            .to_string(),
                    )
                }
            }
        },
        _ => Err(format!("不允许的 sing-box 管理命令: {}", command)),
    }
}

fn parse_configured_command(value: &str, action: SingboxAction) -> Result<Vec<String>, String> {
    if value.trim().is_empty() {
        return Err("命令为空".to_string());
    }
    if command_has_shell_metachar(value) {
        return Err("命令包含不允许的 shell 元字符".to_string());
    }
    let mut parts: Vec<String> = value.split_whitespace().map(|s| s.to_string()).collect();
    if parts.is_empty() {
        return Err("命令为空".to_string());
    }

    if command_name(&parts[0]) == "sudo" && parts.get(1).map(|s| s.as_str()) != Some("-n") {
        parts.insert(1, "-n".to_string());
    }

    validate_service_command(&parts, action)?;
    Ok(parts)
}

fn default_singbox_command(action: SingboxAction) -> Vec<String> {
    let sudo_bin = std::env::var("SUDO_BIN").unwrap_or_else(|_| "/usr/bin/sudo".to_string());
    if cfg!(target_os = "macos") {
        vec![
            sudo_bin,
            "-n".to_string(),
            get_brew_bin(),
            "services".to_string(),
            action.as_str().to_string(),
            "sing-box".to_string(),
        ]
    } else {
        vec![
            sudo_bin,
            "-n".to_string(),
            "systemctl".to_string(),
            action.as_str().to_string(),
            "sing-box".to_string(),
        ]
    }
}

fn singbox_command_for_action(action: SingboxAction) -> Result<Vec<String>, String> {
    let env_key = match action {
        SingboxAction::Start => "SINGBOX_START_CMD",
        SingboxAction::Stop => "SINGBOX_STOP_CMD",
        SingboxAction::Restart => "SINGBOX_RESTART_CMD",
    };
    if let Ok(cmd) = std::env::var(env_key) {
        return parse_configured_command(&cmd, action);
    }
    Ok(default_singbox_command(action))
}

pub async fn manage_singbox(action: SingboxAction) -> Result<String, String> {
    let parts = singbox_command_for_action(action)?;
    let (program, args) = parts
        .split_first()
        .ok_or_else(|| "sing-box 管理命令为空".to_string())?;

    let output = tokio::time::timeout(
        Duration::from_secs(20),
        tokio::process::Command::new(program).args(args).output(),
    )
    .await
    .map_err(|_| format!("sing-box {} 命令执行超时", action.as_str()))?
    .map_err(|e| format!("无法执行 sing-box {} 命令: {}", action.as_str(), e))?;

    if output.status.success() {
        return Ok(format!("sing-box {} 命令执行成功", action.as_str()));
    }

    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let detail = if stderr.trim().is_empty() {
        stdout.trim()
    } else {
        stderr.trim()
    };
    Err(format!(
        "sing-box {} 命令失败: {}。如果 sing-box 需要 sudo，请为该命令配置 NOPASSWD，或用 SINGBOX_*_CMD 指定允许的管理命令。",
        action.as_str(),
        detail
    ))
}

pub async fn restart_singbox() -> Result<String, String> {
    manage_singbox(SingboxAction::Restart).await
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
            let mut current_server = ob.get("server").and_then(|s| s.as_str()).unwrap_or("");
            let mut current_port = ob.get("server_port").and_then(|p| p.as_u64()).unwrap_or(0) as u16;

            // 如果是 selector 类型，则尝试寻找其默认的底层出口服务器
            if ob.get("type").and_then(|t| t.as_str()) == Some("selector") {
                if let Some(default_tag) = ob.get("default").and_then(|d| d.as_str()) {
                    for other_ob in outbounds {
                        if other_ob.get("tag").and_then(|t| t.as_str()) == Some(default_tag) {
                            current_server = other_ob.get("server").and_then(|s| s.as_str()).unwrap_or("");
                            current_port = other_ob.get("server_port").and_then(|p| p.as_u64()).unwrap_or(0) as u16;
                            break;
                        }
                    }
                }
            }

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
pub async fn switch_local_node(
    node_name: &str,
    current_node_lock: Arc<RwLock<String>>,
) -> Result<String, String> {
    let nodes = load_local_nodes();
    let node = nodes
        .iter()
        .find(|n| n.name == node_name)
        .ok_ok_or_else(|| format!("本地节点池中未找到名为 '{}' 的节点", node_name))?;

    let config_path = get_singbox_config_path();
    let content = fs::read_to_string(&config_path)
        .map_err(|e| format!("无法读取 sing-box 配置文件: {}", e))?;

    let mut json_val: Value =
        serde_json::from_str(&content).map_err(|e| format!("解析 sing-box 配置文件失败: {}", e))?;

    let outbounds = json_val
        .get_mut("outbounds")
        .and_then(|o| o.as_array_mut())
        .ok_ok_or_else(|| "配置文件中未找到 outbounds 字段".to_string())?;

    let mut found = false;
    for ob in outbounds {
        if ob.get("tag").and_then(|t| t.as_str()) == Some("proxy") {
            if ob.get("type").and_then(|t| t.as_str()) == Some("selector") {
                ob["default"] = Value::String(node.name.clone());
            } else if let Some(template) = &node.outbound {
                let mut next = template.clone();
                next["tag"] = Value::String("proxy".to_string());
                *ob = next;
            } else {
                ob["server"] = Value::String(node.server.clone());
                ob["server_port"] = Value::Number(node.server_port.into());
                if let Some(ref pwd) = node.password {
                    ob["password"] = Value::String(pwd.clone());
                } else if let Some(obj) = ob.as_object_mut() {
                    obj.remove("password");
                }
                if let Some(ref sni) = node.server_name {
                    if ob.get("tls").is_none() {
                        ob["tls"] = serde_json::json!({});
                    }
                    if let Some(tls) = ob.get_mut("tls").and_then(|t| t.as_object_mut()) {
                        tls.insert("server_name".to_string(), Value::String(sni.clone()));
                    }
                } else if let Some(tls) = ob.get_mut("tls").and_then(|t| t.as_object_mut()) {
                    tls.remove("server_name");
                }
            }
            found = true;
            break;
        }
    }

    if !found {
        return Err("未能在配置文件中定位到 tag 为 'proxy' 的代理出口 outbound 项".to_string());
    }

    // 确保对大盘控制域名的直连分流配置已注入
    let _ = ensure_control_domain_bypass(&mut json_val);

    let new_data =
        serde_json::to_string_pretty(&json_val).map_err(|e| format!("序列化新配置失败: {}", e))?;

    let temp_path = get_temp_check_path();
    fs::write(&temp_path, &new_data).map_err(|e| format!("写入临时检查文件失败: {}", e))?;

    // 运行校验
    let check_output = Command::new(get_singbox_bin())
        .args(["check", "-c", &temp_path])
        .output()
        .map_err(|e| format!("无法启动 sing-box 进行语法校验: {}", e))?;

    if !check_output.status.success() {
        let err_msg = String::from_utf8_lossy(&check_output.stderr).to_string();
        return Err(format!("新配置语法校验失败: {}", err_msg));
    }

    // 覆盖原正式配置
    fs::write(&config_path, &new_data).map_err(|e| {
        format!(
            "配置通过语法校验，但在覆盖正式配置文件时失败（请检查读写权限）: {}",
            e
        )
    })?;

    // 异步执行重启
    tokio::spawn(async {
        sleep(Duration::from_millis(500)).await;
        if let Err(e) = restart_singbox().await {
            eprintln!("⚠️  {}", e);
        }
    });

    // 更新内存中的当前节点名称
    let mut guard = current_node_lock.write().await;
    *guard = node_name.to_string();

    Ok(format!(
        "成功切换到节点 '{}'，配置校验通过，代理服务重启中！",
        node_name
    ))
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

pub fn ensure_control_domain_bypass(json_val: &mut Value) -> bool {
    let control_domains = configured_control_domain_suffixes();
    if control_domains.is_empty() {
        return false;
    }

    let route = match json_val.get_mut("route") {
        Some(r) => r,
        None => return false,
    };
    let rules = match route.get_mut("rules").and_then(|r| r.as_array_mut()) {
        Some(r) => r,
        None => return false,
    };

    let mut exists = false;
    for rule in rules.iter() {
        if rule.get("outbound").and_then(|o| o.as_str()) == Some("direct")
            && let Some(suffix_arr) = rule.get("domain_suffix").and_then(|s| s.as_array())
            && control_domains
                .iter()
                .all(|domain| suffix_arr.iter().any(|v| v.as_str() == Some(domain)))
        {
            exists = true;
            break;
        }
    }

    if !exists {
        println!(">>> sing-box 路由规则中缺失控制域名直连规则，正在自动注入...");
        let new_rule = serde_json::json!({
            "domain_suffix": control_domains,
            "outbound": "direct"
        });
        rules.insert(0, new_rule);
        true
    } else {
        false
    }
}

pub async fn check_and_apply_control_domain_bypass() -> Result<(), String> {
    let config_path = get_singbox_config_path();
    if !std::path::Path::new(&config_path).exists() {
        return Ok(());
    }
    let content = fs::read_to_string(&config_path)
        .map_err(|e| format!("无法读取 sing-box 配置文件: {}", e))?;

    let mut json_val: Value =
        serde_json::from_str(&content).map_err(|e| format!("解析 sing-box 配置文件失败: {}", e))?;

    if ensure_control_domain_bypass(&mut json_val) {
        let new_data = serde_json::to_string_pretty(&json_val)
            .map_err(|e| format!("序列化新配置失败: {}", e))?;

        let temp_path = get_temp_check_path();
        fs::write(&temp_path, &new_data).map_err(|e| format!("写入临时检查文件失败: {}", e))?;

        let check_output = Command::new(get_singbox_bin())
            .args(["check", "-c", &temp_path])
            .output()
            .map_err(|e| format!("无法启动 sing-box 进行语法校验: {}", e))?;

        if !check_output.status.success() {
            let err_msg = String::from_utf8_lossy(&check_output.stderr).to_string();
            return Err(format!("新配置语法校验失败: {}", err_msg));
        }

        fs::write(&config_path, &new_data)
            .map_err(|e| format!("配置通过语法校验，但在覆盖正式配置文件时失败: {}", e))?;

        println!(">>> 已自动更新本地 sing-box 配置文件以让控制域名直连，正在重启 sing-box 服务...");
        restart_singbox().await?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_configured_command_inserts_sudo_non_interactive() {
        let parsed = parse_configured_command(
            "sudo brew services restart sing-box",
            SingboxAction::Restart,
        )
        .unwrap();
        assert_eq!(parsed[0], "sudo");
        assert_eq!(parsed[1], "-n");
        assert_eq!(parsed[2], "brew");
    }

    #[test]
    fn test_parse_configured_command_rejects_shell_metacharacters() {
        let err = parse_configured_command(
            "sudo brew services restart sing-box; rm -rf /",
            SingboxAction::Restart,
        )
        .expect_err("shell metacharacters should be rejected");
        assert!(err.contains("shell"));
    }

    #[test]
    fn test_parse_configured_command_rejects_sudo_to_unrelated_command() {
        let err = parse_configured_command("sudo rm -rf /tmp/example", SingboxAction::Restart)
            .expect_err("sudo must not allow unrelated commands");
        assert!(err.contains("不允许"));
    }

    #[test]
    fn test_parse_configured_command_rejects_wrong_action() {
        let err = parse_configured_command("brew services stop sing-box", SingboxAction::Restart)
            .expect_err("configured command must match requested action");
        assert!(err.contains("brew 管理命令"));
    }

    #[test]
    fn test_singbox_action_from_str() {
        assert_eq!(
            SingboxAction::from_str("restart"),
            Some(SingboxAction::Restart)
        );
        assert_eq!(SingboxAction::from_str("reload"), None);
    }
}

#!/bin/bash
set -e

# 1. 本地读取并导出 .env 中的 API 凭证及环境变量
if [ -f .env ]; then
    export $(cat .env | grep -v '^#' | xargs)
fi

# 2. 配置信息 (NAS) - 优先从环境变量/.env读取，默认回落到占位符
SERVER=${SERVER:-"root@your-nas-domain.com"}
SSH_PORT=${SSH_PORT:-"your_nas_ssh_port"}
APP_DIR=${APP_DIR:-"/opt/bwg_usage"}
BINARY_NAME=${BINARY_NAME:-"bwg_usage"}
DOMAIN=${DOMAIN:-"your-nas-domain.com:8443"}
PORT=${PORT:-"18082"}

# 3. 搬瓦工 VPS 的 SSH 连接信息 - 优先从环境变量/.env读取，默认回落到占位符
VPS_SSH_HOST=${VPS_SSH_HOST:-"your_vps_ip_here"}
VPS_SSH_PORT=${VPS_SSH_PORT:-"your_vps_ssh_port"}
VPS_SSH_USER=${VPS_SSH_USER:-"root"}
VEID=${VEID:-"your_bwg_veid"}
API_KEY=${API_KEY:-"private_yourBwgApiKeyHere"}
BWG_SERVER_NAME=${BWG_SERVER_NAME:-"VPS-01"}
BWG_SERVER_IP=${BWG_SERVER_IP:-"$VPS_SSH_HOST"}
REPORT_TOKEN=${REPORT_TOKEN:-""}
REPORT_AUTH_REQUIRED=${REPORT_AUTH_REQUIRED:-"true"}
DASHBOARD_TOKEN=${DASHBOARD_TOKEN:-"$REPORT_TOKEN"}
READ_AUTH_REQUIRED=${READ_AUTH_REQUIRED:-"true"}
DEVICE_ONLINE_SECS=${DEVICE_ONLINE_SECS:-"90"}
VPS_LOG_TAIL_LINES=${VPS_LOG_TAIL_LINES:-"10000"}
DIRECT_SUFFIXES=${DIRECT_SUFFIXES:-""}
DIRECT_SUFFIXES_FILE=${DIRECT_SUFFIXES_FILE:-""}

if [ -z "$REPORT_TOKEN" ]; then
    echo "❌ 错误: 必须配置 REPORT_TOKEN，客户端 daemon 与 NAS server 需要使用同一个 token。"
    echo "示例: REPORT_TOKEN=\$(openssl rand -hex 32) ./deploy.sh"
    exit 1
fi

trap 'rm -f config.env bwg_servers.generated.json v2ray-traffic.service bwg_usage.service' EXIT

echo ">>> 1. 本地交叉编译 Rust 代码 (Linux x64 musl)..."
./build_linux.sh
TARGET_DIR=$(cargo metadata --format-version 1 | grep -o '"target_directory":"[^"]*"' | head -n 1 | cut -d':' -f2 | tr -d '"')
TARGET_DIR=${TARGET_DIR:-"./target"}

echo ">>> 2. 部署 VPS 侧监控程序 (纯 Rust 版)..."
# 解析多 VPS SSH
if [ -n "$VPS_SSH_HOSTS" ]; then
    # 以逗号分割为数组
    IFS=',' read -r -a hosts_arr <<< "$VPS_SSH_HOSTS"
    IFS=',' read -r -a ports_arr <<< "$VPS_SSH_PORTS"
    IFS=',' read -r -a users_arr <<< "$VPS_SSH_USERS"
else
    # 兼容单 VPS
    hosts_arr=("$VPS_SSH_HOST")
    ports_arr=("$VPS_SSH_PORT")
    users_arr=("$VPS_SSH_USER")
fi

for i in "${!hosts_arr[@]}"; do
    host="${hosts_arr[$i]}"
    port="${ports_arr[$i]:-22}"
    user="${users_arr[$i]:-root}"
    
    echo ">>> 开始部署 VPS 侧统计守护进程 [${host}:${port}] (用户: ${user})..."
    
    # 确保远程目录存在并停止服务以释放文件锁定
    ssh -o StrictHostKeyChecking=accept-new -p $port $user@$host "mkdir -p /usr/local/bin && systemctl stop v2ray-traffic || true"
    
    # 屏蔽指定黑名单域名 (在 VPS 端 v2ray 级别阻断访问)
    echo ">>> 配置 VPS v2ray 路由规则以屏蔽特定黑名单域名..."
    python_script='
import json
import sys

path = "/etc/v2ray/config.json"
try:
    with open(path, "r") as f:
        data = json.load(f)
except Exception as e:
    print("ERROR_READ: " + str(e))
    sys.exit(1)

rules = data.setdefault("routing", {}).setdefault("rules", [])
google_play_domains = [
    "domain:googleapis.cn",
    "domain:services.googleapis.cn",
    "domain:googleapis.com",
    "domain:gvt0.com",
    "domain:gvt1.com",
    "domain:gvt2.com",
    "domain:gvt3.com",
    "domain:gvt5.com",
    "domain:googleusercontent.com",
    "domain:googlezip.net",
    "domain:xn--ngstr-lra8j.com"
]
target_domains = [
    "domain:mirrors.tuna.tsinghua.edu.cn",
    "domain:internal-api-lark-api.feishu.cn"
]

changed = False
google_allow = None
for rule in rules:
    if rule.get("outboundTag") == "direct" and any(
        d in rule.get("domain", []) for d in ["domain:googleapis.cn", "domain:services.googleapis.cn"]
    ):
        google_allow = rule
        break

if google_allow is None:
    insert_idx = len(rules)
    for idx, rule in enumerate(rules):
        if "geosite:cn" in rule.get("domain", []) or "geoip:cn" in rule.get("ip", []):
            insert_idx = idx
            break
    rules.insert(insert_idx, {
        "type": "field",
        "domain": google_play_domains,
        "outboundTag": "direct"
    })
    changed = True
else:
    domains = google_allow.setdefault("domain", [])
    for domain in google_play_domains:
        if domain not in domains:
            domains.append(domain)
            changed = True

found_block = False
for rule in rules:
    if rule.get("outboundTag") == "block" and set(rule.get("domain", [])) == set(target_domains):
        found_block = True
        break

if not found_block:
    new_rule = {
        "type": "field",
        "domain": target_domains,
        "outboundTag": "block"
    }
    insert_idx = 0
    for idx, rule in enumerate(rules):
        if "api" in rule.get("inboundTag", []):
            insert_idx = idx + 1
            break
    rules.insert(insert_idx, new_rule)
    changed = True

if changed:
    try:
        with open(path, "w") as f:
            json.dump(data, f, indent=2)
        print("UPDATED")
    except Exception as e:
        print("ERROR_WRITE: " + str(e))
        sys.exit(1)
else:
    print("NO_CHANGE")
'
    
    res=$(ssh -o StrictHostKeyChecking=accept-new -p $port $user@$host "python3 -c '$python_script'" || echo "FAILED")
    echo ">>> 路由配置修改状态: $res"
    if [ "$res" = "UPDATED" ]; then
        echo ">>> 检测到路由配置已更新，正在重启 v2ray 服务..."
        ssh -o StrictHostKeyChecking=accept-new -p $port $user@$host "systemctl restart v2ray"
    fi
    
    # 上传 Linux 静态编译 Rust 二进制至 VPS
    scp -O -o StrictHostKeyChecking=accept-new -P $port $TARGET_DIR/x86_64-unknown-linux-musl/release/bwg_usage $user@$host:/usr/local/bin/bwg_usage
    ssh -o StrictHostKeyChecking=accept-new -p $port $user@$host "chmod +x /usr/local/bin/bwg_usage"
    
    # 生成 Systemd 服务文件并上传
    cat <<EOF > v2ray-traffic.service
[Unit]
Description=V2Ray Domain Traffic Analyzer Daemon (Rust)
After=network.target

[Service]
Type=simple
User=root
ExecStart=/usr/local/bin/bwg_usage v2ray-traffic
Restart=always

[Install]
WantedBy=network.target
EOF

    scp -O -o StrictHostKeyChecking=accept-new -P $port v2ray-traffic.service $user@$host:/etc/systemd/system/v2ray-traffic.service
    rm -f v2ray-traffic.service
    
    # 停止原有的 python 脚本服务并清理
    ssh -o StrictHostKeyChecking=accept-new -p $port $user@$host "systemctl stop traffic_analyzer || true; systemctl disable traffic_analyzer || true; rm -f /etc/systemd/system/traffic_analyzer.service /etc/v2ray/sh/traffic_analyzer.py || true"
    
    # 启动新的 rust 服务
    ssh -o StrictHostKeyChecking=accept-new -p $port $user@$host "systemctl daemon-reload && systemctl enable v2ray-traffic && systemctl restart v2ray-traffic"
done

echo ">>> 3. 准备 NAS 上的远程部署目录..."
ssh -p $SSH_PORT $SERVER "mkdir -p $APP_DIR $APP_DIR/static"

echo ">>> 4. 停止 NAS 上现有的服务..."
ssh -p $SSH_PORT $SERVER "systemctl stop bwg_usage || true"

echo ">>> 5. 上传二进制程序及静态前端文件至 NAS..."
scp -O -P $SSH_PORT $TARGET_DIR/x86_64-unknown-linux-musl/release/bwg_usage $SERVER:$APP_DIR/$BINARY_NAME
scp -O -P $SSH_PORT -r static/* $SERVER:$APP_DIR/static/

echo ">>> 6. 生成并上传 NAS 配置文件..."
cat <<EOF > config.env
PORT=$PORT
VEID=$VEID
API_KEY=$API_KEY
STATIC_DIR=$APP_DIR/static
VPS_SSH_HOST=$VPS_SSH_HOST
VPS_SSH_PORT=$VPS_SSH_PORT
VPS_SSH_USER=$VPS_SSH_USER
VPS_SSH_HOSTS=$VPS_SSH_HOSTS
VPS_SSH_PORTS=$VPS_SSH_PORTS
VPS_SSH_USERS=$VPS_SSH_USERS
REPORT_TOKEN=$REPORT_TOKEN
REPORT_AUTH_REQUIRED=$REPORT_AUTH_REQUIRED
DASHBOARD_TOKEN=$DASHBOARD_TOKEN
READ_AUTH_REQUIRED=$READ_AUTH_REQUIRED
DEVICE_ONLINE_SECS=$DEVICE_ONLINE_SECS
VPS_LOG_TAIL_LINES=$VPS_LOG_TAIL_LINES
DIRECT_SUFFIXES=$DIRECT_SUFFIXES
DIRECT_SUFFIXES_FILE=$DIRECT_SUFFIXES_FILE
EOF

scp -O -P $SSH_PORT config.env $SERVER:$APP_DIR/config.env
rm config.env

echo ">>> 6b. 上传或生成搬瓦工服务器配置..."
if [ -f bwg_servers.json ]; then
    scp -O -P $SSH_PORT bwg_servers.json $SERVER:$APP_DIR/bwg_servers.json
elif [ "$VEID" != "your_bwg_veid" ] && [ "$API_KEY" != "private_yourBwgApiKeyHere" ] && [ -n "$BWG_SERVER_IP" ]; then
    cat <<EOF > bwg_servers.generated.json
[
  {
    "name": "$BWG_SERVER_NAME",
    "veid": "$VEID",
    "api_key": "$API_KEY",
    "ip": "$BWG_SERVER_IP"
  }
]
EOF
    scp -O -P $SSH_PORT bwg_servers.generated.json $SERVER:$APP_DIR/bwg_servers.json
    rm bwg_servers.generated.json
else
    echo "⚠️  未找到本地 bwg_servers.json，且 VEID/API_KEY/BWG_SERVER_IP 不完整；NAS 将无法显示真实搬瓦工官方流量。"
fi

echo ">>> 7. 配置并上传 NAS Systemd 服务文件..."
cat <<EOF > bwg_usage.service
[Unit]
Description=BandwagonHost Traffic Usage Monitor Service
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=$APP_DIR
ExecStart=$APP_DIR/$BINARY_NAME server
Restart=always
EnvironmentFile=$APP_DIR/config.env

[Install]
WantedBy=network.target
EOF

scp -O -P $SSH_PORT bwg_usage.service $SERVER:/etc/systemd/system/bwg_usage.service
rm bwg_usage.service

echo ">>> 8. 在 NAS 上重载 Systemd 并启动服务..."
ssh -p $SSH_PORT $SERVER "systemctl daemon-reload && systemctl enable bwg_usage && systemctl restart bwg_usage"

# 清理本地的临时编译文件 (可选，保留 target 可加速下次编译)
# cargo clean

echo ">>> 部署完成！"
echo "程序已在 NAS 上启动并监听端口 $PORT"
echo "可以通过域名访问：https://$DOMAIN"

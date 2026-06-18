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
    
    # 确保远程目录存在
    ssh -o StrictHostKeyChecking=no -p $port $user@$host "mkdir -p /usr/local/bin"
    
    # 上传 Linux 静态编译 Rust 二进制至 VPS
    scp -O -o StrictHostKeyChecking=no -P $port $TARGET_DIR/x86_64-unknown-linux-musl/release/bwg_usage $user@$host:/usr/local/bin/bwg_usage
    ssh -o StrictHostKeyChecking=no -p $port $user@$host "chmod +x /usr/local/bin/bwg_usage"
    
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

    scp -O -o StrictHostKeyChecking=no -P $port v2ray-traffic.service $user@$host:/etc/systemd/system/v2ray-traffic.service
    rm -f v2ray-traffic.service
    
    # 停止原有的 python 脚本服务并清理
    ssh -o StrictHostKeyChecking=no -p $port $user@$host "systemctl stop traffic_analyzer || true; systemctl disable traffic_analyzer || true; rm -f /etc/systemd/system/traffic_analyzer.service /etc/v2ray/sh/traffic_analyzer.py || true"
    
    # 启动新的 rust 服务
    ssh -o StrictHostKeyChecking=no -p $port $user@$host "systemctl daemon-reload && systemctl enable v2ray-traffic && systemctl restart v2ray-traffic"
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
EOF

scp -O -P $SSH_PORT config.env $SERVER:$APP_DIR/config.env
rm config.env

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

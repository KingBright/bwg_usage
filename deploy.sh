#!/bin/bash
set -e

# 配置信息 (NAS)
SERVER="root@your-nas-domain.com"
SSH_PORT="your_nas_ssh_port"
APP_DIR="/opt/bwg_usage"
BINARY_NAME="bwg_usage"
DOMAIN="your-nas-domain.com:8443"

# 本地读取 .env 中的 API 凭证
if [ -f .env ]; then
    export $(cat .env | grep -v '^#' | xargs)
fi

VEID=${VEID:-"your_bwg_veid"}
API_KEY=${API_KEY:-"private_yourBwgApiKeyHere"}
PORT="18082"

# 搬瓦工 VPS 的 SSH 连接信息
VPS_SSH_HOST="your_vps_ip_here"
VPS_SSH_PORT="your_vps_ssh_port"
VPS_SSH_USER="root"

echo ">>> 1. 本地交叉编译 Rust 代码 (Linux x64 musl)..."
./build_linux.sh
TARGET_DIR=$(cargo metadata --format-version 1 | grep -o '"target_directory":"[^"]*"' | head -n 1 | cut -d':' -f2 | tr -d '"')
TARGET_DIR=${TARGET_DIR:-"./target"}

echo ">>> 2. 部署 VPS 侧域名流量统计脚本..."
# 上传脚本至 VPS 并赋予执行权限
scp -O -o StrictHostKeyChecking=no -P $VPS_SSH_PORT traffic_analyzer.py $VPS_SSH_USER@$VPS_SSH_HOST:/etc/v2ray/sh/traffic_analyzer.py
ssh -o StrictHostKeyChecking=no -p $VPS_SSH_PORT $VPS_SSH_USER@$VPS_SSH_HOST "chmod +x /etc/v2ray/sh/traffic_analyzer.py"

# 配置 VPS 上的 Systemd 守护进程
cat <<EOF > traffic_analyzer.service
[Unit]
Description=V2Ray Domain Traffic Analyzer Daemon
After=network.target

[Service]
Type=simple
User=root
ExecStart=/usr/bin/python3 /etc/v2ray/sh/traffic_analyzer.py
Restart=always

[Install]
WantedBy=network.target
EOF

scp -O -o StrictHostKeyChecking=no -P $VPS_SSH_PORT traffic_analyzer.service $VPS_SSH_USER@$VPS_SSH_HOST:/etc/systemd/system/traffic_analyzer.service
rm traffic_analyzer.service

# 重启 VPS 上的统计服务
ssh -o StrictHostKeyChecking=no -p $VPS_SSH_PORT $VPS_SSH_USER@$VPS_SSH_HOST "systemctl daemon-reload && systemctl enable traffic_analyzer && systemctl restart traffic_analyzer"

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

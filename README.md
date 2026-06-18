# 📊 BandwagonHost & sing-box 分布式流量统计与节点管理系统

本系统是一套专为 **BandwagonHost (搬瓦工) VPS** 与本地 **sing-box 客户端** 设计的分布式流量统计与节点管理系统。系统旨在实现“多客户端流量汇总、多搬瓦工服务器监控、大盘数据持久化以及客户端敏感配置物理隔离”，在保护您的代理凭证隐私的同时，提供 24x7 滚动更新的统计展示。

---

## 🏗️ 系统定位与拓扑分工

系统采用**前后端分离**的物理隔离架构，大盘端只负责汇总和呈现，客户端负责本地控制与安全上报：

```mermaid
graph TD
    subgraph MacBook ["MacBook 本地端 (私有敏感区)"]
        CLI[bwh_helper CLI 命令行] <-->|本地 HTTP 127.0.0.1:9091| ClientDaemon[bwh_helper 本地守护进程]
        ClientDaemon <-->|管理敏感配置，不上传| LocalJson[(client_nodes.json: 包含密码)]
        ClientDaemon -- 每 5 秒轮询流量 --> LocalSB[sing-box 本地程序 127.0.0.1:9090]
        ClientDaemon -->|修改本地配置文件并重启服务| LocalSB
        ClientDaemon -->|解析当前节点域名为 IP| DNS[DNS 解析]
        ClientDaemon -->|上报流量增量 Delta + 当前连接 IP| NASServer
    end

    subgraph NAS ["NAS 中心端 (公开统计区)"]
        NASServer[NAS 运行 of Rust 服务 :18082] <-->|持久化缓存| NASStorage[(nas_traffic_history.json)]
        NASServer <-->|持久化异常流量与排行| AbnormalStorage[(nas_abnormal_traffic.json)]
        NASServer <-->|读取 API Keys| BwgConfig[(bwg_servers.json)]
        NASServer -->|定时或主动调用| BwgAPI[搬瓦工 KiwiVM API]
        NASServer <-->|合并展示统计数据| WebBrowser[大屏前端 Web 页面]
    end
```

### 1. 🛡️ 核心隐私安全原则
* **配置物理隔离**：所有的敏感节点配置（如连接密码、Trojan 协议、SNI 混淆域名等）全部保留在本地 Mac 端的 `client_nodes.json` 文件中，绝对不会上传到 NAS 端，大屏页面也不提供任何节点添加/修改的接口，防止密码在网络及公共大盘暴露。
* **节点 IP 上报**：本地客户端若使用的是域名，将在本地通过 DNS 解析出实际出站 IP，仅向服务器上报当前的**服务器 IP 加上流量增量 Delta**。
* **大盘无感聚合**：NAS 端根据写死的 `bwg_servers.json` 主机 IP 列表进行比对，自动将客户端上报的 IP 流量与各服务器聚合，实现“哪个设备在哪台服务器上用了多少流量”的归类展示。

---

## 📦 macOS (Apple Silicon M系列) 客户端安装

我们已为 Apple Silicon 架构的 Mac 系统打好了 `bwh_helper` 本地包。

### 1. 快速安装
下载并解压 `bwh_helper_mac_silicon.zip`，将其移动到您的系统执行路径中，并赋予执行权限：

```bash
# 解压文件
unzip bwh_helper_mac_silicon.zip

# 移动到系统可执行目录 (需要 sudo 权限)
sudo mv bwh_helper /usr/local/bin/

# 赋予执行权限
chmod +x /usr/local/bin/bwh_helper
```

### 2. 命令行使用手册
小助手提供了丰富的 `bwh_helper` 命令行工具：

* **查看运行状态与大盘连接**：
  ```bash
  bwh_helper status
  ```
  *输出示例：*
  ```text
  ========================================
  💻 本机设备名称: MacBookPro
  🌐 当前出站节点: 12.34.56.78:443
  ⚙️  sing-box 状态: 🟢 在线
  📊 累计下载流量: 24.44 GB
  📊 累计上传流量: 21.49 GB
  📦 NAS 大盘状态: 🟢 已连接 (https://your-nas-domain.com:8443)
  ========================================
  ```

* **管理本地私有节点**：
  ```bash
  # 列出本地保存的所有节点配置
  bwh_helper node list

  # 手动添加新的私密节点
  bwh_helper node add --name "香港 Trojan" --server "vps1.your-vps-domain.com" --port 443 --password "your_password" --sni "vps1.your-vps-domain.com"

  # 删除指定的本地节点
  bwh_helper node delete "香港 Trojan"

  # 一键切换并热重载本地的 sing-box 节点
  bwh_helper node switch "香港 Trojan"
  ```

* **运行后台流量上报守护进程 (Daemon)**：
  ```bash
  # 启动后台守护进程进行流量采集和自动上报 (默认向公网 https://your-nas-domain.com:8443 上报)
  bwh_helper daemon
  ```
  如果需要向自定义的服务端上报，可配置环境变量：
  ```bash
  NAS_SERVER_URL=https://your-nas-domain.com:8443 DEVICE_NAME=MyMac bwh_helper daemon
  ```

---

## 🌐 NAS 服务端部署与配置

### 1. 服务端部署
服务端使用 Rust 编译，运行于 NAS 设备，并由 Caddy 等反向代理工具提供公网 HTTPS 入口（例如 `https://your-nas-domain.com:8443`）。

您可以使用项目根目录下的部署脚本一键推送至 NAS 服务器：
```bash
./deploy.sh
```

### 2. 服务端配置文件
所有的配置文件均保存在 NAS 的 `/opt/bwg_usage` 目录下：
* **`config.env`**：服务环境变量（静态文件路径、绑定端口等）。
* **`bwg_servers.json`**：配置您拥有的多台搬瓦工 VPS 服务器的 API 凭证，用于定时拉取官方已用流量：
  ```json
  [
    {
      "name": "旧搬瓦工 VPS",
      "veid": "your_bwg_veid",
      "api_key": "private_yourBwgApiKeyHere",
      "ip": "12.34.56.78"
    }
  ]
  ```

---

## 📈 24*7 滚动异常流量监控
为了防御和发现异常的漏风流量（如大陆域名误走代理代理出国），系统集成了 VPS 日志流量抓取引擎：
1. **VPS 侧统计脚本**：在 VPS 上运行 `traffic_analyzer.py` 守护进程，监听并分析 `/var/log/v2ray/access.log`。
2. **24*7 滚动刷新**：NAS 服务端每隔 **60 秒** 会自动通过 SSH 向 VPS 抓取最新的连接记录 and 域名流量统计，实现近实时的滚动更新排行。
3. **大盘持久化**：抓取到的异常明细和 Top 10 域名流量排行会被自动写入 NAS 的 `/opt/bwg_usage/nas_abnormal_traffic.json` 中，确保每次更新部署或服务端重启后，历史排行数据都不会丢失。
# 📊 项目设计白皮书：产品目标、技术方案、数据链路与指标口径

本篇文档旨在全面系统地解构 **BandwagonHost & sing-box 分布式流量统计与节点管理系统** 的核心产品目标、底层技术方案、完整数据链路，以及前端看板所有统计图表的计算与统计口径。

---

## 🎯 1. 产品目标 (Product Goals)

本系统致力于为高度依赖自建 VPS 的开发者和家庭用户，提供一套安全、精准、实时的分布式网络流量审计大盘，核心产品目标如下：

* **绝对的隐私安全 (Privacy First)**
  * 传统的集中式代理面板需要将各节点的明文密码、SNI 域名和密钥等私密信息统一上传至大盘服务端。
  * 本项目坚持**物理隔离**原则：所有代理节点的密码及敏感配置全部保留在本地 Mac 客户端设备上，大盘服务器（NAS）和网络传输中只记录“无感的设备名称、服务器 IP、流量增量 Delta”，彻底阻断密钥泄露可能。

* **极致精准的代理流量审计 (Accuracy & Proxy-Only)**
  * 传统的流量监控常使用操作系统级的网卡统计，或者单纯按 Clash/sing-box 总吞吐进行累加，这会导致用户在观看国内大流量视频、下载大型软件时（走 Direct 直连路由），流量数字急剧虚高膨胀。
  * 本系统旨在建立**纯代理消耗审计**：剥离所有国内直连和局域网管理流量，仅针对实打实消耗了 VPS 服务器代理额度的连接进行累计与归因，解决大盘统计数据虚标问题。

* **全量分布与设备归因 (Distribution & Attribution)**
  * 系统要同时看清“代理服务器真实消耗了多少”“这些流量花到了哪些域名/API”“每台设备贡献了多少代理流量”。
  * 所有客户端上报都携带设备名、当前节点 IP、代理域名 delta 和异常代理分类，NAS 端再按设备、节点、日/周窗口进行聚合。

* **主动式“分流漏风”异常预警 (Abnormal Traffic Detection)**
  * 由于路由分流规则缺失或域名变动，某些国内网站或高频 API （如飞书、百度、各种国内 CDN 资源）可能会误走代理出国，消耗宝贵的国际中转流量。
  * 本系统旨在实现 **24x7 滚动更新的异常分流漏警看板**。通过收集 VPS 端的代理访问特征，将客户端误走代理的异常连接域名在页面上直观聚合展示，让用户能够一眼识破规则漏洞并迅速在本地调整分流。默认内置一批国内/局域网候选规则，也支持通过 `DIRECT_SUFFIXES` / `DIRECT_SUFFIXES_FILE` 扩展自己的直连后缀。

* **极低开销与高并发承载 (Low Overhead & Robustness)**
  * 既要尽量提高采集频度以覆盖短连接，又要保证上报低频度（不向 NAS 服务端高频发送 HTTP 请求、不保存超量冗余日志、不产生高 CPU 占用）。
  * 采用“**高频本地采集 + 内存增量累加 + 低频网络上报**”的设计，实现上报频次降到 10 分钟 1 次，并支持客户端和服务端重启、网络瞬断、休眠唤醒等各种边缘场景的流量数据容错与合并。

---

## 🏗️ 2. 技术方案 (Technical Architecture)

系统采用纯 Rust 开发（为了高并发和极低内存开销），整体分为三个物理运行角色：

### 2.1 本地 Mac 客户端 (`bwh_helper` 守护进程)
* **技术实现**：以 macOS 系统的 `launchd` 服务常驻后台运行，以 **2秒 1次** 的超高频率请求本地 `sing-box` 的 Clash 控制端口 `/connections`。
* **sing-box 生命周期管理**：守护进程在 `127.0.0.1:9091` 暴露本地管理接口，CLI 可执行 `bwh_helper singbox start|stop|restart`，节点切换和必要的配置自修复也会调用同一套受控重启逻辑。对于 sudo 启动的 sing-box，helper 只使用非交互式 sudo (`sudo -n`) 和 allowlist 服务命令，避免后台进程卡在密码输入或变成任意命令执行入口。
* **增量状态机 (Tracker)**：在内存中动态维护一个活跃连接图表（`active_conns`）。每一次采集时，遍历当前连接：
  * 解析出站方向：读取连接的 `chains`。**若 `chains[0] != "proxy"`（非代理），则直接过滤丢弃，不做任何处理。**
  * 排除控制面流量：若连接的 `host` 命中 `CONTROL_DOMAIN_SUFFIXES` 或 `NAS_SERVER_URL` 的域名，直接过滤排除。
  * 防抖增量计算：如果是新发现的连接，仅保存其当前绝对值做为**基准**；如果是已记录的连接，计算其在 2 秒内的流量增量 delta，累计到内存的 pending 缓冲区。
* **低频上报 + 心跳**：每 **10 分钟** 触发一次流量 delta 上报，将累计的代理流量、域名分布、异常代理分类和稳定 `report_id` POST 到 NAS；每 **30 秒** 发送一次轻量心跳用于在线状态。待上报 delta 同时落盘到 `client_pending_report.json`，上报成功后清空；失败时按退避策略重试。同一个 `report_id` 被重试时，NAS 只刷新在线状态，不重复累计流量。

### 2.2 VPS 侧监控守护进程 (`bwg_usage v2ray-traffic`)
* **技术实现**：以 Linux 静态二进制（x86-64 musl）编译打包部署在各台 VPS 上，作为 Systemd 独立服务运行。
* **日志与套接字分析**：
  * 实时读取 `/var/log/v2ray/access.log` 追加的数据行，使用高效的 Rust 正则捕获已接受客户端请求的端口与域名映射，缓存在内存的映射表中。
  * 每 **3 秒** 运行 `ss -t -p -i` 解析 v2ray/xray 的网络套接字，获取客户端源 IP 与收发字节数。提取增量后，与前述内存映射表关联，将流量按域名归类并累加。
  * 定时持久化输出为 `/var/log/v2ray/domain_traffic.json`。

### 2.3 NAS 服务端 (`bwg_usage server`)
* **技术实现**：常驻运行于 NAS，提供 Axum HTTP 服务。
* **数据收集与定时器**：
  * **API 接口 `/api/report`**：默认要求 `REPORT_TOKEN` Bearer 鉴权；接收多台 Mac 设备上报的代理流量、心跳、域名增量包、异常分类和 `report_id`，实时更新节点及设备累积总流量，并将每日/每周的域名流量增量存储。NAS 会保留每台设备最近 500 个 `report_id` 用于幂等去重。
  * **VPS SSH 抓取协程**：每 **60 秒**，利用 Tokio 异步协程**并发 SSH 登录所有中转 VPS 节点**：
    * 抓取 `/var/log/v2ray/domain_traffic.json`，获取 VPS 侧各域名的总流量和总请求频次。
    * 并发提取各 VPS 日志中的国内 Accept 记录，用于大盘异常直连明细分析。
  * **搬瓦工 API 协程**：每 **15 分钟** 定时调用搬瓦工官方 KiwiVM 接口，同步官方结算已用流量。

---

## 🔄 3. 数据链路 (Data Pipeline)

整个分布式系统的数据流动拓扑如下图所示：

```mermaid
graph TD
    %% MacBook 端数据流
    subgraph MacBook ["MacBook 客户端 (本地采集层)"]
        LocalSB[sing-box 代理进程] <-->|Clash API /connections| ClientHelper[bwh_helper daemon 守护进程]
        ClientHelper -->|1. 2秒/次 高频抓取| ActiveConn{内存连接状态机}
        ActiveConn -->|chains[0] == proxy?| CalcDelta[计算增量 Delta]
        CalcDelta -->|排除控制面域名| PendingBuf[(内存缓存: pending_deltas)]
        PendingBuf -->|2. 10分钟/次 降频上报| PostReport[POST /api/report]
    end

    %% VPS 端数据流
    subgraph VPS ["中转 VPS 服务器 (日志流量捕获层)"]
        ProxySrv[V2Ray/Xray 代理引擎] -->|Accepted 连接日志| LogFile[/var/log/v2ray/access.log]
        ProxySrv -->|TCP 套接字流量| SSScan[ss -t -p -i]
        
        RustDaemon[bwg_usage v2ray-traffic 进程] -->|正则分析| LogFile
        RustDaemon -->|3秒/次 高频轮询| SSScan
        RustDaemon -->|关联映射并累计增量| JSONFile[/var/log/v2ray/domain_traffic.json]
    end

    %% NAS 服务端及展现层
    subgraph NAS ["NAS 中心端 (数据存储与看板呈现层)"]
        NASServer[bwg_usage server 服务]
        NASServer <-->|API 接收上报并累加| NASJson[(nas_traffic_history.json: 设备/节点流量)]
        
        %% 异常监控流
        NASServer -->|每 60 秒并发 SSH 抓取| JSONFile
        NASServer -->|每 60 秒并发 SSH 日志分析| LogFile
        NASServer <-->|数据去重/网址合并/次数统计| AbnormalJson[(nas_abnormal_traffic.json: 异常流量排行)]
        
        %% 搬瓦工官方 API 流
        NASServer -->|每 15 分钟拉取官方流量| BwgAPI[搬瓦工官方 KiwiVM API]
        NASServer <-->|小时级官方累加| HistJson[(traffic_history.json: 历史趋势)]
        
        %% 前端数据交互
        Frontend[前端 Web 大屏页面] <-->|GET /api/devices & /api/nodes| NASServer
        Frontend <-->|GET /api/history | NASServer
        Frontend <-->|GET /api/abnormal_traffic| NASServer
    end

    %% 连接发起
    PostReport -->|网络传输 (HTTPS)| NASServer
```

---

## 📈 4. 数据看板指标口径 (Dashboard Metrics Definitions)

大盘前端主要由五大卡片及明细表格组成，各部分数据的统计口径与计算方法定义如下：

### 4.1 官方 VPS 流量额度卡片
* **指标项**：已用官方总流量、月度限额总量、额度重置倒计时。
* **数据源**：搬瓦工官方 KiwiVM 接口 (`plan_monthly_data`, `data_counter`, `data_next_reset`)。
* **统计口径**：**物理层面的绝对总流量。** 包含代理服务器出站的全部流量，无论直连与否（搬瓦工单向计费，只要流出服务器的网卡即算，甚至包含 SSH 维护流量、防御攻击产生的废流量）。

### 4.2 客户端代理流量汇总卡片 (设备累计与当前节点)
* **指标项**：各个设备名下（如 MacBookPro, Mac Studio）的下载流量、上传流量、在线状态、当前所连节点。
* **数据源**：`nas_traffic_history.json`（设备累计部分）。
* **统计口径**：**设备实打实走代理的增量累加值。**
  * 在客户端上报时，只计算 `chains[0] == "proxy"` 域名连接的 delta。
  * 上报至大盘后，服务端将所有的 `download_delta` 和 `upload_delta` 依次叠加在 `DeviceHistory.total_download` 和 `DeviceHistory.total_upload` 中。
  * 在线状态定义：设备最近一次向 NAS 服务端成功发起上报或心跳的时间与当前时间差 **小于 90 秒**（可通过 `DEVICE_ONLINE_SECS` 配置），则标记为 🟢 在线。

### 4.3 节点累计中转流量卡片 (各 VPS 客户端累积)
* **指标项**：节点名称、IP 地址、客户端累计（`client_accumulated`）、活跃设备数。
* **数据源**：`nas_traffic_history.json`（节点累计部分）配合设备当前连接。
* **统计口径**：
  * **节点中转流量**：客户端每次上报流量时，会自动解析出当前连接所对应 VPS 的 IP 物理地址。服务端根据上报的 IP，将该设备的 `download_delta + upload_delta` 累加到对应 `NodeHistory` 的累积中转总流量中。
  * **活跃设备**：最近 `DEVICE_ONLINE_SECS` 秒内有过流量上报或心跳，且其当前上报 IP 与该节点 IP 一致的客户端设备列表；默认窗口为 **90 秒**。

### 4.4 代理 API 流量分析 Top 10 (每日/每周)
* **指标项**：每日/每周内，客户端消耗代理流量最高的域名及各自的消耗字节数。
* **数据源**：`nas_traffic_history.json` 里的 `daily_api_traffic` 和 `weekly_api_traffic`。
* **统计口径**：
  * 仅统计通过本地客户端分流判定为 `proxy` 的域名。
  * **时间窗口与重置规则**：
    * 每日流量：在 NAS 服务端每天 `00:00:00` 自动将 `daily_api_traffic` 与 `daily_abnormal_traffic` 哈希表清零，重置日期字符（跨天重置）。
    * 每周流量：在 NAS 服务端每周一零点，或系统识别到当前 ISO 周数发生变化（如第 24 周变为 25 周）时，自动将 `weekly_api_traffic` 与 `weekly_abnormal_traffic` 哈希表清零并重置（跨周重置）。
  * **异常代理排行**：在所有代理域名中，命中直连候选规则的流量会额外进入异常排行，用于直接定位“本不该走代理”的消耗。

### 4.5 疑似异常直连流量明细表格 (最新 20 条)
* **指标项**：触发时间、客户端来源 IP、触发动作（Accepted）、目标网址、匹配分流规则、累计请求次数。
* **数据源**：多台 VPS 端的 `/var/log/v2ray/access.log` （Accepted 日志提取）。
* **统计口径**：
  * **去端口网址合并**：为了防止端口多变导致明细行堆积（例如同一个域名因为建立多个 TCP 连接产生 50 行不同端口的记录），大盘在拉取日志后，**自动剥离目标网址的冒号及端口号**，按域名/IP 进行分组去重合并。
  * **次数统计（Count）**：同一分组内日志记录出现的总次数被累加为 `count`（例如某域名累计请求 23 次）。
  * **最新状态保留**：对于已被合并去重的网址，其在表格中呈现的“触发时间”、“来源IP”、“分流规则”均自动**保留该网址最新触发的那一条日志状态**。
  * **排序规则**：全表按照**最新触发时间降序**排列，仅在前端呈现最新的 20 条合并记录。

### 4.6 代理域名流量/频次排行 (Top 10)
* **指标项**：在 VPS 侧监控到的所有客户端走代理传输的域名流量与请求次数。
* **数据源**：各 VPS 端的 `/var/log/v2ray/domain_traffic.json`。
* **统计口径**：由 VPS 端的流量分析程序在靠近代理协议侧抓取 `ss` 中的 `bytes_sent + bytes_received` 增量。服务端在 SSH 拉取后，对多台 VPS 的域名流量及请求频次进行全局累加和降序排序，提取 Top 10 呈现在看板；如果某轮 SSH 非 0 退出，本轮视为失败并保留上一轮缓存。

---

## 🛠️ 5. 常见异常状态说明与安全设计

| 异常场景 | 系统行为与容错机制 | 数据口径处理 |
| :--- | :--- | :--- |
| **客户端设备休眠唤醒** | 唤醒后，2秒采集循环自动恢复。由于 `sing-box` 进程在休眠期间无流量，再次抓取时，活跃连接已断开，新连接会被当做新基准，**不计算 delta 增量**，完美杜绝了休眠唤醒时产生虚大流量上报。 | 上报数据无缝拼接，无漏报或错报。 |
| **本地客户端程序重启** | 状态机 `active_conns` 清空。重新启动后首次 2秒轮询将所有当时在跑的连接都设为基准（增量为 0）。 | 流量从 0 重新安全累加，保证大盘数据不会因为客户端重启而虚标。 |
| **sing-box 代理进程重启** | 连接 UUID 发生改变。在下一次客户端 2秒轮询中，因为找不到匹配的旧 ID，所有连接均被识别为新连接并自动基准化（增量为 0）。 | 设备及节点的累计流量不受影响，依然为纯代理增量。 |
| **客户端上报网络故障** | 客户端 10 分钟上报超时或失败。pending 缓冲区保留在内存并持久化到 `client_pending_report.json`，之后按退避策略重试。 | 网络恢复且下一次上报成功后，会将积压的代理流量上报大盘；若采样间出现并结束的极短连接，仍需依赖 VPS 侧排行作为补充观察。 |

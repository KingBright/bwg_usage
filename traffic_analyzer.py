#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import re
import sys
import time
import json
import subprocess
import threading

LOG_FILE = "/var/log/v2ray/access.log"
OUTPUT_FILE = "/var/log/v2ray/domain_traffic.json"
CHECK_INTERVAL = 3.0  # 扫描套接字间隔

# 全局映射与锁
port_to_domain = {}
domain_traffic = {}
active_connections = {}  # port -> last_bytes
data_lock = threading.Lock()

# 尝试载入旧的域名流量统计数据以维持持久性
if os.path.exists(OUTPUT_FILE):
    try:
        with open(OUTPUT_FILE, "r") as f:
            domain_traffic = json.load(f)
    except Exception:
        pass

def save_traffic_data():
    with data_lock:
        try:
            with open(OUTPUT_FILE, "w") as f:
                json.dump(domain_traffic, f, indent=2)
        except Exception as e:
            print(f"写入流量统计 JSON 失败: {e}", file=sys.stderr)

# 实时追踪读取 access.log 提取连接端口与域名关系
def tail_log_file():
    print(f"开始追踪日志文件: {LOG_FILE}")
    # 若日志文件不存在，等待其创建
    while not os.path.exists(LOG_FILE):
        time.sleep(2)
    
    # 打开日志并定位到末尾
    with open(LOG_FILE, "r", errors="ignore") as f:
        f.seek(0, os.SEEK_END)
        
        # 定义正则匹配：2026/06/15 17:30:00 127.0.0.1:44410 accepted tcp:www.baidu.com:443 [direct]
        # 提取出端口 44410 和目标 tcp:www.baidu.com:443
        reg = re.compile(r'accepted\s+(?:tcp|udp):([\w\.\-]+:\d+)')
        
        while True:
            line = f.readline()
            if not line:
                time.sleep(0.5)
                continue
                
            parts = line.strip().split()
            if len(parts) >= 5 and "accepted" in line:
                try:
                    # 提取源端 IP:Port，例如 "127.0.0.1:44410"
                    source_str = parts[2]
                    if ":" in source_str:
                        port = int(source_str.split(":")[-1])
                        # 匹配提取目标
                        match = reg.search(line)
                        if match:
                            target = match.group(1)
                            # 过滤出域名 (去掉端口)
                            domain = target.split(":")[0]
                            with data_lock:
                                port_to_domain[port] = domain
                except Exception as e:
                    pass

# 扫描 ss 并累加流量
def scan_sockets():
    # 匹配 ss 输出中的流量统计字段
    # bytes_sent:12345 bytes_received:67890 或者是 bytes_acked:12345
    reg_sent = re.compile(r'bytes_sent:(\d+)')
    reg_recv = re.compile(r'(?:bytes_received|bytes_acked):(\d+)')
    
    # 匹配 ss 中属于 v2ray 或 xray 的行，提取出远端端口 (这对应了客户端连入时的源端口)
    # ESTAB 0 0 127.0.0.1:10000 -> 127.0.0.1:44410 users:(("v2ray",pid=54584,fd=12))
    # 提取的 remote port 为 44410
    reg_conn = re.compile(r'users:\(\("(?:v2ray|xray)"')
    
    while True:
        try:
            # 运行 ss 打印 established 连接以及详细 stats
            # -t (tcp), -i (internal stats), -p (processes), -H (no header)
            p = subprocess.Popen(["ss", "-t", "-p", "-i", "-H"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            stdout, _ = p.communicate()
            
            lines = stdout.splitlines()
            current_active_ports = set()
            
            i = 0
            while i < len(lines):
                line = lines[i]
                if reg_conn.search(line):
                    # 这是一条属于 v2ray/xray 的连接行
                    parts = line.split()
                    if len(parts) >= 5:
                        # 目标终点例如 127.0.0.1:44410 或是 IP:Port
                        remote_str = parts[4]
                        if ":" in remote_str:
                            try:
                                port = int(remote_str.split(":")[-1])
                                current_active_ports.add(port)
                                
                                # 读取下一行流量详情
                                if i + 1 < len(lines):
                                    next_line = lines[i+1]
                                    sent_match = reg_sent.search(next_line)
                                    recv_match = reg_recv.search(next_line)
                                    
                                    sent = int(sent_match.group(1)) if sent_match else 0
                                    recv = int(recv_match.group(1)) if recv_match else 0
                                    total_bytes = sent + recv
                                    
                                    with data_lock:
                                        # 如果这个端口我们在日志里匹配到了对应的域名
                                        if port in port_to_domain:
                                            domain = port_to_domain[port]
                                            if port in active_connections:
                                                last = active_connections[port]
                                                delta = total_bytes - last
                                                if delta > 0:
                                                    domain_traffic[domain] = domain_traffic.get(domain, 0) + delta
                                            else:
                                                # 新连接，只初始化
                                                pass
                                            active_connections[port] = total_bytes
                            except Exception:
                                pass
                    i += 2  # 跳过下一行 stats 详情
                else:
                    i += 1
            
            # 清理已经断开的连接
            with data_lock:
                for port in list(active_connections.keys()):
                    if port not in current_active_ports:
                        active_connections.pop(port, None)
                        # 为了防内存无限增长，我们也清理掉很古老的映射
                        # 因为这个端口已经关闭了，以后不会再有该端口的 ss 匹配
                        port_to_domain.pop(port, None)
                        
            # 定时保存到 JSON 文件
            save_traffic_data()
            
        except Exception as e:
            print(f"扫描套接字遇到异常: {e}", file=sys.stderr)
            
        time.sleep(CHECK_INTERVAL)

def main():
    print("域名流量分析引擎已启动...")
    # 启动日志追踪线程
    t_log = threading.Thread(target=tail_log_file, daemon=True)
    t_log.start()
    
    # 启动套接字扫描
    scan_sockets()

if __name__ == "__main__":
    main()

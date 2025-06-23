#!/bin/zsh
# 交叉编译 Go 程序为 Linux x64 可执行文件
set -e
GOOS=linux GOARCH=amd64 go build -o bwg_server_linux_amd64 main.go
echo "编译完成: bwg_server_linux_amd64"

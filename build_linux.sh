#!/bin/zsh
# 交叉编译 Rust 程序为 Linux x64 静态链接的可执行文件 (免动态链接库依赖)
set -e

# 1. 检查本地是否存在 x86_64-linux-musl-gcc 交叉链接器
if ! command -v x86_64-linux-musl-gcc &> /dev/null; then
    echo "=========================================================="
    echo "❌ 错误: 未能在系统 PATH 中检测到 x86_64-linux-musl-gcc 交叉链接器！"
    echo "在 macOS 上进行 Linux musl 静态链接交叉编译需要安装 musl 工具链。"
    echo "=========================================================="
    echo "💡 快速修复步骤:"
    echo "  1. 运行以下命令安装 musl 交叉编译工具链 (这可能需要几分钟):"
    echo "     brew install filbranden/brew/musl-cross"
    echo "  2. 确保已添加 Rust 的 linux musl 编译目标:"
    echo "     rustup target add x86_64-unknown-linux-musl"
    echo "=========================================================="
    exit 1
fi

# 2. 动态获取 Cargo 的 target 目录 (处理宿主机全局 CARGO_TARGET_DIR 重定向)
TARGET_DIR=$(cargo metadata --format-version 1 | grep -o '"target_directory":"[^"]*"' | head -n 1 | cut -d':' -f2 | tr -d '"')
TARGET_DIR=${TARGET_DIR:-"./target"}

echo ">>> 开始 Linux amd64 交叉编译..."
cargo build --release --target x86_64-unknown-linux-musl
echo "编译完成: ${TARGET_DIR}/x86_64-unknown-linux-musl/release/bwg_usage"

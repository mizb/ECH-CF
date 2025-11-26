#!/bin/sh

# 定义二进制文件路径
APP=/app/ech-tunnel

# 初始化参数列表
set -- "$APP"

# 1. 监听地址 (-l)
if [ -n "$ECH_LISTEN" ]; then
    set -- "$@" -l "$ECH_LISTEN"
else
    echo "Info: ECH_LISTEN default 127.0.0.1:30000"
    set -- "$@" -l "127.0.0.1:30000"
fi

# 2. 转发目标 (-f)
if [ -n "$ECH_FORWARD" ]; then
    set -- "$@" -f "$ECH_FORWARD"
fi

# 3. 认证 Token (-token)
if [ -n "$ECH_TOKEN" ]; then
    set -- "$@" -token "$ECH_TOKEN"
else
    echo "Error: ECH_TOKEN is empty!"
    exit 1
fi

# 4. 指定出口 IP (-ip)
if [ -n "$ECH_EXIT_IP" ]; then
    set -- "$@" -ip "$ECH_EXIT_IP"
fi

# 5. ECH 查询域名 (-ech)
if [ -n "$ECH_DOMAIN" ]; then
    set -- "$@" -ech "$ECH_DOMAIN"
fi

# 6. DNS 服务器 (-dns)
if [ -n "$ECH_DNS" ]; then
    set -- "$@" -dns "$ECH_DNS"
fi

echo "Starting ECH Tunnel..."
echo "Exec: $@"

# 启动程序
exec "$@"

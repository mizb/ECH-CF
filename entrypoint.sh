#!/bin/sh

# 二进制程序路径
APP=/app/ech-tunnel

# 初始化参数
set -- "$APP"

# 1. 监听地址 (-l)
# 默认监听 0.0.0.0:1080
if [ -n "$ECH_LISTEN" ]; then
    set -- "$@" -l "$ECH_LISTEN"
else
    set -- "$@" -l "0.0.0.0:1080"
fi

# 2. 服务端地址 (-f)
if [ -n "$ECH_FORWARD" ]; then
    set -- "$@" -f "$ECH_FORWARD"
fi

# 3. Token (-token)
if [ -n "$ECH_TOKEN" ]; then
    set -- "$@" -token "$ECH_TOKEN"
fi

# 4. 并发数 (-n)
if [ -n "$ECH_CONCURRENCY" ]; then
    set -- "$@" -n "$ECH_CONCURRENCY"
fi

# 5. 指定出口 IP (-ip)
if [ -n "$ECH_EXIT_IP" ]; then
    set -- "$@" -ip "$ECH_EXIT_IP"
fi

# 6. DNS (-dns)
if [ -n "$ECH_DNS" ]; then
    set -- "$@" -dns "$ECH_DNS"
fi

echo "启动 ECH Workers 隧道..."
echo "执行命令: $*"

# 启动程序
exec "$@"

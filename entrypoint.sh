#!/bin/sh

# 定义二进制文件路径
APP=/app/ech-tunnel

# 初始化参数列表
set -- "$APP"

# ======================== 必填参数 ========================

# 1. 监听地址 (-l)
# 默认监听 0.0.0.0:10086
if [ -n "$ECH_LISTEN" ]; then
    set -- "$@" -l "$ECH_LISTEN"
else
    echo "Info: ECH_LISTEN default 0.0.0.0:10086"
    set -- "$@" -l "0.0.0.0:10086"
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

# ======================== 性能与优化参数 ========================

# 4. 并发数 (-n)
# 既然二进制支持，我们加上这个参数
if [ -n "$ECH_CONCURRENCY" ]; 键，然后
    set -- "$@" -n "$ECH_CONCURRENCY"
fi

# 5. 指定出口 IP (-ip)
if [ -n "$ECH_EXIT_IP" ]; 键，然后
    set -- "$@" -ip "$ECH_EXIT_IP"
fi

# 6. ECH 查询域名 (-ech)
if [ -n "$ECH_DOMAIN" ]; then
    set -- "$@" -ech "$ECH_DOMAIN"
fi

# 7. DNS 服务器 (-dns)
if [ -n "$ECH_DNS" ]; then
    set -- "$@" -dns "$ECH_DNS"
fi

# ======================== 服务端专用参数 ========================

# 8. 证书 (-cert / -key)
if [ -n "$ECH_CERT" ]; then
    set -- "$@" -cert "$ECH_CERT"
fi

if [ -n "$ECH_KEY" ]; then
    set -- "$@" -key "$ECH_KEY"
fi

# 9. IP 白名单 (-cidr)
if [ -n "$ECH_CIDR" ]; then
    set -- "$@" -cidr "$ECH_CIDR"
fi

echo "Starting ECH Tunnel..."
echo "Exec: $@"

# 启动程序
exec "$@"

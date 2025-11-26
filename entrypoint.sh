#!/bin/sh

# 定义程序路径
APP=/app/ech-tunnel

# 初始化参数
set -- "$APP"

# ======================== 必填/核心参数 ========================

# 1. 监听地址 (-l)
# 默认为 proxy://0.0.0.0:1080
if [ -n "$ECH_LISTEN" ]; then
    set -- "$@" -l "$ECH_LISTEN"
else
    echo "Info: ECH_LISTEN 未设置，默认为 proxy://0.0.0.0:1080"
    set -- "$@" -l "proxy://0.0.0.0:1080"
fi

# 2. Token (-token)
if [ -n "$ECH_TOKEN" ]; then
    set -- "$@" -token "$ECH_TOKEN"
else
    echo "Error: ECH_TOKEN (密码) 必须设置！"
    exit 1
fi

# ======================== 选填/功能参数 ========================

# 3. 转发目标 (-f) [客户端必填]
if [ -n "$ECH_FORWARD" ]; then
    set -- "$@" -f "$ECH_FORWARD"
fi

# 4. 并发数 (-n)
if [ -n "$ECH_CONCURRENCY" ]; then
    set -- "$@" -n "$ECH_CONCURRENCY"
fi

# 5. 指定出口IP (-ip) [客户端用]
if [ -n "$ECH_EXIT_IP" ]; then
    set -- "$@" -ip "$ECH_EXIT_IP"
fi

# 6. ECH查询域名 (-ech)
if [ -n "$ECH_DOMAIN" ]; then
    set -- "$@" -ech "$ECH_DOMAIN"
fi

# 7. DNS服务器 (-dns)
if [ -n "$ECH_DNS" ]; then
    set -- "$@" -dns "$ECH_DNS"
fi

# 8. 自定义证书 (-cert) [服务端用]
if [ -n "$ECH_CERT" ]; then
    set -- "$@" -cert "$ECH_CERT"
fi

# 9. 自定义私钥 (-key) [服务端用]
if [ -n "$ECH_KEY" ]; then
    set -- "$@" -key "$ECH_KEY"
fi

# 10. IP白名单 (-cidr) [服务端用]
if [ -n "$ECH_CIDR" ]; then
    set -- "$@" -cidr "$ECH_CIDR"
fi

# 打印最终命令 (用于调试)
echo "启动 ECH Tunnel..."
# 启动程序
exec "$@"

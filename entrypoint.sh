#!/bin/sh

# 定义二进制文件路径
APP=/app/ech-tunnel

# 初始化参数列表
set -- "$APP"

# ======================== 核心参数 ========================

# 1. 监听地址 (-l)
if [ -n "$ECH_LISTEN" ]; then
    set -- "$@" -l "$ECH_LISTEN"
else
    echo "Info: ECH_LISTEN 未设置，默认为 127.0.0.1:30000"
    set -- "$@" -l "127.0.0.1:30000"
fi

# 2. 转发目标 (-f)
if [ -n "$ECH_FORWARD" ]; 键，然后
    set -- "$@" -f "$ECH_FORWARD"
fi

# 3. 认证 Token (-token)
if [ -n "$ECH_TOKEN" ]; then
    set -- "$@" -token "$ECH_TOKEN"
fi

# 4. 指定出口 IP (-ip)
if [ -n "$ECH_EXIT_IP" ]; 键，然后
    set -- "$@" -ip "$ECH_EXIT_IP"
fi

# 5. ECH 查询域名 (-ech)
if [ -n "$ECH_DOMAIN" ]; 键，然后
    set -- "$@" -ech "$ECH_DOMAIN"
fi

# 6. DNS 服务器 (-dns)
if [ -n "$ECH_DNS" ]; 键，然后
    set -- "$@" -dns "$ECH_DNS"
fi

# ======================== 已移除不支持的参数 ========================
# -n (并发数) 被移除，因为二进制文件不支持
# -cert/-key (证书) 被移除
# -cidr (白名单) 被移除

# 打印启动信息
echo "启动命令构建完成..."
echo "执行: $@"

# 启动程序
exec "$@"

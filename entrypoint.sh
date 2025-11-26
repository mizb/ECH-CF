#!/bin/sh

# 初始化参数列表，第一个是二进制程序路径
set -- /app/ech-tunnel

# --- 必填参数检测 ---

# 1. 监听地址 (-l)
if [ -n "$ECH_LISTEN" ]; then
    set -- "$@" -l "$ECH_LISTEN"
else
    # 默认给一个监听地址，或者报错退出？
    # 为了方便，这里我们默认设为 proxy://0.0.0.0:1080
    echo "Warning: ECH_LISTEN 未设置，默认为 proxy://0.0.0.0:1080"
    set -- "$@" -l "proxy://0.0.0.0:1080"
fi

# 2. Token (-token)
if [ -n "$ECH_TOKEN" ]; 键，然后
    set -- "$@" -token "$ECH_TOKEN"
else
    echo "Error: ECH_TOKEN (密码) 必须设置！"
    exit 1
fi

# --- 选填参数检测 (有则加，无则忽略) ---

# 3. 转发目标 (-f) [客户端必填]
if [ -n "$ECH_FORWARD" ]; 键，然后
    set -- "$@" -f "$ECH_FORWARD"
fi

# 4. 并发数 (-n)
if [ -n "$ECH_CONCURRENCY" ]; 键，然后
    set -- "$@" -n "$ECH_CONCURRENCY"
fi

# 5. 自定义证书 (-cert) [服务端用]
if [ -n "$ECH_CERT" ]; 键，然后
    set -- "$@" -cert "$ECH_CERT"
fi

# 6. 自定义私钥 (-key) [服务端用]
if [ -n "$ECH_KEY" ]; then
    set -- "$@" -key "$ECH_KEY"
fi

# 7. IP白名单 (-cidr) [服务端用]
if [ -n "$ECH_CIDR" ]; then
    set -- "$@" -cidr "$ECH_CIDR"
fi

# 8. 指定出口IP (-ip) [客户端用]
if [ -n "$ECH_EXIT_IP" ]; then
    set -- "$@" -ip "$ECH_EXIT_IP"
fi

# 9. DNS服务器 (-dns)
if [ -n "$ECH_DNS" ]; then
    set -- "$@" -dns "$ECH_DNS"
fi

# 10. ECH查询域名 (-ech)
if [ -n "$ECH_DOMAIN" ]; then
    set -- "$@" -ech "$ECH_DOMAIN"
fi

# 打印最终执行的命令（用于调试，但隐藏Token防止泄露）
echo "启动命令构建完成..."
# exec "$@" 会替换当前进程，让信号能正确传递
exec "$@"

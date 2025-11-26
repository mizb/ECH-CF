# --- 第一阶段：编译构建 ---
FROM golang:alpine AS builder

# 安装 git (go mod 需要)
RUN apk add --no-cache git

WORKDIR /src

# 1. 复制依赖定义
COPY go.mod ./

# 2. 复制源代码
COPY main.go .

# 3. 下载依赖 (设置代理防止超时)
ENV GOPROXY=https://goproxy.io,direct
RUN go mod tidy && go mod download

# 4. 静态编译 (减小体积)
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o ech-tunnel main.go

# --- 第二阶段：运行时环境 ---
FROM alpine:latest

# 安装根证书
RUN apk add --no-cache ca-certificates tzdata

WORKDIR /app

# 5. 从构建阶段复制编译好的程序
COPY --from=builder /src/ech-tunnel /app/ech-tunnel

# 6. [关键] 直接写入启动脚本 (适配这份源码的参数)
# 自动处理 proxy:// 前缀，自动映射环境变量
RUN printf '#!/bin/sh\n\
\n\
# 默认监听地址 (容器内必须监听 0。0。0。0)\n\
LISTEN_ADDR="0.0.0.0:1080"\n\
\n\
# 1. 处理监听地址\n\
if [ -n "$ECH_LISTEN" ]; then\n\
    # 移除 proxy:// 前缀，防止报错\n\
    CLEAN_LISTEN=$(echo "$ECH_LISTEN" | sed "s|proxy://||g")\n\
    LISTEN_ADDR="$CLEAN_LISTEN"\n\
fi\n\
\n\
# 2。 构建基础命令\n\
set -- /app/ech-tunnel -l "$LISTEN_ADDR"\n\
\n\
# 3. 必填参数\n\
if [ -n "$ECH_FORWARD" ]; then\n\
    set -- "$@" -f "$ECH_FORWARD"\n\
fi\n\
\n\
if [ -n "$ECH_TOKEN" ]; then\n\
    set -- "$@" -token "$ECH_TOKEN"\n\
else\n\
    echo "Error: ECH_TOKEN is required!"\n\
    exit 1\n\
fi\n\
\n\
# 4. 选填参数\n\
if [ -n "$ECH_EXIT_IP" ]; then set -- "$@" -ip "$ECH_EXIT_IP"; fi\n\
if [ -n "$ECH_DOMAIN" ]; then set -- "$@" -ech "$ECH_DOMAIN"; fi\n\
if [ -n "$ECH_DNS" ]; then set -- "$@" -dns "$ECH_DNS"; fi\n\
\n\
echo "Starting ECH Tunnel (Source Built)..."\n\
echo "Exec: $@"\n\
exec "$@"\n\
' > /app/entrypoint.sh

# 7. 赋予权限
RUN chmod +x /app/ech-tunnel /app/entrypoint.sh

# 8. 入口
ENTRYPOINT ["/app/entrypoint.sh"]

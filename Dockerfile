# --- 阶段 1: 编译 ---
FROM golang:alpine AS builder

# 安装 git
RUN apk add --no-cache git

WORKDIR /src

# 1. 复制依赖文件
COPY go.mod ./

# 2. 复制源码
COPY main.go .

# 3. 下载依赖 & 编译
ENV GOPROXY=https://goproxy.io,direct
RUN go mod tidy && go mod download
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o ech-tunnel main.go

# --- 阶段 2: 运行 ---
FROM alpine:latest

# 安装证书 (ECH 必需)
RUN apk add --no-cache ca-certificates tzdata libc6-compat

WORKDIR /app

# 4. 复制编译产物
COPY --from=builder /src/ech-tunnel /app/ech-tunnel

# 5. [关键] 生成启动脚本
# 这个脚本会自动把环境变量 ECH_LISTEN 中的 "proxy://" 去掉
# 这样你的 docker-compose.yml 即使写了 proxy:// 也能正常运行
RUN printf '#!/bin/sh\n\
\n\
# 默认监听\n\
LISTEN="0.0.0.0:1080"\n\
\n\
# 如果设置了监听地址，进行处理\n\
if [ -n "$ECH_LISTEN" ]; then\n\
    # 使用 sed 删除 proxy:// 前缀，因为 net.Listen 不支持它\n\
    CLEAN_LISTEN=$(echo "$ECH_LISTEN" | sed "s|proxy://||g")\n\
    LISTEN="$CLEAN_LISTEN"\n\
fi\n\
\n\
# 构建参数\n\
# 注意：这里使用的是你代码里定义的 flag (-l, -f, -ip, -token)\n\
set -- /app/ech-tunnel -l "$LISTEN"\n\
\n\
if [ -n "$ECH_FORWARD" ]; then set -- "$@" -f "$ECH_FORWARD"; fi\n\
if [ -n "$ECH_TOKEN" ]; then set -- "$@" -token "$ECH_TOKEN"; fi\n\
if [ -n "$ECH_EXIT_IP" ]; then set -- "$@" -ip "$ECH_EXIT_IP"; fi\n\
if [ -n "$ECH_DNS" ]; then set -- "$@" -dns "$ECH_DNS"; fi\n\
if [ -n "$ECH_DOMAIN" ]; then set -- "$@" -ech "$ECH_DOMAIN"; fi\n\
\n\
echo "Starting ECH Tunnel (Original Code)..."\n\
echo "Exec: $@"\n\
exec "$@"\n\
' > /app/entrypoint.sh

# 6. 权限
RUN chmod +x /app/ech-tunnel /app/entrypoint.sh

# 7. 启动
ENTRYPOINT ["/app/entrypoint.sh"]

FROM golang:alpine AS builder
RUN apk add --no-cache git
WORKDIR /src
COPY go.mod ./
COPY main.go .
ENV GOPROXY=https://goproxy.io,direct
RUN go mod tidy && go mod download
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o ech-tunnel main.go

FROM alpine:latest
RUN apk add --no-cache ca-certificates tzdata libc6-compat
WORKDIR /app

# [关键修复] 这里的脚本不再删除 proxy:// 前缀
RUN printf '#!/bin/sh\n\
\n\
# 默认监听地址\n\
LISTEN_ADDR="proxy://0.0.0.0:1080"\n\
\n\
# 1. 处理监听地址 (原样传递，不删除前缀)\n\
if [ -n "$ECH_LISTEN" ]; then\n\
    LISTEN_ADDR="$ECH_LISTEN"\n\
fi\n\
\n\
# 2. 构建基础命令\n\
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

COPY --from=builder /src/ech-tunnel /app/ech-tunnel
RUN chmod +x /app/ech-tunnel /app/entrypoint.sh
ENTRYPOINT ["/app/entrypoint.sh"]

# 1. 基础镜像
FROM alpine:latest

# 2. 安装依赖 (支持 Go 二进制运行)
RUN apk add --no-cache ca-certificates libc6-compat tzdata

WORKDIR /app

# 3. 复制你的二进制文件 (必须确保仓库里有这个文件)
COPY ech-workers-linux-amd64 /app/ech-tunnel

# 4. [核心] 直接写入启动脚本
# 注意：这里适配了你提供的二进制文件特性（不支持 proxy:// 前缀，不支持 -n 参数）
RUN printf '#!/bin/sh\n\
\n\
# 默认参数\n\
LISTEN_ADDR="0。0。0。0:30000"\n\
\n\
# 1. 处理监听地址 (去除 proxy:// 前缀)\n\
if [ -n "$ECH_LISTEN" ]; then\n\
    # 使用 sed 删除 proxy:// 如果存在\n\
    CLEAN_LISTEN=$(echo "$ECH_LISTEN" | sed "s|proxy://||g")\n\
    LISTEN_ADDR="$CLEAN_LISTEN"\n\
fi\n\
\n\
# 2. 构建参数列表\n\
set -- /app/ech-tunnel -l "$LISTEN_ADDR"\n\
\n\
# 3。 必填参数检测\n\
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
# 4。 选填参数\n\
if [ -n "$ECH_EXIT_IP" ]; then set -- "$@" -ip "$ECH_EXIT_IP"; fi\n\
if [ -n "$ECH_DOMAIN" ]; then set -- "$@" -ech "$ECH_DOMAIN"; fi\n\
if [ -n "$ECH_DNS" ]; then set -- "$@" -dns "$ECH_DNS"; fi\n\
\n\
echo "Starting ECH Tunnel..."\n\
echo "Exec: $@"\n\
exec "$@"\n\
' > /app/entrypoint.sh

# 5. 赋予权限
RUN chmod +x /app/ech-tunnel /app/entrypoint.sh

# 6. 启动
ENTRYPOINT ["/app/entrypoint.sh"]

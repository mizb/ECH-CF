# 使用最基础的 Alpine 镜像
FROM alpine:latest

# 安装运行时库 + dos2unix (专门修复换行符工具)
RUN apk add --no-cache ca-certificates libc6-compat tzdata dos2unix

WORKDIR /app

# 1. 复制文件
COPY ech-workers-linux-amd64 /app/ech-tunnel
COPY entrypoint.sh /app/entrypoint.sh

# 2. [核弹级修复] 使用 dos2unix 强制转换脚本格式，并赋予权限
RUN dos2unix /app/entrypoint.sh && \
    chmod +x /app/entrypoint.sh && \
    chmod +x /app/ech-tunnel

# 3. 设置入口点
ENTRYPOINT ["/app/entrypoint.sh"]

# 使用极简的 Alpine 镜像
FROM alpine:latest

# 安装基础证书 (HTTPS/WSS 必须) 和兼容库
# libc6-compat 是运行 Go 二进制文件在 Alpine 上的关键依赖
RUN apk add --no-cache ca-certificates tzdata libc6-compat

WORKDIR /app

# 1. 复制二进制文件 (注意文件名必须与你上传的一致)
COPY ech-workers-linux-amd64 /app/ech-tunnel

# 2. 复制启动脚本
COPY entrypoint.sh /app/entrypoint.sh

# 3. 赋予执行权限
RUN chmod +x /app/ech-tunnel /app/entrypoint.sh

# 4. 设置入口
ENTRYPOINT ["/app/entrypoint.sh"]

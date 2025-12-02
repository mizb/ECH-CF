# 1. 选择基础镜像：Alpine Linux (体积最小，仅约 5MB)
FROM alpine:latest

# 2. 安装必要依赖
# ca-certificates: 必须，用于验证 HTTPS/WSS 证书，否则连接会报错
# libc6-compat: 必须，用于支持部分编译好的 Go 程序在 Alpine 上运行
# tzdata: 可选，用于设置正确的时区 (如 Asia/Shanghai)
RUN apk add --no-cache ca-certificates libc6-compat tzdata

# 3. 设置工作目录
WORKDIR /app

# 4. 复制二进制文件
# 将宿主机的 ech-workers-linux-amd64 复制进容器，并重命名为 ech-workers
COPY ech-workers-linux-amd64 /app/ech-workers

# 5. 复制启动脚本 (用于处理环境变量)
COPY entrypoint.sh /app/entrypoint.sh

# 6. 赋予执行权限
# 必须给脚本和二进制文件都加上 +x 权限
RUN chmod +x /app/ech-workers /app/entrypoint.sh

# 7. 设置容器入口点
# 容器启动时，先运行 entrypoint.sh 处理环境变量，再由脚本启动程序
ENTRYPOINT ["/app/entrypoint.sh"]

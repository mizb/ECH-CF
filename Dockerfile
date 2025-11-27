# 基础镜像：Alpine (体积小，安全性高)
FROM alpine:latest

# 1. 安装必要依赖
# ca-certificates: 必须，用于 HTTPS/ECH 证书验证
# tzdata: 用于正确显示日志时间
RUN apk add --no-cache ca-certificates tzdata

# 2. 设置工作目录
WORKDIR /app

# 3. 复制二进制文件并重命名
# 宿主机文件名 (ech-workers-linux-amd64) -> 容器内文件名 (ech-tunnel)
COPY ech-workers-linux-amd64 /app/ech-tunnel

# 4. 赋予执行权限
RUN chmod +x /app/ech-tunnel

# 5. 设置时区 (可选，默认上海时间)
ENV TZ=Asia/Shanghai

# 6. 设置容器启动入口
ENTRYPOINT ["/app/ech-tunnel"]

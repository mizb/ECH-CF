# === 第一阶段：构建 ===
FROM golang:1.21-alpine AS builder

WORKDIR /app

# 为了国内构建速度，虽然在Github Actions里其实不需要，但保留无妨
ENV GOPROXY=https://proxy.golang.org,direct

# 1. 处理依赖
COPY go.mod ./
# 如果还没生成 go.sum，这一步会自动下载
RUN go mod tidy

# 2. 复制源码
COPY . .

# 3. 编译静态二进制文件
# -s -w 去掉调试信息减小体积
# CGO_ENABLED=0 确保可以在轻量级系统运行
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -o app main.go

# === 第二阶段：运行 ===
FROM alpine:latest

# 安装基础证书（TLS/HTTPS连接必须）和时区数据
RUN apk --no-cache add ca-certificates tzdata

WORKDIR /app

# 从构建层复制编译好的程序
COPY --from=builder /app/app .

# 设置时区为上海（方便查看日志）
ENV TZ=Asia/Shanghai

# 赋予执行权限
RUN chmod +x ./app

# 容器启动命令
ENTRYPOINT ["./app"]

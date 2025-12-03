# 第一阶段：构建阶段
FROM golang:1.21-alpine AS builder

# 设置工作目录
WORKDIR /app

# 设置 Go 代理，加速国内构建（可选，但在 Github Actions 中通常不需要）
ENV GOPROXY=https://proxy.golang.org,direct

# 复制依赖文件并下载
COPY go.mod ./
# 如果有 go.sum 也复制，没有则自动生成
# COPY go.sum ./ 
RUN go mod tidy

# 复制源码
COPY . .

# 编译 (CGO_ENABLED=0 确保生成静态二进制文件)
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -o client main.go

# 第二阶段：运行阶段
FROM alpine:latest

# 安装基础证书（HTTPS/TLS 必须）和时区数据
RUN apk --no-cache add ca-certificates tzdata

WORKDIR /app

# 从构建阶段复制二进制文件
COPY --from=builder /app/client .

# 设置时区为上海
ENV TZ=Asia/Shanghai

# 赋予执行权限
RUN chmod +x ./client

# 容器入口
ENTRYPOINT ["./client"]

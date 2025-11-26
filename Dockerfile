# --- 第一阶段：编译源码 ---
FROM golang:alpine AS builder

# 安装 git 以便下载依赖
RUN apk add --no-cache git

WORKDIR /src

# 复制依赖文件并下载
COPY go.mod ./
RUN go mod tidy && go mod download

# 复制源代码
COPY main.go .

# 静态编译 Go 程序
# CGO_ENABLED=0: 禁用 CGO，确保不依赖系统动态库
# -ldflags="-s -w": 去除调试信息，减小体积
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o ech-tunnel main.go

# --- 第二阶段：运行时镜像 ---
FROM alpine:latest

# 安装必要证书 (HTTPS/WSS 必需) 和时区数据
RUN apk add --no-cache ca-certificates tzdata libc6-compat

WORKDIR /app

# 从编译阶段复制二进制文件
COPY --from=builder /src/ech-tunnel /app/ech-tunnel

# 复制启动脚本
COPY entrypoint.sh /app/entrypoint.sh

# 赋予执行权限
RUN chmod +x /app/ech-tunnel /app/entrypoint.sh

# 设置入口点
ENTRYPOINT ["/app/entrypoint.sh"]

# --- 第一阶段：编译构建 ---
FROM golang:alpine AS builder

# 安装 git (go mod 需要)
RUN apk add --no-cache git

WORKDIR /src

# 1. 先复制 go.mod (如果有的话)
COPY go.mod ./

# 2. 【关键修改】必须先把源代码复制进去，否则 tidy 无法检测依赖
COPY main.go .

# 3. 【关键修改】现在执行 tidy，它会扫描 main.go 并自动下载缺失的包 (uuid, websocket)
# 设置代理防止网络超时
ENV GOPROXY=https://goproxy.io,direct
RUN go mod tidy && go mod download

# 4. 静态编译
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o ech-tunnel main.go

# --- 第二阶段：运行时环境 ---
FROM alpine:latest

# 安装根证书
RUN apk add --no-cache ca-certificates tzdata libc6-compat

WORKDIR /app

# 复制编译好的程序
COPY --from=builder /src/ech-tunnel /app/ech-tunnel

# 复制启动脚本
COPY entrypoint.sh /app/entrypoint.sh

# 赋予权限
RUN chmod +x /app/ech-tunnel /app/entrypoint.sh

# 设置入口
ENTRYPOINT ["/app/entrypoint.sh"]

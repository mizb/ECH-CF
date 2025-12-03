# === 第一阶段：构建 ===
FROM golang:1.21-alpine AS builder

WORKDIR /app

ENV GOPROXY=https://proxy.golang.org,direct

# 1. 先把所有文件（包括 go.mod 和 main.go）都复制进去
# 修正点：这一步必须在 go mod tidy 之前
COPY . .

# 2. 现在有了代码，tidy 才能分析出需要下载哪些依赖
RUN go mod tidy

# 3. 编译静态二进制文件
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -o app main.go

# === 第二阶段：运行 ===
FROM alpine:latest

RUN apk --no-cache add ca-certificates tzdata

WORKDIR /app

COPY --from=builder /app/app .

ENV TZ=Asia/Shanghai

RUN chmod +x ./app

ENTRYPOINT ["./app"]

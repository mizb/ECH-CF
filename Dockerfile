# === 第一阶段：构建 ===
# 1. 必须将版本升级到 1.23 (支持 ECH)
FROM golang:1.23-alpine AS builder

WORKDIR /app

ENV GOPROXY=https://proxy.golang.org,direct

# 2. 开启 ECH 实验性功能支持 (关键!)
ENV GOEXPERIMENT=ech

COPY . .

RUN go mod tidy

# 3. 编译
# 注意：GOEXPERIMENT 环境变量已经被上面的 ENV 设置了，这里会自动生效
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -o app main.go

# === 第二阶段：运行 ===
FROM alpine:latest

RUN apk --no-cache add ca-certificates tzdata

WORKDIR /app

COPY --from=builder /app/app .

ENV TZ=Asia/Shanghai

RUN chmod +x ./app

ENTRYPOINT ["./app"]

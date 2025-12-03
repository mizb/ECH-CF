# === 第一阶段：构建 ===
# 保持使用 1.23，因为你需要这个版本才支持 ECH 字段
FROM golang:1.23-alpine AS builder

WORKDIR /app

ENV GOPROXY=https://proxy.golang.org,direct

# 【重要】删除了之前那行 GOEXPERIMENT，Go 1.23 默认就支持了
# ENV GOEXPERIMENT=ech  <-- 这行不要了

COPY . .

RUN go mod tidy

# 编译
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -o app main.go

# === 第二阶段：运行 ===
FROM alpine:latest

RUN apk --no-cache add ca-certificates tzdata

WORKDIR /app

COPY --from=builder /app/app .

ENV TZ=Asia/Shanghai

RUN chmod +x ./app

ENTRYPOINT ["./app"]

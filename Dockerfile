# FROM alpine:latest

RUN apk add --no-cache ca-certificates tzdata
WORKDIR /app

# 确保你的 git 仓库里有这个文件
COPY ech-workers-linux-amd64 /app/ech-tunnel

RUN chmod +x /app/ech-tunnel
ENV TZ=Asia/Shanghai
ENTRYPOINT ["/app/ech-tunnel"]

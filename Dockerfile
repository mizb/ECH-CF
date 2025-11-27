FROM golang:alpine AS builder
RUN apk add --no-cache git
WORKDIR /src
COPY go.mod ./
COPY main.go .
ENV GOPROXY=https://goproxy.io,direct
RUN go mod tidy && go mod download
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o ech-tunnel main.go

FROM alpine:latest
RUN apk add --no-cache ca-certificates tzdata libc6-compat
WORKDIR /app
# 脚本部分保持不变...
RUN printf '#!/bin/sh\n\
\n\
LISTEN_ADDR="proxy://0.0.0.0:1080"\n\
if [ -n "$ECH_LISTEN" ]; then LISTEN_ADDR="$ECH_LISTEN"; fi\n\
set -- /app/ech-tunnel -l "$LISTEN_ADDR"\n\
if [ -n "$ECH_FORWARD" ]; then set -- "$@" -f "$ECH_FORWARD"; fi\n\
if [ -n "$ECH_TOKEN" ]; then set -- "$@" -token "$ECH_TOKEN"; else echo "Error: ECH_TOKEN is required!"; exit 1; fi\n\
if [ -n "$ECH_EXIT_IP" ]; then set -- "$@" -ip "$ECH_EXIT_IP"; fi\n\
if [ -n "$ECH_DOMAIN" ]; then set -- "$@" -ech "$ECH_DOMAIN"; fi\n\
if [ -n "$ECH_DNS" ]; then set -- "$@" -dns "$ECH_DNS"; fi\n\
if [ -n "$ECH_CONCURRENCY" ]; then set -- "$@" -n "$ECH_CONCURRENCY"; fi\n\
\n\
echo "Starting ECH Tunnel (Source Built)。.."\n\
echo "Exec: $@"\n\
exec "$@"\n\
' > /app/entrypoint.sh

COPY --from=builder /src/ech-tunnel /app/ech-tunnel
RUN chmod +x /app/ech-tunnel /app/entrypoint.sh
ENTRYPOINT ["/app/entrypoint.sh"]

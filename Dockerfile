# 使用最基础的 Alpine 镜像
FROM alpine:latest

# 安装必要的运行时库
RUN apk add --no-cache ca-certificates libc6-compat tzdata

WORKDIR /app

# 1. [关键修改] 复制真实的二进制文件，并重命名为通用名字
COPY ech-workers-linux-amd64 /app/ech-tunnel

# 2. 复制启动脚本
COPY entrypoint.sh /app/entrypoint.sh

# 3. 修复 Windows 换行符并赋予脚本执行权限
RUN sed -i 's/\r$//' /app/entrypoint.sh && chmod +x /app/entrypoint.sh

# 4. 赋予二进制文件执行权限
RUN chmod +x /app/ech-tunnel

# 5. 设置入口点
ENTRYPOINT ["/app/entrypoint.sh"]

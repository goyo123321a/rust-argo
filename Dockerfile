# 构建阶段
FROM rust:alpine AS builder

# 安装 musl 开发工具（确保静态链接）
RUN apk add --no-cache musl-dev

WORKDIR /app

# 复制依赖清单并构建依赖层（缓存）
COPY Cargo.toml .
RUN mkdir src && echo "fn main() {}" > src/main.rs
RUN cargo build --release

# 复制真实源代码并构建
COPY src ./src
RUN cargo build --release

# 运行阶段
FROM alpine:latest

# 安装 CA 证书（用于 HTTPS 请求）
RUN apk add --no-cache ca-certificates

WORKDIR /app

# 从构建阶段复制二进制（无需指定目标三元组，因为构建器本机编译）
COPY --from=builder /app/target/release/proxy-deployer /usr/local/bin/proxy-deployer

# 可选：复制自定义 index.html（若需要）
# COPY index.html /app/index.html

# 创建工作目录
RUN mkdir -p /app/.tmp && chmod 755 /app/.tmp

# 暴露端口
EXPOSE 7860

# 启动
ENTRYPOINT ["/usr/local/bin/proxy-deployer"]

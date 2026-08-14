# 构建阶段：使用 musl 目标生成静态二进制
FROM rust:alpine AS builder

# 安装 musl 工具链（已包含）和必要构建依赖
RUN apk add --no-cache musl-dev

# 添加 musl 目标（默认已经存在，但显式添加确保）
RUN rustup target add x86_64-unknown-linux-musl

WORKDIR /app

# 复制 Cargo.toml 并创建虚拟 main.rs 以缓存依赖
COPY Cargo.toml .
RUN mkdir src && echo "fn main() {}" > src/main.rs

# 构建依赖（此层会被缓存，除非 Cargo.toml 变化）
RUN cargo build --release --target x86_64-unknown-linux-musl

# 复制真实源代码并重新构建（利用缓存）
COPY src ./src
RUN touch src/main.rs && cargo build --release --target x86_64-unknown-linux-musl

# 运行阶段：使用最小化的 Alpine 镜像
FROM alpine:latest

# 安装 CA 证书（用于 HTTPS 请求）
RUN apk add --no-cache ca-certificates

WORKDIR /app

# 从构建阶段复制静态二进制
COPY --from=builder /app/target/x86_64-unknown-linux-musl/release/proxy-deployer /usr/local/bin/proxy-deployer

# 可选：复制自定义 index.html（如果存在）
# COPY index.html /app/index.html

# 创建运行时目录
RUN mkdir -p /app/.tmp && chmod 755 /app/.tmp

# 暴露默认端口
EXPOSE 7860

# 设置入口点
ENTRYPOINT ["/usr/local/bin/proxy-deployer"]

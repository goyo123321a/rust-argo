# ---------- 构建阶段 ----------
FROM rust:alpine AS builder

# 安装构建依赖（OpenSSL 和 musl 工具链）
RUN apk add --no-cache musl-dev openssl-dev

WORKDIR /app

# 复制 Cargo.toml 并创建假 main.rs 以缓存依赖层
COPY Cargo.toml ./
RUN mkdir src && echo "fn main() {}" > src/main.rs
RUN cargo build --release

# 复制真实源代码并重新编译（利用缓存）
COPY src ./src
RUN touch src/main.rs && cargo build --release

# ---------- 最终运行阶段 ----------
FROM alpine:latest

# 安装运行时依赖（CA 证书用于 HTTPS 下载，busybox 提供 sh/nohup 等）
RUN apk add --no-cache ca-certificates

WORKDIR /app

# 从构建阶段复制二进制
COPY --from=builder /app/target/release/rust-sub /usr/local/bin/rust-sub

# 创建默认工作目录（可被环境变量覆盖）
RUN mkdir -p /app/.tmp && chmod 755 /app/.tmp

# 暴露 HTTP 服务端口（默认 3000）
EXPOSE 7860

# 启动程序
ENTRYPOINT ["/usr/local/bin/rust-sub"]

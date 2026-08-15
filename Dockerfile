# ========== 第一阶段：构建 ==========
FROM rust:alpine AS builder

# 安装 musl 工具链（Alpine 默认已带，但需要确保）
RUN apk add --no-cache musl-dev

# 设置工作目录
WORKDIR /app

# 复制依赖清单以利用 Docker 缓存
COPY Cargo.toml Cargo.lock ./

# 创建虚拟 main.rs 以构建依赖层（避免重复编译）
RUN mkdir src && echo "fn main() {}" > src/main.rs && \
    cargo build --release && \
    rm -rf src target/release/deps/rust_node2go*

# 复制真实源码并构建
COPY src ./src
RUN cargo build --release

# ========== 第二阶段：运行镜像 ==========
FROM alpine:latest

# 安装常用工具（与 Node 版本保持一致）
RUN apk add --no-cache \
    openssl \
    curl \
    bash \
    wget \
    gcompat \
    iproute2 \
    coreutils

# 创建非 root 用户（与 Node 版本一致）
RUN addgroup -g 1001 -S nodejs && \
    adduser -S nodejs -u 1001 -G nodejs

# 设置工作目录（与 Node 版本一致）
WORKDIR /tmp

# 从构建阶段复制编译好的二进制
COPY --from=builder /app/target/release/rust-node2go /usr/local/bin/app

# 设置权限（确保可执行）
RUN chmod +x /usr/local/bin/app

# 切换到非 root 用户
USER nodejs

# 暴露端口（与 Node 版本一致）
EXPOSE 7860

# 启动应用
CMD ["/usr/local/bin/app"]

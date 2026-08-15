# ========== 第一阶段：构建 ==========
FROM rust:alpine AS builder

# 安装 musl 工具链
RUN apk add --no-cache musl-dev

WORKDIR /app

# 1. 仅复制 Cargo.toml（不依赖 Cargo.lock）
COPY Cargo.toml ./

# 2. 创建虚拟 main.rs 以触发依赖下载
RUN mkdir src && echo "fn main() {}" > src/main.rs

# 3. 构建依赖层（自动生成 Cargo.lock 并缓存依赖）
RUN cargo build --release

# 4. 移除虚拟 src，复制真实源码
RUN rm -rf src
COPY src ./src

# 5. 重新构建（只编译我们的源码，依赖已缓存）
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

# 创建非 root 用户
RUN addgroup -g 1001 -S nodejs && \
    adduser -S nodejs -u 1001 -G nodejs

WORKDIR /tmp

# 从构建阶段复制二进制
COPY --from=builder /app/target/release/rust-node2go /usr/local/bin/app

# 设置权限
RUN chmod +x /usr/local/bin/app

# 切换到非 root 用户
USER nodejs

EXPOSE 7860

CMD ["/usr/local/bin/app"]

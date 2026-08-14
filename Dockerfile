# 构建阶段
FROM rust:alpine AS builder
RUN apk add --no-cache musl-dev
RUN rustup target add x86_64-unknown-linux-musl
WORKDIR /app
COPY Cargo.toml .
RUN mkdir src && echo "fn main() {}" > src/main.rs
RUN cargo build --release --target x86_64-unknown-linux-musl
COPY src ./src
# 直接构建，无需 touch
RUN cargo build --release --target x86_64-unknown-linux-musl

# 运行阶段
FROM alpine:latest
RUN apk add --no-cache ca-certificates
WORKDIR /app
COPY --from=builder /app/target/x86_64-unknown-linux-musl/release/proxy-deployer /usr/local/bin/proxy-deployer
# 可选：COPY index.html /app/index.html
RUN mkdir -p /app/.tmp && chmod 755 /app/.tmp
EXPOSE 3000
ENTRYPOINT ["/usr/local/bin/proxy-deployer"]

# 构建阶段
FROM rust:alpine AS builder
RUN apk add --no-cache musl-dev
RUN rustup target add x86_64-unknown-linux-musl
WORKDIR /app
COPY Cargo.toml .
RUN mkdir src && echo "fn main() {}" > src/main.rs
RUN cargo build --release --target x86_64-unknown-linux-musl
COPY src ./src
RUN cargo build --release --target x86_64-unknown-linux-musl

# 运行阶段
FROM alpine:latest
RUN apk add --no-cache ca-certificates
WORKDIR /app
COPY --from=builder /app/target/x86_64-unknown-linux-musl/release/proxy-deployer /usr/local/bin/proxy-deployer
RUN mkdir -p /app/.tmp && chmod 755 /app/.tmp
EXPOSE 3000
ENTRYPOINT ["/usr/local/bin/proxy-deployer"]

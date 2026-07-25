# 使用 Alpine 作为基础，并安装 musl 工具链
FROM rust:alpine AS builder
RUN apk add --no-cache musl-dev openssl-dev

WORKDIR /app
COPY Cargo.toml .
RUN mkdir src && echo "fn main() {}" > src/main.rs
RUN cargo build --release

COPY src ./src
RUN touch src/main.rs && cargo build --release

FROM alpine:latest
RUN apk add --no-cache ca-certificates
WORKDIR /app
COPY --from=builder /app/target/release/rust-sub /usr/local/bin/rust-sub
RUN mkdir -p /app/.tmp && chmod 755 /app/.tmp
EXPOSE 7860
ENTRYPOINT ["/usr/local/bin/rust-sub"]

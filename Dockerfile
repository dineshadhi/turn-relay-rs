#Building stage
FROM rust:1.86 as build

COPY . ./build
WORKDIR /build

RUN apt-get update && \
    apt-get install -y \
    protobuf-compiler

RUN cargo build --release

# Runtime stage
FROM ubuntu:24.04 as turnny
RUN apt-get update
WORKDIR /app
COPY --from=build /build/target/release/turnny /usr/local/bin/turnny
ENTRYPOINT ["turnny", "--config", "/app/turnserver.conf"]

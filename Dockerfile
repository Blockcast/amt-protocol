FROM rust:1.88-bookworm AS build
WORKDIR /src
COPY . .
RUN cargo build --release --no-default-features --features native --bin amt-verify

FROM debian:bookworm-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY --from=build /src/target/release/amt-verify /usr/local/bin/amt-verify
USER 65532:65532
ENTRYPOINT ["amt-verify"]

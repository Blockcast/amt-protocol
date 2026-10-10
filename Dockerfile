# Builds the published production amt-verify binary (publish-amt-verify.yml,
# which runs only on push to main -- no PR check builds this image).
#
# Keep this version exactly equal to rust-toolchain.toml's `channel`, patch
# included; tests/toolchain_pin_test.sh fails otherwise. That equality is the
# whole pre-merge check on this image's compiler: `lint (native)` and
# `test (native)` compile this binary's code on every PR, and they are only
# evidence about this image while they use the same rustc it will.
# .dockerignore still keeps that toml out of the build context, so the compiler
# here comes from this line and not from a file that happened to be copied in.
# To diverge deliberately, say why here and add the exception to that test --
# BLO-42208. Was 1.88 from 2026-07-24 to 2026-10-09; nothing bound it.
FROM rust:1.99.0-bookworm AS build
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

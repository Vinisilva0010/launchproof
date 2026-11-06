# LaunchProof API (lp-server). Two stages: build with stable Rust, run on Debian slim.
FROM rust:1-bookworm AS build
WORKDIR /app
COPY . .
# The pinned toolchain file is for Anchor program builds; the API uses stable Rust.
# Fat LTO is disabled here to fit free build machines; the code is unchanged.
RUN rm -f rust-toolchain.toml \
 && CARGO_PROFILE_RELEASE_LTO=false CARGO_PROFILE_RELEASE_CODEGEN_UNITS=16 \
    cargo build --release --locked -p lp-server

FROM debian:bookworm-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates \
 && rm -rf /var/lib/apt/lists/* \
 && useradd --system --uid 10001 app
COPY --from=build /app/target/release/lp-server /usr/local/bin/lp-server
USER app
ENV PORT=8080
EXPOSE 8080
CMD ["lp-server"]

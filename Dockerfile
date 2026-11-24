# Secret Vault server in Docker (docs/user-guide.md, "Run it in Docker").
#
#   docker compose up -d --build
#   docker compose exec vault-server vault-server show

FROM rust:1.97-bookworm AS build
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY src ./src
RUN cargo build --release --locked && strip target/release/vault-server

FROM debian:bookworm-slim
RUN useradd --system --uid 10001 --home-dir /data --shell /usr/sbin/nologin vault-server \
    && install -d -o vault-server -g vault-server -m 700 /data
COPY --from=build /src/target/release/vault-server /usr/local/bin/vault-server
USER vault-server
ENV VAULT_SERVER_DATA=/data \
    VAULT_SERVER_LISTEN=0.0.0.0:8443
VOLUME /data
EXPOSE 8443
ENTRYPOINT ["vault-server"]
CMD ["serve"]

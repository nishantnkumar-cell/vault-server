# vault-server

The sync server for [Secret Vault](https://github.com/nishantnkumar-cell/PasswordVault),
to run on a computer of your own: natively on Linux or macOS, or in Docker
anywhere.

All your devices keep one vault in sync through it: the desktop app and the
`vault` command on Linux and macOS, and the iPhone and iPad app. (Windows and
Android use the same protocol and will work with it when those apps resume.)

- **End-to-end encrypted.** The server only ever holds each vault's
  encrypted file. It never sees a master password, a key or an item.
- **Post-quantum connections.** TLS 1.3 with the hybrid key exchange
  X25519 + ML-KEM-768 (X25519MLKEM768), so recorded traffic stays safe
  against a future quantum computer.
- **No account, no cost.** It makes its own certificate authority; devices
  pin it by a fingerprint in the join link or QR code.
- **Version history.** The last 20 versions of each vault file (up to 30
  days) are kept, so a bad save can be rolled back.
- **Same protocol as before.** It speaks the vault's sync API 1, exactly
  like the Cloudflare Worker and the Docker server in the vault repo, so the
  apps need nothing new.

Coming next: encrypted backups to Google Drive, OneDrive, Dropbox or a
folder, `.deb` and Arch packages, and moving an existing Docker sync server
over without joining devices again.

## Start here

- [User guide](docs/user-guide.md): install it, connect your first computer,
  add your phone, step by step.
- [How it works](docs/how-it-works.md): the protocol, the crypto, what the
  server can and cannot see.
- [Release notes](docs/release-notes.md)

Quick start with Docker:

```sh
git clone https://github.com/nishantnkumar-cell/vault-server.git
cd vault-server
# put your computer's address in VAULT_SERVER_HOSTS in compose.yaml, then:
docker compose up -d --build
docker compose exec vault-server vault-server show
```

## Licence

[PolyForm Noncommercial 1.0.0](LICENSE.md), the same as Secret Vault.

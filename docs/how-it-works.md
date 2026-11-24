# How vault-server works

vault-server is a second implementation of the Secret Vault sync API 1, the
one the Cloudflare Worker in the vault repo implements
(`server/sync/src/index.js`, described in the vault's `docs/cloud-sync.md`).
Clients cannot tell the two apart except by the `server` field of `GET /`.

## Parts

| Part | Where | What it does |
| --- | --- | --- |
| API | `src/api.rs` | The HTTP and WebSocket calls, limits and answers of API 1 |
| Storage | `src/store.rs` | One SQLite file: mailboxes, file versions, device token hashes, join ticket hashes |
| TLS | `src/tls.rs` | Own certificate authority, server certificate, TLS 1.3 with X25519MLKEM768 preferred |
| Server | `src/server.rs` | Data folder, keys, listeners |
| Command | `src/main.rs` | `init`, `serve`, `show`, `status`, `history`, `restore` |

## The data folder

| File | What |
| --- | --- |
| `admin-key` | 256-bit random key; needed to create a mailbox (or `ADMIN_KEY` from the environment) |
| `hosts` | The host names last given with `--hosts` / `VAULT_SERVER_HOSTS` |
| `tls/ca.pem`, `tls/ca.key` | The server's own certificate authority: EC P-256, 20 years, `pathLen 0`, key usage certificate signing only |
| `tls/server.crt`, `tls/server.key` | Server certificate signed by it: 10 years, `serverAuth`, names `localhost`, `127.0.0.1` and every host given. Made again when the hosts change; the authority stays |
| `vault-server.db` | SQLite (WAL, `synchronous=FULL`) |

The folder is mode 0700 and every file 0600. The systemd unit adds
`UMask=0077`, runs as its own user with no capabilities, a read-only system,
no home folders and a system-call filter.

## Sync API 1

Tokens are base64url, 256 bits. `Authorization: Bearer <token>` is a device
token unless said otherwise. Every answer has `Cache-Control: no-store`.

| Call | Does |
| --- | --- |
| `GET /` | `{"service":"secret-vault-sync","api":1,"revision":2,"server":"vault-server","version":"…"}` |
| `GET /ca.pem` | The server's own certificate authority, no token needed |
| `GET /join` | A page telling someone who opened a join link in a browser what to do |
| `POST /v1/m/<id>` | Create an empty mailbox. `X-Admin-Key`; the bearer token becomes the first device's; `X-Device-Name` |
| `GET` or `HEAD /v1/m/<id>` | The file with `ETag: "<version>"`; 204 while empty; 304 for `If-None-Match` |
| `PUT /v1/m/<id>` | Save. `If-Match: "<version>"` required (428); 412 with the current ETag when another device saved first |
| `DELETE /v1/m/<id>` | Delete the mailbox, its files (all versions) and devices |
| `POST /v1/m/<id>/tickets` | One-time join ticket, 10 minutes |
| `POST /v1/m/<id>/join` | `X-Ticket`; the bearer token is the new device's |
| `GET /v1/m/<id>/devices`, `DELETE /v1/m/<id>/devices/<dev>` | List, remove (closes that device's watchers with code 4001) |
| `GET /v1/m/<id>/watch` | WebSocket: `{"version":n}` on connect and after every save; `ping` → `pong`; closed with 4004 when the mailbox is deleted |

A wrong token and an unknown mailbox get the same 401. Limits, the same as
the Worker's: 4 MiB per file, 60 saves a minute per mailbox, 32 devices, 32
watchers, 5 unused tickets. The version check and the write happen in one
SQLite transaction, so two saves cannot both win.

Tokens and tickets are stored only as SHA-256. The admin key is compared in
constant time (both sides hashed first).

## Version history

Every save adds a row; the server keeps the newest 20 versions of each
mailbox, and drops any but the current one that are older than 30 days.
`vault-server restore MAILBOX N` saves version N's bytes as a new version, so
devices fetch it through the normal path and merge it (the vault format's
merge, vault `docs/format.md` 5.1). Old versions are exactly as encrypted as
the current one.

Note for the future backup restore: a restore can bring back the device
tokens of the time of the backup. The restore will list them and let the
owner drop devices removed since (see the vault's security review of
2026-11-10: a synced copy must not undo a revoke).

## Crypto

| Layer | What protects it |
| --- | --- |
| Vault file and items | Sealed by the vault itself with a 256-bit key (XChaCha20-Poly1305); the server never has the key |
| Shared collections | X-Wing (ML-KEM-768 + X25519) per member, in the vault |
| Connection | TLS 1.3 only. Key exchange preference: **X25519MLKEM768**, then X25519, then P-256 (aws-lc-rs). The test `prefers_post_quantum_key_exchange` checks both a hybrid client and a classical one |
| Server identity | Own CA (EC P-256) pinned by fingerprint: base64url SHA-256 of its DER, 43 characters |

Signatures (the certificates) only need to hold at the moment of connecting,
so a future quantum computer cannot use them to read recorded traffic; the
key exchange is what needed to change, and it has. ML-DSA certificates can
follow when rustls supports them.

The vault apps today build their TLS with rustls and `ring`, which has no
ML-KEM, so they connect with X25519. A small change in the vault repo
(rustls with aws-lc-rs in `vault-cloud` and `vault-mobile`) moves them to the
hybrid; nothing on the server side changes for that.

## Backups

`vault-server backup add` makes the **backup key**, an X-Wing key pair
(ML-KEM-768 + X25519, the same code the vault uses for shared collections).
The server keeps `backup.pub`; the secret half is shown once as a recovery
code (the 32-byte seed, 13 groups of 4 characters) and never stored.

A snapshot is JSON: each mailbox's current file (base64url), version, and
devices (token SHA-256 only), plus `admin-key`, `hosts`, `tls/ca.pem` and
`tls/ca.key`. It is sealed with a fresh X-Wing encapsulation to the backup
key; the shared secret is the key for XChaCha20-Poly1305 with a random
24-byte nonce, and the format tag is the associated data:

```
"SVBK1\0" | X-Wing ciphertext (1120) | nonce (24) | AEAD ciphertext + tag
```

A changed file fails the tag and is refused, never half-restored. File
names are `vault-server-YYYYMMDD-HHMMSS.svbak` (UTC). A target is written to
`NAME.part`, renamed, read back and compared by SHA-256. Retention keeps the
newest snapshot of each of the last 7 days, 4 ISO weeks and 12 months, and
always the newest overall. Target settings are in `backup.json`, results in
`backup-status.json`, both mode 0600. The scheduler in `serve` checks once a
minute: due when something was saved and 10 minutes have passed since, or the
last good backup is a day old; after a failure it waits 5 minutes.

Restore reads the whole snapshot first, lists the devices, and writes into
the database only with `--confirm`, in one transaction, into a server that
has no vaults.

## What the server sees

When devices sync, from which addresses, the size of each file, device names
(as typed in setup) and how many versions there are. It cannot read or
change a vault; it can withhold, delay or delete copies, and each device
keeps its own full copy.

## Checks

- `tests/api.rs`: the Worker's test cases, run over real TLS against the
  server (20 tests).
- CI job **Works with the vault's own sync client**: builds
  `compat/compat-check.rs` inside the vault repo against `vault-cloud` and runs
  it against this server (fingerprint fetch, create, save and conflict, join
  link, watch, remove, delete).
- CI job **Docker image**: TLS with its own authority, the fingerprint matches
  the certificate, and it stays the same across a restart.

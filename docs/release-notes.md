# Release notes

Newest first. Each release says what is new for you, what you need to do, and
what differs between Linux, macOS and Windows.

## 0.3.1 (not yet released): connection limits

### Connections are limited

- **One computer on the network can no longer tie up the server** by opening many
  connections and saying nothing. At most 64 connections from one address and 512
  in all are served at once; a connection that sends no request within 20 seconds,
  or is quiet for 2 minutes, is closed; and a save must arrive within 2 minutes.
  Live updates are not affected. Before this, such connections stayed open and
  the server could stop answering. **Upgrade if your server is reachable by
  people you do not trust**, for example from the internet.
- Nothing to set up. If many devices reach the server through one proxy, they
  share the limit of 64 connections.
- `vault-server import` no longer leaves its temporary copy of an old database
  behind when it fails.

## 0.3.0 (2026-11-24): Linux packages and moving from the old Docker server

### What's new

- **A `.deb` for Debian 13 and Ubuntu 24.04 or newer**, an **Arch Linux
  package**, and a **`.tar.gz`** for any other Linux with systemd. Each
  installs the program, the `vault-server` systemd service (hardened, as its
  own user) and its settings file `/etc/vault-server/env`, so there is no
  Rust to install and no building. See [section 4A of the user guide](user-guide.md#4a-linux-from-a-package-easiest).
- **Safe by default.** The service is not started by the install (it needs
  your addresses first); upgrading restarts it and keeps everything; removing
  the package keeps `/var/lib/vault-server`.
- **Checked on every change**: CI installs the `.deb` with real dpkg, starts
  the service under systemd and talks to it over TLS, upgrades it in place and
  removes it; it builds, installs and removes the Arch package in an Arch
  container. A tag such as `v0.3.0` drafts a release with the files and a
  `SHA256SUMS.txt`.

- **`vault-server import`**: takes over the old Docker server's data (vault
  files, devices with their keys, the certificate authority and admin key), so
  **devices keep working and the fingerprint stays the same**. The old
  server's files are named by a hash, so you give each vault's mailbox id
  (`vault cloud status` on a device shows it, in Secret Vault versions after 0.2.0). See [Moving from the old Docker server](user-guide.md#moving-from-the-old-docker-server-in-the-vault-repo).

### What you need to do

Nothing for an existing server. To move a hand-installed server to the
package, install it over the same data folder: `/var/lib/vault-server` is the
same, so the fingerprint and devices stay. Stop and disable your own
`/etc/systemd/system/vault-server.service` first (the package's file is the
one in `/usr/lib/systemd/system`).

### Differences between systems

The packages are for Linux on x86-64. macOS and Windows are unchanged (see
0.1.0).

### Known limits

- `vault-server import` has been tried on files built to the old server's documented layout (and carries its authority over), not on a volume written by a real workerd: stop the old server before importing and keep your copy until the new one works.
- Google Drive, OneDrive and Dropbox backup targets are not available yet.

## 0.2.0 (first released in 0.3.0): sealed backups

### What's new

- **Backups to a folder you choose** (a USB disk, a NAS share, or a folder
  your OneDrive, Google Drive or Dropbox app syncs). `vault-server backup
  add folder PATH` makes the backup key and shows its **recovery code once**.
- **Sealed with post-quantum encryption** (X-Wing, then XChaCha20-Poly1305):
  the server keeps only the public key, so a stolen server or disk cannot
  open the backups, and a changed file is refused.
- **Automatic**: 10 minutes after the last change and at least daily, kept as
  7 daily, 4 weekly and 12 monthly snapshots. Each is read back and compared.
  `vault-server status` shows the last good backup per target, or why it is
  failing.
- **Restore** into a new server with `vault-server backup restore`, which
  first shows the devices (so you can leave out one removed since with
  `--drop`) and changes nothing until `--confirm`. Devices keep their keys and
  the same fingerprint, because the certificate authority is in the backup.
  A single vault's file can be taken out with `--mailbox ID --out FILE`.

- **Security:** the post-quantum signature library (`ml-dsa`) that
  `vault-core` pulls in had a timing weakness (RUSTSEC-2025-0144). The server
  now uses the same fixed copy as the vault apps. Other libraries are at
  their newest compatible versions.

### What you need to do

Nothing for an existing server. To turn backups on, follow section 9 of the
[user guide](user-guide.md#9-backups), and keep the recovery code safe.

### Differences between systems

The same on Linux and macOS. Windows still runs the server in Docker; mount a
folder into the container to use a folder target.

### Known limits

- Google Drive, OneDrive and Dropbox cannot be added directly yet: that needs
  this program registered with each of them. A folder those apps sync works
  now.
- The recovery code is the seed in base32 groups, not 24 words.
- Packages and the Docker import came in 0.3.0.

## 0.1.0 (first released in 0.3.0): the server itself

The first version of **vault-server**, a sync server you run on a computer of
your own. It replaces the Docker sync server in the vault repo (user guide
chapter 16 there) with one program that also runs without Docker, and it is
where the coming backup features will live.

### What's new

- **One server for every Secret Vault app.** It speaks the same sync
  protocol (API 1) as before, so the desktop app, the `vault` command and the
  iPhone and iPad app use it with no update: `vault cloud setup --server`,
  join links and QR codes work as they do today.
- **Post-quantum connections.** The server prefers the hybrid key exchange
  X25519MLKEM768 (X25519 plus ML-KEM-768) and speaks only TLS 1.3. Today's
  vault apps connect with X25519 until a vault update moves them to the
  hybrid too; nothing breaks either way.
- **Runs natively on Linux and macOS**, as a systemd service or by hand, as
  well as in Docker. The Docker image no longer needs workerd or Node.
- **Its own certificate authority**, made on first start, pinned by
  fingerprint exactly like the old Docker server.
- **Version history**: the last 20 versions of each vault's file, for up to
  30 days. `vault-server history` lists them and `vault-server restore`
  makes an older one the newest again. Devices merge it with what they
  have, so nothing on them is lost.
- **`vault-server status`** lists the vaults on the server and their
  devices; **`vault-server show`** prints the address, fingerprint and
  admin key again.

### What you need to do

Nothing changes for an existing setup until you choose to move. To start
fresh, follow the [user guide](user-guide.md). To move from the old Docker
server, see [Moving from the old Docker server](user-guide.md#moving-from-the-old-docker-server-in-the-vault-repo).

### Differences between systems

| | Linux | macOS | Windows |
| --- | --- | --- | --- |
| Run the server natively | Yes, systemd service | Yes, by hand or at login (launchd comes later) | No; use Docker Desktop |
| Run it in Docker | Docker Engine | Docker Desktop | Docker Desktop (WSL 2) |
| Use it from the vault apps | Desktop app, `vault` | Desktop app, `vault` | Same protocol; Windows app on hold |

### Known limits

- Backups are in 0.2.0, not this version
  (next release).
- No `.deb` or Arch package yet: build it with Rust or use Docker.
- Moving from the old Docker server means setting up again (devices join
  again with a link). An import tool comes with the packages.

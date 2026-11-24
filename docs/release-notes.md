# Release notes

Newest first. Each release says what is new for you, what you need to do, and
what differs between Linux, macOS and Windows.

## 0.2.0 (not released yet): sealed backups

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
- `.deb` and Arch packages, and importing the old Docker volume, are next.

## 0.1.0 (not released yet): the server itself

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

# vault-server user guide

This guide takes you from nothing to a working sync server on a computer in
your home, with your first computer and your phone connected. No Docker or
Rust knowledge is needed if you follow it step by step. The examples use the
placeholder names "Alex Example" and `vault.home.example`; use your own.

**Contents**

1. [What it is and when to use it](#1-what-it-is-and-when-to-use-it)
2. [What you need](#2-what-you-need)
3. [Give the server computer a fixed address](#3-give-the-server-computer-a-fixed-address)
4. [Install and start the server](#4-install-and-start-the-server) (Linux, Docker, macOS)
5. [Let your other devices in (firewall)](#5-let-your-other-devices-in-firewall)
6. [Connect your first computer](#6-connect-your-first-computer)
7. [Add more devices, including your phone](#7-add-more-devices-including-your-phone)
8. [Day to day: status, history, undoing a bad save](#8-day-to-day-status-history-undoing-a-bad-save)
9. [Moving from the old Docker server in the vault repo](#moving-from-the-old-docker-server-in-the-vault-repo)
10. [Away from home](#10-away-from-home)
11. [Updating the server](#11-updating-the-server)
12. [Troubleshooting](#12-troubleshooting)
13. [Differences between Linux, macOS and Windows](#13-differences-between-linux-macos-and-windows)

## 1. What it is and when to use it

Secret Vault keeps your vault on every device. To keep those copies the same,
the devices need a place to meet. **vault-server** is that place, running on a
computer you own: a desktop that is usually on, a small home server, a NAS
that runs Docker, or a Raspberry Pi 4 or newer.

```
 Alex's laptop               the server computer (at home)          Alex's phone
 ┌──────────────┐            ┌─────────────────────────────┐        ┌──────────────┐
 │ Secret Vault │──https────▶│ vault-server, port 8443     │◀─https─│ Secret Vault │
 │ (the vault)  │            │ keeps the ENCRYPTED file    │        │ (same vault) │
 └──────────────┘            │ and each device's access    │        └──────────────┘
                             └─────────────────────────────┘
```

Use it when:

- you would rather not use a Cloudflare account (the other cloud sync option,
  vault user guide chapter 15);
- your devices are at home most of the time, or you can reach home through a
  VPN (section 10);
- you want the server's copy to stay in your house.

What the server can and cannot do:

- It **stores only encrypted vault files**. It never sees your master
  password, your keys or any item, so someone who steals the server computer
  learns nothing from it.
- It **cannot change** your vault: every device checks each file it gets.
- It **can** see when your devices sync, from which addresses, and how big
  the file is, and (like any server) it could withhold or delete the copy.
  Each device keeps its own full vault, so nothing is lost if the server
  disappears.

## 2. What you need

- One computer to run the server. It can also be a computer you use the vault
  on.
- On that computer, **either** Linux (any recent Debian, Ubuntu, Fedora or
  Arch), **or** Docker (Linux, macOS or Windows), **or** macOS.
- Secret Vault with cloud sync (the `vault cloud` command and the desktop
  app's **Sync** page) on each computer, with `vaultd` running and the vault
  unlocked on the first one. On a phone, the iPhone or iPad app.
- About twenty minutes the first time.

## 3. Give the server computer a fixed address

Your other devices find the server by its address on your home network. That
address must not change.

### 3.1 Find the address

| The server computer | How |
|---|---|
| Linux | `ip -4 addr show scope global`; the address after `inet`, such as `192.168.1.20` |
| macOS | **System Settings → Wi-Fi** (or **Network**), **Details…** next to your network; **IP address** |
| Windows | `ipconfig` in PowerShell; **IPv4 Address** under your Wi-Fi or Ethernet adapter |

Home addresses almost always start with `192.168.`, `10.` or `172.16.` to
`172.31.`.

### 3.2 Keep it fixed

Open your router's page (often [192.168.1.1](http://192.168.1.1) or
[192.168.0.1](http://192.168.0.1); the address and password are usually on a
sticker on the router). Look for **DHCP reservation**, **Address
reservation** or **Static lease**, pick the server computer and save.

You can also use a name, such as `vault.home.example` if your router gives
names, or `computername.local` on many home networks. You can give both a
name and the address; the server's certificate covers all of them.

## 4. Install and start the server

Pick **one** of the ways below. On Linux, a package is the easiest.

### 4A. Linux, from a package (easiest)

A package installs the program, the `vault-server` service and its user in
one step, and keeps your data when you remove or upgrade it. Download the
file for your system from the
[releases page](https://github.com/nishantnkumar-cell/vault-server/releases)
(check it against `SHA256SUMS.txt`).

| System | Install |
|---|---|
| Debian 13, Ubuntu 24.04 or newer | `sudo apt install ./vault-server_0.3.1_amd64.deb` |
| Arch Linux | `sudo pacman -U vault-server-0.3.1-x86_64.pkg.tar.zst` |
| Any other Linux with systemd (x86-64) | `sudo tar -xzf vault-server-0.3.1-linux-x86_64.tar.gz -C /` then `sudo systemd-sysusers && sudo systemctl daemon-reload` |

(Use the version number of the file you downloaded.) The server is **not
started yet**: it needs the address from step 3 first.

1. Tell it the address (replace the example with yours; a name and the
   address, separated by a comma, also works):

   ```sh
   sudo nano /etc/vault-server/env        # remove the # before VAULT_SERVER_HOSTS and edit it
   ```

   The file is readable by root only, because it can also hold the admin key.

2. Start it, now and at every boot:

   ```sh
   sudo systemctl enable --now vault-server
   ```

3. Print what you need for step 6:

   ```sh
   sudo -u vault-server VAULT_SERVER_DATA=/var/lib/vault-server vault-server show
   ```

   The output is the one shown in 4A2 below.

Upgrading is installing the newer package: the server restarts by itself and
keeps its data, certificate and fingerprint. Removing the package
(`sudo apt remove vault-server`, `sudo pacman -R vault-server`) stops the
service but **keeps `/var/lib/vault-server`** (your vaults' files, keys and
backup settings) and the `vault-server` user. Delete them by hand only if you
want everything gone.

### 4A2. Linux, built from source

Use this on a system without a package, or to build it yourself. The server
runs as its own user, `vault-server`, starts with the computer, and keeps
everything in `/var/lib/vault-server`.

1. Install Rust (once) and build the server:

   ```sh
   curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh   # accept the defaults
   source "$HOME/.cargo/env"
   git clone https://github.com/nishantnkumar-cell/vault-server.git
   cd vault-server
   cargo build --release
   ```

2. Install it as a service:

   ```sh
   sudo install -m 755 target/release/vault-server /usr/local/bin/
   sudo useradd --system --home-dir /var/lib/vault-server --shell /usr/sbin/nologin vault-server
   sudo install -m 644 contrib/systemd/vault-server.service /etc/systemd/system/
   ```

3. Tell it the address from step 3 (replace the example with yours; a name
   and the address, separated by a comma, also works):

   ```sh
   sudo mkdir -p /etc/vault-server
   echo 'VAULT_SERVER_HOSTS=192.168.1.20' | sudo tee /etc/vault-server/env
   ```

4. Start it, now and at every boot:

   ```sh
   sudo systemctl enable --now vault-server
   ```

5. Print what you need for step 6:

   ```sh
   sudo -u vault-server VAULT_SERVER_DATA=/var/lib/vault-server vault-server show
   ```

   ```
   Secret Vault server (vault-server 0.1.0)
     address:      https://192.168.1.20:8443
     certificate:  localhost, 127.0.0.1, 192.168.1.20
     fingerprint:  tbCvXr6N001Lm6NUgBwIgyL5MjAWEOiHLXJ0gQT5dRQ
     admin key:    3q9V…

   On the first computer, with the vault unlocked:
     vault cloud setup --server https://192.168.1.20:8443 --fingerprint tbCvXr6N001Lm6NUgBwIgyL5MjAWEOiHLXJ0gQT5dRQ
   ```

   - The **fingerprint** identifies the server's own certificate. Devices
     check it, so another computer on your network cannot pretend to be your
     server. It stays the same as long as `/var/lib/vault-server` is kept.
   - The **admin key** lets setup create a place for your vault on the
     server. Treat it like a password; only setup needs it.

`systemctl status vault-server` shows whether it runs, and
`journalctl -u vault-server` shows its log.

### 4B. Docker (Linux, macOS or Windows)

1. Install Docker:

   | The server computer | What to install |
   |---|---|
   | Linux (Debian, Ubuntu) | `sudo apt install docker.io docker-compose-v2`, then `sudo usermod -aG docker $USER`, sign out and back in |
   | Linux (Arch) | `sudo pacman -S docker docker-compose`, `sudo systemctl enable --now docker`, then `sudo usermod -aG docker $USER`, sign out and back in |
   | Windows 10/11 | [Docker Desktop](https://docs.docker.com/desktop/setup/install/windows-install/), with **Use WSL 2** ticked |
   | macOS | [Docker Desktop](https://docs.docker.com/desktop/setup/install/mac-install/) (Apple silicon or Intel) |

   On Windows and macOS, tick **Docker Desktop → Settings → General → Start
   Docker Desktop when you sign in**, so the server comes back after a
   restart.

2. Get the server files: `git clone https://github.com/nishantnkumar-cell/vault-server.git`
   then `cd vault-server`. (Without git: **Code → Download ZIP** on GitHub,
   unpack it, open a terminal in the folder.)

3. Open `compose.yaml` in a text editor and put your address from step 3 on
   the `VAULT_SERVER_HOSTS` line:

   ```yaml
       environment:
         VAULT_SERVER_HOSTS: "192.168.1.20"
   ```

   If port 8443 is taken on that computer, change the **first** number of
   `"8443:8443"` (for example `"9443:8443"`) and set
   `VAULT_SERVER_PUBLIC_PORT: "9443"`.

4. Start it (the first time takes a few minutes to build):

   ```sh
   docker compose up -d --build
   ```

5. Print what you need for step 6:

   ```sh
   docker compose exec vault-server vault-server show
   ```

   The output is the same as in 4A step 5. Everything lives in the Docker
   volume `vault-server-data`; keep it, and the fingerprint stays the same.

### 4C. macOS, without Docker

1. Install Rust as in 4A step 1, and build the same way.
2. Make a data folder and start it, with your Mac's address:

   ```sh
   mkdir -p ~/Library/Application\ Support/vault-server
   export VAULT_SERVER_DATA=~/Library/Application\ Support/vault-server
   ./target/release/vault-server --hosts 192.168.1.20 init
   ./target/release/vault-server serve
   ```

   `init` prints the same text as in 4A step 5. The server runs while that
   Terminal window is open; starting it at login comes in a later version
   (for now, use Docker Desktop if you want that).

3. The first time, macOS asks whether `vault-server` may accept incoming
   network connections: click **Allow**.

## 5. Let your other devices in (firewall)

Devices reach the server on port 8443 (or the one you picked).

| The server computer | What to do |
|---|---|
| Linux with no firewall (Debian, Ubuntu default) | Nothing |
| Linux with `ufw` | `sudo ufw allow 8443/tcp` |
| Linux with `firewalld` (Fedora) | `sudo firewall-cmd --permanent --add-port=8443/tcp` then `sudo firewall-cmd --reload` |
| macOS | Allow `vault-server` (or Docker) when macOS asks, or in **System Settings → Network → Firewall → Options** |
| Windows (Docker Desktop) | Allow Docker Desktop on **Private networks** when asked. Make sure your home network is **Private** (**Settings → Network & internet**, your network, **Network profile type**) |

Check from another computer, with your address:

```sh
curl -k https://192.168.1.20:8443/
```

It prints `{"api":1,…,"server":"vault-server",…}`. (`-k` skips the certificate
check for this test; Secret Vault checks the fingerprint instead.) If it
hangs or says `Connection refused`, check the firewall and the address.

## 6. Connect your first computer

On the computer whose vault you want to sync, unlock the vault.

**In the desktop app:** **Sync** in the sidebar → under **Cloud sync is off**,
pick **A server on my own computer (Docker)** (it works for this server
however you run it) → fill in **Server address**,
**Fingerprint** and **Admin key** from `show` → **Set up**. After a few
seconds the card says **Cloud sync is on**.

**With the command line:** copy the last line `show` printed:

```sh
vault cloud setup --server https://192.168.1.20:8443 --fingerprint tbCvXr6N001Lm6NUgBwIgyL5MjAWEOiHLXJ0gQT5dRQ
```

It asks for the admin key (paste it; it is not shown). Add
`--name "Alex's laptop"` to choose how this computer appears in the device
list.

Then make sure the sync helper `vault-sync` runs on this computer, as in
the vault user guide, chapter 15, step 3 (on Linux, `systemctl --user enable
--now vault-sync`). It is the part that talks to the server.

Check on the server: `vault-server status` (4A: run it with
`sudo -u vault-server VAULT_SERVER_DATA=/var/lib/vault-server`; 4B: with
`docker compose exec vault-server`) lists one vault with one device.

## 7. Add more devices, including your phone

On a device that already syncs, make a **join link**. It works once and for
ten minutes, and holds no password or key.

- Desktop app: **Sync → Add a device**. It shows the link and a QR code.
- Command line: `vault cloud link`

Then on the new device:

| New device | What to do |
|---|---|
| Linux or macOS desktop app | No vault yet: on the welcome screen click **I already use Secret Vault on another device**, paste the link under **With cloud sync**, **Join with the link**. Vault already unlocked there: **Sync → Join with a link from another device** |
| Command line | `vault cloud join 'https://192.168.1.20:8443/join#v1.…'` |
| iPhone or iPad | No vault yet: **Join with a Link from My Computer**. Already using the vault: **Settings → Cloud Sync → Join with a Link from My Computer**. Scan the QR code or paste the link. The phone asks once to find devices on your local network: tap **Allow** |

On a computer, start the `vault-sync` helper there too. Unlock with your
master password and the device is in. Changes reach the
other unlocked devices within about 10 seconds.

To cut off a lost or sold device: **Sync → Devices → Remove**, or
`vault cloud devices` then `vault cloud remove ID`. The server closes its
connection at once.

## 8. Day to day: status, history, undoing a bad save

Commands on the server computer (prefix them as in section 6):

| Command | What it does |
|---|---|
| `vault-server status` | Each vault: its version, size, last save, devices and their last contact |
| `vault-server show` | The address, fingerprint and admin key again |
| `vault-server history MAILBOX` | The kept versions of one vault's file (the last 20, up to 30 days) |
| `vault-server restore MAILBOX VERSION` | Make an older version the newest again |
| `vault-server backup ...` | Sealed backups: see section 9 |

**Undoing a bad save.** If a device wrote something you did not want (for
example after restoring an old backup on it), find the version from before
in `history` and `restore` it. Every device downloads it within 15 minutes
and **merges** it with what it has, so this brings back deleted or changed
items; it does not remove items added since. Deleted items you want gone
again can simply be deleted again.

## 9. Backups

The server can copy everything it holds to a place of your choice, sealed so
that only you can open it. Do this once; after that it runs by itself while
the server runs.

**What a backup holds:** every vault's current file, the devices allowed to
use it (only the fingerprint of each device key), and the server's own
certificate authority and admin key. That last part is why restoring needs
no new setup on your devices: they keep their keys and the fingerprint they
already trust.

**Step 1. Add a place for backups.** Use a USB disk, a NAS share, or a
folder that another program (OneDrive, Google Drive, Dropbox, Syncthing)
already syncs:

```sh
vault-server backup add folder /mnt/usb-disk/vault-backups
```

The first time, this shows the **backup recovery code** once. **Write it
down or print it now**, and keep it somewhere other than this computer (a
secure note in your own vault is fine, but not the only copy). It is the
only key to the backups: without it nobody can open them, you included.
The server keeps only the matching public key, so a thief of the server or
of the disk cannot read them either.

**Step 2. Make one now** and check it:

```sh
vault-server backup now
vault-server backup list
```

From then on a backup is made 10 minutes after the last change (a burst of
edits makes one backup) and at least once a day, while `vault-server serve`
runs. It is written, read back and compared, so a failing disk is noticed.
`vault-server status` shows when each target last worked, or that it is
failing and why.

**How many are kept:** the newest of each of the last 7 days, 4 weeks and 12
months; older ones are deleted from the target.

| Command | What it does |
|---|---|
| `vault-server backup add folder PATH [--name NAME]` | Add a target |
| `vault-server backup remove NAME` | Stop using a target (its files stay) |
| `vault-server backup list` | Targets, how the last backup went, snapshots kept |
| `vault-server backup now` | Make a backup right away |
| `vault-server backup restore --from TARGET` | Look inside a backup, or restore it |

Google Drive, OneDrive and Dropbox cannot be added directly yet. Until
then, point a folder target at the folder your Google Drive, OneDrive or
Dropbox app syncs; the files in it are sealed, so the provider sees nothing.
Adding them directly is planned; [preparing for it](cloud-backup-setup.md)
explains the app registration each service needs.

### Restoring after losing the server

1. Install `vault-server` on the new computer and run `vault-server init`
   (use the same `--hosts` as before, or the new address).
2. Look inside the backup. You are asked for the recovery code:

   ```sh
   vault-server backup restore --from /mnt/usb-disk/vault-backups
   ```

   It lists the vaults and their devices and **changes nothing**.
3. If you removed a device (a lost phone) after that backup was made, name it
   so it does not get its access back: `--drop DEVICE_ID` (repeat for each).
4. Restore for real, into this new, empty server:

   ```sh
   vault-server backup restore --from /mnt/usb-disk/vault-backups --drop 3f9a1c2b --confirm
   ```

5. Start the server. Your devices reconnect with their old keys and the same
   fingerprint; nothing to set up again. Add a backup target again.

A server that already has vaults refuses a restore. Use a new data folder.

**Only need one vault's file?** Take it out without a server and open it with
your master password:

```sh
vault-server backup restore --from /mnt/usb-disk/vault-backups \
    --mailbox MAILBOX_ID --out vault.svault
```

You can type the recovery code when asked, or set `VAULT_BACKUP_CODE` for a
script (it then shows in the environment, so avoid that on a shared computer).

## Moving from the old Docker server in the vault repo

The old server (`server/sync` in the vault repo) and this one speak the same
protocol. **`vault-server import` takes over the old server's data**: the
vaults' files, the devices with their keys, the certificate authority (so the
**fingerprint stays the same**) and the admin key. Your devices keep working
without joining again.

You need two things from the old server: its data folder, and the **mailbox
id** of each vault, which a device knows (the old server's files are named by a
hash, not by the id).

1. **Find the mailbox id.** On a device that uses the old server, run
   `vault cloud status`. The `mailbox:` line is a 32-character id. (Shown by
   Secret Vault versions after 0.2.0; on an older one, update the app first.)
2. **Stop the old server**, so its files are complete:

   ```sh
   cd server/sync            # in the vault repo
   docker compose down       # NOT with -v: that deletes the data
   ```

3. **Get at its data folder.** The volume is called `vault-sync-data` (with the
   compose project name in front). Find it, and copy it so the old data stays
   as it is:

   ```sh
   docker volume ls | grep vault-sync-data
   sudo cp -a "$(docker volume inspect -f '{{ .Mountpoint }}' <the volume name>)" ./old-sync-data
   ```

4. **Install vault-server** (section 4) but do not start it yet, and look at
   what the old folder holds:

   ```sh
   sudo -u vault-server VAULT_SERVER_DATA=/var/lib/vault-server vault-server import ./old-sync-data --list
   ```

   Each vault is listed with its file name and its devices, so you can tell
   them apart:

   ```
   9f8e7d6c5b4a  version 7, 5021 bytes, 2 device(s): Laptop (last seen …), iPhone (last seen …)
   ```

5. **Import.** With one vault, give its mailbox id; with several, say which
   file is which with `NAME=ID` (the start of the name is enough):

   ```sh
   sudo -u vault-server VAULT_SERVER_DATA=/var/lib/vault-server vault-server import ./old-sync-data --mailbox 0123456789abcdef0123456789abcdef
   sudo -u vault-server VAULT_SERVER_DATA=/var/lib/vault-server vault-server import ./old-sync-data --mailbox 9f8e=0123…  --mailbox a1b2=89ab…
   ```

   It refuses a server that already keeps vaults. Vaults you give no id for
   are not imported, and it says so.

6. **Start vault-server on the old address and port** (the same `--hosts`, and
   publish port 8443 as before). Devices connect as before: same address,
   same fingerprint, same keys. If the address has to change, run
   `vault cloud setup --server NEW-ADDRESS --fingerprint SAME-FINGERPRINT` on
   one device and the others follow.
7. When everything syncs, remove the old container and volume
   (`docker compose down -v` in the old `server/sync` folder) and your copy
   `./old-sync-data` (it holds the old admin key and certificate key).

**If you cannot get the data or the id,** start fresh instead; your vault
stays on every device the whole time, so nothing is lost: turn sync off on
every device (`vault cloud off`), set up with the new server (section 6), and
join each device with a new link (section 7). Each one merges its own copy.

## 10. Away from home

The server is reachable where its address is, which is usually only your
home network. Devices that leave home keep working with their own copy and
sync again when they are back. To sync away from home, use a VPN into your
home network (many routers have one built in, or use WireGuard or Tailscale)
and add the VPN address of the server computer to `VAULT_SERVER_HOSTS`, then
restart the server: it makes a new certificate for the extra address, with
the same fingerprint, so devices keep working.

Do not forward port 8443 on your router to the internet unless you know you
want that; the server is built for a home network.

## 11. Updating the server

- **Linux service (4A):** `git pull`, `cargo build --release`,
  `sudo install -m 755 target/release/vault-server /usr/local/bin/`,
  `sudo systemctl restart vault-server`.
- **Docker (4B):** `git pull`, then `docker compose up -d --build`.
- **macOS (4C):** `git pull`, `cargo build --release`, start it again.

Your vaults, devices and the fingerprint stay.

## 12. Troubleshooting

| What you see | What to do |
|---|---|
| `vault cloud setup` says the fingerprint does not match | Copy it again from `show`. If it still differs, something else answers on that address: check the address |
| `could not reach the server` | Check section 5 (firewall), that the server runs (`systemctl status vault-server` or `docker compose ps`), and that the device is on the home network |
| `the certificate is not valid for` the address | Add that name or address to `VAULT_SERVER_HOSTS` and restart the server |
| `wrong admin key` | Copy it again from `show` (it is also in the file `admin-key` in the data folder) |
| `this join link was used already or has expired` | Make a new link; each works once, for ten minutes |
| `vault-server status` says `no server data` | Point it at the data folder: `VAULT_SERVER_DATA=/var/lib/vault-server` (and run as the `vault-server` user) |
| The service does not start | `journalctl -u vault-server -n 50` shows why |

## 13. Differences between Linux, macOS and Windows

| | Linux | macOS | Windows |
|---|---|---|---|
| Run the server without Docker | Yes, as a systemd service that starts at boot | Yes, from Terminal; starting at login comes later | No |
| Run the server in Docker | Docker Engine | Docker Desktop | Docker Desktop (WSL 2) |
| Where its data is | `/var/lib/vault-server` (service) or the Docker volume | The folder you chose, or the Docker volume | The Docker volume |
| Firewall step | `ufw` / `firewalld` if used | Allow when asked | Allow on Private networks |
| Sync from the vault apps | Desktop app and `vault` | Desktop app and `vault` | The Windows app is on hold; it uses the same protocol |
| iPhone and iPad | Join with link or QR, any server computer | | |

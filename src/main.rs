//! The `vault-server` command. See docs/user-guide.md.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::ExitCode;

use anyhow::{Result, bail};
use clap::{Args, Parser, Subcommand};

use vault_server::api::when;
use vault_server::backup;
use vault_server::import;
use vault_server::server::{self, Config};
use vault_server::store::Store;
use vault_server::{tls, util};

#[derive(Parser)]
#[command(
    name = "vault-server",
    version,
    about = "Sync server for Secret Vault: keeps each vault's encrypted file for its devices."
)]
struct Cli {
    #[command(flatten)]
    common: Common,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Args)]
struct Common {
    /// The data folder (keys, certificates, the database).
    #[arg(
        long,
        env = "VAULT_SERVER_DATA",
        default_value = "/var/lib/vault-server",
        global = true
    )]
    data: PathBuf,
    /// Names and addresses other devices use to reach this computer,
    /// comma-separated, such as "vault.home.example,192.168.1.20".
    #[arg(long, env = "VAULT_SERVER_HOSTS", default_value = "", global = true)]
    hosts: String,
    /// Where to listen for HTTPS.
    #[arg(
        long,
        env = "VAULT_SERVER_LISTEN",
        default_value = "0.0.0.0:8443",
        global = true
    )]
    listen: SocketAddr,
    /// The port devices connect to, when it differs from the one in --listen
    /// (for example when Docker publishes another port).
    #[arg(long, env = "VAULT_SERVER_PUBLIC_PORT", global = true)]
    public_port: Option<u16>,
}

#[derive(Subcommand)]
enum Cmd {
    /// Make the keys and certificates (if needed) and print how to connect.
    Init,
    /// Run the server.
    Serve {
        /// Also serve plain HTTP on this computer only (127.0.0.1), for tests.
        #[arg(long, env = "VAULT_SERVER_HTTP_LOOPBACK")]
        http_loopback: Option<SocketAddr>,
    },
    /// Print the address, fingerprint and admin key again.
    Show,
    /// List the vaults (mailboxes) this server keeps, with their devices.
    Status,
    /// List the kept versions of one vault's file.
    History {
        /// The mailbox id (32 hex characters, from `vault-server status`).
        mailbox: String,
    },
    /// Make an older version of a vault's file the newest again.
    Restore {
        mailbox: String,
        /// The version number, from `vault-server history`.
        version: i64,
    },
    /// Take over the data of the old Docker sync server (the workerd one in
    /// the vault repo): devices keep working with the same keys and
    /// fingerprint. Stop the old server first.
    Import {
        /// The old server's data folder (the Docker volume's contents, with
        /// `mailboxes/`, `tls/` and `admin-key`).
        folder: PathBuf,
        /// Only list the vaults found, with their devices.
        #[arg(long)]
        list: bool,
        /// Which vault each file is, as its 32-character mailbox id from a
        /// device (`vault cloud status`): `ID` when there is one file, else
        /// `NAME=ID` with the name from `--list` (a unique start is enough).
        #[arg(long = "mailbox")]
        mailbox: Vec<String>,
    },
    /// Sealed backups of everything this server keeps.
    Backup {
        #[command(subcommand)]
        cmd: BackupCmd,
    },
}

#[derive(Subcommand)]
enum BackupCmd {
    /// Add a place to keep backups: `folder PATH` (a USB disk, NAS share or a
    /// folder some other program syncs). The first one makes the backup key
    /// and shows its recovery code once.
    Add {
        /// folder (google, onedrive and dropbox need this program's cloud
        /// registration and are not available yet)
        kind: String,
        path: Option<PathBuf>,
        /// A short name for the target (default folder1, folder2, ...).
        #[arg(long)]
        name: Option<String>,
    },
    /// Stop using a backup target (its files stay where they are).
    Remove { name: String },
    /// List the targets, how the last backup went, and the snapshots kept.
    List,
    /// Make a backup now.
    Now,
    /// Open a backup: list its devices, or put it into a new, empty server.
    Restore {
        /// A target name, a folder of snapshots, or one `.svbak` file.
        #[arg(long)]
        from: String,
        /// Which snapshot (default: the newest).
        #[arg(long)]
        snapshot: Option<String>,
        /// Leave this device out (one removed after the backup was made).
        #[arg(long = "drop")]
        drop: Vec<String>,
        /// Really restore (without it only the contents are shown).
        #[arg(long)]
        confirm: bool,
        /// With --out: take just this vault's file out of the backup.
        #[arg(long, requires = "out")]
        mailbox: Option<String>,
        #[arg(long)]
        out: Option<PathBuf>,
    },
}

fn config(c: &Common, http_loopback: Option<SocketAddr>) -> Result<Config> {
    let mut cfg = Config {
        data: c.data.clone(),
        listen: c.listen,
        hosts: tls::parse_hosts(&c.hosts),
        public_port: c.public_port,
        admin_key: std::env::var("ADMIN_KEY").ok(),
        http_loopback,
        limits: Default::default(),
    };
    server::remember_hosts(&mut cfg)?;
    Ok(cfg)
}

fn open_store(c: &Common) -> Result<Store> {
    let p = server::db_path(&c.data);
    if !p.exists() {
        bail!(
            "no server data in {} yet: run `vault-server init` first (or pass --data)",
            c.data.display()
        );
    }
    Store::open(&p)
}

fn mailbox_arg(m: &str) -> Result<()> {
    if !util::is_hex(m, 32) {
        bail!("a mailbox id is 32 lowercase hex characters, as `vault-server status` lists them");
    }
    Ok(())
}

async fn run(cli: Cli) -> Result<()> {
    match cli.cmd {
        Cmd::Init => {
            let cfg = config(&cli.common, None)?;
            let p = server::prepare(&cfg)?;
            // Make the database too, so `status` works before the first start.
            Store::open(&server::db_path(&cfg.data))?;
            if p.made_ca {
                println!("Made this server's own certificate authority and admin key.\n");
            }
            print!("{}", server::show(&cfg, &p, true));
        }
        Cmd::Show => {
            let cfg = config(&cli.common, None)?;
            let p = server::prepare(&cfg)?;
            print!("{}", server::show(&cfg, &p, true));
        }
        Cmd::Serve { http_loopback } => {
            let cfg = config(&cli.common, http_loopback)?;
            let running = server::start(&cfg).await?;
            let p = server::prepare(&cfg)?;
            for line in server::show(&cfg, &p, false).lines() {
                tracing::info!("{line}");
            }
            tracing::info!(
                "listening on {} (TLS 1.3, post-quantum key exchange X25519MLKEM768 preferred)",
                running.https
            );
            if let Some(h) = running.http {
                tracing::warn!("also plain HTTP on {h}, for this computer only");
            }
            tokio::spawn(backup::schedule(cfg.data.clone()));
            tokio::select! {
                _ = running_wait(running) => bail!("the server stopped"),
                _ = shutdown() => tracing::info!("stopping"),
            }
        }
        Cmd::Status => {
            let store = open_store(&cli.common)?;
            let list = store.mailboxes()?;
            if list.is_empty() {
                println!(
                    "No vaults yet. Run `vault cloud setup --server ...` on your first computer."
                );
            }
            print_backup_summary(&cli.common.data);
            for m in list {
                println!(
                    "{}  version {}, {} bytes, saved {}, {} device(s), {} version(s) kept",
                    m.id,
                    m.version,
                    m.size.unwrap_or(0),
                    m.saved.map(when).unwrap_or_else(|| "never".into()),
                    m.devices,
                    m.history
                );
                for d in store.devices(&m.id)? {
                    println!("    {}  {}  last seen {}", d.id, d.name, when(d.seen));
                }
            }
        }
        Cmd::Backup { cmd } => backup_cmd(&cli.common, cmd)?,
        Cmd::Import {
            folder,
            list,
            mailbox,
        } => import_cmd(&cli.common, &folder, list, &mailbox)?,
        Cmd::History { mailbox } => {
            mailbox_arg(&mailbox)?;
            let store = open_store(&cli.common)?;
            if store.version(&mailbox)?.is_none() {
                bail!("no such mailbox");
            }
            for v in store.history(&mailbox)? {
                println!(
                    "version {:>6}  {}  {} bytes",
                    v.version,
                    when(v.saved),
                    v.size
                );
            }
        }
        Cmd::Restore { mailbox, version } => {
            mailbox_arg(&mailbox)?;
            let mut store = open_store(&cli.common)?;
            match store.restore(&mailbox, version)? {
                Some(v) => println!(
                    "Version {version} is now the newest (version {v}). Devices pick it up within 15 minutes\nand merge it with what they have; nothing on them is lost."
                ),
                None => bail!("that version is not kept; see `vault-server history {mailbox}`"),
            }
        }
    }
    Ok(())
}

fn import_cmd(c: &Common, folder: &std::path::Path, list: bool, given: &[String]) -> Result<()> {
    let old = import::scan(folder)?;
    if old.is_empty() {
        bail!("no mailboxes found under {}/mailboxes", folder.display());
    }
    if list || given.is_empty() {
        println!("Vaults found in {}:", folder.display());
        for m in &old {
            println!("  {}", import::describe(m));
        }
        if !list {
            println!(
                "\nTo import, say which vault each is, using the mailbox id from one of its devices\n(`vault cloud status`). With one vault: --mailbox ID. With several:\n--mailbox NAME=ID for each, where NAME is the start of the name above."
            );
        }
        return Ok(());
    }
    let given: Vec<import::Assignment> = given
        .iter()
        .map(|g| match g.split_once('=') {
            Some((n, id)) => (Some(n.to_string()), id.to_string()),
            None => (None, g.to_string()),
        })
        .collect();
    let picked = import::assign(&old, &given)?;
    let report = import::import(&c.data, folder, &old, &picked)?;
    println!(
        "Imported {} vault(s) with {} device(s).",
        report.mailboxes, report.devices
    );
    if report.kept_authority {
        println!("The old certificate authority was kept, so the fingerprint is unchanged.");
    } else {
        println!(
            "The old server had no certificate authority in {}/tls: this server makes its own, and devices must set up again with its new fingerprint.",
            folder.display()
        );
    }
    if report.kept_admin_key {
        println!("The old admin key was kept.");
    }
    if !report.left_out.is_empty() {
        println!(
            "Not imported (no --mailbox given): {}",
            report.left_out.join(", ")
        );
    }
    println!(
        "\nNext: stop the old server, start this one on the same address and port\n(`vault-server serve`, with the same --hosts), and the devices keep working:\nnothing to set up again. If the address changes, run `vault cloud setup --server`\nagain on one device with the new address and the same fingerprint."
    );
    Ok(())
}

fn print_backup_summary(data: &std::path::Path) {
    let targets = backup::targets(data);
    if targets.is_empty() {
        println!("Backups: none yet (`vault-server backup add folder PATH`).");
        return;
    }
    let st = backup::statuses(data);
    for t in targets {
        let s = st.get(&t.name).cloned().unwrap_or_default();
        match (s.ok, s.error) {
            (Some(ok), None) => println!("Backup {}: last good {}", t.name, when(ok)),
            (ok, Some(e)) => println!(
                "Backup {}: FAILING ({e}); last good {}",
                t.name,
                ok.map(when).unwrap_or_else(|| "never".into())
            ),
            (None, None) => println!("Backup {}: not made yet", t.name),
        }
    }
}

fn read_code() -> Result<[u8; 32]> {
    use std::io::Write;
    let text = match std::env::var("VAULT_BACKUP_CODE") {
        Ok(v) if !v.trim().is_empty() => v,
        _ => {
            eprint!("Backup recovery code: ");
            std::io::stderr().flush().ok();
            let mut l = String::new();
            std::io::stdin().read_line(&mut l)?;
            l
        }
    };
    backup::parse_code(&text)
}

/// Finds the sealed bytes for `--from` (a target name, a folder or a file).
fn find_snapshot(data: &std::path::Path, from: &str, which: Option<&str>) -> Result<Vec<u8>> {
    let as_target = backup::targets(data).into_iter().find(|t| t.name == from);
    let folder = match &as_target {
        Some(t) => t.clone(),
        None => {
            let p = std::path::Path::new(from);
            if p.is_file() {
                return Ok(std::fs::read(p)?);
            }
            backup::Target {
                name: from.into(),
                kind: "folder".into(),
                path: from.into(),
            }
        }
    };
    let list = folder.list()?;
    let name = match which {
        Some(n) => n.to_string(),
        None => list
            .last()
            .map(|x| x.0.clone())
            .ok_or_else(|| anyhow::anyhow!("no backups found in {from}"))?,
    };
    folder.get(&name)
}

fn backup_cmd(c: &Common, cmd: BackupCmd) -> Result<()> {
    let data = &c.data;
    match cmd {
        BackupCmd::Add { kind, path, name } => match kind.as_str() {
            "folder" => {
                let Some(path) = path else {
                    bail!("usage: vault-server backup add folder PATH");
                };
                let code = backup::add_folder(data, name.as_deref(), &path)?;
                println!("Added the backup folder {}.", path.display());
                if let Some(code) = code {
                    println!(
                        "\nBACKUP RECOVERY CODE (shown once; print it or keep it in your vault):\n\n    {code}\n\nWithout it nobody can open the backups, you included. With it, anyone who\nhas a backup file can. This server keeps only the matching public key."
                    );
                }
                println!(
                    "\nA backup is made 10 minutes after the last change and at least daily while\n`vault-server serve` runs. Make one now with `vault-server backup now`."
                );
            }
            "google" | "onedrive" | "dropbox" => bail!(
                "{kind} backups are not available yet: they need this program registered with {kind}. \
                 Use `backup add folder PATH` with a folder that your {kind} app syncs for now."
            ),
            other => bail!("unknown backup kind {other}; use folder"),
        },
        BackupCmd::Remove { name } => {
            backup::remove_target(data, &name)?;
            println!("Removed {name}. Its files were left where they are.");
        }
        BackupCmd::List => {
            print_backup_summary(data);
            for t in backup::targets(data) {
                println!("\n{}  ({}, {})", t.name, t.kind, t.path);
                match t.list() {
                    Ok(l) if l.is_empty() => println!("    no snapshots yet"),
                    Ok(l) => {
                        for (n, ms) in l.iter().rev() {
                            println!("    {n}  {}", when(*ms));
                        }
                    }
                    Err(e) => println!("    cannot read: {e:#}"),
                }
            }
        }
        BackupCmd::Now => {
            let mut store = open_store(c)?;
            let mut bad = 0;
            for (t, r) in backup::run_once(data, &mut store)? {
                match r {
                    Ok(n) => println!("{t}: wrote {n}"),
                    Err(e) => {
                        bad += 1;
                        eprintln!("{t}: FAILED: {e:#}");
                    }
                }
            }
            if bad > 0 {
                bail!("{bad} backup target(s) failed");
            }
        }
        BackupCmd::Restore {
            from,
            snapshot,
            drop,
            confirm,
            mailbox,
            out,
        } => {
            let blob = find_snapshot(data, &from, snapshot.as_deref())?;
            let snap = backup::read_snapshot(read_code()?, &blob)?;
            if let (Some(id), Some(out)) = (&mailbox, &out) {
                mailbox_arg(id)?;
                let m = snap
                    .mailboxes
                    .iter()
                    .find(|m| &m.id == id)
                    .ok_or_else(|| anyhow::anyhow!("that backup has no such vault"))?;
                let Some(f) = &m.file else {
                    bail!("that vault was still empty in this backup");
                };
                std::fs::write(out, data_encoding::BASE64URL_NOPAD.decode(f.as_bytes())?)?;
                println!(
                    "Wrote {}: open it with your master password (`vault sync on` / `vaultd --vault`).",
                    out.display()
                );
                return Ok(());
            }
            println!("Backup made {}:", when(snap.created));
            for m in &snap.mailboxes {
                println!("  vault {}  version {}", m.id, m.version);
                for d in &m.devices {
                    let dropped = if drop.contains(&d.id) {
                        "  (will be left out)"
                    } else {
                        ""
                    };
                    println!(
                        "      device {}  {}  last seen {}{dropped}",
                        d.id,
                        d.name,
                        when(d.seen)
                    );
                }
            }
            if !confirm {
                println!(
                    "\nNothing was changed. If a device above was removed after this backup, add\n`--drop DEVICE` for it, then run again with `--confirm` to restore into this\nnew, empty server."
                );
                return Ok(());
            }
            backup::restore(data, &snap, &drop)?;
            println!(
                "\nRestored. Start the server (`vault-server serve`); devices reconnect with their\nold keys and the same fingerprint. Add a backup target again with `backup add`."
            );
        }
    }
    Ok(())
}

async fn running_wait(r: server::Running) {
    r.wait().await
}

async fn shutdown() {
    let ctrl_c = tokio::signal::ctrl_c();
    #[cfg(unix)]
    {
        let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("signal handler");
        tokio::select! {
            _ = ctrl_c => {},
            _ = term.recv() => {},
        }
    }
    #[cfg(not(unix))]
    let _ = ctrl_c.await;
}

#[tokio::main]
async fn main() -> ExitCode {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .with_target(false)
        .with_ansi(std::io::IsTerminal::is_terminal(&std::io::stdout()))
        .init();
    match run(Cli::parse()).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("vault-server: {e:#}");
            ExitCode::FAILURE
        }
    }
}

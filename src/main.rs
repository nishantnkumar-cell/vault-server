//! The `vault-server` command. See docs/user-guide.md.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::ExitCode;

use anyhow::{Result, bail};
use clap::{Args, Parser, Subcommand};

use vault_server::api::when;
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
}

fn config(c: &Common, http_loopback: Option<SocketAddr>) -> Result<Config> {
    let mut cfg = Config {
        data: c.data.clone(),
        listen: c.listen,
        hosts: tls::parse_hosts(&c.hosts),
        public_port: c.public_port,
        admin_key: std::env::var("ADMIN_KEY").ok(),
        http_loopback,
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

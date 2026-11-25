//! Starting the server: the data folder, keys, certificates and listeners.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use hyper::service::{Service, service_fn};
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use hyper_util::server::conn::auto;
use hyper_util::service::TowerToHyperService;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

use crate::api::{self, Shared};
use crate::limits::{Activity, Gate, Limits};
use crate::store::Store;
use crate::{files, tls, util};

/// Where everything lives and how to reach it.
#[derive(Clone, Debug)]
pub struct Config {
    /// The data folder: `admin-key`, `tls/`, `vault-server.db`.
    pub data: PathBuf,
    /// Where to listen for HTTPS.
    pub listen: SocketAddr,
    /// Names and addresses devices use to reach this computer.
    pub hosts: Vec<String>,
    /// The port devices connect to, when it differs from `listen`'s (Docker).
    pub public_port: Option<u16>,
    /// An admin key from the environment instead of `admin-key`.
    pub admin_key: Option<String>,
    /// Plain HTTP on this computer only, for tests and development.
    pub http_loopback: Option<SocketAddr>,
    /// How many connections, and how long they may be quiet.
    pub limits: Limits,
}

/// What [`prepare`] found or made.
pub struct Prepared {
    pub admin_key: String,
    pub ca_pem: String,
    pub fingerprint: String,
    pub names: Vec<String>,
    pub made_ca: bool,
}

pub fn tls_dir(data: &Path) -> PathBuf {
    data.join("tls")
}

pub fn db_path(data: &Path) -> PathBuf {
    data.join("vault-server.db")
}

/// Host names are remembered in `<data>/hosts`: given ones replace them,
/// none given means the remembered ones. So `serve` without `--hosts` keeps
/// what `init --hosts` set.
pub fn remember_hosts(cfg: &mut Config) -> Result<()> {
    let p = cfg.data.join("hosts");
    if cfg.hosts.is_empty() {
        if let Ok(s) = std::fs::read_to_string(&p) {
            cfg.hosts = tls::parse_hosts(&s);
        }
    } else {
        files::private_dir(&cfg.data)?;
        files::write_private(&p, cfg.hosts.join(",").as_bytes())?;
    }
    Ok(())
}

/// Makes the data folder, the admin key, the certificate authority and the
/// server certificate as needed. Safe to run on every start.
pub fn prepare(cfg: &Config) -> Result<Prepared> {
    files::private_dir(&cfg.data)?;
    let tdir = tls_dir(&cfg.data);
    files::private_dir(&tdir)?;
    let admin_key = match &cfg.admin_key {
        Some(k) if !k.trim().is_empty() => k.trim().to_owned(),
        _ => {
            let p = cfg.data.join("admin-key");
            match std::fs::read_to_string(&p) {
                Ok(k) if !k.trim().is_empty() => k.trim().to_owned(),
                _ => {
                    let k = util::random_token();
                    files::write_private(&p, k.as_bytes())?;
                    k
                }
            }
        }
    };
    let made_ca = tls::ensure_ca(&tdir)?;
    let names = tls::names(&cfg.hosts);
    tls::ensure_server_cert(&tdir, &names)?;
    Ok(Prepared {
        admin_key,
        ca_pem: std::fs::read_to_string(tdir.join("ca.pem"))?,
        fingerprint: tls::ca_fingerprint(&tdir)?,
        names,
        made_ca,
    })
}

/// The address devices should use: the first host given, or a placeholder.
pub fn address(cfg: &Config) -> String {
    let port = cfg.public_port.unwrap_or(cfg.listen.port());
    match cfg.hosts.first() {
        Some(h) if h.contains(':') => format!("https://[{h}]:{port}"),
        Some(h) => format!("https://{h}:{port}"),
        None => format!("https://<this computer's address>:{port}"),
    }
}

/// The text `vault-server show` prints. With `secret`, the admin key too.
pub fn show(cfg: &Config, p: &Prepared, secret: bool) -> String {
    let addr = address(cfg);
    let mut s = format!(
        "Secret Vault server (vault-server {})\n  address:      {addr}\n  certificate:  {}\n  fingerprint:  {}\n",
        env!("CARGO_PKG_VERSION"),
        p.names.join(", "),
        p.fingerprint
    );
    if secret {
        s.push_str(&format!("  admin key:    {}\n", p.admin_key));
    } else {
        s.push_str("  admin key:    run `vault-server show` to see it\n");
    }
    let setup_addr = if cfg.hosts.is_empty() {
        "https://ADDRESS:PORT".to_owned()
    } else {
        addr
    };
    s.push_str(&format!(
        "\nOn the first computer, with the vault unlocked:\n  vault cloud setup --server {setup_addr} --fingerprint {}\n",
        p.fingerprint
    ));
    if cfg.hosts.is_empty() {
        s.push_str(
            "\nNo host names are set yet: add this computer's name or fixed IP address\n(--hosts or VAULT_SERVER_HOSTS) so other devices can reach it.\n",
        );
    }
    s
}

/// A running server, for tests and `serve`.
pub struct Running {
    pub https: SocketAddr,
    pub http: Option<SocketAddr>,
    pub shared: Arc<Shared>,
    tasks: Vec<tokio::task::JoinHandle<()>>,
}

impl Running {
    /// Runs until either listener stops (they only stop on an error).
    pub async fn wait(mut self) {
        if let Some(t) = self.tasks.pop() {
            let _ = t.await;
        }
    }

    pub fn stop(&self) {
        for t in &self.tasks {
            t.abort();
        }
    }
}

/// Answers one connection until it ends or has been quiet too long. A
/// connection that becomes a WebSocket finishes here and carries on by itself.
async fn serve<I>(stream: I, app: axum::Router, limits: Limits)
where
    I: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let activity = Activity::default();
    let seen = activity.clone();
    let inner = TowerToHyperService::new(app);
    let svc = service_fn(move |req| {
        let busy = seen.request();
        let answer = inner.call(req);
        async move {
            let r = answer.await;
            drop(busy);
            r
        }
    });
    let mut builder = auto::Builder::new(TokioExecutor::new());
    builder
        .http1()
        .timer(TokioTimer::new())
        .header_read_timeout(limits.first_request);
    builder
        .http2()
        .timer(TokioTimer::new())
        .max_concurrent_streams(32)
        .keep_alive_interval(Some(Duration::from_secs(30)))
        .keep_alive_timeout(Duration::from_secs(10));
    let connection = builder.serve_connection_with_upgrades(TokioIo::new(stream), svc);
    tokio::pin!(connection);
    let tick = (limits.first_request.min(limits.idle) / 4).max(Duration::from_millis(50));
    loop {
        tokio::select! {
            _ = connection.as_mut() => return,
            _ = tokio::time::sleep(tick) => {
                if activity.expired(&limits) {
                    return; // dropping the connection closes it
                }
            }
        }
    }
}

/// Prepares and starts listening. Returns once the sockets are bound.
pub async fn start(cfg: &Config) -> Result<Running> {
    let p = prepare(cfg)?;
    let store = Store::open(&db_path(&cfg.data)).context("opening the database")?;
    let shared = Shared::new(store, p.admin_key.clone(), Some(p.ca_pem.clone()));
    let app = api::router(shared.clone());
    let acceptor = TlsAcceptor::from(tls::server_config(&tls_dir(&cfg.data))?);

    let https = TcpListener::bind(cfg.listen)
        .await
        .with_context(|| format!("listening on {}", cfg.listen))?;
    let https_addr = https.local_addr()?;
    let mut tasks = Vec::new();

    let tls_app = app.clone();
    let limits = cfg.limits;
    let gate = Gate::new(limits);
    tasks.push(tokio::spawn(async move {
        loop {
            let (tcp, peer) = match https.accept().await {
                Ok(c) => c,
                Err(e) => {
                    // Out of file handles, for example: wait, do not spin.
                    tracing::warn!("cannot accept a connection: {e}");
                    tokio::time::sleep(Duration::from_millis(200)).await;
                    continue;
                }
            };
            // No room: close it at once, so that the others stay responsive.
            let Some(place) = gate.enter(peer.ip()) else {
                tracing::debug!("too many connections; refusing one from {peer}");
                continue;
            };
            let acceptor = acceptor.clone();
            let app = tls_app.clone();
            tokio::spawn(async move {
                let _place = place;
                let stream =
                    match tokio::time::timeout(limits.handshake, acceptor.accept(tcp)).await {
                        Ok(Ok(s)) => s,
                        Ok(Err(e)) => {
                            tracing::debug!("TLS handshake with {peer} failed: {e}");
                            return;
                        }
                        Err(_) => return,
                    };
                serve(stream, app, limits).await;
            });
        }
    }));

    let mut http_addr = None;
    if let Some(addr) = cfg.http_loopback {
        if !addr.ip().is_loopback() {
            bail!("plain HTTP is only allowed on 127.0.0.1 or ::1, not {addr}");
        }
        let l = TcpListener::bind(addr)
            .await
            .with_context(|| format!("listening on {addr}"))?;
        http_addr = Some(l.local_addr()?);
        tasks.insert(
            0,
            tokio::spawn(async move {
                let _ = axum::serve(l, app).await;
            }),
        );
    }

    Ok(Running {
        https: https_addr,
        http: http_addr,
        shared,
        tasks,
    })
}

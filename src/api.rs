//! The sync API, version 1: the same calls, answers and limits as the
//! Cloudflare Worker in the vault repo (`server/sync/src/index.js`), so every
//! Secret Vault client works with either. See docs/api.md.

use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use axum::Router;
use axum::body::{Body, to_bytes};
use axum::extract::ws::rejection::WebSocketUpgradeRejection;
use axum::extract::ws::{CloseFrame, Message, WebSocket, WebSocketUpgrade};
use axum::extract::{Path, State};
use axum::http::{HeaderMap, HeaderValue, Method, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{any, get};
use tokio::sync::broadcast;

use crate::store::{Join, MAX_DEVICES, Save, Store};
use crate::util::{is_hex, is_token, same_secret};

/// Bumped when the API gains something clients may check for. 2 = `/ca.pem`,
/// matching the Worker's revision.
pub const REVISION: u32 = 2;
/// Largest vault file accepted.
pub const MAX_FILE: usize = 4 * 1024 * 1024;
/// Saves per mailbox per minute before 429.
pub const MAX_WRITES_PER_MINUTE: usize = 60;
/// Open watch sockets per mailbox.
pub const MAX_WATCHERS: usize = 32;

/// What watchers of a mailbox hear.
#[derive(Clone, Debug)]
enum Event {
    Version(i64),
    Removed(String),
    Deleted,
}

pub struct Shared {
    pub store: Mutex<Store>,
    pub admin_key: String,
    pub ca_pem: Option<String>,
    hubs: Mutex<HashMap<String, broadcast::Sender<Event>>>,
    writes: Mutex<HashMap<String, VecDeque<Instant>>>,
}

impl Shared {
    pub fn new(store: Store, admin_key: String, ca_pem: Option<String>) -> Arc<Shared> {
        Arc::new(Shared {
            store: Mutex::new(store),
            admin_key,
            ca_pem,
            hubs: Mutex::new(HashMap::new()),
            writes: Mutex::new(HashMap::new()),
        })
    }

    fn store(&self) -> std::sync::MutexGuard<'_, Store> {
        self.store.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn hub(&self, mailbox: &str) -> broadcast::Sender<Event> {
        self.hubs
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .entry(mailbox.to_owned())
            .or_insert_with(|| broadcast::channel(64).0)
            .clone()
    }

    fn notify(&self, mailbox: &str, ev: Event) {
        if let Some(h) = self
            .hubs
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(mailbox)
        {
            let _ = h.send(ev);
        }
    }

    /// Sliding one-minute window: a soft limit against a runaway client.
    fn rate_limited(&self, mailbox: &str) -> bool {
        let now = Instant::now();
        let mut all = self.writes.lock().unwrap_or_else(|e| e.into_inner());
        let w = all.entry(mailbox.to_owned()).or_default();
        while w
            .front()
            .is_some_and(|t| now.duration_since(*t) >= Duration::from_secs(60))
        {
            w.pop_front();
        }
        if w.len() >= MAX_WRITES_PER_MINUTE {
            return true;
        }
        w.push_back(now);
        false
    }
}

type St = State<Arc<Shared>>;

fn no_store(mut r: Response) -> Response {
    r.headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    r
}

fn text(status: StatusCode, body: &str) -> Response {
    no_store(
        (
            status,
            [(header::CONTENT_TYPE, "text/plain; charset=utf-8")],
            format!("{body}\n"),
        )
            .into_response(),
    )
}

fn json(status: StatusCode, v: serde_json::Value) -> Response {
    no_store((status, axum::Json(v)).into_response())
}

fn with_etag(mut r: Response, version: i64) -> Response {
    if let Ok(v) = HeaderValue::from_str(&format!("\"{version}\"")) {
        r.headers_mut().insert(header::ETAG, v);
    }
    r
}

fn server_error(e: anyhow::Error) -> Response {
    tracing::error!("{e:#}");
    text(
        StatusCode::INTERNAL_SERVER_ERROR,
        "the server could not do that",
    )
}

/// "12", "\"12\"" or W/"12" -> 12; anything else -> None.
pub fn parse_tag(h: Option<&HeaderValue>) -> Option<i64> {
    let s = h?.to_str().ok()?.trim();
    let s = s.strip_prefix("W/").unwrap_or(s);
    let s = s.strip_prefix('"').unwrap_or(s);
    let s = s.strip_suffix('"').unwrap_or(s);
    if s.is_empty() || s.len() > 15 || !s.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    s.parse().ok()
}

fn bearer(h: &HeaderMap) -> Option<String> {
    let v = h.get(header::AUTHORIZATION)?.to_str().ok()?;
    let t = v.strip_prefix("Bearer ")?;
    is_token(t).then(|| t.to_owned())
}

fn device_name(h: &HeaderMap) -> String {
    let raw = h
        .get("x-device-name")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let clean: String = raw.chars().filter(|c| !c.is_control()).collect();
    let name: String = clean.trim().chars().take(64).collect();
    if name.is_empty() {
        "device".into()
    } else {
        name
    }
}

const JOIN_PAGE: &str = r#"<!doctype html><meta charset="utf-8"><meta name="viewport" content="width=device-width">
<title>Join a Secret Vault</title>
<body style="font:16px/1.5 system-ui,sans-serif;max-width:36em;margin:2em auto;padding:0 1em">
<h1>Join a Secret Vault</h1>
<p>This link adds a device to a vault's cloud sync. Open it with Secret Vault instead of a browser:</p>
<ul><li>Desktop app: <b>Sync</b> &rarr; <b>Join with a link</b>, and paste it.</li>
<li>Command line: <code>vault cloud join '&lt;the link&gt;'</code></li>
<li>iPhone or iPad: <b>Settings</b> &rarr; <b>Cloud Sync</b> &rarr; <b>Join</b>, or scan the QR code.</li></ul>
<p>The link works once and for ten minutes. It holds no password or key: you still unlock with your master password.</p>
</body>"#;

pub fn router(shared: Arc<Shared>) -> Router {
    Router::new()
        .route("/", get(info))
        .route("/v1", get(info))
        .route("/ca.pem", get(ca_pem))
        .route("/join", get(join_page))
        .route("/v1/m/{id}", any(mailbox))
        .route("/v1/m/{id}/{sub}", any(mailbox_sub))
        .route("/v1/m/{id}/{sub}/{arg}", any(mailbox_arg))
        .fallback(|| async { text(StatusCode::NOT_FOUND, "not found") })
        .with_state(shared)
}

async fn info() -> Response {
    json(
        StatusCode::OK,
        serde_json::json!({
            "service": "secret-vault-sync",
            "api": 1,
            "revision": REVISION,
            "server": "vault-server",
            "version": env!("CARGO_PKG_VERSION"),
        }),
    )
}

async fn ca_pem(State(s): St) -> Response {
    match &s.ca_pem {
        Some(p) => no_store(
            (
                [(header::CONTENT_TYPE, "application/x-pem-file")],
                p.clone(),
            )
                .into_response(),
        ),
        None => text(
            StatusCode::NOT_FOUND,
            "this server uses a public certificate",
        ),
    }
}

async fn join_page() -> Response {
    no_store(
        (
            [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
            JOIN_PAGE,
        )
            .into_response(),
    )
}

async fn mailbox(
    st: St,
    Path(id): Path<String>,
    method: Method,
    headers: HeaderMap,
    body: Body,
) -> Response {
    handle(st, id, String::new(), None, method, headers, body, None).await
}

async fn mailbox_sub(
    st: St,
    Path((id, sub)): Path<(String, String)>,
    method: Method,
    headers: HeaderMap,
    ws: Result<WebSocketUpgrade, WebSocketUpgradeRejection>,
    body: Body,
) -> Response {
    handle(st, id, sub, None, method, headers, body, ws.ok()).await
}

async fn mailbox_arg(
    st: St,
    Path((id, sub, arg)): Path<(String, String, String)>,
    method: Method,
    headers: HeaderMap,
    body: Body,
) -> Response {
    handle(st, id, sub, Some(arg), method, headers, body, None).await
}

#[allow(clippy::too_many_arguments)]
async fn handle(
    State(s): St,
    id: String,
    sub: String,
    arg: Option<String>,
    method: Method,
    headers: HeaderMap,
    body: Body,
    ws: Option<WebSocketUpgrade>,
) -> Response {
    if !matches!(sub.as_str(), "" | "tickets" | "join" | "devices" | "watch") {
        return text(StatusCode::NOT_FOUND, "not found");
    }
    if arg.is_some() && sub != "devices" {
        return text(StatusCode::NOT_FOUND, "not found");
    }
    if !is_hex(&id, 32) {
        return text(
            StatusCode::BAD_REQUEST,
            "mailbox id must be 32 lowercase hex characters",
        );
    }
    if method == Method::POST && sub.is_empty() {
        let given = headers
            .get("x-admin-key")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        if !same_secret(given, &s.admin_key) {
            return text(StatusCode::FORBIDDEN, "wrong admin key");
        }
    }
    let Some(token) = bearer(&headers) else {
        return text(StatusCode::UNAUTHORIZED, "missing or malformed token");
    };

    let exists = match s.store().version(&id) {
        Ok(v) => v.is_some(),
        Err(e) => return server_error(e),
    };

    if method == Method::POST && sub.is_empty() {
        if exists {
            return text(StatusCode::CONFLICT, "mailbox already exists");
        }
        return match s.store().create(&id, &token, &device_name(&headers)) {
            Ok(Some(dev)) => json(StatusCode::CREATED, serde_json::json!({ "device": dev })),
            Ok(None) => text(StatusCode::CONFLICT, "mailbox already exists"),
            Err(e) => server_error(e),
        };
    }
    if !exists {
        return text(StatusCode::UNAUTHORIZED, "unknown mailbox or wrong token");
    }

    if method == Method::POST && sub == "join" {
        let ticket = headers
            .get("x-ticket")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        if !is_token(ticket) {
            return text(StatusCode::BAD_REQUEST, "X-Ticket is missing or malformed");
        }
        return match s.store().join(&id, ticket, &token, &device_name(&headers)) {
            Ok(Join::Joined(dev)) => {
                json(StatusCode::CREATED, serde_json::json!({ "device": dev }))
            }
            Ok(Join::BadTicket) => text(
                StatusCode::UNAUTHORIZED,
                "this join link was used already or has expired; make a new one",
            ),
            Ok(Join::TooManyDevices) => text(
                StatusCode::TOO_MANY_REQUESTS,
                &format!("at most {MAX_DEVICES} devices; remove one first"),
            ),
            Ok(Join::TokenInUse) => text(StatusCode::CONFLICT, "that token is in use"),
            Err(e) => server_error(e),
        };
    }

    // Same answer for "no such mailbox" and "wrong token", so the id alone
    // tells a stranger nothing.
    let me = match s.store().device(&id, &token) {
        Ok(Some(d)) => d,
        Ok(None) => return text(StatusCode::UNAUTHORIZED, "unknown mailbox or wrong token"),
        Err(e) => return server_error(e),
    };
    let version = match s.store().version(&id) {
        Ok(Some(v)) => v,
        Ok(None) => return text(StatusCode::UNAUTHORIZED, "unknown mailbox or wrong token"),
        Err(e) => return server_error(e),
    };

    match (method.as_str(), sub.as_str()) {
        ("GET" | "HEAD", "") => {
            if parse_tag(headers.get(header::IF_NONE_MATCH)) == Some(version) {
                return no_store(with_etag(StatusCode::NOT_MODIFIED.into_response(), version));
            }
            if version == 0 {
                return no_store(with_etag(StatusCode::NO_CONTENT.into_response(), version));
            }
            let data = match s.store().load(&id) {
                Ok(Some(d)) => d,
                Ok(None) => Vec::new(),
                Err(e) => return server_error(e),
            };
            no_store(with_etag(
                ([(header::CONTENT_TYPE, "application/octet-stream")], data).into_response(),
                version,
            ))
        }
        ("PUT", "") => {
            let Some(want) = parse_tag(headers.get(header::IF_MATCH)) else {
                return text(
                    StatusCode::PRECONDITION_REQUIRED,
                    "If-Match with the version you merged from is required",
                );
            };
            if want != version {
                return with_etag(
                    text(
                        StatusCode::PRECONDITION_FAILED,
                        "someone saved first: fetch, merge, try again",
                    ),
                    version,
                );
            }
            if s.rate_limited(&id) {
                let mut r = text(
                    StatusCode::TOO_MANY_REQUESTS,
                    "too many saves; wait a minute",
                );
                r.headers_mut()
                    .insert(header::RETRY_AFTER, HeaderValue::from_static("60"));
                return r;
            }
            let declared = headers
                .get(header::CONTENT_LENGTH)
                .and_then(|v| v.to_str().ok())
                .and_then(|v| v.parse::<usize>().ok())
                .unwrap_or(0);
            let too_big = format!("file larger than {MAX_FILE} bytes");
            if declared > MAX_FILE {
                return text(StatusCode::PAYLOAD_TOO_LARGE, &too_big);
            }
            let data = match to_bytes(body, MAX_FILE).await {
                Ok(b) => b,
                Err(_) => return text(StatusCode::PAYLOAD_TOO_LARGE, &too_big),
            };
            if data.is_empty() {
                return text(StatusCode::BAD_REQUEST, "empty file");
            }
            match s.store().save(&id, version, &data) {
                Ok(Save::Saved(v)) => {
                    s.notify(&id, Event::Version(v));
                    with_etag(text(StatusCode::OK, "saved"), v)
                }
                Ok(Save::Conflict(cur)) => with_etag(
                    text(
                        StatusCode::PRECONDITION_FAILED,
                        "someone saved first: fetch, merge, try again",
                    ),
                    cur,
                ),
                Err(e) => server_error(e),
            }
        }
        ("DELETE", "") => {
            if let Err(e) = s.store().delete(&id) {
                return server_error(e);
            }
            s.notify(&id, Event::Deleted);
            no_store(StatusCode::NO_CONTENT.into_response())
        }
        ("POST", "tickets") => match s.store().ticket(&id) {
            Ok(Some((ticket, expires))) => json(
                StatusCode::CREATED,
                serde_json::json!({ "ticket": ticket, "expires": expires }),
            ),
            Ok(None) => text(
                StatusCode::TOO_MANY_REQUESTS,
                "too many unused join links; wait ten minutes",
            ),
            Err(e) => server_error(e),
        },
        ("GET", "devices") if arg.is_none() => match s.store().devices(&id) {
            Ok(list) => json(
                StatusCode::OK,
                serde_json::Value::Array(
                    list.into_iter()
                        .map(|d| {
                            serde_json::json!({
                                "id": d.id,
                                "name": d.name,
                                "created": d.created / 1000,
                                "lastSeen": d.seen / 1000,
                                "current": d.id == me,
                            })
                        })
                        .collect(),
                ),
            ),
            Err(e) => server_error(e),
        },
        ("DELETE", "devices") => {
            let Some(dev) = arg.filter(|a| is_hex(a, 16)) else {
                return text(
                    StatusCode::BAD_REQUEST,
                    "device id must be 16 hex characters",
                );
            };
            match s.store().remove_device(&id, &dev) {
                Ok(true) => {
                    s.notify(&id, Event::Removed(dev));
                    no_store(StatusCode::NO_CONTENT.into_response())
                }
                Ok(false) => text(StatusCode::NOT_FOUND, "no such device"),
                Err(e) => server_error(e),
            }
        }
        ("GET", "watch") => {
            let Some(ws) = ws else {
                return text(StatusCode::UPGRADE_REQUIRED, "WebSocket upgrade required");
            };
            let hub = s.hub(&id);
            if hub.receiver_count() >= MAX_WATCHERS {
                return text(StatusCode::TOO_MANY_REQUESTS, "too many open watchers");
            }
            let rx = hub.subscribe();
            ws.on_upgrade(move |socket| watch(socket, rx, me, version))
        }
        _ => text(StatusCode::METHOD_NOT_ALLOWED, "method not allowed"),
    }
}

/// One watcher: `{"version":n}` now and after every save; "ping" -> "pong".
async fn watch(mut ws: WebSocket, mut rx: broadcast::Receiver<Event>, me: String, version: i64) {
    let hello = serde_json::json!({ "version": version }).to_string();
    if ws.send(Message::Text(hello.into())).await.is_err() {
        return;
    }
    let close = |code: u16, reason: &'static str| {
        Message::Close(Some(CloseFrame {
            code,
            reason: reason.into(),
        }))
    };
    loop {
        tokio::select! {
            ev = rx.recv() => match ev {
                Ok(Event::Version(v)) => {
                    let msg = serde_json::json!({ "version": v }).to_string();
                    if ws.send(Message::Text(msg.into())).await.is_err() { return; }
                }
                Ok(Event::Removed(d)) if d == me => {
                    let _ = ws.send(close(4001, "device removed")).await;
                    return;
                }
                Ok(Event::Removed(_)) => {}
                Ok(Event::Deleted) => {
                    let _ = ws.send(close(4004, "mailbox deleted")).await;
                    return;
                }
                // Missed some notices: the next one carries the newest version,
                // and the client asks every 15 minutes anyway.
                Err(broadcast::error::RecvError::Lagged(_)) => {}
                Err(broadcast::error::RecvError::Closed) => return,
            },
            msg = ws.recv() => match msg {
                Some(Ok(Message::Text(t))) if t.as_str() == "ping" => {
                    if ws.send(Message::Text("pong".into())).await.is_err() { return; }
                }
                Some(Ok(Message::Close(_))) | None | Some(Err(_)) => return,
                Some(Ok(_)) => {}
            },
        }
    }
}

/// For logs: milliseconds since 1970 to a short UTC date and time.
pub fn when(ms: i64) -> String {
    if ms <= 0 {
        return "never".into();
    }
    time::OffsetDateTime::from_unix_timestamp(ms / 1000)
        .map(|t| {
            format!(
                "{:04}-{:02}-{:02} {:02}:{:02} UTC",
                t.year(),
                u8::from(t.month()),
                t.day(),
                t.hour(),
                t.minute()
            )
        })
        .unwrap_or_else(|_| "?".into())
}

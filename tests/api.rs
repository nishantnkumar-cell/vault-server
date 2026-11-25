//! The sync API, end to end over real TLS, as a Secret Vault client sees it.
//!
//! These are the same cases as the Cloudflare Worker's tests in the vault
//! repo (`server/sync/test/mailbox.test.ts`), so the two servers answer
//! every call the same way.

use std::sync::Arc;
use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use reqwest::{Client, Method, StatusCode};
use rustls::pki_types::CertificateDer;
use rustls::pki_types::pem::PemObject;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::{Message, protocol::frame::coding::CloseCode};
use vault_server::api::{MAX_FILE, MAX_WRITES_PER_MINUTE};
use vault_server::limits::Limits;
use vault_server::server::{self, Config, Running};
use vault_server::store::MAX_TICKETS;
use vault_server::util::{random_hex, random_token};

const ADMIN_KEY: &str = "test-admin-key-not-secret";

struct T {
    _dir: tempfile::TempDir,
    run: Running,
    client: Client,
    ca: CertificateDer<'static>,
    base: String,
}

impl Drop for T {
    fn drop(&mut self) {
        self.run.stop();
    }
}

fn roots(ca: &CertificateDer<'static>) -> rustls::RootCertStore {
    let mut r = rustls::RootCertStore::empty();
    r.add(ca.clone()).unwrap();
    r
}

/// A client like the vault's: trusts only the server's own authority.
fn tls_client(
    ca: &CertificateDer<'static>,
    provider: rustls::crypto::CryptoProvider,
) -> rustls::ClientConfig {
    rustls::ClientConfig::builder_with_provider(Arc::new(provider))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(roots(ca))
        .with_no_client_auth()
}

async fn start() -> T {
    start_with(Limits::default()).await
}

async fn start_with(limits: Limits) -> T {
    let dir = tempfile::tempdir().unwrap();
    let cfg = Config {
        data: dir.path().join("data"),
        listen: "127.0.0.1:0".parse().unwrap(),
        hosts: vec!["vault.home.example".into()],
        public_port: None,
        admin_key: Some(ADMIN_KEY.into()),
        http_loopback: None,
        limits,
    };
    let run = server::start(&cfg).await.unwrap();
    let ca = CertificateDer::from_pem_file(cfg.data.join("tls/ca.pem")).unwrap();
    let client = Client::builder()
        .tls_backend_preconfigured(tls_client(&ca, vault_server::tls::provider()))
        .build()
        .unwrap();
    let base = format!("https://localhost:{}", run.https.port());
    T {
        _dir: dir,
        run,
        client,
        ca,
        base,
    }
}

impl T {
    async fn call(
        &self,
        method: Method,
        path: &str,
        token: Option<&str>,
        headers: &[(&str, &str)],
        body: Option<Vec<u8>>,
    ) -> reqwest::Response {
        let mut r = self
            .client
            .request(method, format!("{}/v1/m/{path}", self.base));
        if let Some(t) = token {
            r = r.bearer_auth(t);
        }
        for (k, v) in headers {
            r = r.header(*k, *v);
        }
        if let Some(b) = body {
            r = r.body(b);
        }
        r.send().await.unwrap()
    }

    async fn get(&self, path: &str, token: &str) -> reqwest::Response {
        self.call(Method::GET, path, Some(token), &[], None).await
    }

    /// A mailbox holding `file` (version 1), its first device's token and id.
    async fn create(&self, file: Option<Vec<u8>>) -> (String, String, String) {
        let id = random_hex(16);
        let token = random_token();
        let r = self
            .call(
                Method::POST,
                &id,
                Some(&token),
                &[("x-admin-key", ADMIN_KEY), ("x-device-name", "Laptop")],
                None,
            )
            .await;
        assert_eq!(r.status(), 201);
        let device = r.json::<serde_json::Value>().await.unwrap()["device"]
            .as_str()
            .unwrap()
            .to_owned();
        assert_eq!(device.len(), 16);
        if let Some(f) = file {
            let put = self
                .call(
                    Method::PUT,
                    &id,
                    Some(&token),
                    &[("if-match", "\"0\"")],
                    Some(f),
                )
                .await;
            assert_eq!(put.status(), 200);
        }
        (id, token, device)
    }

    async fn join(&self, id: &str, token: &str, name: &str) -> (String, String) {
        let t = self
            .call(
                Method::POST,
                &format!("{id}/tickets"),
                Some(token),
                &[],
                None,
            )
            .await;
        assert_eq!(t.status(), 201);
        let v: serde_json::Value = t.json().await.unwrap();
        let ticket = v["ticket"].as_str().unwrap().to_owned();
        assert!(v["expires"].as_i64().unwrap() > 0);
        let mine = random_token();
        let r = self
            .call(
                Method::POST,
                &format!("{id}/join"),
                Some(&mine),
                &[("x-ticket", &ticket), ("x-device-name", name)],
                None,
            )
            .await;
        assert_eq!(r.status(), 201);
        let dev = r.json::<serde_json::Value>().await.unwrap()["device"]
            .as_str()
            .unwrap()
            .to_owned();
        (mine, dev)
    }

    async fn watch(
        &self,
        id: &str,
        token: &str,
    ) -> tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>
    {
        let url = format!("wss://localhost:{}/v1/m/{id}/watch", self.run.https.port());
        let mut req = url.into_client_request().unwrap();
        req.headers_mut()
            .insert("authorization", format!("Bearer {token}").parse().unwrap());
        let cfg = tls_client(&self.ca, vault_server::tls::provider());
        let (ws, resp) = tokio_tungstenite::connect_async_tls_with_config(
            req,
            None,
            false,
            Some(tokio_tungstenite::Connector::Rustls(Arc::new(cfg))),
        )
        .await
        .unwrap();
        assert_eq!(resp.status(), 101);
        ws
    }
}

fn bytes(n: usize, fill: u8) -> Vec<u8> {
    vec![fill; n]
}

fn etag(r: &reqwest::Response) -> String {
    r.headers()
        .get("etag")
        .map(|v| v.to_str().unwrap().to_owned())
        .unwrap_or_default()
}

// ---- the server ----

#[tokio::test]
async fn says_what_it_is() {
    let t = start().await;
    let r = t.client.get(format!("{}/", t.base)).send().await.unwrap();
    assert_eq!(r.headers()["cache-control"], "no-store");
    let v: serde_json::Value = r.json().await.unwrap();
    assert_eq!(v["service"], "secret-vault-sync");
    assert_eq!(v["api"], 1);
    assert_eq!(v["revision"], 2);
    assert_eq!(v["server"], "vault-server");
    let page = t
        .client
        .get(format!("{}/join", t.base))
        .send()
        .await
        .unwrap();
    assert!(page.text().await.unwrap().contains("Join a Secret Vault"));
    let nope = t
        .client
        .get(format!("{}/nope", t.base))
        .send()
        .await
        .unwrap();
    assert_eq!(nope.status(), 404);
}

#[tokio::test]
async fn serves_its_certificate_authority_with_the_pinned_fingerprint() {
    let t = start().await;
    let pem = t
        .client
        .get(format!("{}/ca.pem", t.base))
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    let der = CertificateDer::from_pem_slice(pem.as_bytes()).unwrap();
    assert_eq!(der, t.ca);
    // The fingerprint `vault cloud setup --fingerprint` and join links use.
    let fp = vault_server::util::fingerprint(der.as_ref());
    assert_eq!(fp.len(), 43);
    assert_eq!(
        fp,
        vault_server::tls::ca_fingerprint(&t._dir.path().join("data/tls")).unwrap()
    );
}

#[tokio::test]
async fn prefers_post_quantum_key_exchange() {
    let t = start().await;
    for (provider, want) in [
        // A client that offers the hybrid group gets it.
        (
            vault_server::tls::provider(),
            rustls::NamedGroup::X25519MLKEM768,
        ),
        // The vault's clients before they move to ML-KEM (rustls with ring,
        // X25519 first) still connect.
        (
            rustls::crypto::ring::default_provider(),
            rustls::NamedGroup::X25519,
        ),
    ] {
        let cfg = Arc::new(tls_client(&t.ca, provider));
        let tcp = tokio::net::TcpStream::connect(t.run.https).await.unwrap();
        let conn = tokio_rustls::TlsConnector::from(cfg)
            .connect("localhost".try_into().unwrap(), tcp)
            .await
            .unwrap();
        let (_, session) = conn.get_ref();
        assert_eq!(
            session.protocol_version(),
            Some(rustls::ProtocolVersion::TLSv1_3)
        );
        assert_eq!(
            session.negotiated_key_exchange_group().unwrap().name(),
            want
        );
    }
}

#[tokio::test]
async fn certificate_names_the_configured_host() {
    let t = start().await;
    let cfg = Arc::new(tls_client(&t.ca, vault_server::tls::provider()));
    let tcp = tokio::net::TcpStream::connect(t.run.https).await.unwrap();
    tokio_rustls::TlsConnector::from(cfg.clone())
        .connect("vault.home.example".try_into().unwrap(), tcp)
        .await
        .expect("the certificate covers the host given with --hosts");
    let tcp = tokio::net::TcpStream::connect(t.run.https).await.unwrap();
    assert!(
        tokio_rustls::TlsConnector::from(cfg)
            .connect("other.example.com".try_into().unwrap(), tcp)
            .await
            .is_err()
    );
}

// ---- creating a mailbox ----

#[tokio::test]
async fn create_needs_the_admin_key() {
    let t = start().await;
    let (id, tok) = (random_hex(16), random_token());
    let r = t.call(Method::POST, &id, Some(&tok), &[], None).await;
    assert_eq!(r.status(), 403);
    let r = t
        .call(
            Method::POST,
            &id,
            Some(&tok),
            &[("x-admin-key", "wrong")],
            None,
        )
        .await;
    assert_eq!(r.status(), 403);
}

#[tokio::test]
async fn starts_empty_and_refuses_a_second_create_and_bad_ids_or_tokens() {
    let t = start().await;
    let (id, token, _) = t.create(None).await;
    let empty = t.get(&id, &token).await;
    assert_eq!(empty.status(), 204);
    assert_eq!(etag(&empty), "\"0\"");
    let again = t
        .call(
            Method::POST,
            &id,
            Some(&token),
            &[("x-admin-key", ADMIN_KEY)],
            None,
        )
        .await;
    assert_eq!(again.status(), 409);
    assert_eq!(t.get("NOT-HEX", &token).await.status(), 400);
    assert_eq!(t.get(&id, "short").await.status(), 401);
    assert_eq!(
        t.call(Method::GET, &id, None, &[], None).await.status(),
        401
    );
}

// ---- reading and writing ----

#[tokio::test]
async fn returns_the_file_with_its_version_and_304_when_unchanged() {
    let t = start().await;
    let file = bytes(8192, 3);
    let (id, token, _) = t.create(Some(file.clone())).await;
    let r = t.get(&id, &token).await;
    assert_eq!(r.status(), 200);
    assert_eq!(etag(&r), "\"1\"");
    assert_eq!(r.headers()["cache-control"], "no-store");
    assert_eq!(r.bytes().await.unwrap().to_vec(), file);
    let same = t
        .call(
            Method::GET,
            &id,
            Some(&token),
            &[("if-none-match", "\"1\"")],
            None,
        )
        .await;
    assert_eq!(same.status(), 304);
    let head = t.call(Method::HEAD, &id, Some(&token), &[], None).await;
    assert_eq!(head.status(), 200);
    assert_eq!(etag(&head), "\"1\"");
}

#[tokio::test]
async fn answers_a_wrong_token_and_an_unknown_mailbox_the_same_way() {
    let t = start().await;
    let (id, _, _) = t.create(Some(bytes(10, 1))).await;
    let a = t.get(&id, &random_token()).await;
    let b = t.get(&random_hex(16), &random_token()).await;
    assert_eq!(a.status(), 401);
    assert_eq!(b.status(), 401);
    assert_eq!(a.text().await.unwrap(), b.text().await.unwrap());
}

#[tokio::test]
async fn saves_only_on_top_of_the_version_the_client_merged_from() {
    let t = start().await;
    let (id, token, _) = t.create(Some(bytes(4096, 7))).await;
    let r = t
        .call(Method::PUT, &id, Some(&token), &[], Some(bytes(10, 0)))
        .await;
    assert_eq!(r.status(), 428);
    let ok = t
        .call(
            Method::PUT,
            &id,
            Some(&token),
            &[("if-match", "\"1\"")],
            Some(bytes(10, 1)),
        )
        .await;
    assert_eq!(ok.status(), 200);
    assert_eq!(etag(&ok), "\"2\"");
    // A second device that also started from version 1 loses the race.
    let late = t
        .call(
            Method::PUT,
            &id,
            Some(&token),
            &[("if-match", "W/\"1\"")],
            Some(bytes(10, 2)),
        )
        .await;
    assert_eq!(late.status(), 412);
    assert_eq!(etag(&late), "\"2\"");
    let now = t.get(&id, &token).await;
    assert_eq!(now.bytes().await.unwrap().to_vec(), bytes(10, 1));
}

#[tokio::test]
async fn keeps_large_files() {
    let t = start().await;
    let big: Vec<u8> = (0..3 * 1024 * 1024 + 17).map(|i| (i % 251) as u8).collect();
    let (id, token, _) = t.create(Some(big.clone())).await;
    let r = t.get(&id, &token).await;
    assert_eq!(r.bytes().await.unwrap().to_vec(), big);
}

#[tokio::test]
async fn refuses_files_over_the_size_limit_and_empty_files() {
    let t = start().await;
    let (id, token, _) = t.create(Some(bytes(10, 1))).await;
    let too_big = t
        .call(
            Method::PUT,
            &id,
            Some(&token),
            &[("if-match", "\"1\"")],
            Some(bytes(MAX_FILE + 1, 7)),
        )
        .await;
    assert_eq!(too_big.status(), 413);
    let empty = t
        .call(
            Method::PUT,
            &id,
            Some(&token),
            &[("if-match", "\"1\"")],
            Some(Vec::new()),
        )
        .await;
    assert_eq!(empty.status(), 400);
    let exactly = t
        .call(
            Method::PUT,
            &id,
            Some(&token),
            &[("if-match", "\"1\"")],
            Some(bytes(MAX_FILE, 7)),
        )
        .await;
    assert_eq!(exactly.status(), 200);
}

#[tokio::test]
async fn limits_saves_per_minute() {
    let t = start().await;
    let (id, token, _) = t.create(None).await;
    for v in 0..MAX_WRITES_PER_MINUTE {
        let tag = format!("\"{v}\"");
        let r = t
            .call(
                Method::PUT,
                &id,
                Some(&token),
                &[("if-match", &tag)],
                Some(bytes(10, 1)),
            )
            .await;
        assert_eq!(r.status(), 200);
    }
    let tag = format!("\"{MAX_WRITES_PER_MINUTE}\"");
    let r = t
        .call(
            Method::PUT,
            &id,
            Some(&token),
            &[("if-match", &tag)],
            Some(bytes(10, 1)),
        )
        .await;
    assert_eq!(r.status(), 429);
    assert_eq!(r.headers()["retry-after"], "60");
}

// ---- devices ----

#[tokio::test]
async fn joins_a_device_with_a_one_time_ticket() {
    let t = start().await;
    let (id, token, laptop) = t.create(Some(bytes(10, 1))).await;
    let (phone, phone_id) = t.join(&id, &token, "Phone").await;
    assert_eq!(t.get(&id, &phone).await.status(), 200);
    let list: Vec<serde_json::Value> = t
        .get(&format!("{id}/devices"), &phone)
        .await
        .json()
        .await
        .unwrap();
    let got: Vec<(String, String, bool)> = list
        .iter()
        .map(|d| {
            (
                d["id"].as_str().unwrap().to_owned(),
                d["name"].as_str().unwrap().to_owned(),
                d["current"].as_bool().unwrap(),
            )
        })
        .collect();
    assert_eq!(
        got,
        vec![
            (laptop, "Laptop".to_owned(), false),
            (phone_id, "Phone".to_owned(), true)
        ]
    );
    assert!(list[0]["created"].as_i64().unwrap() > 1_700_000_000);
    assert!(list[0]["lastSeen"].as_i64().unwrap() > 1_700_000_000);
}

#[tokio::test]
async fn refuses_a_used_made_up_or_missing_ticket() {
    let t = start().await;
    let (id, token, _) = t.create(Some(bytes(10, 1))).await;
    let tk: serde_json::Value = t
        .call(
            Method::POST,
            &format!("{id}/tickets"),
            Some(&token),
            &[],
            None,
        )
        .await
        .json()
        .await
        .unwrap();
    let ticket = tk["ticket"].as_str().unwrap();
    let (t, id) = (&t, &id);
    let join = |tick: Option<String>| {
        let mut h = vec![];
        if let Some(x) = tick {
            h.push(x);
        }
        async move {
            let hs: Vec<(&str, &str)> = h.iter().map(|x| ("x-ticket", x.as_str())).collect();
            t.call(
                Method::POST,
                &format!("{id}/join"),
                Some(&random_token()),
                &hs,
                None,
            )
            .await
            .status()
        }
    };
    assert_eq!(join(Some(ticket.to_owned())).await, StatusCode::CREATED);
    assert_eq!(
        join(Some(ticket.to_owned())).await,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(join(Some(random_token())).await, StatusCode::UNAUTHORIZED);
    assert_eq!(join(None).await, StatusCode::BAD_REQUEST);
    // Only a device can ask for a ticket.
    let r = t
        .call(
            Method::POST,
            &format!("{id}/tickets"),
            Some(&random_token()),
            &[],
            None,
        )
        .await;
    assert_eq!(r.status(), 401);
}

#[tokio::test]
async fn limits_unused_tickets() {
    let t = start().await;
    let (id, token, _) = t.create(Some(bytes(10, 1))).await;
    for _ in 0..MAX_TICKETS {
        let r = t
            .call(
                Method::POST,
                &format!("{id}/tickets"),
                Some(&token),
                &[],
                None,
            )
            .await;
        assert_eq!(r.status(), 201);
    }
    let r = t
        .call(
            Method::POST,
            &format!("{id}/tickets"),
            Some(&token),
            &[],
            None,
        )
        .await;
    assert_eq!(r.status(), 429);
}

#[tokio::test]
async fn removing_a_device_locks_it_out() {
    let t = start().await;
    let (id, token, _) = t.create(Some(bytes(10, 1))).await;
    let (phone, phone_id) = t.join(&id, &token, "Phone").await;
    let r = t
        .call(
            Method::DELETE,
            &format!("{id}/devices/zz"),
            Some(&token),
            &[],
            None,
        )
        .await;
    assert_eq!(r.status(), 400);
    let r = t
        .call(
            Method::DELETE,
            &format!("{id}/devices/{phone_id}"),
            Some(&token),
            &[],
            None,
        )
        .await;
    assert_eq!(r.status(), 204);
    assert_eq!(t.get(&id, &phone).await.status(), 401);
    assert_eq!(t.get(&id, &token).await.status(), 200);
    let r = t
        .call(
            Method::DELETE,
            &format!("{id}/devices/{phone_id}"),
            Some(&token),
            &[],
            None,
        )
        .await;
    assert_eq!(r.status(), 404);
}

#[tokio::test]
async fn delete_removes_the_mailbox() {
    let t = start().await;
    let (id, token, _) = t.create(Some(bytes(10, 1))).await;
    let r = t.call(Method::DELETE, &id, Some(&token), &[], None).await;
    assert_eq!(r.status(), 204);
    assert_eq!(t.get(&id, &token).await.status(), 401);
}

// ---- watching for changes ----

#[tokio::test]
async fn sends_the_version_on_connect_and_after_each_save() {
    let t = start().await;
    let (id, token, _) = t.create(Some(bytes(10, 1))).await;
    let mut ws = t.watch(&id, &token).await;
    let first = ws.next().await.unwrap().unwrap();
    assert_eq!(first, Message::Text(r#"{"version":1}"#.into()));
    t.call(
        Method::PUT,
        &id,
        Some(&token),
        &[("if-match", "\"1\"")],
        Some(bytes(10, 2)),
    )
    .await;
    let second = ws.next().await.unwrap().unwrap();
    assert_eq!(second, Message::Text(r#"{"version":2}"#.into()));
    ws.send(Message::Text("ping".into())).await.unwrap();
    assert_eq!(
        ws.next().await.unwrap().unwrap(),
        Message::Text("pong".into())
    );
}

#[tokio::test]
async fn closes_a_removed_devices_socket() {
    let t = start().await;
    let (id, token, _) = t.create(Some(bytes(10, 1))).await;
    let (phone, phone_id) = t.join(&id, &token, "Phone").await;
    let mut ws = t.watch(&id, &phone).await;
    ws.next().await.unwrap().unwrap();
    t.call(
        Method::DELETE,
        &format!("{id}/devices/{phone_id}"),
        Some(&token),
        &[],
        None,
    )
    .await;
    match ws.next().await.unwrap().unwrap() {
        Message::Close(Some(f)) => assert_eq!(f.code, CloseCode::from(4001)),
        other => panic!("expected a close, got {other:?}"),
    }
}

#[tokio::test]
async fn needs_a_websocket_upgrade_and_a_valid_token() {
    let t = start().await;
    let (id, token, _) = t.create(Some(bytes(10, 1))).await;
    assert_eq!(t.get(&format!("{id}/watch"), &token).await.status(), 426);
    let r = t
        .call(
            Method::GET,
            &format!("{id}/watch"),
            Some(&random_token()),
            &[("upgrade", "websocket")],
            None,
        )
        .await;
    assert_eq!(r.status(), 401);
}

// ---- strangers cannot use up the server ----

type Tls = tokio_rustls::client::TlsStream<tokio::net::TcpStream>;

/// A TLS connection that has not asked for anything yet.
async fn silent(t: &T) -> std::io::Result<Tls> {
    let cfg = tls_client(&t.ca, vault_server::tls::provider());
    let tcp = tokio::net::TcpStream::connect(("127.0.0.1", t.run.https.port())).await?;
    tokio_rustls::TlsConnector::from(Arc::new(cfg))
        .connect("localhost".try_into().unwrap(), tcp)
        .await
}

/// True if the server closes the connection within `wait`.
async fn closed_within(c: &mut Tls, wait: Duration) -> bool {
    let mut buf = [0u8; 4096];
    tokio::time::timeout(wait, async {
        // Anything the server says (HTTP/1 sends nothing unasked) then the end.
        while matches!(c.read(&mut buf).await, Ok(n) if n > 0) {}
    })
    .await
    .is_ok()
}

fn tight() -> Limits {
    Limits {
        total: 8,
        per_address: 6,
        handshake: Duration::from_secs(2),
        first_request: Duration::from_millis(700),
        idle: Duration::from_millis(1500),
    }
}

#[tokio::test]
async fn silent_and_half_sent_connections_are_closed() {
    let t = start_with(tight()).await;
    let mut nothing = silent(&t).await.unwrap();
    let mut half = silent(&t).await.unwrap();
    half.write_all(b"GET /v1 HTTP/1.1\r\nHost: x\r\n")
        .await
        .unwrap();
    assert!(closed_within(&mut nothing, Duration::from_secs(5)).await);
    assert!(closed_within(&mut half, Duration::from_secs(5)).await);
    // A connection that asked once and then went quiet is closed too.
    let mut once = silent(&t).await.unwrap();
    once.write_all(b"GET /v1 HTTP/1.1\r\nHost: x\r\n\r\n")
        .await
        .unwrap();
    assert!(closed_within(&mut once, Duration::from_secs(6)).await);
}

#[tokio::test]
async fn one_address_cannot_take_every_place_and_places_come_back() {
    let t = start_with(Limits {
        first_request: Duration::from_secs(3),
        ..tight()
    })
    .await;
    let mut held = Vec::new();
    for _ in 0..tight().per_address {
        held.push(silent(&t).await.unwrap());
    }
    // The next is turned away at once (closed before or just after the handshake).
    match silent(&t).await {
        Err(_) => {}
        Ok(mut c) => assert!(closed_within(&mut c, Duration::from_secs(1)).await),
    }
    // Once the quiet ones are timed out, a real request gets through again.
    for c in &mut held {
        assert!(closed_within(c, Duration::from_secs(10)).await);
    }
    let r = t.client.get(format!("{}/v1", t.base)).send().await.unwrap();
    assert_eq!(r.status(), 200);
}

#[tokio::test]
async fn live_updates_outlast_the_idle_limit() {
    let t = start_with(tight()).await;
    let (id, token, _) = t.create(None).await;
    let mut ws = t.watch(&id, &token).await;
    assert!(ws.next().await.is_some(), "the first notice");
    tokio::time::sleep(tight().idle * 3).await;
    ws.send(Message::text("ping")).await.unwrap();
    let reply = tokio::time::timeout(Duration::from_secs(5), ws.next())
        .await
        .expect("the socket is still served");
    assert_eq!(reply.unwrap().unwrap(), Message::text("pong"));
}

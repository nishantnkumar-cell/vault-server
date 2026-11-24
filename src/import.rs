//! Moving an existing Docker sync server (the workerd one in the vault repo)
//! to this server.
//!
//! The old server's data volume holds the admin key, its certificate
//! authority (`tls/ca.pem` and `tls/ca.key`) and one SQLite file per mailbox
//! under `mailboxes/`. Taking over the authority and the admin key means the
//! fingerprint stays the same, and taking over each mailbox (its file, version
//! and devices, which keep only the SHA-256 of their tokens) means every
//! device keeps working with the same token: nobody joins again.
//!
//! workerd names a mailbox's file after a hash of its name, and the name (the
//! 32-character mailbox id the devices use) is not in the file, so the person
//! says which file is which vault. `vault-server import --list` shows each
//! file's devices to make that easy.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result, anyhow, bail};
use data_encoding::{BASE64, BASE64URL_NOPAD};
use rusqlite::{Connection, OpenFlags};

use crate::store::{DeviceRow, MailboxRow, Store};
use crate::{files, server, util};

/// One mailbox found in the old volume.
#[derive(Debug, Clone)]
pub struct OldMailbox {
    /// The file's name without `.sqlite`, how `--mailbox NAME=ID` points at it.
    pub name: String,
    pub path: PathBuf,
    pub version: i64,
    pub created: i64,
    /// The vault file; `None` while the mailbox is empty.
    pub file: Option<Vec<u8>>,
    pub devices: Vec<DeviceRow>,
}

/// Every mailbox under `<folder>/mailboxes`. The server should be stopped, but
/// a file with a write-ahead log is read correctly either way: the file, its
/// `-wal` and `-shm` are copied to a temporary folder and opened there.
pub fn scan(folder: &Path) -> Result<Vec<OldMailbox>> {
    let root = folder.join("mailboxes");
    if !root.is_dir() {
        bail!(
            "{} has no mailboxes folder: point this at the old server's data folder \
             (the Docker volume, for example /var/lib/docker/volumes/vault-sync-data/_data)",
            folder.display()
        );
    }
    let mut found = Vec::new();
    collect(&root, &mut found)?;
    found.sort();
    let mut out = Vec::new();
    for p in found {
        // Skip files that are not mailboxes (workerd also keeps metadata).
        if let Some(m) = read_mailbox(&p)? {
            out.push(m);
        }
    }
    Ok(out)
}

fn collect(dir: &Path, out: &mut Vec<PathBuf>) -> Result<()> {
    for e in std::fs::read_dir(dir).with_context(|| format!("reading {}", dir.display()))? {
        let p = e?.path();
        if p.is_dir() {
            collect(&p, out)?;
        } else if p.extension().is_some_and(|x| x == "sqlite") {
            out.push(p);
        }
    }
    Ok(())
}

fn read_mailbox(path: &Path) -> Result<Option<OldMailbox>> {
    let tmp = tempfile_dir()?;
    let name = path
        .file_stem()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_default();
    let base = path
        .file_name()
        .unwrap_or_default()
        .to_string_lossy()
        .into_owned();
    for ext in ["", "-wal", "-shm"] {
        let from = path.with_file_name(format!("{base}{ext}"));
        if from.exists() {
            std::fs::copy(&from, tmp.join(format!("m.sqlite{ext}")))
                .with_context(|| format!("copying {}", from.display()))?;
        }
    }
    let db = Connection::open_with_flags(
        tmp.join("m.sqlite"),
        OpenFlags::SQLITE_OPEN_READ_WRITE, // recovering a log needs it; it is a copy
    )?;
    let has = |t: &str| -> Result<bool> {
        Ok(db.query_row(
            "SELECT count(*) FROM sqlite_master WHERE type = 'table' AND name = ?",
            [t],
            |r| r.get::<_, i64>(0),
        )? > 0)
    };
    let result = if has("meta")? && has("chunks")? && has("devices")? {
        let meta = |k: &str| -> Result<Option<String>> {
            Ok(db
                .query_row("SELECT v FROM meta WHERE k = ?", [k], |r| r.get(0))
                .ok())
        };
        let version: i64 = meta("version")?.and_then(|v| v.parse().ok()).unwrap_or(0);
        let mut devices = Vec::new();
        {
            let mut st = db.prepare(
                "SELECT id, name, token, created, seen FROM devices ORDER BY created, id",
            )?;
            for d in st.query_map([], |r| {
                Ok(DeviceRow {
                    id: r.get(0)?,
                    name: r.get(1)?,
                    token: r.get(2)?,
                    created: r.get(3)?,
                    seen: r.get(4)?,
                })
            })? {
                devices.push(d?);
            }
        }
        let mut file = Vec::new();
        {
            let mut st = db.prepare("SELECT data FROM chunks ORDER BY i")?;
            for c in st.query_map([], |r| r.get::<_, Vec<u8>>(0))? {
                file.extend_from_slice(&c?);
            }
        }
        let created = meta("created")?
            .and_then(|v| v.parse().ok())
            .or_else(|| devices.iter().map(|d| d.created).min())
            .unwrap_or_else(util::now_ms);
        Some(OldMailbox {
            name,
            path: path.to_path_buf(),
            version,
            created,
            file: (!file.is_empty()).then_some(file),
            devices,
        })
    } else {
        None
    };
    drop(db);
    let _ = std::fs::remove_dir_all(&tmp);
    Ok(result)
}

fn tempfile_dir() -> Result<PathBuf> {
    let d = std::env::temp_dir().join(format!("vault-server-import-{}", util::random_hex(6)));
    files::private_dir(&d)?;
    Ok(d)
}

// ----- the authority key --------------------------------------------------------

/// OpenSSL writes the old authority's key as SEC1 (`BEGIN EC PRIVATE KEY`);
/// this server reads PKCS#8 (`BEGIN PRIVATE KEY`). Converts a P-256 key, and
/// passes a PKCS#8 one through.
pub fn key_to_pkcs8(pem: &str) -> Result<String> {
    if pem.contains("BEGIN PRIVATE KEY") {
        return Ok(pem.to_string());
    }
    let b64: String = pem
        .lines()
        .filter(|l| !l.starts_with("-----"))
        .flat_map(|l| l.trim().chars())
        .collect();
    let der = BASE64
        .decode(b64.as_bytes())
        .map_err(|_| anyhow!("the old authority's key is not a PEM key"))?;
    let wrapped = wrap_pkcs8(&der)?;
    let mut out = String::from("-----BEGIN PRIVATE KEY-----\n");
    for line in BASE64.encode(&wrapped).as_bytes().chunks(64) {
        out.push_str(std::str::from_utf8(line)?);
        out.push('\n');
    }
    out.push_str("-----END PRIVATE KEY-----\n");
    Ok(out)
}

/// DER of a length (short or long form).
fn der_len(n: usize) -> Vec<u8> {
    if n < 128 {
        vec![n as u8]
    } else if n < 256 {
        vec![0x81, n as u8]
    } else {
        vec![0x82, (n >> 8) as u8, n as u8]
    }
}

fn der(tag: u8, body: &[u8]) -> Vec<u8> {
    let mut v = vec![tag];
    v.extend(der_len(body.len()));
    v.extend_from_slice(body);
    v
}

/// Reads one DER element: (tag, body, rest).
fn der_read(b: &[u8]) -> Result<(u8, &[u8], &[u8])> {
    let bad = || anyhow!("the old authority's key is damaged");
    let tag = *b.first().ok_or_else(bad)?;
    let l0 = *b.get(1).ok_or_else(bad)? as usize;
    let (len, head) = match l0 {
        0..=127 => (l0, 2),
        0x81 => (*b.get(2).ok_or_else(bad)? as usize, 3),
        0x82 => (
            ((*b.get(2).ok_or_else(bad)? as usize) << 8) | *b.get(3).ok_or_else(bad)? as usize,
            4,
        ),
        _ => return Err(bad()),
    };
    let body = b.get(head..head + len).ok_or_else(bad)?;
    Ok((tag, body, &b[head + len..]))
}

/// SEC1 `ECPrivateKey` for P-256 into a PKCS#8 `PrivateKeyInfo`.
fn wrap_pkcs8(sec1: &[u8]) -> Result<Vec<u8>> {
    const P256: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07];
    const EC_PUBLIC_KEY: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01];
    let (tag, seq, _) = der_read(sec1)?;
    if tag != 0x30 {
        bail!("the old authority's key is not an EC key");
    }
    let (t, version, rest) = der_read(seq)?;
    if t != 0x02 || version != [1] {
        bail!("the old authority's key is not a SEC1 EC key");
    }
    let (t, private, mut rest) = der_read(rest)?;
    if t != 0x04 || private.len() != 32 {
        bail!("the old authority's key is not a P-256 key");
    }
    let mut public = None;
    while !rest.is_empty() {
        let (t, body, r) = der_read(rest)?;
        rest = r;
        match t {
            0xa0 => {
                let (_, oid, _) = der_read(body)?;
                if oid != P256 {
                    bail!("the old authority's key is not on the P-256 curve");
                }
            }
            0xa1 => public = Some(body.to_vec()),
            _ => {}
        }
    }
    // The inner key without the curve (the algorithm identifier has it).
    let mut inner = der(0x02, &[1]);
    inner.extend(der(0x04, private));
    if let Some(p) = public {
        inner.extend(der(0xa1, &p));
    }
    let inner = der(0x30, &inner);
    let mut alg = der(0x06, EC_PUBLIC_KEY);
    alg.extend(der(0x06, P256));
    let mut info = der(0x02, &[0]);
    info.extend(der(0x30, &alg));
    info.extend(der(0x04, &inner));
    Ok(der(0x30, &info))
}

// ----- importing ----------------------------------------------------------------

/// Which old file is which vault: `(name prefix or None, mailbox id)`.
pub type Assignment = (Option<String>, String);

/// Pairs `--mailbox` values with the scanned files. `ID` alone is allowed
/// only when there is a single file; `NAME=ID` picks a file by (a unique
/// prefix of) its name.
pub fn assign<'a>(
    old: &'a [OldMailbox],
    given: &[Assignment],
) -> Result<Vec<(&'a OldMailbox, String)>> {
    let mut out: Vec<(&OldMailbox, String)> = Vec::new();
    for (name, id) in given {
        if !util::is_hex(id, 32) {
            bail!("{id} is not a mailbox id (32 lowercase hex characters)");
        }
        let m = match name {
            None if old.len() == 1 => &old[0],
            None => bail!(
                "there are {} mailboxes: say which file is which with --mailbox NAME=ID \
                 (`vault-server import --list FOLDER` shows the names and devices)",
                old.len()
            ),
            Some(n) => {
                let hits: Vec<_> = old
                    .iter()
                    .filter(|m| m.name.starts_with(n.as_str()))
                    .collect();
                match hits.as_slice() {
                    [one] => *one,
                    [] => bail!("no mailbox file starts with {n}"),
                    _ => bail!("{n} matches more than one mailbox file; use more characters"),
                }
            }
        };
        if out.iter().any(|(o, _)| o.name == m.name) {
            bail!("the mailbox file {} was given twice", m.name);
        }
        if out.iter().any(|(_, i)| i == id) {
            bail!("the mailbox id {id} was given twice");
        }
        out.push((m, id.clone()));
    }
    Ok(out)
}

/// What an import did.
#[derive(Debug, Default)]
pub struct Report {
    pub mailboxes: usize,
    pub devices: usize,
    pub kept_authority: bool,
    pub kept_admin_key: bool,
    pub left_out: Vec<String>,
}

/// Loads the old server's authority, admin key and the assigned mailboxes
/// into the new server's data folder `data` (which must keep no vaults yet).
pub fn import(
    data: &Path,
    folder: &Path,
    old: &[OldMailbox],
    picked: &[(&OldMailbox, String)],
) -> Result<Report> {
    if picked.is_empty() {
        bail!("no mailboxes chosen: give --mailbox ID (one vault) or --mailbox NAME=ID");
    }
    let mut report = Report::default();
    files::private_dir(data)?;
    let mut store = Store::open(&server::db_path(data))?;
    let rows: Vec<MailboxRow> = picked
        .iter()
        .map(|(m, id)| MailboxRow {
            id: id.clone(),
            version: m.version,
            created: m.created,
            saved: util::now_ms(),
            file: m.file.as_ref().map(|f| BASE64URL_NOPAD.encode(f)),
            devices: m.devices.clone(),
        })
        .collect();
    // An empty mailbox must keep version 0 and no file row.
    for r in &rows {
        report.devices += r.devices.len();
    }
    store.import(&rows)?;
    report.mailboxes = rows.len();
    report.left_out = old
        .iter()
        .filter(|m| !picked.iter().any(|(p, _)| p.name == m.name))
        .map(|m| m.name.clone())
        .collect();

    // The authority and admin key keep devices' fingerprint and setup working.
    let tls = server::tls_dir(data);
    files::private_dir(&tls)?;
    let (pem, key) = (folder.join("tls/ca.pem"), folder.join("tls/ca.key"));
    if pem.is_file() && key.is_file() {
        let key_pem = key_to_pkcs8(&std::fs::read_to_string(&key)?)?;
        files::write_private(&tls.join("ca.pem"), &std::fs::read(&pem)?)?;
        files::write_private(&tls.join("ca.key"), key_pem.as_bytes())?;
        // The server certificate is made again for the restored authority.
        let _ = std::fs::remove_file(tls.join("server.crt"));
        report.kept_authority = true;
    }
    let admin = folder.join("admin-key");
    if admin.is_file() {
        files::write_private(&data.join("admin-key"), &std::fs::read(&admin)?)?;
        report.kept_admin_key = true;
    }
    Ok(report)
}

/// Mailbox id and file name pairs for the output of `--list`.
pub fn describe(m: &OldMailbox) -> String {
    let devices: Vec<String> = m
        .devices
        .iter()
        .map(|d| format!("{} (last seen {})", d.name, crate::api::when(d.seen)))
        .collect();
    format!(
        "{}  version {}, {} bytes, {} device(s): {}",
        m.name,
        m.version,
        m.file.as_ref().map_or(0, Vec::len),
        m.devices.len(),
        if devices.is_empty() {
            "none".into()
        } else {
            devices.join(", ")
        }
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Made by the old server's entrypoint.sh commands (`openssl ecparam
    /// -name prime256v1 -genkey -noout` and `openssl req -x509 ...`).
    const OLD_KEY: &str = "-----BEGIN EC PRIVATE KEY-----
MHcCAQEEICOXB3j2At6McTb+mglg8AoxkRV91BX7T8vsneTwjo8ToAoGCCqGSM49
AwEHoUQDQgAEhEUjDFm+dIv3wapUNFR5el9OKLDSL2sZIDGrOn22J997K/LotSaX
Ra96C7htL38LmeuNfEjrv95COZRIz9pWtQ==
-----END EC PRIVATE KEY-----
";
    const OLD_CA: &str = "-----BEGIN CERTIFICATE-----
MIIBnjCCAUWgAwIBAgIUNj2094dm8ALhhqze/sliWVq/BsMwCgYIKoZIzj0EAwIw
LDEqMCgGA1UEAwwhU2VjcmV0IFZhdWx0IHN5bmMgc2VydmVyIChvd24gQ0EpMB4X
DTI2MTEyNDEwNTM0MloXDTQ2MTExOTEwNTM0MlowLDEqMCgGA1UEAwwhU2VjcmV0
IFZhdWx0IHN5bmMgc2VydmVyIChvd24gQ0EpMFkwEwYHKoZIzj0CAQYIKoZIzj0D
AQcDQgAEhEUjDFm+dIv3wapUNFR5el9OKLDSL2sZIDGrOn22J997K/LotSaXRa96
C7htL38LmeuNfEjrv95COZRIz9pWtaNFMEMwHQYDVR0OBBYEFIj6ah0cvtXFp1lT
fuC+1bb6y8zAMBIGA1UdEwEB/wQIMAYBAf8CAQAwDgYDVR0PAQH/BAQDAgEGMAoG
CCqGSM49BAMCA0cAMEQCIBnoDXZY8CnvoIYveUaGC0J4Y9wHfcTny4MUDcbRsBme
AiBFdJY1p96uJThbgGZ07QVH9QX+dL0NlPnAWlvm6TIFdA==
-----END CERTIFICATE-----
";
    /// The old entrypoint's own recipe: base64url SHA-256 of the authority's DER.
    const OLD_FINGERPRINT: &str = "7nxbuFeD62eZ21R7UJTLyxOVsTNKjtB6knSGcavb-Ik";
    /// `openssl ec -in key -pubout -outform DER`, hex.
    const OLD_PUBLIC: &str = "3059301306072a8648ce3d020106082a8648ce3d030107034200048445230c59be748bf7c1aa543454797a5f4e28b0d22f6b192031ab3a7db627df7b2bf2e8b5269745af7a0bb86d2f7f0b99eb8d7c48ebbfde42399448cfda56b5";

    #[test]
    fn the_old_sec1_key_becomes_a_pkcs8_key_for_the_same_pair() {
        let pkcs8 = key_to_pkcs8(OLD_KEY).unwrap();
        assert!(pkcs8.starts_with("-----BEGIN PRIVATE KEY-----"));
        let kp = rcgen::KeyPair::from_pem(&pkcs8).expect("the new server can read it");
        assert_eq!(
            data_encoding::HEXLOWER.encode(rcgen::PublicKeyData::der_bytes(&kp)),
            OLD_PUBLIC.replace("3059301306072a8648ce3d020106082a8648ce3d030107034200", ""),
            "same key pair"
        );
        // Already PKCS#8: unchanged. Junk and wrong curves: refused.
        assert_eq!(key_to_pkcs8(&pkcs8).unwrap(), pkcs8);
        assert!(key_to_pkcs8("not a key").is_err());
        assert!(
            key_to_pkcs8("-----BEGIN EC PRIVATE KEY-----\nAAAA\n-----END EC PRIVATE KEY-----\n")
                .is_err()
        );
    }

    /// A mailbox file the way the old server's Mailbox class writes it.
    fn old_file(
        path: &Path,
        version: i64,
        file: &[u8],
        devices: &[(&str, &str, &str)],
        wal: bool,
    ) -> Connection {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        let db = Connection::open(path).unwrap();
        if wal {
            db.pragma_update(None, "journal_mode", "WAL").unwrap();
            db.pragma_update(None, "wal_autocheckpoint", 0).unwrap();
        }
        db.execute_batch(
            "CREATE TABLE meta (k TEXT PRIMARY KEY, v TEXT NOT NULL);
             CREATE TABLE chunks (i INTEGER PRIMARY KEY, data BLOB NOT NULL);
             CREATE TABLE devices (id TEXT PRIMARY KEY, name TEXT NOT NULL, token TEXT NOT NULL UNIQUE, created INTEGER NOT NULL, seen INTEGER NOT NULL);
             CREATE TABLE tickets (hash TEXT PRIMARY KEY, expires INTEGER NOT NULL);",
        )
        .unwrap();
        db.execute(
            "INSERT INTO meta VALUES ('version', ?)",
            [version.to_string()],
        )
        .unwrap();
        db.execute("INSERT INTO meta VALUES ('created', '1700000000000')", [])
            .unwrap();
        // The old server stores the file in chunks.
        for (i, c) in file.chunks(7).enumerate() {
            db.execute(
                "INSERT INTO chunks VALUES (?, ?)",
                rusqlite::params![i as i64, c],
            )
            .unwrap();
        }
        for (id, name, token) in devices {
            db.execute(
                "INSERT INTO devices VALUES (?, ?, ?, 1700000000000, 1700000099999)",
                rusqlite::params![id, name, util::sha256_hex(token)],
            )
            .unwrap();
        }
        db.execute("INSERT INTO tickets VALUES ('abc', 1)", [])
            .unwrap();
        db
    }

    fn old_volume(root: &Path) -> Vec<Connection> {
        std::fs::create_dir_all(root.join("tls")).unwrap();
        std::fs::write(root.join("tls/ca.pem"), OLD_CA).unwrap();
        std::fs::write(root.join("tls/ca.key"), OLD_KEY).unwrap();
        std::fs::write(root.join("admin-key"), "old-admin-key\n").unwrap();
        let m = root.join("mailboxes/secret-vault-sync-mailbox");
        vec![
            // Two files, one with an unflushed log, and a stray file.
            old_file(
                &m.join("aaaa1111.sqlite"),
                5,
                b"first vault file bytes",
                &[("d1", "Laptop", "tok-laptop"), ("d2", "Phone", "tok-phone")],
                false,
            ),
            old_file(
                &m.join("bbbb2222.sqlite"),
                2,
                b"second",
                &[("d3", "Desktop", "tok-desktop")],
                true,
            ),
        ]
    }

    #[test]
    fn scan_reads_files_and_logs_and_ignores_others() {
        let dir = tempfile::tempdir().unwrap();
        let _open = old_volume(dir.path()); // the second file's data is still in its log
        std::fs::write(
            dir.path()
                .join("mailboxes/secret-vault-sync-mailbox/readme.txt"),
            "x",
        )
        .unwrap();
        let old = scan(dir.path()).unwrap();
        assert_eq!(old.len(), 2);
        let a = &old[0];
        assert_eq!((a.name.as_str(), a.version), ("aaaa1111", 5));
        assert_eq!(a.file.as_deref(), Some(&b"first vault file bytes"[..]));
        assert_eq!(a.devices.len(), 2);
        let b = &old[1];
        assert_eq!(b.file.as_deref(), Some(&b"second"[..]), "read from the log");
        assert!(describe(a).contains("Laptop"));
        assert!(scan(&dir.path().join("tls")).is_err(), "not a data folder");
    }

    #[test]
    fn assignment_needs_clear_names() {
        let dir = tempfile::tempdir().unwrap();
        let _open = old_volume(dir.path());
        let old = scan(dir.path()).unwrap();
        let id1 = "1".repeat(32);
        let id2 = "2".repeat(32);
        // Two files: a bare id is ambiguous.
        assert!(assign(&old, &[(None, id1.clone())]).is_err());
        let ok = assign(
            &old,
            &[
                (Some("aaaa".into()), id1.clone()),
                (Some("bbbb".into()), id2.clone()),
            ],
        )
        .unwrap();
        assert_eq!(ok[0].0.name, "aaaa1111");
        assert_eq!(ok[1].1, id2);
        assert!(assign(&old, &[(Some("zzz".into()), id1.clone())]).is_err());
        assert!(
            assign(
                &old,
                &[
                    (Some("aaaa".into()), id1.clone()),
                    (Some("aaaa1".into()), id2.clone())
                ]
            )
            .is_err(),
            "same file twice"
        );
        assert!(
            assign(
                &old,
                &[
                    (Some("aaaa".into()), id1.clone()),
                    (Some("bbbb".into()), id1.clone())
                ]
            )
            .is_err(),
            "same id twice"
        );
        assert!(assign(&old, &[(Some("aaaa".into()), "short".into())]).is_err());
        // A single file takes a bare id.
        assert_eq!(assign(&old[..1], &[(None, id1)]).unwrap().len(), 1);
    }

    #[test]
    fn imported_devices_keep_their_tokens_and_the_authority_its_fingerprint() {
        let old_dir = tempfile::tempdir().unwrap();
        let _open = old_volume(old_dir.path());
        let old = scan(old_dir.path()).unwrap();
        let id = "a".repeat(32);
        let picked = assign(&old, &[(Some("aaaa".into()), id.clone())]).unwrap();

        let new = tempfile::tempdir().unwrap();
        let report = import(new.path(), old_dir.path(), &old, &picked).unwrap();
        assert_eq!((report.mailboxes, report.devices), (1, 2));
        assert!(report.kept_authority && report.kept_admin_key);
        assert_eq!(report.left_out, vec!["bbbb2222".to_string()]);

        let store = Store::open(&server::db_path(new.path())).unwrap();
        assert_eq!(store.version(&id).unwrap(), Some(5));
        assert_eq!(store.load(&id).unwrap().unwrap(), b"first vault file bytes");
        // The tokens the devices hold still open the mailbox.
        assert_eq!(
            store.device(&id, "tok-laptop").unwrap().as_deref(),
            Some("d1")
        );
        assert_eq!(
            store.device(&id, "tok-phone").unwrap().as_deref(),
            Some("d2")
        );
        assert_eq!(
            store.device(&id, "tok-desktop").unwrap(),
            None,
            "not imported"
        );
        assert_eq!(
            std::fs::read_to_string(new.path().join("admin-key")).unwrap(),
            "old-admin-key\n"
        );
        // The authority is the old one, readable by this server, same fingerprint.
        let tls = server::tls_dir(new.path());
        assert_eq!(std::fs::read_to_string(tls.join("ca.pem")).unwrap(), OLD_CA);
        assert_eq!(crate::tls::ca_fingerprint(&tls).unwrap(), OLD_FINGERPRINT);
        // A server can start with it (makes a certificate under that authority).
        crate::tls::ensure_ca(&tls).unwrap();
        crate::tls::ensure_server_cert(&tls, &["localhost".to_string()]).unwrap();
        // A second import into the same server is refused.
        assert!(import(new.path(), old_dir.path(), &old, &picked).is_err());
        assert!(
            import(
                tempfile::tempdir().unwrap().path(),
                old_dir.path(),
                &old,
                &[]
            )
            .is_err()
        );
    }
}

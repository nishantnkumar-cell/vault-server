//! Backups: a sealed snapshot of everything the server holds, written to
//! the backup targets you added.
//!
//! A snapshot has every mailbox's current file and devices (tokens only as
//! their SHA-256), plus the certificate authority, the admin key and the
//! host names, so that after a restore the devices keep their tokens *and*
//! the fingerprint they pinned. It is sealed to the **backup key** with
//! X-Wing (ML-KEM-768 + X25519) and XChaCha20-Poly1305. The server keeps
//! only the public half; the secret half is shown once as the backup
//! recovery code. See docs/how-it-works.md.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, anyhow, bail};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use data_encoding::{BASE32_NOPAD, BASE64URL_NOPAD, HEXLOWER};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use time::OffsetDateTime;
use vault_core::OsRandom;
use vault_core::xwing::{self, CIPHERTEXT_LEN, XWingSecret};

use crate::store::{MailboxRow, Store};
use crate::{files, server, util};

/// First bytes of every sealed snapshot.
const MAGIC: &[u8] = b"SVBK1\0";
const NONCE_LEN: usize = 24;
const SUFFIX: &str = ".svbak";
const PREFIX: &str = "vault-server-";
/// Retention: this many daily, weekly and monthly snapshots are kept.
pub const KEEP_DAILY: usize = 7;
pub const KEEP_WEEKLY: usize = 4;
pub const KEEP_MONTHLY: usize = 12;
/// A burst of saves makes one backup, this long after the last one.
pub const QUIET_MS: i64 = 10 * 60 * 1000;
/// At least one backup this often.
pub const MAX_AGE_MS: i64 = 24 * 60 * 60 * 1000;

// ----- keys ---------------------------------------------------------------------

fn pub_path(data: &Path) -> PathBuf {
    data.join("backup.pub")
}

fn config_path(data: &Path) -> PathBuf {
    data.join("backup.json")
}

fn status_path(data: &Path) -> PathBuf {
    data.join("backup-status.json")
}

/// Whether a backup key exists yet.
pub fn has_key(data: &Path) -> bool {
    pub_path(data).exists()
}

/// Makes the backup key. The server keeps the public half; the returned
/// recovery code is the secret half and is shown once.
pub fn make_key(data: &Path) -> Result<String> {
    if has_key(data) {
        bail!("this server already has a backup key");
    }
    let sk = XWingSecret::generate(&mut OsRandom).map_err(|e| anyhow!("{e:?}"))?;
    files::private_dir(data)?;
    files::write_private(
        &pub_path(data),
        HEXLOWER.encode(&sk.public_key()).as_bytes(),
    )?;
    Ok(encode_code(sk.seed()))
}

/// 32 bytes as 13 groups of 4 base32 characters.
fn encode_code(seed: &[u8; 32]) -> String {
    let s = BASE32_NOPAD.encode(seed);
    s.as_bytes()
        .chunks(4)
        .map(|c| std::str::from_utf8(c).unwrap_or(""))
        .collect::<Vec<_>>()
        .join("-")
}

/// Reads a recovery code typed by a person: case, dashes and spaces do not matter.
pub fn parse_code(text: &str) -> Result<[u8; 32]> {
    let clean: String = text
        .chars()
        .filter(|c| !c.is_whitespace() && *c != '-')
        .collect::<String>()
        .to_uppercase();
    let bytes = BASE32_NOPAD
        .decode(clean.as_bytes())
        .map_err(|_| anyhow!("that is not a backup recovery code"))?;
    bytes
        .try_into()
        .map_err(|_| anyhow!("that is not a backup recovery code (wrong length)"))
}

fn public_key(data: &Path) -> Result<Vec<u8>> {
    let hex = std::fs::read_to_string(pub_path(data))
        .context("no backup key yet: add a backup target with `vault-server backup add`")?;
    let pk = HEXLOWER.decode(hex.trim().as_bytes())?;
    xwing::check_public_key(&pk).map_err(|e| anyhow!("the backup key is damaged: {e:?}"))?;
    Ok(pk)
}

// ----- sealing ------------------------------------------------------------------

/// Seals `plain` so only the holder of the recovery code can open it.
pub fn seal(pk: &[u8], plain: &[u8]) -> Result<Vec<u8>> {
    let (ct, ss) = xwing::encapsulate(pk, &mut OsRandom).map_err(|e| anyhow!("{e:?}"))?;
    let mut nonce = [0u8; NONCE_LEN];
    getrandom::fill(&mut nonce).map_err(|e| anyhow!("{e}"))?;
    let sealed = XChaCha20Poly1305::new(&(*ss).into())
        .encrypt(
            &XNonce::from(nonce),
            Payload {
                msg: plain,
                aad: MAGIC,
            },
        )
        .map_err(|_| anyhow!("sealing the backup failed"))?;
    let mut out = Vec::with_capacity(MAGIC.len() + ct.len() + NONCE_LEN + sealed.len());
    out.extend_from_slice(MAGIC);
    out.extend_from_slice(&ct);
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&sealed);
    Ok(out)
}

/// Opens a sealed snapshot with the recovery code's secret.
pub fn open(seed: [u8; 32], blob: &[u8]) -> Result<Vec<u8>> {
    let head = MAGIC.len() + CIPHERTEXT_LEN + NONCE_LEN;
    if blob.len() < head + 16 || &blob[..MAGIC.len()] != MAGIC {
        bail!("this is not a vault-server backup");
    }
    let ct = &blob[MAGIC.len()..MAGIC.len() + CIPHERTEXT_LEN];
    let nonce: [u8; NONCE_LEN] = blob[MAGIC.len() + CIPHERTEXT_LEN..head]
        .try_into()
        .map_err(|_| anyhow!("damaged backup"))?;
    let ss = XWingSecret::from_seed(seed)
        .decapsulate(ct)
        .map_err(|_| anyhow!("damaged backup"))?;
    XChaCha20Poly1305::new(&(*ss).into())
        .decrypt(
            &XNonce::from(nonce),
            Payload {
                msg: &blob[head..],
                aad: MAGIC,
            },
        )
        .map_err(|_| anyhow!("wrong recovery code, or the backup was changed"))
}

// ----- snapshot -----------------------------------------------------------------

/// What a snapshot holds once opened.
#[derive(Debug, Serialize, Deserialize)]
pub struct Snapshot {
    pub format: u32,
    pub created: i64,
    pub mailboxes: Vec<MailboxRow>,
    /// Small files of the data folder, by relative path (certificate
    /// authority, admin key, host names), base64url.
    pub files: BTreeMap<String, String>,
}

/// Data-folder files a restore brings back.
const KEPT_FILES: &[&str] = &["admin-key", "hosts", "tls/ca.pem", "tls/ca.key"];

pub fn snapshot(data: &Path, store: &mut Store) -> Result<Snapshot> {
    let mut kept = BTreeMap::new();
    for name in KEPT_FILES {
        if let Ok(b) = std::fs::read(data.join(name)) {
            kept.insert((*name).to_string(), BASE64URL_NOPAD.encode(&b));
        }
    }
    Ok(Snapshot {
        format: 1,
        created: util::now_ms(),
        mailboxes: store.export()?,
        files: kept,
    })
}

/// A sealed snapshot, ready to upload.
pub fn make_sealed(data: &Path, store: &mut Store) -> Result<Vec<u8>> {
    let json = serde_json::to_vec(&snapshot(data, store)?)?;
    seal(&public_key(data)?, &json)
}

pub fn read_snapshot(seed: [u8; 32], blob: &[u8]) -> Result<Snapshot> {
    let plain = open(seed, blob)?;
    let s: Snapshot =
        serde_json::from_slice(&plain).context("the backup opened but is not readable")?;
    if s.format != 1 {
        bail!(
            "this backup was made by a newer vault-server (format {})",
            s.format
        );
    }
    Ok(s)
}

/// Writes a snapshot's files and mailboxes into a (new) data folder.
pub fn restore(data: &Path, snap: &Snapshot, drop_devices: &[String]) -> Result<()> {
    let mut rows = snap.mailboxes.clone();
    for id in drop_devices {
        let mut found = false;
        for m in &mut rows {
            let before = m.devices.len();
            m.devices.retain(|d| &d.id != id);
            found |= m.devices.len() != before;
        }
        if !found {
            bail!("the backup has no device {id}");
        }
    }
    files::private_dir(data)?;
    let mut store = Store::open(&server::db_path(data))?;
    store.import(&rows)?;
    for (name, b64) in &snap.files {
        if !KEPT_FILES.contains(&name.as_str()) {
            continue;
        }
        let bytes = BASE64URL_NOPAD.decode(b64.as_bytes())?;
        let path = data.join(name);
        if let Some(dir) = path.parent() {
            files::private_dir(dir)?;
        }
        files::write_private(&path, &bytes)?;
    }
    // The server certificate is made again for the restored authority.
    let _ = std::fs::remove_file(data.join("tls/server.crt"));
    Ok(())
}

// ----- names and retention ------------------------------------------------------

/// `vault-server-20261124-093000.svbak`, in UTC.
pub fn snapshot_name(ms: i64) -> String {
    let t = OffsetDateTime::from_unix_timestamp(ms / 1000).unwrap_or(OffsetDateTime::UNIX_EPOCH);
    format!(
        "{PREFIX}{:04}{:02}{:02}-{:02}{:02}{:02}{SUFFIX}",
        t.year(),
        t.month() as u8,
        t.day(),
        t.hour(),
        t.minute(),
        t.second()
    )
}

/// The time in a snapshot name, in milliseconds, or `None` for other files.
pub fn parse_name(name: &str) -> Option<i64> {
    let d = name.strip_prefix(PREFIX)?.strip_suffix(SUFFIX)?;
    let (date, clock) = d.split_once('-')?;
    if date.len() != 8
        || clock.len() != 6
        || !(date.bytes().chain(clock.bytes())).all(|b| b.is_ascii_digit())
    {
        return None;
    }
    let n = |s: &str| s.parse::<u8>().ok();
    let month = time::Month::try_from(n(&date[4..6])?).ok()?;
    let day = n(&date[6..8])?;
    let d = time::Date::from_calendar_date(date[..4].parse().ok()?, month, day).ok()?;
    let t = time::Time::from_hms(n(&clock[0..2])?, n(&clock[2..4])?, n(&clock[4..6])?).ok()?;
    Some(
        time::PrimitiveDateTime::new(d, t)
            .assume_utc()
            .unix_timestamp()
            * 1000,
    )
}

/// Which of `snapshots` (name, time) to delete: keeps the newest of each of
/// the last [`KEEP_DAILY`] days, [`KEEP_WEEKLY`] weeks and [`KEEP_MONTHLY`]
/// months that have one, and always the newest overall.
pub fn expired(snapshots: &[(String, i64)]) -> Vec<String> {
    let mut list: Vec<&(String, i64)> = snapshots.iter().collect();
    list.sort_by_key(|x| std::cmp::Reverse(x.1));
    let mut keep = std::collections::HashSet::new();
    let mut days = Vec::new();
    let mut weeks = Vec::new();
    let mut months = Vec::new();
    for (i, (name, ms)) in list.iter().enumerate() {
        let t =
            OffsetDateTime::from_unix_timestamp(ms / 1000).unwrap_or(OffsetDateTime::UNIX_EPOCH);
        let day = (t.year(), t.ordinal());
        let iso = t.to_iso_week_date();
        let week = (iso.0, iso.1);
        let month = (t.year(), t.month() as u8);
        let mut take = i == 0;
        if !days.contains(&day) && days.len() < KEEP_DAILY {
            days.push(day);
            take = true;
        }
        if !weeks.contains(&week) && weeks.len() < KEEP_WEEKLY {
            weeks.push(week);
            take = true;
        }
        if !months.contains(&month) && months.len() < KEEP_MONTHLY {
            months.push(month);
            take = true;
        }
        if take {
            keep.insert(name.clone());
        }
    }
    list.iter()
        .filter(|(n, _)| !keep.contains(n))
        .map(|(n, _)| n.clone())
        .collect()
}

// ----- targets ------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Target {
    pub name: String,
    pub kind: String,
    pub path: String,
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct Config {
    targets: Vec<Target>,
}

/// How the last run went, per target name.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Status {
    /// Last good backup, milliseconds since 1970.
    pub ok: Option<i64>,
    /// Last attempt that failed, with why.
    pub error: Option<String>,
    pub error_at: Option<i64>,
}

fn read_json<T: Default + for<'de> Deserialize<'de>>(p: &Path) -> T {
    std::fs::read(p)
        .ok()
        .and_then(|b| serde_json::from_slice(&b).ok())
        .unwrap_or_default()
}

pub fn targets(data: &Path) -> Vec<Target> {
    read_json::<Config>(&config_path(data)).targets
}

fn save_targets(data: &Path, targets: Vec<Target>) -> Result<()> {
    files::write_private(
        &config_path(data),
        &serde_json::to_vec_pretty(&Config { targets })?,
    )
}

pub fn statuses(data: &Path) -> BTreeMap<String, Status> {
    read_json(&status_path(data))
}

fn save_status(data: &Path, s: &BTreeMap<String, Status>) -> Result<()> {
    files::write_private(&status_path(data), &serde_json::to_vec_pretty(s)?)
}

/// Adds a folder target. Returns the recovery code when this made the
/// backup key (shown once).
pub fn add_folder(data: &Path, name: Option<&str>, path: &Path) -> Result<Option<String>> {
    let path = std::path::absolute(path)?;
    std::fs::create_dir_all(&path).with_context(|| format!("making {}", path.display()))?;
    // Prove it can be written before relying on it.
    let probe = path.join(".vault-server-write-test");
    std::fs::write(&probe, b"ok").with_context(|| format!("{} is not writable", path.display()))?;
    let _ = std::fs::remove_file(probe);
    let mut list = targets(data);
    let name = name.map(str::to_string).unwrap_or_else(|| {
        let base = format!("folder{}", list.len() + 1);
        base
    });
    if list.iter().any(|t| t.name == name) {
        bail!("there is already a backup target called {name}");
    }
    let code = if has_key(data) {
        None
    } else {
        Some(make_key(data)?)
    };
    list.push(Target {
        name,
        kind: "folder".into(),
        path: path.display().to_string(),
    });
    save_targets(data, list)?;
    Ok(code)
}

pub fn remove_target(data: &Path, name: &str) -> Result<()> {
    let mut list = targets(data);
    let before = list.len();
    list.retain(|t| t.name != name);
    if list.len() == before {
        bail!("no backup target called {name}; see `vault-server backup list`");
    }
    save_targets(data, list)?;
    let mut st = statuses(data);
    st.remove(name);
    save_status(data, &st)
}

impl Target {
    fn dir(&self) -> PathBuf {
        PathBuf::from(&self.path)
    }

    /// Snapshots at this target, oldest first.
    pub fn list(&self) -> Result<Vec<(String, i64)>> {
        let mut out = Vec::new();
        for e in std::fs::read_dir(self.dir())
            .with_context(|| format!("reading {}", self.path))?
            .flatten()
        {
            let name = e.file_name().to_string_lossy().into_owned();
            if let Some(ms) = parse_name(&name) {
                out.push((name, ms));
            }
        }
        out.sort_by_key(|x| x.1);
        Ok(out)
    }

    pub fn get(&self, name: &str) -> Result<Vec<u8>> {
        if parse_name(name).is_none() {
            bail!("{name} is not a snapshot name");
        }
        std::fs::read(self.dir().join(name)).with_context(|| format!("reading {name}"))
    }

    /// Uploads, then reads it back and compares, so a broken write is caught.
    fn put(&self, name: &str, bytes: &[u8]) -> Result<()> {
        let tmp = self.dir().join(format!("{name}.part"));
        std::fs::write(&tmp, bytes)?;
        std::fs::rename(&tmp, self.dir().join(name))?;
        let back = self.get(name)?;
        if Sha256::digest(&back) != Sha256::digest(bytes) {
            bail!(
                "the copy written to {} does not match; the disk may be failing",
                self.path
            );
        }
        Ok(())
    }

    fn delete(&self, name: &str) -> Result<()> {
        std::fs::remove_file(self.dir().join(name))?;
        Ok(())
    }
}

/// Makes one snapshot and puts it on every target, then applies retention.
/// Each target's result is kept in the status file.
pub fn run_once(data: &Path, store: &mut Store) -> Result<Vec<(String, Result<String>)>> {
    let list = targets(data);
    if list.is_empty() {
        bail!("no backup targets yet: `vault-server backup add folder PATH`");
    }
    let sealed = make_sealed(data, store)?;
    let now = util::now_ms();
    let name = snapshot_name(now);
    let mut status = statuses(data);
    let mut results = Vec::new();
    for t in &list {
        let r = t.put(&name, &sealed).and_then(|_| {
            let all = t.list()?;
            for old in expired(&all) {
                t.delete(&old)?;
            }
            Ok(name.clone())
        });
        let s = status.entry(t.name.clone()).or_default();
        match &r {
            Ok(_) => {
                s.ok = Some(now);
                s.error = None;
                s.error_at = None;
            }
            Err(e) => {
                s.error = Some(format!("{e:#}"));
                s.error_at = Some(now);
            }
        }
        results.push((t.name.clone(), r));
    }
    save_status(data, &status)?;
    Ok(results)
}

/// Whether a backup is due: there is something new and it has been quiet,
/// or the last good one is a day old.
pub fn due(data: &Path, newest_save: Option<i64>, now: i64) -> bool {
    if targets(data).is_empty() {
        return false;
    }
    let status = statuses(data);
    let last_ok = targets(data)
        .iter()
        .map(|t| status.get(&t.name).and_then(|s| s.ok).unwrap_or(0))
        .min()
        .unwrap_or(0);
    let last_try = status
        .values()
        .filter_map(|s| s.error_at.or(s.ok))
        .max()
        .unwrap_or(0);
    // After a failure wait a while before trying again.
    if now - last_try < 5 * 60 * 1000 {
        return false;
    }
    if now - last_ok >= MAX_AGE_MS {
        return true;
    }
    matches!(newest_save, Some(s) if s > last_ok && now - s >= QUIET_MS)
}

/// Runs in the background of `serve`: checks every minute whether a backup
/// is due.
pub async fn schedule(data: PathBuf) {
    loop {
        tokio::time::sleep(std::time::Duration::from_secs(60)).await;
        let d = data.clone();
        let res = tokio::task::spawn_blocking(move || -> Result<()> {
            let mut store = Store::open(&server::db_path(&d))?;
            let newest = store.mailboxes()?.iter().filter_map(|m| m.saved).max();
            if due(&d, newest, util::now_ms()) {
                for (target, r) in run_once(&d, &mut store)? {
                    match r {
                        Ok(n) => tracing::info!("backup {n} written to {target}"),
                        Err(e) => tracing::error!("backup to {target} failed: {e:#}"),
                    }
                }
            }
            Ok(())
        })
        .await;
        if let Ok(Err(e)) = res {
            tracing::error!("backup check failed: {e:#}");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(y: i32, m: u8, d: u8, h: u8) -> i64 {
        let date = time::Date::from_calendar_date(y, time::Month::try_from(m).unwrap(), d).unwrap();
        time::PrimitiveDateTime::new(date, time::Time::from_hms(h, 0, 0).unwrap())
            .assume_utc()
            .unix_timestamp()
            * 1000
    }

    #[test]
    fn seal_round_trips_and_rejects_wrong_codes() {
        let sk = XWingSecret::generate(&mut OsRandom).unwrap();
        let blob = seal(&sk.public_key(), b"hello vault").unwrap();
        assert_eq!(open(*sk.seed(), &blob).unwrap(), b"hello vault");
        let other = XWingSecret::generate(&mut OsRandom).unwrap();
        assert!(open(*other.seed(), &blob).is_err());
        let mut bad = blob.clone();
        *bad.last_mut().unwrap() ^= 1;
        assert!(open(*sk.seed(), &bad).is_err());
        assert!(open(*sk.seed(), b"nope").is_err());
    }

    #[test]
    fn recovery_code_round_trips() {
        let seed = [7u8; 32];
        let code = encode_code(&seed);
        assert_eq!(parse_code(&code).unwrap(), seed);
        assert_eq!(
            parse_code(&code.to_lowercase().replace('-', " ")).unwrap(),
            seed
        );
        assert!(parse_code("ABCD").is_err());
        assert!(parse_code("not a code!").is_err());
    }

    #[test]
    fn names_round_trip() {
        let ms = at(2026, 11, 24, 9);
        let n = snapshot_name(ms);
        assert_eq!(n, "vault-server-20261124-090000.svbak");
        assert_eq!(parse_name(&n), Some(ms));
        assert_eq!(parse_name("notes.txt"), None);
        assert_eq!(parse_name("vault-server-20261324-090000.svbak"), None);
    }

    #[test]
    fn retention_keeps_daily_weekly_monthly_and_the_newest() {
        // Two snapshots a day for 40 days, then one a month for a year.
        let mut all = Vec::new();
        for d in 0..40 {
            let day = at(2026, 11, 24, 0) - d * 86_400_000;
            for h in [3, 15] {
                let ms = day + h * 3_600_000;
                all.push((snapshot_name(ms), ms));
            }
        }
        let gone = expired(&all);
        let kept: Vec<_> = all.iter().filter(|(n, _)| !gone.contains(n)).collect();
        // The newest one is always kept.
        let newest = all.iter().max_by_key(|x| x.1).unwrap();
        assert!(kept.iter().any(|(n, _)| n == &newest.0));
        // One per day for 7 days, plus older weekly and monthly ones: far
        // fewer than 80, and at least 7.
        assert!(
            kept.len() >= KEEP_DAILY && kept.len() < 25,
            "{}",
            kept.len()
        );
        // No two kept snapshots in the last 7 days share a day.
        let recent: Vec<_> = kept
            .iter()
            .filter(|(_, ms)| *ms > at(2026, 11, 17, 0))
            .collect();
        let mut days: Vec<_> = recent.iter().map(|(_, ms)| ms / 86_400_000).collect();
        days.sort();
        days.dedup();
        assert_eq!(days.len(), recent.len());
        // Nothing to delete when there is only one.
        assert!(expired(&[all[0].clone()]).is_empty());
        assert!(expired(&[]).is_empty());
    }

    #[test]
    fn due_waits_for_quiet_and_a_day_forces_one() {
        let dir = tempfile::tempdir().unwrap();
        let d = dir.path();
        assert!(!due(d, Some(1), 10_000_000), "no targets, no backup");
        add_folder(d, Some("usb"), &d.join("usb")).unwrap();
        let now = 100 * 86_400_000;
        // Never backed up: due at once.
        assert!(due(d, None, now));
        let mut st = BTreeMap::new();
        st.insert(
            "usb".to_string(),
            Status {
                ok: Some(now - 3_600_000),
                ..Default::default()
            },
        );
        save_status(d, &st).unwrap();
        // A save 1 minute ago: still busy. 11 minutes ago: due.
        assert!(!due(d, Some(now - 60_000), now));
        assert!(due(d, Some(now - 11 * 60_000), now));
        // Nothing new since the last backup and it is recent: not due.
        assert!(!due(d, Some(now - 2 * 3_600_000), now));
        // A day old: due even with nothing new.
        st.get_mut("usb").unwrap().ok = Some(now - MAX_AGE_MS - 1);
        save_status(d, &st).unwrap();
        assert!(due(d, None, now));
    }

    #[test]
    fn backup_and_restore_bring_devices_and_the_authority_back() {
        let src = tempfile::tempdir().unwrap();
        let dst = tempfile::tempdir().unwrap();
        let usb = tempfile::tempdir().unwrap();
        let (data, fresh) = (src.path(), dst.path());
        std::fs::create_dir_all(data.join("tls")).unwrap();
        std::fs::write(data.join("tls/ca.pem"), "CA PEM").unwrap();
        std::fs::write(data.join("tls/ca.key"), "CA KEY").unwrap();
        std::fs::write(data.join("admin-key"), "admin").unwrap();
        let mut store = Store::open(&server::db_path(data)).unwrap();
        let mb = "a".repeat(32);
        let token = util::random_token();
        let dev = store.create(&mb, &token, "Laptop").unwrap().unwrap();
        store.save(&mb, 0, b"encrypted vault bytes").unwrap();

        let code = add_folder(data, Some("usb"), usb.path())
            .unwrap()
            .expect("first target makes the key");
        assert!(
            add_folder(data, Some("usb2"), &usb.path().join("b"))
                .unwrap()
                .is_none()
        );
        let results = run_once(data, &mut store).unwrap();
        assert!(results.iter().all(|(_, r)| r.is_ok()));
        assert!(statuses(data)["usb"].ok.is_some());

        let t = &targets(data)[0];
        let (name, _) = t.list().unwrap().pop().unwrap();
        let blob = t.get(&name).unwrap();
        // Sealed: no plain text in the file.
        assert!(!blob.windows(5).any(|w| w == b"admin"));
        let seed = parse_code(&code).unwrap();
        let snap = read_snapshot(seed, &blob).unwrap();
        assert_eq!(snap.mailboxes.len(), 1);

        // Dropping an unknown device is refused; a known one is removed.
        assert!(restore(fresh, &snap, &["nope".into()]).is_err());
        restore(fresh, &snap, &[]).unwrap();
        assert_eq!(
            std::fs::read_to_string(fresh.join("tls/ca.key")).unwrap(),
            "CA KEY"
        );
        assert_eq!(
            std::fs::read_to_string(fresh.join("admin-key")).unwrap(),
            "admin"
        );
        let back = Store::open(&server::db_path(fresh)).unwrap();
        // The old token still works, and the file is the saved one.
        assert_eq!(back.device(&mb, &token).unwrap(), Some(dev.clone()));
        assert_eq!(back.load(&mb).unwrap().unwrap(), b"encrypted vault bytes");
        // Restoring into a server that already has vaults is refused.
        assert!(restore(fresh, &snap, &[]).is_err());

        let other = tempfile::tempdir().unwrap();
        restore(other.path(), &snap, &[dev]).unwrap();
        let s2 = Store::open(&server::db_path(other.path())).unwrap();
        assert_eq!(s2.device(&mb, &token).unwrap(), None);
    }
}

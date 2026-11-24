//! Storage: one SQLite file for every mailbox.
//!
//! A mailbox holds one encrypted vault file (the server never has its key),
//! its version number, the devices allowed to use it (only the SHA-256 of
//! each token) and unused join tickets (only their SHA-256). The server also
//! keeps the last [`HISTORY_KEEP`] versions of each file for
//! [`HISTORY_DAYS`] days, so a bad save can be rolled back.

use std::path::Path;

use anyhow::Result;
use rusqlite::{Connection, OptionalExtension, params};

use crate::util::{now_ms, random_hex, sha256_hex};

/// Versions kept per mailbox, the current one included.
pub const HISTORY_KEEP: i64 = 20;
/// Older versions than this are dropped (the current one always stays).
pub const HISTORY_DAYS: i64 = 30;
/// Devices per mailbox.
pub const MAX_DEVICES: i64 = 32;
/// Unused join tickets kept per mailbox.
pub const MAX_TICKETS: i64 = 5;
pub const TICKET_SECONDS: i64 = 10 * 60;
/// `seen` is written at most this often per device.
const SEEN_EVERY_MS: i64 = 60 * 60 * 1000;

pub struct Store {
    db: Connection,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Device {
    pub id: String,
    pub name: String,
    pub created: i64,
    pub seen: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MailboxInfo {
    pub id: String,
    pub version: i64,
    pub created: i64,
    pub saved: Option<i64>,
    pub size: Option<i64>,
    pub devices: i64,
    pub history: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Version {
    pub version: i64,
    pub saved: i64,
    pub size: i64,
}

/// What [`Store::join`] can say.
#[derive(Debug, PartialEq, Eq)]
pub enum Join {
    Joined(String),
    BadTicket,
    TooManyDevices,
    TokenInUse,
}

/// What [`Store::save`] can say.
#[derive(Debug, PartialEq, Eq)]
pub enum Save {
    Saved(i64),
    /// Someone saved first; the current version.
    Conflict(i64),
}

impl Store {
    pub fn open(path: &Path) -> Result<Store> {
        let db = Connection::open(path)?;
        Self::init(db)
    }

    pub fn memory() -> Result<Store> {
        Self::init(Connection::open_in_memory()?)
    }

    fn init(db: Connection) -> Result<Store> {
        db.busy_timeout(std::time::Duration::from_secs(10))?;
        db.execute_batch(
            "PRAGMA journal_mode = WAL;
             PRAGMA synchronous = FULL;
             PRAGMA foreign_keys = ON;
             CREATE TABLE IF NOT EXISTS mailboxes (
               id TEXT PRIMARY KEY, version INTEGER NOT NULL, created INTEGER NOT NULL);
             CREATE TABLE IF NOT EXISTS files (
               mailbox TEXT NOT NULL REFERENCES mailboxes(id) ON DELETE CASCADE,
               version INTEGER NOT NULL, saved INTEGER NOT NULL, data BLOB NOT NULL,
               PRIMARY KEY (mailbox, version));
             CREATE TABLE IF NOT EXISTS devices (
               mailbox TEXT NOT NULL REFERENCES mailboxes(id) ON DELETE CASCADE,
               id TEXT NOT NULL, name TEXT NOT NULL, token TEXT NOT NULL,
               created INTEGER NOT NULL, seen INTEGER NOT NULL,
               PRIMARY KEY (mailbox, id), UNIQUE (mailbox, token));
             CREATE TABLE IF NOT EXISTS tickets (
               mailbox TEXT NOT NULL REFERENCES mailboxes(id) ON DELETE CASCADE,
               hash TEXT NOT NULL, expires INTEGER NOT NULL,
               PRIMARY KEY (mailbox, hash));",
        )?;
        Ok(Store { db })
    }

    /// The current version, or None for no such mailbox.
    pub fn version(&self, mailbox: &str) -> Result<Option<i64>> {
        Ok(self
            .db
            .query_row(
                "SELECT version FROM mailboxes WHERE id = ?",
                [mailbox],
                |r| r.get(0),
            )
            .optional()?)
    }

    /// Creates an empty mailbox with its first device. None if it exists.
    pub fn create(&mut self, mailbox: &str, token: &str, name: &str) -> Result<Option<String>> {
        let tx = self.db.transaction()?;
        let exists: bool = tx
            .query_row(
                "SELECT 1 FROM mailboxes WHERE id = ?",
                [mailbox],
                |_| Ok(()),
            )
            .optional()?
            .is_some();
        if exists {
            return Ok(None);
        }
        let now = now_ms();
        tx.execute(
            "INSERT INTO mailboxes (id, version, created) VALUES (?, 0, ?)",
            params![mailbox, now],
        )?;
        let id = random_hex(8);
        tx.execute(
            "INSERT INTO devices (mailbox, id, name, token, created, seen) VALUES (?, ?, ?, ?, ?, ?)",
            params![mailbox, id, name, sha256_hex(token), now, now],
        )?;
        tx.commit()?;
        Ok(Some(id))
    }

    /// The device a token belongs to, and marks it seen (at most hourly).
    pub fn device(&self, mailbox: &str, token: &str) -> Result<Option<String>> {
        let row: Option<(String, i64)> = self
            .db
            .query_row(
                "SELECT id, seen FROM devices WHERE mailbox = ? AND token = ?",
                params![mailbox, sha256_hex(token)],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?;
        let Some((id, seen)) = row else {
            return Ok(None);
        };
        let now = now_ms();
        if now - seen > SEEN_EVERY_MS {
            self.db.execute(
                "UPDATE devices SET seen = ? WHERE mailbox = ? AND id = ?",
                params![now, mailbox, id],
            )?;
        }
        Ok(Some(id))
    }

    /// The current file, or None while the mailbox is empty.
    pub fn load(&self, mailbox: &str) -> Result<Option<Vec<u8>>> {
        Ok(self
            .db
            .query_row(
                "SELECT f.data FROM files f JOIN mailboxes m ON m.id = f.mailbox AND m.version = f.version
                 WHERE m.id = ?",
                [mailbox],
                |r| r.get(0),
            )
            .optional()?)
    }

    /// One kept version's file.
    pub fn load_version(&self, mailbox: &str, version: i64) -> Result<Option<Vec<u8>>> {
        Ok(self
            .db
            .query_row(
                "SELECT data FROM files WHERE mailbox = ? AND version = ?",
                params![mailbox, version],
                |r| r.get(0),
            )
            .optional()?)
    }

    /// Saves `data` on top of version `base`, keeping the history trimmed.
    pub fn save(&mut self, mailbox: &str, base: i64, data: &[u8]) -> Result<Save> {
        let tx = self.db.transaction()?;
        let current: i64 = tx.query_row(
            "SELECT version FROM mailboxes WHERE id = ?",
            [mailbox],
            |r| r.get(0),
        )?;
        if current != base {
            return Ok(Save::Conflict(current));
        }
        let next = current + 1;
        let now = now_ms();
        tx.execute(
            "INSERT INTO files (mailbox, version, saved, data) VALUES (?, ?, ?, ?)",
            params![mailbox, next, now, data],
        )?;
        tx.execute(
            "UPDATE mailboxes SET version = ? WHERE id = ?",
            params![next, mailbox],
        )?;
        tx.execute(
            "DELETE FROM files WHERE mailbox = ?1 AND version < ?2 AND (version <= ?2 - ?3 OR saved < ?4)",
            params![mailbox, next, HISTORY_KEEP, now - HISTORY_DAYS * 86_400_000],
        )?;
        tx.commit()?;
        Ok(Save::Saved(next))
    }

    /// Deletes a mailbox with its files, devices and tickets.
    pub fn delete(&mut self, mailbox: &str) -> Result<()> {
        self.db
            .execute("DELETE FROM mailboxes WHERE id = ?", [mailbox])?;
        Ok(())
    }

    /// A new one-time ticket, or None when too many are unused.
    pub fn ticket(&mut self, mailbox: &str) -> Result<Option<(String, i64)>> {
        let now = now_ms();
        self.db
            .execute("DELETE FROM tickets WHERE expires < ?", [now])?;
        let n: i64 = self.db.query_row(
            "SELECT count(*) FROM tickets WHERE mailbox = ?",
            [mailbox],
            |r| r.get(0),
        )?;
        if n >= MAX_TICKETS {
            return Ok(None);
        }
        let ticket = crate::util::random_token();
        let expires = now + TICKET_SECONDS * 1000;
        self.db.execute(
            "INSERT INTO tickets (mailbox, hash, expires) VALUES (?, ?, ?)",
            params![mailbox, sha256_hex(&ticket), expires],
        )?;
        Ok(Some((ticket, expires / 1000)))
    }

    /// Trades a ticket for a new device with `token`.
    pub fn join(&mut self, mailbox: &str, ticket: &str, token: &str, name: &str) -> Result<Join> {
        let tx = self.db.transaction()?;
        let now = now_ms();
        tx.execute("DELETE FROM tickets WHERE expires < ?", [now])?;
        let gone = tx.execute(
            "DELETE FROM tickets WHERE mailbox = ? AND hash = ?",
            params![mailbox, sha256_hex(ticket)],
        )?;
        if gone == 0 {
            tx.commit()?;
            return Ok(Join::BadTicket);
        }
        let n: i64 = tx.query_row(
            "SELECT count(*) FROM devices WHERE mailbox = ?",
            [mailbox],
            |r| r.get(0),
        )?;
        if n >= MAX_DEVICES {
            tx.commit()?;
            return Ok(Join::TooManyDevices);
        }
        let hash = sha256_hex(token);
        let used = tx
            .query_row(
                "SELECT 1 FROM devices WHERE mailbox = ? AND token = ?",
                params![mailbox, hash],
                |_| Ok(()),
            )
            .optional()?
            .is_some();
        if used {
            tx.commit()?;
            return Ok(Join::TokenInUse);
        }
        let id = random_hex(8);
        tx.execute(
            "INSERT INTO devices (mailbox, id, name, token, created, seen) VALUES (?, ?, ?, ?, ?, ?)",
            params![mailbox, id, name, hash, now, now],
        )?;
        tx.commit()?;
        Ok(Join::Joined(id))
    }

    pub fn devices(&self, mailbox: &str) -> Result<Vec<Device>> {
        let mut st = self.db.prepare(
            "SELECT id, name, created, seen FROM devices WHERE mailbox = ? ORDER BY created, id",
        )?;
        let rows = st
            .query_map([mailbox], |r| {
                Ok(Device {
                    id: r.get(0)?,
                    name: r.get(1)?,
                    created: r.get(2)?,
                    seen: r.get(3)?,
                })
            })?
            .collect::<Result<_, _>>()?;
        Ok(rows)
    }

    /// Removes a device; false if there was none with that id.
    pub fn remove_device(&mut self, mailbox: &str, device: &str) -> Result<bool> {
        Ok(self.db.execute(
            "DELETE FROM devices WHERE mailbox = ? AND id = ?",
            params![mailbox, device],
        )? > 0)
    }

    /// Every mailbox, for `vault-server status`.
    pub fn mailboxes(&self) -> Result<Vec<MailboxInfo>> {
        let mut st = self.db.prepare(
            "SELECT m.id, m.version, m.created,
                    (SELECT saved FROM files WHERE mailbox = m.id AND version = m.version),
                    (SELECT length(data) FROM files WHERE mailbox = m.id AND version = m.version),
                    (SELECT count(*) FROM devices WHERE mailbox = m.id),
                    (SELECT count(*) FROM files WHERE mailbox = m.id)
             FROM mailboxes m ORDER BY m.created, m.id",
        )?;
        let rows = st
            .query_map([], |r| {
                Ok(MailboxInfo {
                    id: r.get(0)?,
                    version: r.get(1)?,
                    created: r.get(2)?,
                    saved: r.get(3)?,
                    size: r.get(4)?,
                    devices: r.get(5)?,
                    history: r.get(6)?,
                })
            })?
            .collect::<Result<_, _>>()?;
        Ok(rows)
    }

    /// The kept versions of one mailbox, newest first.
    pub fn history(&self, mailbox: &str) -> Result<Vec<Version>> {
        let mut st = self.db.prepare(
            "SELECT version, saved, length(data) FROM files WHERE mailbox = ? ORDER BY version DESC",
        )?;
        let rows = st
            .query_map([mailbox], |r| {
                Ok(Version {
                    version: r.get(0)?,
                    saved: r.get(1)?,
                    size: r.get(2)?,
                })
            })?
            .collect::<Result<_, _>>()?;
        Ok(rows)
    }

    /// Makes an older version the newest again (as a new version, so every
    /// device downloads it and merges it with what it has).
    pub fn restore(&mut self, mailbox: &str, version: i64) -> Result<Option<i64>> {
        let Some(data) = self.load_version(mailbox, version)? else {
            return Ok(None);
        };
        let current = self.version(mailbox)?.unwrap_or(0);
        match self.save(mailbox, current, &data)? {
            Save::Saved(v) => Ok(Some(v)),
            Save::Conflict(_) => {
                anyhow::bail!("another save happened at the same moment; try again")
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::random_token;

    #[test]
    fn save_conflict_history() {
        let mut s = Store::memory().unwrap();
        let mb = random_hex(16);
        let tok = random_token();
        let dev = s.create(&mb, &tok, "Laptop").unwrap().unwrap();
        assert!(s.create(&mb, &tok, "Laptop").unwrap().is_none());
        assert_eq!(s.device(&mb, &tok).unwrap(), Some(dev));
        assert_eq!(s.load(&mb).unwrap(), None);
        for i in 0..25 {
            assert_eq!(s.save(&mb, i, &[i as u8; 10]).unwrap(), Save::Saved(i + 1));
        }
        assert_eq!(s.save(&mb, 3, b"late").unwrap(), Save::Conflict(25));
        let h = s.history(&mb).unwrap();
        assert_eq!(h.len(), HISTORY_KEEP as usize);
        assert_eq!(h[0].version, 25);
        assert_eq!(s.load(&mb).unwrap(), Some(vec![24u8; 10]));
        assert_eq!(s.restore(&mb, 10).unwrap(), Some(26));
        assert_eq!(s.load(&mb).unwrap(), Some(vec![9u8; 10]));
        assert_eq!(s.restore(&mb, 2).unwrap(), None);
        s.delete(&mb).unwrap();
        assert_eq!(s.version(&mb).unwrap(), None);
        assert!(s.history(&mb).unwrap().is_empty());
    }

    #[test]
    fn tickets_and_join() {
        let mut s = Store::memory().unwrap();
        let mb = random_hex(16);
        let tok = random_token();
        s.create(&mb, &tok, "Laptop").unwrap();
        let (t, _) = s.ticket(&mb).unwrap().unwrap();
        let phone = random_token();
        assert!(matches!(
            s.join(&mb, &t, &phone, "Phone").unwrap(),
            Join::Joined(_)
        ));
        assert_eq!(
            s.join(&mb, &t, &random_token(), "x").unwrap(),
            Join::BadTicket
        );
        let (t2, _) = s.ticket(&mb).unwrap().unwrap();
        assert_eq!(s.join(&mb, &t2, &phone, "again").unwrap(), Join::TokenInUse);
        assert_eq!(s.devices(&mb).unwrap().len(), 2);
    }
}

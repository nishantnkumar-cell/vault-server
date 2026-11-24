//! Files in the data folder, readable only by the server's own user.

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::Path;

use anyhow::{Context, Result};

/// Writes `bytes` to `path` with mode 0600, through a temporary file so a
/// crash never leaves half a key behind.
pub fn write_private(path: &Path, bytes: &[u8]) -> Result<()> {
    let tmp = path.with_extension("tmp");
    {
        let mut f = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&tmp)
            .with_context(|| format!("writing {}", tmp.display()))?;
        f.write_all(bytes)?;
        f.sync_all()?;
    }
    fs::rename(&tmp, path).with_context(|| format!("writing {}", path.display()))?;
    Ok(())
}

/// Makes a folder with mode 0700 (and its parents).
pub fn private_dir(path: &Path) -> Result<()> {
    fs::create_dir_all(path).with_context(|| format!("making {}", path.display()))?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))
        .with_context(|| format!("setting the permissions of {}", path.display()))?;
    Ok(())
}

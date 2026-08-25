//! Where the two persistence tests put their files, and why it is not `/tmp`.
//!
//! **`/tmp` is tmpfs on carapace-dev, and both measurements are wrong on tmpfs.** A tmpfs
//! mapping is shmem: it showed up as +79 600 KiB of `Private_Dirty` for an 80 MiB blocklist,
//! so the reading that separates memory the agent owns from memory the kernel is lending it
//! reported the whole mapping as owned — and it was right, because shmem is not evictable,
//! only swappable. On the state side a durable commit on tmpfs performs no device write at
//! all, so its cost is redb's bookkeeping and not the `fsync` the cadence exists to avoid.
//!
//! `/var/tmp` is the directory whose definition is that it survives a reboot, so it is on a
//! disk. The filesystem is checked rather than assumed, and reported with every number.

use std::path::{Path, PathBuf};

const SCRATCH: &str = "/var/tmp";

/// A directory that removes itself.
///
/// Not tidiness: a failed test leaves 80 MiB behind, and a full disk on this VM produces
/// link errors that look like anything but a full disk.
pub struct Scratch(PathBuf);

impl Scratch {
    pub fn new(name: &str) -> Self {
        let path = Path::new(SCRATCH).join(format!("lorica-{name}-{}", std::process::id()));
        let kind = filesystem(Path::new(SCRATCH));
        assert_ne!(
            kind, "tmpfs",
            "{SCRATCH} is tmpfs, and on tmpfs neither the page accounting nor the fsync this \
             suite measures means what it says"
        );
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path)
            .unwrap_or_else(|err| panic!("cannot create {}: {err}", path.display()));
        Self(path)
    }

    pub fn path(&self) -> &Path {
        &self.0
    }

    pub fn join(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

pub fn machine() -> String {
    std::fs::read_to_string("/proc/sys/kernel/hostname")
        .map(|name| name.trim().to_string())
        .unwrap_or_else(|_| "unknown".into())
}

/// The filesystem type a path sits on, from `/proc/mounts`, longest mount point wins.
pub fn filesystem(path: &Path) -> String {
    let Ok(mounts) = std::fs::read_to_string("/proc/mounts") else {
        return "unknown".into();
    };
    let mut best = ("", "unknown");
    for line in mounts.lines() {
        let mut fields = line.split_whitespace();
        let Some(point) = fields.nth(1) else { continue };
        let Some(kind) = fields.next() else { continue };
        if path.starts_with(point) && point.len() >= best.0.len() {
            best = (point, kind);
        }
    }
    best.1.into()
}

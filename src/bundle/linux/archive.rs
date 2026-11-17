//! Helpers for writing package archives with explicit, root-owned entries.
//!
//! `tar::Builder::append_path_with_name` copies the *build machine's* uid/gid
//! into the archive. A package built by an ordinary user therefore installs
//! files owned by uid 1000 on the target system: on any machine where uid 1000
//! belongs to a real user (almost all of them), that user silently gains write
//! access to installed binaries, desktop entries and licences. The same files
//! also arrive `0664`/`0775` because the staging tree is created with the
//! builder's umask.
//!
//! Every entry written through these helpers is `root:root`, and modes are
//! normalised so group-write never reaches the target.

use std::fs::{self, File};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::time::UNIX_EPOCH;
use tar::{Builder, EntryType, Header};

/// uid of the account packages are installed as.
pub const ROOT_UID: u64 = 0;
/// gid of the group packages are installed as.
pub const ROOT_GID: u64 = 0;

/// Normalise a mode to what a package may legitimately carry: keep the special
/// bits (setuid/setgid/sticky) and `rwxr-xr-x`, drop group/other write.
///
/// `0664` becomes `0644`, `0775` becomes `0755`, `0755` stays `0755`.
pub fn normalize_mode(mode: u32) -> u32 {
    (mode & 0o7000) | (mode & 0o755)
}

/// Numeric permission bits of a host file, or `0644` if they cannot be read.
pub fn file_mode(_path: &Path) -> u32 {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::metadata(_path)
            .map(|m| m.permissions().mode() & 0o7777)
            .unwrap_or(0o644)
    }
    #[cfg(not(unix))]
    {
        0o644
    }
}

/// Append a regular file, preserving its (normalised) mode but replacing the
/// owner with root.
pub fn append_file<W: Write>(
    builder: &mut Builder<W>,
    source: &Path,
    archive_path: &Path,
    mode: u32,
) -> io::Result<()> {
    let metadata = fs::metadata(source)?;
    let mut header = root_header(EntryType::Regular, metadata.len(), mode, mtime(&metadata))?;
    let mut file = File::open(source)?;
    builder.append_data(&mut header, archive_path, &mut file)
}

/// Append a directory entry. `archive_path` is written with a trailing slash.
pub fn append_dir<W: Write>(
    builder: &mut Builder<W>,
    source: &Path,
    archive_path: &Path,
) -> io::Result<()> {
    let metadata = fs::metadata(source)?;
    let mut header = root_header(EntryType::Directory, 0, 0o755, mtime(&metadata))?;
    builder.append_data(&mut header, dir_path(archive_path), io::empty())
}

/// Path with a trailing slash, which is what marks a tar entry as a directory
/// for extractors that look at the path rather than at the type flag.
pub fn dir_path(path: &Path) -> PathBuf {
    PathBuf::from(format!("{}/", path.display()))
}

fn root_header(entry_type: EntryType, size: u64, mode: u32, mtime: u64) -> io::Result<Header> {
    let mut header = Header::new_gnu();
    header.set_entry_type(entry_type);
    header.set_size(size);
    header.set_mode(normalize_mode(mode));
    header.set_uid(ROOT_UID);
    header.set_gid(ROOT_GID);
    header.set_mtime(mtime);
    header.set_username("root")?;
    header.set_groupname("root")?;
    Ok(header)
}

/// Timestamp to stamp on an entry.
///
/// `SOURCE_DATE_EPOCH` wins when set, so a release build is reproducible;
/// otherwise the source file's own mtime is kept.
fn mtime(metadata: &fs::Metadata) -> u64 {
    if let Some(epoch) = std::env::var_os("SOURCE_DATE_EPOCH")
        .and_then(|v| v.to_str().and_then(|s| s.parse::<u64>().ok()))
    {
        return epoch;
    }

    metadata
        .modified()
        .ok()
        .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_normalize_mode_drops_group_write() {
        assert_eq!(normalize_mode(0o664), 0o644);
        assert_eq!(normalize_mode(0o775), 0o755);
        assert_eq!(normalize_mode(0o755), 0o755);
        assert_eq!(normalize_mode(0o644), 0o644);
        // Restrictive modes are not widened.
        assert_eq!(normalize_mode(0o600), 0o600);
        // Special bits survive.
        assert_eq!(normalize_mode(0o4755), 0o4755);
        assert_eq!(normalize_mode(0o1777), 0o1755);
    }

    #[test]
    fn test_entries_are_root_owned() {
        let dir = std::env::temp_dir().join(format!("twincan-archive-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();

        let payload = dir.join("payload");
        fs::write(&payload, b"hello").unwrap();

        let mut buf = Vec::new();
        {
            let mut builder = Builder::new(&mut buf);
            append_dir(&mut builder, &dir, Path::new("usr/bin")).unwrap();
            append_file(&mut builder, &payload, Path::new("usr/bin/payload"), 0o775).unwrap();
            builder.finish().unwrap();
        }

        let mut archive = tar::Archive::new(buf.as_slice());
        let entries: Vec<_> = archive.entries().unwrap().map(|e| e.unwrap()).collect();
        assert_eq!(entries.len(), 2);

        for entry in &entries {
            let header = entry.header();
            assert_eq!(header.uid().unwrap(), 0);
            assert_eq!(header.gid().unwrap(), 0);
            assert_eq!(header.username().unwrap(), Some("root"));
            assert_eq!(header.groupname().unwrap(), Some("root"));
        }

        assert!(entries[0].header().entry_type().is_dir());
        assert!(entries[0].path().unwrap().to_string_lossy().ends_with('/'));
        assert_eq!(entries[0].header().mode().unwrap(), 0o755);

        assert_eq!(entries[1].header().mode().unwrap(), 0o755);

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_two_builds_are_reproducible() {
        // Test that setting SOURCE_DATE_EPOCH guarantees byte-identical archives.
        unsafe {
            std::env::set_var("SOURCE_DATE_EPOCH", "1700000000");
        }
        let dir = std::env::temp_dir().join(format!("twincan-repro-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();

        let payload = dir.join("payload");
        fs::write(&payload, b"reproducible payload content").unwrap();

        let mut buf1 = Vec::new();
        {
            let mut builder = Builder::new(&mut buf1);
            append_dir(&mut builder, &dir, Path::new("usr/bin")).unwrap();
            append_file(&mut builder, &payload, Path::new("usr/bin/payload"), 0o755).unwrap();
            builder.finish().unwrap();
        }

        let mut buf2 = Vec::new();
        {
            let mut builder = Builder::new(&mut buf2);
            append_dir(&mut builder, &dir, Path::new("usr/bin")).unwrap();
            append_file(&mut builder, &payload, Path::new("usr/bin/payload"), 0o755).unwrap();
            builder.finish().unwrap();
        }

        assert_eq!(buf1, buf2);
        let _ = fs::remove_dir_all(&dir);
    }
}

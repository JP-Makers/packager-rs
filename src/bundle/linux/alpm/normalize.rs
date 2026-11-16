//! Post-processing pass that makes a finished ALPM archive root-owned.
//!
//! `alpm_package` builds the tarball from a staging directory, so every entry
//! inherits the uid/gid and mode of the account that ran the build:
//! `1000/1000`, `0664` for files and `0775` for directories. Installed with
//! `pacman`, the payload then belongs to whatever local user happens to be
//! uid 1000.
//!
//! Rewriting the staging tree is not an option (it needs root), so the
//! finished `.pkg.tar.zst` is decompressed, every header is rewritten, and the
//! `.MTREE` ownership records are updated to match. File contents — and
//! therefore every `sha256digest` in `.MTREE` — are left untouched.

use crate::bundle::linux::archive::{self, normalize_mode, ROOT_GID, ROOT_UID};
use std::ffi::OsStr;
use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use tar::{Archive, Builder};

/// Name of the ownership/summary file inside an ALPM package.
const MTREE: &str = ".MTREE";
/// zstd level used by `alpm-compress`'s default settings.
const ZSTD_LEVEL: i32 = 3;

/// Rewrite `path` in place so it installs as `root:root` with 0644/0755.
pub fn normalize_alpm_package(path: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let tmp = tmp_path(path);

    match rewrite(path, &tmp) {
        Ok(()) => {
            fs::rename(&tmp, path)?;
            Ok(())
        }
        Err(e) => {
            let _ = fs::remove_file(&tmp);
            Err(e)
        }
    }
}

fn tmp_path(path: &Path) -> PathBuf {
    let mut name = path.file_name().unwrap_or_default().to_os_string();
    name.push(".normalizing");
    path.with_file_name(name)
}

fn rewrite(input_path: &Path, output_path: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let input = File::open(input_path)?;
    let decoder = zstd::stream::read::Decoder::new(input)?;
    let mut archive = Archive::new(decoder);

    let output = File::create(output_path)?;
    let encoder = zstd::stream::write::Encoder::new(output, ZSTD_LEVEL)?;
    let mut builder = Builder::new(encoder);

    for entry in archive.entries()? {
        let mut entry = entry?;
        let entry_path = entry.path()?.into_owned();
        let mut header = entry.header().clone();
        let entry_type = header.entry_type();

        header.set_uid(ROOT_UID);
        header.set_gid(ROOT_GID);
        header.set_username("root")?;
        header.set_groupname("root")?;
        header.set_mode(normalize_mode(header.mode().unwrap_or(0o644)));

        let is_mtree = entry_path.file_name() == Some(OsStr::new(MTREE));

        if is_mtree && entry_type.is_file() {
            let mut raw = Vec::new();
            entry.read_to_end(&mut raw)?;

            let (plain, encoding) = decode_mtree(&raw)?;
            let updated = rewrite_mtree(&plain);
            let compressed = encode_mtree(&updated, encoding);

            header.set_size(compressed.len() as u64);
            header.set_cksum();
            builder.append_data(&mut header, &entry_path, compressed.as_slice())?;
        } else if entry_type.is_dir() {
            header.set_size(0);
            header.set_cksum();
            builder.append_data(&mut header, archive::dir_path(&entry_path), io::empty())?;
        } else if entry_type.is_file() {
            header.set_cksum();
            builder.append_data(&mut header, &entry_path, &mut entry)?;
        } else {
            // Symlinks, hard links, fifos and device nodes carry no payload,
            // and a non-zero size makes the archive unreadable.
            header.set_size(0);
            header.set_cksum();
            builder.append_data(&mut header, &entry_path, io::empty())?;
        }
    }

    builder.finish()?;
    let encoder = builder.into_inner()?;
    encoder.finish()?;

    Ok(())
}

/// Compression used by the `.MTREE` payload, so it can be re-encoded the same
/// way. pacman accepts all three.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum MtreeEncoding {
    Zstd,
    Gzip,
    Plain,
}

fn decode_mtree(
    raw: &[u8],
) -> Result<(Vec<u8>, MtreeEncoding), Box<dyn std::error::Error>> {
    // zstd frame magic.
    if raw.starts_with(&[0x28, 0xb5, 0x2f, 0xfd]) {
        return Ok((zstd::stream::decode_all(raw)?, MtreeEncoding::Zstd));
    }
    // gzip magic.
    if raw.starts_with(&[0x1f, 0x8b]) {
        let mut plain = Vec::new();
        flate2::read::GzDecoder::new(raw).read_to_end(&mut plain)?;
        return Ok((plain, MtreeEncoding::Gzip));
    }
    if raw.first() == Some(&b'#') {
        return Ok((raw.to_vec(), MtreeEncoding::Plain));
    }

    Err(format!(
        "{MTREE} is neither zstd, gzip nor plain mtree text; cannot normalise ownership"
    )
    .into())
}

fn encode_mtree(plain: &[u8], encoding: MtreeEncoding) -> Vec<u8> {
    match encoding {
        MtreeEncoding::Zstd => {
            zstd::stream::encode_all(plain, ZSTD_LEVEL).unwrap_or_else(|_| plain.to_vec())
        }
        MtreeEncoding::Gzip => {
            let mut encoder =
                flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
            encoder
                .write_all(plain)
                .and_then(|_| encoder.finish())
                .unwrap_or_else(|_| plain.to_vec())
        }
        MtreeEncoding::Plain => plain.to_vec(),
    }
}

/// Rewrite every `uid=`, `gid=` and `mode=` keyword in an mtree document.
fn rewrite_mtree(input: &[u8]) -> Vec<u8> {
    let text = String::from_utf8_lossy(input);
    let mut output = String::with_capacity(text.len());

    for line in text.lines() {
        output.push_str(&rewrite_mtree_line(line));
        output.push('\n');
    }

    output.into_bytes()
}

fn rewrite_mtree_line(line: &str) -> String {
    // Comments and blank lines carry no ownership.
    if line.starts_with('#') || line.trim().is_empty() {
        return line.to_string();
    }

    let mut output = String::with_capacity(line.len());

    for (index, token) in line.split(' ').enumerate() {
        if index > 0 {
            output.push(' ');
        }

        if token.starts_with("uid=") {
            output.push_str("uid=0");
        } else if token.starts_with("gid=") {
            output.push_str("gid=0");
        } else if let Some(value) = token.strip_prefix("mode=") {
            let mode = u32::from_str_radix(value, 8).unwrap_or(0o644);
            output.push_str(&format!("mode={:o}", normalize_mode(mode)));
        } else {
            // Paths escape spaces as `\040`, so plain splitting is safe.
            output.push_str(token);
        }
    }

    output
}

#[cfg(test)]
mod tests {
    use super::*;
    use tar::{EntryType, Header};

    #[test]
    fn test_rewrite_mtree_line_normalises_ownership_and_mode() {
        assert_eq!(
            rewrite_mtree_line("/set type=file uid=1000 gid=1000 mode=664"),
            "/set type=file uid=0 gid=0 mode=644"
        );
        assert_eq!(rewrite_mtree_line("/set mode=775"), "/set mode=755");
        assert_eq!(
            rewrite_mtree_line("./usr/bin/TwinCAN time=1 mode=755 size=10 sha256digest=ab"),
            "./usr/bin/TwinCAN time=1 mode=755 size=10 sha256digest=ab"
        );
        assert_eq!(rewrite_mtree_line("#mtree"), "#mtree");
        // Paths keep their escaped spaces.
        assert_eq!(
            rewrite_mtree_line("./usr/share/a\\040b time=1 type=dir"),
            "./usr/share/a\\040b time=1 type=dir"
        );
    }

    #[test]
    fn test_normalize_rewrites_headers_and_mtree() {
        let dir = std::env::temp_dir().join(format!("twincan-alpm-norm-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let pkg = dir.join("test-1.0-1-x86_64.pkg.tar.zst");

        write_sample_archive(&pkg);
        normalize_alpm_package(&pkg).expect("normalisation should succeed");

        let entries = read_entries(&pkg);

        // .MTREE, .PKGINFO, usr/, usr/bin/, usr/bin/TwinCAN, usr/share/licenses/twincan/, LICENSE
        assert_eq!(entries.len(), 7);

        for (path, header) in &entries {
            assert_eq!(header.uid().unwrap(), 0, "uid of {path:?}");
            assert_eq!(header.gid().unwrap(), 0, "gid of {path:?}");
            assert_eq!(header.username().unwrap(), Some("root"));
        }

        let modes: Vec<_> = entries
            .iter()
            .map(|(p, h)| (p.clone(), h.mode().unwrap()))
            .collect();
        assert!(modes.contains(&("usr/".to_string(), 0o755)));
        assert!(modes.contains(&("usr/bin/TwinCAN".to_string(), 0o755)));
        assert!(modes.contains(&("usr/share/licenses/twincan/LICENSE".to_string(), 0o644)));

        let mtree = entries
            .iter()
            .find(|(p, _)| p == MTREE)
            .map(|(_, _)| read_mtree(&pkg))
            .expect("package must still contain .MTREE");

        assert!(mtree.contains("/set type=file uid=0 gid=0 mode=644"), "{mtree}");
        assert!(mtree.contains("/set mode=755"), "{mtree}");
        assert!(!mtree.contains("1000"), "{mtree}");
        assert!(!mtree.contains("mode=664"), "{mtree}");

        // The payload must still be readable after the rewrite.
        assert_eq!(read_payload(&pkg), b"binary payload\n");

        let _ = fs::remove_dir_all(&dir);
    }

    fn push_entry(
        builder: &mut Builder<zstd::stream::write::Encoder<'static, File>>,
        entry_type: EntryType,
        path: &str,
        mode: u32,
        data: &[u8],
    ) {
        let mut header = Header::new_gnu();
        header.set_entry_type(entry_type);
        header.set_size(data.len() as u64);
        header.set_mode(mode);
        header.set_uid(1000);
        header.set_gid(1000);
        header.set_mtime(1_700_000_000);
        header.set_username("jeyaraj").unwrap();
        header.set_groupname("jeyaraj").unwrap();
        builder.append_data(&mut header, path, data).unwrap();
    }

    fn write_sample_archive(path: &Path) {
        let mtree = b"#mtree\n\
/set type=file uid=1000 gid=1000 mode=664\n\
./.PKGINFO time=1 size=10 sha256digest=00\n\
/set mode=775\n\
./usr time=1 type=dir\n\
./usr/bin time=1 type=dir\n\
./usr/bin/TwinCAN time=1 mode=755 size=15 sha256digest=00\n";

        let file = File::create(path).unwrap();
        let encoder = zstd::stream::write::Encoder::new(file, ZSTD_LEVEL).unwrap();
        let mut builder = Builder::new(encoder);

        let compressed = zstd::stream::encode_all(&mtree[..], ZSTD_LEVEL).unwrap();
        push_entry(&mut builder, EntryType::Regular, MTREE, 0o664, &compressed);
        push_entry(&mut builder, EntryType::Regular, ".PKGINFO", 0o664, b"pkgname=test\n");
        push_entry(&mut builder, EntryType::Directory, "usr", 0o775, b"");
        push_entry(&mut builder, EntryType::Directory, "usr/bin", 0o775, b"");
        push_entry(
            &mut builder,
            EntryType::Regular,
            "usr/bin/TwinCAN",
            0o755,
            b"binary payload\n",
        );
        push_entry(
            &mut builder,
            EntryType::Directory,
            "usr/share/licenses/twincan",
            0o775,
            b"",
        );
        push_entry(
            &mut builder,
            EntryType::Regular,
            "usr/share/licenses/twincan/LICENSE",
            0o664,
            b"MIT\n",
        );

        builder.finish().unwrap();
        builder.into_inner().unwrap().finish().unwrap();
    }

    fn read_entries(path: &Path) -> Vec<(String, Header)> {
        let file = File::open(path).unwrap();
        let decoder = zstd::stream::read::Decoder::new(file).unwrap();
        let mut archive = Archive::new(decoder);

        archive
            .entries()
            .unwrap()
            .map(|entry| {
                let entry = entry.unwrap();
                (
                    entry.path().unwrap().to_string_lossy().into_owned(),
                    entry.header().clone(),
                )
            })
            .collect()
    }

    fn read_mtree(path: &Path) -> String {
        let file = File::open(path).unwrap();
        let decoder = zstd::stream::read::Decoder::new(file).unwrap();
        let mut archive = Archive::new(decoder);

        for entry in archive.entries().unwrap() {
            let mut entry = entry.unwrap();
            if entry.path().unwrap().to_string_lossy() == MTREE {
                let mut raw = Vec::new();
                entry.read_to_end(&mut raw).unwrap();
                let (plain, _) = decode_mtree(&raw).unwrap();
                return String::from_utf8(plain).unwrap();
            }
        }

        String::new()
    }

    fn read_payload(path: &Path) -> Vec<u8> {
        let file = File::open(path).unwrap();
        let decoder = zstd::stream::read::Decoder::new(file).unwrap();
        let mut archive = Archive::new(decoder);

        for entry in archive.entries().unwrap() {
            let mut entry = entry.unwrap();
            if entry.path().unwrap().to_string_lossy() == "usr/bin/TwinCAN" {
                let mut data = Vec::new();
                entry.read_to_end(&mut data).unwrap();
                return data;
            }
        }

        Vec::new()
    }
}

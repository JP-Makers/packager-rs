use crate::bundle::linux::archive::{ROOT_GID, ROOT_UID, normalize_mode};
use crate::chmod::chmod_package_with_metadata;
use crate::metadata::Metadata;
use crate::repro::timestamp;
use md5::Md5;
use sha2::{Digest as Sha256Digest, Sha256};
use std::fs::{self, File};
use std::io::Write;
use std::path::{Path, PathBuf};
use tar::{Builder, EntryType, Header};

/// Generate gzip-compressed BSD mtree specification for staged package files.
pub fn generate_mtree(base_dir: &Path, mtime: u64) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut out = String::new();
    out.push_str("#mtree\n");
    out.push_str("/set type=file uid=0 gid=0 mode=644\n");

    let mut entries = Vec::new();
    for entry in walkdir::WalkDir::new(base_dir)
        .min_depth(1)
        .sort_by_file_name()
    {
        let entry = entry?;
        let rel_path = entry.path().strip_prefix(base_dir)?;
        let rel_str = rel_path.to_string_lossy();
        if rel_str == ".MTREE" {
            continue;
        }
        entries.push((
            entry.path().to_path_buf(),
            rel_path.to_path_buf(),
            entry.file_type(),
        ));
    }

    entries.sort_by(|a, b| a.1.cmp(&b.1));

    for (abs_path, rel_path, file_type) in entries {
        let path_str = format!(
            "./{}",
            rel_path
                .to_string_lossy()
                .replace('\\', "/")
                .replace(' ', "\\040")
        );

        if file_type.is_dir() {
            out.push_str(&format!(
                "{} time={}.0 mode=755 type=dir\n",
                path_str, mtime
            ));
        } else if file_type.is_symlink() {
            let target = fs::read_link(&abs_path)?;
            let target_str = target
                .to_string_lossy()
                .replace('\\', "/")
                .replace(' ', "\\040");
            out.push_str(&format!(
                "{} time={}.0 mode=777 type=link link={}\n",
                path_str, mtime, target_str
            ));
        } else if file_type.is_file() {
            let data = fs::read(&abs_path)?;
            let size = data.len();

            let mut md5_h = Md5::new();
            md5_h.update(&data);
            let md5_hex = hex::encode(md5_h.finalize());

            let mut sha256_h = Sha256::new();
            sha256_h.update(&data);
            let sha256_hex = hex::encode(sha256_h.finalize());

            let rel_str = rel_path.to_string_lossy();
            let is_special = rel_str == ".PKGINFO" || rel_str == ".BUILDINFO";
            let is_exec = !is_special && {
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    fs::metadata(&abs_path)
                        .map(|m| (m.permissions().mode() & 0o111) != 0)
                        .unwrap_or(false)
                }
                #[cfg(not(unix))]
                {
                    let r = rel_path.to_string_lossy();
                    r.starts_with("usr/bin")
                        || r.starts_with("bin")
                        || r.starts_with("usr/sbin")
                        || r.starts_with("sbin")
                }
            };

            let mode_str = if is_exec { "mode=755" } else { "mode=644" };

            out.push_str(&format!(
                "{} time={}.0 {} size={} md5digest={} sha256digest={}\n",
                path_str, mtime, mode_str, size, md5_hex, sha256_hex
            ));
        }
    }

    let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    gz.write_all(out.as_bytes())?;
    Ok(gz.finish()?)
}

/// Pure-Rust Arch Linux / ALPM package (.pkg.tar.zst) generator.
///
/// Builds fully compliant, reproducible, root-owned packages compatible with `pacman`
/// on any host platform (Linux, macOS, Windows, FreeBSD) without external tools.
pub fn alpm_package(
    metadata: &Metadata,
    output_dir: &Path,
) -> Result<PathBuf, Box<dyn std::error::Error>> {
    let alpm_dir = format!("{}.alpm", metadata.name);
    let base_dir = PathBuf::from(&alpm_dir);
    chmod_package_with_metadata(metadata, &base_dir, false)?;

    // 1. Create .PKGINFO and .BUILDINFO in base_dir
    super::pkg_info::create_package_info(&base_dir, metadata)?;
    super::build_info::create_build_info(&base_dir, metadata)?;

    // 2. Generate gzip-compressed .MTREE
    let mtime = timestamp();
    let mtree_bytes = generate_mtree(&base_dir, mtime)?;
    fs::write(base_dir.join(".MTREE"), &mtree_bytes)?;

    // 3. Ensure output directory exists
    if !output_dir.exists() {
        fs::create_dir_all(output_dir)?;
    }

    let pkg_arch = metadata.arch.first().map(|s| s.as_str()).unwrap_or("any");
    let package_filename = format!(
        "{}-{}-{}-{}.pkg.tar.zst",
        metadata.name, metadata.version, metadata.release, pkg_arch
    );
    let package_path = output_dir.join(package_filename);

    // 4. Create .pkg.tar.zst archive with root:root ownership and normalized modes
    let output_file = File::create(&package_path)?;
    let zstd_encoder = zstd::stream::write::Encoder::new(output_file, 3)?.auto_finish();
    let mut tar = Builder::new(zstd_encoder);

    // Arch Linux conventions place .PKGINFO, .BUILDINFO, and .MTREE first
    let special_headers = [".PKGINFO", ".BUILDINFO", ".MTREE"];
    for name in &special_headers {
        let p = base_dir.join(name);
        if p.is_file() {
            let data = fs::read(&p)?;
            let mut header = Header::new_gnu();
            header.set_entry_type(EntryType::Regular);
            header.set_size(data.len() as u64);
            header.set_mode(0o644);
            header.set_uid(ROOT_UID);
            header.set_gid(ROOT_GID);
            header.set_mtime(mtime);
            header.set_username("root")?;
            header.set_groupname("root")?;
            header.set_cksum();
            tar.append_data(&mut header, name, data.as_slice())?;
        }
    }

    // Collect all remaining files and directories
    let mut entries = Vec::new();
    for entry in walkdir::WalkDir::new(&base_dir)
        .min_depth(1)
        .sort_by_file_name()
    {
        let entry = entry?;
        let rel_path = entry.path().strip_prefix(&base_dir)?;
        let rel_str = rel_path.to_string_lossy();
        if special_headers.contains(&rel_str.as_ref()) {
            continue;
        }
        entries.push((
            entry.path().to_path_buf(),
            rel_path.to_path_buf(),
            entry.file_type(),
        ));
    }

    entries.sort_by(|a, b| a.1.cmp(&b.1));

    for (abs_path, rel_path, file_type) in entries {
        let rel_str = rel_path.to_string_lossy().replace('\\', "/");

        let mut header = Header::new_gnu();
        header.set_uid(ROOT_UID);
        header.set_gid(ROOT_GID);
        header.set_username("root")?;
        header.set_groupname("root")?;
        header.set_mtime(mtime);

        if file_type.is_dir() {
            header.set_entry_type(EntryType::Directory);
            header.set_size(0);
            header.set_mode(0o755);
            header.set_cksum();
            let dir_name = format!("{}/", rel_str);
            tar.append_data(&mut header, dir_name, std::io::empty())?;
        } else if file_type.is_symlink() {
            let target = fs::read_link(&abs_path)?;
            header.set_entry_type(EntryType::Symlink);
            header.set_size(0);
            header.set_mode(0o777);
            header.set_cksum();
            tar.append_link(&mut header, &rel_str, &target)?;
        } else if file_type.is_file() {
            let data = fs::read(&abs_path)?;
            header.set_entry_type(EntryType::Regular);
            header.set_size(data.len() as u64);

            let is_exec = {
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    fs::metadata(&abs_path)
                        .map(|m| (m.permissions().mode() & 0o111) != 0)
                        .unwrap_or(false)
                }
                #[cfg(not(unix))]
                {
                    rel_str.starts_with("usr/bin")
                        || rel_str.starts_with("bin")
                        || rel_str.starts_with("usr/sbin")
                        || rel_str.starts_with("sbin")
                }
            };
            let mode = if is_exec { 0o755 } else { 0o644 };
            header.set_mode(normalize_mode(mode));
            header.set_cksum();
            tar.append_data(&mut header, &rel_str, data.as_slice())?;
        }
    }

    tar.finish()?;

    // 5. Clean up temporary staging directory if clean_workdir is requested
    if metadata.clean_workdir {
        let _ = fs::remove_dir_all(&base_dir);
    }

    println!("ALPM package created successfully!");
    println!("  Location: {}", package_path.display());
    Ok(package_path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;
    use tar::Archive;

    #[test]
    fn test_alpm_package_creation() {
        let tmp = std::env::temp_dir().join(format!(
            "test_alpm_pkg_{}",
            uuid::Uuid::new_v4().hyphenated()
        ));
        let _ = fs::remove_dir_all(&tmp);
        fs::create_dir_all(&tmp).expect("create temp dir");

        let out_dir = tmp.join("out");
        fs::create_dir_all(&out_dir).expect("create out dir");

        let work_dir = tmp.join("work");
        fs::create_dir_all(work_dir.join("bin")).expect("create bin dir");
        fs::write(work_dir.join("bin/alpm-test-app"), b"#!/bin/sh\necho alpm").expect("write bin");

        let metadata = Metadata {
            name: "alpm-test-app".to_string(),
            version: "1.2.3".to_string(),
            release: "1".to_string(),
            description: "Test ALPM package creation".to_string(),
            maintainer: "Maintainer <m@example.com>".to_string(),
            arch: vec!["x86_64".to_string()],
            workdir: Some(work_dir.to_string_lossy().to_string()),
            package_instructions: vec![format!(
                "install -m755 \"local:{}\" to /usr/bin/",
                work_dir.join("bin/alpm-test-app").display()
            )],
            clean_workdir: false,
            ..Default::default()
        };

        let pkg_path = alpm_package(&metadata, &out_dir).expect("alpm_package");
        assert!(pkg_path.exists());
        assert!(pkg_path.to_string_lossy().ends_with(".pkg.tar.zst"));

        // Open and read .pkg.tar.zst
        let file = File::open(&pkg_path).expect("open package file");
        let decoder = zstd::stream::read::Decoder::new(file).expect("zstd decoder");
        let mut archive = Archive::new(decoder);

        let mut entry_names = Vec::new();
        let mut has_pkginfo = false;
        let mut has_buildinfo = false;
        let mut mtree_data: Option<Vec<u8>> = None;

        for entry in archive.entries().expect("entries") {
            let mut entry = entry.expect("valid entry");
            let path_str = entry
                .path()
                .expect("entry path")
                .to_string_lossy()
                .into_owned();
            entry_names.push(path_str.clone());

            // Root-owned
            assert_eq!(entry.header().uid().unwrap(), 0);
            assert_eq!(entry.header().gid().unwrap(), 0);
            assert_eq!(entry.header().username().unwrap(), Some("root"));

            if path_str == ".PKGINFO" {
                has_pkginfo = true;
            } else if path_str == ".BUILDINFO" {
                has_buildinfo = true;
            } else if path_str == ".MTREE" {
                let mut data = Vec::new();
                entry.read_to_end(&mut data).expect("read mtree");
                mtree_data = Some(data);
            }
        }

        assert!(has_pkginfo, "archive must contain .PKGINFO");
        assert!(has_buildinfo, "archive must contain .BUILDINFO");
        assert!(mtree_data.is_some(), "archive must contain .MTREE");

        // Verify .MTREE content by decompressing gzip
        let compressed_mtree = mtree_data.unwrap();
        let mut gz_decoder = flate2::read::GzDecoder::new(&compressed_mtree[..]);
        let mut mtree_text = String::new();
        gz_decoder
            .read_to_string(&mut mtree_text)
            .expect("decompress gzip mtree");

        assert!(mtree_text.starts_with("#mtree\n"));
        assert!(mtree_text.contains("/set type=file uid=0 gid=0 mode=644\n"));
        assert!(mtree_text.contains("./.PKGINFO"));
        assert!(mtree_text.contains("./.BUILDINFO"));
        assert!(mtree_text.contains("./usr/bin/alpm-test-app"));

        let _ = fs::remove_dir_all(&tmp);
        let _ = fs::remove_dir_all(format!("{}.alpm", metadata.name));
    }
}

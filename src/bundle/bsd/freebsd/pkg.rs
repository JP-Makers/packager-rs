use super::manifest::FreeBSDManifest;
use crate::chmod::chmod_package_with_metadata;
use crate::metadata::Metadata;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs::{self, File};
use std::path::{Path, PathBuf};

/// Builds a FreeBSD binary package (`.pkg`) in pure Rust.
///
/// The package is a Zstandard-compressed tarball containing:
/// - `+COMPACT_MANIFEST`: UCL/JSON metadata subset without file listings or scripts
/// - `+MANIFEST`: Complete UCL/JSON metadata including file checksums and scripts
/// - `+DESC`: Long description and project URL
/// - File payloads mapped to target paths (e.g. `usr/local/bin/...`, `usr/local/share/...`)
pub fn freebsd_package(
    metadata: &Metadata,
    output_dir: &Path,
) -> Result<PathBuf, Box<dyn std::error::Error>> {
    println!("Packaging {} into FreeBSD Package (.pkg)...", metadata.name);

    let staged_dir_name = format!("{}.freebsd-dir", metadata.name);
    let staged_dir = PathBuf::from(&staged_dir_name);

    // 1. Stage the files according to package instructions
    chmod_package_with_metadata(metadata, &staged_dir, false)?;

    // 2. Scan staged files, compute SHA256 checksums, and compute flatsize
    let mut files_to_embed = Vec::new();
    let mut files_manifest = BTreeMap::new();
    let mut total_flatsize: u64 = 0;
    let mut has_desktop_or_icons = false;

    if staged_dir.exists() {
        for entry in walkdir::WalkDir::new(&staged_dir).into_iter().flatten() {
            if entry.file_type().is_file() {
                let path = entry.path();
                let rel = path.strip_prefix(&staged_dir).unwrap_or(path);
                let rel_str = rel.to_string_lossy().into_owned();

                // On FreeBSD, map third-party /usr/ and /etc/ directories to /usr/local/
                let target_tar_path = if rel_str.starts_with("usr/local/") {
                    rel_str.clone()
                } else if let Some(stripped) = rel_str.strip_prefix("usr/") {
                    format!("usr/local/{}", stripped)
                } else if let Some(stripped) = rel_str.strip_prefix("etc/") {
                    format!("usr/local/etc/{}", stripped)
                } else {
                    rel_str.clone()
                };

                let bytes = fs::read(path)?;
                let file_size = bytes.len() as u64;
                total_flatsize += file_size;

                // Compute SHA256 digest
                let mut hasher = Sha256::new();
                hasher.update(&bytes);
                let checksum = hex::encode(hasher.finalize());

                // FreeBSD +MANIFEST files map uses absolute target paths with leading slash
                let manifest_key = format!("/{}", target_tar_path);
                files_manifest.insert(manifest_key, checksum);

                // Check for desktop/icon integration
                if target_tar_path.contains("share/applications")
                    || target_tar_path.contains("share/icons")
                {
                    has_desktop_or_icons = true;
                }

                // File mode (defaulting to 0o755 for executable/bin or 0o644 for others)
                #[cfg(unix)]
                let mode = {
                    use std::os::unix::fs::PermissionsExt;
                    entry
                        .metadata()
                        .map(|m| m.permissions().mode())
                        .unwrap_or(0o644)
                };
                #[cfg(not(unix))]
                let mode = if target_tar_path.contains("bin/") {
                    0o755
                } else {
                    0o644
                };

                files_to_embed.push((target_tar_path, bytes, mode));
            }
        }
    }

    // 3. Construct FreeBSD Manifest
    let manifest = FreeBSDManifest::from_metadata(
        metadata,
        total_flatsize,
        files_manifest,
        has_desktop_or_icons,
    );

    let full_manifest_json = manifest.to_manifest_json()?;
    let compact_manifest_json = manifest.to_compact_json()?;
    let desc_content = manifest.to_desc();

    // 4. Prepare output package path: <output_dir>/<name>-<version>_<release>_<arch>.pkg
    if !output_dir.exists() {
        fs::create_dir_all(output_dir)?;
    }

    let pkg_filename = format!(
        "{}-{}_{}_{}.pkg",
        metadata.name,
        metadata.version,
        metadata.release,
        metadata.freebsd_arch()
    );
    let pkg_file_path = output_dir.join(&pkg_filename);

    // 5. Create Zstandard-compressed tar archive in pure Rust
    let pkg_file = File::create(&pkg_file_path)?;
    let zstd_encoder = zstd::stream::write::Encoder::new(pkg_file, 3)?.auto_finish();
    let mut tar = tar::Builder::new(zstd_encoder);

    // Append +COMPACT_MANIFEST first
    let compact_bytes = compact_manifest_json.into_bytes();
    let mut compact_header = tar::Header::new_gnu();
    compact_header.set_size(compact_bytes.len() as u64);
    compact_header.set_mode(0o644);
    compact_header.set_mtime(0);
    compact_header.set_cksum();
    tar.append_data(
        &mut compact_header,
        "+COMPACT_MANIFEST",
        compact_bytes.as_slice(),
    )?;

    // Append +MANIFEST
    let manifest_bytes = full_manifest_json.into_bytes();
    let mut manifest_header = tar::Header::new_gnu();
    manifest_header.set_size(manifest_bytes.len() as u64);
    manifest_header.set_mode(0o644);
    manifest_header.set_mtime(0);
    manifest_header.set_cksum();
    tar.append_data(&mut manifest_header, "+MANIFEST", manifest_bytes.as_slice())?;

    // Append +DESC
    let desc_bytes = desc_content.into_bytes();
    let mut desc_header = tar::Header::new_gnu();
    desc_header.set_size(desc_bytes.len() as u64);
    desc_header.set_mode(0o644);
    desc_header.set_mtime(0);
    desc_header.set_cksum();
    tar.append_data(&mut desc_header, "+DESC", desc_bytes.as_slice())?;

    // Append payload files
    for (rel_path, bytes, mode) in &files_to_embed {
        let mut file_header = tar::Header::new_gnu();
        file_header.set_size(bytes.len() as u64);
        file_header.set_mode(*mode);
        file_header.set_mtime(0);
        file_header.set_cksum();
        tar.append_data(&mut file_header, rel_path, bytes.as_slice())?;
    }

    // Finalize tar and compress
    tar.finish()?;

    println!("FreeBSD package created successfully!");
    println!("  Location: {}", pkg_file_path.display());

    // 6. Clean up temporary staging directory if requested
    if metadata.should_clean_workdir() && staged_dir.exists() {
        let _ = fs::remove_dir_all(&staged_dir);
    }

    Ok(pkg_file_path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;

    #[test]
    fn test_freebsd_packaging_flow() {
        let tmp = std::env::temp_dir().join("test_freebsd_pkg");
        let _ = fs::remove_dir_all(&tmp);
        fs::create_dir_all(&tmp).expect("create temp dir");

        let out_dir = tmp.join("out");
        fs::create_dir_all(&out_dir).expect("create out dir");

        let metadata = Metadata {
            name: "bsdtest".to_string(),
            version: "1.0.0".to_string(),
            release: "1".to_string(),
            maintainer: "FreeBSD Test Maintainer".to_string(),
            email: "test@freebsd.org".to_string(),
            description: "Test FreeBSD package".to_string(),
            arch: vec!["x86_64".to_string()],
            url: "https://example.com/bsdtest".to_string(),
            license: "MIT".to_string(),
            freebsd_origin: "devel/bsdtest".to_string(),
            freebsd_categories: vec!["devel".to_string()],
            freebsd_depends: vec!["misc/helper-tool".to_string()],
            ..Default::default()
        };

        let pkg_path =
            freebsd_package(&metadata, &out_dir).expect("freebsd_package should succeed");
        assert!(pkg_path.exists());
        assert!(pkg_path.to_string_lossy().ends_with("_amd64.pkg"));

        // Verify the package is a valid zstd-compressed tar archive
        let file = File::open(&pkg_path).expect("open pkg file");
        let zstd_dec = zstd::stream::read::Decoder::new(file).expect("create zstd decoder");
        let mut archive = tar::Archive::new(zstd_dec);

        let mut found_compact = false;
        let mut found_manifest = false;
        let mut found_desc = false;
        let mut manifest_content = String::new();

        for entry in archive.entries().expect("entries") {
            let mut entry = entry.expect("valid entry");
            let path = entry
                .path()
                .expect("valid path")
                .to_string_lossy()
                .into_owned();

            if path == "+COMPACT_MANIFEST" {
                found_compact = true;
            } else if path == "+MANIFEST" {
                found_manifest = true;
                entry
                    .read_to_string(&mut manifest_content)
                    .expect("read manifest");
            } else if path == "+DESC" {
                found_desc = true;
            }
        }

        assert!(found_compact, "+COMPACT_MANIFEST must exist in tarball");
        assert!(found_manifest, "+MANIFEST must exist in tarball");
        assert!(found_desc, "+DESC must exist in tarball");

        // Verify manifest contents
        assert!(manifest_content.contains("\"name\": \"bsdtest\""));
        assert!(manifest_content.contains("\"origin\": \"devel/bsdtest\""));
        assert!(manifest_content.contains("\"abi\": \"FreeBSD:14:amd64\""));
        assert!(manifest_content.contains("\"arch\": \"freebsd:14:x86:64\""));
        assert!(manifest_content.contains("\"version\": \"1.0.0\""));

        // Clean up
        let _ = fs::remove_dir_all(&tmp);
        let _ = fs::remove_dir_all(format!("{}.freebsd-dir", metadata.name));
    }
}

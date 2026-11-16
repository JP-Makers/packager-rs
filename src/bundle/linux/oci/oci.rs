use crate::chmod::chmod_package_with_metadata;
use crate::metadata::Metadata;
use flate2::write::GzEncoder;
use flate2::Compression;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

/// OCI content descriptor conforming to OCI Image Spec.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct OciDescriptor {
    #[serde(rename = "mediaType")]
    pub media_type: String,
    pub digest: String,
    pub size: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub annotations: Option<BTreeMap<String, String>>,
}

/// OCI Image Manifest specification (v1).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct OciManifest {
    #[serde(rename = "schemaVersion")]
    pub schema_version: u32,
    #[serde(rename = "mediaType")]
    pub media_type: String,
    pub config: OciDescriptor,
    pub layers: Vec<OciDescriptor>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub annotations: Option<BTreeMap<String, String>>,
}

/// OCI Image Configuration specification.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct OciConfig {
    pub created: String,
    pub architecture: String,
    pub os: String,
    pub config: OciExecutionConfig,
    pub rootfs: OciRootfs,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct OciExecutionConfig {
    #[serde(rename = "Env", skip_serializing_if = "Vec::is_empty")]
    pub env: Vec<String>,
    #[serde(rename = "Entrypoint", skip_serializing_if = "Vec::is_empty")]
    pub entrypoint: Vec<String>,
    #[serde(rename = "WorkingDir", skip_serializing_if = "String::is_empty")]
    pub working_dir: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct OciRootfs {
    #[serde(rename = "type")]
    pub rootfs_type: String,
    pub diff_ids: Vec<String>,
}

fn format_iso8601_now() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let days = secs / 86400;
    let rem_secs = secs % 86400;
    let hours = rem_secs / 3600;
    let mins = (rem_secs % 3600) / 60;
    let s = rem_secs % 60;

    let mut y = 1970i64;
    let mut d = days as i64;
    loop {
        let leap = if (y % 4 == 0 && y % 100 != 0) || (y % 400 == 0) { 1 } else { 0 };
        let days_in_year = 365 + leap;
        if d >= days_in_year {
            d -= days_in_year;
            y += 1;
        } else {
            let mdays = [31, 28 + leap, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
            let mut m = 0;
            while m < 12 && d >= mdays[m] {
                d -= mdays[m];
                m += 1;
            }
            return format!("{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z", y, m + 1, d + 1, hours, mins, s);
        }
    }
}

/// Builds an OCI image layer and manifest from package files.
pub fn build_oci_manifest(
    metadata: &Metadata,
    root_dir: &Path,
    output_dir: &Path,
) -> Result<PathBuf, Box<dyn std::error::Error>> {
    fs::create_dir_all(output_dir)?;

    // 1. Create rootfs tar archive
    let mut tar_bytes = Vec::new();
    {
        let mut tar_builder = tar::Builder::new(&mut tar_bytes);
        tar_builder.mode(tar::HeaderMode::Deterministic);

        for entry in walkdir::WalkDir::new(root_dir).min_depth(1) {
            let entry = entry?;
            let rel_path = entry.path().strip_prefix(root_dir)?;
            let rel_str = rel_path.to_string_lossy().into_owned();

            if entry.file_type().is_dir() {
                tar_builder.append_dir(&rel_str, entry.path())?;
            } else if entry.file_type().is_file() {
                let mut file = fs::File::open(entry.path())?;
                tar_builder.append_file(&rel_str, &mut file)?;
            } else if entry.file_type().is_symlink() {
                let target = fs::read_link(entry.path())?;
                let mut header = tar::Header::new_gnu();
                header.set_entry_type(tar::EntryType::Symlink);
                header.set_size(0);
                tar_builder.append_link(&mut header, &rel_str, &target)?;
            }
        }
        tar_builder.finish()?;
    }

    // Compute diff_id (SHA-256 of uncompressed tar)
    let mut diff_hasher = Sha256::new();
    diff_hasher.update(&tar_bytes);
    let diff_id = format!("sha256:{}", hex::encode(diff_hasher.finalize()));

    // 2. Gzip-compress rootfs layer
    let mut gz_encoder = GzEncoder::new(Vec::new(), Compression::default());
    gz_encoder.write_all(&tar_bytes)?;
    let layer_compressed = gz_encoder.finish()?;

    let mut layer_hasher = Sha256::new();
    layer_hasher.update(&layer_compressed);
    let layer_digest = format!("sha256:{}", hex::encode(layer_hasher.finalize()));
    let layer_size = layer_compressed.len() as u64;

    // 3. Generate OCI config JSON
    let created_ts = format_iso8601_now();
    let arch = match metadata.deb_arch() {
        "amd64" => "amd64",
        "arm64" => "arm64",
        "i386" => "386",
        "armhf" => "arm",
        other => other,
    };

    let entrypoint = if !metadata.appimage_exec.is_empty() {
        vec![metadata.appimage_exec.clone()]
    } else {
        vec![format!("/usr/bin/{}", metadata.name)]
    };

    let config_struct = OciConfig {
        created: created_ts,
        architecture: arch.to_string(),
        os: "linux".to_string(),
        config: OciExecutionConfig {
            env: vec![
                "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin".to_string(),
            ],
            entrypoint,
            working_dir: "/".to_string(),
        },
        rootfs: OciRootfs {
            rootfs_type: "layers".to_string(),
            diff_ids: vec![diff_id],
        },
    };

    let config_json = serde_json::to_string_pretty(&config_struct)?;
    let mut config_hasher = Sha256::new();
    config_hasher.update(config_json.as_bytes());
    let config_digest = format!("sha256:{}", hex::encode(config_hasher.finalize()));
    let config_size = config_json.len() as u64;

    // 4. Assemble OCI Image Manifest
    let manifest = OciManifest {
        schema_version: 2,
        media_type: "application/vnd.oci.image.manifest.v1+json".to_string(),
        config: OciDescriptor {
            media_type: "application/vnd.oci.image.config.v1+json".to_string(),
            digest: config_digest,
            size: config_size,
            annotations: None,
        },
        layers: vec![OciDescriptor {
            media_type: "application/vnd.oci.image.layer.v1.tar+gzip".to_string(),
            digest: layer_digest,
            size: layer_size,
            annotations: None,
        }],
        annotations: None,
    };

    let manifest_json = serde_json::to_string_pretty(&manifest)?;

    // Filename matching upstream Keygen convention: <name>-<version>-linux-<arch>.oci-manifest.json
    let target_arch = metadata.primary_arch();
    let manifest_filename = format!(
        "{}-{}-linux-{}.oci-manifest.json",
        metadata.name, metadata.version, target_arch
    );
    let manifest_path = output_dir.join(manifest_filename);
    fs::write(&manifest_path, manifest_json)?;

    // Also write layer blob and config blob so OCI image payload exists alongside the manifest
    let layer_blob_filename = format!(
        "{}-{}-linux-{}-layer.tar.gz",
        metadata.name, metadata.version, target_arch
    );
    fs::write(output_dir.join(layer_blob_filename), &layer_compressed)?;

    let config_blob_filename = format!(
        "{}-{}-linux-{}-config.json",
        metadata.name, metadata.version, target_arch
    );
    fs::write(output_dir.join(config_blob_filename), config_json.as_bytes())?;

    println!("OCI manifest created at: {}", manifest_path.display());
    Ok(manifest_path)
}

/// Packages the application into an OCI image manifest.
pub fn oci_package(
    metadata: &Metadata,
    output_dir: &Path,
) -> Result<PathBuf, Box<dyn std::error::Error>> {
    let tmp_dir = format!("{}.oci-rootfs", metadata.name);
    let rootfs_dir = PathBuf::from(&tmp_dir);

    // Populate package directory structure according to metadata
    chmod_package_with_metadata(metadata, &rootfs_dir, false)?;

    let result = build_oci_manifest(metadata, &rootfs_dir, output_dir);

    // Clean up temporary rootfs staging directory
    let _ = fs::remove_dir_all(&rootfs_dir);

    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_oci_manifest_structure() {
        let tmp = std::env::temp_dir().join("test_oci_manifest");
        let _ = fs::remove_dir_all(&tmp);
        fs::create_dir_all(&tmp).expect("create temp dir");

        let rootfs = tmp.join("rootfs");
        let bin_dir = rootfs.join("usr/bin");
        fs::create_dir_all(&bin_dir).expect("create bin dir");
        fs::write(bin_dir.join("testapp"), b"#!/bin/sh\necho test").expect("write bin");

        let out_dir = tmp.join("out");
        fs::create_dir_all(&out_dir).expect("create out dir");

        let metadata = Metadata {
            name: "testapp".to_string(),
            version: "1.0.0".to_string(),
            release: "1".to_string(),
            arch: vec!["x86_64".to_string()],
            ..Default::default()
        };

        let manifest_path = build_oci_manifest(&metadata, &rootfs, &out_dir).expect("build oci manifest");
        assert!(manifest_path.exists());
        assert_eq!(manifest_path.file_name().unwrap(), "testapp-1.0.0-linux-x86_64.oci-manifest.json");

        let content = fs::read_to_string(&manifest_path).expect("read manifest");
        let parsed: OciManifest = serde_json::from_str(&content).expect("parse oci manifest");

        assert_eq!(parsed.schema_version, 2);
        assert_eq!(parsed.media_type, "application/vnd.oci.image.manifest.v1+json");
        assert_eq!(parsed.config.media_type, "application/vnd.oci.image.config.v1+json");
        assert!(parsed.config.digest.starts_with("sha256:"));
        assert_eq!(parsed.layers.len(), 1);
        assert_eq!(parsed.layers[0].media_type, "application/vnd.oci.image.layer.v1.tar+gzip");
        assert!(parsed.layers[0].digest.starts_with("sha256:"));

        let _ = fs::remove_dir_all(&tmp);
    }
}

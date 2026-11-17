use crate::chmod::chmod_package_with_metadata;
use crate::metadata::Metadata;
use crate::repro::{iso8601, timestamp};
use flate2::Compression;
use flate2::write::GzEncoder;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

/// OCI platform descriptor.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct OciPlatform {
    pub architecture: String,
    pub os: String,
}

/// OCI index manifest entry.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct OciIndexManifestEntry {
    #[serde(rename = "mediaType")]
    pub media_type: String,
    pub digest: String,
    pub size: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub platform: Option<OciPlatform>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub annotations: Option<BTreeMap<String, String>>,
}

/// OCI Image Index specification (v1).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct OciIndex {
    #[serde(rename = "schemaVersion")]
    pub schema_version: u32,
    #[serde(rename = "mediaType", skip_serializing_if = "Option::is_none")]
    pub media_type: Option<String>,
    pub manifests: Vec<OciIndexManifestEntry>,
}

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
    let created_ts = iso8601(timestamp());
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
    let config_hex = hex::encode(config_hasher.finalize());
    let config_digest = format!("sha256:{}", config_hex);
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
            digest: layer_digest.clone(),
            size: layer_size,
            annotations: None,
        }],
        annotations: None,
    };

    let manifest_json = serde_json::to_string_pretty(&manifest)?;
    let mut manifest_hasher = Sha256::new();
    manifest_hasher.update(manifest_json.as_bytes());
    let manifest_hex = hex::encode(manifest_hasher.finalize());
    let manifest_digest = format!("sha256:{}", manifest_hex);
    let manifest_size = manifest_json.len() as u64;

    // 5. Standard OCI Image Layout files
    // 5a. oci-layout
    let oci_layout_path = output_dir.join("oci-layout");
    fs::write(&oci_layout_path, "{\"imageLayoutVersion\": \"1.0.0\"}\n")?;

    // 5b. blobs/sha256/<hash>
    let blobs_dir = output_dir.join("blobs").join("sha256");
    fs::create_dir_all(&blobs_dir)?;

    let layer_hex = layer_digest
        .strip_prefix("sha256:")
        .unwrap_or(&layer_digest);
    fs::write(blobs_dir.join(&config_hex), config_json.as_bytes())?;
    fs::write(blobs_dir.join(layer_hex), &layer_compressed)?;
    fs::write(blobs_dir.join(&manifest_hex), manifest_json.as_bytes())?;

    // 5c. index.json
    let index = OciIndex {
        schema_version: 2,
        media_type: Some("application/vnd.oci.image.index.v1+json".to_string()),
        manifests: vec![OciIndexManifestEntry {
            media_type: "application/vnd.oci.image.manifest.v1+json".to_string(),
            digest: manifest_digest,
            size: manifest_size,
            platform: Some(OciPlatform {
                architecture: arch.to_string(),
                os: "linux".to_string(),
            }),
            annotations: None,
        }],
    };
    let index_json = serde_json::to_string_pretty(&index)?;
    fs::write(output_dir.join("index.json"), index_json)?;

    // Filename matching upstream Keygen convention: <name>-<version>-linux-<arch>.oci-manifest.json
    let target_arch = metadata.primary_arch();
    let manifest_filename = format!(
        "{}-{}-linux-{}.oci-manifest.json",
        metadata.name, metadata.version, target_arch
    );
    let manifest_path = output_dir.join(manifest_filename);
    fs::write(&manifest_path, &manifest_json)?;

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
    fs::write(
        output_dir.join(config_blob_filename),
        config_json.as_bytes(),
    )?;

    println!("OCI layout created at: {}", output_dir.display());
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

        let manifest_path =
            build_oci_manifest(&metadata, &rootfs, &out_dir).expect("build oci manifest");
        assert!(manifest_path.exists());
        assert_eq!(
            manifest_path.file_name().unwrap(),
            "testapp-1.0.0-linux-x86_64.oci-manifest.json"
        );

        let content = fs::read_to_string(&manifest_path).expect("read manifest");
        let parsed: OciManifest = serde_json::from_str(&content).expect("parse oci manifest");

        assert_eq!(parsed.schema_version, 2);
        assert_eq!(
            parsed.media_type,
            "application/vnd.oci.image.manifest.v1+json"
        );
        assert_eq!(
            parsed.config.media_type,
            "application/vnd.oci.image.config.v1+json"
        );
        assert!(parsed.config.digest.starts_with("sha256:"));
        assert_eq!(parsed.layers.len(), 1);
        assert_eq!(
            parsed.layers[0].media_type,
            "application/vnd.oci.image.layer.v1.tar+gzip"
        );
        assert!(parsed.layers[0].digest.starts_with("sha256:"));

        let _ = fs::remove_dir_all(&tmp);
    }

    #[test]
    fn test_oci_layout_is_complete() {
        let tmp = std::env::temp_dir().join(format!(
            "test_oci_layout_{}",
            uuid::Uuid::new_v4().hyphenated()
        ));
        let _ = fs::remove_dir_all(&tmp);
        fs::create_dir_all(&tmp).expect("create temp dir");

        let rootfs = tmp.join("rootfs");
        let bin_dir = rootfs.join("usr/bin");
        fs::create_dir_all(&bin_dir).expect("create bin dir");
        fs::write(bin_dir.join("app"), b"#!/bin/sh\necho running").expect("write bin");

        let out_dir = tmp.join("out");
        fs::create_dir_all(&out_dir).expect("create out dir");

        let metadata = Metadata {
            name: "complete-app".to_string(),
            version: "2.0.0".to_string(),
            release: "1".to_string(),
            arch: vec!["x86_64".to_string()],
            ..Default::default()
        };

        build_oci_manifest(&metadata, &rootfs, &out_dir).expect("build oci manifest");

        // 1. oci-layout exists and has correct version
        let layout_file = out_dir.join("oci-layout");
        assert!(layout_file.exists(), "oci-layout file must exist");
        let layout_content: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(&layout_file).unwrap()).unwrap();
        assert_eq!(layout_content["imageLayoutVersion"], "1.0.0");

        // 2. index.json exists and is valid
        let index_file = out_dir.join("index.json");
        assert!(index_file.exists(), "index.json file must exist");
        let index: OciIndex =
            serde_json::from_str(&fs::read_to_string(&index_file).unwrap()).unwrap();
        assert_eq!(index.schema_version, 2);
        assert!(!index.manifests.is_empty());

        // 3. blobs/sha256/ directory exists and all referenced blobs exist and have matching digests
        let blobs_dir = out_dir.join("blobs").join("sha256");
        assert!(blobs_dir.exists(), "blobs/sha256 directory must exist");

        for m_desc in &index.manifests {
            let m_hex = m_desc
                .digest
                .strip_prefix("sha256:")
                .expect("sha256 prefix");
            let m_blob_path = blobs_dir.join(m_hex);
            assert!(m_blob_path.exists(), "manifest blob {} must exist", m_hex);

            let m_bytes = fs::read(&m_blob_path).unwrap();
            let mut hasher = Sha256::new();
            hasher.update(&m_bytes);
            assert_eq!(hex::encode(hasher.finalize()), m_hex);

            let manifest: OciManifest = serde_json::from_slice(&m_bytes).unwrap();

            // Check config blob
            let cfg_hex = manifest
                .config
                .digest
                .strip_prefix("sha256:")
                .expect("sha256 prefix");
            let cfg_blob_path = blobs_dir.join(cfg_hex);
            assert!(cfg_blob_path.exists(), "config blob {} must exist", cfg_hex);
            let cfg_bytes = fs::read(&cfg_blob_path).unwrap();
            let mut hasher = Sha256::new();
            hasher.update(&cfg_bytes);
            assert_eq!(hex::encode(hasher.finalize()), cfg_hex);

            // Check layer blobs
            for layer in &manifest.layers {
                let layer_hex = layer.digest.strip_prefix("sha256:").expect("sha256 prefix");
                let layer_blob_path = blobs_dir.join(layer_hex);
                assert!(
                    layer_blob_path.exists(),
                    "layer blob {} must exist",
                    layer_hex
                );
                let layer_bytes = fs::read(&layer_blob_path).unwrap();
                let mut hasher = Sha256::new();
                hasher.update(&layer_bytes);
                assert_eq!(hex::encode(hasher.finalize()), layer_hex);
            }
        }

        let _ = fs::remove_dir_all(&tmp);
    }
}

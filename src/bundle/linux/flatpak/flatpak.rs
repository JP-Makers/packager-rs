use super::application::FlatpakApplication;
use super::architecture::FlatpakArchitecture;
use crate::bundle::linux::archive;
use crate::chmod::chmod_package_with_metadata;
use crate::metadata::Metadata;
use flate2::Compression;
use flate2::write::GzEncoder;
use std::fs::{self, File};
use std::io::Write;
use std::path::{Path, PathBuf};
use tar::Builder;

pub fn flatpak_package(
    metadata: &Metadata,
    output_dir: &Path,
) -> Result<PathBuf, Box<dyn std::error::Error>> {
    let app_id = metadata.flatpak_id();
    let flatpak_dir = format!("{}.flatpak-dir", metadata.name);
    let base_dir = PathBuf::from(&flatpak_dir);

    // Create Flatpak layout
    let files_dir = base_dir.join("files");
    let export_dir = base_dir.join("export");
    let export_apps = export_dir.join("share/applications");
    let export_icons = export_dir.join("share/icons/hicolor/scalable/apps");
    fs::create_dir_all(&export_apps)?;
    fs::create_dir_all(&export_icons)?;

    // Populate files using package layout (files/ represents /app prefix)
    chmod_package_with_metadata(metadata, &files_dir, false)?;

    let exec_command = metadata.executable_name();
    let flatpak_arch = FlatpakArchitecture::from_arch_str(metadata.primary_arch());
    let arch = flatpak_arch.as_str();

    // Look for desktop and icon in files_dir and export them
    if let Ok(entries) = walkdir::WalkDir::new(&files_dir)
        .into_iter()
        .collect::<Result<Vec<_>, _>>()
    {
        for entry in entries {
            let path = entry.path();
            if path.is_file()
                && let Some(ext) = path.extension().and_then(|e| e.to_str())
            {
                if ext == "desktop" {
                    let target_desktop = export_apps.join(format!("{}.desktop", app_id));
                    fs::copy(path, target_desktop)?;
                } else if ext == "svg" || ext == "png" {
                    let target_icon = export_icons.join(format!("{}.{}", app_id, ext));
                    fs::copy(path, target_icon)?;
                }
            }
        }
    }

    // Generate Flatpak metadata INI file
    let meta_file_path = base_dir.join("metadata");
    let mut meta_file = File::create(&meta_file_path)?;
    writeln!(meta_file, "[Application]")?;
    writeln!(meta_file, "name={}", app_id)?;
    writeln!(
        meta_file,
        "runtime={}/{}/{}",
        metadata.flatpak_runtime, arch, metadata.flatpak_runtime_version
    )?;
    writeln!(
        meta_file,
        "sdk={}/{}/{}",
        metadata.flatpak_sdk, arch, metadata.flatpak_runtime_version
    )?;
    writeln!(meta_file, "command={}", exec_command)?;
    writeln!(meta_file)?;
    writeln!(meta_file, "[Context]")?;
    writeln!(meta_file, "shared=network;ipc;")?;
    writeln!(meta_file, "sockets=x11;wayland;fallback-x11;pulseaudio;")?;
    writeln!(meta_file, "devices=all;")?;
    writeln!(meta_file, "filesystems=xdg-download;")?;
    drop(meta_file);

    // Build typed FlatpakApplication manifest
    let app_manifest = FlatpakApplication::from_metadata(metadata, &exec_command);

    // Write JSON manifest inside build directory
    let manifest_file_path = base_dir.join(format!("{}.json", app_id));
    fs::write(&manifest_file_path, app_manifest.to_json()?)?;

    // Also write YAML manifest inside build directory
    let manifest_yaml_path = base_dir.join(format!("{}.yaml", app_id));
    fs::write(&manifest_yaml_path, app_manifest.to_yaml()?)?;

    if !output_dir.exists() {
        fs::create_dir_all(output_dir)?;
    }

    // Copy manifests into output_dir
    let out_manifest_path = output_dir.join(format!("{}.json", app_id));
    fs::copy(&manifest_file_path, &out_manifest_path)?;

    let out_yaml_manifest_path = output_dir.join(format!("{}.yaml", app_id));
    fs::copy(&manifest_yaml_path, &out_yaml_manifest_path)?;

    // Generate .flatpakref file
    let ref_filename = format!("{}.flatpakref", app_id);
    let ref_path = output_dir.join(&ref_filename);
    let mut ref_file = File::create(&ref_path)?;
    writeln!(ref_file, "[Flatpak Ref]")?;
    writeln!(ref_file, "Title={}", metadata.name)?;
    writeln!(ref_file, "Name={}", app_id)?;
    writeln!(ref_file, "Branch=stable")?;
    writeln!(ref_file, "Url={}", metadata.url)?;
    writeln!(ref_file, "Description={}", metadata.description)?;
    drop(ref_file);

    let flatpak_tar_gz_path = output_dir.join(format!(
        "{}_{}_{}.flatpak.tar.gz",
        metadata.name, metadata.version, arch
    ));

    let return_path = create_flatpak_bundle(&base_dir, &flatpak_tar_gz_path)?;

    println!("Flatpak package created successfully!");
    println!("  JSON Manifest: {}", out_manifest_path.display());
    println!("  YAML Manifest: {}", out_yaml_manifest_path.display());
    println!("  Ref File     : {}", ref_path.display());
    println!("  Archive      : {}", return_path.display());

    // Clean up temporary bundle directory only if clean_workdir is requested
    if metadata.clean_workdir {
        let _ = fs::remove_dir_all(&base_dir);
    }

    Ok(return_path)
}

fn create_flatpak_bundle(
    base_dir: &Path,
    tar_gz_path: &Path,
) -> Result<PathBuf, Box<dyn std::error::Error>> {
    let file = File::create(tar_gz_path)?;
    let enc = GzEncoder::new(file, Compression::default());
    let mut tar = Builder::new(enc);

    for entry in walkdir::WalkDir::new(base_dir) {
        let entry = entry?;
        let path = entry.path();
        let rel_path = path.strip_prefix(base_dir)?;
        if path.is_file() {
            archive::append_file(&mut tar, path, rel_path, archive::file_mode(path))?;
        } else if path.is_dir() && !rel_path.as_os_str().is_empty() {
            archive::append_dir(&mut tar, path, rel_path)?;
        }
    }

    tar.finish()?;
    let enc = tar.into_inner()?;
    enc.finish()?;

    Ok(tar_gz_path.to_path_buf())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_flatpak_extension_matches_format() {
        let tmp = std::env::temp_dir().join(format!(
            "test_flatpak_ext_{}",
            uuid::Uuid::new_v4().hyphenated()
        ));
        let _ = fs::remove_dir_all(&tmp);
        fs::create_dir_all(&tmp).expect("create temp dir");

        let out_dir = tmp.join("out");
        fs::create_dir_all(&out_dir).expect("create out dir");

        let work_dir = tmp.join("work");
        fs::create_dir_all(work_dir.join("usr/bin")).expect("create bin dir");
        fs::write(
            work_dir.join("usr/bin/mytestapp"),
            b"#!/bin/sh\necho flatpak",
        )
        .expect("write bin");

        let metadata = Metadata {
            name: "mytestapp".to_string(),
            version: "1.0.0".to_string(),
            description: "A short test application description".to_string(),
            maintainer: "Maintainer <m@example.com>".to_string(),
            workdir: Some(work_dir.to_string_lossy().to_string()),
            package_instructions: vec![format!(
                "install -m755 \"local:{}\" to /usr/bin/",
                work_dir.join("usr/bin/mytestapp").display()
            )],
            ..Default::default()
        };

        let result_path = flatpak_package(&metadata, &out_dir).expect("package flatpak");
        assert!(result_path.exists());
        let result_str = result_path.to_string_lossy();
        assert!(
            result_str.ends_with(".flatpak.tar.gz"),
            "expected result to end with .flatpak.tar.gz, got {}",
            result_str
        );

        // Verify that NO fake .flatpak file (without .tar.gz) was generated
        let fake_flatpak = out_dir.join(format!("{}_1.0.0_x86_64.flatpak", metadata.name));
        assert!(
            !fake_flatpak.exists(),
            "fake .flatpak file should not exist, but found {}",
            fake_flatpak.display()
        );

        let _ = fs::remove_dir_all(&tmp);
        let _ = fs::remove_dir_all(format!("{}.flatpak-dir", metadata.name));
    }
}

use crate::bundle::linux::appimage::squashfs::squashfs_build_to_file;
use crate::chmod::chmod_package_with_metadata;
use crate::metadata::Metadata;
use serde::Serialize;
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Serialize)]
struct SnapApp<'a> {
    command: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    desktop: Option<String>,
    plugs: Vec<&'a str>,
}

#[derive(Debug, Serialize)]
struct SnapYaml<'a> {
    name: &'a str,
    version: &'a str,
    summary: &'a str,
    description: &'a str,
    grade: &'a str,
    confinement: &'a str,
    base: &'a str,
    architectures: Vec<&'a str>,
    apps: BTreeMap<&'a str, SnapApp<'a>>,
}

#[derive(Debug, Clone, Serialize)]
struct SnapPart<'a> {
    plugin: &'a str,
    source: &'a str,
}

#[derive(Debug, Serialize)]
struct SnapcraftYaml<'a> {
    name: &'a str,
    version: &'a str,
    summary: &'a str,
    description: &'a str,
    grade: &'a str,
    confinement: &'a str,
    base: &'a str,
    apps: BTreeMap<&'a str, SnapApp<'a>>,
    parts: BTreeMap<&'a str, SnapPart<'a>>,
}

pub fn snap_package(
    metadata: &Metadata,
    output_dir: &Path,
) -> Result<PathBuf, Box<dyn std::error::Error>> {
    let snap_dir = format!("{}.snap-dir", metadata.name);
    let base_dir = PathBuf::from(&snap_dir);

    // Prepare package layout in temporary directory
    chmod_package_with_metadata(metadata, &base_dir, false)?;

    // Create meta/ and meta/gui/ directories
    let meta_dir = base_dir.join("meta");
    let gui_dir = meta_dir.join("gui");
    fs::create_dir_all(&gui_dir)?;

    // Look for desktop file and icon in base_dir
    let mut desktop_found = false;
    let mut icon_found = false;

    if let Ok(entries) = walkdir::WalkDir::new(&base_dir)
        .into_iter()
        .collect::<Result<Vec<_>, _>>()
    {
        for entry in entries {
            let path = entry.path();
            if path.is_file()
                && let Some(ext) = path.extension().and_then(|e| e.to_str())
            {
                if ext == "desktop" && !desktop_found {
                    let target_desktop = gui_dir.join(format!("{}.desktop", metadata.name));
                    fs::copy(path, target_desktop)?;
                    desktop_found = true;
                } else if (ext == "png" || ext == "svg") && !icon_found {
                    let target_icon = gui_dir.join(format!("icon.{}", ext));
                    fs::copy(path, target_icon)?;
                    icon_found = true;
                }
            }
        }
    }

    // Ensure desktop entry uses the snapped icon path
    if desktop_found && icon_found {
        let target_desktop = gui_dir.join(format!("{}.desktop", metadata.name));
        if target_desktop.exists() {
            let icon_file = if gui_dir.join("icon.svg").exists() {
                "icon.svg"
            } else {
                "icon.png"
            };
            if let Ok(content) = fs::read_to_string(&target_desktop) {
                let mut rewritten = String::new();
                for l in content.lines() {
                    if l.starts_with("Icon=") {
                        rewritten.push_str(&format!("Icon=${{SNAP}}/meta/gui/{}\n", icon_file));
                    } else {
                        rewritten.push_str(l);
                        rewritten.push('\n');
                    }
                }
                fs::write(&target_desktop, rewritten)?;
            }
        }
    }

    // Determine executable path relative to snap root
    let exec_cmd = if !metadata.appimage_exec.is_empty() {
        metadata.appimage_exec.trim_start_matches('/').to_string()
    } else {
        format!("usr/bin/{}", metadata.name)
    };

    let architecture = metadata.deb_arch();

    // Create meta/snap.yaml per Canonical Snap specification using serde_yaml
    let snap_yaml_path = meta_dir.join("snap.yaml");
    let mut apps = BTreeMap::new();
    apps.insert(
        metadata.name.as_str(),
        SnapApp {
            command: exec_cmd,
            desktop: if desktop_found {
                Some(format!("meta/gui/{}.desktop", metadata.name))
            } else {
                None
            },
            plugs: vec![
                "desktop",
                "desktop-legacy",
                "x11",
                "wayland",
                "unity7",
                "opengl",
                "home",
                "network",
                "audio-playback",
                "raw-usb",
                "hardware-observe",
                "network-control",
            ],
        },
    );

    let snap_meta = SnapYaml {
        name: &metadata.name,
        version: &metadata.version,
        summary: &metadata.description,
        description: &metadata.description,
        grade: &metadata.snap_grade,
        confinement: &metadata.snap_confinement,
        base: &metadata.snap_base,
        architectures: vec![architecture],
        apps: apps.clone(),
    };

    let yaml_content = serde_yaml::to_string(&snap_meta)?;
    fs::write(&snap_yaml_path, yaml_content)?;

    // Also generate a declarative snapcraft.yaml for developers using serde_yaml
    let snapcraft_yaml_path = meta_dir.join("snapcraft.yaml");
    let mut parts = BTreeMap::new();
    parts.insert(
        metadata.name.as_str(),
        SnapPart {
            plugin: "dump",
            source: ".",
        },
    );

    let snapcraft_meta = SnapcraftYaml {
        name: &metadata.name,
        version: &metadata.version,
        summary: &metadata.description,
        description: &metadata.description,
        grade: &metadata.snap_grade,
        confinement: &metadata.snap_confinement,
        base: &metadata.snap_base,
        apps,
        parts,
    };
    let sc_yaml = serde_yaml::to_string(&snapcraft_meta)?;
    fs::write(&snapcraft_yaml_path, sc_yaml)?;

    if !output_dir.exists() {
        fs::create_dir_all(output_dir)?;
    }

    let snap_filename = format!(
        "{}_{}_{}.snap",
        metadata.name, metadata.version, architecture
    );
    let snap_output_path = output_dir.join(snap_filename);

    // Build SquashFS container for .snap
    let base_dir_str = base_dir.to_string_lossy();
    squashfs_build_to_file(&base_dir_str, &snap_output_path)?;

    println!(".snap package created successfully!");
    println!("  Location: {}", snap_output_path.display());

    // Clean up temporary bundle directory only if clean_workdir is requested
    if metadata.clean_workdir {
        let _ = fs::remove_dir_all(&base_dir);
    }

    Ok(snap_output_path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_snapcraft_has_apps_and_parts() {
        let tmp = std::env::temp_dir().join(format!(
            "test_snapcraft_{}",
            uuid::Uuid::new_v4().hyphenated()
        ));
        let _ = fs::remove_dir_all(&tmp);
        fs::create_dir_all(&tmp).expect("create temp dir");

        let out_dir = tmp.join("out");
        fs::create_dir_all(&out_dir).expect("create out dir");

        let work_dir = tmp.join("work");
        fs::create_dir_all(work_dir.join("usr/bin")).expect("create bin dir");
        fs::write(work_dir.join("usr/bin/snaptest"), b"#!/bin/sh\necho snap").expect("write bin");

        let metadata = Metadata {
            name: "snaptest".to_string(),
            version: "1.0.0".to_string(),
            description: "A short snap test description".to_string(),
            maintainer: "Maintainer <m@example.com>".to_string(),
            workdir: Some(work_dir.to_string_lossy().to_string()),
            package_instructions: vec![format!(
                "install -m755 \"local:{}\" to /usr/bin/",
                work_dir.join("usr/bin/snaptest").display()
            )],
            snap_grade: "stable".to_string(),
            snap_confinement: "strict".to_string(),
            snap_base: "core22".to_string(),
            clean_workdir: false,
            ..Default::default()
        };

        let snap_path = snap_package(&metadata, &out_dir).expect("snap_package");
        assert!(snap_path.exists());

        // Verify the staged snapcraft.yaml file
        let snap_dir = PathBuf::from(format!("{}.snap-dir", metadata.name));
        let snapcraft_path = snap_dir.join("meta/snapcraft.yaml");
        assert!(snapcraft_path.exists(), "meta/snapcraft.yaml must exist");

        let content = fs::read_to_string(&snapcraft_path).expect("read snapcraft.yaml");
        let parsed: serde_yaml::Value =
            serde_yaml::from_str(&content).expect("parse snapcraft.yaml");

        // Verify apps block
        let apps = parsed.get("apps").expect("snapcraft.yaml must have apps");
        let app = apps.get("snaptest").expect("must have app entry");
        assert!(app.get("command").is_some());
        assert!(app.get("plugs").is_some());

        // Verify parts block
        let parts = parsed.get("parts").expect("snapcraft.yaml must have parts");
        let part = parts.get("snaptest").expect("must have part entry");
        assert_eq!(part.get("plugin").and_then(|p| p.as_str()), Some("dump"));
        assert_eq!(part.get("source").and_then(|s| s.as_str()), Some("."));

        let _ = fs::remove_dir_all(&tmp);
        let _ = fs::remove_dir_all(&snap_dir);
    }
}

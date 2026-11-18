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

/// Locate desktop and icon files deterministically.
fn locate_desktop_and_icon(base_dir: &Path, app_name: &str) -> (Option<PathBuf>, Option<PathBuf>) {
    let mut desktop_files = Vec::new();
    let mut icon_files = Vec::new();

    if let Ok(entries) = walkdir::WalkDir::new(base_dir)
        .sort_by_file_name()
        .into_iter()
        .collect::<Result<Vec<_>, _>>()
    {
        for entry in entries {
            let path = entry.path();
            if path.is_file()
                && let Some(ext) = path.extension().and_then(|e| e.to_str())
            {
                if ext == "desktop" {
                    desktop_files.push(path.to_path_buf());
                } else if ext == "png" || ext == "svg" {
                    icon_files.push(path.to_path_buf());
                }
            }
        }
    }

    // 1. Desktop: prefer <app_name>.desktop, otherwise first alphabetically
    let chosen_desktop = desktop_files
        .iter()
        .find(|p| p.file_name().and_then(|f| f.to_str()) == Some(&format!("{app_name}.desktop")))
        .cloned()
        .or_else(|| desktop_files.into_iter().next());

    // 2. Icon: prefer <app_name>.svg, then <app_name>.png, then any svg, then any png
    let chosen_icon = icon_files
        .iter()
        .find(|p| p.file_name().and_then(|f| f.to_str()) == Some(&format!("{app_name}.svg")))
        .or_else(|| {
            icon_files.iter().find(|p| {
                p.file_name().and_then(|f| f.to_str()) == Some(&format!("{app_name}.png"))
            })
        })
        .or_else(|| {
            icon_files
                .iter()
                .find(|p| p.extension().and_then(|e| e.to_str()) == Some("svg"))
        })
        .or_else(|| icon_files.first())
        .cloned();

    (chosen_desktop, chosen_icon)
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

    // Look for desktop file and icon deterministically
    let (chosen_desktop, chosen_icon) = locate_desktop_and_icon(&base_dir, &metadata.name);

    let desktop_found = if let Some(ref d_path) = chosen_desktop {
        let target_desktop = gui_dir.join(format!("{}.desktop", metadata.name));
        fs::copy(d_path, target_desktop)?;
        true
    } else {
        false
    };

    let icon_found = if let Some(ref i_path) = chosen_icon {
        let ext = i_path.extension().and_then(|e| e.to_str()).unwrap_or("png");
        let target_icon = gui_dir.join(format!("icon.{}", ext));
        fs::copy(i_path, target_icon)?;
        true
    } else {
        false
    };

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

    // Create meta/snap.yaml per Canonical Snap specification using serde_yml
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
            plugs: metadata.snap_plugs(),
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
        apps,
    };

    let yaml_content = serde_yml::to_string(&snap_meta)?;
    fs::write(&snap_yaml_path, yaml_content)?;

    // Note: snapcraft.yaml is a build-source recipe and is intentionally omitted
    // from the built snap package's meta/ directory.

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

        // Verify meta/snap.yaml exists
        let snap_dir = PathBuf::from(format!("{}.snap-dir", metadata.name));
        let snap_yaml_path = snap_dir.join("meta/snap.yaml");
        assert!(snap_yaml_path.exists(), "meta/snap.yaml must exist");

        // Verify snapcraft.yaml is NOT written into meta/
        let snapcraft_path = snap_dir.join("meta/snapcraft.yaml");
        assert!(
            !snapcraft_path.exists(),
            "meta/snapcraft.yaml must NOT exist in the built snap's meta/"
        );

        let content = fs::read_to_string(&snap_yaml_path).expect("read snap.yaml");
        let parsed: serde_yml::Value = serde_yml::from_str(&content).expect("parse snap.yaml");

        // Verify apps block
        let apps = parsed.get("apps").expect("snap.yaml must have apps");
        let app = apps.get("snaptest").expect("must have app entry");
        assert!(app.get("command").is_some());
        let plugs = app
            .get("plugs")
            .expect("must have plugs")
            .as_sequence()
            .expect("plugs sequence");

        // Default plugs must not contain over-broad plugs
        let plug_names: Vec<&str> = plugs.iter().filter_map(|v| v.as_str()).collect();
        assert!(
            !plug_names.contains(&"raw-usb"),
            "raw-usb should not be in default plugs"
        );
        assert!(
            !plug_names.contains(&"hardware-observe"),
            "hardware-observe should not be in default plugs"
        );
        assert!(
            !plug_names.contains(&"network-control"),
            "network-control should not be in default plugs"
        );
        assert!(
            !plug_names.contains(&"unity7"),
            "unity7 should not be in default plugs"
        );
        assert!(plug_names.contains(&"desktop"));
        assert!(plug_names.contains(&"home"));

        let _ = fs::remove_dir_all(&tmp);
        let _ = fs::remove_dir_all(&snap_dir);
    }

    #[test]
    fn test_snap_custom_plugs() {
        let tmp = std::env::temp_dir().join(format!(
            "test_snap_custom_{}",
            uuid::Uuid::new_v4().hyphenated()
        ));
        let _ = fs::remove_dir_all(&tmp);
        fs::create_dir_all(&tmp).expect("create temp dir");

        let out_dir = tmp.join("out");
        fs::create_dir_all(&out_dir).expect("create out dir");

        let work_dir = tmp.join("work");
        fs::create_dir_all(work_dir.join("usr/bin")).expect("create bin dir");
        fs::write(work_dir.join("usr/bin/snapcustom"), b"#!/bin/sh\necho snap").expect("write bin");

        let metadata = Metadata {
            name: "snapcustom".to_string(),
            version: "1.0.0".to_string(),
            description: "Custom plugs snap".to_string(),
            maintainer: "Maintainer <m@example.com>".to_string(),
            workdir: Some(work_dir.to_string_lossy().to_string()),
            package_instructions: vec![format!(
                "install -m755 \"local:{}\" to /usr/bin/",
                work_dir.join("usr/bin/snapcustom").display()
            )],
            snap_plugs: vec!["home".to_string(), "network".to_string()],
            clean_workdir: false,
            ..Default::default()
        };

        let snap_path = snap_package(&metadata, &out_dir).expect("snap_package");
        assert!(snap_path.exists());

        let snap_dir = PathBuf::from(format!("{}.snap-dir", metadata.name));
        let snap_yaml_path = snap_dir.join("meta/snap.yaml");
        let content = fs::read_to_string(&snap_yaml_path).expect("read snap.yaml");
        let parsed: serde_yml::Value = serde_yml::from_str(&content).expect("parse snap.yaml");
        let app = parsed.get("apps").unwrap().get("snapcustom").unwrap();
        let plugs: Vec<&str> = app
            .get("plugs")
            .unwrap()
            .as_sequence()
            .unwrap()
            .iter()
            .filter_map(|v| v.as_str())
            .collect();
        assert_eq!(plugs, vec!["home", "network"]);

        let _ = fs::remove_dir_all(&tmp);
        let _ = fs::remove_dir_all(&snap_dir);
    }
}

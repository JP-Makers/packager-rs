use crate::bundle::macos::dmg::iso::generate_iso_image;
use crate::bundle::macos::dmg::koly::create_udif_dmg_image;
use crate::bundle::macos::dmg::plist::{generate_info_plist, generate_pkg_info};
use crate::chmod::chmod_package_with_metadata;
use crate::metadata::Metadata;
use crate::payload::is_macho;
use std::fs;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

/// Find the main executable file based on metadata configuration and workdir contents.
fn locate_executable(metadata: &Metadata, staged_root: &Path) -> Option<(PathBuf, String)> {
    let exec_name = metadata.executable_name();

    // 1. Check in staged root (e.g. usr/bin/<name> or bin/<name> or <name>)
    let candidates = [
        staged_root.join("usr/bin").join(&exec_name),
        staged_root.join("bin").join(&exec_name),
        staged_root.join(&exec_name),
        staged_root.join("usr/bin").join(&metadata.name),
        staged_root.join("bin").join(&metadata.name),
        staged_root.join(&metadata.name),
    ];

    for c in &candidates {
        if c.is_file() {
            return Some((c.clone(), exec_name));
        }
    }

    // 2. Check workdir directly
    let work = Path::new(metadata.workdir());
    let work_candidates = [
        work.join(&metadata.appimage_exec),
        work.join("usr/bin").join(&exec_name),
        work.join("bin").join(&exec_name),
        work.join(&exec_name),
        work.join("target/release").join(&exec_name),
        work.join(&metadata.name),
        PathBuf::from(&metadata.name),
    ];

    for c in &work_candidates {
        if c.is_file() {
            return Some((c.clone(), exec_name));
        }
    }

    // 3. Fallback: recursively search staged_root for any executable file matching exec_name or name
    if let Ok(entries) = walkdir::WalkDir::new(staged_root)
        .into_iter()
        .collect::<Result<Vec<_>, _>>()
    {
        for entry in entries {
            if entry.file_type().is_file() {
                let file_name = entry.file_name().to_string_lossy();
                if file_name == exec_name || file_name == metadata.name {
                    return Some((entry.into_path(), exec_name));
                }
            }
        }
    }

    None
}

/// Locate or extract an icon file (.icns only) for the bundle.
fn locate_icon(metadata: &Metadata, staged_root: &Path) -> Option<(PathBuf, String)> {
    // 1. Explicit metadata mac_icon (must be .icns)
    if !metadata.mac_icon.is_empty() {
        let candidates = [
            PathBuf::from(&metadata.mac_icon),
            Path::new(metadata.workdir()).join(&metadata.mac_icon),
        ];
        for p in &candidates {
            if p.is_file() {
                let is_icns = p
                    .extension()
                    .and_then(|s| s.to_str())
                    .is_some_and(|ext| ext.eq_ignore_ascii_case("icns"))
                    || fs::read(p).map(|b| b.starts_with(b"icns")).unwrap_or(false);
                if is_icns {
                    let filename = p
                        .file_name()
                        .unwrap_or_default()
                        .to_string_lossy()
                        .to_string();
                    return Some((p.clone(), filename));
                }
            }
        }
    }

    // 2. Search staged root or workdir for .icns
    for root in &[staged_root, Path::new(metadata.workdir()), Path::new(".")] {
        if let Ok(entries) = walkdir::WalkDir::new(root)
            .max_depth(4)
            .into_iter()
            .collect::<Result<Vec<_>, _>>()
        {
            for entry in entries {
                if entry.file_type().is_file() {
                    let path = entry.path();
                    let is_icns = path
                        .extension()
                        .and_then(|s| s.to_str())
                        .is_some_and(|ext| ext.eq_ignore_ascii_case("icns"))
                        || fs::read(path)
                            .map(|b| b.starts_with(b"icns"))
                            .unwrap_or(false);
                    if is_icns {
                        let filename = path
                            .file_name()
                            .unwrap_or_default()
                            .to_string_lossy()
                            .to_string();
                        return Some((path.to_path_buf(), filename));
                    }
                }
            }
        }
    }

    // SVG / PNG fallback is intentionally omitted: macOS cannot load non-ICNS icons directly.
    None
}

/// Package the application into a native macOS Apple Disk Image (`.dmg`) in pure Rust.
pub fn dmg_package(
    metadata: &Metadata,
    output_dir: &Path,
) -> Result<PathBuf, Box<dyn std::error::Error>> {
    println!("Packaging macOS DMG for: {}", metadata.name);

    if !output_dir.exists() {
        fs::create_dir_all(output_dir)?;
    }

    let app_name = metadata.app_name();
    let dmg_staging_dir = PathBuf::from(format!("{}.dmg-dir", metadata.name));
    if dmg_staging_dir.exists() {
        fs::remove_dir_all(&dmg_staging_dir)?;
    }
    fs::create_dir_all(&dmg_staging_dir)?;

    // Step 1: Stage application files using chmod_package_with_metadata into a temporary dir
    let temp_root = dmg_staging_dir.join("_pkg_root");
    chmod_package_with_metadata(metadata, &temp_root, false)?;

    // Step 2: Create .app bundle structure inside staging directory
    let app_bundle_dir = dmg_staging_dir.join(format!("{}.app", app_name));
    let contents_dir = app_bundle_dir.join("Contents");
    let macos_dir = contents_dir.join("MacOS");
    let resources_dir = contents_dir.join("Resources");

    fs::create_dir_all(&macos_dir)?;
    fs::create_dir_all(&resources_dir)?;

    // Step 3: Populate executable
    let (exec_source, exec_filename) =
        locate_executable(metadata, &temp_root).ok_or_else(|| {
            format!(
                "refusing to build DMG: no macOS executable found in {temp_root:?} or workdir {:?}",
                metadata.workdir()
            )
        })?;

    let exec_bytes = fs::read(&exec_source)?;
    if !is_macho(&exec_bytes) {
        return Err(format!(
            "refusing to build DMG: {:?} is not a Mach-O executable; supply a macOS payload for [build.mac]",
            exec_source.display()
        )
        .into());
    }

    let target_exec = macos_dir.join(&exec_filename);
    fs::copy(&exec_source, &target_exec)?;
    #[cfg(unix)]
    {
        fs::set_permissions(&target_exec, fs::Permissions::from_mode(0o755))?;
    }

    // Step 4: Populate icon if available
    let icon_info = locate_icon(metadata, &temp_root);
    let icon_leaf_name = if let Some((icon_src, ref icon_file)) = icon_info {
        let dest_icon = resources_dir.join(icon_file);
        fs::copy(&icon_src, &dest_icon)?;
        Some(icon_file.clone())
    } else {
        None
    };

    // Step 5: Write Info.plist and PkgInfo
    let info_plist = generate_info_plist(metadata, &exec_filename, icon_leaf_name.as_deref());
    let info_plist_path = contents_dir.join("Info.plist");
    fs::write(&info_plist_path, info_plist)?;

    let pkg_info_path = contents_dir.join("PkgInfo");
    fs::write(&pkg_info_path, generate_pkg_info())?;

    // Step 5b: Copy optional Credits.rtf and NOTICE into Resources if present
    for (filename, dest_name) in &[
        ("Credits.rtf", "Credits.rtf"),
        ("NOTICE", "NOTICE"),
        ("NOTICE.txt", "NOTICE"),
    ] {
        let work = Path::new(metadata.workdir());
        let candidates = [
            work.join(filename),
            PathBuf::from(filename),
            PathBuf::from(format!("assets/{}", filename)),
            PathBuf::from(format!("packaging/macos/{}", filename)),
        ];
        for c in &candidates {
            if c.is_file() {
                fs::copy(c, resources_dir.join(dest_name))?;
                break;
            }
        }
    }

    // Step 6: Create `Applications` symlink in staging directory for drag-and-drop installation
    let apps_link = dmg_staging_dir.join("Applications");
    #[cfg(unix)]
    {
        std::os::unix::fs::symlink("/Applications", &apps_link)?;
    }
    #[cfg(not(unix))]
    {
        fs::write(&apps_link, b"/Applications")?;
    }

    // Step 6b: Stage optional Finder window layout (.DS_Store and .background/background.tiff)
    let work = Path::new(metadata.workdir());
    let ds_candidates = [
        work.join("dmg-layout.DS_Store"),
        work.join(".DS_Store"),
        PathBuf::from("packaging/macos/dmg/dmg-layout.DS_Store"),
        PathBuf::from("dmg-layout.DS_Store"),
        PathBuf::from(".DS_Store"),
    ];
    for c in &ds_candidates {
        if c.is_file() {
            fs::copy(c, dmg_staging_dir.join(".DS_Store"))?;
            break;
        }
    }

    let bg_candidates = [
        work.join("background.tiff"),
        work.join(".background/background.tiff"),
        PathBuf::from("packaging/macos/dmg/background.tiff"),
        PathBuf::from("background.tiff"),
    ];
    for c in &bg_candidates {
        if c.is_file() {
            let bg_dir = dmg_staging_dir.join(".background");
            fs::create_dir_all(&bg_dir)?;
            fs::copy(c, bg_dir.join("background.tiff"))?;
            break;
        }
    }

    // Step 7: Clean up the intermediate _pkg_root staging dir before creating image
    if temp_root.exists() {
        let _ = fs::remove_dir_all(&temp_root);
    }

    // Step 8: Build the DMG image using pure-Rust ISO-9660 + Joliet engine and Apple UDIF container
    let arch = metadata.mac_arch();
    let dmg_filename = format!("{}_{}_{}.dmg", metadata.name, metadata.version, arch);
    let output_dmg_path = output_dir.join(&dmg_filename);

    if output_dmg_path.exists() {
        let _ = fs::remove_file(&output_dmg_path);
    }

    println!("Building DMG using pure-Rust ISO-9660 + Joliet UDIF engine...");
    let iso_bytes = generate_iso_image(&dmg_staging_dir, &app_name)?;
    let dmg_bytes = create_udif_dmg_image(&app_name, &iso_bytes);
    fs::create_dir_all(output_dir)?;
    fs::write(&output_dmg_path, dmg_bytes)?;

    // Step 9: Clean up staging directory if requested
    if metadata.clean_workdir && dmg_staging_dir.exists() {
        let _ = fs::remove_dir_all(&dmg_staging_dir);
    }

    println!("  Location: {}", output_dmg_path.display());
    Ok(output_dmg_path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bundle::macos::dmg::plist::validate_plist_xml;
    use uuid::Uuid;

    fn macho_payload() -> Vec<u8> {
        let mut bytes = vec![0u8; 64];
        bytes[..4].copy_from_slice(&[0xcf, 0xfa, 0xed, 0xfe]);
        bytes
    }

    fn test_workdir(tmp: &Path, name: &str, bytes: &[u8]) -> PathBuf {
        let work = tmp.join("work");
        fs::create_dir_all(&work).unwrap();
        fs::write(work.join(name), bytes).unwrap();
        work
    }

    #[test]
    fn test_dmg_packaging_flow() {
        let tmp = std::env::temp_dir().join(format!("test_dmg_{}", Uuid::new_v4().hyphenated()));
        let work_dir = test_workdir(&tmp, "dmgtest", &macho_payload());

        let metadata = Metadata {
            name: "dmgtest".to_string(),
            version: "1.0.0".to_string(),
            maintainer: "Test Maintainer".to_string(),
            workdir: Some(work_dir.to_string_lossy().to_string()),
            clean_workdir: true,
            ..Default::default()
        };

        let out_dir = tmp.join("out");
        let dmg_path = dmg_package(&metadata, &out_dir).expect("DMG packaging should succeed");
        assert!(dmg_path.exists());
        assert_eq!(dmg_path.extension().and_then(|s| s.to_str()), Some("dmg"));

        // Verify DMG structure in pure Rust
        let dmg_bytes = fs::read(&dmg_path).expect("Failed to read generated DMG");
        assert!(
            dmg_bytes.len() > 512,
            "DMG size must be larger than 512 bytes"
        );

        // Verify koly trailer (last 512 bytes)
        let koly = &dmg_bytes[dmg_bytes.len() - 512..];
        assert_eq!(&koly[0..4], b"koly", "Must have 'koly' trailer signature");
        assert_eq!(
            u32::from_be_bytes([koly[4], koly[5], koly[6], koly[7]]),
            4,
            "Trailer version must be 4"
        );
        assert_eq!(
            u32::from_be_bytes([koly[8], koly[9], koly[10], koly[11]]),
            512,
            "Trailer size must be 512"
        );

        // Verify ISO-9660 Primary Volume Descriptor at sector 16
        assert_eq!(
            &dmg_bytes[16 * 2048 + 1..16 * 2048 + 6],
            b"CD001",
            "PVD must have CD001 identifier"
        );
        // Verify Joliet Supplementary Volume Descriptor at sector 17
        assert_eq!(
            &dmg_bytes[17 * 2048 + 1..17 * 2048 + 6],
            b"CD001",
            "SVD must have CD001 identifier"
        );

        // Verify XML plist offset and length
        let xml_offset = u64::from_be_bytes([
            koly[216], koly[217], koly[218], koly[219], koly[220], koly[221], koly[222], koly[223],
        ]) as usize;
        let xml_len = u64::from_be_bytes([
            koly[224], koly[225], koly[226], koly[227], koly[228], koly[229], koly[230], koly[231],
        ]) as usize;

        let plist_bytes = &dmg_bytes[xml_offset..xml_offset + xml_len];
        let plist_str = std::str::from_utf8(plist_bytes).expect("Valid UTF-8 XML plist");
        assert!(
            validate_plist_xml(plist_str).is_ok(),
            "Embedded UDIF XML plist must be well-formed"
        );
        assert!(
            plist_str.contains("<key>blkx</key>"),
            "Plist must contain blkx key"
        );

        let _ = fs::remove_dir_all(&tmp);
        let _ = fs::remove_dir_all(format!("{}.dmg-dir", metadata.name));
    }

    #[test]
    fn test_dmg_rejects_non_macho_payload() {
        let tmp =
            std::env::temp_dir().join(format!("test_dmg_elf_{}", Uuid::new_v4().hyphenated()));
        let work_dir = test_workdir(&tmp, "elfdmg", b"\x7fELF\x02\x01\x01");

        let metadata = Metadata {
            name: "elfdmg".to_string(),
            version: "1.0.0".to_string(),
            maintainer: "Test Maintainer".to_string(),
            workdir: Some(work_dir.to_string_lossy().to_string()),
            ..Default::default()
        };

        let out_dir = tmp.join("out");
        let err = dmg_package(&metadata, &out_dir)
            .expect_err("a non-Mach-O payload must not produce a DMG");
        assert!(
            err.to_string().contains("not a Mach-O executable"),
            "unexpected error: {err}"
        );

        let _ = fs::remove_dir_all(&tmp);
        let _ = fs::remove_dir_all(format!("{}.dmg-dir", metadata.name));
    }

    #[test]
    fn test_dmg_without_executable_errors() {
        let tmp =
            std::env::temp_dir().join(format!("test_dmg_empty_{}", Uuid::new_v4().hyphenated()));
        let work_dir = tmp.join("work");
        fs::create_dir_all(&work_dir).unwrap();

        let metadata = Metadata {
            name: "emptydmg".to_string(),
            version: "1.0.0".to_string(),
            maintainer: "Test Maintainer".to_string(),
            workdir: Some(work_dir.to_string_lossy().to_string()),
            ..Default::default()
        };

        let out_dir = tmp.join("out");
        let err =
            dmg_package(&metadata, &out_dir).expect_err("an empty payload must not produce a DMG");
        assert!(
            err.to_string().contains("no macOS executable found"),
            "unexpected error: {err}"
        );

        let _ = fs::remove_dir_all(&tmp);
        let _ = fs::remove_dir_all(format!("{}.dmg-dir", metadata.name));
    }

    #[test]
    fn test_dmg_icon_fallback_omits_non_icns() {
        let tmp =
            std::env::temp_dir().join(format!("test_dmg_icon_{}", Uuid::new_v4().hyphenated()));
        let work_dir = test_workdir(&tmp, "iconapp", &macho_payload());
        // Write SVG and PNG icons, but no ICNS
        fs::write(work_dir.join("icon.svg"), b"<svg></svg>").unwrap();
        fs::write(work_dir.join("icon.png"), b"\x89PNG\r\n\x1a\n").unwrap();

        let metadata = Metadata {
            name: "iconapp".to_string(),
            version: "1.0.0".to_string(),
            maintainer: "Test Maintainer".to_string(),
            workdir: Some(work_dir.to_string_lossy().to_string()),
            ..Default::default()
        };

        let icon_info = locate_icon(&metadata, &work_dir);
        assert!(
            icon_info.is_none(),
            "SVG and PNG icons must be ignored for macOS DMG"
        );

        let out_dir = tmp.join("out");
        let dmg_path =
            dmg_package(&metadata, &out_dir).expect("dmg packaging succeeds without icon");
        assert!(dmg_path.exists());

        let _ = fs::remove_dir_all(&tmp);
        let _ = fs::remove_dir_all(format!("{}.dmg-dir", metadata.name));
    }
}

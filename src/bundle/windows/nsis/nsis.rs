// Pure-Rust NSIS package bundler and standalone installer generator.
// Generates complete Modern UI 2 NSIS script hierarchies and standalone Windows PE setup executables.

use super::pe::{
    NsisInstallerConfig, PeFileEntry, create_bmp, create_ico, create_pe_installer_with_config,
};
use super::script::{generate_language_files, generate_nsi_script};
use crate::chmod::chmod_package_with_metadata;
use crate::metadata::Metadata;
use std::fs;
use std::path::{Path, PathBuf};

/// Locate a graphic or icon asset if explicitly defined in metadata.
/// If not entered, commented out, or the file does not exist, returns None.
fn locate_asset(
    explicit_path: &str,
    metadata: &Metadata,
    staged_root: &Path,
) -> Option<Vec<u8>> {
    let trimmed = explicit_path.trim();
    if trimmed.is_empty() {
        return None;
    }

    let candidates = [
        PathBuf::from(trimmed),
        Path::new(metadata.workdir()).join(trimmed),
        staged_root.join(trimmed),
    ];

    for c in &candidates {
        if let Ok(bytes) = fs::read(c) {
            return Some(bytes);
        }
    }

    None
}

/// Builds an NSIS installer directory and a standalone Windows setup executable (.exe).
pub fn nsis_package(
    metadata: &Metadata,
    output_dir: &Path,
) -> Result<PathBuf, Box<dyn std::error::Error>> {
    println!("Packaging {} into Windows NSIS Installer...", metadata.name);

    let staged_dir = PathBuf::from(format!("{}.nsis-dir", metadata.name));
    chmod_package_with_metadata(metadata, &staged_dir, false)?;

    let graphics_dir = staged_dir.join("graphics");
    let lang_dir = staged_dir.join("lang");
    fs::create_dir_all(&graphics_dir)?;
    fs::create_dir_all(&lang_dir)?;

    // 1. Prepare Graphics Assets (header.bmp, wizard.bmp, icon.ico)
    // If not entered or commented out in metadata.toml, create temporary fallbacks
    let header_bytes = locate_asset(&metadata.win_header, metadata, &staged_dir)
        .unwrap_or_else(|| create_bmp(150, 57, 240, 242, 245));
    fs::write(graphics_dir.join("header.bmp"), header_bytes)?;

    let wizard_bytes = locate_asset(&metadata.win_wizard, metadata, &staged_dir)
        .unwrap_or_else(|| create_bmp(164, 314, 230, 235, 245));
    fs::write(graphics_dir.join("wizard.bmp"), wizard_bytes)?;

    let icon_bytes = locate_asset(&metadata.win_icon, metadata, &staged_dir)
        .unwrap_or_else(|| create_ico(32, 32, 24, 119, 242));
    fs::write(graphics_dir.join("icon.ico"), &icon_bytes)?;

    // 2. Prepare Language Files
    for (filename, content) in generate_language_files(&metadata.app_name()) {
        fs::write(lang_dir.join(filename), content)?;
    }

    // 3. Collect Staged Files for script generation
    let mut staged_relative_files = Vec::new();
    let mut license_relative = None;
    let exec_name = metadata.executable_name();

    if let Ok(entries) = walkdir::WalkDir::new(&staged_dir)
        .into_iter()
        .collect::<Result<Vec<_>, _>>()
    {
        for entry in entries {
            if entry.file_type().is_file() {
                let path = entry.path();
                let rel = path
                    .strip_prefix(&staged_dir)
                    .unwrap_or(path)
                    .to_string_lossy();

                // Skip internal assets from script file list
                if rel.starts_with("graphics")
                    || rel.starts_with("lang")
                    || rel.ends_with(".nsi")
                    || rel.ends_with(".bat")
                {
                    continue;
                }

                let rel_str = rel.to_string();
                let lower = rel_str.to_lowercase();
                if lower.contains("license") || lower.contains("copying") {
                    license_relative = Some(rel_str.clone());
                }
                staged_relative_files.push(rel_str);
            }
        }
    }

    // Fallback if no files were staged via package instructions
    if staged_relative_files.is_empty() {
        let work = Path::new(metadata.workdir());
        let candidates = [
            work.join(format!("{exec_name}.exe")),
            work.join(&exec_name),
            work.join(format!("{}.exe", metadata.name)),
            work.join(&metadata.name),
        ];

        let (filename, data) = candidates
            .into_iter()
            .find_map(|c| {
                let bytes = fs::read(&c).ok()?;
                let name = c.file_name()?.to_string_lossy().to_string();
                Some((name, bytes))
            })
            .unwrap_or_else(|| {
                (
                    format!("{exec_name}.exe"),
                    b"MZ\x90\x00\x03\x00\x00\x00PureRustNSISPayload".to_vec(),
                )
            });

        fs::write(staged_dir.join(&filename), data)?;
        staged_relative_files.push(filename);
    }

    // 4. Generate <name>_Setup.nsi
    let nsi_script = generate_nsi_script(
        metadata,
        &staged_relative_files,
        license_relative.as_deref(),
        Some("icon.ico"),
    );
    let nsi_path = staged_dir.join(format!("{}_Setup.nsi", metadata.name));
    fs::write(&nsi_path, &nsi_script)?;

    // 5. Build Standalone PE and Export Source Directory in one pass
    let nsis_dist_dir = output_dir.join(format!("{}-nsis", metadata.name));
    if nsis_dist_dir.exists() {
        let _ = fs::remove_dir_all(&nsis_dist_dir);
    }
    fs::create_dir_all(&nsis_dist_dir)?;

    let mut file_payloads = Vec::new();
    for entry in walkdir::WalkDir::new(&staged_dir).into_iter().flatten() {
        let path = entry.path();
        let rel = path.strip_prefix(&staged_dir).unwrap_or(path);
        let target = nsis_dist_dir.join(rel);

        if entry.file_type().is_dir() {
            let _ = fs::create_dir_all(&target);
        } else if entry.file_type().is_file()
            && let Ok(bytes) = fs::read(path)
        {
            let _ = fs::write(&target, &bytes);
            file_payloads.push((rel.to_string_lossy().to_string(), bytes));
        }
    }

    let files_to_embed: Vec<PeFileEntry<'_>> = file_payloads
        .iter()
        .map(|(name, data)| PeFileEntry {
            name,
            data,
        })
        .collect();

    let is_64bit = metadata.win_arch() == "x64" || metadata.win_arch() == "arm64";
    let main_exe = if exec_name.ends_with(".exe") {
        exec_name
    } else {
        format!("{exec_name}.exe")
    };

    let nsis_cfg = NsisInstallerConfig {
        app_name: &metadata.app_name(),
        version: &metadata.version,
        manufacturer: &metadata.win_manufacturer(),
        install_dir: &metadata.win_install_dir(),
        main_exe: &main_exe,
        icon_bytes: Some(&icon_bytes),
        embed_first_header: false,
    };

    let pe_installer_bytes = create_pe_installer_with_config(is_64bit, &files_to_embed, &nsis_cfg)?;

    fs::create_dir_all(output_dir)?;
    let setup_exe_filename = format!(
        "{}_{}_{}_setup.exe",
        metadata.name,
        metadata.version,
        metadata.win_arch()
    );
    let setup_exe_path = output_dir.join(&setup_exe_filename);
    fs::write(&setup_exe_path, &pe_installer_bytes)?;

    // Clean up temporary staging directory if requested
    if metadata.should_clean_workdir() && staged_dir.exists() {
        let _ = fs::remove_dir_all(&staged_dir);
    }

    println!("NSIS setup installer generated successfully at {:?}", setup_exe_path);
    println!("NSIS source hierarchy available at {:?}", nsis_dist_dir);
    Ok(setup_exe_path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_nsis_packaging_flow() {
        let tmp = std::env::temp_dir().join(format!("test_nsis_{}", uuid::Uuid::new_v4().hyphenated()));
        let out_dir = tmp.join("out");
        fs::create_dir_all(&out_dir).unwrap();

        let metadata = Metadata {
            name: "testnsis".to_string(),
            version: "2.0.1".to_string(),
            release: "1".to_string(),
            maintainer: "JP-MAKERS".to_string(),
            description: "Test NSIS installer".to_string(),
            arch: vec!["x86_64".to_string()],
            url: "https://example.com".to_string(),
            license: "MIT".to_string(),
            win_manufacturer: "JP-MAKERS".to_string(),
            win_install_dir: "TestNSISApp".to_string(),
            ..Default::default()
        };

        let setup_exe = nsis_package(&metadata, &out_dir).expect("nsis_package should succeed");
        assert!(setup_exe.exists());
        assert!(setup_exe.to_string_lossy().ends_with("_setup.exe"));

        let bytes = fs::read(&setup_exe).expect("must read setup exe");
        assert!(bytes.len() > 1024);
        assert_eq!(&bytes[0..2], b"MZ");
        assert_eq!(&bytes[64..68], b"PE\x00\x00");

        let nsis_dir = out_dir.join("testnsis-nsis");
        assert!(nsis_dir.exists());
        assert!(nsis_dir.join("testnsis_Setup.nsi").is_file());
        assert!(nsis_dir.join("lang/English.nsh").is_file());
        assert!(nsis_dir.join("graphics/header.bmp").is_file());
        assert!(nsis_dir.join("graphics/wizard.bmp").is_file());
        assert!(nsis_dir.join("graphics/icon.ico").is_file());

        let hdr = fs::read(nsis_dir.join("graphics/header.bmp")).unwrap();
        assert_eq!(&hdr[0..2], b"BM");
        let wiz = fs::read(nsis_dir.join("graphics/wizard.bmp")).unwrap();
        assert_eq!(&wiz[0..2], b"BM");
        let ico = fs::read(nsis_dir.join("graphics/icon.ico")).unwrap();
        assert_eq!(&ico[0..4], &[0x00, 0x00, 0x01, 0x00]);

        let _ = fs::remove_dir_all(&tmp);
        let _ = fs::remove_dir_all(format!("{}.nsis-dir", metadata.name));
    }

    #[test]
    fn test_nsis_custom_graphics() {
        let tmp = std::env::temp_dir().join(format!("test_nsis_gfx_{}", uuid::Uuid::new_v4().hyphenated()));
        let out_dir = tmp.join("out");
        let work_dir = tmp.join("work");
        fs::create_dir_all(&out_dir).unwrap();
        fs::create_dir_all(&work_dir).unwrap();

        let custom_header_path = work_dir.join("my_header.bmp");
        let custom_wizard_path = work_dir.join("my_wizard.bmp");
        let header_bytes = [0x42, 0x4D, 0x36, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x36, 0x00, 0x00, 0x00];
        let wizard_bytes = [0x42, 0x4D, 0x78, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x36, 0x00, 0x00, 0x00];
        fs::write(&custom_header_path, header_bytes).unwrap();
        fs::write(&custom_wizard_path, wizard_bytes).unwrap();

        let metadata = Metadata {
            name: "testgfx".to_string(),
            version: "1.0.0".to_string(),
            release: "1".to_string(),
            workdir: Some(work_dir.to_string_lossy().to_string()),
            win_header: custom_header_path.to_string_lossy().to_string(),
            win_wizard: custom_wizard_path.to_string_lossy().to_string(),
            ..Default::default()
        };

        let setup_exe = nsis_package(&metadata, &out_dir).expect("nsis_package with custom graphics should succeed");
        assert!(setup_exe.exists());

        let nsis_dir = out_dir.join("testgfx-nsis");
        assert!(nsis_dir.exists());
        let read_header = fs::read(nsis_dir.join("graphics/header.bmp")).unwrap();
        assert_eq!(&read_header[..], &header_bytes[..]);
        let read_wizard = fs::read(nsis_dir.join("graphics/wizard.bmp")).unwrap();
        assert_eq!(&read_wizard[..], &wizard_bytes[..]);

        let _ = fs::remove_dir_all(&tmp);
        let _ = fs::remove_dir_all(format!("{}.nsis-dir", metadata.name));
    }
}

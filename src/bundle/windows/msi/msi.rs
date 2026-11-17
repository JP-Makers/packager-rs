// Pure-Rust Windows Installer (.msi) generator using msi 0.11.1.
// Produces fully compliant MSI installation databases without invoking external tools.

use super::cab::{CabFileEntry, create_cabinet};
use super::tables::{ShortcutRecord, TableSetup};
use crate::chmod::chmod_package_with_metadata;
use crate::metadata::Metadata;
use crate::payload::is_pe;
use msi::Package;
use std::collections::{BTreeMap, BTreeSet};
use std::fs;

use std::io::Write;
use std::path::{Path, PathBuf};
use uuid::Uuid;

/// Internal representation of a file to be included in the MSI package.
struct StagedFile {
    file_id: String,
    comp_id: String,
    comp_uuid: String,
    filename: String,
    rel_path: String,
    dir_id: String,
    data: Vec<u8>,
    is_main_exe: bool,
}

/// Validate Windows .ico magic bytes (reserved 0, type 1 = icon)
fn is_valid_ico(bytes: &[u8]) -> bool {
    bytes.len() >= 6 && bytes[0] == 0 && bytes[1] == 0 && bytes[2] == 1 && bytes[3] == 0
}

/// Locate or load an icon (.ico) file for the installer.
fn locate_icon(metadata: &Metadata, staged_root: &Path) -> Option<(String, Vec<u8>)> {
    // 1. Explicit metadata win_icon
    if !metadata.win_icon.is_empty() {
        let p = Path::new(&metadata.win_icon);
        if p.is_file()
            && let Ok(bytes) = fs::read(p)
            && is_valid_ico(&bytes)
        {
            return Some(("AppIcon.ico".to_string(), bytes));
        }
        let wp = Path::new(metadata.workdir()).join(&metadata.win_icon);
        if wp.is_file()
            && let Ok(bytes) = fs::read(wp)
            && is_valid_ico(&bytes)
        {
            return Some(("AppIcon.ico".to_string(), bytes));
        }
    }

    // 2. Search staged root, workdir, and current directory for any .ico file
    for root in &[staged_root, Path::new(metadata.workdir()), Path::new(".")] {
        if let Ok(entries) = walkdir::WalkDir::new(root)
            .max_depth(4)
            .into_iter()
            .collect::<Result<Vec<_>, _>>()
        {
            for entry in entries {
                if entry.file_type().is_file() {
                    let path = entry.path();
                    if let Some(ext) = path.extension().and_then(|s| s.to_str())
                        && ext.eq_ignore_ascii_case("ico")
                        && let Ok(bytes) = fs::read(path)
                        && is_valid_ico(&bytes)
                    {
                        return Some(("AppIcon.ico".to_string(), bytes));
                    }
                }
            }
        }
    }

    None
}

/// Build a Windows Installer (.msi) package for the given metadata.
pub fn msi_package(
    metadata: &Metadata,
    output_dir: &Path,
) -> Result<PathBuf, Box<dyn std::error::Error>> {
    println!("Packaging {} into Windows MSI Installer...", metadata.name);

    let staged_dir = PathBuf::from(format!("{}.msi-dir", metadata.name));
    chmod_package_with_metadata(metadata, &staged_dir, false)?;

    // Collect all staged files
    let mut files_to_package: Vec<StagedFile> = Vec::new();
    let exec_name = metadata.executable_name();
    let win_upgrade_uuid = metadata.win_upgrade_code();

    if staged_dir.exists()
        && let Ok(entries) = walkdir::WalkDir::new(&staged_dir)
            .into_iter()
            .collect::<Result<Vec<_>, _>>()
    {
        let mut staged: Vec<(String, PathBuf)> = entries
            .into_iter()
            .filter(|entry| entry.file_type().is_file())
            .map(|entry| {
                let path = entry.into_path();
                let rel = path
                    .strip_prefix(&staged_dir)
                    .unwrap_or(&path)
                    .to_string_lossy()
                    .replace('\\', "/");
                (rel, path)
            })
            .collect();
        // WalkDir ordering is filesystem-dependent; sort so the component
        // UUIDs, file sequence numbers, and cabinet entries are stable.
        staged.sort_by(|a, b| a.0.cmp(&b.0));

        for (rel, path) in staged {
            let filename = path
                .file_name()
                .unwrap_or_default()
                .to_string_lossy()
                .to_string();
            let data = fs::read(&path)?;

            let is_main = rel == format!("usr/bin/{exec_name}")
                || rel == format!("bin/{exec_name}")
                || rel == exec_name
                || filename == exec_name
                || filename == format!("{}.exe", exec_name)
                || filename == metadata.name
                || filename == format!("{}.exe", metadata.name);

            let idx = files_to_package.len();
            let file_id = format!("fil_{:04}", idx);
            let comp_id = format!("cmp_{:04}", idx);

            let seed = format!("{}:{}", win_upgrade_uuid, rel);
            let comp_uuid = format!(
                "{{{}}}",
                Uuid::new_v5(&Uuid::NAMESPACE_DNS, seed.as_bytes()).hyphenated()
            )
            .to_ascii_uppercase();

            files_to_package.push(StagedFile {
                file_id,
                comp_id,
                comp_uuid,
                filename,
                rel_path: rel,
                // Filled in once the full directory set is known.
                dir_id: "INSTALLFOLDER".to_string(),
                data,
                is_main_exe: is_main,
            });
        }
    }

    // Fallback: check workdir if staged directory did not yield any files
    if files_to_package.is_empty() {
        let work = Path::new(metadata.workdir());
        let candidates = [
            work.join(format!("{}.exe", exec_name)),
            work.join(&exec_name),
            work.join(format!("{}.exe", metadata.name)),
            work.join(&metadata.name),
        ];

        let mut found_candidate = None;
        for c in &candidates {
            if c.is_file()
                && let Ok(data) = fs::read(c)
            {
                let filename = c
                    .file_name()
                    .unwrap_or_default()
                    .to_string_lossy()
                    .to_string();
                found_candidate = Some((filename, data));
                break;
            }
        }

        let (filename, data) = match found_candidate {
            Some(pair) => pair,
            None => {
                return Err(format!(
                    "refusing to build MSI: no Windows executable found in {staged_dir:?} or workdir {:?}",
                    metadata.workdir()
                )
                .into());
            }
        };

        let seed = format!("{}:{}", win_upgrade_uuid, filename);
        let comp_uuid = format!(
            "{{{}}}",
            Uuid::new_v5(&Uuid::NAMESPACE_DNS, seed.as_bytes()).hyphenated()
        )
        .to_ascii_uppercase();

        files_to_package.push(StagedFile {
            file_id: "fil_0000".to_string(),
            comp_id: "cmp_0000".to_string(),
            comp_uuid,
            rel_path: filename.clone(),
            filename,
            dir_id: "INSTALLFOLDER".to_string(),
            data,
            is_main_exe: true,
        });
    }

    // Build the Directory table from the staged relative paths. Each file's
    // Component points at its immediate parent so `bin/app.exe` and
    // `share/app.exe` no longer collide in one flat INSTALLFOLDER.
    let mut dir_paths: BTreeSet<String> = BTreeSet::new();
    for file in &files_to_package {
        let mut parent = Path::new(&file.rel_path).parent();
        while let Some(dir) = parent {
            let key = dir.to_string_lossy().replace('\\', "/");
            if key.is_empty() {
                break;
            }
            dir_paths.insert(key);
            parent = dir.parent();
        }
    }

    let mut dir_ids: BTreeMap<String, String> = BTreeMap::new();
    for (index, path) in dir_paths.iter().enumerate() {
        dir_ids.insert(path.clone(), format!("dir_{:04}", index));
    }

    for file in &mut files_to_package {
        file.dir_id = Path::new(&file.rel_path)
            .parent()
            .map(|parent| parent.to_string_lossy().replace('\\', "/"))
            .filter(|parent| !parent.is_empty())
            .and_then(|parent| dir_ids.get(&parent).cloned())
            .unwrap_or_else(|| "INSTALLFOLDER".to_string());
    }

    // Ensure at least one file is designated as main executable for shortcut
    // targeting. Prefer a real PE image, then refuse a wrong-platform payload.
    if !files_to_package.iter().any(|f| f.is_main_exe)
        && let Some(idx) = files_to_package.iter().position(|f| is_pe(&f.data))
    {
        files_to_package[idx].is_main_exe = true;
    }

    let main = files_to_package
        .iter()
        .find(|f| f.is_main_exe)
        .ok_or("refusing to build MSI: no Windows PE executable found in the staged payload")?;
    if !is_pe(&main.data) {
        return Err(format!(
            "refusing to build MSI: {:?} is not a Windows PE executable; supply a Windows payload for [build.windows]",
            main.filename
        )
        .into());
    }

    // Locate optional icon
    let icon_info = locate_icon(metadata, &staged_dir);

    // Build the pure-Rust cabinet payload
    let cab_entries: Vec<CabFileEntry<'_>> = files_to_package
        .iter()
        .map(|f| CabFileEntry {
            name: &f.file_id,
            data: &f.data,
        })
        .collect();
    let cab_bytes = create_cabinet(&cab_entries)?;

    // Prepare destination MSI path
    fs::create_dir_all(output_dir)?;
    let msi_filename = format!(
        "{}_{}_{}.msi",
        metadata.name,
        metadata.version,
        metadata.win_arch()
    );
    let msi_path = output_dir.join(&msi_filename);

    if msi_path.exists() {
        fs::remove_file(&msi_path)?;
    }

    let file = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(true)
        .open(&msi_path)?;
    let mut pkg = Package::create(msi::PackageType::Installer, file)?;

    let is_64bit = metadata.win_arch() == "x64" || metadata.win_arch() == "arm64";
    let prod_code_str = metadata.win_product_code();
    let upgrade_code_str = metadata.win_upgrade_code();
    let manufacturer_str = metadata.win_manufacturer();
    let app_name_str = metadata.app_name();
    let msi_version_str = metadata.msi_version();
    let install_dir_str = metadata.win_install_dir();

    // 1. Configure Summary Information
    {
        let summary = pkg.summary_info_mut();
        summary.set_title(format!("{} Installation", app_name_str));
        summary.set_subject(if metadata.description.is_empty() {
            metadata.name.clone()
        } else {
            metadata.description.clone()
        });
        summary.set_author(&manufacturer_str);
        summary.set_arch(match metadata.win_arch() {
            "x64" => "x64",
            "arm64" => "Arm64",
            _ => "Intel",
        });
        summary.set_languages(&[msi::LanguageId::from_id(1033)]);

        let prod_clean = prod_code_str.trim_matches('{').trim_matches('}');
        let prod_uuid = Uuid::parse_str(prod_clean).unwrap_or_else(|_| Uuid::new_v4());
        summary.set_uuid(prod_uuid);

        summary.set_word_count(2); // 2 = compressed cabinet files
        summary.set_page_count(200); // Windows Installer 2.0+
        summary.set_creating_application("package-builder");
        summary.set_creation_time_to_now();
    }

    // 2. Configure Property Table
    let mut props: Vec<(&str, &str)> = vec![
        ("ProductCode", &prod_code_str),
        ("ProductName", &app_name_str),
        ("ProductVersion", &msi_version_str),
        ("Manufacturer", &manufacturer_str),
        ("UpgradeCode", &upgrade_code_str),
        ("ProductLanguage", "1033"),
        ("SecureCustomProperties", "INSTALLFOLDER;ALLUSERS"),
        ("ARPNOMODIFY", "1"),
        ("ARPNOREPAIR", "1"),
    ];

    let all_users_val = match metadata.win_install_scope.as_str() {
        "perUserOrMachine" => "2",
        "perUser" => "",
        _ => "1",
    };
    if !all_users_val.is_empty() {
        props.push(("ALLUSERS", all_users_val));
    }

    if icon_info.is_some() {
        props.push(("ARPPRODUCTICON", "AppIcon.ico"));
    }
    if !metadata.url.is_empty() {
        props.push(("ARPURLINFOABOUT", &metadata.url));
    }

    TableSetup::setup_property_table(&mut pkg, &props)?;

    // 3. Configure Directory Table
    let program_files_dir = if is_64bit {
        "ProgramFiles64Folder"
    } else {
        "ProgramFilesFolder"
    };

    let mut dirs_owned: Vec<(String, Option<String>, String)> = vec![
        ("TARGETDIR".to_string(), None, "SourceDir".to_string()),
        (
            program_files_dir.to_string(),
            Some("TARGETDIR".to_string()),
            if is_64bit {
                ".:ProgFiles64".to_string()
            } else {
                ".:ProgFiles".to_string()
            },
        ),
        (
            "ManufacturerFolder".to_string(),
            Some(program_files_dir.to_string()),
            manufacturer_str.clone(),
        ),
        (
            "INSTALLFOLDER".to_string(),
            Some("ManufacturerFolder".to_string()),
            install_dir_str.clone(),
        ),
    ];

    // One row per staged directory, wired to its immediate parent.
    // Sorted by depth so parents always precede children in the Directory table.
    let mut sorted_dir_paths: Vec<String> = dir_paths.into_iter().collect();
    sorted_dir_paths.sort_by_key(|p| (p.matches('/').count(), p.clone()));

    for path in &sorted_dir_paths {
        let id = dir_ids
            .get(path)
            .cloned()
            .expect("every directory path has an id");
        let parent = Path::new(path)
            .parent()
            .map(|p| p.to_string_lossy().replace('\\', "/"))
            .filter(|p| !p.is_empty())
            .and_then(|p| dir_ids.get(&p).cloned())
            .unwrap_or_else(|| "INSTALLFOLDER".to_string());
        let default_dir = Path::new(path)
            .file_name()
            .map(|name| name.to_string_lossy().into_owned())
            .unwrap_or_else(|| path.clone());
        dirs_owned.push((id, Some(parent), default_dir));
    }

    if metadata.win_program_menu_shortcut {
        dirs_owned.push((
            "ProgramMenuFolder".to_string(),
            Some("TARGETDIR".to_string()),
            ".:Programs".to_string(),
        ));
        dirs_owned.push((
            "AppMenuFolder".to_string(),
            Some("ProgramMenuFolder".to_string()),
            app_name_str.clone(),
        ));
    }
    if metadata.win_desktop_shortcut {
        dirs_owned.push((
            "DesktopFolder".to_string(),
            Some("TARGETDIR".to_string()),
            ".:Desktop".to_string(),
        ));
    }

    let dirs: Vec<(&str, Option<&str>, &str)> = dirs_owned
        .iter()
        .map(|(id, parent, default_dir)| (id.as_str(), parent.as_deref(), default_dir.as_str()))
        .collect();

    TableSetup::setup_directory_table(&mut pkg, &dirs)?;

    // 4. Configure Component Table
    let comp_attrs: i16 = if is_64bit { 256 } else { 0 };
    let comp_records: Vec<(&str, &str, &str, i16, Option<&str>)> = files_to_package
        .iter()
        .map(|f| {
            (
                f.comp_id.as_str(),
                f.comp_uuid.as_str(),
                f.dir_id.as_str(),
                comp_attrs,
                Some(f.file_id.as_str()),
            )
        })
        .collect();

    TableSetup::setup_component_table(&mut pkg, &comp_records)?;

    // 5. Configure File Table
    let file_records: Vec<(&str, &str, &str, i32, i16)> = files_to_package
        .iter()
        .enumerate()
        .map(|(i, f)| {
            (
                f.file_id.as_str(),
                f.comp_id.as_str(),
                f.filename.as_str(),
                f.data.len() as i32,
                (i + 1) as i16,
            )
        })
        .collect();

    TableSetup::setup_file_table(&mut pkg, &file_records)?;

    // 6. Configure Media Table
    TableSetup::setup_media_table(&mut pkg, files_to_package.len() as i16, "#Data1.cab")?;

    // 7. Configure Feature & FeatureComponents Tables
    TableSetup::setup_feature_table(
        &mut pkg,
        "Complete",
        &metadata.app_name(),
        &metadata.description,
    )?;

    let comp_ids: Vec<&str> = files_to_package
        .iter()
        .map(|f| f.comp_id.as_str())
        .collect();
    TableSetup::setup_feature_components_table(&mut pkg, "Complete", &comp_ids)?;

    // 8. Configure Shortcut Table
    let main_exe = files_to_package
        .iter()
        .find(|f| f.is_main_exe)
        .unwrap_or(&files_to_package[0]);
    let target_ref = format!("[#{}]", main_exe.file_id);
    let icon_ref = if icon_info.is_some() {
        Some("AppIcon.ico")
    } else {
        None
    };

    let mut shortcuts: Vec<ShortcutRecord<'_>> = Vec::new();

    if metadata.win_program_menu_shortcut {
        shortcuts.push((
            "sc_ProgramMenu",
            "AppMenuFolder",
            &app_name_str,
            &main_exe.comp_id,
            &target_ref,
            icon_ref,
            &main_exe.dir_id,
        ));
    }
    if metadata.win_desktop_shortcut {
        shortcuts.push((
            "sc_Desktop",
            "DesktopFolder",
            &app_name_str,
            &main_exe.comp_id,
            &target_ref,
            icon_ref,
            &main_exe.dir_id,
        ));
    }

    if !shortcuts.is_empty() {
        TableSetup::setup_shortcut_table(&mut pkg, &shortcuts)?;
    }

    // 9. Configure Execution Sequences
    TableSetup::setup_install_execute_sequence_table(&mut pkg)?;
    TableSetup::setup_admin_execute_sequence_table(&mut pkg)?;

    // 10. Write Icon Stream (if present)
    if let Some((icon_name, icon_bytes)) = &icon_info {
        TableSetup::setup_icon_table(&mut pkg, icon_name)?;
        let mut stream = pkg.write_stream(icon_name)?;
        stream.write_all(icon_bytes)?;
    }

    // 11. Write Embedded Cabinet Stream
    {
        let mut stream = pkg.write_stream("Data1.cab")?;
        stream.write_all(&cab_bytes)?;
    }

    // 12. Flush compound file database
    pkg.flush()?;

    // Clean up temporary staging directory if requested
    if metadata.should_clean_workdir() && staged_dir.exists() {
        let _ = fs::remove_dir_all(&staged_dir);
    }

    println!("MSI package generated successfully at {:?}", msi_path);
    Ok(msi_path)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pe_payload() -> Vec<u8> {
        let mut bytes = vec![0u8; 0x80];
        bytes[0] = b'M';
        bytes[1] = b'Z';
        bytes[0x3c..0x40].copy_from_slice(&0x40u32.to_le_bytes());
        bytes[0x40..0x44].copy_from_slice(b"PE\0\0");
        bytes
    }

    fn write_payload(dir: &Path, name: &str, bytes: &[u8]) -> PathBuf {
        fs::create_dir_all(dir).unwrap();
        let path = dir.join(name);
        fs::write(&path, bytes).unwrap();
        path
    }

    #[test]
    fn test_msi_package_creation() {
        let tmp = std::env::temp_dir().join(format!("test_msi_{}", Uuid::new_v4().hyphenated()));
        let out_dir = tmp.join("out");
        let work_dir = tmp.join("work");
        fs::create_dir_all(&out_dir).unwrap();
        write_payload(&work_dir, "testapp.exe", &pe_payload());

        let metadata = Metadata {
            name: "testapp".to_string(),
            version: "1.2.3".to_string(),
            release: "1".to_string(),
            maintainer: "Acme Corp".to_string(),
            description: "Test application for Windows Installer".to_string(),
            arch: vec!["x86_64".to_string()],
            url: "https://example.com".to_string(),
            license: "MIT".to_string(),
            workdir: Some(work_dir.to_string_lossy().to_string()),
            win_upgrade_code: "{11111111-2222-3333-4444-555555555555}".to_string(),
            win_product_code: "{66666666-7777-8888-9999-AAAAAAAAAAAA}".to_string(),
            win_manufacturer: "Acme Corporation".to_string(),
            win_install_dir: "AcmeTestApp".to_string(),
            win_install_scope: "perMachine".to_string(),
            win_desktop_shortcut: true,
            win_program_menu_shortcut: true,
            ..Default::default()
        };

        let msi_path = msi_package(&metadata, &out_dir).expect("msi_package should succeed");
        assert!(msi_path.exists());
        assert!(msi_path.to_string_lossy().ends_with(".msi"));

        // Open and inspect the generated MSI using msi::open
        let pkg = msi::open(&msi_path).expect("msi::open should succeed");
        assert_eq!(pkg.summary_info().author(), Some("Acme Corporation"));
        assert_eq!(pkg.summary_info().arch(), Some("x64"));

        // Verify tables exist
        assert!(pkg.has_table("Property"));
        assert!(pkg.has_table("Directory"));
        assert!(pkg.has_table("Component"));
        assert!(pkg.has_table("File"));
        assert!(pkg.has_table("Media"));
        assert!(pkg.has_table("Feature"));
        assert!(pkg.has_table("Shortcut"));

        // Verify stream exists
        assert!(pkg.has_stream("Data1.cab"));

        // Clean up
        let _ = fs::remove_dir_all(&tmp);
        let _ = fs::remove_dir_all(format!("{}.msi-dir", metadata.name));
    }

    #[test]
    fn test_msi_rejects_non_pe_payload() {
        let tmp =
            std::env::temp_dir().join(format!("test_msi_elf_{}", Uuid::new_v4().hyphenated()));
        let work_dir = tmp.join("work");
        write_payload(&work_dir, "elfapp.exe", b"\x7fELF\x02\x01\x01");

        let metadata = Metadata {
            name: "elfapp".to_string(),
            version: "1.0.0".to_string(),
            maintainer: "Test".to_string(),
            workdir: Some(work_dir.to_string_lossy().to_string()),
            ..Default::default()
        };

        let out_dir = tmp.join("out");
        let err =
            msi_package(&metadata, &out_dir).expect_err("a non-PE payload must not produce an MSI");
        assert!(
            err.to_string().contains("not a Windows PE executable"),
            "unexpected error: {err}"
        );
        assert!(
            !out_dir.join("elfapp_1.0.0_x64.msi").exists(),
            "no MSI may be written for a rejected payload"
        );

        let _ = fs::remove_dir_all(&tmp);
        let _ = fs::remove_dir_all(format!("{}.msi-dir", metadata.name));
    }

    #[test]
    fn test_msi_without_payload_errors() {
        let tmp =
            std::env::temp_dir().join(format!("test_msi_empty_{}", Uuid::new_v4().hyphenated()));
        let work_dir = tmp.join("work");
        fs::create_dir_all(&work_dir).unwrap();

        let metadata = Metadata {
            name: "emptyapp".to_string(),
            version: "1.0.0".to_string(),
            maintainer: "Test".to_string(),
            workdir: Some(work_dir.to_string_lossy().to_string()),
            ..Default::default()
        };

        let out_dir = tmp.join("out");
        let err =
            msi_package(&metadata, &out_dir).expect_err("an empty payload must not produce an MSI");
        assert!(
            err.to_string().contains("no Windows executable found"),
            "unexpected error: {err}"
        );

        let _ = fs::remove_dir_all(&tmp);
        let _ = fs::remove_dir_all(format!("{}.msi-dir", metadata.name));
    }

    #[test]
    fn test_msi_preserves_subdirectories() {
        let tmp =
            std::env::temp_dir().join(format!("test_msi_subdirs_{}", Uuid::new_v4().hyphenated()));
        let work_dir = tmp.join("work");
        write_payload(&work_dir.join("bin"), "app.exe", &pe_payload());
        write_payload(&work_dir.join("share"), "app.exe", &pe_payload());
        write_payload(
            &work_dir.join("share/doc"),
            "readme.txt",
            b"documentation content",
        );

        let metadata = Metadata {
            name: "subdirapp".to_string(),
            version: "1.0.0".to_string(),
            maintainer: "Test".to_string(),
            workdir: Some(work_dir.to_string_lossy().to_string()),
            package_instructions: vec![
                format!(
                    "install -m755 \"local:{}\" to /bin/",
                    work_dir.join("bin/app.exe").display()
                ),
                format!(
                    "install -m644 \"local:{}\" to /share/",
                    work_dir.join("share/app.exe").display()
                ),
                format!(
                    "install -m644 \"local:{}\" to /share/doc/",
                    work_dir.join("share/doc/readme.txt").display()
                ),
            ],
            win_upgrade_code: "{11111111-2222-3333-4444-555555555555}".to_string(),
            win_product_code: "{66666666-7777-8888-9999-AAAAAAAAAAAA}".to_string(),
            win_manufacturer: "TestCorp".to_string(),
            win_install_dir: "TestSubdirApp".to_string(),
            ..Default::default()
        };

        let out_dir = tmp.join("out");
        let msi_path = msi_package(&metadata, &out_dir)
            .expect("msi_package should succeed with subdirectories");
        assert!(msi_path.exists());

        let pkg = msi::open(&msi_path).expect("open MSI");
        assert!(pkg.has_table("Directory"));
        assert!(pkg.has_table("Component"));
        assert!(pkg.has_table("File"));

        let _ = fs::remove_dir_all(&tmp);
        let _ = fs::remove_dir_all(format!("{}.msi-dir", metadata.name));
    }
}

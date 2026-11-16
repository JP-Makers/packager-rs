use crate::chmod::chmod_package_with_metadata;
use crate::metadata::{self, Metadata};
use std::fs::{self, File};
use std::path::{Path, PathBuf};

pub fn rpm_package(
    metadata: &Metadata,
    output_dir: &Path,
) -> Result<PathBuf, Box<dyn std::error::Error>> {
    let rpm_dir = format!("{}.rpm", metadata.name);
    let base_dir = PathBuf::from(&rpm_dir);

    // Prepare files in temporary directory
    chmod_package_with_metadata(metadata, &base_dir, false)?;

    let architecture = metadata.rpm_arch();

    let build_config = rpm::BuildConfig::v4().compression(rpm::CompressionType::Gzip);

    let mut builder = rpm::PackageBuilder::new(
        &metadata.name,
        &metadata.version,
        &metadata.license,
        architecture,
        &metadata.description,
    );
    builder.using_config(build_config);
    builder.release(&metadata.release);

    // Add dependencies
    for dep in &metadata.rpm_depends {
        builder.requires(rpm::Dependency::any(dep));
    }

    // Add provides
    for prov in &metadata.provides {
        builder.provides(rpm::Dependency::any(prov));
    }

    // Add conflicts
    for conf in &metadata.conflicts {
        builder.conflicts(rpm::Dependency::any(conf));
    }

    // Add files
    let mut has_desktop_or_icons = false;
    for entry in walkdir::WalkDir::new(&base_dir) {
        let entry = entry?;
        let path = entry.path();
        if path.is_file() {
            let rel_path = path.strip_prefix(&base_dir)?;
            let rel_str = rel_path.to_string_lossy();
            if rel_str.contains("usr/share/applications") || rel_str.contains("usr/share/icons") {
                has_desktop_or_icons = true;
            }
            let target_path = format!("/{}", rel_str);

            // Get mode and add file
            #[cfg(unix)]
            {
                use std::os::unix::fs::MetadataExt;
                let mode = fs::metadata(path)?.mode();
                builder.with_file(path, rpm::FileOptions::new(&target_path).mode(mode as u16))?;
            }
            #[cfg(not(unix))]
            {
                builder.with_file(path, rpm::FileOptions::new(&target_path))?;
            }
        }
    }

    // Automatically trigger desktop database and icon cache updates on install/uninstall
    if has_desktop_or_icons {
        let script = "if which update-desktop-database >/dev/null 2>&1; then update-desktop-database -q /usr/share/applications || true; fi\n\
if which gtk-update-icon-cache >/dev/null 2>&1; then gtk-update-icon-cache -q -t -f /usr/share/icons/hicolor 2>/dev/null || true; fi";
        builder.post_install_script(script);
        builder.post_uninstall_script(script);
    }

    let package = builder.build()?;

    // Create output directory
    if !output_dir.exists() {
        fs::create_dir_all(output_dir)?;
    }

    let rpm_file_path = output_dir.join(format!(
        "{}-{}-{}.{}.rpm",
        metadata.name, metadata.version, metadata.release, architecture
    ));

    let mut f = File::create(&rpm_file_path)?;
    package.write(&mut f)?;

    println!(".rpm package created successfully!");
    println!("  Location: {}", rpm_file_path.display());

    // Clean up temporary bundle directory only if clean_workdir is requested
    if metadata.clean_workdir {
        let _ = fs::remove_dir_all(&base_dir);
    }

    Ok(rpm_file_path)
}

pub fn rpm_build() -> Result<(), Box<dyn std::error::Error>> {
    let metadata = metadata::extract_metadata("metadata.toml")?;
    let output_dir = std::env::current_dir()?.join("output");
    rpm_package(&metadata, &output_dir)?;
    Ok(())
}

use crate::chmod::chmod_package_with_metadata;
use crate::metadata::Metadata;
use std::fs::{self, File};
use std::path::{Path, PathBuf};

fn parse_rpm_dep(raw: &str) -> rpm::Dependency {
    let trimmed = raw.trim();
    for op in [">=", "<=", "=", ">", "<"] {
        if let Some(pos) = trimmed.find(op) {
            let name = trimmed[..pos].trim();
            let ver = trimmed[pos + op.len()..].trim();
            if !name.is_empty() && !ver.is_empty() {
                return match op {
                    ">=" => rpm::Dependency::greater_eq(name, ver),
                    "<=" => rpm::Dependency::less_eq(name, ver),
                    "=" => rpm::Dependency::eq(name, ver),
                    ">" => rpm::Dependency::greater(name, ver),
                    "<" => rpm::Dependency::less(name, ver),
                    _ => rpm::Dependency::any(name),
                };
            }
        }
    }
    rpm::Dependency::any(trimmed)
}

fn is_system_dir(p: &str) -> bool {
    matches!(
        p,
        "" | "/"
            | "/usr"
            | "/usr/bin"
            | "/usr/sbin"
            | "/usr/lib"
            | "/usr/lib64"
            | "/usr/share"
            | "/usr/share/applications"
            | "/usr/share/icons"
            | "/usr/share/icons/hicolor"
            | "/usr/share/icons/hicolor/scalable"
            | "/usr/share/icons/hicolor/scalable/apps"
            | "/usr/share/doc"
            | "/usr/share/licenses"
            | "/etc"
    )
}

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
        builder.requires(parse_rpm_dep(dep));
    }

    // Add provides
    for prov in &metadata.provides {
        builder.provides(parse_rpm_dep(prov));
    }

    // Add conflicts
    for conf in &metadata.conflicts {
        builder.conflicts(parse_rpm_dep(conf));
    }

    // Add files and package-owned directories
    let mut has_desktop_or_icons = false;
    for entry in walkdir::WalkDir::new(&base_dir).sort_by_file_name() {
        let entry = entry?;
        let path = entry.path();
        let rel_path = path.strip_prefix(&base_dir)?;
        let rel_str = rel_path.to_string_lossy();
        if rel_str.is_empty() {
            continue;
        }
        let target_path = format!("/{}", rel_str);

        if path.is_file() {
            if rel_str.contains("usr/share/applications") || rel_str.contains("usr/share/icons") {
                has_desktop_or_icons = true;
            }

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
        } else if path.is_dir() && !is_system_dir(&target_path) {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_rpm_dep() {
        let dep = parse_rpm_dep("glibc >= 2.31");
        assert_eq!(dep.name, "glibc");
        assert_eq!(dep.version, "2.31");

        let dep_eq = parse_rpm_dep("python3 = 3.10");
        assert_eq!(dep_eq.name, "python3");
        assert_eq!(dep_eq.version, "3.10");

        let dep_any = parse_rpm_dep("curl");
        assert_eq!(dep_any.name, "curl");
        assert_eq!(dep_any.version, "");
    }
}

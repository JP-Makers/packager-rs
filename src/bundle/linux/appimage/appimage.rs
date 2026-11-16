use std::fs::File;
use std::io::{BufReader, BufWriter, Write};
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use crate::bundle::linux::appimage::squashfs::squashfs_build;
use crate::chmod::chmod_package_with_metadata;
use crate::metadata::{self, Metadata};

static RUNTIME_X86_64: &[u8] = include_bytes!("apprun/runtime-x86_64");
static RUNTIME_AARCH64: &[u8] = include_bytes!("apprun/runtime-aarch64");
static RUNTIME_ARMHF: &[u8] = include_bytes!("apprun/runtime-armhf");
static RUNTIME_I686: &[u8] = include_bytes!("apprun/runtime-i686");

fn select_runtime(arch: &str) -> &'static [u8] {
    match arch {
        "x86_64" | "amd64" => RUNTIME_X86_64,
        "aarch64" | "arm64" => RUNTIME_AARCH64,
        "armhf" | "armv7h" | "armv7hl" => RUNTIME_ARMHF,
        "i686" | "i386" => RUNTIME_I686,
        _ => RUNTIME_X86_64,
    }
}

pub fn appimage_package(
    metadata: &Metadata,
    output_dir: &Path,
) -> Result<PathBuf, Box<dyn std::error::Error>> {
    // Check if metadata is valid
    if metadata.appimage_exec.is_empty() {
        return Err("appimage_exec not found in metadata".into());
    }

    if metadata.appimage_desktop_instructions.is_empty() {
        return Err("appimage_desktop instructions not found in metadata".into());
    }

    if metadata.appimage_icon_instructions.is_empty() {
        return Err("appimage_icon instructions not found in metadata".into());
    }

    // Create AppDir
    let base_dir = PathBuf::from(format!("{}.AppDir", metadata.name));
    chmod_package_with_metadata(metadata, &base_dir, true)?;

    // Create .DirIcon in root of AppDir for desktop environment file managers
    let dir_icon_path = base_dir.join(".DirIcon");
    if !dir_icon_path.exists()
        && let Ok(entries) = std::fs::read_dir(&base_dir)
    {
        for entry in entries.flatten() {
            let path = entry.path();
            if let Some(ext) = path.extension().and_then(|e| e.to_str())
                && (ext == "svg" || ext == "png")
                && path.is_file()
            {
                let _ = std::fs::copy(&path, &dir_icon_path);
                break;
            }
        }
    }

    if !output_dir.exists() {
        std::fs::create_dir_all(output_dir)?;
    }

    let arch_str = metadata.primary_arch();
    let base_name = format!(
        "{}-{}-{}-{}",
        metadata.name, metadata.version, metadata.release, arch_str
    );

    // Add AppRun with comprehensive desktop, Qt, and library environment exports
    let apprun_path = base_dir.join("AppRun");
    let mut file = File::create(&apprun_path)?;

    let exec_path = if metadata.appimage_exec.starts_with('/') {
        metadata.appimage_exec.clone()
    } else {
        format!("/{}", metadata.appimage_exec)
    };

    let content = format!(
        r#"#!/bin/sh
HERE="$(dirname "$(readlink -f "$0" 2>/dev/null || realpath "$0" 2>/dev/null || echo "$0")")"
export PATH="$HERE/usr/bin:$PATH"
if [ -n "$LD_LIBRARY_PATH" ]; then
    export LD_LIBRARY_PATH="$HERE/usr/lib:$HERE/usr/lib64:$HERE/lib:$HERE/lib64:$LD_LIBRARY_PATH"
else
    export LD_LIBRARY_PATH="$HERE/usr/lib:$HERE/usr/lib64:$HERE/lib:$HERE/lib64"
fi
export XDG_DATA_DIRS="$HERE/usr/share:${{XDG_DATA_DIRS:-/usr/local/share:/usr/share}}"
if [ -n "$QT_PLUGIN_PATH" ]; then
    export QT_PLUGIN_PATH="$HERE/usr/plugins:$HERE/usr/lib/qt6/plugins:$HERE/usr/lib/x86_64-linux-gnu/qt6/plugins:$QT_PLUGIN_PATH"
else
    export QT_PLUGIN_PATH="$HERE/usr/plugins:$HERE/usr/lib/qt6/plugins:$HERE/usr/lib/x86_64-linux-gnu/qt6/plugins"
fi
if [ -n "$QML2_IMPORT_PATH" ]; then
    export QML2_IMPORT_PATH="$HERE/usr/qml:$HERE/usr/lib/qt6/qml:$QML2_IMPORT_PATH"
else
    export QML2_IMPORT_PATH="$HERE/usr/qml:$HERE/usr/lib/qt6/qml"
fi
exec "$HERE{}" "$@"
"#,
        exec_path
    );

    file.write_all(content.as_bytes())?;

    #[cfg(unix)]
    file.set_permissions(std::fs::Permissions::from_mode(0o755))?;

    // Squashfs build
    let base_dir_str = base_dir.to_string_lossy().into_owned();
    squashfs_build(&base_dir_str, &base_name)?;

    let squashfs_path = format!("{}.squashfs", base_name);
    let mut squashfs_data = BufReader::new(File::open(&squashfs_path)?);

    // Create AppImage with 755 permission
    let output_appimage_path = output_dir.join(format!("{}.AppImage", base_name));
    let mut output_file = File::create(&output_appimage_path)?;

    #[cfg(unix)]
    output_file.set_permissions(std::fs::Permissions::from_mode(0o755))?;

    let runtime_bytes = select_runtime(arch_str);
    let mut out_writer = BufWriter::new(&mut output_file);
    out_writer.write_all(runtime_bytes)?;
    std::io::copy(&mut squashfs_data, &mut out_writer)?;
    out_writer.flush()?;
    drop(out_writer);
    drop(output_file);
    drop(squashfs_data);

    // Cleanup intermediate files
    let _ = std::fs::remove_file(&squashfs_path);

    // Clean up temporary bundle directory only if clean_workdir is requested
    if metadata.clean_workdir {
        let _ = std::fs::remove_dir_all(&base_dir);
    }

    println!("AppImage created successfully!");
    println!("  Location: {}", output_appimage_path.display());

    Ok(output_appimage_path)
}

pub fn appimage_build() -> Result<(), Box<dyn std::error::Error>> {
    let metadata = metadata::extract_metadata("metadata.toml")?;
    let output_dir = std::env::current_dir()?.join("output");
    appimage_package(&metadata, &output_dir)?;
    Ok(())
}

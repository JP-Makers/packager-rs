use std::fs::File;
use std::io::{BufReader, BufWriter, Write};
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use crate::bundle::linux::appimage::squashfs::squashfs_build;
use crate::chmod::chmod_package_with_metadata;
use crate::metadata::Metadata;

static RUNTIME_X86_64: &[u8] = include_bytes!("apprun/runtime-x86_64");
static RUNTIME_AARCH64: &[u8] = include_bytes!("apprun/runtime-aarch64");
static RUNTIME_ARMHF: &[u8] = include_bytes!("apprun/runtime-armhf");
static RUNTIME_I686: &[u8] = include_bytes!("apprun/runtime-i686");

/// Information and cryptographic verification digest for embedded AppImage runtimes.
pub struct EmbeddedRuntimeInfo {
    pub arch: &'static str,
    pub runtime_version: &'static str,
    pub sha256: &'static str,
    pub bytes: &'static [u8],
}

pub static EMBEDDED_RUNTIMES: &[EmbeddedRuntimeInfo] = &[
    EmbeddedRuntimeInfo {
        arch: "x86_64",
        runtime_version: "AppImage runtime (type 2)",
        sha256: "27ddd3f78e483fc5f7856e413d7c17092917f8c35bfe3318a0d378aa9435ad17",
        bytes: RUNTIME_X86_64,
    },
    EmbeddedRuntimeInfo {
        arch: "aarch64",
        runtime_version: "AppImage runtime (type 2)",
        sha256: "f3188be1cdd9a005d1219e675f3130a23aea644e7de39c1f0caedd366818391f",
        bytes: RUNTIME_AARCH64,
    },
    EmbeddedRuntimeInfo {
        arch: "armhf",
        runtime_version: "AppImage runtime (type 2)",
        sha256: "27afb5883745ba5549322717ba11cff30ee3cf4faa9a5b27b4052a1e1cd0125c",
        bytes: RUNTIME_ARMHF,
    },
    EmbeddedRuntimeInfo {
        arch: "i686",
        runtime_version: "AppImage runtime (type 2)",
        sha256: "34f26b2d377b5f2c354d693d3ca1a1cd4a4aa50796a01f0ad2772c908ff34b2f",
        bytes: RUNTIME_I686,
    },
];

/// Select the appropriate AppImage runtime for the given architecture.
///
/// Returns an error on unknown or unsupported architectures instead of silently
/// falling back to x86_64.
fn select_runtime(arch: &str) -> Result<&'static [u8], Box<dyn std::error::Error>> {
    match arch {
        "x86_64" | "amd64" => Ok(RUNTIME_X86_64),
        "aarch64" | "arm64" => Ok(RUNTIME_AARCH64),
        "armhf" | "armv7h" | "armv7hl" => Ok(RUNTIME_ARMHF),
        "i686" | "i386" => Ok(RUNTIME_I686),
        other => Err(format!(
            "unknown or unsupported architecture for AppImage: '{other}' (expected x86_64, aarch64, armhf, or i686)"
        )
        .into()),
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
                std::fs::copy(&path, &dir_icon_path)?;
                break;
            }
        }
    }

    if !output_dir.exists() {
        std::fs::create_dir_all(output_dir)?;
    }

    let arch_str = metadata.primary_arch();
    let runtime_bytes = select_runtime(arch_str)?;

    let base_name = format!(
        "{}-{}-{}-{}",
        metadata.name, metadata.version, metadata.release, arch_str
    );

    let multiarch = match arch_str {
        "x86_64" | "amd64" => "x86_64-linux-gnu",
        "aarch64" | "arm64" => "aarch64-linux-gnu",
        "armhf" | "armv7h" | "armv7hl" => "arm-linux-gnueabihf",
        "i686" | "i386" => "i386-linux-gnu",
        _ => "x86_64-linux-gnu",
    };

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
MULTIARCH="{multiarch}"
if [ -n "$LD_LIBRARY_PATH" ]; then
    export LD_LIBRARY_PATH="$HERE/usr/lib:$HERE/usr/lib64:$HERE/usr/lib/$MULTIARCH:$HERE/lib:$HERE/lib64:$HERE/lib/$MULTIARCH:$LD_LIBRARY_PATH"
else
    export LD_LIBRARY_PATH="$HERE/usr/lib:$HERE/usr/lib64:$HERE/usr/lib/$MULTIARCH:$HERE/lib:$HERE/lib64:$HERE/lib/$MULTIARCH"
fi
export XDG_DATA_DIRS="$HERE/usr/share:${{XDG_DATA_DIRS:-/usr/local/share:/usr/share}}"
if [ -n "$QT_PLUGIN_PATH" ]; then
    export QT_PLUGIN_PATH="$HERE/usr/plugins:$HERE/usr/lib/qt6/plugins:$HERE/usr/lib/$MULTIARCH/qt6/plugins:$QT_PLUGIN_PATH"
else
    export QT_PLUGIN_PATH="$HERE/usr/plugins:$HERE/usr/lib/qt6/plugins:$HERE/usr/lib/$MULTIARCH/qt6/plugins"
fi
for d in "$HERE/usr/lib/"*"-linux-"*/qt6/plugins; do
    if [ -d "$d" ]; then
        export QT_PLUGIN_PATH="$d:$QT_PLUGIN_PATH"
    fi
done
if [ -n "$QML2_IMPORT_PATH" ]; then
    export QML2_IMPORT_PATH="$HERE/usr/qml:$HERE/usr/lib/qt6/qml:$QML2_IMPORT_PATH"
else
    export QML2_IMPORT_PATH="$HERE/usr/qml:$HERE/usr/lib/qt6/qml"
fi
exec "$HERE{exec_path}" "$@"
"#
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

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};

    #[test]
    fn test_embedded_runtimes_checksums() {
        for runtime in EMBEDDED_RUNTIMES {
            let mut hasher = Sha256::new();
            hasher.update(runtime.bytes);
            let actual_hash = hex::encode(hasher.finalize());
            assert_eq!(
                actual_hash, runtime.sha256,
                "SHA-256 mismatch for runtime arch '{}'",
                runtime.arch
            );
        }
    }

    #[test]
    fn test_select_runtime_known_architectures() {
        assert!(select_runtime("x86_64").is_ok());
        assert!(select_runtime("amd64").is_ok());
        assert!(select_runtime("aarch64").is_ok());
        assert!(select_runtime("arm64").is_ok());
        assert!(select_runtime("armhf").is_ok());
        assert!(select_runtime("i686").is_ok());
    }

    #[test]
    fn test_select_runtime_unknown_architecture_errors() {
        let err = select_runtime("riscv64").expect_err("unknown arch must error");
        assert!(
            err.to_string()
                .contains("unknown or unsupported architecture")
        );

        let err2 = select_runtime("mips").expect_err("mips must error");
        assert!(
            err2.to_string()
                .contains("unknown or unsupported architecture")
        );
    }
}

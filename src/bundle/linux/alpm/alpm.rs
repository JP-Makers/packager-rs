use crate::metadata::Metadata;
use std::path::{Path, PathBuf};

#[cfg(target_os = "linux")]
use super::build_info::create_build_info;
#[cfg(target_os = "linux")]
use super::normalize::normalize_alpm_package;
#[cfg(target_os = "linux")]
use super::pkg_info::create_package_info;
#[cfg(target_os = "linux")]
use crate::chmod::chmod_package_with_metadata;
#[cfg(target_os = "linux")]
use alpm_compress::compression::CompressionSettings;
#[cfg(target_os = "linux")]
use alpm_mtree::create_mtree_v2_from_input_dir;
#[cfg(target_os = "linux")]
use alpm_package::{InputDir, OutputDir, Package, PackageCreationConfig, PackageInput};

#[cfg(target_os = "linux")]
pub fn alpm_package(
    metadata: &Metadata,
    output_dir: &Path,
) -> Result<PathBuf, Box<dyn std::error::Error>> {
    let alpm_dir = format!("{}.alpm", metadata.name);
    let base_dir = PathBuf::from(&alpm_dir);
    chmod_package_with_metadata(metadata, &base_dir, false)?;
    let input_path = std::env::current_dir()?.join(&base_dir);
    let input_dir = InputDir::new(input_path)?;

    if !output_dir.exists() {
        std::fs::create_dir_all(output_dir)?;
    }
    let abs_out_dir = if output_dir.is_absolute() {
        output_dir.to_path_buf()
    } else {
        std::env::current_dir()?.join(output_dir)
    };
    let alpm_out_dir = OutputDir::new(abs_out_dir)?;

    // Create a valid BUILDINFO file
    create_build_info(&input_dir, metadata)?;

    // Create a valid PKGINFO file
    create_package_info(&input_dir, metadata)?;

    // Create a valid ALPM-MTREE file from the input directory
    create_mtree_v2_from_input_dir(&input_dir)?;

    // Create PackageInput and PackageCreationConfig
    let package_input: PackageInput = input_dir.try_into()?;
    let config =
        PackageCreationConfig::new(package_input, alpm_out_dir, CompressionSettings::default())?;
    Package::try_from(&config)?;

    let pkg_arch = metadata.arch.first().map(|s| s.as_str()).unwrap_or("any");
    let package_filename = format!(
        "{}-{}-{}-{}.pkg.tar.zst",
        metadata.name, metadata.version, metadata.release, pkg_arch
    );
    let package_path = output_dir.join(package_filename);

    if !package_path.is_file() {
        return Err(format!("ALPM package was not created at {}", package_path.display()).into());
    }

    // `Package::try_from` archives the build user's uid/gid (1000/1000) and
    // umask-derived modes. Rewrite the finished archive so the payload
    // installs as root:root with 0644/0755, including the .MTREE records.
    normalize_alpm_package(&package_path)?;

    // Clean up temporary bundle directory only if clean_workdir is requested
    if metadata.clean_workdir {
        let _ = std::fs::remove_dir_all(&base_dir);
    }

    println!("ALPM package created successfully!");
    println!("  Location: {}", package_path.display());
    Ok(package_path)
}

#[cfg(not(target_os = "linux"))]
pub fn alpm_package(
    _metadata: &Metadata,
    _output_dir: &Path,
) -> Result<PathBuf, Box<dyn std::error::Error>> {
    Err("ALPM package creation is only supported on Linux hosts due to alpm-mtree kernel dependencies".into())
}

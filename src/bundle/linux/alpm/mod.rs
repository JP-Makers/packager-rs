#[cfg(target_os = "linux")]
pub mod alpm;
#[cfg(target_os = "linux")]
pub mod build_info;
#[cfg(target_os = "linux")]
pub mod normalize;
pub mod pkg_info;

#[cfg(target_os = "linux")]
pub use alpm::alpm_package;

#[cfg(not(target_os = "linux"))]
pub fn alpm_package(
    _metadata: &crate::metadata::Metadata,
    _output_dir: &std::path::Path,
) -> Result<std::path::PathBuf, Box<dyn std::error::Error>> {
    Err("Arch Linux (ALPM) package creation requires a Linux host".into())
}

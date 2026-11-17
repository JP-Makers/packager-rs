use crate::metadata::Metadata;
#[cfg(target_os = "linux")]
use alpm_buildinfo::BuildInfoV2;
use std::fs::File;
use std::io::Write;
use std::path::Path;
#[cfg(target_os = "linux")]
use std::str::FromStr;

pub fn get_build_date() -> u64 {
    crate::repro::timestamp()
}

#[cfg(target_os = "linux")]
pub fn create_build_info(
    input_path: impl AsRef<Path>,
    metadata: &Metadata,
) -> Result<(), Box<dyn std::error::Error>> {
    let input_path = input_path.as_ref();
    let buildinfo_path = input_path.join(".BUILDINFO");
    let mut file = File::create(&buildinfo_path)?;

    let mut buildenv_str = String::new();
    for opt in &metadata.alpm_build_env {
        buildenv_str.push_str(&format!("buildenv = {}\n", opt));
    }

    let buildinfo_data = format!(
        r#"format = 2
pkgname = {}
pkgbase = {}
pkgver = {}-{}
pkgarch = {}
pkgbuild_sha256sum = {}
packager = {} <{}>
builddate = {}
builddir = /build
startdir = /startdir/
buildtool = devtools
buildtoolver = 1:1.2.1-1-any
{}"#,
        metadata.name,
        metadata.name,
        metadata.version,
        metadata.release,
        metadata.arch.first().unwrap_or(&"any".to_string()),
        metadata.metadata_sha256sum,
        metadata.maintainer,
        metadata.email,
        get_build_date(),
        buildenv_str
    );

    let buildinfo = BuildInfoV2::from_str(&buildinfo_data)?;

    write!(file, "{}", buildinfo)?;

    Ok(())
}

#[cfg(target_os = "linux")]
use crate::metadata::Metadata;
#[cfg(target_os = "linux")]
use std::fs::File;
#[cfg(target_os = "linux")]
use std::io::Write;
use std::path::Path;

pub fn get_installed_size(input_path: impl AsRef<Path>) -> u64 {
    let mut total_size = 0;
    for entry in walkdir::WalkDir::new(input_path)
        .into_iter()
        .filter_map(|e| e.ok())
    {
        if let Ok(metadata) = entry.metadata()
            && metadata.is_file()
        {
            total_size += metadata.len();
        }
    }
    total_size
}

#[cfg(target_os = "linux")]
pub fn create_package_info(
    input_path: impl AsRef<Path>,
    metadata: &Metadata,
) -> Result<(), Box<dyn std::error::Error>> {
    let input_path = input_path.as_ref();
    let mut file = File::create(input_path.join(".PKGINFO"))?;

    let mut dynamic_fields = String::new();
    for conflict in &metadata.conflicts {
        dynamic_fields.push_str(&format!("conflict = {}\n", conflict));
    }
    for provide in &metadata.provides {
        dynamic_fields.push_str(&format!("provides = {}\n", provide));
    }
    for dep in &metadata.alpm_depends {
        dynamic_fields.push_str(&format!("depend = {}\n", dep));
    }

    write!(
        file,
        r#"pkgname = {}
pkgbase = {}
xdata = pkgtype=pkg
pkgver = {}-{}
pkgdesc = {}
url = {}
builddate = {}
packager = {} <{}>
size = {}
arch = {}
license = {}
{}"#,
        metadata.name,
        metadata.name,
        metadata.version,
        metadata.release,
        metadata.description,
        metadata.url,
        super::build_info::get_build_date(),
        metadata.maintainer,
        metadata.email,
        get_installed_size(input_path),
        metadata.arch.first().unwrap_or(&"any".to_string()),
        metadata.license,
        dynamic_fields
    )?;
    Ok(())
}

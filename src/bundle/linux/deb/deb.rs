use crate::bundle::linux::alpm::pkg_info::get_installed_size;
use crate::bundle::linux::archive;
use crate::chmod::chmod_package_with_metadata;
use crate::metadata::Metadata;
use flate2::Compression;
use flate2::write::GzEncoder;
use md5::{Digest, Md5};
use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use tar::Builder;

pub fn deb_package(
    metadata: &Metadata,
    output_dir: &Path,
) -> Result<PathBuf, Box<dyn std::error::Error>> {
    let deb_dir = format!("{}.deb", metadata.name);
    let base_dir = PathBuf::from(&deb_dir);

    // Prepare files in temporary directory using chmod_package_with_metadata logic
    chmod_package_with_metadata(metadata, &base_dir, false)?;

    // Create DEBIAN directory for control file
    let debian_dir = base_dir.join("DEBIAN");
    fs::create_dir_all(&debian_dir)?;

    // Create control file
    let control_path = debian_dir.join("control");
    let mut control_file = File::create(control_path)?;

    let architecture = metadata.deb_arch();

    // Debian Installed-Size is measured in KiB (1024-byte blocks), rounded up
    let installed_size_kib = get_installed_size(&base_dir).div_ceil(1024);

    writeln!(control_file, "Package: {}", metadata.name)?;
    writeln!(
        control_file,
        "Version: {}-{}",
        metadata.version, metadata.release
    )?;
    writeln!(control_file, "Architecture: {}", architecture)?;
    writeln!(
        control_file,
        "Maintainer: {} <{}>",
        metadata.maintainer, metadata.email
    )?;
    writeln!(control_file, "Installed-Size: {}", installed_size_kib)?;
    if !metadata.deb_depends.is_empty() {
        writeln!(control_file, "Depends: {}", metadata.deb_depends.join(", "))?;
    }
    if !metadata.conflicts.is_empty() {
        writeln!(control_file, "Conflicts: {}", metadata.conflicts.join(", "))?;
    }
    if !metadata.provides.is_empty() {
        writeln!(control_file, "Provides: {}", metadata.provides.join(", "))?;
    }
    writeln!(control_file, "Section: utils")?;
    writeln!(control_file, "Priority: optional")?;
    writeln!(control_file, "Homepage: {}", metadata.url)?;
    writeln!(control_file, "Description: {}", metadata.description)?;

    // Create debian-binary
    let debian_binary_path = base_dir.join("debian-binary");
    let mut debian_binary = File::create(&debian_binary_path)?;
    writeln!(debian_binary, "2.0")?;

    // Collect data files and compute md5sums
    let mut md5sums_entries: Vec<(String, String)> = Vec::new();
    let mut data_files: Vec<(PathBuf, PathBuf)> = Vec::new(); // (abs_path, rel_path)

    for entry in walkdir::WalkDir::new(&base_dir) {
        let entry = entry?;
        let path = entry.path().to_path_buf();
        let rel_path = path.strip_prefix(&base_dir)?.to_path_buf();

        if rel_path.starts_with("DEBIAN")
            || rel_path == Path::new("debian-binary")
            || rel_path == Path::new("data.tar.gz")
            || rel_path == Path::new("control.tar.gz")
            || rel_path.as_os_str().is_empty()
        {
            continue;
        }

        if path.is_file() {
            // Compute MD5
            let mut file_data = Vec::new();
            File::open(&path)?.read_to_end(&mut file_data)?;
            let mut hasher = Md5::new();
            hasher.update(&file_data);
            let digest = hasher.finalize();
            let rel_str = rel_path.to_string_lossy().into_owned();
            md5sums_entries.push((hex::encode(digest), rel_str));
            data_files.push((path, rel_path));
        } else if path.is_dir() {
            data_files.push((path, rel_path));
        }
    }

    // Create md5sums file in DEBIAN/
    let md5sums_path = debian_dir.join("md5sums");
    let mut md5sums_file = File::create(&md5sums_path)?;
    for (hash, rel) in &md5sums_entries {
        writeln!(md5sums_file, "{}  {}", hash, rel)?;
    }

    // Create data.tar.gz
    let data_tar_gz_path = base_dir.join("data.tar.gz");
    let data_tar_gz = File::create(&data_tar_gz_path)?;
    let enc = GzEncoder::new(data_tar_gz, Compression::default());
    let mut tar = Builder::new(enc);

    for (abs_path, rel_path) in &data_files {
        if abs_path.is_file() {
            archive::append_file(&mut tar, abs_path, rel_path, archive::file_mode(abs_path))?;
        } else if abs_path.is_dir() {
            archive::append_dir(&mut tar, abs_path, rel_path)?;
        }
    }
    tar.finish()?;
    let enc = tar.into_inner()?;
    enc.finish()?;

    // Check if package installs desktop or icon files
    let has_desktop_or_icons = data_files.iter().any(|(_, rel)| {
        let s = rel.to_string_lossy();
        s.contains("usr/share/applications") || s.contains("usr/share/icons")
    });

    // Create control.tar.gz
    let control_tar_gz_path = base_dir.join("control.tar.gz");
    let control_tar_gz = File::create(&control_tar_gz_path)?;
    let enc = GzEncoder::new(control_tar_gz, Compression::default());
    let mut tar = Builder::new(enc);
    archive::append_file(
        &mut tar,
        &debian_dir.join("control"),
        Path::new("control"),
        0o644,
    )?;
    archive::append_file(&mut tar, &md5sums_path, Path::new("md5sums"), 0o644)?;

    if has_desktop_or_icons {
        let postinst_path = debian_dir.join("postinst");
        let mut postinst = File::create(&postinst_path)?;
        write!(
            postinst,
            "#!/bin/sh\nset -e\n\
if [ \"$1\" = \"configure\" ] || [ \"$1\" = \"abort-upgrade\" ] || [ \"$1\" = \"abort-deconfigure\" ] || [ \"$1\" = \"abort-remove\" ]; then\n\
    if which update-desktop-database >/dev/null 2>&1; then\n        update-desktop-database -q /usr/share/applications || true\n    fi\n\
    if which gtk-update-icon-cache >/dev/null 2>&1; then\n        gtk-update-icon-cache -q -t -f /usr/share/icons/hicolor 2>/dev/null || true\n    fi\n\
fi\n"
        )?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&postinst_path, fs::Permissions::from_mode(0o755))?;
        }
        archive::append_file(&mut tar, &postinst_path, Path::new("postinst"), 0o755)?;

        let postrm_path = debian_dir.join("postrm");
        let mut postrm = File::create(&postrm_path)?;
        write!(
            postrm,
            "#!/bin/sh\nset -e\n\
if [ \"$1\" = \"remove\" ] || [ \"$1\" = \"purge\" ]; then\n\
    if which update-desktop-database >/dev/null 2>&1; then\n        update-desktop-database -q /usr/share/applications || true\n    fi\n\
    if which gtk-update-icon-cache >/dev/null 2>&1; then\n        gtk-update-icon-cache -q -t -f /usr/share/icons/hicolor 2>/dev/null || true\n    fi\n\
fi\n"
        )?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&postrm_path, fs::Permissions::from_mode(0o755))?;
        }
        archive::append_file(&mut tar, &postrm_path, Path::new("postrm"), 0o755)?;
    }

    tar.finish()?;
    let enc = tar.into_inner()?;
    enc.finish()?;

    // Combine into .deb using ar
    if !output_dir.exists() {
        fs::create_dir_all(output_dir)?;
    }
    let deb_file_path = output_dir.join(format!(
        "{}_{}-{}_{}.deb",
        metadata.name, metadata.version, metadata.release, architecture
    ));
    let deb_file = File::create(&deb_file_path)?;
    let mut ar = ar::Builder::new(deb_file);

    // Add files in order: debian-binary, control.tar.gz, data.tar.gz
    add_file_to_ar(&mut ar, &debian_binary_path, "debian-binary")?;
    add_file_to_ar(&mut ar, &control_tar_gz_path, "control.tar.gz")?;
    add_file_to_ar(&mut ar, &data_tar_gz_path, "data.tar.gz")?;

    drop(ar);

    println!(".deb package created successfully!");
    println!("  Location: {}", deb_file_path.display());

    // Clean up temporary bundle directory only if clean_workdir is requested
    if metadata.clean_workdir {
        let _ = fs::remove_dir_all(&base_dir);
    }

    Ok(deb_file_path)
}

fn add_file_to_ar<W: Write>(ar: &mut ar::Builder<W>, path: &Path, name: &str) -> io::Result<()> {
    let mut file = File::open(path)?;
    let metadata = file.metadata()?;
    let header = ar::Header::from_metadata(name.as_bytes().to_vec(), &metadata);
    ar.append(&header, &mut file)
}

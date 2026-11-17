use backhand::{
    FilesystemCompressor, FilesystemWriter, NodeHeader,
    compression::{CompressionOptions, Compressor, Zstd},
};
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::{fs, path::Path};
use walkdir::WalkDir;

pub fn squashfs_build_to_file(
    app_dir: &str,
    output_path: &Path,
) -> Result<(), Box<dyn std::error::Error>> {
    if !Path::new(app_dir).exists() {
        return Err(format!("Directory {} not found", app_dir).into());
    }

    let mut fs_writer = FilesystemWriter::default();

    // Configure Zstd level 20
    fs_writer.set_compressor(FilesystemCompressor::new(
        Compressor::Zstd,
        Some(CompressionOptions::Zstd(Zstd {
            compression_level: 20,
        })),
    )?);

    // Set root permissions
    fs_writer.set_root_uid(0);
    fs_writer.set_root_gid(0);
    fs_writer.set_root_mode(0o755);

    println!("Converting {} to SquashFS (level 20)...", app_dir);

    let dir_header = NodeHeader::new(0o755, 0, 0, 0);
    let symlink_header = NodeHeader::new(0o777, 0, 0, 0);

    for entry in WalkDir::new(app_dir).min_depth(1) {
        let entry = entry?;
        let rel_path = entry.path().strip_prefix(app_dir)?;

        if entry.file_type().is_dir() {
            fs_writer.push_dir(rel_path, dir_header)?;
        } else if entry.file_type().is_file() {
            #[cfg(unix)]
            let file_mode = (entry.metadata()?.permissions().mode() & 0o7777) as u16;
            #[cfg(not(unix))]
            let file_mode = 0o644;

            let file_header = NodeHeader::new(file_mode, 0, 0, 0);
            fs_writer.push_file(fs::File::open(entry.path())?, rel_path, file_header)?;
        } else if entry.file_type().is_symlink() {
            fs_writer.push_symlink(fs::read_link(entry.path())?, rel_path, symlink_header)?;
        }
    }

    if let Some(parent) = output_path.parent()
        && !parent.as_os_str().is_empty()
    {
        fs::create_dir_all(parent)?;
    }

    fs_writer.write(&mut fs::File::create(output_path)?)?;
    println!("Created {} successfully!", output_path.display());
    Ok(())
}

pub fn squashfs_build(app_dir: &str, output_name: &str) -> Result<(), Box<dyn std::error::Error>> {
    let out_file = format!("{}.squashfs", output_name);
    squashfs_build_to_file(app_dir, Path::new(&out_file))
}

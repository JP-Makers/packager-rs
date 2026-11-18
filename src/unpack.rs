use bzip2::read::BzDecoder;
use flate2::read::GzDecoder;
use liblzma::read::XzDecoder;
use std::fs::{self, File};
use std::io::{self, Read};
use std::path::Path;
use tar::Archive;
use zstd::stream::read::Decoder as ZstdDecoder;

/// Maximum allowed decompressed size (8 GiB) to protect against decompression bombs.
pub const MAX_UNPACK_SIZE: u64 = 8 * 1024 * 1024 * 1024;

pub fn unpack_source(path: &str, dest: &str) -> io::Result<()> {
    fs::create_dir_all(dest)?;
    let file = File::open(path)?;
    let extension = Path::new(path)
        .extension()
        .and_then(|ext| ext.to_str())
        .unwrap_or("")
        .to_lowercase();

    println!("Unpacking {} into {}...", path, dest);

    match extension.as_str() {
        "gz" | "tgz" => {
            let decoder = GzDecoder::new(file);
            let mut archive = Archive::new(decoder.take(MAX_UNPACK_SIZE));
            archive.unpack(dest)?;
        }
        "xz" | "txz" => {
            let decoder = XzDecoder::new(file);
            let mut archive = Archive::new(decoder.take(MAX_UNPACK_SIZE));
            archive.unpack(dest)?;
        }
        "bz2" | "tbz2" => {
            let decoder = BzDecoder::new(file);
            let mut archive = Archive::new(decoder.take(MAX_UNPACK_SIZE));
            archive.unpack(dest)?;
        }
        "zst" => {
            let decoder = ZstdDecoder::new(file)?;
            let mut archive = Archive::new(decoder.take(MAX_UNPACK_SIZE));
            archive.unpack(dest)?;
        }
        "zip" => {
            let mut archive = zip::ZipArchive::new(file)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
            let mut total_unpacked: u64 = 0;
            for i in 0..archive.len() {
                let mut zip_file = archive
                    .by_index(i)
                    .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
                total_unpacked += zip_file.size();
                if total_unpacked > MAX_UNPACK_SIZE {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!(
                            "decompressed zip archive exceeds maximum permitted size of {MAX_UNPACK_SIZE} bytes"
                        ),
                    ));
                }
                let outpath = match zip_file.enclosed_name() {
                    Some(path) => Path::new(dest).join(path),
                    None => continue,
                };
                if zip_file.is_dir() {
                    fs::create_dir_all(&outpath)?;
                } else {
                    if let Some(p) = outpath.parent()
                        && !p.exists()
                    {
                        fs::create_dir_all(p)?;
                    }
                    let mut outfile = File::create(&outpath)?;
                    io::copy(&mut (&mut zip_file).take(MAX_UNPACK_SIZE), &mut outfile)?;
                }
            }
        }
        _ => {
            if path.ends_with(".tar") {
                let mut archive = Archive::new(file.take(MAX_UNPACK_SIZE));
                archive.unpack(dest)?;
            } else {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("Unsupported archive extension: {}", extension),
                ));
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn test_zip_source_extracts() {
        let tmp =
            std::env::temp_dir().join(format!("test_zip_{}", uuid::Uuid::new_v4().hyphenated()));
        let _ = fs::remove_dir_all(&tmp);
        fs::create_dir_all(&tmp).expect("create temp dir");

        let zip_file_path = tmp.join("test.zip");
        {
            let file = File::create(&zip_file_path).expect("create zip file");
            let mut zip = zip::ZipWriter::new(file);
            let options = zip::write::SimpleFileOptions::default()
                .compression_method(zip::CompressionMethod::Stored);
            zip.start_file("hello.txt", options).expect("start file");
            zip.write_all(b"Hello from inside zip!")
                .expect("write file");
            zip.finish().expect("finish zip");
        }

        let extract_dir = tmp.join("extracted");
        unpack_source(
            zip_file_path.to_str().unwrap(),
            extract_dir.to_str().unwrap(),
        )
        .expect("unpack zip");

        let extracted_file = extract_dir.join("hello.txt");
        assert!(extracted_file.exists());
        assert_eq!(
            fs::read_to_string(extracted_file).unwrap(),
            "Hello from inside zip!"
        );

        let _ = fs::remove_dir_all(&tmp);
    }
}

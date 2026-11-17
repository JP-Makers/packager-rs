use bzip2::read::BzDecoder;
use flate2::read::GzDecoder;
use liblzma::read::XzDecoder;
use std::fs::{self, File};
use std::io;
use std::path::Path;
use tar::Archive;
use zstd::stream::read::Decoder as ZstdDecoder;

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
            let mut archive = Archive::new(decoder);
            archive.unpack(dest)?;
        }
        "xz" | "txz" => {
            let decoder = XzDecoder::new(file);
            let mut archive = Archive::new(decoder);
            archive.unpack(dest)?;
        }
        "bz2" | "tbz2" => {
            let decoder = BzDecoder::new(file);
            let mut archive = Archive::new(decoder);
            archive.unpack(dest)?;
        }
        "zst" => {
            let decoder = ZstdDecoder::new(file)?;
            let mut archive = Archive::new(decoder);
            archive.unpack(dest)?;
        }
        "zip" => {
            let mut archive = zip::ZipArchive::new(file)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
            archive.extract(dest).map_err(io::Error::other)?;
        }
        _ => {
            if path.ends_with(".tar") {
                let mut archive = Archive::new(file);
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

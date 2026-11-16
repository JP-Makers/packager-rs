use super::metadata::Metadata;
use blake2::{Blake2b512, Digest};
use md5::Md5;
use sha1::Sha1;
use sha2::{Sha224, Sha256, Sha384, Sha512};
use std::fs::File;
use std::io::{self, Read};

fn compute_hash<D: Digest + Default>(path: &str) -> io::Result<String> {
    let mut file = File::open(path)?;
    let mut hasher = D::new();
    let mut buffer = [0u8; 8192];

    loop {
        let n = file.read(&mut buffer)?;
        if n == 0 {
            break;
        }
        hasher.update(&buffer[..n]);
    }

    Ok(hex::encode(hasher.finalize()))
}

pub fn md5_hash(path: &str) -> io::Result<String> {
    compute_hash::<Md5>(path)
}

pub fn sha1_hash(path: &str) -> io::Result<String> {
    compute_hash::<Sha1>(path)
}

#[allow(dead_code)]
pub fn blake2b512_hash(path: &str) -> io::Result<String> {
    compute_hash::<Blake2b512>(path)
}

#[allow(dead_code)]
pub fn sha224_hash(path: &str) -> io::Result<String> {
    compute_hash::<Sha224>(path)
}

pub fn sha256_hash(path: &str) -> io::Result<String> {
    compute_hash::<Sha256>(path)
}

#[allow(dead_code)]
pub fn sha384_hash(path: &str) -> io::Result<String> {
    compute_hash::<Sha384>(path)
}

pub fn sha512_hash(path: &str) -> io::Result<String> {
    compute_hash::<Sha512>(path)
}

pub fn verify_checksum(metadata: &Metadata, file_path: &str, source_index: usize) -> io::Result<()> {
    let (expected_hashes, actual, algo_name) = if !metadata.sha512sums.is_empty() {
        (&metadata.sha512sums, sha512_hash(file_path)?, "SHA512")
    } else if !metadata.sha256sums.is_empty() {
        (&metadata.sha256sums, sha256_hash(file_path)?, "SHA256")
    } else if !metadata.sha1sums.is_empty() {
        (&metadata.sha1sums, sha1_hash(file_path)?, "SHA1")
    } else if !metadata.md5sums.is_empty() {
        (&metadata.md5sums, md5_hash(file_path)?, "MD5")
    } else {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("no checksums found in metadata for {file_path}; refusing to process unverified source"),
        ));
    };

    println!("Verifying {} checksum for {}...", algo_name, file_path);

    let expected = match expected_hashes.get(source_index) {
        Some(h) => h,
        None => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "Missing {} checksum for source index {}: expected {} sums, but found {}",
                    algo_name,
                    source_index,
                    source_index + 1,
                    expected_hashes.len()
                ),
            ));
        }
    };

    if expected.eq_ignore_ascii_case("SKIP") {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("checksum verification cannot be skipped for {file_path}; provide a genuine cryptographic hash"),
        ));
    }

    if actual.eq_ignore_ascii_case(expected) {
        println!("Hash matches!");
        println!("Expected: {}", expected);
        println!("Actual:   {}", actual);
        Ok(())
    } else {
        println!("Hash mismatch for {}!", file_path);
        println!("Expected: {}", expected);
        println!("Actual:   {}", actual);
        Err(io::Error::new(io::ErrorKind::InvalidData, "Hash mismatch"))
    }
}

/// Verify a file directly against an expected hash value.
/// Automatically detects algorithm from hex digest length (64 = SHA-256, 128 = SHA-512, 40 = SHA-1, 32 = MD5).
pub fn verify_checksum_value(file_path: &str, expected: &str) -> io::Result<()> {
    if expected.eq_ignore_ascii_case("SKIP") {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("checksum verification cannot be skipped for {file_path}; provide a genuine cryptographic hash"),
        ));
    }

    let actual = match expected.len() {
        128 => sha512_hash(file_path)?,
        64 => sha256_hash(file_path)?,
        40 => sha1_hash(file_path)?,
        32 => md5_hash(file_path)?,
        _ => sha256_hash(file_path)?,
    };

    if actual.eq_ignore_ascii_case(expected) {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("checksum mismatch for {file_path}: expected {expected}, calculated {actual}"),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::io::Write;
    use std::path::PathBuf;

    struct TestFile {
        path: PathBuf,
    }

    impl Drop for TestFile {
        fn drop(&mut self) {
            let _ = fs::remove_file(&self.path);
        }
    }

    fn temp_test_file(tag: &str, content: &[u8]) -> (TestFile, String) {
        static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let count = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "test_checksum_{}_{}_{}.tmp",
            tag,
            std::process::id(),
            count
        ));
        let mut file = fs::File::create(&path).expect("create temp file");
        file.write_all(content).expect("write content");
        file.flush().expect("flush");
        let path_str = path.to_string_lossy().into_owned();
        (TestFile { path }, path_str)
    }

    #[test]
    fn test_verify_checksum_rejects_skip() {
        let (_guard, path) = temp_test_file("skip", b"test payload for checksum");
        let meta = Metadata {
            sha256sums: vec!["SKIP".to_string()],
            ..Default::default()
        };

        let err = verify_checksum(&meta, &path, 0)
            .expect_err("SKIP checksum must be rejected with an error");
        assert!(err.to_string().contains("cannot be skipped"));
    }

    #[test]
    fn test_verify_checksum_rejects_empty_sums() {
        let (_guard, path) = temp_test_file("empty", b"test payload");
        let meta = Metadata::default();

        let err = verify_checksum(&meta, &path, 0)
            .expect_err("empty checksum array must be rejected");
        assert!(err.to_string().contains("no checksums found"));
    }

    #[test]
    fn test_verify_checksum_succeeds_on_match() {
        let (_guard, path) = temp_test_file("match", b"secure data");
        let actual_hash = sha256_hash(&path).expect("hash");
        let meta = Metadata {
            sha256sums: vec![actual_hash],
            ..Default::default()
        };

        assert!(verify_checksum(&meta, &path, 0).is_ok());
    }

    #[test]
    fn test_verify_checksum_detects_mismatch() {
        let (_guard, path) = temp_test_file("mismatch", b"secure data");
        let meta = Metadata {
            sha256sums: vec!["0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".to_string()],
            ..Default::default()
        };

        let err = verify_checksum(&meta, &path, 0).expect_err("mismatched hash must error");
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }
}

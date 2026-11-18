use futures_util::StreamExt;
use reqwest::Client;
use std::path::Path;
use tokio::fs::{self, File};
use tokio::io::AsyncWriteExt;

/// Maximum allowed download size (4 GiB) to prevent disk exhaustion DoS.
pub const MAX_DOWNLOAD_SIZE: u64 = 4 * 1024 * 1024 * 1024;

pub async fn fetch_source(source: &str) -> Result<String, Box<dyn std::error::Error>> {
    fetch_source_with_base(source, None).await
}

pub async fn fetch_source_with_base(
    source: &str,
    base_dir: Option<&Path>,
) -> Result<String, Box<dyn std::error::Error>> {
    if source.starts_with("http://") || source.starts_with("https://") {
        // Try to get filename from URL (stripping any query params and trailing slashes)
        let clean_source = source
            .split('?')
            .next()
            .unwrap_or(source)
            .trim_end_matches('/');
        let raw_filename = clean_source
            .split('/')
            .next_back()
            .filter(|s| !s.is_empty())
            .unwrap_or("downloaded_file");

        let filename = if raw_filename == "."
            || raw_filename == ".."
            || raw_filename.contains('\\')
            || raw_filename.contains('/')
        {
            "downloaded_file".to_string()
        } else {
            raw_filename.to_string()
        };

        // Skip download if file already exists (cache)
        if Path::new(&filename).is_file() {
            println!("Using cached {}", filename);
            return Ok(filename);
        }

        println!("Downloading {} from {}...", filename, source);
        let client = Client::builder()
            .connect_timeout(std::time::Duration::from_secs(15))
            .timeout(std::time::Duration::from_secs(300))
            .build()?;
        let response = client.get(source).send().await?.error_for_status()?;

        let part_filename = format!("{}.part", filename);
        let mut file = File::create(&part_filename).await?;
        let mut stream = response.bytes_stream();
        let mut total_bytes: u64 = 0;

        while let Some(chunk) = stream.next().await {
            let chunk = match chunk {
                Ok(c) => c,
                Err(e) => {
                    let _ = fs::remove_file(&part_filename).await;
                    return Err(Box::new(e));
                }
            };
            total_bytes += chunk.len() as u64;
            if total_bytes > MAX_DOWNLOAD_SIZE {
                let _ = fs::remove_file(&part_filename).await;
                return Err(format!(
                    "Download exceeded maximum permitted size of {MAX_DOWNLOAD_SIZE} bytes"
                )
                .into());
            }
            if let Err(e) = file.write_all(&chunk).await {
                let _ = fs::remove_file(&part_filename).await;
                return Err(Box::new(e));
            }
        }
        file.flush().await?;
        drop(file);

        fs::rename(&part_filename, &filename).await?;
        println!("Download of {} complete!", filename);
        Ok(filename)
    } else {
        // Assume local path (with optional file:// prefix)
        let local_source = if let Some(stripped) = source.strip_prefix("file://") {
            #[cfg(windows)]
            {
                let s = stripped.strip_prefix("localhost").unwrap_or(stripped);
                if s.starts_with('/') && s.len() > 2 && s.as_bytes()[2] == b':' {
                    &s[1..]
                } else {
                    s
                }
            }
            #[cfg(not(windows))]
            {
                stripped.strip_prefix("localhost").unwrap_or(stripped)
            }
        } else {
            source
        };

        let path_candidate = Path::new(local_source);
        let path = if let Some(base) = base_dir
            && !path_candidate.is_absolute()
            && base.join(local_source).exists()
        {
            base.join(local_source)
        } else if path_candidate.exists() {
            path_candidate.to_path_buf()
        } else {
            return Err(format!("Source path does not exist: {}", source).into());
        };

        if path.is_dir() {
            return Err(format!("Source path is a directory, not a file: {}", source).into());
        }

        let filename = path
            .file_name()
            .and_then(|n| n.to_str())
            .ok_or("Invalid source path")?
            .to_string();

        // If it's already in the current directory or resolves to the same file, no need to copy
        let dest = Path::new(&filename);
        if dest.exists() {
            if let (Ok(p1), Ok(p2)) = (path.canonicalize(), dest.canonicalize())
                && p1 == p2
            {
                return Ok(filename);
            }
        } else if path.parent().is_none_or(|p| p.as_os_str().is_empty()) {
            return Ok(filename);
        }

        // Copy local file to current directory
        fs::copy(&path, &filename).await?;
        println!("Copied {} to current directory", path.display());

        Ok(filename)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_fetch_source_rejects_missing_local_file() {
        let err = fetch_source("non_existent_file_xyz_1234.tar.gz")
            .await
            .expect_err("missing file must error");
        assert!(err.to_string().contains("does not exist"));
    }

    #[tokio::test]
    async fn test_fetch_source_rejects_directory() {
        let err = fetch_source("src").await.expect_err("directory must error");
        assert!(err.to_string().contains("is a directory"));
    }

    #[tokio::test]
    async fn test_fetch_source_file_scheme() {
        let tmp = std::env::temp_dir().join(format!(
            "test_fetch_file_{}.txt",
            uuid::Uuid::new_v4().hyphenated()
        ));
        std::fs::write(&tmp, b"test payload").unwrap();
        let uri = format!("file://{}", tmp.display());
        let res = fetch_source(&uri)
            .await
            .expect("fetch file:// should succeed");
        assert_eq!(res, tmp.file_name().unwrap().to_str().unwrap());
        let _ = std::fs::remove_file(&tmp);
        let _ = std::fs::remove_file(&res);
    }
}

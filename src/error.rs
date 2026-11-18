use std::fmt;

/// Packager error types for unified, descriptive error handling across the library and CLI.
#[derive(Debug)]
pub enum PackagerError {
    Manifest(String),
    Checksum(String),
    InstallDirective(String),
    Source(String),
    Unpack(String),
    Build(String),
    Io(std::io::Error),
    Other(String),
}

impl fmt::Display for PackagerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Manifest(msg) => write!(f, "manifest error: {msg}"),
            Self::Checksum(msg) => write!(f, "checksum error: {msg}"),
            Self::InstallDirective(msg) => write!(f, "install directive error: {msg}"),
            Self::Source(msg) => write!(f, "source error: {msg}"),
            Self::Unpack(msg) => write!(f, "unpack error: {msg}"),
            Self::Build(msg) => write!(f, "build error: {msg}"),
            Self::Io(err) => write!(f, "I/O error: {err}"),
            Self::Other(msg) => write!(f, "{msg}"),
        }
    }
}

impl std::error::Error for PackagerError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(err) => Some(err),
            _ => None,
        }
    }
}

impl From<std::io::Error> for PackagerError {
    fn from(err: std::io::Error) -> Self {
        Self::Io(err)
    }
}

impl From<String> for PackagerError {
    fn from(msg: String) -> Self {
        Self::Other(msg)
    }
}

impl From<&str> for PackagerError {
    fn from(msg: &str) -> Self {
        Self::Other(msg.to_string())
    }
}

impl From<Box<dyn std::error::Error>> for PackagerError {
    fn from(err: Box<dyn std::error::Error>) -> Self {
        Self::Other(err.to_string())
    }
}

impl From<Box<dyn std::error::Error + Send + Sync>> for PackagerError {
    fn from(err: Box<dyn std::error::Error + Send + Sync>) -> Self {
        Self::Other(err.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_display_formatting() {
        let err = PackagerError::Manifest("missing name".to_string());
        assert_eq!(err.to_string(), "manifest error: missing name");

        let err = PackagerError::Checksum("sha256 mismatch".to_string());
        assert_eq!(err.to_string(), "checksum error: sha256 mismatch");

        let io_err = PackagerError::from(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "file not found",
        ));
        assert!(io_err.to_string().contains("I/O error:"));
    }
}

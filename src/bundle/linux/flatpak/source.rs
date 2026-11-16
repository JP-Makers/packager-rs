use serde::{Deserialize, Serialize};

/// Supported Flatpak source types.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub enum FlatpakSourceType {
    #[default]
    Archive,
    Git,
    File,
    Dir,
    Script,
    Shell,
    Patch,
    ExtraData,
}

/// Representation of a Flatpak source entry.
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub struct FlatpakSource {
    pub r#type: FlatpakSourceType,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sha256: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub branch: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tag: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub commands: Vec<String>,
}

impl FlatpakSource {
    pub fn new_archive(url: impl Into<String>, sha256: impl Into<String>) -> Self {
        Self {
            r#type: FlatpakSourceType::Archive,
            url: Some(url.into()),
            sha256: Some(sha256.into()),
            ..Default::default()
        }
    }

    pub fn new_file(path: impl Into<String>) -> Self {
        Self {
            r#type: FlatpakSourceType::File,
            path: Some(path.into()),
            ..Default::default()
        }
    }

    pub fn new_git(url: impl Into<String>, branch: Option<String>) -> Self {
        Self {
            r#type: FlatpakSourceType::Git,
            url: Some(url.into()),
            branch,
            ..Default::default()
        }
    }
}


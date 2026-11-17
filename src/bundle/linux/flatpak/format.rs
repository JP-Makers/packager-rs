use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

/// Supported Flatpak manifest formats (JSON and YAML).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
pub enum FlatpakManifestFormat {
    #[default]
    JSON,
    YAML,
}

impl FlatpakManifestFormat {
    /// Detect format from a file path extension.
    pub fn from_path(file_path: &str) -> Option<Self> {
        let lower = file_path.to_lowercase();
        if lower.ends_with(".yaml") || lower.ends_with(".yml") {
            Some(Self::YAML)
        } else if lower.ends_with(".json") {
            Some(Self::JSON)
        } else {
            None
        }
    }

    /// Parse a manifest string into type `T`.
    pub fn parse<T: DeserializeOwned>(
        &self,
        content: &str,
    ) -> Result<T, Box<dyn std::error::Error>> {
        match self {
            Self::JSON => Ok(serde_json::from_str(content)?),
            Self::YAML => Ok(serde_yaml::from_str(content)?),
        }
    }

    /// Serialize a value of type `T` into a formatted string.
    pub fn dump<T: Serialize>(&self, value: &T) -> Result<String, Box<dyn std::error::Error>> {
        match self {
            Self::JSON => Ok(serde_json::to_string_pretty(value)?),
            Self::YAML => Ok(serde_yaml::to_string(value)?),
        }
    }
}

use super::build_system::FlatpakBuildSystem;
use super::source::FlatpakSource;
use serde::{Deserialize, Serialize};

/// Flatpak module specification defining build steps and sources.
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub struct FlatpakModule {
    pub name: String,
    pub buildsystem: FlatpakBuildSystem,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub build_commands: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub sources: Vec<FlatpakSource>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub config_opts: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub cleanup: Vec<String>,
}

impl FlatpakModule {
    pub fn new(name: impl Into<String>, buildsystem: FlatpakBuildSystem) -> Self {
        Self {
            name: name.into(),
            buildsystem,
            ..Default::default()
        }
    }
}


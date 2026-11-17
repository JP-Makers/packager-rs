use serde::{Deserialize, Serialize};

/// Flatpak module build system.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub enum FlatpakBuildSystem {
    #[default]
    Simple,
    Autotools,
    Cmake,
    #[serde(rename = "cmake-ninja")]
    CmakeNinja,
    Meson,
    Qmake,
}

impl FlatpakBuildSystem {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Simple => "simple",
            Self::Autotools => "autotools",
            Self::Cmake => "cmake",
            Self::CmakeNinja => "cmake-ninja",
            Self::Meson => "meson",
            Self::Qmake => "qmake",
        }
    }
}

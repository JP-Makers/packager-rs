use serde::{Deserialize, Serialize};

pub const X86_64: &str = "x86_64";
pub const AARCH64: &str = "aarch64";
pub const ARM: &str = "arm";
pub const I386: &str = "i386";
pub const RISCV64: &str = "riscv64";

/// Supported architectures for Flatpak runtimes and applications.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub enum FlatpakArchitecture {
    #[default]
    #[serde(rename = "x86_64")]
    X86_64,
    #[serde(rename = "aarch64")]
    Aarch64,
    #[serde(rename = "arm")]
    Arm,
    #[serde(rename = "i386")]
    I386,
    #[serde(rename = "riscv64")]
    Riscv64,
}

impl FlatpakArchitecture {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::X86_64 => X86_64,
            Self::Aarch64 => AARCH64,
            Self::Arm => ARM,
            Self::I386 => I386,
            Self::Riscv64 => RISCV64,
        }
    }

    pub fn from_arch_str(arch: &str) -> Self {
        match arch {
            "x86_64" | "amd64" => Self::X86_64,
            "aarch64" | "arm64" => Self::Aarch64,
            "armhf" | "armv7h" | "armv7hl" | "arm" => Self::Arm,
            "i686" | "i386" => Self::I386,
            "riscv64" => Self::Riscv64,
            _ => Self::X86_64,
        }
    }
}


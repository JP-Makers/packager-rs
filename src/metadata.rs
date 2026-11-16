use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::Read;
use std::path::Path;

fn deserialize_string_or_int<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: serde::Deserializer<'de>,
{
    struct StringOrInt;

    impl<'de> serde::de::Visitor<'de> for StringOrInt {
        type Value = String;

        fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
            formatter.write_str("a string or integer")
        }

        fn visit_str<E>(self, value: &str) -> Result<String, E>
        where
            E: serde::de::Error,
        {
            Ok(value.to_string())
        }

        fn visit_string<E>(self, value: String) -> Result<String, E>
        where
            E: serde::de::Error,
        {
            Ok(value)
        }

        fn visit_i64<E>(self, value: i64) -> Result<String, E>
        where
            E: serde::de::Error,
        {
            Ok(value.to_string())
        }

        fn visit_u64<E>(self, value: u64) -> Result<String, E>
        where
            E: serde::de::Error,
        {
            Ok(value.to_string())
        }
    }

    deserializer.deserialize_any(StringOrInt)
}

/// Target platforms supported for platform-specific build configurations.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PlatformTarget {
    Linux,
    Mac,
    Windows,
    FreeBsd,
}

impl std::fmt::Display for PlatformTarget {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PlatformTarget::Linux => write!(f, "linux"),
            PlatformTarget::Mac => write!(f, "mac"),
            PlatformTarget::Windows => write!(f, "windows"),
            PlatformTarget::FreeBsd => write!(f, "freebsd"),
        }
    }
}

/// Platform-specific build configuration allowing custom sources, checksums, arch, workdir, and package instructions.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlatformBuildConfig {
    #[serde(default)]
    pub sources: Vec<String>,
    #[serde(default)]
    pub sha256sums: Vec<String>,
    #[serde(default)]
    pub sha512sums: Vec<String>,
    #[serde(default)]
    pub sha1sums: Vec<String>,
    #[serde(default)]
    pub md5sums: Vec<String>,
    #[serde(default)]
    pub arch: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workdir: Option<String>,
    #[serde(default, alias = "package")]
    pub package_instructions: Vec<String>,
}

/// Container for platform-specific build tables: `[build.linux]`, `[build.mac]`, `[build.windows]`, and `[build.freebsd]`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct BuildPlatforms {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub linux: Option<PlatformBuildConfig>,
    #[serde(default, alias = "macos", skip_serializing_if = "Option::is_none")]
    pub mac: Option<PlatformBuildConfig>,
    #[serde(default, alias = "win", skip_serializing_if = "Option::is_none")]
    pub windows: Option<PlatformBuildConfig>,
    #[serde(default, alias = "bsd", skip_serializing_if = "Option::is_none")]
    pub freebsd: Option<PlatformBuildConfig>,
}

fn default_alpm_build_env() -> Vec<String> {
    vec![
        "!distcc".to_string(),
        "color".to_string(),
        "!ccache".to_string(),
        "check".to_string(),
        "!sign".to_string(),
    ]
}

fn default_snap_confinement() -> String {
    "strict".to_string()
}

fn default_snap_base() -> String {
    "core22".to_string()
}

fn default_snap_grade() -> String {
    "stable".to_string()
}

fn default_flatpak_runtime() -> String {
    "org.freedesktop.Platform".to_string()
}

fn default_flatpak_runtime_version() -> String {
    "24.08".to_string()
}

fn default_flatpak_sdk() -> String {
    "org.freedesktop.Sdk".to_string()
}

fn default_mac_min_system_version() -> String {
    "11.0".to_string()
}

fn default_win_install_scope() -> String {
    "perMachine".to_string()
}

fn default_freebsd_prefix() -> String {
    "/usr/local".to_string()
}

fn default_true() -> bool {
    true
}


#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Metadata {
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub version: String,
    #[serde(default, deserialize_with = "deserialize_string_or_int")]
    pub release: String,
    #[serde(default)]
    pub maintainer: String,
    #[serde(default)]
    pub email: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub arch: Vec<String>,
    #[serde(default)]
    pub url: String,
    #[serde(default)]
    pub license: String,
    #[serde(default)]
    pub alpm_depends: Vec<String>,
    #[serde(default)]
    pub deb_depends: Vec<String>,
    #[serde(default)]
    pub rpm_depends: Vec<String>,
    #[serde(default)]
    pub provides: Vec<String>,
    #[serde(default)]
    pub conflicts: Vec<String>,
    #[serde(default)]
    pub sources: Vec<String>,
    #[serde(default)]
    pub md5sums: Vec<String>,
    #[serde(default)]
    pub sha1sums: Vec<String>,
    #[serde(default)]
    pub sha256sums: Vec<String>,
    #[serde(default)]
    pub sha512sums: Vec<String>,
    #[serde(default = "default_alpm_build_env")]
    pub alpm_build_env: Vec<String>,
    #[serde(default)]
    pub appimage_exec: String,
    #[serde(default, alias = "package")]
    pub package_instructions: Vec<String>,
    #[serde(default, alias = "appimage_icon")]
    pub appimage_icon_instructions: Vec<String>,
    #[serde(default, alias = "appimage_desktop")]
    pub appimage_desktop_instructions: Vec<String>,
    #[serde(default)]
    pub pkgbuild_sha256sum: String,
    #[serde(default)]
    pub clean_workdir: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workdir: Option<String>,
    #[serde(default = "default_snap_confinement")]
    pub snap_confinement: String,
    #[serde(default = "default_snap_base")]
    pub snap_base: String,
    #[serde(default = "default_snap_grade")]
    pub snap_grade: String,
    #[serde(default)]
    pub flatpak_id: String,
    #[serde(default = "default_flatpak_runtime")]
    pub flatpak_runtime: String,
    #[serde(default = "default_flatpak_runtime_version")]
    pub flatpak_runtime_version: String,
    #[serde(default = "default_flatpak_sdk")]
    pub flatpak_sdk: String,
    #[serde(default)]
    pub mac_bundle_id: String,
    #[serde(default)]
    pub mac_category: String,
    #[serde(default = "default_mac_min_system_version")]
    pub mac_min_system_version: String,
    #[serde(default)]
    pub mac_icon: String,
    #[serde(default)]
    pub win_upgrade_code: String,
    #[serde(default)]
    pub win_product_code: String,
    #[serde(default)]
    pub win_manufacturer: String,
    #[serde(default)]
    pub win_install_dir: String,
    #[serde(default = "default_win_install_scope")]
    pub win_install_scope: String,
    #[serde(default)]
    pub win_icon: String,
    #[serde(default)]
    pub win_header: String,
    #[serde(default)]
    pub win_wizard: String,
    #[serde(default = "default_true")]
    pub win_desktop_shortcut: bool,
    #[serde(default = "default_true")]
    pub win_program_menu_shortcut: bool,
    #[serde(default)]
    pub freebsd_depends: Vec<String>,
    #[serde(default)]
    pub freebsd_origin: String,
    #[serde(default)]
    pub freebsd_categories: Vec<String>,
    #[serde(default = "default_freebsd_prefix")]
    pub freebsd_prefix: String,
    #[serde(default)]
    pub freebsd_abi: String,
    #[serde(default)]
    pub keygen: bool,
    #[serde(default)]
    pub keygen_key: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub build: Option<BuildPlatforms>,
}

impl Default for Metadata {
    fn default() -> Self {
        Self {
            name: String::new(),
            version: String::new(),
            release: String::new(),
            maintainer: String::new(),
            email: String::new(),
            description: String::new(),
            arch: Vec::new(),
            url: String::new(),
            license: String::new(),
            alpm_depends: Vec::new(),
            deb_depends: Vec::new(),
            rpm_depends: Vec::new(),
            provides: Vec::new(),
            conflicts: Vec::new(),
            sources: Vec::new(),
            md5sums: Vec::new(),
            sha1sums: Vec::new(),
            sha256sums: Vec::new(),
            sha512sums: Vec::new(),
            alpm_build_env: vec![
                "!distcc".to_string(),
                "color".to_string(),
                "!ccache".to_string(),
                "check".to_string(),
                "!sign".to_string(),
            ],
            appimage_exec: String::new(),
            package_instructions: Vec::new(),
            appimage_icon_instructions: Vec::new(),
            appimage_desktop_instructions: Vec::new(),
            pkgbuild_sha256sum: String::new(),
            clean_workdir: false,
            workdir: None,
            snap_confinement: "strict".to_string(),
            snap_base: "core22".to_string(),
            snap_grade: "stable".to_string(),
            flatpak_id: String::new(),
            flatpak_runtime: "org.freedesktop.Platform".to_string(),
            flatpak_runtime_version: "24.08".to_string(),
            flatpak_sdk: "org.freedesktop.Sdk".to_string(),
            mac_bundle_id: String::new(),
            mac_category: "public.app-category.developer-tools".to_string(),
            mac_min_system_version: "11.0".to_string(),
            mac_icon: String::new(),
            win_upgrade_code: String::new(),
            win_product_code: String::new(),
            win_manufacturer: String::new(),
            win_install_dir: String::new(),
            win_install_scope: "perMachine".to_string(),
            win_icon: String::new(),
            win_header: String::new(),
            win_wizard: String::new(),
            win_desktop_shortcut: true,
            win_program_menu_shortcut: true,
            freebsd_depends: Vec::new(),
            freebsd_origin: String::new(),
            freebsd_categories: Vec::new(),
            freebsd_prefix: default_freebsd_prefix(),
            freebsd_abi: String::new(),
            keygen: false,
            keygen_key: String::new(),
            build: None,
        }
    }
}

/// A single path component that is safe to use as a directory name.
pub(crate) fn is_safe_component(value: &str) -> bool {
    !value.is_empty()
        && value != "."
        && value != ".."
        && !value.starts_with('.')
        && value
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
}

fn validate_component(field: &str, value: &str) -> Result<(), Box<dyn std::error::Error>> {
    if !is_safe_component(value) {
        return Err(format!(
            "{field} must be a plain name ([A-Za-z0-9._-], no '/', no '..', no leading '.'), got {value:?}"
        )
        .into());
    }
    Ok(())
}

/// Values that end up inside output file names may contain more characters
/// than a directory name, but never a path separator.
fn is_safe_filename_part(value: &str) -> bool {
    !value.is_empty()
        && !value.contains('/')
        && !value.contains('\\')
        && !value.contains('\0')
        && value != "."
        && value != ".."
        && !value.starts_with('.')
}

fn validate_filename_part(field: &str, value: &str) -> Result<(), Box<dyn std::error::Error>> {
    if !is_safe_filename_part(value) {
        return Err(format!(
            "{field} may not contain path separators or be empty, got {value:?}"
        )
        .into());
    }
    Ok(())
}

fn validate_single_line(field: &str, value: &str) -> Result<(), Box<dyn std::error::Error>> {
    if value.chars().any(|c| c.is_control()) {
        return Err(format!("{field} must not contain newlines or control characters").into());
    }
    Ok(())
}

fn validate_checksum_list(
    kind: &str,
    checksums: &[String],
    sources: &[String],
    expected_len: usize,
) -> Result<(), Box<dyn std::error::Error>> {
    if checksums.len() != sources.len() {
        return Err(format!(
            "{kind} count ({}) does not match sources count ({})",
            checksums.len(),
            sources.len()
        )
        .into());
    }
    for sum in checksums {
        if sum.eq_ignore_ascii_case("SKIP") {
            return Err(format!("{kind} contains 'SKIP': checksum bypass is forbidden for security").into());
        }
        if sum.len() != expected_len || !sum.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(format!(
                "{kind} entry {sum:?} is not a valid {expected_len}-character hexadecimal digest"
            )
            .into());
        }
    }
    Ok(())
}

fn validate_source_checksums(
    sources: &[String],
    md5sums: &[String],
    sha1sums: &[String],
    sha256sums: &[String],
    sha512sums: &[String],
    context: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    if sources.is_empty() {
        return Ok(());
    }

    let has_any = !sha256sums.is_empty()
        || !sha512sums.is_empty()
        || !sha1sums.is_empty()
        || !md5sums.is_empty();

    if !has_any {
        return Err(format!(
            "No package checksums found for {context} sources ({sources:?})"
        )
        .into());
    }

    if !sha256sums.is_empty() {
        validate_checksum_list("sha256sums", sha256sums, sources, 64)?;
    }
    if !sha512sums.is_empty() {
        validate_checksum_list("sha512sums", sha512sums, sources, 128)?;
    }
    if !sha1sums.is_empty() {
        validate_checksum_list("sha1sums", sha1sums, sources, 40)?;
    }
    if !md5sums.is_empty() {
        validate_checksum_list("md5sums", md5sums, sources, 32)?;
    }

    Ok(())
}

impl Metadata {
    /// Load and parse metadata from a TOML file path.
    ///
    /// A missing path is an error. Silently falling back to `./metadata.toml`
    /// means a typo builds a completely different project.
    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Self, Box<dyn std::error::Error>> {
        let p = path.as_ref();
        if !p.exists() {
            return Err(format!(
                "metadata file not found: {} (pass an explicit path with -m)",
                p.display()
            )
            .into());
        }

        let mut file = File::open(p)?;
        let mut buffer = Vec::new();
        file.read_to_end(&mut buffer)?;
        Self::from_bytes(&buffer)
    }

    /// Parse metadata from a string slice in TOML format (also implements `std::str::FromStr`).
    #[allow(clippy::should_implement_trait)]
    pub fn from_str(s: &str) -> Result<Self, Box<dyn std::error::Error>> {
        Self::from_bytes(s.as_bytes())
    }

    /// Parse metadata from raw TOML bytes, calculating the SHA-256 for ALPM buildinfo.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Box<dyn std::error::Error>> {
        let mut hasher = Sha256::new();
        hasher.update(bytes);
        let pkgbuild_sha256sum = hex::encode(hasher.finalize());

        let text = std::str::from_utf8(bytes)?;
        let mut meta: Metadata = toml::from_str(text)?;
        meta.pkgbuild_sha256sum = pkgbuild_sha256sum;
        meta.validate()?;
        Ok(meta)
    }

    /// Validate that all required core fields, sources, and checksums are present.
    ///
    /// Beyond presence, this rejects identifiers that would escape the build
    /// tree: `name` and `workdir` become directory names (and are passed to
    /// `remove_dir_all`), while `version`, `release` and `arch` become file
    /// names.
    pub fn validate(&self) -> Result<(), Box<dyn std::error::Error>> {
        if self.name.is_empty() {
            return Err("Package name not found".into());
        }
        validate_single_line("name", &self.name)?;

        if self.version.is_empty() {
            return Err("Package version not found".into());
        }
        validate_single_line("version", &self.version)?;

        if self.release.is_empty() {
            return Err("Package release not found".into());
        }
        validate_single_line("release", &self.release)?;

        if self.maintainer.is_empty() {
            return Err("Package maintainer not found".into());
        }
        validate_single_line("maintainer", &self.maintainer)?;

        if self.description.is_empty() {
            return Err("Package description not found".into());
        }
        validate_single_line("description", &self.description)?;
        if self.description.chars().count() > 79 {
            return Err("Package description exceeds 79 characters".into());
        }

        if !self.email.is_empty() {
            validate_single_line("email", &self.email)?;
            if !self.email.contains('@')
                || self.email.contains(' ')
                || self.email.starts_with('@')
                || self.email.ends_with('@')
            {
                return Err(format!("email must be a valid email address, got {:?}", self.email).into());
            }
        }

        if self.arch.is_empty() {
            let has_platform_arch = self.build.as_ref().is_some_and(|b| {
                b.linux.as_ref().is_some_and(|p| !p.arch.is_empty())
                    || b.mac.as_ref().is_some_and(|p| !p.arch.is_empty())
                    || b.windows.as_ref().is_some_and(|p| !p.arch.is_empty())
                    || b.freebsd.as_ref().is_some_and(|p| !p.arch.is_empty())
            });
            if !has_platform_arch {
                return Err("Package arch not found".into());
            }
        }
        for arch in &self.arch {
            validate_single_line("arch", arch)?;
            validate_filename_part("arch", arch)?;
        }

        if self.url.is_empty() {
            return Err("Package url not found".into());
        }
        validate_single_line("url", &self.url)?;

        if self.license.is_empty() {
            return Err("Package license not found".into());
        }
        validate_single_line("license", &self.license)?;

        // Relations & dependencies injection checks
        for dep in &self.deb_depends {
            validate_single_line("deb_depends", dep)?;
        }
        for dep in &self.rpm_depends {
            validate_single_line("rpm_depends", dep)?;
        }
        for dep in &self.alpm_depends {
            validate_single_line("alpm_depends", dep)?;
        }
        for dep in &self.freebsd_depends {
            validate_single_line("freebsd_depends", dep)?;
        }
        for p in &self.provides {
            validate_single_line("provides", p)?;
        }
        for c in &self.conflicts {
            validate_single_line("conflicts", c)?;
        }

        // Single-line checks for platform metadata fields
        validate_single_line("appimage_exec", &self.appimage_exec)?;
        validate_single_line("flatpak_id", &self.flatpak_id)?;
        validate_single_line("flatpak_runtime", &self.flatpak_runtime)?;
        validate_single_line("flatpak_runtime_version", &self.flatpak_runtime_version)?;
        validate_single_line("flatpak_sdk", &self.flatpak_sdk)?;
        validate_single_line("mac_bundle_id", &self.mac_bundle_id)?;
        validate_single_line("mac_category", &self.mac_category)?;
        validate_single_line("mac_min_system_version", &self.mac_min_system_version)?;
        validate_single_line("mac_icon", &self.mac_icon)?;
        validate_single_line("win_upgrade_code", &self.win_upgrade_code)?;
        validate_single_line("win_product_code", &self.win_product_code)?;
        validate_single_line("win_manufacturer", &self.win_manufacturer)?;
        validate_single_line("win_install_dir", &self.win_install_dir)?;
        validate_single_line("win_install_scope", &self.win_install_scope)?;
        validate_single_line("win_icon", &self.win_icon)?;
        validate_single_line("win_header", &self.win_header)?;
        validate_single_line("win_wizard", &self.win_wizard)?;
        validate_single_line("freebsd_origin", &self.freebsd_origin)?;
        validate_single_line("freebsd_prefix", &self.freebsd_prefix)?;
        validate_single_line("freebsd_abi", &self.freebsd_abi)?;
        validate_single_line("keygen_key", &self.keygen_key)?;

        // Identifiers that become paths or file names.
        validate_component("name", &self.name)?;
        validate_component("workdir", self.workdir())?;
        for workdir in self.all_workdirs() {
            validate_component("workdir", &workdir)?;
        }
        validate_filename_part("version", &self.version)?;
        validate_filename_part("release", &self.release)?;

        if let Some(build) = &self.build {
            for cfg in [&build.linux, &build.mac, &build.windows, &build.freebsd]
                .into_iter()
                .flatten()
            {
                for arch in &cfg.arch {
                    validate_single_line("arch", arch)?;
                    validate_filename_part("arch", arch)?;
                }
                if let Some(workdir) = &cfg.workdir {
                    validate_component("workdir", workdir)?;
                }
            }
        }

        let all_srcs = self.all_sources();
        if all_srcs.is_empty() {
            return Err("Package sources not found".into());
        }

        // Validate top-level checksums if sources are present
        validate_source_checksums(
            &self.sources,
            &self.md5sums,
            &self.sha1sums,
            &self.sha256sums,
            &self.sha512sums,
            "top-level",
        )?;

        // Validate per-platform checksums if defined
        if let Some(build) = &self.build {
            if let Some(ref l) = build.linux {
                validate_source_checksums(
                    &l.sources,
                    &l.md5sums,
                    &l.sha1sums,
                    &l.sha256sums,
                    &l.sha512sums,
                    "build.linux",
                )?;
            }
            if let Some(ref m) = build.mac {
                validate_source_checksums(
                    &m.sources,
                    &m.md5sums,
                    &m.sha1sums,
                    &m.sha256sums,
                    &m.sha512sums,
                    "build.mac",
                )?;
            }
            if let Some(ref w) = build.windows {
                validate_source_checksums(
                    &w.sources,
                    &w.md5sums,
                    &w.sha1sums,
                    &w.sha256sums,
                    &w.sha512sums,
                    "build.windows",
                )?;
            }
            if let Some(ref b) = build.freebsd {
                validate_source_checksums(
                    &b.sources,
                    &b.md5sums,
                    &b.sha1sums,
                    &b.sha256sums,
                    &b.sha512sums,
                    "build.freebsd",
                )?;
            }
        }

        Ok(())
    }

    /// Return all unique sources defined across top-level and platform build configurations.
    pub fn all_sources(&self) -> Vec<String> {
        let mut all = self.sources.clone();
        if let Some(ref build) = self.build {
            if let Some(ref l) = build.linux {
                all.extend(l.sources.clone());
            }
            if let Some(ref m) = build.mac {
                all.extend(m.sources.clone());
            }
            if let Some(ref w) = build.windows {
                all.extend(w.sources.clone());
            }
            if let Some(ref b) = build.freebsd {
                all.extend(b.sources.clone());
            }
        }
        let mut seen = std::collections::HashSet::new();
        all.into_iter().filter(|s| seen.insert(s.clone())).collect()
    }

    /// Return all workdirs defined across top-level and platform build configurations.
    pub fn all_workdirs(&self) -> Vec<String> {
        let mut dirs = vec![self.workdir().to_string()];
        if let Some(ref build) = self.build {
            if let Some(ref l) = build.linux
                && let Some(ref w) = l.workdir
            {
                dirs.push(w.clone());
            }
            if let Some(ref m) = build.mac
                && let Some(ref w) = m.workdir
            {
                dirs.push(w.clone());
            }
            if let Some(ref win) = build.windows
                && let Some(ref w) = win.workdir
            {
                dirs.push(w.clone());
            }
            if let Some(ref b) = build.freebsd
                && let Some(ref w) = b.workdir
            {
                dirs.push(w.clone());
            }
        }
        let mut seen = std::collections::HashSet::new();
        dirs.into_iter().filter(|s| seen.insert(s.clone())).collect()
    }

    /// Produce a specialized `Metadata` for a specific platform target, overriding
    /// sources, checksums, arch, workdir, and package instructions if specified under `[build.<platform>]`.
    pub fn for_platform(&self, target: PlatformTarget) -> Metadata {
        let mut platform_meta = self.clone();
        if let Some(ref build) = self.build {
            let platform_config = match target {
                PlatformTarget::Linux => build.linux.as_ref(),
                PlatformTarget::Mac => build.mac.as_ref(),
                PlatformTarget::Windows => build.windows.as_ref(),
                PlatformTarget::FreeBsd => build.freebsd.as_ref(),
            };

            if let Some(cfg) = platform_config {
                if !cfg.sources.is_empty() {
                    platform_meta.sources = cfg.sources.clone();
                }
                if !cfg.sha256sums.is_empty() {
                    platform_meta.sha256sums = cfg.sha256sums.clone();
                }
                if !cfg.sha512sums.is_empty() {
                    platform_meta.sha512sums = cfg.sha512sums.clone();
                }
                if !cfg.sha1sums.is_empty() {
                    platform_meta.sha1sums = cfg.sha1sums.clone();
                }
                if !cfg.md5sums.is_empty() {
                    platform_meta.md5sums = cfg.md5sums.clone();
                }
                if !cfg.arch.is_empty() {
                    platform_meta.arch = cfg.arch.clone();
                }
                if cfg.workdir.is_some() {
                    platform_meta.workdir = cfg.workdir.clone();
                }
                if !cfg.package_instructions.is_empty() {
                    platform_meta.package_instructions = cfg.package_instructions.clone();
                }
            }
        }
        platform_meta
    }

    pub fn deb_arch(&self) -> &str {
        match self.arch.first().map(|s| s.as_str()).unwrap_or("all") {
            "x86_64" | "amd64" => "amd64",
            "aarch64" | "arm64" => "arm64",
            "i686" | "i386" => "i386",
            "armhf" | "armv7h" | "armv7hl" => "armhf",
            "riscv64" => "riscv64",
            "all" => "all",
            other => other,
        }
    }

    pub fn rpm_arch(&self) -> &str {
        match self.arch.first().map(|s| s.as_str()).unwrap_or("noarch") {
            "x86_64" | "amd64" => "x86_64",
            "aarch64" | "arm64" => "aarch64",
            "i686" | "i386" => "i686",
            "armhf" | "armv7h" | "armv7hl" => "armv7hl",
            "riscv64" => "riscv64",
            "noarch" => "noarch",
            other => other,
        }
    }

    pub fn primary_arch(&self) -> &str {
        self.arch.first().map(|s| s.as_str()).unwrap_or("x86_64")
    }

    /// Return the macOS architecture string (e.g. `universal`, `arm64`, `x86_64`).
    pub fn mac_arch(&self) -> &str {
        match self.primary_arch() {
            "x86_64" | "amd64" => "x86_64",
            "aarch64" | "arm64" => "arm64",
            "universal" => "universal",
            other if !other.is_empty() => other,
            _ => "universal",
        }
    }

    /// Return FreeBSD architecture name (e.g. `amd64`, `aarch64`, `i386`, `armv7`, `riscv64`).
    pub fn freebsd_arch(&self) -> &str {
        match self.primary_arch() {
            "x86_64" | "amd64" => "amd64",
            "aarch64" | "arm64" => "aarch64",
            "i686" | "i386" => "i386",
            "armhf" | "armv7h" | "armv7hl" | "armv7" => "armv7",
            "riscv64" => "riscv64",
            other => other,
        }
    }

    /// Return FreeBSD package arch triple for `+MANIFEST` (e.g. `freebsd:14:x86:64`).
    pub fn freebsd_pkg_arch(&self) -> String {
        match self.freebsd_arch() {
            "amd64" => "freebsd:14:x86:64".to_string(),
            "aarch64" => "freebsd:14:aarch64:64".to_string(),
            "i386" => "freebsd:14:x86:32".to_string(),
            "armv7" => "freebsd:14:arm:32:el:eabihf".to_string(),
            "riscv64" => "freebsd:14:riscv:64".to_string(),
            other => format!("freebsd:14:{}", other),
        }
    }

    /// Return FreeBSD ABI string for `+MANIFEST` (e.g. `FreeBSD:14:amd64`).
    pub fn freebsd_abi(&self) -> String {
        if !self.freebsd_abi.is_empty() {
            return self.freebsd_abi.clone();
        }
        format!("FreeBSD:14:{}", self.freebsd_arch())
    }

    /// Return FreeBSD origin string (e.g. `devel/twincan`).
    pub fn freebsd_origin(&self) -> String {
        if !self.freebsd_origin.is_empty() {
            return self.freebsd_origin.clone();
        }
        let category = self.freebsd_categories.first().map(|s| s.as_str()).unwrap_or("devel");
        format!("{}/{}", category, self.name)
    }

    /// Return FreeBSD categories list (defaults to `["devel"]`).
    pub fn freebsd_categories(&self) -> Vec<String> {
        if !self.freebsd_categories.is_empty() {
            return self.freebsd_categories.clone();
        }
        vec!["devel".to_string()]
    }

    /// Return the directory where sources are unpacked (defaults to `self.name`).
    pub fn workdir(&self) -> &str {
        self.workdir.as_deref().unwrap_or(&self.name)
    }

    /// Return whether the working directory should be cleaned after building.
    pub fn should_clean_workdir(&self) -> bool {
        self.clean_workdir
    }

    /// Return the Flatpak reverse-DNS Application ID (e.g. `org.jpmakers.twincan`).
    pub fn flatpak_id(&self) -> String {
        if !self.flatpak_id.is_empty() {
            return self.flatpak_id.clone();
        }
        let clean_maintainer: String = self
            .maintainer
            .chars()
            .filter(|c| c.is_alphanumeric())
            .collect::<String>()
            .to_lowercase();
        let m = if clean_maintainer.is_empty() {
            "example".to_string()
        } else {
            clean_maintainer
        };
        let clean_name: String = self
            .name
            .chars()
            .filter(|c| c.is_alphanumeric() || *c == '_' || *c == '.')
            .collect::<String>()
            .to_lowercase();
        format!("org.{}.{}", m, clean_name)
    }

    /// Return the main executable filename inside the package.
    pub fn executable_name(&self) -> String {
        if !self.appimage_exec.is_empty() {
            let p = Path::new(&self.appimage_exec);
            if let Some(file_name) = p.file_name().and_then(|s| s.to_str()) {
                return file_name.to_string();
            }
        }
        self.name.clone()
    }

    /// Return the macOS CFBundleIdentifier (e.g. `com.jpmakers.twincan`).
    pub fn mac_bundle_id(&self) -> String {
        if !self.mac_bundle_id.is_empty() {
            return self.mac_bundle_id.clone();
        }
        let clean_maintainer: String = self
            .maintainer
            .chars()
            .filter(|c| c.is_alphanumeric())
            .collect::<String>()
            .to_lowercase();
        let m = if clean_maintainer.is_empty() {
            "example".to_string()
        } else {
            clean_maintainer
        };
        let clean_name: String = self
            .name
            .chars()
            .filter(|c| c.is_alphanumeric() || *c == '_' || *c == '.')
            .collect::<String>()
            .to_lowercase();
        format!("com.{}.{}", m, clean_name)
    }

    /// Return the application display name suitable for macOS .app bundles (e.g. `TwinCAN`).
    pub fn app_name(&self) -> String {
        if !self.appimage_exec.is_empty() {
            let p = Path::new(&self.appimage_exec);
            if let Some(file_name) = p.file_name().and_then(|s| s.to_str()) {
                return file_name.to_string();
            }
        }
        let mut chars = self.name.chars();
        match chars.next() {
            None => String::new(),
            Some(f) => f.to_uppercase().collect::<String>() + chars.as_str(),
        }
    }

    /// Return the Windows architecture string (e.g. `x64`, `x86`, `arm64`).
    pub fn win_arch(&self) -> &str {
        match self.primary_arch() {
            "x86_64" | "amd64" | "x64" => "x64",
            "aarch64" | "arm64" => "arm64",
            "i686" | "i386" | "x86" => "x86",
            other => other,
        }
    }

    /// Return the Windows manufacturer name (defaults to maintainer).
    pub fn win_manufacturer(&self) -> String {
        if !self.win_manufacturer.is_empty() {
            return self.win_manufacturer.clone();
        }
        if !self.maintainer.is_empty() {
            return self.maintainer.clone();
        }
        "PackageMaintainer".to_string()
    }

    /// Return the Windows install folder name (defaults to app_name()).
    pub fn win_install_dir(&self) -> String {
        if !self.win_install_dir.is_empty() {
            return self.win_install_dir.clone();
        }
        self.app_name()
    }

    /// Return the Windows UpgradeCode GUID formatted as `{XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX}`.
    /// If not specified in metadata, generates a deterministic GUID based on UUID v5.
    pub fn win_upgrade_code(&self) -> String {
        if !self.win_upgrade_code.is_empty() {
            let s = self.win_upgrade_code.trim();
            if s.starts_with('{') && s.ends_with('}') {
                return s.to_ascii_uppercase();
            }
            return format!("{{{}}}", s).to_ascii_uppercase();
        }
        let seed = format!("{}:{}", self.win_manufacturer(), self.name);
        let u = uuid::Uuid::new_v5(&uuid::Uuid::NAMESPACE_DNS, seed.as_bytes());
        format!("{{{}}}", u.hyphenated()).to_ascii_uppercase()
    }

    /// Return the Windows ProductCode GUID formatted as `{XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX}`.
    /// If not specified in metadata, generates a deterministic GUID based on UUID v5 from name and version.
    pub fn win_product_code(&self) -> String {
        if !self.win_product_code.is_empty() {
            let s = self.win_product_code.trim();
            if s.starts_with('{') && s.ends_with('}') {
                return s.to_ascii_uppercase();
            }
            return format!("{{{}}}", s).to_ascii_uppercase();
        }
        let seed = format!("{}:{}:{}", self.win_manufacturer(), self.name, self.version);
        let u = uuid::Uuid::new_v5(&uuid::Uuid::NAMESPACE_DNS, seed.as_bytes());
        format!("{{{}}}", u.hyphenated()).to_ascii_uppercase()
    }

    /// Return a 3-part numeric version string (e.g. `1.2.3`) required by MSI ProductVersion.
    pub fn msi_version(&self) -> String {
        let clean = self.version.split('-').next().unwrap_or("1.0.0");
        let parts: Vec<&str> = clean.split('.').collect();
        match parts.len() {
            0 => "1.0.0".to_string(),
            1 => format!("{}.0.0", parts[0]),
            2 => format!("{}.{}.0", parts[0], parts[1]),
            _ => format!("{}.{}.{}", parts[0], parts[1], parts[2]),
        }
    }


    /// Serialize metadata to a TOML string.
    pub fn to_toml(&self) -> Result<String, toml::ser::Error> {
        toml::to_string_pretty(self)
    }

    /// Deserialize metadata from a TOML string.
    pub fn from_toml(toml_str: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let mut hasher = Sha256::new();
        hasher.update(toml_str.as_bytes());
        let pkgbuild_sha256sum = hex::encode(hasher.finalize());

        let mut meta: Metadata = toml::from_str(toml_str)?;
        meta.pkgbuild_sha256sum = pkgbuild_sha256sum;
        meta.validate()?;
        Ok(meta)
    }

    /// Serialize metadata to a pretty JSON string.
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }

    /// Deserialize metadata from a JSON string.
    pub fn from_json(json_str: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let meta: Metadata = serde_json::from_str(json_str)?;
        meta.validate()?;
        Ok(meta)
    }

    /// Serialize metadata to a YAML string.
    pub fn to_yaml(&self) -> Result<String, serde_yaml::Error> {
        serde_yaml::to_string(self)
    }

    /// Deserialize metadata from a YAML string.
    pub fn from_yaml(yaml_str: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let meta: Metadata = serde_yaml::from_str(yaml_str)?;
        meta.validate()?;
        Ok(meta)
    }
}

impl std::str::FromStr for Metadata {
    type Err = Box<dyn std::error::Error>;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::from_bytes(s.as_bytes())
    }
}

pub fn extract_metadata(metadata_path: &str) -> Result<Metadata, Box<dyn std::error::Error>> {
    Metadata::from_file(metadata_path)
}

#[allow(dead_code)]
pub fn print_metadata(metadata_path: &str) -> Result<(), Box<dyn std::error::Error>> {
    let metadata = extract_metadata(metadata_path)?;

    println!("Package: {}", metadata.name);
    println!("Version: {}", metadata.version);
    println!("Release: {}", metadata.release);
    println!("Maintainer: {}", metadata.maintainer);
    println!("Description: {}", metadata.description);
    println!("Arch: {:?}", metadata.arch);
    println!("URL: {}", metadata.url);
    println!("License: {}", metadata.license);
    println!("ALPM Depends: {:?}", metadata.alpm_depends);
    println!("DEB Depends: {:?}", metadata.deb_depends);
    println!("RPM Depends: {:?}", metadata.rpm_depends);
    println!("Provides: {:?}", metadata.provides);
    println!("Conflicts: {:?}", metadata.conflicts);
    println!("Sources: {:?}", metadata.sources);
    println!("SHA256SUMS: {:?}", metadata.sha256sums);

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_metadata_file() {
        let meta = Metadata::from_file("metadata.toml").expect("Should parse default metadata.toml file");
        assert_eq!(meta.name, "twincan");
        assert_eq!(meta.deb_arch(), "amd64");
        assert_eq!(meta.rpm_arch(), "x86_64");
        assert_eq!(meta.primary_arch(), "x86_64");
    }

    #[test]
    fn test_parse_from_str() {
        let raw = r#"
name = "myapp"
version = "2.0.0"
release = "1"
maintainer = "Alice"
email = "alice@example.com"
description = "Test application"
arch = ["aarch64"]
url = "https://example.com/myapp"
license = "MIT"
sources = ["https://example.com/myapp.tar.gz"]
sha256sums = ["a31c61e733ae21eaa645de0e870c03d4fdb812c7e5a0a5666ef229ceba7fa8f4"]
"#;
        let meta = Metadata::from_str(raw).expect("Should parse string metadata");
        assert_eq!(meta.name, "myapp");
        assert_eq!(meta.version, "2.0.0");
        assert_eq!(meta.deb_arch(), "arm64");
        assert_eq!(meta.rpm_arch(), "aarch64");
    }

    #[test]
    fn test_arch_mapping() {
        let mut meta = Metadata {
            arch: vec!["aarch64".to_string()],
            ..Default::default()
        };
        assert_eq!(meta.deb_arch(), "arm64");
        assert_eq!(meta.rpm_arch(), "aarch64");

        meta.arch = vec!["i686".to_string()];
        assert_eq!(meta.deb_arch(), "i386");
        assert_eq!(meta.rpm_arch(), "i686");

        meta.arch = vec!["armhf".to_string()];
        assert_eq!(meta.deb_arch(), "armhf");
        assert_eq!(meta.rpm_arch(), "armv7hl");

        meta.arch = vec!["riscv64".to_string()];
        assert_eq!(meta.deb_arch(), "riscv64");
        assert_eq!(meta.rpm_arch(), "riscv64");
        assert_eq!(meta.primary_arch(), "riscv64");
    }

    #[test]
    fn test_work_dir_options() {
        let raw = r#"
name = "myapp"
version = "1.0.0"
release = "1"
maintainer = "Bob"
email = "bob@example.com"
description = "Workdir test"
arch = ["x86_64"]
url = "https://example.com/myapp"
license = "MIT"
sources = ["https://example.com/myapp.tar.gz"]
sha256sums = ["a31c61e733ae21eaa645de0e870c03d4fdb812c7e5a0a5666ef229ceba7fa8f4"]
workdir = "custom_build_dir"
clean_workdir = true
"#;
        let meta = Metadata::from_str(raw).expect("Should parse metadata with workdir options");
        assert_eq!(meta.workdir(), "custom_build_dir");
        assert!(meta.should_clean_workdir());
    }

    #[test]
    fn test_serde_json_metadata() {
        let raw = r#"
name = "testapp"
version = "1.2.3"
release = "1"
maintainer = "Tester"
email = "test@example.com"
description = "JSON test"
arch = ["x86_64"]
url = "https://example.com"
license = "MIT"
sources = ["https://example.com/testapp.tar.gz"]
sha256sums = ["a31c61e733ae21eaa645de0e870c03d4fdb812c7e5a0a5666ef229ceba7fa8f4"]
flatpak_id = "org.example.TestApp"
snap_confinement = "strict"
"#;
        let meta = Metadata::from_str(raw).expect("Should parse metadata");
        let json_str = meta.to_json().expect("Should serialize to JSON");
        assert!(json_str.contains("\"name\": \"testapp\""));
        assert!(json_str.contains("\"flatpak_id\": \"org.example.TestApp\""));
        assert!(json_str.contains("\"snap_confinement\": \"strict\""));

        let deserialized = Metadata::from_json(&json_str).expect("Should deserialize from JSON");
        assert_eq!(deserialized.name, meta.name);
        assert_eq!(deserialized.version, meta.version);
        assert_eq!(deserialized.flatpak_id, meta.flatpak_id);
        assert_eq!(deserialized.snap_confinement, meta.snap_confinement);
    }

    #[test]
    fn test_serde_yaml_metadata() {
        let raw = r#"
name = "testyaml"
version = "3.2.1"
release = "1"
maintainer = "YAML Tester"
email = "yaml@example.com"
description = "YAML test package"
arch = ["x86_64"]
url = "https://example.com/yaml"
license = "Apache-2.0"
sources = ["https://example.com/yaml.tar.gz"]
sha256sums = ["a31c61e733ae21eaa645de0e870c03d4fdb812c7e5a0a5666ef229ceba7fa8f4"]
snap_confinement = "classic"
snap_base = "core24"
snap_grade = "devel"
"#;
        let meta = Metadata::from_str(raw).expect("Should parse metadata");
        let yaml_str = meta.to_yaml().expect("Should serialize to YAML");
        assert!(yaml_str.contains("name: testyaml"));
        assert!(yaml_str.contains("snap_confinement: classic"));
        assert!(yaml_str.contains("snap_base: core24"));

        let deserialized = Metadata::from_yaml(&yaml_str).expect("Should deserialize from YAML");
        assert_eq!(deserialized.name, meta.name);
        assert_eq!(deserialized.version, meta.version);
        assert_eq!(deserialized.snap_confinement, meta.snap_confinement);
        assert_eq!(deserialized.snap_base, meta.snap_base);
    }

    #[test]
    fn test_keygen_metadata_parsing() {
        let raw1 = r#"
name = "keygentest1"
version = "1.0.0"
release = "1"
maintainer = "Bob"
email = "bob@example.com"
description = "Keygen test"
arch = ["x86_64"]
url = "https://example.com/keygen1"
license = "MIT"
sources = ["https://example.com/test.tar.gz"]
sha256sums = ["a31c61e733ae21eaa645de0e870c03d4fdb812c7e5a0a5666ef229ceba7fa8f4"]
keygen = true
keygen_key = "/custom/path/key.sec"
"#;
        let meta1 = Metadata::from_str(raw1).expect("parse metadata with keygen: true");
        assert!(meta1.keygen);
        assert_eq!(meta1.keygen_key, "/custom/path/key.sec");

        let raw2 = r#"
name = "keygentest2"
version = "1.0.0"
release = "1"
maintainer = "Alice"
email = "alice@example.com"
description = "Keygen test 2"
arch = ["x86_64"]
url = "https://example.com/keygen2"
license = "MIT"
sources = ["https://example.com/test.tar.gz"]
sha256sums = ["a31c61e733ae21eaa645de0e870c03d4fdb812c7e5a0a5666ef229ceba7fa8f4"]
keygen = true
keygen_key = "/custom/path/key.asc"
"#;
        let meta2 = Metadata::from_str(raw2).expect("parse metadata with keygen = true");
        assert!(meta2.keygen);
        assert_eq!(meta2.keygen_key, "/custom/path/key.asc");
    }

    #[test]
    fn test_serde_toml_metadata() {
        let toml_str = r#"
name = "twincan"
version = "1.0.0"
release = 1
maintainer = "JP-Makers"
email = "contact@jp-makers.com"
description = "TwinCAN GUI"
url = "https://github.com/JP-Makers/twincan"
license = "MIT"
arch = ["x86_64"]
sources = ["https://example.com/twincan.tar.gz"]
sha256sums = ["a31c61e733ae21eaa645de0e870c03d4fdb812c7e5a0a5666ef229ceba7fa8f4"]

[build.linux]
sources = ["https://example.com/twincan-linux.tar.gz"]
sha256sums = ["1111111111111111111111111111111111111111111111111111111111111111"]
arch = ["x86_64"]
workdir = "twincan-linux"

[build.mac]
sources = ["https://example.com/twincan-mac.tar.gz"]
sha256sums = ["2222222222222222222222222222222222222222222222222222222222222222"]
arch = ["arm64", "x86_64"]
workdir = "twincan-mac"

[build.windows]
sources = ["https://example.com/twincan-win.tar.gz"]
sha256sums = ["3333333333333333333333333333333333333333333333333333333333333333"]
arch = ["x64"]
workdir = "twincan-win"

[build.freebsd]
sources = ["https://example.com/twincan-bsd.tar.gz"]
sha256sums = ["4444444444444444444444444444444444444444444444444444444444444444"]
arch = ["amd64"]
workdir = "twincan-bsd"
"#;
        let meta = Metadata::from_toml(toml_str).expect("Should parse TOML metadata");
        assert_eq!(meta.name, "twincan");
        assert_eq!(meta.release, "1");
        assert!(meta.build.is_some());

        // Platform specialization
        let linux_meta = meta.for_platform(PlatformTarget::Linux);
        assert_eq!(linux_meta.sources, vec!["https://example.com/twincan-linux.tar.gz"]);
        assert_eq!(linux_meta.workdir(), "twincan-linux");

        let mac_meta = meta.for_platform(PlatformTarget::Mac);
        assert_eq!(mac_meta.sources, vec!["https://example.com/twincan-mac.tar.gz"]);
        assert_eq!(mac_meta.workdir(), "twincan-mac");
        assert_eq!(mac_meta.arch, vec!["arm64", "x86_64"]);

        let win_meta = meta.for_platform(PlatformTarget::Windows);
        assert_eq!(win_meta.sources, vec!["https://example.com/twincan-win.tar.gz"]);
        assert_eq!(win_meta.workdir(), "twincan-win");
        assert_eq!(win_meta.arch, vec!["x64"]);

        let bsd_meta = meta.for_platform(PlatformTarget::FreeBsd);
        assert_eq!(bsd_meta.sources, vec!["https://example.com/twincan-bsd.tar.gz"]);
        assert_eq!(bsd_meta.workdir(), "twincan-bsd");
        assert_eq!(bsd_meta.arch, vec!["amd64"]);

        // Serialization and re-deserialization
        let serialized = meta.to_toml().expect("Should serialize to TOML");
        assert!(serialized.contains("twincan-linux.tar.gz"));
        assert!(serialized.contains("[build.linux]"));

        let deserialized = Metadata::from_toml(&serialized).expect("Should re-deserialize from TOML");
        assert_eq!(deserialized.name, meta.name);
        assert_eq!(deserialized.sources, meta.sources);

        // all_sources
        let all_srcs = meta.all_sources();
        assert_eq!(all_srcs.len(), 5);
    }

    /// Minimal metadata that passes `validate()`, with `extra` appended.
    fn valid_toml(extra: &str) -> String {
        format!(
            r#"
name = "twincan"
version = "1.0.0"
release = "1"
maintainer = "Alice"
description = "Test application"
arch = ["x86_64"]
url = "https://example.com/twincan"
license = "MIT"
sources = ["https://example.com/twincan.tar.gz"]
sha256sums = ["a31c61e733ae21eaa645de0e870c03d4fdb812c7e5a0a5666ef229ceba7fa8f4"]
{extra}
"#
        )
    }

    #[test]
    fn test_validate_accepts_plain_identifiers() {
        Metadata::from_str(&valid_toml("")).expect("baseline metadata must validate");
        Metadata::from_str(&valid_toml(r#"workdir = "twincan-1.0.0""#))
            .expect("a relative workdir is valid");
    }

    #[test]
    fn test_validate_rejects_parent_workdir() {
        let err = Metadata::from_str(&valid_toml(r#"workdir = "../x""#))
            .expect_err("workdir may not escape the build tree");
        assert!(err.to_string().contains("workdir"), "{err}");
    }

    #[test]
    fn test_validate_rejects_hidden_workdir() {
        let err = Metadata::from_str(&valid_toml(r#"workdir = ".cache""#))
            .expect_err("a leading dot makes a hidden directory");
        assert!(err.to_string().contains("workdir"), "{err}");
    }

    #[test]
    fn test_validate_rejects_name_with_separator() {
        let raw = valid_toml("").replace(r#"name = "twincan""#, r#"name = "a/b""#);
        let err = Metadata::from_str(&raw).expect_err("name is used as a directory name");
        assert!(err.to_string().contains("name"), "{err}");
    }

    #[test]
    fn test_validate_rejects_version_with_separator() {
        let raw = valid_toml("").replace(r#"version = "1.0.0""#, r#"version = "../../1.0.0""#);
        let err = Metadata::from_str(&raw).expect_err("version is used in output file names");
        assert!(err.to_string().contains("version"), "{err}");
    }

    #[test]
    fn test_validate_requires_a_checksum() {
        let raw = valid_toml("").replace(
            r#"sha256sums = ["a31c61e733ae21eaa645de0e870c03d4fdb812c7e5a0a5666ef229ceba7fa8f4"]"#,
            "",
        );
        let err = Metadata::from_str(&raw).expect_err("an unverified source must be refused");
        assert!(err.to_string().contains("checksums"), "{err}");
    }

    #[test]
    fn test_validate_rejects_newline_in_description() {
        let raw = valid_toml("").replace(
            r#"description = "Test application""#,
            r#"description = "Test\napplication""#,
        );
        let err = Metadata::from_str(&raw).expect_err("newline in description must be rejected");
        assert!(err.to_string().contains("description"), "{err}");
    }

    #[test]
    fn test_validate_rejects_description_too_long() {
        let long_desc = "a".repeat(80);
        let raw = valid_toml("").replace(
            r#"description = "Test application""#,
            &format!("description = \"{long_desc}\""),
        );
        let err = Metadata::from_str(&raw).expect_err("description over 79 characters must be rejected");
        assert!(err.to_string().contains("79 characters"), "{err}");
    }

    #[test]
    fn test_validate_rejects_mismatched_sha256_count() {
        let raw = valid_toml("").replace(
            r#"sha256sums = ["a31c61e733ae21eaa645de0e870c03d4fdb812c7e5a0a5666ef229ceba7fa8f4"]"#,
            r#"sha256sums = ["a31c61e733ae21eaa645de0e870c03d4fdb812c7e5a0a5666ef229ceba7fa8f4", "a31c61e733ae21eaa645de0e870c03d4fdb812c7e5a0a5666ef229ceba7fa8f4"]"#,
        );
        let err = Metadata::from_str(&raw).expect_err("checksum count mismatch must be rejected");
        assert!(err.to_string().contains("does not match sources count"), "{err}");
    }

    #[test]
    fn test_validate_rejects_invalid_sha256_format() {
        let raw = valid_toml("").replace(
            r#"sha256sums = ["a31c61e733ae21eaa645de0e870c03d4fdb812c7e5a0a5666ef229ceba7fa8f4"]"#,
            r#"sha256sums = ["not_a_valid_hex_hash"]"#,
        );
        let err = Metadata::from_str(&raw).expect_err("invalid hex format must be rejected");
        assert!(err.to_string().contains("hexadecimal"), "{err}");
    }

    #[test]
    fn test_validate_rejects_skip_checksum() {
        let raw = valid_toml("").replace(
            r#"sha256sums = ["a31c61e733ae21eaa645de0e870c03d4fdb812c7e5a0a5666ef229ceba7fa8f4"]"#,
            r#"sha256sums = ["SKIP"]"#,
        );
        let err = Metadata::from_str(&raw).expect_err("SKIP checksum must be rejected");
        assert!(err.to_string().contains("SKIP"), "{err}");
    }

    #[test]
    fn test_validate_rejects_invalid_email() {
        let raw = valid_toml(r#"email = "invalid-email-no-at""#);
        let err = Metadata::from_str(&raw).expect_err("invalid email must be rejected");
        assert!(err.to_string().contains("email"), "{err}");
    }
}
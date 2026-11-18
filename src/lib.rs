use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

mod bundle;
mod checksum;
mod chmod;
mod clone;
mod error;
mod metadata;
mod payload;
mod repro;
mod unpack;

pub use bundle::bsd::{FreeBSDDep, FreeBSDManifest, freebsd_package};
pub use bundle::keygen::{
    KeygenResults, default_key_dir, default_key_dir_for, generate_ed25519_keypair,
    generate_or_load_key, generate_or_load_key_in, generate_zsync, parse_ed25519_armored_signature,
    run_keygen, run_keygen_with_key_dir, sign_bytes, validate_ed25519_signature, verify_signature,
};
pub use bundle::linux::alpm::{alpm_package, normalize_alpm_package};
pub use bundle::linux::appimage::{EMBEDDED_RUNTIMES, EmbeddedRuntimeInfo, appimage_package};
pub use bundle::linux::deb::deb_package;
pub use bundle::linux::flatpak::{
    FlatpakApplication, FlatpakArchitecture, FlatpakBuildSystem, FlatpakManifestFormat,
    FlatpakModule, FlatpakSource, FlatpakSourceType, flatpak_package,
};
pub use bundle::linux::oci::{
    OciConfig, OciDescriptor, OciExecutionConfig, OciManifest, OciPlatform, OciRootfs,
    build_oci_manifest, oci_package,
};
pub use bundle::linux::rpm::rpm_package;
pub use bundle::linux::snap::snap_package;
pub use bundle::macos::dmg_package;
pub use bundle::windows::msi_package;
pub use checksum::{
    md5_hash, sha1_hash, sha256_hash, sha512_hash, verify_checksum, verify_checksum_value,
};
pub use chmod::chmod_package_with_metadata;
pub use clone::{fetch_source, fetch_source_with_base};
pub use error::PackagerError;
pub use metadata::{BuildPlatforms, Metadata, PlatformBuildConfig, PlatformTarget};
pub use unpack::unpack_source;

/// Target platform and format selection.
#[derive(Debug, Clone, Default)]
pub struct PlatformSelection {
    pub all: bool,
    pub deb: bool,
    pub appimage: bool,
    pub rpm: bool,
    pub alpm: bool,
    pub snap: bool,
    pub flatpak: bool,
    pub dmg: bool,
    pub msi: bool,
    pub freebsd: bool,
    pub oci: bool,
}

impl PlatformSelection {
    /// True if no specific format flags were set or `--all` was explicitly requested.
    pub fn is_all(&self) -> bool {
        self.all
            || (!self.deb
                && !self.appimage
                && !self.rpm
                && !self.alpm
                && !self.snap
                && !self.flatpak
                && !self.dmg
                && !self.msi
                && !self.freebsd
                && !self.oci)
    }
}

/// Results containing paths to all packages built by `PackageBuilder`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct BuildResults {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub alpm: Option<PathBuf>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub appimage: Option<PathBuf>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deb: Option<PathBuf>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rpm: Option<PathBuf>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub snap: Option<PathBuf>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub flatpak: Option<PathBuf>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dmg: Option<PathBuf>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub msi: Option<PathBuf>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub freebsd: Option<PathBuf>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub oci: Option<PathBuf>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub keygen: Option<KeygenResults>,
}

impl BuildResults {
    /// Serialize results to a formatted JSON string.
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }

    /// Deserialize results from a JSON string.
    pub fn from_json(s: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(s)
    }

    /// Serialize results to a formatted YAML string.
    pub fn to_yaml(&self) -> Result<String, serde_yml::Error> {
        serde_yml::to_string(self)
    }

    /// Deserialize results from a YAML string.
    pub fn from_yaml(s: &str) -> Result<Self, serde_yml::Error> {
        serde_yml::from_str(s)
    }

    /// Serialize results to a formatted TOML string.
    pub fn to_toml(&self) -> Result<String, toml::ser::Error> {
        toml::to_string_pretty(self)
    }

    /// Deserialize results from a TOML string.
    pub fn from_toml(s: &str) -> Result<Self, toml::de::Error> {
        toml::from_str(s)
    }
}

/// High-level builder interface for orchestrating multi-distro Linux package creation.
#[derive(Debug, Clone)]
pub struct PackageBuilder {
    pub metadata: Metadata,
    pub output_dir: PathBuf,
}

/// Resolve a cleanup target and confirm it lives strictly inside `cwd`.
///
/// Kept separate from [`PackageBuilder::clean_workdir`] so the containment
/// rule can be unit-tested without touching the process working directory.
fn resolve_clean_target(cwd: &Path, target: &Path) -> Result<PathBuf, Box<dyn std::error::Error>> {
    let resolved = target
        .canonicalize()
        .map_err(|e| format!("cannot resolve {:?} before removing it: {e}", target))?;

    if resolved == cwd || !resolved.starts_with(cwd) {
        return Err(format!(
            "refusing to remove {:?}: it is not inside the working directory {:?}",
            target, cwd
        )
        .into());
    }

    if resolved.parent().is_none() {
        return Err(format!("refusing to remove root-like path: {:?}", target).into());
    }

    Ok(resolved)
}

impl PackageBuilder {
    /// Create a new `PackageBuilder` with the given `Metadata`.
    pub fn new(metadata: Metadata) -> Self {
        Self {
            metadata,
            output_dir: PathBuf::from("output"),
        }
    }

    /// Load metadata from a file path and create a `PackageBuilder`.
    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Self, Box<dyn std::error::Error>> {
        let metadata = Metadata::from_file(path)?;
        Ok(Self::new(metadata))
    }

    /// Parse metadata from a string and create a `PackageBuilder` (also implements `std::str::FromStr`).
    #[allow(clippy::should_implement_trait)]
    pub fn from_str(s: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let metadata = Metadata::from_str(s)?;
        Ok(Self::new(metadata))
    }

    /// Set a custom output directory for built packages.
    pub fn output_dir<P: AsRef<Path>>(mut self, path: P) -> Self {
        self.output_dir = path.as_ref().to_path_buf();
        self
    }

    /// Reference to the parsed metadata.
    pub fn metadata(&self) -> &Metadata {
        &self.metadata
    }

    /// Mutable reference to the parsed metadata.
    pub fn metadata_mut(&mut self) -> &mut Metadata {
        &mut self.metadata
    }

    /// Unpack an archive file into the target directory.
    fn unpack_archive(filename: &str, workdir: &str) -> Result<(), Box<dyn std::error::Error>> {
        unpack_source(filename, workdir)?;
        Ok(())
    }

    /// Validate metadata and verify existing local source files without mutating the working directory.
    pub fn check(&self) -> Result<(), Box<dyn std::error::Error>> {
        self.metadata.validate()?;

        // Verify checksums of any sources that already exist locally on disk
        for (index, source) in self.metadata.sources.iter().enumerate() {
            let path = if let Some(ref mdir) = self.metadata.manifest_dir {
                let candidate = mdir.join(source);
                if candidate.exists() {
                    candidate
                } else {
                    PathBuf::from(source)
                }
            } else {
                PathBuf::from(source)
            };
            if path.exists() {
                verify_checksum(&self.metadata, path.to_str().unwrap_or(source), index)?;
            }
        }

        if let Some(ref build) = self.metadata.build {
            let platforms = [
                (PlatformTarget::Linux, build.linux.as_ref()),
                (PlatformTarget::Mac, build.mac.as_ref()),
                (PlatformTarget::Windows, build.windows.as_ref()),
                (PlatformTarget::FreeBsd, build.freebsd.as_ref()),
            ];

            for (target, cfg_opt) in platforms {
                if let Some(cfg) = cfg_opt {
                    let platform_meta = self.metadata.for_platform(target);
                    for (index, source) in cfg.sources.iter().enumerate() {
                        let path = if let Some(ref mdir) = platform_meta.manifest_dir {
                            let candidate = mdir.join(source);
                            if candidate.exists() {
                                candidate
                            } else {
                                PathBuf::from(source)
                            }
                        } else {
                            PathBuf::from(source)
                        };
                        if path.exists() {
                            verify_checksum(
                                &platform_meta,
                                path.to_str().unwrap_or(source),
                                index,
                            )?;
                        }
                    }
                }
            }
        }

        Ok(())
    }

    /// Fetch a single source, verify its checksum, and unpack into the specified workdir.
    async fn fetch_verify_and_unpack(
        meta: &Metadata,
        source: &str,
        index: usize,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let filename = clone::fetch_source_with_base(source, meta.manifest_dir.as_deref()).await?;
        verify_checksum(meta, &filename, index)?;
        Self::unpack_archive(&filename, meta.workdir())?;
        Ok(())
    }

    /// Fetch and decompress all sources specified in metadata across top-level and platform configurations.
    pub async fn fetch_and_unpack(&self) -> Result<(), Box<dyn std::error::Error>> {
        // 1. Fetch, verify, and unpack top-level sources
        for (index, source) in self.metadata.sources.iter().enumerate() {
            Self::fetch_verify_and_unpack(&self.metadata, source, index).await?;
        }

        // 2. Fetch, verify, and unpack platform-specific sources (if defined in build)
        if let Some(ref build) = self.metadata.build {
            let platforms = [
                (PlatformTarget::Linux, build.linux.as_ref()),
                (PlatformTarget::Mac, build.mac.as_ref()),
                (PlatformTarget::Windows, build.windows.as_ref()),
                (PlatformTarget::FreeBsd, build.freebsd.as_ref()),
            ];

            for (target, cfg_opt) in platforms {
                if !self.metadata.platform_enabled(target) {
                    continue;
                }
                if let Some(cfg) = cfg_opt {
                    let platform_meta = self.metadata.for_platform(target);
                    for (index, source) in cfg.sources.iter().enumerate() {
                        if self.metadata.sources.contains(source) {
                            continue;
                        }
                        Self::fetch_verify_and_unpack(&platform_meta, source, index).await?;
                    }
                }
            }
        }
        Ok(())
    }

    /// Refuse an explicit build when the platform is disabled in metadata.
    ///
    /// `build_all` skips disabled targets; a direct `--dmg`/`--msi` request
    /// must fail loudly instead of silently producing nothing.
    fn ensure_platform_enabled(
        &self,
        target: PlatformTarget,
        artifact: &str,
    ) -> Result<(), Box<dyn std::error::Error>> {
        if self.metadata.platform_enabled(target) {
            Ok(())
        } else {
            Err(format!(
                "refusing to build {artifact}: platform '{target}' is disabled in metadata ([build.{target}] enabled = false)"
            )
            .into())
        }
    }

    /// Build an Arch Linux / ALPM package (`.pkg.tar.zst`).
    pub fn alpm_package(&self) -> Result<PathBuf, Box<dyn std::error::Error>> {
        self.ensure_platform_enabled(PlatformTarget::Linux, "Arch Linux / ALPM package")?;
        let meta = self.metadata.for_platform(PlatformTarget::Linux);
        alpm_package(&meta, &self.output_dir)
    }

    /// Build a standalone AppImage (`.AppImage`).
    pub fn appimage_package(&self) -> Result<PathBuf, Box<dyn std::error::Error>> {
        self.ensure_platform_enabled(PlatformTarget::Linux, "AppImage")?;
        let meta = self.metadata.for_platform(PlatformTarget::Linux);
        appimage_package(&meta, &self.output_dir)
    }

    /// Build a Debian / Ubuntu package (`.deb`).
    pub fn deb_package(&self) -> Result<PathBuf, Box<dyn std::error::Error>> {
        self.ensure_platform_enabled(PlatformTarget::Linux, "Debian package")?;
        let meta = self.metadata.for_platform(PlatformTarget::Linux);
        deb_package(&meta, &self.output_dir)
    }

    /// Build a Fedora / RHEL package (`.rpm`).
    pub fn rpm_package(&self) -> Result<PathBuf, Box<dyn std::error::Error>> {
        self.ensure_platform_enabled(PlatformTarget::Linux, "RPM package")?;
        let meta = self.metadata.for_platform(PlatformTarget::Linux);
        rpm_package(&meta, &self.output_dir)
    }

    /// Build a Canonical Snap package (`.snap`).
    pub fn snap_package(&self) -> Result<PathBuf, Box<dyn std::error::Error>> {
        self.ensure_platform_enabled(PlatformTarget::Linux, "Snap package")?;
        let meta = self.metadata.for_platform(PlatformTarget::Linux);
        snap_package(&meta, &self.output_dir)
    }

    /// Build a Flatpak package and manifest.
    pub fn flatpak_package(&self) -> Result<PathBuf, Box<dyn std::error::Error>> {
        self.ensure_platform_enabled(PlatformTarget::Linux, "Flatpak package")?;
        let meta = self.metadata.for_platform(PlatformTarget::Linux);
        flatpak_package(&meta, &self.output_dir)
    }

    /// Build a macOS Apple Disk Image (`.dmg`).
    pub fn dmg_package(&self) -> Result<PathBuf, Box<dyn std::error::Error>> {
        self.ensure_platform_enabled(PlatformTarget::Mac, "macOS disk image")?;
        let meta = self.metadata.for_platform(PlatformTarget::Mac);
        dmg_package(&meta, &self.output_dir)
    }

    /// Build a Windows Installer package (`.msi`).
    pub fn msi_package(&self) -> Result<PathBuf, Box<dyn std::error::Error>> {
        self.ensure_platform_enabled(PlatformTarget::Windows, "Windows installer")?;
        let meta = self.metadata.for_platform(PlatformTarget::Windows);
        msi_package(&meta, &self.output_dir)
    }

    /// Build a FreeBSD binary package (`.pkg`).
    pub fn freebsd_package(&self) -> Result<PathBuf, Box<dyn std::error::Error>> {
        self.ensure_platform_enabled(PlatformTarget::FreeBsd, "FreeBSD package")?;
        let meta = self.metadata.for_platform(PlatformTarget::FreeBsd);
        freebsd_package(&meta, &self.output_dir)
    }

    /// Build an OCI image manifest (`.oci-manifest.json`).
    pub fn oci_package(&self) -> Result<PathBuf, Box<dyn std::error::Error>> {
        self.ensure_platform_enabled(PlatformTarget::Linux, "OCI manifest")?;
        let meta = self.metadata.for_platform(PlatformTarget::Linux);
        oci_package(&meta, &self.output_dir)
    }

    /// Run keygen to sign packages, produce SHA256SUMS.txt, and export release signing key.
    pub fn generate_keygen(
        &self,
        package_paths: &[PathBuf],
    ) -> Result<KeygenResults, Box<dyn std::error::Error>> {
        run_keygen(&self.metadata, &self.output_dir, package_paths)
    }

    /// Remove the unpacked work directory and any temporary build directories.
    ///
    /// Every path is resolved and confirmed to live inside the current working
    /// directory before anything is removed. `workdir` and `name` come from
    /// metadata, and a single `..` in either used to delete arbitrary
    /// directories on the host.
    pub fn clean_workdir(&self) -> Result<(), Box<dyn std::error::Error>> {
        let cwd = std::env::current_dir()?.canonicalize()?;

        let mut targets: Vec<PathBuf> = self
            .metadata
            .all_workdirs()
            .into_iter()
            .map(PathBuf::from)
            .collect();
        targets.push(PathBuf::from(&self.metadata.name));

        for suffix in &[
            ".alpm",
            ".AppDir",
            ".deb",
            ".rpm",
            ".snap-dir",
            ".flatpak-dir",
            ".dmg-dir",
            ".msi-dir",
            ".freebsd-dir",
            ".oci-rootfs",
        ] {
            targets.push(PathBuf::from(format!("{}{}", self.metadata.name, suffix)));
        }

        for target in targets {
            if !target.exists() {
                continue;
            }

            let resolved = resolve_clean_target(&cwd, &target)?;

            println!("Removing work directory: {}", target.display());
            std::fs::remove_dir_all(&resolved)?;
        }

        Ok(())
    }

    /// Fetch sources, verify checksums, unpack, and build all enabled package formats.
    pub async fn build_all(&self) -> Result<BuildResults, Box<dyn std::error::Error>> {
        self.fetch_and_unpack().await?;

        let linux = self.metadata.platform_enabled(PlatformTarget::Linux);
        let mac = self.metadata.platform_enabled(PlatformTarget::Mac);
        let windows = self.metadata.platform_enabled(PlatformTarget::Windows);
        let freebsd_enabled = self.metadata.platform_enabled(PlatformTarget::FreeBsd);

        for (target, enabled) in [
            (PlatformTarget::Linux, linux),
            (PlatformTarget::Mac, mac),
            (PlatformTarget::Windows, windows),
            (PlatformTarget::FreeBsd, freebsd_enabled),
        ] {
            if !enabled {
                println!("Skipping platform '{target}': [build.{target}] enabled = false");
            }
        }

        let alpm = if linux {
            Some(self.alpm_package()?)
        } else {
            None
        };
        let appimage = if linux {
            Some(self.appimage_package()?)
        } else {
            None
        };
        let deb = if linux {
            Some(self.deb_package()?)
        } else {
            None
        };
        let rpm = if linux {
            Some(self.rpm_package()?)
        } else {
            None
        };
        let snap = if linux {
            Some(self.snap_package()?)
        } else {
            None
        };
        let flatpak = if linux {
            Some(self.flatpak_package()?)
        } else {
            None
        };
        let dmg = if mac { Some(self.dmg_package()?) } else { None };
        let msi = if windows {
            Some(self.msi_package()?)
        } else {
            None
        };
        let freebsd = if freebsd_enabled {
            Some(self.freebsd_package()?)
        } else {
            None
        };
        let oci = if linux {
            Some(self.oci_package()?)
        } else {
            None
        };

        let keygen = if self.metadata.keygen {
            let mut pkgs = Vec::new();
            if let Some(ref p) = alpm {
                pkgs.push(p.clone());
            }
            if let Some(ref p) = appimage {
                pkgs.push(p.clone());
            }
            if let Some(ref p) = deb {
                pkgs.push(p.clone());
            }
            if let Some(ref p) = rpm {
                pkgs.push(p.clone());
            }
            if let Some(ref p) = snap {
                pkgs.push(p.clone());
            }
            if let Some(ref p) = flatpak {
                pkgs.push(p.clone());
            }
            if let Some(ref p) = dmg {
                pkgs.push(p.clone());
            }
            if let Some(ref p) = msi {
                pkgs.push(p.clone());
            }
            if let Some(ref p) = freebsd {
                pkgs.push(p.clone());
            }
            if let Some(ref p) = oci {
                pkgs.push(p.clone());
            }
            Some(self.generate_keygen(&pkgs)?)
        } else {
            None
        };

        if self.metadata.clean_workdir {
            self.clean_workdir()?;
        }

        Ok(BuildResults {
            alpm,
            appimage,
            deb,
            rpm,
            snap,
            flatpak,
            dmg,
            msi,
            freebsd,
            oci,
            keygen,
        })
    }

    /// Return preview of what would be packaged and where (dry-run mode).
    pub fn dry_run(&self) -> Vec<String> {
        let mut lines = Vec::new();
        lines.push(format!(
            "Dry run for {} v{}:",
            self.metadata.name, self.metadata.version
        ));
        lines.push(format!("  Output directory: {}", self.output_dir.display()));
        lines.push("  Package instructions:".to_string());
        for instr in &self.metadata.package_instructions {
            lines.push(format!("    [install] {}", instr));
        }
        lines
    }

    /// Build selected package formats based on the provided selection.
    pub async fn build_selected(
        &self,
        selection: &PlatformSelection,
    ) -> Result<Vec<(&'static str, PathBuf)>, Box<dyn std::error::Error>> {
        let build_all = selection.is_all();
        let linux_enabled = self.metadata.platform_enabled(PlatformTarget::Linux);
        let mac_enabled = self.metadata.platform_enabled(PlatformTarget::Mac);
        let windows_enabled = self.metadata.platform_enabled(PlatformTarget::Windows);
        let freebsd_enabled = self.metadata.platform_enabled(PlatformTarget::FreeBsd);

        if build_all {
            for (target, enabled) in [
                (PlatformTarget::Linux, linux_enabled),
                (PlatformTarget::Mac, mac_enabled),
                (PlatformTarget::Windows, windows_enabled),
                (PlatformTarget::FreeBsd, freebsd_enabled),
            ] {
                if !enabled {
                    println!("Skipping platform '{target}': [build.{target}] enabled = false");
                }
            }
        }

        let build_deb = (build_all && linux_enabled) || selection.deb;
        let build_appimage = (build_all && linux_enabled) || selection.appimage;
        let build_rpm = (build_all && linux_enabled) || selection.rpm;
        let build_alpm = (build_all && linux_enabled) || selection.alpm;
        let build_snap = (build_all && linux_enabled) || selection.snap;
        let build_flatpak = (build_all && linux_enabled) || selection.flatpak;
        let build_dmg = (build_all && mac_enabled) || selection.dmg;
        let build_msi = (build_all && windows_enabled) || selection.msi;
        let build_freebsd = (build_all && freebsd_enabled) || selection.freebsd;
        let build_oci = (build_all && linux_enabled) || selection.oci;

        println!(
            "Building packages for {} v{}...",
            self.metadata.name, self.metadata.version
        );

        self.fetch_and_unpack().await?;

        let mut generated = Vec::new();
        if build_alpm {
            let p = self.alpm_package()?;
            generated.push(("Arch / ALPM", p));
        }
        if build_appimage {
            let p = self.appimage_package()?;
            generated.push(("AppImage", p));
        }
        if build_deb {
            let p = self.deb_package()?;
            generated.push(("Debian", p));
        }
        if build_rpm {
            let p = self.rpm_package()?;
            generated.push(("RPM", p));
        }
        if build_snap {
            let p = self.snap_package()?;
            generated.push(("Snap", p));
        }
        if build_flatpak {
            let p = self.flatpak_package()?;
            generated.push(("Flatpak", p));
        }
        if build_dmg {
            let p = self.dmg_package()?;
            generated.push(("macOS DMG", p));
        }
        if build_msi {
            let p = self.msi_package()?;
            generated.push(("Windows MSI", p));
        }
        if build_freebsd {
            let p = self.freebsd_package()?;
            generated.push(("FreeBSD PKG", p));
        }
        if build_oci {
            let p = self.oci_package()?;
            generated.push(("OCI Manifest", p));
        }

        Ok(generated)
    }
}

impl std::str::FromStr for PackageBuilder {
    type Err = Box<dyn std::error::Error>;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let metadata = Metadata::from_str(s)?;
        Ok(Self::new(metadata))
    }
}

/// Convenience function to fetch and unpack sources from `./metadata.toml`.
pub async fn build_package() -> Result<(), Box<dyn std::error::Error>> {
    let builder = PackageBuilder::from_file("metadata.toml")?;
    builder.fetch_and_unpack().await
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn test_platform_enabled_defaults_true() {
        let metadata = Metadata::default();
        for target in [
            PlatformTarget::Linux,
            PlatformTarget::Mac,
            PlatformTarget::Windows,
            PlatformTarget::FreeBsd,
        ] {
            assert!(
                metadata.platform_enabled(target),
                "{target} must be enabled when no build table is present"
            );
        }
    }

    #[test]
    fn test_platform_disabled_is_reported() {
        let metadata = Metadata {
            build: Some(BuildPlatforms {
                windows: Some(PlatformBuildConfig {
                    enabled: false,
                    ..Default::default()
                }),
                ..Default::default()
            }),
            ..Default::default()
        };
        assert!(!metadata.platform_enabled(PlatformTarget::Windows));
        assert!(metadata.platform_enabled(PlatformTarget::Linux));
    }

    #[test]
    fn test_disabled_platform_explicit_build_errors() {
        let metadata = Metadata {
            name: "disabled-mac".to_string(),
            build: Some(BuildPlatforms {
                mac: Some(PlatformBuildConfig {
                    enabled: false,
                    ..Default::default()
                }),
                ..Default::default()
            }),
            ..Default::default()
        };
        let builder = PackageBuilder::new(metadata);
        let err = builder
            .dmg_package()
            .expect_err("an explicit build on a disabled platform must fail");
        let message = err.to_string();
        assert!(
            message.contains("disabled in metadata"),
            "unexpected error: {message}"
        );
        assert!(
            message.contains("[build.mac]"),
            "unexpected error: {message}"
        );
    }

    #[test]
    fn test_build_results_serde_json() {
        let results = BuildResults {
            alpm: Some(PathBuf::from("dist/app_1.0_x86_64.pkg.tar.zst")),
            appimage: Some(PathBuf::from("dist/app_1.0_x86_64.AppImage")),
            deb: Some(PathBuf::from("dist/app_1.0_amd64.deb")),
            rpm: Some(PathBuf::from("dist/app-1.0-1.x86_64.rpm")),
            snap: Some(PathBuf::from("dist/app_1.0_amd64.snap")),
            flatpak: Some(PathBuf::from("dist/app_1.0_x86_64.flatpak")),
            dmg: Some(PathBuf::from("dist/app_1.0_x86_64.dmg")),
            msi: Some(PathBuf::from("dist/app_1.0_x64.msi")),
            freebsd: Some(PathBuf::from("dist/app-1.0_1_amd64.pkg")),
            oci: Some(PathBuf::from("dist/app-1.0-linux-x86_64.oci-manifest.json")),
            keygen: None,
        };

        let json = results
            .to_json()
            .expect("Should serialize BuildResults to JSON");
        assert!(json.contains("app_1.0_amd64.snap"));
        assert!(json.contains("app_1.0_x86_64.flatpak"));
        assert!(json.contains("app_1.0_x86_64.dmg"));
        assert!(json.contains("app_1.0_x64.msi"));
        assert!(json.contains("app-1.0_1_amd64.pkg"));
        assert!(json.contains("app-1.0-linux-x86_64.oci-manifest.json"));

        let deserialized = BuildResults::from_json(&json).expect("Should deserialize BuildResults");
        assert_eq!(deserialized.snap, results.snap);
        assert_eq!(deserialized.flatpak, results.flatpak);
        assert_eq!(deserialized.dmg, results.dmg);
        assert_eq!(deserialized.msi, results.msi);
        assert_eq!(deserialized.freebsd, results.freebsd);
        assert_eq!(deserialized.oci, results.oci);
        assert_eq!(deserialized.deb, results.deb);
    }

    #[test]
    fn test_build_results_serde_yaml() {
        let results = BuildResults {
            alpm: Some(PathBuf::from("dist/app_1.0_x86_64.pkg.tar.zst")),
            appimage: Some(PathBuf::from("dist/app_1.0_x86_64.AppImage")),
            deb: Some(PathBuf::from("dist/app_1.0_amd64.deb")),
            rpm: Some(PathBuf::from("dist/app-1.0-1.x86_64.rpm")),
            snap: Some(PathBuf::from("dist/app_1.0_amd64.snap")),
            flatpak: Some(PathBuf::from("dist/app_1.0_x86_64.flatpak")),
            dmg: Some(PathBuf::from("dist/app_1.0_x86_64.dmg")),
            msi: Some(PathBuf::from("dist/app_1.0_x64.msi")),
            freebsd: Some(PathBuf::from("dist/app-1.0_1_amd64.pkg")),
            oci: Some(PathBuf::from("dist/app-1.0-linux-x86_64.oci-manifest.json")),
            keygen: None,
        };

        let yaml = results
            .to_yaml()
            .expect("Should serialize BuildResults to YAML");
        assert!(yaml.contains("snap: dist/app_1.0_amd64.snap"));
        assert!(yaml.contains("flatpak: dist/app_1.0_x86_64.flatpak"));
        assert!(yaml.contains("dmg: dist/app_1.0_x86_64.dmg"));
        assert!(yaml.contains("msi: dist/app_1.0_x64.msi"));
        assert!(yaml.contains("freebsd: dist/app-1.0_1_amd64.pkg"));

        let deserialized =
            BuildResults::from_yaml(&yaml).expect("Should deserialize BuildResults from YAML");
        assert_eq!(deserialized.snap, results.snap);
        assert_eq!(deserialized.flatpak, results.flatpak);
        assert_eq!(deserialized.dmg, results.dmg);
        assert_eq!(deserialized.msi, results.msi);
        assert_eq!(deserialized.freebsd, results.freebsd);
        assert_eq!(deserialized.deb, results.deb);
    }

    #[test]
    fn test_build_results_serde_toml() {
        let results = BuildResults {
            alpm: Some(PathBuf::from("dist/app_1.0_x86_64.pkg.tar.zst")),
            appimage: Some(PathBuf::from("dist/app_1.0_x86_64.AppImage")),
            deb: Some(PathBuf::from("dist/app_1.0_amd64.deb")),
            rpm: Some(PathBuf::from("dist/app-1.0-1.x86_64.rpm")),
            snap: Some(PathBuf::from("dist/app_1.0_amd64.snap")),
            flatpak: Some(PathBuf::from("dist/app_1.0_x86_64.flatpak")),
            dmg: Some(PathBuf::from("dist/app_1.0_x86_64.dmg")),
            msi: Some(PathBuf::from("dist/app_1.0_x64.msi")),
            freebsd: Some(PathBuf::from("dist/app-1.0_1_amd64.pkg")),
            oci: Some(PathBuf::from("dist/app-1.0-linux-x86_64.oci-manifest.json")),
            keygen: None,
        };

        let toml_str = results
            .to_toml()
            .expect("Should serialize BuildResults to TOML");
        assert!(toml_str.contains("app_1.0_amd64.snap"));
        assert!(toml_str.contains("app_1.0_x86_64.flatpak"));
        assert!(toml_str.contains("app_1.0_x86_64.dmg"));
        assert!(toml_str.contains("app_1.0_x64.msi"));

        let deserialized =
            BuildResults::from_toml(&toml_str).expect("Should deserialize BuildResults from TOML");
        assert_eq!(deserialized.snap, results.snap);
        assert_eq!(deserialized.flatpak, results.flatpak);
        assert_eq!(deserialized.dmg, results.dmg);
        assert_eq!(deserialized.msi, results.msi);
        assert_eq!(deserialized.freebsd, results.freebsd);
        assert_eq!(deserialized.deb, results.deb);
    }

    #[test]
    fn test_cleanup_refuses_paths_outside_cwd() {
        let root = std::env::temp_dir().join(format!("twincan-clean-{}", std::process::id()));
        let inside = root.join("work");
        let outside = root
            .parent()
            .unwrap()
            .join(format!("twincan-outside-{}", std::process::id()));

        let _ = std::fs::remove_dir_all(&root);
        let _ = std::fs::remove_dir_all(&outside);
        std::fs::create_dir_all(&inside).unwrap();
        std::fs::create_dir_all(&outside).unwrap();

        let cwd = root.canonicalize().unwrap();

        // Inside is allowed and returned canonically.
        let ok = resolve_clean_target(&cwd, &inside).expect("inside path is allowed");
        assert!(ok.starts_with(&cwd));

        // Outside is refused.
        let err = resolve_clean_target(&cwd, &outside).expect_err("outside path must be refused");
        assert!(err.to_string().contains("not inside the working directory"));
        assert!(outside.exists(), "refused path must not be touched");

        // The working directory itself is refused.
        assert!(resolve_clean_target(&cwd, &cwd).is_err());

        let _ = std::fs::remove_dir_all(&root);
        let _ = std::fs::remove_dir_all(&outside);
    }

    #[test]
    fn test_check_is_read_only() {
        let tmp = std::env::temp_dir().join(format!(
            "test_check_ro_{}",
            uuid::Uuid::new_v4().hyphenated()
        ));
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(&tmp).unwrap();

        let metadata = Metadata {
            name: "checktest".to_string(),
            version: "1.0.0".to_string(),
            release: "1".to_string(),
            maintainer: "Test <t@example.com>".to_string(),
            description: "Check is read-only test".to_string(),
            url: "https://example.com/checktest".to_string(),
            license: "MIT".to_string(),
            arch: vec!["x86_64".to_string()],
            sources: vec!["https://example.com/checktest.tar.gz".to_string()],
            sha256sums: vec![
                "a31c61e733ae21eaa645de0e870c03d4fdb812c7e5a0a5666ef229ceba7fa8f4".to_string(),
            ],
            ..Default::default()
        };

        let builder = PackageBuilder::new(metadata).output_dir(&tmp);

        // Record directory contents before check
        let entries_before: Vec<_> = std::fs::read_dir(&tmp).unwrap().collect();
        assert!(entries_before.is_empty(), "temp dir should start empty");

        builder
            .check()
            .expect("check() should validate successfully");

        // Verify directory contents after check are still empty (no downloads, no unpacked workdirs)
        let entries_after: Vec<_> = std::fs::read_dir(&tmp).unwrap().collect();
        assert!(
            entries_after.is_empty(),
            "check() must not download or create files"
        );

        let _ = std::fs::remove_dir_all(&tmp);
    }
}

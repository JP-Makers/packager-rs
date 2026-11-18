# Changelog

All notable changes to `packager-rs` (application `package-builder`) will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-11-18

Initial release of `packager-rs` and `package-builder`: a unified, multi-format package bundler written in pure Rust.

### Added
- **Multi-distro Linux Packaging:**
  - Debian / Ubuntu (`.deb`): standard `ar` archive with gzip-compressed `control` and `data`, deterministic mtimes, and automatic desktop/icon scriptlets.
  - Arch Linux (`.pkg.tar.zst`): pure-Rust ALPM packaging with `.PKGINFO`, `.BUILDINFO` v2, and normalized `.MTREE` (Linux-only native builder; stubs on non-Linux).
  - Fedora / RHEL (`.rpm`): pure-Rust RPM v4 package generation with parsed dependency version operators (`>=`, `<=`, `=`, `>`, `<`), automatic `%post`/`%postun` scriptlets, and compressed payloads.
  - AppImage (`.AppImage`): standalone portable bundles with embedded type-2 runtimes for `x86_64`, `aarch64`, `armhf`, and `i686`, SquashFS filesystems, `.DirIcon` extraction, and dynamic multiarch environment exports in `AppRun`.
  - Canonical Snap (`.snap`): SquashFS container packaging with strict `meta/snap.yaml`, configurable plugs with secure minimal defaults, and deterministic icon and desktop selection.
  - Flatpak: application manifests (`.json` / `.yaml`) and `.flatpak.tar.gz` archive generation for Flathub or `flatpak-builder`.
  - OCI Container: pure-Rust OCI Image Layout specification v1 compliance (`oci-layout`, `index.json`, `blobs/sha256/*`), with absolute entrypoint enforcement and concrete architecture validation.
- **Cross-Platform Formats:**
  - Windows Installer (`.msi`): pure-Rust Compound File Binary (CFB) and Microsoft Cabinet (CAB) database generator with MSZIP (RFC 1951 Deflate + `CK` signature) compression, strict numeric `msi_version` validation, and verified table generation.
  - macOS Disk Image (`.dmg`): pure-Rust UDIF DMG image generation with Joliet/ISO-9660 filesystem, Mach-O architecture verification against declared targets, and `.app` bundle structure validation (`Contents/Info.plist`, `Contents/MacOS/<exe>`, `Contents/PkgInfo`).
  - FreeBSD Package (`.pkg`): pure-Rust Zstandard-compressed tarball packaging with UCL/JSON `+MANIFEST`.
- **Security & Reproducibility:**
  - Deterministic builds powered by `SOURCE_DATE_EPOCH` and `crate::repro` timestamps.
  - Path traversal protections: strict root fences (`resolve_clean_target`), destination path canonicalization preventing directory escapes, symlink rejection, and refusal to delete root or outside directories.
  - Passphrase-protected Ed25519 signing keys and OpenPGP armored signatures (`.asc` / `.sig`).
  - Strict checksum verification supporting SHA-256, SHA-512, SHA-1, and MD5, rejecting bypasses (`SKIP`).
  - Correct `zsync` record format with `Hash-Lengths: 2,4,5` (4 bytes rsum + 5 bytes MD5) and zero-padded block calculation.
- **Developer Experience & Library API:**
  - High-level `PackageBuilder` API, `PlatformSelection`, and `BuildResults` serialization (JSON, YAML via `serde_yml`, TOML).
  - Rich typed errors with `PackagerError` replacing unstructured `Box<dyn Error>` custom errors.
  - Manifest-relative local source resolution via `manifest_dir`.
  - CLI flags: `--check` (dry source/syntax validation), `--dry-run` / `--list`, `--clean`, `--export-home`, and individual target format switches.
- **Continuous Integration:**
  - GitHub Actions matrix workflow covering format check (`cargo fmt`), strict linting (`cargo clippy -- -D warnings`), build, and comprehensive unit tests.
  - Real installation and removal testing in containerized Linux environments (`dpkg`, `rpm`, `pacman`).
  - Real installer verification on Windows (`msiexec /i`, upgrade, uninstall) and macOS (`hdiutil verify`, attach, execution).


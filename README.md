# packager-rs (package-builder)

[![Rust Version](https://img.shields.io/badge/rust-1.85%2B%20%282024%20edition%29-orange.svg)](https://www.rust-lang.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Tests](https://img.shields.io/badge/tests-83%20passed%20%7C%200%20failed-brightgreen.svg)](#development)
[![Platforms](https://img.shields.io/badge/platforms-Linux%20%7C%20macOS%20%7C%20Windows%20%7C%20FreeBSD-blueviolet.svg)](#supported-formats)
[![Security](https://img.shields.io/badge/security-Ed25519%20Signed%20%7C%20Sandbox--Fenced-success.svg)](#security--integrity)

A fast, pure-Rust multi-format packaging engine and library. Package CLI utilities, GUI applications, and background services for **Linux, macOS, Windows, FreeBSD, and OCI containers** from a single declarative manifest—**without needing external tools** like `dpkg-deb`, `rpmbuild`, `makepkg`, `appimagetool`, or `msitools`.

---

## Supported Formats

| Format | Extension | Target OS | Status | Build Engine |
| :--- | :--- | :--- | :---: | :--- |
| **Debian / Ubuntu** | `.deb` | Linux | **Production** | Pure Rust (`ar` + gzip `control`/`data`, auto desktop/icon scripts) |
| **Arch Linux (ALPM)**| `.pkg.tar.zst` | Linux | **Production** | Pure Rust (`alpm-package`, `.PKGINFO`, `.BUILDINFO` v2, `.MTREE`) |
| **Fedora / RHEL / SUSE** | `.rpm` | Linux | **Production** | Pure Rust (RPM v4, gzip payload, auto `%post`/`%postun` scriptlets) |
| **Standalone Portable**| `.AppImage` | Linux | **Production** | Pure Rust (embedded ELF runtime + SquashFS payload + `.DirIcon`) |
| **FreeBSD Package** | `.pkg` | FreeBSD | **Production** | Pure Rust (Zstandard tar archive + UCL/JSON `+MANIFEST`) |
| **Cryptographic Signer**| `.asc` / `.sig` | All | **Production** | Pure Rust Ed25519 OpenPGP, `zsync` deltas, and `SHA256SUMS.txt` |
| **Canonical Snap** | `.snap` | Linux | **Sideload / Store** | Pure Rust (SquashFS + `meta/snap.yaml` with hardware plugs) |
| **OCI Container** | `.json` / tarballs | Universal | **Spec v1** | Pure Rust container manifest, config blob, and rootfs layers |
| **Flatpak** | `.flatpak` / `.json` | Linux | **Manifest** | Valid manifest for `flatpak-builder` and Flathub + staging tar |
| **Windows Installer** | `.msi` / `.exe` | Windows | **Experimental** | Pure Rust CFB/CAB database (MSI) & standalone PE NSIS stub |
| **macOS Disk Image** | `.dmg` | macOS | **Experimental** | Pure Rust UDIF container (Gatekeeper requires macOS `codesign`) |

---

## Installation

```bash
# Install package-builder CLI
cargo install --path .

# Or build the release binary locally
cargo build --release
# Output binary: target/release/package-builder
```

---

## CLI Quickstart

```bash
# 1. Build all formats defined in metadata.toml
package-builder

# 2. Build only specific formats
package-builder --deb --appimage --rpm

# 3. Build cross-platform packages (Windows MSI/NSIS, macOS DMG, FreeBSD PKG)
package-builder --msi --nsis --dmg --freebsd -o dist/

# 4. Verify manifest syntax and test source checksums without building
package-builder --check

# 5. Build packages and sign releases with Ed25519 OpenPGP keys + SHA256SUMS.txt
package-builder -d -a -r -k -o dist/

# 6. Clean temporary unpacked sources after building
package-builder --all --clean
```

### CLI Flag Reference

| Flag | Description |
| :--- | :--- |
| `-m, --metadata <FILE>` | Path to manifest specification [default: `metadata.toml`] |
| `-o, --output <DIR>` | Output directory for built packages [default: `output`] |
| `-d, --deb` | Build Debian / Ubuntu (`.deb`) |
| `-a, --appimage` | Build standalone AppImage (`.AppImage`) |
| `-r, --rpm` | Build Fedora / RHEL (`.rpm`) |
| `-p, --alpm` | Build Arch Linux / Pacman (`.pkg.tar.zst`) |
| `-s, --snap` | Build Canonical Snap (`.snap`) |
| `-f, --flatpak` | Build Flatpak package and manifest |
| `-g, --dmg` | Build Apple Disk Image (`.dmg`) for macOS |
| `-w, --msi` | Build Windows Installer (`.msi`) |
| `-n, --nsis` | Build Windows NSIS installer (`.exe`) |
| `-b, --freebsd` | Build FreeBSD package (`.pkg`) |
| `--oci` | Build OCI container image manifest and layers |
| `-k, --keygen` | Generate Ed25519 release keys, detached signatures, and `SHA256SUMS.txt` |
| `--all` | Build all formats (default when no format flag is specified) |
| `-c, --check` | Validate manifest syntax and fetch/verify sources without packaging |
| `--clean` | Remove extracted sources after build completion |
| `--export-home` | Move completed packages to `~/package-builder` |

---

## Rust Library API

Add `package-builder` to your `Cargo.toml`:

```toml
[dependencies]
package-builder = { git = "https://github.com/JP-Makers/packager-rs.git" }
tokio = { version = "1.54.1", features = ["full"] }
```

### Programmatic Build Example

```rust
use package_builder::PackageBuilder;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 1. Initialize builder from manifest file
    let builder = PackageBuilder::from_file("metadata.toml")?
        .output_dir("dist");

    // 2. Fetch remote sources and verify cryptographic checksums
    builder.fetch_and_unpack().await?;

    // 3. Build specific packages
    let deb = builder.deb_package()?;
    let appimage = builder.appimage_package()?;
    let rpm = builder.rpm_package()?;

    println!("Generated: {}, {}, {}", deb.display(), appimage.display(), rpm.display());

    // 4. Optionally sign built packages with Ed25519 keys
    builder.generate_keygen(&[deb, appimage, rpm])?;

    // 5. Clean up temporary unpack directories
    builder.clean_workdir()?;

    Ok(())
}
```

---

## Minimal Manifest (`metadata.toml`)

Create a `metadata.toml` file in your project root:

```toml
name = "myapp"
version = "1.0.0"
release = "1"
maintainer = "Developer Name"
email = "dev@example.com"
description = "Fast, universal cross-platform application."
url = "https://example.com/myapp"
license = "MIT"
arch = ["x86_64"]

# Upstream tarball/zip and strict 64-hex SHA-256 checksum
sources = [
    "https://github.com/example/myapp/releases/download/v1.0.0/myapp.tar.gz",
]
sha256sums = [
    "a31c61e733ae21eaa645de0e870c03d4fdb812c7e5a0a5666ef229ceba7fa8f4",
]

# Runtime dependencies per distribution
deb_depends = ["libc6 (>= 2.31)"]
rpm_depends = ["glibc >= 2.31"]
alpm_depends = ["glibc"]

# AppImage configuration
appimage_exec = "/usr/bin/myapp"
appimage_icon = ["install -m644 \"assets/myapp.svg\" to /"]
appimage_desktop = ["install -m644 \"assets/myapp.desktop\" to /"]

# Package filesystem layout
package = [
    "install -m755 \"bin/myapp\" to /usr/bin/",
    "install -m644 \"assets/myapp.desktop\" to /usr/share/applications/",
    "install -m644 \"assets/myapp.svg\" to /usr/share/icons/hicolor/scalable/apps/",
    "install -m644 \"LICENSE\" to /usr/share/licenses/myapp/",
    "install -m644 \"local:config/default.toml\" to /etc/myapp/config.toml",
]
```

### Installation Directive Syntax

```text
install -m<mode> "[local:]<source_file>" to "<destination_path>"
```
- `-m<mode>`: Octal permissions (`755` for executables, `644` for configs/icons).
- `"local:<path>"`: Resolves `<path>` directly from the local repo instead of the downloaded tarball.
- Trailing `/`: If destination ends in `/`, the original source filename is preserved inside that directory.

---

## Security & Integrity

- **Strict Cryptographic Integrity**: SHA-256 checksums are strictly validated against 64-character hexadecimal digests. Bypasses (e.g. `"SKIP"` or empty arrays) are rejected with hard errors.
- **Supply Chain Signing**: Automated Ed25519 OpenPGP key generation (`pgp`, `ed25519`), binary `.sig` signatures for Arch ALPM, armored `.asc` signatures, and signed `SHA256SUMS.txt` catalogs with post-sign validation.
- **Filesystem Traversal Defense**: Package destinations reject path traversal (`..`), Windows drive prefixes (`C:`), and UNC shares. Cleanups strictly refuse paths outside the current working directory.
- **Symlink Exfiltration Prevention**: Inspects files using `fs::symlink_metadata` to block exfiltration of host secrets.
- **Network Boundaries**: 15s connection timeouts, 300s transfer limits, and 4 GiB maximum download limits to prevent DoS.

---

## Development

```bash
# Run tests
cargo test

# Run linter
cargo clippy --all-targets -- -D warnings

# Format check
cargo fmt --all -- --check
```

---

## License

This project is licensed under the [MIT License](LICENSE).

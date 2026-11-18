use clap::Parser;
use packager_rs::{PackageBuilder, PlatformSelection};
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Parser, Debug)]
#[command(
    name = "package-builder",
    version,
    about = "Unified, multi-format package bundler (Debian, AppImage, RPM, Arch Linux, Snap, Flatpak, macOS DMG, Windows MSI, FreeBSD PKG)"
)]
struct Cli {
    /// Path to the metadata file
    #[arg(short = 'm', long, default_value = "metadata.toml")]
    metadata: PathBuf,

    /// Output directory for generated packages
    #[arg(short = 'o', long, default_value = "output")]
    output: PathBuf,

    /// Build Debian / Ubuntu (.deb) package
    #[arg(short = 'd', long)]
    deb: bool,

    /// Build standalone AppImage (.AppImage) bundle
    #[arg(short = 'a', long)]
    appimage: bool,

    /// Build Fedora / RHEL (.rpm) package
    #[arg(short = 'r', long)]
    rpm: bool,

    /// Build Arch Linux / Pacman (.pkg.tar.zst) package
    #[arg(short = 'p', long)]
    alpm: bool,

    /// Build Canonical Snap (.snap) package
    #[arg(short = 's', long)]
    snap: bool,

    /// Build Flatpak package and manifest
    #[arg(short = 'f', long)]
    flatpak: bool,

    /// Build Apple Disk Image (.dmg) for macOS
    #[arg(short = 'g', long)]
    dmg: bool,

    /// Build Windows Installer (.msi) package
    #[arg(short = 'w', long)]
    msi: bool,

    /// Build FreeBSD package (.pkg)
    #[arg(short = 'b', long)]
    freebsd: bool,

    /// Build OCI container image manifest (.oci-manifest.json)
    #[arg(long)]
    oci: bool,

    /// Generate OpenPGP release signing keys, signatures (.asc / .sig), AppImage delta control (.zsync), and SHA256SUMS.txt
    #[arg(short = 'k', long)]
    keygen: bool,

    /// Build all package formats (default when no specific format flag is given)
    #[arg(long)]
    all: bool,

    /// Validate manifest syntax and verify local sources without mutating work tree
    #[arg(short = 'c', long)]
    check: bool,

    /// Preview package instructions and layout without generating package artifacts
    #[arg(long, visible_alias = "list")]
    dry_run: bool,

    /// Move finished packages to ~/package-builder after build
    #[arg(long)]
    export_home: bool,

    /// Clean working directory (extracted sources) after build completes (can also be set via `clean_workdir: true` in metadata)
    #[arg(long, visible_alias = "clean-workdir")]
    clean: bool,
}

fn move_directory(source: &Path, destination: &Path) -> Result<(), Box<dyn std::error::Error>> {
    if !source.exists() {
        return Ok(());
    }

    // Try atomic rename first (works on the same filesystem)
    if fs::rename(source, destination).is_ok() {
        return Ok(());
    }

    // Fallback: cross-device or non-empty target directory (copy + delete source)
    fs::create_dir_all(destination)?;
    for entry in walkdir::WalkDir::new(source) {
        let entry = entry?;
        let rel_path = entry.path().strip_prefix(source)?;
        let target_path = destination.join(rel_path);

        if entry.file_type().is_dir() {
            fs::create_dir_all(&target_path)?;
        } else if entry.file_type().is_file() {
            fs::copy(entry.path(), &target_path)?;
        }
    }
    fs::remove_dir_all(source)?;
    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    let metadata_path = cli.metadata;

    println!("Loading metadata from: {}", metadata_path.display());
    let builder = PackageBuilder::from_file(&metadata_path)?.output_dir(&cli.output);

    // If check flag is provided, validate metadata and existing local sources without mutating work tree
    if cli.check {
        println!(
            "Validating metadata and verifying local sources for {} v{}...",
            builder.metadata.name, builder.metadata.version
        );
        builder.check()?;
        println!("Metadata and local sources verified successfully!");
        return Ok(());
    }

    if cli.dry_run {
        for line in builder.dry_run() {
            println!("{}", line);
        }
        return Ok(());
    }

    let selection = PlatformSelection {
        all: cli.all,
        deb: cli.deb,
        appimage: cli.appimage,
        rpm: cli.rpm,
        alpm: cli.alpm,
        snap: cli.snap,
        flatpak: cli.flatpak,
        dmg: cli.dmg,
        msi: cli.msi,
        freebsd: cli.freebsd,
        oci: cli.oci,
    };

    let generated = builder.build_selected(&selection).await?;

    println!("\n=== Generated Packages ===");
    for (name, path) in &generated {
        println!("  {:<12}: {}", name, path.display());
    }

    // Keygen & release signing if requested via CLI flag or metadata
    if cli.keygen || builder.metadata.keygen {
        let pkg_paths: Vec<PathBuf> = generated.iter().map(|(_, p)| p.clone()).collect();
        let _ = builder.generate_keygen(&pkg_paths)?;
    }

    // Clean work directory if requested via CLI flag or metadata
    if cli.clean || builder.metadata.clean_workdir {
        builder.clean_workdir()?;
    }

    // Optionally export to ~/package-builder if requested
    if cli.export_home {
        if let Some(home) = dirs::home_dir() {
            let destination = home.join("package-builder");
            if let Some(parent) = destination.parent() {
                fs::create_dir_all(parent)?;
            }
            move_directory(&cli.output, &destination)?;
            println!("\nPackages moved to: {:?}", destination);
        } else {
            println!("\nPackages located in: {:?}", cli.output);
        }
    } else {
        println!("\nPackages located in: {:?}", cli.output);
    }

    Ok(())
}

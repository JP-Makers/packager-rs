use crate::metadata::Metadata;
use ed25519::Signature as Ed25519Signature;
use md5::{Digest, Md5};
use pgp::composed::{
    ArmorOptions, Deserializable, DetachedSignature, SignedKeyDetails, SignedPublicKey,
    SignedSecretKey,
};
use pgp::crypto::hash::HashAlgorithm;
use pgp::crypto::public_key::PublicKeyAlgorithm;
use pgp::packet::{
    KeyFlags, PacketTrait, PubKeyInner, PublicKey, SecretKey, SignatureConfig, SignatureType,
    Subpacket, SubpacketData, UserId,
};
use pgp::ser::Serialize;
use pgp::types::{KeyDetails, KeyVersion, Password, PlainSecretParams, PublicParams, SecretParams, SignedUser, Timestamp};
use serde::{Deserialize, Serialize as SerdeSerialize};
use sha1::Sha1;
use sha2::Sha256;
use std::fs;
use std::io::Cursor;
use std::path::{Path, PathBuf};

/// Results of the keygen signing process.
#[derive(Debug, Clone, Default, PartialEq, Eq, SerdeSerialize, Deserialize)]
pub struct KeygenResults {
    pub public_key: PathBuf,
    pub sha256sums: PathBuf,
    pub sha256sums_sig: PathBuf,
    pub signatures: Vec<PathBuf>,
}

/// Generates a valid OpenPGP Ed25519 keypair dynamically with a certified User ID.
///
/// Randomness comes from the OS and failure is fatal. The previous fallback
/// derived the seed from `SystemTime` + `user_id`, which is predictable.
pub fn generate_ed25519_keypair(
    user_id: &str,
) -> Result<(SignedSecretKey, SignedPublicKey), Box<dyn std::error::Error>> {
    let mut seed = [0u8; 32];

    #[cfg(unix)]
    {
        use std::io::Read;
        let mut f = fs::File::open("/dev/urandom")
            .map_err(|e| format!("cannot open /dev/urandom for key generation: {e}"))?;
        f.read_exact(&mut seed)
            .map_err(|e| format!("cannot read 32 random bytes from /dev/urandom: {e}"))?;
    }

    #[cfg(not(unix))]
    {
        getrandom::fill(&mut seed).map_err(|e| format!("secure RNG unavailable: {e}"))?;
    }

    let secret = pgp::crypto::ed25519::SecretKey::try_from_bytes(
        seed,
        pgp::crypto::ed25519::Mode::EdDSALegacy,
    )?;
    let public_params = PublicParams::EdDSALegacy((&secret).into());
    let secret_params = PlainSecretParams::EdDSALegacy(
        pgp::crypto::eddsa_legacy::SecretKey::Ed25519(secret),
    );

    let now = Timestamp::now();
    let pub_key_inner = PubKeyInner::new(
        KeyVersion::V4,
        PublicKeyAlgorithm::EdDSALegacy,
        now,
        None,
        public_params,
    )?;
    let primary_pub = PublicKey::from_inner(pub_key_inner)?;
    let primary_sec = SecretKey::new(primary_pub.clone(), SecretParams::Plain(secret_params))?;

    let uid = UserId::from_str(Default::default(), user_id)?;

    let mut sig_cfg = SignatureConfig::v4(
        SignatureType::CertPositive,
        PublicKeyAlgorithm::EdDSALegacy,
        HashAlgorithm::Sha512,
    );
    sig_cfg.hashed_subpackets.push(
        Subpacket::regular(SubpacketData::SignatureCreationTime(now))?,
    );
    let mut keyflags = KeyFlags::default();
    keyflags.set_sign(true);
    keyflags.set_certify(true);
    sig_cfg.hashed_subpackets.push(
        Subpacket::regular(SubpacketData::KeyFlags(keyflags))?,
    );
    sig_cfg.hashed_subpackets.push(
        Subpacket::regular(SubpacketData::IssuerFingerprint(primary_pub.fingerprint()))?,
    );
    sig_cfg.unhashed_subpackets.push(
        Subpacket::regular(SubpacketData::IssuerKeyId(primary_pub.legacy_key_id()))?,
    );

    let cert_sig = sig_cfg.sign_certification(
        &primary_sec,
        &primary_pub,
        &Password::empty(),
        uid.tag(),
        &uid,
    )?;

    let signed_user = SignedUser::new(uid, vec![cert_sig]);
    let details = SignedKeyDetails::new(vec![], vec![], vec![signed_user], vec![]);
    let secret_key = SignedSecretKey::new(primary_sec, details, vec![], vec![]);
    let public_key = secret_key.to_public_key();

    Ok((secret_key, public_key))
}

/// File name of the cached private key.
const SECRET_KEY_FILE: &str = "release-signing-key.sec";
/// File name of the published public key.
const PUBLIC_KEY_FILE: &str = "release-signing-key.asc";

/// Directory that holds the long-lived private signing key.
///
/// Deliberately *not* the output directory: `output/` is what gets uploaded,
/// zipped, exported to release distributions, and accidentally committed.
///
/// `PACKAGER_KEY_DIR` overrides the location (used by tests and CI).
pub fn default_key_dir() -> PathBuf {
    if let Some(dir) = std::env::var_os("PACKAGER_KEY_DIR") {
        return PathBuf::from(dir);
    }
    dirs::config_dir()
        .unwrap_or_else(|| PathBuf::from(".config"))
        .join("packager")
        .join("keys")
}

/// Return the application-namespaced key directory under `$XDG_CONFIG_HOME/packager/<app_name>/keys`.
pub fn default_key_dir_for(app_name: &str) -> PathBuf {
    if let Some(dir) = std::env::var_os("PACKAGER_KEY_DIR") {
        return PathBuf::from(dir);
    }
    let config = dirs::config_dir().unwrap_or_else(|| PathBuf::from(".config"));
    if !app_name.is_empty() {
        config.join("packager").join(app_name).join("keys")
    } else {
        config.join("packager").join("keys")
    }
}

/// Write secret material with `0600`, creating the parent directory `0700`.
fn secure_write_secret(path: &Path, data: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
    use std::io::Write;

    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(parent, fs::Permissions::from_mode(0o700))?;
        }
    }

    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }

    let mut file = options.open(path)?;
    file.write_all(data)?;
    file.sync_all()?;
    Ok(())
}

/// Load a secret key, repairing legacy `0664` permissions in place.
///
/// An unreadable key is a hard error: silently generating a replacement
/// invalidates every signature already published under the old key.
fn load_secret_key(path: &Path) -> Result<Option<SignedSecretKey>, Box<dyn std::error::Error>> {
    if !path.exists() {
        return Ok(None);
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(path, fs::Permissions::from_mode(0o600));
    }

    let bytes = fs::read(path)?;
    let (secret, _) = SignedSecretKey::from_armor_single(Cursor::new(&bytes)).map_err(|e| {
        format!(
            "existing signing key {} is unreadable ({e}).\n\
             Refusing to rotate it silently: move it aside or set `keygen_key` explicitly.",
            path.display()
        )
    })?;

    Ok(Some(secret))
}

/// Write the armored public key next to the artifacts (safe to publish).
fn publish_public_key(
    secret: &SignedSecretKey,
    output_dir: &Path,
) -> Result<(SignedPublicKey, PathBuf), Box<dyn std::error::Error>> {
    if !output_dir.exists() {
        fs::create_dir_all(output_dir)?;
    }
    let public = secret.to_public_key();
    let path = output_dir.join(PUBLIC_KEY_FILE);
    fs::write(&path, public.to_armored_string(ArmorOptions::default())?)?;
    Ok((public, path))
}

/// Generates or loads an Ed25519 OpenPGP keypair, storing the private key in
/// the platform config directory (see [`default_key_dir_for`]).
pub fn generate_or_load_key(
    metadata: &Metadata,
    output_dir: &Path,
) -> Result<(SignedSecretKey, SignedPublicKey, PathBuf), Box<dyn std::error::Error>> {
    generate_or_load_key_in(metadata, output_dir, &default_key_dir_for(&metadata.name))
}

/// Same as [`generate_or_load_key`] but with an explicit key directory.
pub fn generate_or_load_key_in(
    metadata: &Metadata,
    output_dir: &Path,
    key_dir: &Path,
) -> Result<(SignedSecretKey, SignedPublicKey, PathBuf), Box<dyn std::error::Error>> {
    // 1. An explicitly configured key wins — and a broken path is an error,
    //    not a reason to quietly mint a different identity.
    if !metadata.keygen_key.is_empty() {
        let key_path = Path::new(&metadata.keygen_key);
        if !key_path.is_file() {
            return Err(format!("keygen_key does not exist: {}", key_path.display()).into());
        }
        let bytes = fs::read(key_path)?;
        let (secret, _) = SignedSecretKey::from_armor_single(Cursor::new(&bytes)).map_err(|e| {
            format!(
                "keygen_key {} is not a valid armored secret key: {e}",
                key_path.display()
            )
        })?;
        let (public, public_path) = publish_public_key(&secret, output_dir)?;
        return Ok((secret, public, public_path));
    }

    // 2. Cached key, outside the output directory.
    let secret_path = key_dir.join(SECRET_KEY_FILE);
    if let Some(secret) = load_secret_key(&secret_path)? {
        let (public, public_path) = publish_public_key(&secret, output_dir)?;
        return Ok((secret, public, public_path));
    }

    // 2b. Migrate a key left behind in `output/` by an older version.
    //     We import it rather than discard it so previously published
    //     signatures keep verifying.
    let legacy_path = output_dir.join(SECRET_KEY_FILE);
    if let Some(secret) = load_secret_key(&legacy_path)? {
        println!(
            "Note: importing legacy signing key from {:?} into {:?}",
            legacy_path, secret_path
        );
        let armor = secret.to_armored_string(ArmorOptions::default())?;
        secure_write_secret(&secret_path, armor.as_bytes())?;
        println!("Private key moved to {:?} (0600).", secret_path);
        println!("Delete {:?} - it must never be published.", legacy_path);
        let (public, public_path) = publish_public_key(&secret, output_dir)?;
        return Ok((secret, public, public_path));
    }

    // 3. Generate a fresh Ed25519 signing keypair.
    let user_id = if !metadata.maintainer.is_empty() && !metadata.email.is_empty() {
        format!("{} <{}>", metadata.maintainer, metadata.email)
    } else if !metadata.name.is_empty() {
        format!("{} Release Key <noreply@{}.org>", metadata.name, metadata.name)
    } else {
        "Release Signing Key <release@example.org>".to_string()
    };
    let (secret_key, _public_key) = generate_ed25519_keypair(&user_id)?;

    let secret_armor = secret_key.to_armored_string(ArmorOptions::default())?;
    secure_write_secret(&secret_path, secret_armor.as_bytes())?;
    println!("Generated release signing key at {:?} (0600)", secret_path);

    let (public_key, public_path) = publish_public_key(&secret_key, output_dir)?;

    Ok((secret_key, public_key, public_path))
}

/// Validates that an OpenPGP signature packet contains a valid, well-formed Ed25519 signature
/// structure conforming to RFC 8032 using the `ed25519` crate.
pub fn validate_ed25519_signature(
    sig: &pgp::packet::Signature,
) -> Result<Ed25519Signature, Box<dyn std::error::Error>> {
    let sig_bytes = sig
        .signature()
        .ok_or("Missing signature bytes in OpenPGP signature packet")?;
    match sig_bytes {
        pgp::types::SignatureBytes::Native(bytes) => {
            let ed_sig = Ed25519Signature::from_slice(bytes)
                .map_err(|e| format!("Invalid Ed25519 native signature: {}", e))?;
            Ok(ed_sig)
        }
        pgp::types::SignatureBytes::Mpis(mpis) => {
            if mpis.len() != 2 {
                return Err(
                    format!("Expected 2 MPIs for Ed25519 signature, found {}", mpis.len()).into(),
                );
            }
            let r_raw: &[u8] = mpis[0].as_ref();
            let s_raw: &[u8] = mpis[1].as_ref();
            if r_raw.len() > 32 || s_raw.len() > 32 {
                return Err("MPI bytes exceed 32-byte Ed25519 component size".into());
            }
            let mut r = [0u8; 32];
            let mut s = [0u8; 32];
            r[32 - r_raw.len()..].copy_from_slice(r_raw);
            s[32 - s_raw.len()..].copy_from_slice(s_raw);
            Ok(Ed25519Signature::from_components(r, s))
        }
    }
}

/// Parses an ASCII-armored detached OpenPGP signature and validates its underlying Ed25519 signature.
pub fn parse_ed25519_armored_signature(
    armored: &str,
) -> Result<Ed25519Signature, Box<dyn std::error::Error>> {
    let (detached, _) = DetachedSignature::from_armor_single(Cursor::new(armored))?;
    validate_ed25519_signature(&detached.signature)
}

/// Verifies a detached armored signature against the provided public key and data.
pub fn verify_signature(
    public_key: &SignedPublicKey,
    data: &[u8],
    armored_sig: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let (detached, _) = DetachedSignature::from_armor_single(Cursor::new(armored_sig))?;
    detached.verify(public_key, data)?;
    Ok(())
}

/// Signs binary data with SHA-512 producing detached armored (`.asc`) and binary (`.sig`) signatures.
pub fn sign_bytes(
    secret_key: &SignedSecretKey,
    data: &[u8],
) -> Result<(String, Vec<u8>), Box<dyn std::error::Error>> {
    let cursor = Cursor::new(data);
    let mut config = SignatureConfig::v4(
        SignatureType::Binary,
        secret_key.primary_key.algorithm(),
        HashAlgorithm::Sha512,
    );
    config.hashed_subpackets.push(
        Subpacket::regular(SubpacketData::SignatureCreationTime(Timestamp::now()))?
    );
    config.hashed_subpackets.push(
        Subpacket::regular(SubpacketData::IssuerFingerprint(secret_key.primary_key.fingerprint()))?
    );
    config.unhashed_subpackets.push(
        Subpacket::regular(SubpacketData::IssuerKeyId(secret_key.primary_key.legacy_key_id()))?
    );

    let sig = config.sign(&secret_key.primary_key, &Password::empty(), cursor)?;
    // Validate Ed25519 cryptographic structure using ed25519 crate
    let _ed_sig = validate_ed25519_signature(&sig)?;
    let detached_sig = DetachedSignature::new(sig);

    // Cryptographically verify signature over the exact payload data with the public key
    let public_key = secret_key.to_public_key();
    detached_sig.verify(&public_key, data)?;

    let armored_sig = detached_sig.to_armored_string(ArmorOptions::default())?;
    let mut binary_sig = Vec::new();
    detached_sig.to_writer(&mut binary_sig)?;

    Ok((armored_sig, binary_sig))
}

fn format_rfc2822_now() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let days = secs / 86400;
    let rem_secs = secs % 86400;
    let hours = rem_secs / 3600;
    let mins = (rem_secs % 3600) / 60;
    let s = rem_secs % 60;

    let wdays = ["Thu", "Fri", "Sat", "Sun", "Mon", "Tue", "Wed"];
    let wday = wdays[(days % 7) as usize];

    let mut y = 1970i64;
    let mut d = days as i64;
    loop {
        let leap = if (y % 4 == 0 && y % 100 != 0) || (y % 400 == 0) { 1 } else { 0 };
        let days_in_year = 365 + leap;
        if d >= days_in_year {
            d -= days_in_year;
            y += 1;
        } else {
            let mdays = [31, 28 + leap, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
            let months = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
            let mut m = 0;
            while m < 12 && d >= mdays[m] {
                d -= mdays[m];
                m += 1;
            }
            return format!("{}, {:02} {} {} {:02}:{:02}:{:02} +0000", wday, d + 1, months[m], y, hours, mins, s);
        }
    }
}

/// Generates a standard `zsync` delta control file for an AppImage bundle.
pub fn generate_zsync(
    appimage_path: &Path,
    zsync_path: &Path,
) -> Result<(), Box<dyn std::error::Error>> {
    let bytes = fs::read(appimage_path)?;
    let filename = appimage_path
        .file_name()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_else(|| "app.AppImage".to_string());
    let file_len = bytes.len();

    let mut sha1_hasher = Sha1::new();
    sha1_hasher.update(&bytes);
    let sha1_hex = hex::encode(sha1_hasher.finalize());

    let mtime_str = format_rfc2822_now();

    let mut out = Vec::new();
    out.extend_from_slice(b"zsync: 0.6.2\n");
    out.extend_from_slice(format!("Filename: {}\n", filename).as_bytes());
    out.extend_from_slice(format!("MTime: {}\n", mtime_str).as_bytes());
    out.extend_from_slice(b"Blocksize: 4096\n");
    out.extend_from_slice(format!("Length: {}\n", file_len).as_bytes());
    out.extend_from_slice(b"Hash-Lengths: 2,2,5\n");
    out.extend_from_slice(format!("URL: {}\n", filename).as_bytes());
    out.extend_from_slice(format!("SHA-1: {}\n\n", sha1_hex).as_bytes());

    for chunk in bytes.chunks(4096) {
        let mut a: u32 = 0;
        let mut b: u32 = 0;
        let len = chunk.len() as u32;
        for (i, &byte) in chunk.iter().enumerate() {
            a = (a + byte as u32) % 65536;
            b = (b + (len - i as u32) * byte as u32) % 65536;
        }
        let a_be = (a as u16).to_be_bytes();
        let b_be = (b as u16).to_be_bytes();
        out.push(a_be[0]);
        out.push(a_be[1]);
        out.push(b_be[0]);
        out.push(b_be[1]);

        let mut md5_hasher = Md5::new();
        md5_hasher.update(chunk);
        let md5_digest = md5_hasher.finalize();
        out.extend_from_slice(&md5_digest[..5]);
    }

    fs::write(zsync_path, out)?;
    Ok(())
}

/// Automatically signs all package artifacts in `output_dir`, produces `.asc` and `.sig` signatures,
/// creates `zsync` for AppImages, and generates `SHA256SUMS.txt` with its detached signature `SHA256SUMS.txt.asc`.
pub fn run_keygen(
    metadata: &Metadata,
    output_dir: &Path,
    package_paths: &[PathBuf],
) -> Result<KeygenResults, Box<dyn std::error::Error>> {
    run_keygen_with_key_dir(
        metadata,
        output_dir,
        &default_key_dir_for(&metadata.name),
        package_paths,
    )
}

/// Same as [`run_keygen`] but with an explicit key directory.
pub fn run_keygen_with_key_dir(
    metadata: &Metadata,
    output_dir: &Path,
    key_dir: &Path,
    package_paths: &[PathBuf],
) -> Result<KeygenResults, Box<dyn std::error::Error>> {
    println!("\nGenerating Keygen release signatures and SHA256SUMS.txt...");

    if !output_dir.exists() {
        fs::create_dir_all(output_dir)?;
    }

    // 1. Generate or load release signing keypair (private key stays in key_dir)
    let (secret_key, _public_key, pub_key_path) =
        generate_or_load_key_in(metadata, output_dir, key_dir)?;

    let mut all_generated_signatures = Vec::new();
    let mut files_for_checksums = Vec::new();

    // Collect all valid packages to process
    let mut target_packages = Vec::new();
    for p in package_paths {
        if p.is_file() {
            target_packages.push(p.clone());
        }
    }

    // Allowed package extensions for scanning output_dir
    const ALLOWED_PACKAGE_EXTENSIONS: &[&str] = &[
        ".deb",
        ".rpm",
        ".pkg.tar.zst",
        ".AppImage",
        ".flatpak",
        ".snap",
        ".dmg",
        ".msi",
        ".exe",
        ".pkg",
        ".zip",
        ".tar.gz",
        ".oci-manifest.json",
        ".oci",
    ];

    // If package_paths is empty, scan output_dir for package files using a strict allowlist
    if target_packages.is_empty() && output_dir.exists() {
        for entry in walkdir::WalkDir::new(output_dir).min_depth(1).max_depth(1).into_iter().flatten() {
            let p = entry.path().to_path_buf();
            if p.is_file() {
                let name = p.file_name().unwrap_or_default().to_string_lossy();
                if ALLOWED_PACKAGE_EXTENSIONS.iter().any(|ext| name.ends_with(ext)) {
                    target_packages.push(p);
                }
            }
        }
    }

    // 2. Sign each package artifact
    for pkg_path in &target_packages {
        let pkg_filename = pkg_path.file_name().unwrap_or_default().to_string_lossy();
        let pkg_bytes = fs::read(pkg_path)?;

        files_for_checksums.push((pkg_path.clone(), pkg_filename.to_string()));

        if pkg_filename.ends_with(".pkg.tar.zst") {
            // Arch ALPM uses binary detached signature (.pkg.tar.zst.sig)
            let (_, binary_sig) = sign_bytes(&secret_key, &pkg_bytes)?;
            let sig_path = pkg_path.with_file_name(format!("{}.sig", pkg_filename));
            fs::write(&sig_path, &binary_sig)?;
            let sig_name = sig_path.file_name().unwrap_or_default().to_string_lossy().to_string();
            files_for_checksums.push((sig_path.clone(), sig_name));
            all_generated_signatures.push(sig_path);
        } else if pkg_filename.ends_with(".oci-manifest.json") || pkg_filename.ends_with(".oci") {
            // OCI container manifests produce binary detached signature (.oci.sig)
            let (_, binary_sig) = sign_bytes(&secret_key, &pkg_bytes)?;
            let sig_name = if pkg_filename.ends_with(".oci-manifest.json") {
                pkg_filename.replace(".oci-manifest.json", ".oci.sig")
            } else {
                format!("{}.sig", pkg_filename)
            };
            let sig_path = pkg_path.with_file_name(sig_name);
            fs::write(&sig_path, &binary_sig)?;
            let sig_name = sig_path.file_name().unwrap_or_default().to_string_lossy().to_string();
            files_for_checksums.push((sig_path.clone(), sig_name));
            all_generated_signatures.push(sig_path);
        } else if pkg_filename.ends_with(".msi")
            || pkg_filename.ends_with(".exe")
            || pkg_filename.ends_with(".dmg")
            || pkg_filename.ends_with(".zip")
        {
            // Windows and macOS binaries are cataloged in SHA256SUMS.txt
        } else {
            // Standard Linux package formats (.deb, .rpm, .flatpak, .tar.gz, .AppImage) produce .asc
            let (armored_sig, _) = sign_bytes(&secret_key, &pkg_bytes)?;
            let asc_path = pkg_path.with_file_name(format!("{}.asc", pkg_filename));
            fs::write(&asc_path, &armored_sig)?;
            let asc_name = asc_path.file_name().unwrap_or_default().to_string_lossy().to_string();
            files_for_checksums.push((asc_path.clone(), asc_name));
            all_generated_signatures.push(asc_path);
        }

        // AppImage additionally produces .zsync and .zsync.asc
        if pkg_filename.ends_with(".AppImage") {
            let zsync_path = pkg_path.with_file_name(format!("{}.zsync", pkg_filename));
            if generate_zsync(pkg_path, &zsync_path).is_ok() {
                let zsync_name = zsync_path.file_name().unwrap_or_default().to_string_lossy().to_string();
                files_for_checksums.push((zsync_path.clone(), zsync_name));
                all_generated_signatures.push(zsync_path.clone());

                let zsync_bytes = fs::read(&zsync_path)?;
                let (zsync_armored, _) = sign_bytes(&secret_key, &zsync_bytes)?;
                let zsync_asc_path = pkg_path.with_file_name(format!("{}.zsync.asc", pkg_filename));
                fs::write(&zsync_asc_path, &zsync_armored)?;
                let zsync_asc_name = zsync_asc_path.file_name().unwrap_or_default().to_string_lossy().to_string();
                files_for_checksums.push((zsync_asc_path.clone(), zsync_asc_name));
                all_generated_signatures.push(zsync_asc_path);
            }
        }
    }

    // Include release-signing-key.asc in SHA256SUMS.txt
    files_for_checksums.push((pub_key_path.clone(), "release-signing-key.asc".to_string()));

    // 3. Generate SHA256SUMS.txt
    files_for_checksums.sort_by(|a, b| a.1.cmp(&b.1));
    let mut sums_content = String::new();
    for (path, filename) in &files_for_checksums {
        let bytes = fs::read(path)?;
        let mut hasher = Sha256::new();
        hasher.update(&bytes);
        let hash = hex::encode(hasher.finalize());
        sums_content.push_str(&format!("{}  {}\n", hash, filename));
    }

    let sha256sums_path = output_dir.join("SHA256SUMS.txt");
    fs::write(&sha256sums_path, &sums_content)?;

    // 4. Sign SHA256SUMS.txt -> SHA256SUMS.txt.asc
    let (sha_sig_armored, _) = sign_bytes(&secret_key, sums_content.as_bytes())?;
    let sha256sums_sig_path = output_dir.join("SHA256SUMS.txt.asc");
    fs::write(&sha256sums_sig_path, sha_sig_armored)?;

    println!("Keygen release artifacts generated successfully:");
    println!("  Public Key   : {}", pub_key_path.display());
    println!("  Checksums    : {}", sha256sums_path.display());
    println!("  Checksums Sig: {}", sha256sums_sig_path.display());
    println!(
        "  Signatures   : {} signature files generated",
        all_generated_signatures.len()
    );

    Ok(KeygenResults {
        public_key: pub_key_path,
        sha256sums: sha256sums_path,
        sha256sums_sig: sha256sums_sig_path,
        signatures: all_generated_signatures,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keygen_complete_flow() {
        let tmp = std::env::temp_dir().join(format!("test_keygen_flow_{}", std::process::id()));
        let _ = fs::remove_dir_all(&tmp);
        fs::create_dir_all(&tmp).expect("create temp dir");

        let out_dir = tmp.join("dist");
        fs::create_dir_all(&out_dir).expect("create out dir");

        // Create sample packages in out_dir
        let deb = out_dir.join("testapp_1.0_amd64.deb");
        fs::write(&deb, b"test debian package payload").expect("write deb");

        let alpm = out_dir.join("testapp-1.0-1-x86_64.pkg.tar.zst");
        fs::write(&alpm, b"test arch package payload").expect("write alpm");

        let appimage = out_dir.join("testapp-1.0-x86_64.AppImage");
        fs::write(&appimage, vec![0u8; 8192]).expect("write appimage");

        let metadata = Metadata {
            name: "testapp".to_string(),
            version: "1.0.0".to_string(),
            release: "1".to_string(),
            maintainer: "Packager Developer".to_string(),
            email: "dev@packager.org".to_string(),
            keygen: true,
            ..Default::default()
        };

        let key_dir = tmp.join("keys");
        let results = run_keygen_with_key_dir(
            &metadata,
            &out_dir,
            &key_dir,
            &[deb.clone(), alpm.clone(), appimage.clone()],
        )
        .expect("run_keygen must succeed");

        // The private key must live outside the published output directory
        // and must be owner-only.
        let secret = key_dir.join("release-signing-key.sec");
        assert!(secret.is_file(), "secret key must be stored in key_dir");
        assert!(
            !out_dir.join("release-signing-key.sec").exists(),
            "secret key must never be written into the output directory"
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(&secret).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600, "secret key must be 0600, got {mode:o}");
        }

        assert!(results.public_key.exists());
        assert!(results.sha256sums.exists());
        assert!(results.sha256sums_sig.exists());

        // Check that deb.asc was created
        let deb_asc = out_dir.join("testapp_1.0_amd64.deb.asc");
        assert!(deb_asc.exists());
        let deb_asc_content = fs::read_to_string(&deb_asc).unwrap();
        assert!(deb_asc_content.contains("-----BEGIN PGP SIGNATURE-----"));

        // Check that alpm.sig was created
        let alpm_sig = out_dir.join("testapp-1.0-1-x86_64.pkg.tar.zst.sig");
        assert!(alpm_sig.exists());

        // Check that appimage.zsync and zsync.asc were created
        let appimage_zsync = out_dir.join("testapp-1.0-x86_64.AppImage.zsync");
        assert!(appimage_zsync.exists());
        let appimage_zsync_asc = out_dir.join("testapp-1.0-x86_64.AppImage.zsync.asc");
        assert!(appimage_zsync_asc.exists());

        // Check SHA256SUMS.txt contents
        let sums = fs::read_to_string(&results.sha256sums).unwrap();
        assert!(sums.contains("testapp_1.0_amd64.deb"));
        assert!(sums.contains("testapp_1.0_amd64.deb.asc"));
        assert!(sums.contains("testapp-1.0-1-x86_64.pkg.tar.zst.sig"));
        assert!(sums.contains("testapp-1.0-x86_64.AppImage.zsync"));

        // Check SHA256SUMS.txt.asc
        let sums_sig = fs::read_to_string(&results.sha256sums_sig).unwrap();
        assert!(sums_sig.contains("-----BEGIN PGP SIGNATURE-----"));

        let _ = fs::remove_dir_all(&tmp);
    }

    #[test]
    fn test_ed25519_signature_validation() {
        let (secret_key, _) =
            generate_ed25519_keypair("Packager Developer <dev@packager.org>").unwrap();
        let data = b"Hello, Ed25519 signed release package payload!";
        let (armored, binary) = sign_bytes(&secret_key, data).unwrap();

        // 1. Validate armored signature parsing with ed25519 crate
        let ed_sig =
            parse_ed25519_armored_signature(&armored).expect("must parse ed25519 armored signature");
        assert_eq!(ed_sig.to_bytes().len(), 64);
        assert_eq!(ed_sig.r_bytes().len(), 32);
        assert_eq!(ed_sig.s_bytes().len(), 32);

        // 2. Validate binary signature parsing with ed25519 crate
        let detached_bin =
            DetachedSignature::from_bytes(Cursor::new(&binary)).expect("must parse detached binary");
        let ed_sig_bin = validate_ed25519_signature(&detached_bin.signature)
            .expect("must validate binary ed25519 signature");
        assert_eq!(ed_sig_bin.to_bytes(), ed_sig.to_bytes());
    }

    fn test_metadata() -> Metadata {
        Metadata {
            name: "testapp".to_string(),
            version: "1.0.0".to_string(),
            release: "1".to_string(),
            maintainer: "Packager Developer".to_string(),
            email: "dev@packager.org".to_string(),
            keygen: true,
            ..Default::default()
        }
    }

    #[test]
    fn test_corrupt_key_is_not_silently_rotated() {
        let tmp = std::env::temp_dir().join(format!("packager-corrupt-key-{}", std::process::id()));
        let _ = fs::remove_dir_all(&tmp);
        let key_dir = tmp.join("keys");
        let out_dir = tmp.join("dist");
        fs::create_dir_all(&key_dir).unwrap();
        fs::create_dir_all(&out_dir).unwrap();

        fs::write(key_dir.join(SECRET_KEY_FILE), b"not a key").unwrap();

        let err = run_keygen_with_key_dir(&test_metadata(), &out_dir, &key_dir, &[])
            .expect_err("an unreadable key must abort instead of rotating silently");
        assert!(err.to_string().contains("Refusing to rotate"));

        let _ = fs::remove_dir_all(&tmp);
    }

    #[test]
    fn test_legacy_key_is_migrated_out_of_output_dir() {
        let tmp = std::env::temp_dir().join(format!("packager-legacy-key-{}", std::process::id()));
        let _ = fs::remove_dir_all(&tmp);
        let key_dir = tmp.join("keys");
        let out_dir = tmp.join("dist");
        fs::create_dir_all(&out_dir).unwrap();

        // Simulate a key produced by the previous version.
        let (secret, _) = generate_ed25519_keypair("Legacy <legacy@example.com>").unwrap();
        let armor = secret.to_armored_string(ArmorOptions::default()).unwrap();
        fs::write(out_dir.join(SECRET_KEY_FILE), armor).unwrap();

        let (loaded, _, _) = generate_or_load_key_in(&test_metadata(), &out_dir, &key_dir)
            .expect("legacy key should be imported");

        // Same identity, now stored securely outside the output directory.
        assert_eq!(
            loaded.to_public_key().to_armored_string(ArmorOptions::default()).unwrap(),
            secret.to_public_key().to_armored_string(ArmorOptions::default()).unwrap()
        );
        assert!(key_dir.join(SECRET_KEY_FILE).is_file());

        let _ = fs::remove_dir_all(&tmp);
    }

    #[test]
    fn test_verify_signature_succeeds_and_fails_on_tampered() {
        let (secret_key, public_key) =
            generate_ed25519_keypair("Packager Developer <dev@packager.org>").unwrap();
        let payload = b"critical package binary payload";
        let (armored_sig, _) = sign_bytes(&secret_key, payload).unwrap();

        // Verification must succeed on original payload
        verify_signature(&public_key, payload, &armored_sig)
            .expect("signature must verify against original payload");

        // Verification must fail on tampered payload
        let tampered = b"critical package binary payload (tampered)";
        assert!(verify_signature(&public_key, tampered, &armored_sig).is_err());
    }

    #[test]
    fn test_run_keygen_ignores_unallowed_extensions_in_output_dir() {
        let tmp = std::env::temp_dir().join(format!("test_keygen_allowlist_{}", std::process::id()));
        let _ = fs::remove_dir_all(&tmp);
        let out_dir = tmp.join("dist");
        let key_dir = tmp.join("keys");
        fs::create_dir_all(&out_dir).unwrap();

        // Allowed package
        fs::write(out_dir.join("app_1.0_amd64.deb"), b"deb payload").unwrap();

        // Unallowed files that must NEVER be signed or cataloged into SHA256SUMS.txt
        fs::write(out_dir.join("id_rsa"), b"secret key").unwrap();
        fs::write(out_dir.join("build.log"), b"build log").unwrap();
        fs::write(out_dir.join("temp.tmp"), b"temporary data").unwrap();

        let metadata = test_metadata();
        let results = run_keygen_with_key_dir(&metadata, &out_dir, &key_dir, &[])
            .expect("run_keygen must succeed");

        let sums = fs::read_to_string(&results.sha256sums).unwrap();
        assert!(sums.contains("app_1.0_amd64.deb"));
        assert!(!sums.contains("id_rsa"), "secret files must not be swept into SHA256SUMS.txt");
        assert!(!sums.contains("build.log"), "logs must not be swept into SHA256SUMS.txt");
        assert!(!sums.contains("temp.tmp"), "temp files must not be swept into SHA256SUMS.txt");

        let _ = fs::remove_dir_all(&tmp);
    }

    #[test]
    fn test_default_key_dir_for_namespaces_by_app_name() {
        unsafe {
            std::env::remove_var("PACKAGER_KEY_DIR");
        }
        let dir_ripgrep = default_key_dir_for("ripgrep");
        assert!(dir_ripgrep.ends_with(Path::new("packager/ripgrep/keys")));

        let dir_daemon = default_key_dir_for("my-daemon");
        assert!(dir_daemon.ends_with(Path::new("packager/my-daemon/keys")));

        let generic = default_key_dir();
        assert!(generic.ends_with(Path::new("packager/keys")));
    }
}

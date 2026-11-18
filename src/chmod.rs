use super::metadata::Metadata;
use std::fs;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::{Component, Path, PathBuf};

/// Parse a single `install` directive into tokens.
///
/// Quoting is significant: a destination such as `/Program Files/TwinCAN/`
/// must be wrapped in double quotes, otherwise it is split on the space and
/// silently installed to the wrong place. Both an unterminated quote and an
/// unquoted path that looks like it contains a space are caller errors, not
/// something we can guess around.
fn tokenize_line(line: &str) -> Result<Vec<String>, Box<dyn std::error::Error>> {
    let mut tokens = Vec::new();
    let mut current = String::new();
    let mut in_quotes = false;
    let mut token_has_content = false;

    for ch in line.chars() {
        match ch {
            '"' => {
                in_quotes = !in_quotes;
                token_has_content = true;
            }
            c if c.is_whitespace() && !in_quotes => {
                if token_has_content {
                    tokens.push(std::mem::take(&mut current));
                    token_has_content = false;
                }
            }
            c => {
                current.push(c);
                token_has_content = true;
            }
        }
    }

    if in_quotes {
        return Err(format!("unterminated quote in install directive: {line:?}").into());
    }
    if token_has_content {
        tokens.push(current);
    }

    Ok(tokens)
}

/// Resolve an install destination against the package root, rejecting anything
/// that could escape it. This is the last line of defence before `fs::copy`.
fn safe_destination(base_dir: &Path, dest: &str) -> Result<PathBuf, Box<dyn std::error::Error>> {
    if dest.contains('\0') {
        return Err(format!("destination contains a NUL byte: {dest:?}").into());
    }
    // Windows drive letter (`C:\...`) or UNC path (`\\server\share`).
    if dest.starts_with("\\\\") || dest.as_bytes().get(1) == Some(&b':') {
        return Err(format!("absolute destination not allowed: {dest:?}").into());
    }

    // Normalize Windows backslashes so cross-compiling on Unix parses components correctly
    let normalized = dest.replace('\\', "/");
    let relative = normalized.trim_start_matches('/');
    let mut depth: i32 = 0;

    for component in Path::new(relative).components() {
        match component {
            Component::ParentDir => {
                depth -= 1;
                if depth < 0 {
                    return Err(format!("destination escapes package root: {dest:?}").into());
                }
            }
            Component::Normal(_) => depth += 1,
            Component::CurDir => {}
            Component::RootDir | Component::Prefix(_) => {
                return Err(format!("absolute destination not allowed: {dest:?}").into());
            }
        }
    }

    Ok(base_dir.join(relative))
}

pub fn chmod_package_with_metadata(
    metadata: &Metadata,
    base_dir: &Path,
    is_appimage: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    println!("Preparing package layout: {}", metadata.name);

    if base_dir == Path::new(".") || base_dir == Path::new("..") || base_dir.as_os_str().is_empty()
    {
        return Err("staging directory cannot be current or parent directory".into());
    }

    if base_dir.is_symlink() {
        return Err(format!(
            "refusing to remove symlinked staging directory: {:?}",
            base_dir
        )
        .into());
    }

    if base_dir.exists() {
        let canon_base = base_dir.canonicalize()?;
        let canon_cwd = std::env::current_dir()?.canonicalize()?;
        if canon_base == canon_cwd {
            return Err("refusing to delete current working directory as staging dir".into());
        }
        let temp_dir = std::env::temp_dir()
            .canonicalize()
            .unwrap_or_else(|_| std::env::temp_dir());
        if !canon_base.starts_with(&canon_cwd) && !canon_base.starts_with(&temp_dir) {
            return Err(format!(
                "staging directory must be inside working directory or temp directory: {:?}",
                base_dir
            )
            .into());
        }
        fs::remove_dir_all(base_dir)?;
    }
    fs::create_dir_all(base_dir)?;

    for line in &metadata.package_instructions {
        process_install_line(
            line,
            base_dir,
            metadata.workdir(),
            false,
            metadata.manifest_dir.as_deref(),
        )?;
    }

    if is_appimage {
        for line in &metadata.appimage_icon_instructions {
            process_install_line(
                line,
                base_dir,
                metadata.workdir(),
                true,
                metadata.manifest_dir.as_deref(),
            )?;
        }
        for line in &metadata.appimage_desktop_instructions {
            process_install_line(
                line,
                base_dir,
                metadata.workdir(),
                true,
                metadata.manifest_dir.as_deref(),
            )?;
        }
    }

    println!("Package layout complete at {:?}", base_dir);
    Ok(())
}

fn process_install_line(
    line: &str,
    base_dir: &Path,
    metadata_name: &str,
    default_to_root: bool,
    manifest_dir: Option<&Path>,
) -> Result<(), Box<dyn std::error::Error>> {
    let trimmed = line.trim();
    let parts = tokenize_line(trimmed)?;
    if parts.is_empty() || parts[0] != "install" {
        return Err(format!("directive must start with 'install': {line:?}").into());
    }
    if parts.len() < 2 {
        return Err(format!("install directive missing arguments: {line:?}").into());
    }

    // Mode
    let mut current_idx = 1;
    let (mode, mode_str) = if current_idx < parts.len() && parts[current_idx].starts_with("-m") {
        let m = parts[current_idx].trim_start_matches("-m");
        current_idx += 1;
        if m.is_empty() || !m.chars().all(|c| matches!(c, '0'..='7')) {
            return Err(
                format!("invalid octal permissions mode in install directive: {line:?}").into(),
            );
        }
        let parsed = u32::from_str_radix(m, 8)?;
        if parsed > 0o7777 {
            return Err(format!(
                "mode {m} exceeds maximum octal 7777 in install directive: {line:?}"
            )
            .into());
        }
        (parsed, m)
    } else {
        (0o644, "644")
    };

    // Source file
    if current_idx >= parts.len() {
        return Err(format!("missing source file in install directive: {line:?}").into());
    }
    let raw_source = parts[current_idx].trim_matches('"');
    current_idx += 1;
    if raw_source.is_empty() {
        return Err(format!("missing source file in install directive: {line:?}").into());
    }

    // Check if source specifies "local:" prefix or is a direct local asset path
    let (source_file_name, is_explicit_local) =
        if let Some(local_path) = raw_source.strip_prefix("local:") {
            (local_path.to_string(), true)
        } else {
            (raw_source.to_string(), false)
        };

    // Only an explicit `local:` source may point outside the work directory.
    // Without the prefix this would be an accidental (or malicious) read of
    // arbitrary files into a published package.
    if !is_explicit_local
        && Path::new(&source_file_name)
            .components()
            .any(|c| c == Component::ParentDir)
    {
        return Err(format!(
            "source path may not escape the work directory (use a `local:` prefix if intentional): {source_file_name:?}"
        )
        .into());
    }

    // Destination
    let dest_path_str = if current_idx < parts.len() && parts[current_idx] == "to" {
        current_idx += 1; // consume "to"
        if current_idx < parts.len() {
            let dest = parts[current_idx].trim_matches('"').to_string();
            current_idx += 1; // consume the destination
            if dest.is_empty() {
                return Err(format!(
                    "empty destination path after 'to' in install directive: {line:?}"
                )
                .into());
            }
            dest
        } else {
            return Err(
                format!("missing destination after 'to' in install directive: {line:?}").into(),
            );
        }
    } else if default_to_root {
        "/".to_string()
    } else {
        return Err(format!("missing 'to <destination>' in install directive: {line:?}").into());
    };

    // The grammar is exactly `install -m<mode> <source> [to <destination>]`.
    if current_idx < parts.len() {
        return Err(format!(
            "unexpected trailing tokens after the install destination (quote any path containing spaces): {:?}",
            &parts[current_idx..]
        )
        .into());
    }

    let source_dir = Path::new(metadata_name);
    let source_path = if is_explicit_local
        && let Some(mdir) = manifest_dir
        && mdir.join(&source_file_name).exists()
    {
        mdir.join(&source_file_name)
    } else if is_explicit_local && Path::new(&source_file_name).exists() {
        PathBuf::from(&source_file_name)
    } else if source_dir.join(&source_file_name).exists() {
        source_dir.join(&source_file_name)
    } else if let Some(mdir) = manifest_dir
        && mdir.join(&source_file_name).exists()
    {
        mdir.join(&source_file_name)
    } else if Path::new(&source_file_name).exists() {
        PathBuf::from(&source_file_name)
    } else {
        return Err(format!(
            "Source file not found: {:?} (checked inside {:?} and working directory)",
            source_file_name, source_dir
        )
        .into());
    };

    let meta = fs::symlink_metadata(&source_path)?;
    if meta.file_type().is_symlink() && !is_explicit_local {
        return Err(format!("refusing to package a symlink: {:?}", source_path).into());
    }

    let canonical = source_path.canonicalize()?;
    if !is_explicit_local {
        let work_root = Path::new(metadata_name).canonicalize()?;
        if !canonical.starts_with(&work_root) {
            return Err(format!(
                "source resolves outside the work directory: {:?}",
                canonical
            )
            .into());
        }
    }

    if source_path.is_dir() {
        return Err(format!("Source is a directory, not a file: {:?}", source_path).into());
    }

    // Reject any destination that walks above the package root *before*
    // creating directories, so nothing is written outside the staging tree.
    let mut full_dest = safe_destination(base_dir, &dest_path_str)?;

    // If destination is a directory (explicit trailing slash or root), append filename
    let is_dir_target = dest_path_str.ends_with('/')
        || dest_path_str.ends_with('\\')
        || dest_path_str == "/"
        || dest_path_str == "\\"
        || full_dest.is_dir();
    if is_dir_target && let Some(file_name) = Path::new(&source_file_name).file_name() {
        // `file_name()` yields a single component, so this cannot escape.
        full_dest = full_dest.join(file_name);
    }

    println!("Installing:");
    println!("  Mode: {}", mode_str);
    println!("  Source: {:?}", source_path);
    println!("  Dest: {:?}", full_dest);

    // Create parent directories
    if let Some(parent) = full_dest.parent() {
        fs::create_dir_all(parent)?;
    }

    // Copy
    fs::copy(&source_path, &full_dest)?;

    // Defence in depth: resolve symlinks and confirm we stayed inside the root.
    let root = base_dir.canonicalize()?;
    let written = full_dest.canonicalize()?;
    if !written.starts_with(&root) {
        let _ = fs::remove_file(&written);
        return Err(format!(
            "destination escaped package root after resolution: {dest_path_str:?}"
        )
        .into());
    }

    // Set permissions
    #[cfg(unix)]
    {
        let mut perms = fs::metadata(&full_dest)?.permissions();
        perms.set_mode(mode);
        fs::set_permissions(&full_dest, perms)?;
    }
    #[cfg(not(unix))]
    {
        let _ = mode;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmpdir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("twincan-chmod-{tag}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).expect("create temp dir");
        dir
    }

    #[test]
    fn test_tokenize_line_with_quotes_and_spaces() {
        let line = r#"install -m755 "Twin CAN/Twin CAN" to "/usr/bin/""#;
        let tokens = tokenize_line(line).expect("tokenize");
        assert_eq!(
            tokens,
            vec!["install", "-m755", "Twin CAN/Twin CAN", "to", "/usr/bin/"]
        );
    }

    #[test]
    fn test_tokenize_line_without_destination() {
        let line = r#"install -m644 "TwinCAN/TwinCAN.desktop""#;
        let tokens = tokenize_line(line).expect("tokenize");
        assert_eq!(tokens, vec!["install", "-m644", "TwinCAN/TwinCAN.desktop"]);
    }

    #[test]
    fn test_tokenize_line_with_local_prefix() {
        let line = r#"install -m644 "local:./metadata" to "/usr/share/doc/twincan/""#;
        let tokens = tokenize_line(line).expect("tokenize");
        assert_eq!(
            tokens,
            vec![
                "install",
                "-m644",
                "local:./metadata",
                "to",
                "/usr/share/doc/twincan/"
            ]
        );
    }

    #[test]
    fn test_tokenize_line_rejects_unterminated_quote() {
        let err = tokenize_line(r#"install -m644 "TwinCAN/LICENSE to /usr/"#)
            .expect_err("unterminated quote must be an error");
        assert!(err.to_string().contains("unterminated quote"));
    }

    #[test]
    fn test_safe_destination_rejects_parent_traversal() {
        let base = Path::new("pkg");
        let err =
            safe_destination(base, "/../../escaped.txt").expect_err("traversal must be rejected");
        assert!(err.to_string().contains("escapes package root"));
    }

    #[test]
    fn test_safe_destination_rejects_drive_and_unc_paths() {
        let base = Path::new("pkg");
        assert!(safe_destination(base, r"C:\Windows\evil.dll").is_err());
        assert!(safe_destination(base, r"\\server\share\evil.dll").is_err());
    }

    #[test]
    fn test_safe_destination_accepts_nested_paths() {
        let base = Path::new("pkg");
        let got = safe_destination(base, "/usr/bin/").expect("nested path is fine");
        assert_eq!(got, Path::new("pkg/usr/bin"));
    }

    #[test]
    fn test_safe_destination_accepts_windows_leading_backslash() {
        let base = Path::new("pkg");
        let got = safe_destination(base, r"\Program Files\TwinCAN\")
            .expect("windows backslash path is fine");
        assert_eq!(got, base.join("Program Files").join("TwinCAN"));
    }

    #[test]
    fn test_windows_path_with_space_is_one_component() {
        let tokens =
            tokenize_line(r#"install -m755 "TwinCAN/TwinCAN" to "/Program Files/TwinCAN/""#)
                .expect("tokenize");
        assert_eq!(tokens[4], "/Program Files/TwinCAN/");
    }

    #[test]
    fn test_install_rejects_traversal_end_to_end() {
        let dir = tmpdir("traversal");
        let base = dir.join("pkg");
        fs::create_dir_all(&base).unwrap();

        let source = dir.join("payload.txt");
        fs::write(&source, b"payload").unwrap();

        let line = format!(
            "install -m644 \"local:{}\" to \"/../../escaped.txt\"",
            source.display()
        );
        let err = process_install_line(&line, &base, "work", false, None)
            .expect_err("traversal must be refused");
        assert!(err.to_string().contains("escapes package root"));
        assert!(!dir.join("escaped.txt").exists());
        assert!(!dir.parent().unwrap().join("escaped.txt").exists());

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_install_writes_inside_root() {
        let dir = tmpdir("inside");
        let base = dir.join("pkg");
        fs::create_dir_all(&base).unwrap();

        let source = dir.join("LICENSE");
        fs::write(&source, b"license text").unwrap();

        let line = format!(
            "install -m644 \"local:{}\" to \"/usr/share/licenses/twincan/\"",
            source.display()
        );
        process_install_line(&line, &base, "work", false, None).expect("install should succeed");

        assert!(base.join("usr/share/licenses/twincan/LICENSE").is_file());

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_install_rejects_unquoted_path_with_spaces() {
        let dir = tmpdir("unquoted");
        let base = dir.join("pkg");
        fs::create_dir_all(&base).unwrap();
        fs::write(dir.join("TwinCAN"), b"bin").unwrap();

        let err = process_install_line(
            &format!(
                "install -m755 \"local:{}\" to /Program Files/TwinCAN/",
                dir.join("TwinCAN").display()
            ),
            &base,
            "work",
            false,
            None,
        )
        .expect_err("unquoted path with spaces must be rejected, not split");
        assert!(err.to_string().contains("unexpected trailing tokens"));

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_install_rejects_parent_source_without_local_prefix() {
        let dir = tmpdir("source");
        let base = dir.join("pkg");
        fs::create_dir_all(&base).unwrap();

        let err = process_install_line(
            "install -m644 \"../../../etc/passwd\" to /usr/bin/",
            &base,
            "work",
            false,
            None,
        )
        .expect_err("escaping source must be refused without local:");
        assert!(err.to_string().contains("may not escape"));

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    #[cfg(unix)]
    fn test_install_rejects_symlink_source() {
        let dir = tmpdir("symlink");
        let work = dir.join("work");
        fs::create_dir_all(&work).unwrap();
        let base = dir.join("pkg");
        fs::create_dir_all(&base).unwrap();

        let secret = dir.join("secret.txt");
        fs::write(&secret, b"sensitive data").unwrap();

        let link = work.join("symlink_payload");
        std::os::unix::fs::symlink(&secret, &link).unwrap();

        let line = "install -m644 \"symlink_payload\" to \"/usr/bin/\"";
        let err = process_install_line(line, &base, work.to_str().unwrap(), false, None)
            .expect_err("symlink source must be rejected");
        assert!(err.to_string().contains("refusing to package a symlink"));

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    #[cfg(unix)]
    fn test_install_rejects_canonical_escape() {
        let dir = tmpdir("escape");
        let work = dir.join("work");
        fs::create_dir_all(&work).unwrap();
        let base = dir.join("pkg");
        fs::create_dir_all(&base).unwrap();

        let outside_dir = dir.join("outside");
        fs::create_dir_all(&outside_dir).unwrap();
        let secret = outside_dir.join("secret.txt");
        fs::write(&secret, b"sensitive data").unwrap();

        // Symlink a directory
        let sym_dir = work.join("sub");
        std::os::unix::fs::symlink(&outside_dir, &sym_dir).unwrap();

        let line = "install -m644 \"sub/secret.txt\" to \"/usr/bin/\"";
        let err = process_install_line(line, &base, work.to_str().unwrap(), false, None)
            .expect_err("canonical escape must be rejected");
        assert!(err.to_string().contains("outside the work directory"));

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_chmod_package_refuses_to_delete_cwd() {
        let metadata = Metadata {
            name: "test".to_string(),
            ..Default::default()
        };
        let err = chmod_package_with_metadata(&metadata, Path::new("."), false)
            .expect_err("refuse to delete cwd");
        assert!(err.to_string().contains("current or parent directory"));
    }

    #[test]
    #[cfg(unix)]
    fn test_chmod_package_refuses_symlinked_base_dir() {
        let dir = tmpdir("sym_base");
        let target = dir.join("target");
        fs::create_dir_all(&target).unwrap();
        let sym = dir.join("sym_staging");
        std::os::unix::fs::symlink(&target, &sym).unwrap();

        let metadata = Metadata {
            name: "test".to_string(),
            ..Default::default()
        };
        let err = chmod_package_with_metadata(&metadata, &sym, false)
            .expect_err("refuse symlinked base dir");
        assert!(
            err.to_string()
                .contains("refusing to remove symlinked staging directory")
        );

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_process_install_line_rejects_keyword_typo() {
        let base = Path::new("pkg");
        let err = process_install_line("instal -m644 \"foo\" to \"/\"", base, "work", false, None)
            .expect_err("instal must fail");
        assert!(
            err.to_string()
                .contains("directive must start with 'install'")
        );

        let err2 =
            process_install_line("Install -m644 \"foo\" to \"/\"", base, "work", false, None)
                .expect_err("Install must fail");
        assert!(
            err2.to_string()
                .contains("directive must start with 'install'")
        );
    }

    #[test]
    fn test_process_install_line_rejects_missing_arguments() {
        let base = Path::new("pkg");
        let err = process_install_line("install", base, "work", false, None)
            .expect_err("install without args must fail");
        assert!(err.to_string().contains("missing arguments"));
    }

    #[test]
    fn test_process_install_line_rejects_missing_source() {
        let base = Path::new("pkg");
        let err = process_install_line("install -m755", base, "work", false, None)
            .expect_err("install without source must fail");
        assert!(err.to_string().contains("missing source file"));
    }

    #[test]
    fn test_process_install_line_rejects_missing_destination() {
        let base = Path::new("pkg");
        let err = process_install_line("install -m644 \"foo\"", base, "work", false, None)
            .expect_err("install without destination must fail when not default_to_root");
        assert!(err.to_string().contains("missing 'to <destination>'"));
    }

    #[test]
    fn test_process_install_line_rejects_invalid_mode() {
        let base = Path::new("pkg");
        let err = process_install_line("install -m888 \"foo\" to \"/\"", base, "work", false, None)
            .expect_err("invalid octal mode must fail");
        assert!(err.to_string().contains("invalid octal permissions mode"));

        let err2 = process_install_line(
            "install -m10000 \"foo\" to \"/\"",
            base,
            "work",
            false,
            None,
        )
        .expect_err("mode > 7777 must fail");
        assert!(err2.to_string().contains("exceeds maximum octal 7777"));
    }
}

use super::build_system::FlatpakBuildSystem;
use super::format::FlatpakManifestFormat;
use super::module::FlatpakModule;
use super::source::FlatpakSource;
use crate::metadata::Metadata;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

/// High-level representation of a Flatpak application manifest (`app-id.json` or `app-id.yaml`).
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub struct FlatpakApplication {
    pub app_id: String,
    pub runtime: String,
    pub runtime_version: String,
    pub sdk: String,
    pub command: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub finish_args: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub modules: Vec<FlatpakModule>,
}

impl FlatpakApplication {
    /// Construct a `FlatpakApplication` manifest model from `Metadata`.
    pub fn from_metadata(metadata: &Metadata, exec_command: &str) -> Self {
        let mut build_cmds = Vec::new();
        for line in &metadata.package_instructions {
            let trimmed = line.trim();
            if trimmed.starts_with("install") {
                // Parse install directive: install -m<mode> <source> [to <dest>]
                let parts: Vec<&str> = trimmed.split_whitespace().collect();
                let mut mode = "644";
                let mut src = "";
                let mut dest = "";
                let mut idx = 1;
                while idx < parts.len() {
                    if parts[idx].starts_with("-m") {
                        mode = parts[idx].trim_start_matches("-m");
                        idx += 1;
                    } else if parts[idx] == "to" {
                        idx += 1;
                        if idx < parts.len() {
                            dest = parts[idx];
                            idx += 1;
                        }
                    } else if src.is_empty() {
                        src = parts[idx];
                        idx += 1;
                    } else {
                        idx += 1;
                    }
                }

                if !src.is_empty() {
                    let clean_src = src.trim_matches('"');
                    let mut app_dest = if dest.is_empty() {
                        "/app/bin/".to_string()
                    } else {
                        dest.trim_matches('"')
                            .replace("/usr/local/", "/app/")
                            .replace("/usr/", "/app/")
                    };
                    if app_dest.ends_with('/') {
                        let filename = Path::new(clean_src)
                            .file_name()
                            .and_then(|n| n.to_str())
                            .unwrap_or("");
                        app_dest.push_str(filename);
                    }
                    build_cmds.push(format!(
                        "install -D -m{} \"{}\" \"{}\"",
                        mode, clean_src, app_dest
                    ));
                }
            }
        }
        if build_cmds.is_empty() {
            build_cmds.push(format!(
                "install -D -m755 {} /app/bin/{}",
                exec_command, exec_command
            ));
        }

        let source_url = metadata.sources.first().cloned().unwrap_or_default();
        let source_sha = metadata.sha256sums.first().cloned().unwrap_or_default();

        let source = FlatpakSource::new_archive(source_url, source_sha);

        let mut module = FlatpakModule::new(&metadata.name, FlatpakBuildSystem::Simple);
        module.build_commands = build_cmds;
        module.sources = vec![source];

        Self {
            app_id: metadata.flatpak_id(),
            runtime: metadata.flatpak_runtime.clone(),
            runtime_version: metadata.flatpak_runtime_version.clone(),
            sdk: metadata.flatpak_sdk.clone(),
            command: exec_command.to_string(),
            finish_args: vec![
                "--share=ipc".to_string(),
                "--socket=x11".to_string(),
                "--socket=wayland".to_string(),
                "--socket=fallback-x11".to_string(),
                "--share=network".to_string(),
                "--socket=pulseaudio".to_string(),
                "--device=all".to_string(),
            ],
            modules: vec![module],
        }
    }

    /// Serialize to JSON format.
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }

    /// Serialize to YAML format.
    pub fn to_yaml(&self) -> Result<String, serde_yaml::Error> {
        serde_yaml::to_string(self)
    }

    /// Dump to string according to `FlatpakManifestFormat`.
    pub fn dump(
        &self,
        format: FlatpakManifestFormat,
    ) -> Result<String, Box<dyn std::error::Error>> {
        format.dump(self)
    }

    /// Parse from file path (auto-detects JSON vs YAML).
    pub fn load_from_file<P: AsRef<Path>>(path: P) -> Result<Self, Box<dyn std::error::Error>> {
        let content = fs::read_to_string(path.as_ref())?;
        let format = FlatpakManifestFormat::from_path(&path.as_ref().to_string_lossy())
            .unwrap_or(FlatpakManifestFormat::JSON);
        format.parse(&content)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bundle::linux::flatpak::build_system::FlatpakBuildSystem;
    use crate::bundle::linux::flatpak::source::FlatpakSource;

    #[test]
    fn test_flatpak_application_json_and_yaml() {
        let app = FlatpakApplication {
            app_id: "org.example.TestApp".to_string(),
            runtime: "org.freedesktop.Platform".to_string(),
            runtime_version: "24.08".to_string(),
            sdk: "org.freedesktop.Sdk".to_string(),
            command: "testapp".to_string(),
            finish_args: vec!["--socket=x11".to_string(), "--share=network".to_string()],
            modules: vec![FlatpakModule {
                name: "testapp".to_string(),
                buildsystem: FlatpakBuildSystem::Simple,
                build_commands: vec!["install -D -m755 testapp /app/bin/testapp".to_string()],
                sources: vec![FlatpakSource::new_archive(
                    "https://example.com/test.tar.gz",
                    "123456",
                )],
                ..Default::default()
            }],
        };

        // Test JSON roundtrip
        let json_str = app.to_json().expect("serialize to JSON");
        assert!(json_str.contains("\"app-id\": \"org.example.TestApp\""));
        let parsed_json: FlatpakApplication = FlatpakManifestFormat::JSON
            .parse(&json_str)
            .expect("parse JSON");
        assert_eq!(parsed_json.app_id, app.app_id);
        assert_eq!(parsed_json.modules.len(), 1);

        // Test YAML roundtrip
        let yaml_str = app.to_yaml().expect("serialize to YAML");
        assert!(yaml_str.contains("app-id: org.example.TestApp"));
        let parsed_yaml: FlatpakApplication = FlatpakManifestFormat::YAML
            .parse(&yaml_str)
            .expect("parse YAML");
        assert_eq!(parsed_yaml.app_id, app.app_id);
        assert_eq!(parsed_yaml.modules[0].name, "testapp");
    }
}

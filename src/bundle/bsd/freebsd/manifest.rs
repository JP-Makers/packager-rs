use crate::metadata::Metadata;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Represents a package dependency in FreeBSD's `+MANIFEST`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FreeBSDDep {
    pub origin: String,
    pub version: String,
}

/// Represents the FreeBSD `+MANIFEST` and `+COMPACT_MANIFEST` UCL/JSON metadata structure.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FreeBSDManifest {
    pub name: String,
    pub version: String,
    pub origin: String,
    pub comment: String,
    pub desc: String,
    pub maintainer: String,
    pub www: String,
    pub abi: String,
    pub arch: String,
    pub prefix: String,
    pub flatsize: u64,
    pub licenselogic: String,
    pub licenses: Vec<String>,
    pub categories: Vec<String>,
    #[serde(skip_serializing_if = "BTreeMap::is_empty", default)]
    pub deps: BTreeMap<String, FreeBSDDep>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub files: Option<BTreeMap<String, String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scripts: Option<BTreeMap<String, String>>,
}

impl FreeBSDManifest {
    /// Constructs a FreeBSDManifest instance from package `Metadata` and collected payload info.
    pub fn from_metadata(
        metadata: &Metadata,
        flatsize: u64,
        files: BTreeMap<String, String>,
        has_desktop_or_icons: bool,
    ) -> Self {
        let maintainer = if !metadata.email.is_empty() {
            metadata.email.clone()
        } else if !metadata.maintainer.is_empty() {
            metadata.maintainer.clone()
        } else {
            "root@localhost".to_string()
        };

        let mut deps = BTreeMap::new();
        for dep_str in &metadata.freebsd_depends {
            let trimmed = dep_str.trim();
            if trimmed.is_empty() {
                continue;
            }
            if let Some((origin_cat, pkg_name)) = trimmed.split_once('/') {
                deps.insert(
                    pkg_name.to_string(),
                    FreeBSDDep {
                        origin: format!("{}/{}", origin_cat, pkg_name),
                        version: ">=0".to_string(),
                    },
                );
            } else {
                deps.insert(
                    trimmed.to_string(),
                    FreeBSDDep {
                        origin: format!("misc/{}", trimmed),
                        version: ">=0".to_string(),
                    },
                );
            }
        }

        let scripts = if has_desktop_or_icons {
            let mut s = BTreeMap::new();
            let hook = "if [ -x /usr/local/bin/update-desktop-database ]; then /usr/local/bin/update-desktop-database -q /usr/local/share/applications || true; fi\nif [ -x /usr/local/bin/gtk-update-icon-cache ]; then /usr/local/bin/gtk-update-icon-cache -q -t -f /usr/local/share/icons/hicolor 2>/dev/null || true; fi\n";
            s.insert("post-install".to_string(), hook.to_string());
            s.insert("post-deinstall".to_string(), hook.to_string());
            Some(s)
        } else {
            None
        };

        let license = if !metadata.license.is_empty() {
            metadata.license.clone()
        } else {
            "unknown".to_string()
        };

        Self {
            name: metadata.name.clone(),
            version: metadata.version.clone(),
            origin: metadata.freebsd_origin(),
            comment: metadata.description.clone(),
            desc: metadata.description.clone(),
            maintainer,
            www: metadata.url.clone(),
            abi: metadata.freebsd_abi(),
            arch: metadata.freebsd_pkg_arch(),
            prefix: metadata.freebsd_prefix.clone(),
            flatsize,
            licenselogic: "single".to_string(),
            licenses: vec![license],
            categories: metadata.freebsd_categories(),
            deps,
            files: Some(files),
            scripts,
        }
    }

    /// Serialize full `+MANIFEST` JSON string with file checksums and scripts.
    pub fn to_manifest_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }

    /// Serialize compact `+COMPACT_MANIFEST` JSON string omitting files and scripts.
    pub fn to_compact_json(&self) -> Result<String, serde_json::Error> {
        let mut compact = self.clone();
        compact.files = None;
        compact.scripts = None;
        serde_json::to_string_pretty(&compact)
    }

    /// Formats the `+DESC` file content.
    pub fn to_desc(&self) -> String {
        format!("{}\n\nWWW: {}\n", self.desc, self.www)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_freebsd_manifest_generation() {
        let metadata = Metadata {
            name: "sample-app".to_string(),
            version: "1.2.3".to_string(),
            release: "1".to_string(),
            maintainer: "FreeBSD Porter".to_string(),
            email: "porter@freebsd.org".to_string(),
            description: "A sample application for FreeBSD".to_string(),
            arch: vec!["x86_64".to_string()],
            url: "https://example.com/app".to_string(),
            license: "BSD2CLAUSE".to_string(),
            freebsd_origin: "sysutils/sample-app".to_string(),
            freebsd_categories: vec!["sysutils".to_string(), "devel".to_string()],
            freebsd_depends: vec!["devel/gettext-runtime".to_string(), "curl".to_string()],
            ..Default::default()
        };

        let mut files = BTreeMap::new();
        files.insert(
            "/usr/local/bin/sample-app".to_string(),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855".to_string(),
        );

        let manifest = FreeBSDManifest::from_metadata(&metadata, 10240, files, true);

        // Test +MANIFEST
        let full_json = manifest
            .to_manifest_json()
            .expect("full manifest should serialize");
        assert!(full_json.contains("\"name\": \"sample-app\""));
        assert!(full_json.contains("\"origin\": \"sysutils/sample-app\""));
        assert!(full_json.contains("\"abi\": \"FreeBSD:14:amd64\""));
        assert!(full_json.contains("\"arch\": \"freebsd:14:x86:64\""));
        assert!(full_json.contains("/usr/local/bin/sample-app"));
        assert!(
            full_json.contains("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
        );
        assert!(full_json.contains("post-install"));

        // Test +COMPACT_MANIFEST
        let compact_json = manifest
            .to_compact_json()
            .expect("compact manifest should serialize");
        assert!(compact_json.contains("\"name\": \"sample-app\""));
        assert!(!compact_json.contains("files"));
        assert!(!compact_json.contains("post-install"));

        // Test +DESC
        let desc = manifest.to_desc();
        assert!(desc.contains("A sample application for FreeBSD"));
        assert!(desc.contains("WWW: https://example.com/app"));
    }
}

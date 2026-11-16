use crate::metadata::Metadata;
use xml::reader::EventReader;
use xml::writer::{EmitterConfig, XmlEvent};

/// Validate that an XML string is syntactically well-formed using `xml::reader::EventReader`.
pub fn validate_plist_xml(xml_str: &str) -> Result<(), Box<dyn std::error::Error>> {
    let reader = EventReader::from_str(xml_str);
    for event in reader {
        event?;
    }
    Ok(())
}

fn write_key_string<W: std::io::Write>(
    writer: &mut xml::writer::EventWriter<W>,
    key: &str,
    val: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    writer.write(XmlEvent::start_element("key"))?;
    writer.write(XmlEvent::characters(key))?;
    writer.write(XmlEvent::end_element())?;
    writer.write(XmlEvent::start_element("string"))?;
    writer.write(XmlEvent::characters(val))?;
    writer.write(XmlEvent::end_element())?;
    Ok(())
}

fn write_key_bool<W: std::io::Write>(
    writer: &mut xml::writer::EventWriter<W>,
    key: &str,
    val: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    writer.write(XmlEvent::start_element("key"))?;
    writer.write(XmlEvent::characters(key))?;
    writer.write(XmlEvent::end_element())?;
    writer.write(XmlEvent::start_element(if val { "true" } else { "false" }))?;
    writer.write(XmlEvent::end_element())?;
    Ok(())
}

/// Generate the contents of `Contents/Info.plist` for the macOS application bundle using the `xml` crate.
pub fn generate_info_plist(
    metadata: &Metadata,
    executable_name: &str,
    icon_name: Option<&str>,
) -> String {
    let display_name = metadata.app_name();
    let bundle_id = metadata.mac_bundle_id();
    let version = &metadata.version;
    let min_sys_ver = if metadata.mac_min_system_version.is_empty() {
        "11.0"
    } else {
        &metadata.mac_min_system_version
    };
    let category = if metadata.mac_category.is_empty() {
        "public.app-category.developer-tools"
    } else {
        &metadata.mac_category
    };

    let copyright = if !metadata.maintainer.is_empty() {
        format!("Copyright © {}. All rights reserved.", metadata.maintainer)
    } else {
        format!("Copyright © {}. All rights reserved.", display_name)
    };

    let mut body_bytes = Vec::new();
    {
        let mut writer = EmitterConfig::new()
            .perform_indent(true)
            .indent_string("    ")
            .write_document_declaration(false)
            .create_writer(&mut body_bytes);

        // <plist version="1.0">
        writer
            .write(XmlEvent::start_element("plist").attr("version", "1.0"))
            .expect("Failed to write plist start");
        // <dict>
        writer
            .write(XmlEvent::start_element("dict"))
            .expect("Failed to write dict start");

        write_key_string(&mut writer, "CFBundleDevelopmentRegion", "en")
            .expect("Failed to write CFBundleDevelopmentRegion");
        write_key_string(&mut writer, "CFBundleDisplayName", &display_name)
            .expect("Failed to write CFBundleDisplayName");
        write_key_string(&mut writer, "CFBundleExecutable", executable_name)
            .expect("Failed to write CFBundleExecutable");

        if let Some(icon) = icon_name {
            let clean_icon = icon.strip_suffix(".icns").unwrap_or(icon);
            if !clean_icon.is_empty() {
                write_key_string(&mut writer, "CFBundleIconFile", clean_icon)
                    .expect("Failed to write CFBundleIconFile");
            }
        }

        write_key_string(&mut writer, "CFBundleIdentifier", &bundle_id)
            .expect("Failed to write CFBundleIdentifier");
        write_key_string(&mut writer, "CFBundleInfoDictionaryVersion", "6.0")
            .expect("Failed to write CFBundleInfoDictionaryVersion");
        write_key_string(&mut writer, "CFBundleName", &display_name)
            .expect("Failed to write CFBundleName");
        write_key_string(&mut writer, "CFBundlePackageType", "APPL")
            .expect("Failed to write CFBundlePackageType");
        write_key_string(&mut writer, "CFBundleShortVersionString", version)
            .expect("Failed to write CFBundleShortVersionString");
        write_key_string(&mut writer, "CFBundleSignature", "????")
            .expect("Failed to write CFBundleSignature");
        write_key_string(&mut writer, "CFBundleVersion", version)
            .expect("Failed to write CFBundleVersion");
        write_key_string(&mut writer, "LSApplicationCategoryType", category)
            .expect("Failed to write LSApplicationCategoryType");
        write_key_string(&mut writer, "LSMinimumSystemVersion", min_sys_ver)
            .expect("Failed to write LSMinimumSystemVersion");
        write_key_bool(&mut writer, "NSHighResolutionCapable", true)
            .expect("Failed to write NSHighResolutionCapable");
        write_key_bool(&mut writer, "NSRequiresAquaSystemAppearance", false)
            .expect("Failed to write NSRequiresAquaSystemAppearance");
        write_key_string(&mut writer, "NSHumanReadableCopyright", &copyright)
            .expect("Failed to write NSHumanReadableCopyright");

        // </dict>
        writer
            .write(XmlEvent::end_element())
            .expect("Failed to write dict end");
        // </plist>
        writer
            .write(XmlEvent::end_element())
            .expect("Failed to write plist end");
    }

    let body_str = String::from_utf8(body_bytes).expect("Valid UTF-8 XML");

    let full_xml = format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n{}\n",
        body_str
    );

    // Validate the generated XML using xml-rs reader
    validate_plist_xml(&full_xml).expect("Generated plist XML must be well-formed");

    full_xml
}

/// Generate the contents of `Contents/PkgInfo` (exactly 8 bytes: `APPL????`).
pub fn generate_pkg_info() -> &'static [u8] {
    b"APPL????"
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pkg_info() {
        assert_eq!(generate_pkg_info(), b"APPL????");
    }

    #[test]
    fn test_generate_info_plist() {
        let metadata = Metadata {
            name: "testapp".to_string(),
            version: "1.2.3".to_string(),
            maintainer: "Test Dev & Co".to_string(),
            ..Default::default()
        };

        let plist = generate_info_plist(&metadata, "testapp", Some("icon.icns"));
        assert!(plist.contains("<key>CFBundleDisplayName</key>"));
        assert!(plist.contains("<string>Testapp</string>"));
        assert!(plist.contains("<key>CFBundleExecutable</key>"));
        assert!(plist.contains("<string>testapp</string>"));
        assert!(plist.contains("<key>CFBundleIconFile</key>"));
        assert!(plist.contains("<string>icon</string>"));
        assert!(plist.contains("<key>CFBundleShortVersionString</key>"));
        assert!(plist.contains("<string>1.2.3</string>"));
        assert!(plist.contains("<key>CFBundlePackageType</key>"));
        assert!(plist.contains("<string>APPL</string>"));
        assert!(plist.contains("Copyright © Test Dev &amp; Co. All rights reserved."));

        // Validate via reader
        assert!(validate_plist_xml(&plist).is_ok());
    }
}

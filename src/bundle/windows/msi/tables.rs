// Standard Windows Installer relational database table definitions and insertion logic.

use msi::{Column, Insert, Package, Value};
use std::io::{Read, Seek, Write};

pub type ShortcutRecord<'a> = (&'a str, &'a str, &'a str, &'a str, &'a str, Option<&'a str>);

pub struct TableSetup;

impl TableSetup {
    /// Create and populate the Property table.
    pub fn setup_property_table<F: Read + Write + Seek>(
        pkg: &mut Package<F>,
        properties: &[(&str, &str)],
    ) -> Result<(), Box<dyn std::error::Error>> {
        let columns = vec![
            Column::build("Property").primary_key().id_string(72),
            Column::build("Value").nullable().formatted_string(255),
        ];
        pkg.create_table("Property", columns)?;

        let mut insert = Insert::into("Property");
        for &(prop, val) in properties {
            insert = insert.row(vec![Value::from(prop), Value::from(val)]);
        }
        pkg.insert_rows(insert)?;
        Ok(())
    }

    /// Create and populate the Directory table.
    pub fn setup_directory_table<F: Read + Write + Seek>(
        pkg: &mut Package<F>,
        directories: &[(&str, Option<&str>, &str)],
    ) -> Result<(), Box<dyn std::error::Error>> {
        let columns = vec![
            Column::build("Directory").primary_key().id_string(72),
            Column::build("Directory_Parent").nullable().id_string(72),
            Column::build("DefaultDir").formatted_string(255),
        ];
        pkg.create_table("Directory", columns)?;

        let mut insert = Insert::into("Directory");
        for &(dir, parent, default_dir) in directories {
            let parent_val = match parent {
                Some(p) => Value::from(p),
                None => Value::Null,
            };
            insert = insert.row(vec![Value::from(dir), parent_val, Value::from(default_dir)]);
        }
        pkg.insert_rows(insert)?;
        Ok(())
    }

    /// Create and populate the Component table.
    pub fn setup_component_table<F: Read + Write + Seek>(
        pkg: &mut Package<F>,
        components: &[(&str, &str, &str, i16, Option<&str>)],
    ) -> Result<(), Box<dyn std::error::Error>> {
        let columns = vec![
            Column::build("Component").primary_key().id_string(72),
            Column::build("ComponentId").nullable().string(38),
            Column::build("Directory_").id_string(72),
            Column::build("Attributes").int16(),
            Column::build("Condition").nullable().formatted_string(255),
            Column::build("KeyPath").nullable().id_string(72),
        ];
        pkg.create_table("Component", columns)?;

        let mut insert = Insert::into("Component");
        for &(comp, comp_id, dir, attr, keypath) in components {
            let kp_val = match keypath {
                Some(kp) => Value::from(kp),
                None => Value::Null,
            };
            insert = insert.row(vec![
                Value::from(comp),
                Value::from(comp_id),
                Value::from(dir),
                Value::from(attr),
                Value::Null,
                kp_val,
            ]);
        }
        pkg.insert_rows(insert)?;
        Ok(())
    }

    /// Create and populate the File table.
    pub fn setup_file_table<F: Read + Write + Seek>(
        pkg: &mut Package<F>,
        files: &[(&str, &str, &str, i32, i16)],
    ) -> Result<(), Box<dyn std::error::Error>> {
        let columns = vec![
            Column::build("File").primary_key().id_string(72),
            Column::build("Component_").id_string(72),
            Column::build("FileName").formatted_string(255),
            Column::build("FileSize").int32(),
            Column::build("Version").nullable().formatted_string(72),
            Column::build("Language").nullable().formatted_string(20),
            Column::build("Attributes").nullable().int16(),
            Column::build("Sequence").int16(),
        ];
        pkg.create_table("File", columns)?;

        let mut insert = Insert::into("File");
        for &(file_id, comp_id, file_name, file_size, seq) in files {
            insert = insert.row(vec![
                Value::from(file_id),
                Value::from(comp_id),
                Value::from(file_name),
                Value::from(file_size),
                Value::Null,
                Value::Null,
                Value::from(512i16), // 512 = msidbFileAttributesCompressed
                Value::from(seq),
            ]);
        }
        pkg.insert_rows(insert)?;
        Ok(())
    }

    /// Create and populate the Media table.
    pub fn setup_media_table<F: Read + Write + Seek>(
        pkg: &mut Package<F>,
        last_sequence: i16,
        cab_name: &str,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let columns = vec![
            Column::build("DiskId").primary_key().int16(),
            Column::build("LastSequence").int16(),
            Column::build("DiskPrompt").nullable().formatted_string(64),
            Column::build("Cabinet").nullable().formatted_string(64),
            Column::build("VolumeLabel").nullable().formatted_string(32),
            Column::build("Source").nullable().formatted_string(72),
        ];
        pkg.create_table("Media", columns)?;

        let insert = Insert::into("Media").row(vec![
            Value::from(1i16),
            Value::from(last_sequence),
            Value::Null,
            Value::from(cab_name),
            Value::Null,
            Value::Null,
        ]);
        pkg.insert_rows(insert)?;
        Ok(())
    }

    /// Create and populate the Feature table.
    pub fn setup_feature_table<F: Read + Write + Seek>(
        pkg: &mut Package<F>,
        feature_name: &str,
        title: &str,
        description: &str,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let columns = vec![
            Column::build("Feature").primary_key().id_string(38),
            Column::build("Feature_Parent").nullable().id_string(38),
            Column::build("Title").nullable().formatted_string(64),
            Column::build("Description").nullable().formatted_string(255),
            Column::build("Display").nullable().int16(),
            Column::build("Level").int16(),
            Column::build("Directory_").nullable().id_string(72),
            Column::build("Attributes").int16(),
        ];
        pkg.create_table("Feature", columns)?;

        let insert = Insert::into("Feature").row(vec![
            Value::from(feature_name),
            Value::Null,
            Value::from(title),
            Value::from(description),
            Value::from(2i16),
            Value::from(1i16),
            Value::from("INSTALLFOLDER"),
            Value::from(0i16),
        ]);
        pkg.insert_rows(insert)?;
        Ok(())
    }

    /// Create and populate the FeatureComponents table.
    pub fn setup_feature_components_table<F: Read + Write + Seek>(
        pkg: &mut Package<F>,
        feature_name: &str,
        component_ids: &[&str],
    ) -> Result<(), Box<dyn std::error::Error>> {
        let columns = vec![
            Column::build("Feature_").primary_key().id_string(38),
            Column::build("Component_").primary_key().id_string(72),
        ];
        pkg.create_table("FeatureComponents", columns)?;

        let mut insert = Insert::into("FeatureComponents");
        for &comp in component_ids {
            insert = insert.row(vec![Value::from(feature_name), Value::from(comp)]);
        }
        pkg.insert_rows(insert)?;
        Ok(())
    }

    /// Create and populate the Shortcut table.
    pub fn setup_shortcut_table<F: Read + Write + Seek>(
        pkg: &mut Package<F>,
        shortcuts: &[ShortcutRecord<'_>],
    ) -> Result<(), Box<dyn std::error::Error>> {
        let columns = vec![
            Column::build("Shortcut").primary_key().id_string(72),
            Column::build("Directory_").id_string(72),
            Column::build("Name").formatted_string(128),
            Column::build("Component_").id_string(72),
            Column::build("Target").formatted_string(72),
            Column::build("Arguments").nullable().formatted_string(255),
            Column::build("Description").nullable().formatted_string(255),
            Column::build("Hotkey").nullable().int16(),
            Column::build("Icon_").nullable().id_string(72),
            Column::build("IconIndex").nullable().int16(),
            Column::build("ShowCmd").nullable().int16(),
            Column::build("WkDir").nullable().id_string(72),
        ];
        pkg.create_table("Shortcut", columns)?;

        let mut insert = Insert::into("Shortcut");
        for &(sc_id, dir, name, comp, target, icon) in shortcuts {
            let (icon_val, icon_idx) = match icon {
                Some(ic) => (Value::from(ic), Value::from(0i16)),
                None => (Value::Null, Value::Null),
            };
            insert = insert.row(vec![
                Value::from(sc_id),
                Value::from(dir),
                Value::from(name),
                Value::from(comp),
                Value::from(target),
                Value::Null,
                Value::Null,
                Value::Null,
                icon_val,
                icon_idx,
                Value::Null,
                Value::from("INSTALLFOLDER"),
            ]);
        }
        pkg.insert_rows(insert)?;
        Ok(())
    }

    /// Create and populate the InstallExecuteSequence table.
    pub fn setup_install_execute_sequence_table<F: Read + Write + Seek>(
        pkg: &mut Package<F>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let columns = vec![
            Column::build("Action").primary_key().id_string(72),
            Column::build("Condition").nullable().formatted_string(255),
            Column::build("Sequence").nullable().int16(),
        ];
        pkg.create_table("InstallExecuteSequence", columns)?;

        let standard_actions: &[(&str, Option<&str>, i16)] = &[
            ("CostInitialize", None, 800),
            ("FileCost", None, 900),
            ("CostFinalize", None, 1000),
            ("InstallValidate", None, 1400),
            ("InstallInitialize", None, 1500),
            ("ProcessComponents", None, 1600),
            ("UnpublishFeatures", None, 1800),
            ("RemoveFiles", None, 3500),
            ("InstallFiles", None, 4000),
            ("CreateShortcuts", None, 4500),
            ("RegisterUser", None, 6000),
            ("RegisterProduct", None, 6100),
            ("PublishFeatures", None, 6300),
            ("PublishProduct", None, 6400),
            ("InstallFinalize", None, 6600),
        ];

        let mut insert = Insert::into("InstallExecuteSequence");
        for &(action, cond, seq) in standard_actions {
            let cond_val = match cond {
                Some(c) => Value::from(c),
                None => Value::Null,
            };
            insert = insert.row(vec![Value::from(action), cond_val, Value::from(seq)]);
        }
        pkg.insert_rows(insert)?;
        Ok(())
    }

    /// Create and populate the AdminExecuteSequence table.
    pub fn setup_admin_execute_sequence_table<F: Read + Write + Seek>(
        pkg: &mut Package<F>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let columns = vec![
            Column::build("Action").primary_key().id_string(72),
            Column::build("Condition").nullable().formatted_string(255),
            Column::build("Sequence").nullable().int16(),
        ];
        pkg.create_table("AdminExecuteSequence", columns)?;

        let admin_actions: &[(&str, Option<&str>, i16)] = &[
            ("CostInitialize", None, 800),
            ("FileCost", None, 900),
            ("CostFinalize", None, 1000),
            ("InstallValidate", None, 1400),
            ("InstallInitialize", None, 1500),
            ("InstallAdminPackage", None, 3900),
            ("InstallFiles", None, 4000),
            ("InstallFinalize", None, 6600),
        ];

        let mut insert = Insert::into("AdminExecuteSequence");
        for &(action, cond, seq) in admin_actions {
            let cond_val = match cond {
                Some(c) => Value::from(c),
                None => Value::Null,
            };
            insert = insert.row(vec![Value::from(action), cond_val, Value::from(seq)]);
        }
        pkg.insert_rows(insert)?;
        Ok(())
    }

    /// Create and populate the Icon table.
    pub fn setup_icon_table<F: Read + Write + Seek>(
        pkg: &mut Package<F>,
        icon_name: &str,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let columns = vec![
            Column::build("Name").primary_key().id_string(72),
            Column::build("Data").binary(),
        ];
        pkg.create_table("Icon", columns)?;

        let insert = Insert::into("Icon").row(vec![Value::from(icon_name), Value::Binary]);
        pkg.insert_rows(insert)?;
        Ok(())
    }
}

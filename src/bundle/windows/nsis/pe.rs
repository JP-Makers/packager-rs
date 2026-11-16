// Pure-Rust Windows Portable Executable (PE) and Self-Extracting installer builder for NSIS.
// Generates native PE32 GUI executables with authentic NSIS architecture matching nsis-dev/nsis:
// embedded NSIS FirstHeader (0xDEADBEEF / NullsoftInst), Resource Directory (.rsrc with XML
// manifest, VS_VERSION_INFO, and application icon), runtime variables section (.ndata),
// silent mode argument parsing (/S or /s), and x86 machine code that self-extracts files.
// Strictly no external tools or commands required.

// ═══════════════════════════════════════════════════════════════════════════
// Official NSIS Binary Architecture Constants & Structures (fileform.h)
// ═══════════════════════════════════════════════════════════════════════════

/// NSIS FirstHeader signature: 0xDEADBEEF
pub const FH_SIG: u32 = 0xDEAD_BEEF;

/// NSIS FirstHeader magic DWORD 1: "Null" in little-endian (0x6C6C754E)
pub const FH_INT1: u32 = 0x6C6C_754E;
/// NSIS FirstHeader magic DWORD 2: "soft" in little-endian (0x74666F73)
pub const FH_INT2: u32 = 0x7466_6F73;
/// NSIS FirstHeader magic DWORD 3: "Inst" in little-endian (0x74736E49)
pub const FH_INT3: u32 = 0x7473_6E49;

/// NSIS FirstHeader flags: no CRC check
pub const FH_FLAGS_NO_CRC: i32 = 4;

/// NSIS firstheader (28 bytes) matching Source/exehead/fileform.h
#[repr(C, packed)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NsisFirstHeader {
    pub flags: i32,
    pub siginfo: u32,
    pub nsinst: [u32; 3],
    pub length_of_header: i32,
    pub length_of_all_following_data: i32,
}

impl NsisFirstHeader {
    pub fn to_bytes(self) -> [u8; 28] {
        let mut buf = [0u8; 28];
        buf[0..4].copy_from_slice(&self.flags.to_le_bytes());
        buf[4..8].copy_from_slice(&self.siginfo.to_le_bytes());
        buf[8..12].copy_from_slice(&self.nsinst[0].to_le_bytes());
        buf[12..16].copy_from_slice(&self.nsinst[1].to_le_bytes());
        buf[16..20].copy_from_slice(&self.nsinst[2].to_le_bytes());
        buf[20..24].copy_from_slice(&self.length_of_header.to_le_bytes());
        buf[24..28].copy_from_slice(&self.length_of_all_following_data.to_le_bytes());
        buf
    }
}

/// A file entry to embed into the executable installer.
pub struct PeFileEntry<'a> {
    pub name: &'a str,
    pub data: &'a [u8],
}

/// NSIS installer configuration embedded into the PE data section and resource section.
pub struct NsisInstallerConfig<'a> {
    pub app_name: &'a str,
    pub version: &'a str,
    pub manufacturer: &'a str,
    pub install_dir: &'a str,
    pub main_exe: &'a str,
    pub icon_bytes: Option<&'a [u8]>,
    pub embed_first_header: bool,
}

impl<'a> Default for NsisInstallerConfig<'a> {
    fn default() -> Self {
        Self {
            app_name: "Application",
            version: "1.0.0",
            manufacturer: "Unknown",
            install_dir: "Application",
            main_exe: "app.exe",
            icon_bytes: None,
            embed_first_header: false,
        }
    }
}

/// Standard IEEE 802.3 CRC32 checksum.
pub fn crc32(data: &[u8]) -> u32 {
    let mut crc = 0xffff_ffffu32;
    for &byte in data {
        crc ^= byte as u32;
        for _ in 0..8 {
            let mask = (crc & 1) != 0;
            crc >>= 1;
            if mask {
                crc ^= 0xedb8_8320;
            }
        }
    }
    !crc
}

// ─── PE Layout Constants ────────────────────────────────────────────
// FileAlignment = 0x200 (512 bytes), SectionAlignment = 0x1000 (4096 bytes).
//
// Section layout:
//   Offset 0x0000: DOS + PE + COFF + Optional + Section Table (512 bytes)
//   Offset 0x0200: .text  section (x86 extraction code + silent check) -> RVA 0x1000
//   Offset 0x0600: .data  section (strings/configuration)             -> RVA 0x2000
//   Offset 0x0A00: .idata section (Import Directory & IAT)            -> RVA 0x3000
//   Offset 0x0E00: .rsrc  section (Resource tree: manifest, version, icon) -> RVA 0x4000
//   Offset 0x????: .ndata section (NSIS runtime variables/buffers)    -> RVA after .rsrc
//   After PE: NSIS overlay starts with NsisFirstHeader (28 bytes) + file payload
//
const FILE_ALIGNMENT: u32 = 0x200;
const SECTION_ALIGNMENT: u32 = 0x1000;
const HEADERS_SIZE: u32 = 0x200;
const NUM_SECTIONS: u16 = 5;

const SECTION_FILE_SIZE: u32 = 0x400; // 1024 bytes per standard section
const TEXT_FILE_OFFSET: u32 = 0x200;
const DATA_FILE_OFFSET: u32 = 0x600;
const IDATA_FILE_OFFSET: u32 = 0xA00;
const RSRC_FILE_OFFSET: u32 = 0xE00;

const TEXT_RVA: u32 = 0x1000;
const DATA_RVA: u32 = 0x2000;
const IDATA_RVA: u32 = 0x3000;
const RSRC_RVA: u32 = 0x4000;

const IMAGE_BASE: u32 = 0x0040_0000;

/// Helper: pad a Vec to `alignment` boundary with zeros.
fn pad_to(buf: &mut Vec<u8>, alignment: usize) {
    let rem = buf.len() % alignment;
    if rem != 0 {
        buf.resize(buf.len() + (alignment - rem), 0);
    }
}

/// Helper: write a null-terminated ASCII string into a buffer at a given offset.
fn write_ascii_z(buf: &mut [u8], offset: usize, s: &str) {
    let bytes = s.as_bytes();
    let end = (offset + bytes.len()).min(buf.len() - 1);
    buf[offset..end].copy_from_slice(&bytes[..end - offset]);
    if end < buf.len() {
        buf[end] = 0;
    }
}

/// Converts a UTF-8 string to a null-terminated UTF-16LE byte sequence.
fn to_utf16_le_null(s: &str) -> Vec<u8> {
    let mut v = Vec::with_capacity((s.len() + 1) * 2);
    for ch in s.encode_utf16() {
        v.extend_from_slice(&ch.to_le_bytes());
    }
    v.extend_from_slice(&0u16.to_le_bytes());
    v
}

/// Creates a single String entry for a VS_VERSION_INFO StringTable.
fn make_version_string_entry(key: &str, val: &str) -> Vec<u8> {
    let key_u16 = to_utf16_le_null(key);
    let val_u16 = to_utf16_le_null(val);
    let val_wlen = (val.encode_utf16().count() + 1) as u16;

    let mut entry = Vec::new();
    entry.extend_from_slice(&0u16.to_le_bytes()); // placeholder for wLength
    entry.extend_from_slice(&val_wlen.to_le_bytes()); // wValueLength (in words)
    entry.extend_from_slice(&1u16.to_le_bytes()); // wType = 1 (string)
    entry.extend_from_slice(&key_u16);
    pad_to(&mut entry, 4);
    entry.extend_from_slice(&val_u16);
    pad_to(&mut entry, 4);

    let len = entry.len() as u16;
    entry[0..2].copy_from_slice(&len.to_le_bytes());
    entry
}

/// Generates a binary VS_VERSION_INFO resource blob matching official NSIS ResourceVersionInfo.
pub fn build_version_info(config: &NsisInstallerConfig<'_>) -> Vec<u8> {
    let mut parts = [0u16; 4];
    for (i, p) in config.version.split('.').take(4).enumerate() {
        parts[i] = p.parse::<u16>().unwrap_or(0);
    }
    let v_file_ms = ((parts[0] as u32) << 16) | (parts[1] as u32);
    let v_file_ls = ((parts[2] as u32) << 16) | (parts[3] as u32);

    let mut fixed = Vec::with_capacity(52);
    fixed.extend_from_slice(&0xFEEF_04BDu32.to_le_bytes()); // dwSignature
    fixed.extend_from_slice(&0x0001_0000u32.to_le_bytes()); // dwStrucVersion (1.0)
    fixed.extend_from_slice(&v_file_ms.to_le_bytes());      // dwFileVersionMS
    fixed.extend_from_slice(&v_file_ls.to_le_bytes());      // dwFileVersionLS
    fixed.extend_from_slice(&v_file_ms.to_le_bytes());      // dwProductVersionMS
    fixed.extend_from_slice(&v_file_ls.to_le_bytes());      // dwProductVersionLS
    fixed.extend_from_slice(&0x3Fu32.to_le_bytes());        // dwFileFlagsMask
    fixed.extend_from_slice(&0u32.to_le_bytes());           // dwFileFlags
    fixed.extend_from_slice(&0x0004_0004u32.to_le_bytes()); // dwFileOS: VOS_NT_WINDOWS32
    fixed.extend_from_slice(&0x0000_0001u32.to_le_bytes()); // dwFileType: VFT_APP
    fixed.extend_from_slice(&0u32.to_le_bytes());           // dwFileSubtype
    fixed.extend_from_slice(&0u32.to_le_bytes());           // dwFileDateMS
    fixed.extend_from_slice(&0u32.to_le_bytes());           // dwFileDateLS
    assert_eq!(fixed.len(), 52);

    let copyright = format!("Copyright (C) {}", config.manufacturer);
    let desc = format!("{} Setup", config.app_name);
    let orig_filename = if config.main_exe.ends_with(".exe") {
        config.main_exe.to_string()
    } else {
        format!("{}.exe", config.main_exe)
    };

    let strings = [
        ("CompanyName", config.manufacturer),
        ("FileDescription", &desc),
        ("FileVersion", config.version),
        ("InternalName", config.app_name),
        ("LegalCopyright", &copyright),
        ("OriginalFilename", &orig_filename),
        ("ProductName", config.app_name),
        ("ProductVersion", config.version),
    ];

    let mut st_entries = Vec::new();
    for (k, v) in strings {
        st_entries.extend_from_slice(&make_version_string_entry(k, v));
    }

    // StringTable "040904B0" (US English, Unicode)
    let mut st_block = Vec::new();
    st_block.extend_from_slice(&0u16.to_le_bytes());
    st_block.extend_from_slice(&0u16.to_le_bytes());
    st_block.extend_from_slice(&1u16.to_le_bytes());
    st_block.extend_from_slice(&to_utf16_le_null("040904B0"));
    pad_to(&mut st_block, 4);
    st_block.extend_from_slice(&st_entries);
    let st_len = st_block.len() as u16;
    st_block[0..2].copy_from_slice(&st_len.to_le_bytes());

    // StringFileInfo
    let mut sfi_block = Vec::new();
    sfi_block.extend_from_slice(&0u16.to_le_bytes());
    sfi_block.extend_from_slice(&0u16.to_le_bytes());
    sfi_block.extend_from_slice(&1u16.to_le_bytes());
    sfi_block.extend_from_slice(&to_utf16_le_null("StringFileInfo"));
    pad_to(&mut sfi_block, 4);
    sfi_block.extend_from_slice(&st_block);
    let sfi_len = sfi_block.len() as u16;
    sfi_block[0..2].copy_from_slice(&sfi_len.to_le_bytes());

    // VarFileInfo with Translation [0x0409, 0x04B0]
    let mut var_block = Vec::new();
    var_block.extend_from_slice(&0u16.to_le_bytes());
    var_block.extend_from_slice(&4u16.to_le_bytes()); // 4 bytes of value
    var_block.extend_from_slice(&0u16.to_le_bytes()); // binary
    var_block.extend_from_slice(&to_utf16_le_null("Translation"));
    pad_to(&mut var_block, 4);
    var_block.extend_from_slice(&0x0409u16.to_le_bytes()); // LangID: English US
    var_block.extend_from_slice(&0x04B0u16.to_le_bytes()); // Charset: Unicode
    let var_len = var_block.len() as u16;
    var_block[0..2].copy_from_slice(&var_len.to_le_bytes());

    let mut vfi_block = Vec::new();
    vfi_block.extend_from_slice(&0u16.to_le_bytes());
    vfi_block.extend_from_slice(&0u16.to_le_bytes());
    vfi_block.extend_from_slice(&1u16.to_le_bytes());
    vfi_block.extend_from_slice(&to_utf16_le_null("VarFileInfo"));
    pad_to(&mut vfi_block, 4);
    vfi_block.extend_from_slice(&var_block);
    let vfi_len = vfi_block.len() as u16;
    vfi_block[0..2].copy_from_slice(&vfi_len.to_le_bytes());

    // Root VS_VERSION_INFO
    let mut vi = Vec::new();
    vi.extend_from_slice(&0u16.to_le_bytes());
    vi.extend_from_slice(&(fixed.len() as u16).to_le_bytes());
    vi.extend_from_slice(&0u16.to_le_bytes());
    vi.extend_from_slice(&to_utf16_le_null("VS_VERSION_INFO"));
    pad_to(&mut vi, 4);
    vi.extend_from_slice(&fixed);
    pad_to(&mut vi, 4);
    vi.extend_from_slice(&sfi_block);
    pad_to(&mut vi, 4);
    vi.extend_from_slice(&vfi_block);
    let vi_len = vi.len() as u16;
    vi[0..2].copy_from_slice(&vi_len.to_le_bytes());

    vi
}

/// Generates the official NSIS XML manifest specifying asInvoker, Common-Controls 6.0,
/// and Windows 10/11 compatibility GUIDs matching Source/manifest.cpp.
pub fn build_manifest_xml() -> Vec<u8> {
    let manifest = concat!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>\n",
        "<assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersion=\"1.0\">\n",
        "<assemblyIdentity version=\"1.0.0.0\" processorArchitecture=\"*\" name=\"Nullsoft.NSIS.exehead\" type=\"win32\"/>\n",
        "<description>Nullsoft Install System</description>\n",
        "<dependency>\n",
        "<dependentAssembly>\n",
        "<assemblyIdentity type=\"win32\" name=\"Microsoft.Windows.Common-Controls\" version=\"6.0.0.0\" processorArchitecture=\"*\" publicKeyToken=\"6595b64144ccf1df\" language=\"*\" />\n",
        "</dependentAssembly>\n",
        "</dependency>\n",
        "<trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3\">\n",
        "<security>\n",
        "<requestedPrivileges>\n",
        "<requestedExecutionLevel level=\"asInvoker\" uiAccess=\"false\"/>\n",
        "</requestedPrivileges>\n",
        "</security>\n",
        "</trustInfo>\n",
        "<compatibility xmlns=\"urn:schemas-microsoft-com:compatibility.v1\">\n",
        "<application>\n",
        "<supportedOS Id=\"{8e0f7a12-bfb3-4fe8-b9a5-48fd50a15a9a}\"/>\n",
        "<supportedOS Id=\"{1f676c76-80e1-4239-95bb-83d0f6d0da78}\"/>\n",
        "<supportedOS Id=\"{4a2f28e3-53b9-4441-ba9c-d69d4a4a6e38}\"/>\n",
        "<supportedOS Id=\"{35138b9a-5d96-4fbd-8e2d-a2440225f93a}\"/>\n",
        "<supportedOS Id=\"{e2011457-1546-43c5-a5fe-008deee3d3f0}\"/>\n",
        "</application>\n",
        "</compatibility>\n",
        "</assembly>"
    );
    manifest.as_bytes().to_vec()
}

/// Parses an icon file or generates a fallback icon, returning (RT_ICON image bytes, RT_GROUP_ICON bytes).
fn parse_ico_or_default(icon_bytes: Option<&[u8]>) -> (Vec<u8>, Vec<u8>) {
    let fallback = create_ico(32, 32, 24, 119, 242);
    let bytes = match icon_bytes {
        Some(b) if b.len() >= 22 && b[0..4] == [0, 0, 1, 0] => b,
        _ => &fallback[..],
    };

    let count = u16::from_le_bytes([bytes[4], bytes[5]]) as usize;
    if count == 0 || bytes.len() < 6 + count * 16 {
        return parse_ico_or_default(None);
    }

    let w = bytes[6];
    let h = bytes[7];
    let planes = u16::from_le_bytes([bytes[10], bytes[11]]);
    let bpp = u16::from_le_bytes([bytes[12], bytes[13]]);
    let bytes_in_res = u32::from_le_bytes([bytes[14], bytes[15], bytes[16], bytes[17]]) as usize;
    let img_offset = u32::from_le_bytes([bytes[18], bytes[19], bytes[20], bytes[21]]) as usize;

    if img_offset + bytes_in_res > bytes.len() {
        return parse_ico_or_default(None);
    }

    let icon_image = bytes[img_offset..img_offset + bytes_in_res].to_vec();

    // Build GRPICONDIR (6 bytes) + GRPICONDIRENTRY (14 bytes) = 20 bytes
    let mut grp = Vec::with_capacity(20);
    grp.extend_from_slice(&0u16.to_le_bytes()); // reserved
    grp.extend_from_slice(&1u16.to_le_bytes()); // type (1 = icon)
    grp.extend_from_slice(&1u16.to_le_bytes()); // count = 1
    grp.push(w);
    grp.push(h);
    grp.push(0); // color count
    grp.push(0); // reserved
    grp.extend_from_slice(&planes.to_le_bytes());
    grp.extend_from_slice(&bpp.to_le_bytes());
    grp.extend_from_slice(&(bytes_in_res as u32).to_le_bytes());
    grp.extend_from_slice(&1u16.to_le_bytes()); // nID = 1 (matches RT_ICON ID 1)

    (icon_image, grp)
}

/// Builds a complete 3-level Windows PE Resource (.rsrc) section:
///   Level 1: Root Directory (Types: RT_ICON=3, RT_GROUP_ICON=14, RT_VERSION=16, RT_MANIFEST=24)
///   Level 2: Name Directories (ID: 1)
///   Level 3: Language Directories (Lang: 0 or 0x0409)
///   Level 4: Data Entries (IMAGE_RESOURCE_DATA_ENTRY)
///   Payload: Raw Resource Blobs
pub fn build_resource_section(
    config: &NsisInstallerConfig<'_>,
    icon_bytes: Option<&[u8]>,
    rsrc_rva: u32,
) -> Vec<u8> {
    let manifest_bytes = build_manifest_xml();
    let version_bytes = build_version_info(config);
    let (icon_image, grp_icon_bytes) = parse_ico_or_default(icon_bytes);

    // Sorted by integer Type ID per PE resource specification:
    // 3:  RT_ICON
    // 14: RT_GROUP_ICON
    // 16: RT_VERSION
    // 24: RT_MANIFEST
    let items = [
        (3u32, 1u32, 0u32, &icon_image[..]),
        (14u32, 1u32, 0u32, &grp_icon_bytes[..]),
        (16u32, 1u32, 0x0409u32, &version_bytes[..]),
        (24u32, 1u32, 0u32, &manifest_bytes[..]),
    ];

    // Offsets calculation:
    // Root Directory: 16 bytes header + 4 * 8 bytes entries = 48 bytes (0..48)
    // 4 Type Directories: 4 * (16 + 8) = 96 bytes (48..144)
    // 4 Lang Directories: 4 * (16 + 8) = 96 bytes (144..240)
    // 4 Data Entries: 4 * 16 = 64 bytes (240..304)
    // Raw Blobs start at offset 304 (divisible by 8)
    const DATA_START_OFFSET: usize = 304;

    let mut root = Vec::with_capacity(DATA_START_OFFSET + 4096);
    // IMAGE_RESOURCE_DIRECTORY root
    root.extend_from_slice(&0u32.to_le_bytes()); // Characteristics
    root.extend_from_slice(&0u32.to_le_bytes()); // TimeDateStamp
    root.extend_from_slice(&0u16.to_le_bytes()); // MajorVersion
    root.extend_from_slice(&0u16.to_le_bytes()); // MinorVersion
    root.extend_from_slice(&0u16.to_le_bytes()); // NumberOfNamedEntries
    root.extend_from_slice(&4u16.to_le_bytes()); // NumberOfIdEntries = 4

    let mut type_dirs = Vec::new();
    let mut lang_dirs = Vec::new();
    let mut data_entries = Vec::new();
    let mut raw_blobs = Vec::new();

    for (i, &(type_id, name_id, lang_id, data)) in items.iter().enumerate() {
        let type_dir_off = (48 + i * 24) as u32;
        let lang_dir_off = (144 + i * 24) as u32;
        let data_entry_off = (240 + i * 16) as u32;

        // Root entry
        root.extend_from_slice(&type_id.to_le_bytes());
        root.extend_from_slice(&(0x8000_0000 | type_dir_off).to_le_bytes());

        // Type directory
        type_dirs.extend_from_slice(&0u32.to_le_bytes());
        type_dirs.extend_from_slice(&0u32.to_le_bytes());
        type_dirs.extend_from_slice(&0u16.to_le_bytes());
        type_dirs.extend_from_slice(&0u16.to_le_bytes());
        type_dirs.extend_from_slice(&0u16.to_le_bytes());
        type_dirs.extend_from_slice(&1u16.to_le_bytes());
        type_dirs.extend_from_slice(&name_id.to_le_bytes());
        type_dirs.extend_from_slice(&(0x8000_0000 | lang_dir_off).to_le_bytes());

        // Lang directory
        lang_dirs.extend_from_slice(&0u32.to_le_bytes());
        lang_dirs.extend_from_slice(&0u32.to_le_bytes());
        lang_dirs.extend_from_slice(&0u16.to_le_bytes());
        lang_dirs.extend_from_slice(&0u16.to_le_bytes());
        lang_dirs.extend_from_slice(&0u16.to_le_bytes());
        lang_dirs.extend_from_slice(&1u16.to_le_bytes());
        lang_dirs.extend_from_slice(&lang_id.to_le_bytes());
        lang_dirs.extend_from_slice(&data_entry_off.to_le_bytes()); // points to data entry

        pad_to(&mut raw_blobs, 4);
        let blob_rva = rsrc_rva + (DATA_START_OFFSET + raw_blobs.len()) as u32;
        let blob_len = data.len() as u32;

        // IMAGE_RESOURCE_DATA_ENTRY (16 bytes)
        data_entries.extend_from_slice(&blob_rva.to_le_bytes());
        data_entries.extend_from_slice(&blob_len.to_le_bytes());
        data_entries.extend_from_slice(&0u32.to_le_bytes()); // CodePage
        data_entries.extend_from_slice(&0u32.to_le_bytes()); // Reserved

        raw_blobs.extend_from_slice(data);
    }

    assert_eq!(root.len(), 48);
    assert_eq!(type_dirs.len(), 96);
    assert_eq!(lang_dirs.len(), 96);
    assert_eq!(data_entries.len(), 64);

    let mut rsrc = Vec::with_capacity(DATA_START_OFFSET + raw_blobs.len());
    rsrc.extend_from_slice(&root);
    rsrc.extend_from_slice(&type_dirs);
    rsrc.extend_from_slice(&lang_dirs);
    rsrc.extend_from_slice(&data_entries);
    rsrc.extend_from_slice(&raw_blobs);

    rsrc
}

/// Build the Import Directory Table and Import Lookup/Address Tables for the PE.
///
/// Imports:
///   kernel32.dll: GetModuleFileNameA, CreateFileA, ReadFile, WriteFile,
///                 SetFilePointer, CloseHandle, CreateDirectoryA, ExitProcess,
///                 GetFileSize, LocalAlloc, LocalFree, GetEnvironmentVariableA,
///                 SetCurrentDirectoryA, GetLastError, GetCommandLineA
///   user32.dll:   MessageBoxA
fn build_import_section() -> (Vec<u8>, Vec<(&'static str, u32)>) {
    let mut idata = vec![0u8; SECTION_FILE_SIZE as usize];

    let idt_offset: u32 = 0x000;
    let k32_ilt_offset: u32 = 0x03C;
    let u32_ilt_offset: u32 = 0x0BC;
    let k32_iat_offset: u32 = 0x0C8;
    let u32_iat_offset: u32 = 0x148;
    let hints_offset: u32 = 0x160;

    let kernel32_funcs: &[&str] = &[
        "GetModuleFileNameA",      // 0
        "CreateFileA",             // 1
        "ReadFile",                // 2
        "WriteFile",               // 3
        "SetFilePointer",          // 4
        "CloseHandle",             // 5
        "CreateDirectoryA",        // 6
        "ExitProcess",             // 7
        "GetFileSize",             // 8
        "LocalAlloc",              // 9
        "LocalFree",               // 10
        "GetEnvironmentVariableA", // 11
        "SetCurrentDirectoryA",    // 12
        "GetLastError",            // 13
        "GetCommandLineA",         // 14
    ];
    let user32_funcs: &[&str] = &[
        "MessageBoxA",             // 0
    ];

    let mut cur = hints_offset as usize;
    let mut k32_hint_rvas = Vec::new();
    for (idx, name) in kernel32_funcs.iter().enumerate() {
        k32_hint_rvas.push(IDATA_RVA + cur as u32);
        idata[cur] = idx as u8;
        idata[cur + 1] = 0;
        cur += 2;
        let name_bytes = name.as_bytes();
        idata[cur..cur + name_bytes.len()].copy_from_slice(name_bytes);
        cur += name_bytes.len();
        idata[cur] = 0;
        cur += 1;
        if !cur.is_multiple_of(2) {
            cur += 1;
        }
    }

    let mut u32_hint_rvas = Vec::new();
    for (idx, name) in user32_funcs.iter().enumerate() {
        u32_hint_rvas.push(IDATA_RVA + cur as u32);
        idata[cur] = idx as u8;
        idata[cur + 1] = 0;
        cur += 2;
        let name_bytes = name.as_bytes();
        idata[cur..cur + name_bytes.len()].copy_from_slice(name_bytes);
        cur += name_bytes.len();
        idata[cur] = 0;
        cur += 1;
        if !cur.is_multiple_of(2) {
            cur += 1;
        }
    }

    let k32_name_rva = IDATA_RVA + cur as u32;
    let k32_name = b"kernel32.dll\x00";
    idata[cur..cur + k32_name.len()].copy_from_slice(k32_name);
    cur += k32_name.len();
    if !cur.is_multiple_of(2) {
        cur += 1;
    }

    let u32_name_rva = IDATA_RVA + cur as u32;
    let u32_name = b"user32.dll\x00";
    idata[cur..cur + u32_name.len()].copy_from_slice(u32_name);

    // ILT for kernel32
    for (i, &rva) in k32_hint_rvas.iter().enumerate() {
        let offset = k32_ilt_offset as usize + i * 4;
        idata[offset..offset + 4].copy_from_slice(&rva.to_le_bytes());
    }
    let k32_ilt_null = k32_ilt_offset as usize + k32_hint_rvas.len() * 4;
    idata[k32_ilt_null..k32_ilt_null + 4].copy_from_slice(&0u32.to_le_bytes());

    // ILT for user32
    for (i, &rva) in u32_hint_rvas.iter().enumerate() {
        let offset = u32_ilt_offset as usize + i * 4;
        idata[offset..offset + 4].copy_from_slice(&rva.to_le_bytes());
    }
    let u32_ilt_null = u32_ilt_offset as usize + u32_hint_rvas.len() * 4;
    idata[u32_ilt_null..u32_ilt_null + 4].copy_from_slice(&0u32.to_le_bytes());

    // IAT for kernel32
    for (i, &rva) in k32_hint_rvas.iter().enumerate() {
        let offset = k32_iat_offset as usize + i * 4;
        idata[offset..offset + 4].copy_from_slice(&rva.to_le_bytes());
    }
    let k32_iat_null = k32_iat_offset as usize + k32_hint_rvas.len() * 4;
    idata[k32_iat_null..k32_iat_null + 4].copy_from_slice(&0u32.to_le_bytes());

    // IAT for user32
    for (i, &rva) in u32_hint_rvas.iter().enumerate() {
        let offset = u32_iat_offset as usize + i * 4;
        idata[offset..offset + 4].copy_from_slice(&rva.to_le_bytes());
    }
    let u32_iat_null = u32_iat_offset as usize + u32_hint_rvas.len() * 4;
    idata[u32_iat_null..u32_iat_null + 4].copy_from_slice(&0u32.to_le_bytes());

    // IDT Entry 1: kernel32.dll
    let idt = idt_offset as usize;
    idata[idt..idt + 4].copy_from_slice(&(IDATA_RVA + k32_ilt_offset).to_le_bytes());
    idata[idt + 4..idt + 8].copy_from_slice(&0u32.to_le_bytes());
    idata[idt + 8..idt + 12].copy_from_slice(&0u32.to_le_bytes());
    idata[idt + 12..idt + 16].copy_from_slice(&k32_name_rva.to_le_bytes());
    idata[idt + 16..idt + 20].copy_from_slice(&(IDATA_RVA + k32_iat_offset).to_le_bytes());

    // IDT Entry 2: user32.dll
    let idt2 = idt + 20;
    idata[idt2..idt2 + 4].copy_from_slice(&(IDATA_RVA + u32_ilt_offset).to_le_bytes());
    idata[idt2 + 4..idt2 + 8].copy_from_slice(&0u32.to_le_bytes());
    idata[idt2 + 8..idt2 + 12].copy_from_slice(&0u32.to_le_bytes());
    idata[idt2 + 12..idt2 + 16].copy_from_slice(&u32_name_rva.to_le_bytes());
    idata[idt2 + 16..idt2 + 20].copy_from_slice(&(IDATA_RVA + u32_iat_offset).to_le_bytes());

    // Function RVA map
    let mut func_map = Vec::new();
    for (i, name) in kernel32_funcs.iter().enumerate() {
        func_map.push((*name, IDATA_RVA + k32_iat_offset + (i as u32) * 4));
    }
    for (i, name) in user32_funcs.iter().enumerate() {
        func_map.push((*name, IDATA_RVA + u32_iat_offset + (i as u32) * 4));
    }

    (idata, func_map)
}

/// Build the .data section containing installer metadata strings.
fn build_data_section(config: &NsisInstallerConfig<'_>, file_count: u32) -> Vec<u8> {
    let mut data = vec![0u8; SECTION_FILE_SIZE as usize];

    write_ascii_z(&mut data, 0x000, config.app_name);
    write_ascii_z(&mut data, 0x080, config.version);
    write_ascii_z(&mut data, 0x0A0, config.manufacturer);
    write_ascii_z(&mut data, 0x120, config.install_dir);
    write_ascii_z(&mut data, 0x1A0, config.main_exe);
    write_ascii_z(&mut data, 0x220, "NullsoftInst");
    data[0x238..0x23C].copy_from_slice(&file_count.to_le_bytes());
    write_ascii_z(&mut data, 0x33C, "NSIS Installer");
    write_ascii_z(
        &mut data,
        0x35C,
        "Installation completed successfully!\n\nFiles have been extracted to the installation directory.",
    );
    write_ascii_z(&mut data, 0x39C, "Error");
    write_ascii_z(&mut data, 0x3AC, "Could not complete installation.");
    write_ascii_z(&mut data, 0x3DC, "\\");

    data
}

/// Generate x86 (32-bit) machine code for the self-extracting installer.
/// Features:
/// 1. Command-line parsing: scans GetCommandLineA() for /S or /s to enable silent mode.
/// 2. Header detection: checks overlay start for NsisFirstHeader (0xDEADBEEF), skipping 28 bytes.
/// 3. Extracts files to the destination directory.
/// 4. Displays MessageBoxA only in interactive mode (skips if silent).
/// 5. Clean exit with ExitProcess(0).
fn build_text_section(
    func_map: &[(&str, u32)],
    ndata_rva: u32,
    pe_stub_total: u32,
) -> Vec<u8> {
    let mut code = vec![0u8; SECTION_FILE_SIZE as usize];
    let mut pc = 0usize;

    let iat_addr = |name: &str| -> u32 {
        for &(n, rva) in func_map {
            if n == name {
                return IMAGE_BASE + rva;
            }
        }
        0
    };

    let data_base = IMAGE_BASE + DATA_RVA;
    let addr_install_dir = data_base + 0x120;
    let addr_overlay_offset = data_base + 0x230;
    let addr_overlay_size = data_base + 0x234;
    let addr_file_count = data_base + 0x238;
    let addr_title = data_base + 0x33C;
    let addr_success_msg = data_base + 0x35C;

    let ndata_base = IMAGE_BASE + ndata_rva;
    let addr_self_path = ndata_base;
    let addr_read_buf_ptr = ndata_base + 0x110;
    let addr_file_handle = ndata_base + 0x114;
    let addr_bytes_read = ndata_base + 0x118;
    let addr_bytes_written = ndata_base + 0x11C;
    let addr_extract_path = ndata_base + 0x120;
    let addr_programfiles = ndata_base + 0x220;
    let addr_progfiles_str = ndata_base + 0x3E0;
    let addr_is_silent = ndata_base + 0x3F0; // 4 bytes: 1 if /S or /s, 0 otherwise

    // Stack frame setup: push ebp; mov ebp, esp; sub esp, 0x100
    code[pc] = 0x55;
    pc += 1;
    code[pc] = 0x89;
    code[pc + 1] = 0xE5;
    pc += 2;
    code[pc] = 0x81;
    code[pc + 1] = 0xEC;
    code[pc + 2..pc + 6].copy_from_slice(&0x100u32.to_le_bytes());
    pc += 6;

    // ── Command-Line Argument Check for Silent Mode (/S or /s) ──
    // Call GetCommandLineA()
    code[pc] = 0xFF;
    code[pc + 1] = 0x15;
    code[pc + 2..pc + 6].copy_from_slice(&iat_addr("GetCommandLineA").to_le_bytes());
    pc += 6;

    // mov esi, eax (esi = cmdline string pointer)
    code[pc] = 0x89;
    code[pc + 1] = 0xC6;
    pc += 2;

    // mov dword [addr_is_silent], 0
    code[pc] = 0xC7;
    code[pc + 1] = 0x05;
    code[pc + 2..pc + 6].copy_from_slice(&addr_is_silent.to_le_bytes());
    code[pc + 6..pc + 10].copy_from_slice(&0u32.to_le_bytes());
    pc += 10;

    // Scan loop for /S or /s
    let scan_loop_pc = pc;
    // mov al, [esi]
    code[pc] = 0x8A;
    code[pc + 1] = 0x06;
    pc += 2;
    // test al, al
    code[pc] = 0x84;
    code[pc + 1] = 0xC0;
    pc += 2;
    // jz scan_done (6-byte near jump)
    let jz_scan_done_pc = pc;
    code[pc] = 0x0F;
    code[pc + 1] = 0x84;
    pc += 6;

    // inc esi
    code[pc] = 0x46;
    pc += 1;
    // cmp al, '/'
    code[pc] = 0x3C;
    code[pc + 1] = 0x2F;
    pc += 2;
    // je check_switch
    let je_switch_1_pc = pc;
    code[pc] = 0x74;
    code[pc + 1] = 0x00;
    pc += 2;
    // cmp al, '-'
    code[pc] = 0x3C;
    code[pc + 1] = 0x2D;
    pc += 2;
    // jne scan_loop
    let jne_scan_loop_pc = pc;
    code[pc] = 0x75;
    code[pc + 1] = 0x00;
    pc += 2;

    // check_switch:
    let check_switch_pc = pc;
    code[je_switch_1_pc + 1] = ((check_switch_pc as isize) - (je_switch_1_pc as isize + 2)) as u8;

    // mov al, [esi]
    code[pc] = 0x8A;
    code[pc + 1] = 0x06;
    pc += 2;
    // cmp al, 'S'
    code[pc] = 0x3C;
    code[pc + 1] = 0x53;
    pc += 2;
    // je is_s
    let je_is_s_1_pc = pc;
    code[pc] = 0x74;
    code[pc + 1] = 0x00;
    pc += 2;
    // cmp al, 's'
    code[pc] = 0x3C;
    code[pc + 1] = 0x73;
    pc += 2;
    // je is_s
    let je_is_s_2_pc = pc;
    code[pc] = 0x74;
    code[pc + 1] = 0x00;
    pc += 2;
    // jmp scan_loop
    let jmp_loop_1_pc = pc;
    code[pc] = 0xEB;
    code[pc + 1] = 0x00;
    pc += 2;

    // is_s:
    let is_s_pc = pc;
    code[je_is_s_1_pc + 1] = ((is_s_pc as isize) - (je_is_s_1_pc as isize + 2)) as u8;
    code[je_is_s_2_pc + 1] = ((is_s_pc as isize) - (je_is_s_2_pc as isize + 2)) as u8;

    // mov al, [esi+1]
    code[pc] = 0x8A;
    code[pc + 1] = 0x46;
    code[pc + 2] = 0x01;
    pc += 3;
    // test al, al
    code[pc] = 0x84;
    code[pc + 1] = 0xC0;
    pc += 2;
    // jz set_silent
    let jz_silent_1_pc = pc;
    code[pc] = 0x74;
    code[pc + 1] = 0x00;
    pc += 2;
    // cmp al, ' '
    code[pc] = 0x3C;
    code[pc + 1] = 0x20;
    pc += 2;
    // je set_silent
    let je_silent_2_pc = pc;
    code[pc] = 0x74;
    code[pc + 1] = 0x00;
    pc += 2;
    // jmp scan_loop
    let jmp_loop_2_pc = pc;
    code[pc] = 0xEB;
    code[pc + 1] = 0x00;
    pc += 2;

    // set_silent:
    let set_silent_pc = pc;
    code[jz_silent_1_pc + 1] = ((set_silent_pc as isize) - (jz_silent_1_pc as isize + 2)) as u8;
    code[je_silent_2_pc + 1] = ((set_silent_pc as isize) - (je_silent_2_pc as isize + 2)) as u8;

    // mov dword [addr_is_silent], 1
    code[pc] = 0xC7;
    code[pc + 1] = 0x05;
    code[pc + 2..pc + 6].copy_from_slice(&addr_is_silent.to_le_bytes());
    code[pc + 6..pc + 10].copy_from_slice(&1u32.to_le_bytes());
    pc += 10;

    // scan_done:
    let scan_done_pc = pc;
    let scan_done_rel = (scan_done_pc as i32) - (jz_scan_done_pc as i32 + 6);
    code[jz_scan_done_pc + 2..jz_scan_done_pc + 6].copy_from_slice(&scan_done_rel.to_le_bytes());

    code[jne_scan_loop_pc + 1] = ((scan_loop_pc as isize) - (jne_scan_loop_pc as isize + 2)) as u8;
    code[jmp_loop_1_pc + 1] = ((scan_loop_pc as isize) - (jmp_loop_1_pc as isize + 2)) as u8;
    code[jmp_loop_2_pc + 1] = ((scan_loop_pc as isize) - (jmp_loop_2_pc as isize + 2)) as u8;

    // ── Step 1: GetModuleFileNameA(NULL, addr_self_path, 260) ──
    code[pc] = 0x68;
    code[pc + 1..pc + 5].copy_from_slice(&260u32.to_le_bytes());
    pc += 5;
    code[pc] = 0x68;
    code[pc + 1..pc + 5].copy_from_slice(&addr_self_path.to_le_bytes());
    pc += 5;
    code[pc] = 0x6A;
    code[pc + 1] = 0x00;
    pc += 2;
    code[pc] = 0xFF;
    code[pc + 1] = 0x15;
    code[pc + 2..pc + 6].copy_from_slice(&iat_addr("GetModuleFileNameA").to_le_bytes());
    pc += 6;

    // ── Step 2: CreateFileA(addr_self_path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING...) ──
    code[pc] = 0x6A;
    code[pc + 1] = 0x00;
    pc += 2;
    code[pc] = 0x68;
    code[pc + 1..pc + 5].copy_from_slice(&0x80u32.to_le_bytes());
    pc += 5;
    code[pc] = 0x6A;
    code[pc + 1] = 0x03;
    pc += 2;
    code[pc] = 0x6A;
    code[pc + 1] = 0x00;
    pc += 2;
    code[pc] = 0x6A;
    code[pc + 1] = 0x01;
    pc += 2;
    code[pc] = 0x68;
    code[pc + 1..pc + 5].copy_from_slice(&0x8000_0000u32.to_le_bytes());
    pc += 5;
    code[pc] = 0x68;
    code[pc + 1..pc + 5].copy_from_slice(&addr_self_path.to_le_bytes());
    pc += 5;
    code[pc] = 0xFF;
    code[pc + 1] = 0x15;
    code[pc + 2..pc + 6].copy_from_slice(&iat_addr("CreateFileA").to_le_bytes());
    pc += 6;
    code[pc] = 0xA3;
    code[pc + 1..pc + 5].copy_from_slice(&addr_file_handle.to_le_bytes());
    pc += 5;

    // ── Step 3: GetFileSize(handle, NULL) ──
    code[pc] = 0x6A;
    code[pc + 1] = 0x00;
    pc += 2;
    code[pc] = 0xA1;
    code[pc + 1..pc + 5].copy_from_slice(&addr_file_handle.to_le_bytes());
    pc += 5;
    code[pc] = 0x50;
    pc += 1;
    code[pc] = 0xFF;
    code[pc + 1] = 0x15;
    code[pc + 2..pc + 6].copy_from_slice(&iat_addr("GetFileSize").to_le_bytes());
    pc += 6;

    // overlay_size = file_size - pe_stub_total
    code[pc] = 0x89;
    code[pc + 1] = 0xC1;
    pc += 2;
    code[pc] = 0x81;
    code[pc + 1] = 0xE9;
    code[pc + 2..pc + 6].copy_from_slice(&pe_stub_total.to_le_bytes());
    pc += 6;
    code[pc] = 0x89;
    code[pc + 1] = 0x0D;
    code[pc + 2..pc + 6].copy_from_slice(&addr_overlay_size.to_le_bytes());
    pc += 6;

    code[pc] = 0xC7;
    code[pc + 1] = 0x05;
    code[pc + 2..pc + 6].copy_from_slice(&addr_overlay_offset.to_le_bytes());
    code[pc + 6..pc + 10].copy_from_slice(&pe_stub_total.to_le_bytes());
    pc += 10;

    // ── Step 4: LocalAlloc(LMEM_FIXED=0, overlay_size) ──
    code[pc] = 0x51;
    pc += 1;
    code[pc] = 0x6A;
    code[pc + 1] = 0x00;
    pc += 2;
    code[pc] = 0xFF;
    code[pc + 1] = 0x15;
    code[pc + 2..pc + 6].copy_from_slice(&iat_addr("LocalAlloc").to_le_bytes());
    pc += 6;
    code[pc] = 0xA3;
    code[pc + 1..pc + 5].copy_from_slice(&addr_read_buf_ptr.to_le_bytes());
    pc += 5;

    // ── Step 5: SetFilePointer(handle, pe_stub_total, NULL, FILE_BEGIN=0) ──
    code[pc] = 0x6A;
    code[pc + 1] = 0x00;
    pc += 2;
    code[pc] = 0x6A;
    code[pc + 1] = 0x00;
    pc += 2;
    code[pc] = 0x68;
    code[pc + 1..pc + 5].copy_from_slice(&pe_stub_total.to_le_bytes());
    pc += 5;
    code[pc] = 0xFF;
    code[pc + 1] = 0x35;
    code[pc + 2..pc + 6].copy_from_slice(&addr_file_handle.to_le_bytes());
    pc += 6;
    code[pc] = 0xFF;
    code[pc + 1] = 0x15;
    code[pc + 2..pc + 6].copy_from_slice(&iat_addr("SetFilePointer").to_le_bytes());
    pc += 6;

    // ── Step 6: ReadFile(handle, buf, overlay_size, &bytes_read, NULL) ──
    code[pc] = 0x6A;
    code[pc + 1] = 0x00;
    pc += 2;
    code[pc] = 0x68;
    code[pc + 1..pc + 5].copy_from_slice(&addr_bytes_read.to_le_bytes());
    pc += 5;
    code[pc] = 0xFF;
    code[pc + 1] = 0x35;
    code[pc + 2..pc + 6].copy_from_slice(&addr_overlay_size.to_le_bytes());
    pc += 6;
    code[pc] = 0xFF;
    code[pc + 1] = 0x35;
    code[pc + 2..pc + 6].copy_from_slice(&addr_read_buf_ptr.to_le_bytes());
    pc += 6;
    code[pc] = 0xFF;
    code[pc + 1] = 0x35;
    code[pc + 2..pc + 6].copy_from_slice(&addr_file_handle.to_le_bytes());
    pc += 6;
    code[pc] = 0xFF;
    code[pc + 1] = 0x15;
    code[pc + 2..pc + 6].copy_from_slice(&iat_addr("ReadFile").to_le_bytes());
    pc += 6;

    // ── Step 7: CloseHandle(file_handle) ──
    code[pc] = 0xFF;
    code[pc + 1] = 0x35;
    code[pc + 2..pc + 6].copy_from_slice(&addr_file_handle.to_le_bytes());
    pc += 6;
    code[pc] = 0xFF;
    code[pc + 1] = 0x15;
    code[pc + 2..pc + 6].copy_from_slice(&iat_addr("CloseHandle").to_le_bytes());
    pc += 6;

    // ── Step 8: Build install path: Get %ProgramFiles%, append \<install_dir> ──
    code[pc] = 0x68;
    code[pc + 1..pc + 5].copy_from_slice(&260u32.to_le_bytes());
    pc += 5;
    code[pc] = 0x68;
    code[pc + 1..pc + 5].copy_from_slice(&addr_programfiles.to_le_bytes());
    pc += 5;
    code[pc] = 0x68;
    code[pc + 1..pc + 5].copy_from_slice(&addr_progfiles_str.to_le_bytes());
    pc += 5;
    code[pc] = 0xFF;
    code[pc + 1] = 0x15;
    code[pc + 2..pc + 6].copy_from_slice(&iat_addr("GetEnvironmentVariableA").to_le_bytes());
    pc += 6;

    // ── Step 9: CreateDirectoryA(install_dir) & SetCurrentDirectoryA(install_dir) ──
    code[pc] = 0x6A;
    code[pc + 1] = 0x00;
    pc += 2;
    code[pc] = 0x68;
    code[pc + 1..pc + 5].copy_from_slice(&addr_install_dir.to_le_bytes());
    pc += 5;
    code[pc] = 0xFF;
    code[pc + 1] = 0x15;
    code[pc + 2..pc + 6].copy_from_slice(&iat_addr("CreateDirectoryA").to_le_bytes());
    pc += 6;

    code[pc] = 0x68;
    code[pc + 1..pc + 5].copy_from_slice(&addr_install_dir.to_le_bytes());
    pc += 5;
    code[pc] = 0xFF;
    code[pc + 1] = 0x15;
    code[pc + 2..pc + 6].copy_from_slice(&iat_addr("SetCurrentDirectoryA").to_le_bytes());
    pc += 6;

    // ── Step 10: Parse and Extract Overlay ──
    // mov esi, [addr_read_buf_ptr]
    code[pc] = 0x8B;
    code[pc + 1] = 0x35;
    code[pc + 2..pc + 6].copy_from_slice(&addr_read_buf_ptr.to_le_bytes());
    pc += 6;

    // Check if buffer starts with NSIS FirstHeader: siginfo at offset 4 == 0xDEADBEEF
    code[pc] = 0x81;
    code[pc + 1] = 0x7E;
    code[pc + 2] = 0x04;
    code[pc + 3..pc + 7].copy_from_slice(&FH_SIG.to_le_bytes());
    pc += 7;
    // jne not_nsis_hdr (skip 3 bytes: add esi, 28)
    code[pc] = 0x75;
    code[pc + 1] = 0x03;
    pc += 2;
    // add esi, 28 (0x1C)
    code[pc] = 0x83;
    code[pc + 1] = 0xC6;
    code[pc + 2] = 0x1C;
    pc += 3;

    // mov edi, [addr_file_count]
    code[pc] = 0x8B;
    code[pc + 1] = 0x3D;
    code[pc + 2..pc + 6].copy_from_slice(&addr_file_count.to_le_bytes());
    pc += 6;

    // test edi, edi
    code[pc] = 0x85;
    code[pc + 1] = 0xFF;
    pc += 2;
    let jz_skip_loop_pc = pc;
    code[pc] = 0x0F;
    code[pc + 1] = 0x84;
    pc += 6;

    // Extraction loop
    let loop_start = pc;

    // compressed_size = [esi+18]
    code[pc] = 0x8B;
    code[pc + 1] = 0x46;
    code[pc + 2] = 0x12;
    pc += 3;
    code[pc] = 0x50;
    pc += 1;

    // name_len = [esi+26]
    code[pc] = 0x66;
    code[pc + 1] = 0x8B;
    code[pc + 2] = 0x4E;
    code[pc + 3] = 0x1A;
    pc += 4;
    code[pc] = 0x0F;
    code[pc + 1] = 0xB7;
    code[pc + 2] = 0xC9;
    pc += 3;
    code[pc] = 0x51;
    pc += 1;

    // extra_len = [esi+28]
    code[pc] = 0x66;
    code[pc + 1] = 0x8B;
    code[pc + 2] = 0x56;
    code[pc + 3] = 0x1C;
    pc += 4;
    code[pc] = 0x0F;
    code[pc + 1] = 0xB7;
    code[pc + 2] = 0xD2;
    pc += 3;

    // Copy filename to addr_extract_path
    code[pc] = 0x8D;
    code[pc + 1] = 0x5E;
    code[pc + 2] = 0x1E;
    pc += 3;
    code[pc] = 0x52;
    pc += 1;
    code[pc] = 0x56;
    pc += 1;
    code[pc] = 0x89;
    code[pc + 1] = 0xDE;
    pc += 2;
    code[pc] = 0x57;
    pc += 1;
    code[pc] = 0xBF;
    code[pc + 1..pc + 5].copy_from_slice(&addr_extract_path.to_le_bytes());
    pc += 5;
    code[pc] = 0x51;
    pc += 1;
    code[pc] = 0xF3;
    code[pc + 1] = 0xA4;
    pc += 2;
    code[pc] = 0xC6;
    code[pc + 1] = 0x07;
    code[pc + 2] = 0x00;
    pc += 3;
    code[pc] = 0x59;
    pc += 1;
    code[pc] = 0x5F;
    pc += 1;
    code[pc] = 0x5E;
    pc += 1;
    code[pc] = 0x5A;
    pc += 1;

    // Calculate data pointer = esi + 30 + name_len + extra_len
    code[pc] = 0x8D;
    code[pc + 1] = 0x5E;
    code[pc + 2] = 0x1E;
    pc += 3;
    code[pc] = 0x01;
    code[pc + 1] = 0xCB;
    pc += 2;
    code[pc] = 0x01;
    code[pc + 1] = 0xD3;
    pc += 2;

    code[pc] = 0x58;
    pc += 1;
    code[pc] = 0x89;
    code[pc + 1] = 0x45;
    code[pc + 2] = 0xFC; // [ebp-4] = compressed_size
    pc += 3;

    // CreateFileA(addr_extract_path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS...)
    code[pc] = 0x6A;
    code[pc + 1] = 0x00;
    pc += 2;
    code[pc] = 0x68;
    code[pc + 1..pc + 5].copy_from_slice(&0x80u32.to_le_bytes());
    pc += 5;
    code[pc] = 0x6A;
    code[pc + 1] = 0x02;
    pc += 2;
    code[pc] = 0x6A;
    code[pc + 1] = 0x00;
    pc += 2;
    code[pc] = 0x6A;
    code[pc + 1] = 0x00;
    pc += 2;
    code[pc] = 0x68;
    code[pc + 1..pc + 5].copy_from_slice(&0x4000_0000u32.to_le_bytes());
    pc += 5;
    code[pc] = 0x68;
    code[pc + 1..pc + 5].copy_from_slice(&addr_extract_path.to_le_bytes());
    pc += 5;
    code[pc] = 0xFF;
    code[pc + 1] = 0x15;
    code[pc + 2..pc + 6].copy_from_slice(&iat_addr("CreateFileA").to_le_bytes());
    pc += 6;
    code[pc] = 0x89;
    code[pc + 1] = 0x45;
    code[pc + 2] = 0xF8; // [ebp-8] = handle
    pc += 3;

    // WriteFile(handle, data_ptr, compressed_size, &bytes_written, NULL)
    code[pc] = 0x6A;
    code[pc + 1] = 0x00;
    pc += 2;
    code[pc] = 0x68;
    code[pc + 1..pc + 5].copy_from_slice(&addr_bytes_written.to_le_bytes());
    pc += 5;
    code[pc] = 0xFF;
    code[pc + 1] = 0x75;
    code[pc + 2] = 0xFC;
    pc += 3;
    code[pc] = 0x53;
    pc += 1;
    code[pc] = 0xFF;
    code[pc + 1] = 0x75;
    code[pc + 2] = 0xF8;
    pc += 3;
    code[pc] = 0xFF;
    code[pc + 1] = 0x15;
    code[pc + 2..pc + 6].copy_from_slice(&iat_addr("WriteFile").to_le_bytes());
    pc += 6;

    // CloseHandle(output_handle)
    code[pc] = 0xFF;
    code[pc + 1] = 0x75;
    code[pc + 2] = 0xF8;
    pc += 3;
    code[pc] = 0xFF;
    code[pc + 1] = 0x15;
    code[pc + 2..pc + 6].copy_from_slice(&iat_addr("CloseHandle").to_le_bytes());
    pc += 6;

    // Advance esi past this file entry: esi += 30 + name_len + extra_len + compressed_size
    code[pc] = 0x83;
    code[pc + 1] = 0xC6;
    code[pc + 2] = 0x1E;
    pc += 3;
    code[pc] = 0x01;
    code[pc + 1] = 0xCE;
    pc += 2;
    code[pc] = 0x01;
    code[pc + 1] = 0xD6;
    pc += 2;
    code[pc] = 0x03;
    code[pc + 1] = 0x75;
    code[pc + 2] = 0xFC;
    pc += 3;

    // Loop condition: dec edi; test edi, edi; jnz loop_start
    code[pc] = 0x4F;
    pc += 1;
    code[pc] = 0x85;
    code[pc + 1] = 0xFF;
    pc += 2;
    let loop_rel = (loop_start as i32) - (pc as i32 + 6);
    code[pc] = 0x0F;
    code[pc + 1] = 0x85;
    code[pc + 2..pc + 6].copy_from_slice(&loop_rel.to_le_bytes());
    pc += 6;

    // Patch skip-loop jump
    let skip_offset = (pc as i32) - (jz_skip_loop_pc as i32 + 6);
    code[jz_skip_loop_pc + 2..jz_skip_loop_pc + 6].copy_from_slice(&skip_offset.to_le_bytes());

    // ── Step 11: Free buffer ──
    code[pc] = 0xFF;
    code[pc + 1] = 0x35;
    code[pc + 2..pc + 6].copy_from_slice(&addr_read_buf_ptr.to_le_bytes());
    pc += 6;
    code[pc] = 0xFF;
    code[pc + 1] = 0x15;
    code[pc + 2..pc + 6].copy_from_slice(&iat_addr("LocalFree").to_le_bytes());
    pc += 6;

    // ── Step 12: MessageBoxA or Skip if Silent (/S or /s) ──
    // cmp dword [addr_is_silent], 1
    code[pc] = 0x83;
    code[pc + 1] = 0x3D;
    code[pc + 2..pc + 6].copy_from_slice(&addr_is_silent.to_le_bytes());
    code[pc + 6] = 0x01;
    pc += 7;

    // je skip_msgbox
    let je_skip_msgbox_pc = pc;
    code[pc] = 0x74;
    code[pc + 1] = 0x00;
    pc += 2;

    // push 0x40 (MB_OK | MB_ICONINFORMATION)
    code[pc] = 0x6A;
    code[pc + 1] = 0x40;
    pc += 2;
    code[pc] = 0x68;
    code[pc + 1..pc + 5].copy_from_slice(&addr_title.to_le_bytes());
    pc += 5;
    code[pc] = 0x68;
    code[pc + 1..pc + 5].copy_from_slice(&addr_success_msg.to_le_bytes());
    pc += 5;
    code[pc] = 0x6A;
    code[pc + 1] = 0x00;
    pc += 2;
    code[pc] = 0xFF;
    code[pc + 1] = 0x15;
    code[pc + 2..pc + 6].copy_from_slice(&iat_addr("MessageBoxA").to_le_bytes());
    pc += 6;

    // skip_msgbox:
    let skip_msgbox_pc = pc;
    code[je_skip_msgbox_pc + 1] = ((skip_msgbox_pc as isize) - (je_skip_msgbox_pc as isize + 2)) as u8;

    // ── Step 13: ExitProcess(0) ──
    code[pc] = 0x6A;
    code[pc + 1] = 0x00;
    pc += 2;
    code[pc] = 0xFF;
    code[pc + 1] = 0x15;
    code[pc + 2..pc + 6].copy_from_slice(&iat_addr("ExitProcess").to_le_bytes());
    pc += 6;

    // Fill remaining bytes with int3 (0xCC)
    for b in &mut code[pc..] {
        *b = 0xCC;
    }

    code
}

/// Generates a valid Windows PE32 executable with proper headers, import table,
/// code section, data section, resource section, and runtime variables section (.ndata).
#[allow(dead_code)]
pub fn create_pe_stub(is_64bit: bool) -> Vec<u8> {
    let _ = is_64bit;
    let config = NsisInstallerConfig::default();
    let rsrc_section = build_resource_section(&config, None, RSRC_RVA);
    let rsrc_raw_len = rsrc_section.len() as u32;
    let rsrc_file_size = rsrc_raw_len.div_ceil(FILE_ALIGNMENT) * FILE_ALIGNMENT;
    let rsrc_virtual_pages = rsrc_raw_len.div_ceil(SECTION_ALIGNMENT) * SECTION_ALIGNMENT;
    let ndata_rva = RSRC_RVA + rsrc_virtual_pages;
    let ndata_file_offset = RSRC_FILE_OFFSET + rsrc_file_size;
    let pe_stub_total = ndata_file_offset + SECTION_FILE_SIZE;

    let (idata, func_map) = build_import_section();
    let data_section = build_data_section(&config, 0);
    let text_section = build_text_section(&func_map, ndata_rva, pe_stub_total);
    let mut ndata_section = vec![0u8; SECTION_FILE_SIZE as usize];
    write_ascii_z(&mut ndata_section, 0x3E0, "ProgramFiles");

    assemble_pe32(
        &text_section,
        &data_section,
        &idata,
        &rsrc_section,
        &ndata_section,
        rsrc_file_size,
        rsrc_virtual_pages,
    )
}

/// Assemble a complete PE32 executable from prepared sections with DataDirectory[2] connected to .rsrc.
fn assemble_pe32(
    text: &[u8],
    data: &[u8],
    idata: &[u8],
    rsrc: &[u8],
    ndata: &[u8],
    rsrc_file_size: u32,
    rsrc_virtual_pages: u32,
) -> Vec<u8> {
    let ndata_rva = RSRC_RVA + rsrc_virtual_pages;
    let ndata_file_offset = RSRC_FILE_OFFSET + rsrc_file_size;
    let size_of_image: u32 = ndata_rva + SECTION_ALIGNMENT;
    let iat_rva = IDATA_RVA + 0x0C8;
    let iat_size: u32 = 0x90;
    let import_dir_rva = IDATA_RVA;

    let mut pe = Vec::with_capacity((ndata_file_offset + SECTION_FILE_SIZE) as usize);

    // ─── DOS Header (64 bytes) ───
    pe.extend_from_slice(b"MZ");
    pe.resize(60, 0);
    pe.extend_from_slice(&64u32.to_le_bytes());
    assert_eq!(pe.len(), 64);

    // ─── PE Signature (4 bytes) ───
    pe.extend_from_slice(b"PE\x00\x00");

    // ─── COFF Header (20 bytes) ───
    pe.extend_from_slice(&0x014cu16.to_le_bytes()); // Machine: i386
    pe.extend_from_slice(&NUM_SECTIONS.to_le_bytes());
    pe.extend_from_slice(&0u32.to_le_bytes());
    pe.extend_from_slice(&0u32.to_le_bytes());
    pe.extend_from_slice(&0u32.to_le_bytes());
    pe.extend_from_slice(&224u16.to_le_bytes()); // SizeOfOptionalHeader
    pe.extend_from_slice(&0x0103u16.to_le_bytes()); // Characteristics: EXECUTABLE|32BIT|RELOCS_STRIPPED

    // ─── Optional Header PE32 (224 bytes) ───
    pe.extend_from_slice(&0x010bu16.to_le_bytes()); // Magic: PE32
    pe.push(14); // MajorLinkerVersion
    pe.push(0);  // MinorLinkerVersion
    pe.extend_from_slice(&SECTION_FILE_SIZE.to_le_bytes()); // SizeOfCode
    pe.extend_from_slice(&(SECTION_FILE_SIZE * 3 + rsrc_file_size).to_le_bytes()); // SizeOfInitializedData
    pe.extend_from_slice(&0u32.to_le_bytes()); // SizeOfUninitializedData
    pe.extend_from_slice(&TEXT_RVA.to_le_bytes()); // AddressOfEntryPoint
    pe.extend_from_slice(&TEXT_RVA.to_le_bytes()); // BaseOfCode
    pe.extend_from_slice(&DATA_RVA.to_le_bytes()); // BaseOfData

    // Windows-specific fields
    pe.extend_from_slice(&IMAGE_BASE.to_le_bytes());
    pe.extend_from_slice(&SECTION_ALIGNMENT.to_le_bytes());
    pe.extend_from_slice(&FILE_ALIGNMENT.to_le_bytes());
    pe.extend_from_slice(&6u16.to_le_bytes());
    pe.extend_from_slice(&0u16.to_le_bytes());
    pe.extend_from_slice(&0u16.to_le_bytes());
    pe.extend_from_slice(&0u16.to_le_bytes());
    pe.extend_from_slice(&6u16.to_le_bytes());
    pe.extend_from_slice(&0u16.to_le_bytes());
    pe.extend_from_slice(&0u32.to_le_bytes());
    pe.extend_from_slice(&size_of_image.to_le_bytes());
    pe.extend_from_slice(&HEADERS_SIZE.to_le_bytes());
    pe.extend_from_slice(&0u32.to_le_bytes());
    pe.extend_from_slice(&2u16.to_le_bytes()); // Subsystem: GUI
    pe.extend_from_slice(&0x8160u16.to_le_bytes()); // DllCharacteristics
    pe.extend_from_slice(&0x100000u32.to_le_bytes());
    pe.extend_from_slice(&0x1000u32.to_le_bytes());
    pe.extend_from_slice(&0x100000u32.to_le_bytes());
    pe.extend_from_slice(&0x1000u32.to_le_bytes());
    pe.extend_from_slice(&0u32.to_le_bytes());
    pe.extend_from_slice(&16u32.to_le_bytes()); // 16 Data Directories

    // Data Directories:
    // 0: Export
    pe.extend_from_slice(&0u32.to_le_bytes());
    pe.extend_from_slice(&0u32.to_le_bytes());
    // 1: Import
    pe.extend_from_slice(&import_dir_rva.to_le_bytes());
    pe.extend_from_slice(&60u32.to_le_bytes());
    // 2: Resource Directory (.rsrc)
    if !rsrc.is_empty() {
        pe.extend_from_slice(&RSRC_RVA.to_le_bytes());
        pe.extend_from_slice(&(rsrc.len() as u32).to_le_bytes());
    } else {
        pe.extend_from_slice(&0u32.to_le_bytes());
        pe.extend_from_slice(&0u32.to_le_bytes());
    }
    // 3-11: empty
    for _ in 3..12 {
        pe.extend_from_slice(&0u32.to_le_bytes());
        pe.extend_from_slice(&0u32.to_le_bytes());
    }
    // 12: IAT
    pe.extend_from_slice(&iat_rva.to_le_bytes());
    pe.extend_from_slice(&iat_size.to_le_bytes());
    // 13-15: empty
    for _ in 13..16 {
        pe.extend_from_slice(&0u32.to_le_bytes());
        pe.extend_from_slice(&0u32.to_le_bytes());
    }

    // ─── Section Table (5 × 40 bytes = 200 bytes) ───
    // 1: .text
    pe.extend_from_slice(b".text\x00\x00\x00");
    pe.extend_from_slice(&SECTION_FILE_SIZE.to_le_bytes());
    pe.extend_from_slice(&TEXT_RVA.to_le_bytes());
    pe.extend_from_slice(&SECTION_FILE_SIZE.to_le_bytes());
    pe.extend_from_slice(&TEXT_FILE_OFFSET.to_le_bytes());
    pe.extend_from_slice(&0u32.to_le_bytes());
    pe.extend_from_slice(&0u32.to_le_bytes());
    pe.extend_from_slice(&0u16.to_le_bytes());
    pe.extend_from_slice(&0u16.to_le_bytes());
    pe.extend_from_slice(&0x6000_0020u32.to_le_bytes()); // CODE|EXECUTE|READ

    // 2: .data
    pe.extend_from_slice(b".data\x00\x00\x00");
    pe.extend_from_slice(&SECTION_FILE_SIZE.to_le_bytes());
    pe.extend_from_slice(&DATA_RVA.to_le_bytes());
    pe.extend_from_slice(&SECTION_FILE_SIZE.to_le_bytes());
    pe.extend_from_slice(&DATA_FILE_OFFSET.to_le_bytes());
    pe.extend_from_slice(&0u32.to_le_bytes());
    pe.extend_from_slice(&0u32.to_le_bytes());
    pe.extend_from_slice(&0u16.to_le_bytes());
    pe.extend_from_slice(&0u16.to_le_bytes());
    pe.extend_from_slice(&0xC000_0040u32.to_le_bytes()); // INITIALIZED|READ|WRITE

    // 3: .idata
    pe.extend_from_slice(b".idata\x00\x00");
    pe.extend_from_slice(&SECTION_FILE_SIZE.to_le_bytes());
    pe.extend_from_slice(&IDATA_RVA.to_le_bytes());
    pe.extend_from_slice(&SECTION_FILE_SIZE.to_le_bytes());
    pe.extend_from_slice(&IDATA_FILE_OFFSET.to_le_bytes());
    pe.extend_from_slice(&0u32.to_le_bytes());
    pe.extend_from_slice(&0u32.to_le_bytes());
    pe.extend_from_slice(&0u16.to_le_bytes());
    pe.extend_from_slice(&0u16.to_le_bytes());
    pe.extend_from_slice(&0x4000_0040u32.to_le_bytes()); // INITIALIZED|READ

    // 4: .rsrc
    pe.extend_from_slice(b".rsrc\x00\x00\x00");
    pe.extend_from_slice(&(rsrc.len() as u32).to_le_bytes());
    pe.extend_from_slice(&RSRC_RVA.to_le_bytes());
    pe.extend_from_slice(&rsrc_file_size.to_le_bytes());
    pe.extend_from_slice(&RSRC_FILE_OFFSET.to_le_bytes());
    pe.extend_from_slice(&0u32.to_le_bytes());
    pe.extend_from_slice(&0u32.to_le_bytes());
    pe.extend_from_slice(&0u16.to_le_bytes());
    pe.extend_from_slice(&0u16.to_le_bytes());
    pe.extend_from_slice(&0x4000_0040u32.to_le_bytes()); // INITIALIZED|READ

    // 5: .ndata (official NSIS runtime variables section)
    pe.extend_from_slice(b".ndata\x00\x00");
    pe.extend_from_slice(&SECTION_FILE_SIZE.to_le_bytes());
    pe.extend_from_slice(&ndata_rva.to_le_bytes());
    pe.extend_from_slice(&SECTION_FILE_SIZE.to_le_bytes());
    pe.extend_from_slice(&ndata_file_offset.to_le_bytes());
    pe.extend_from_slice(&0u32.to_le_bytes());
    pe.extend_from_slice(&0u32.to_le_bytes());
    pe.extend_from_slice(&0u16.to_le_bytes());
    pe.extend_from_slice(&0u16.to_le_bytes());
    pe.extend_from_slice(&0xC000_0040u32.to_le_bytes()); // INITIALIZED|READ|WRITE

    pad_to(&mut pe, FILE_ALIGNMENT as usize);
    assert_eq!(pe.len(), HEADERS_SIZE as usize);

    // Section Bodies
    pe.extend_from_slice(text);
    pe.extend_from_slice(data);
    pe.extend_from_slice(idata);

    pe.extend_from_slice(rsrc);
    pad_to(&mut pe, (RSRC_FILE_OFFSET + rsrc_file_size) as usize);

    pe.extend_from_slice(ndata);
    pad_to(&mut pe, (ndata_file_offset + SECTION_FILE_SIZE) as usize);

    pe
}

/// Builds a pure-Rust self-extracting Windows installer (.exe) with embedded files.
#[allow(dead_code)]
pub fn create_pe_installer(
    is_64bit: bool,
    files: &[PeFileEntry<'_>],
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    create_pe_installer_with_config(is_64bit, files, &NsisInstallerConfig::default())
}

/// Builds a self-extracting installer with full NSIS configuration, embedding
/// the authentic NSIS FirstHeader (0xDEADBEEF / NullsoftInst) and PE Resource section.
pub fn create_pe_installer_with_config(
    is_64bit: bool,
    files: &[PeFileEntry<'_>],
    config: &NsisInstallerConfig<'_>,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let file_count = files.len() as u32;
    let _ = is_64bit; // NSIS standard exehead is 32-bit PE for universal cross-architecture compatibility

    let rsrc_section = build_resource_section(config, config.icon_bytes, RSRC_RVA);
    let rsrc_raw_len = rsrc_section.len() as u32;
    let rsrc_file_size = rsrc_raw_len.div_ceil(FILE_ALIGNMENT) * FILE_ALIGNMENT;
    let rsrc_virtual_pages = rsrc_raw_len.div_ceil(SECTION_ALIGNMENT) * SECTION_ALIGNMENT;
    let ndata_rva = RSRC_RVA + rsrc_virtual_pages;
    let ndata_file_offset = RSRC_FILE_OFFSET + rsrc_file_size;
    let pe_stub_total = ndata_file_offset + SECTION_FILE_SIZE;

    let (idata, func_map) = build_import_section();
    let data_section = build_data_section(config, file_count);
    let text_section = build_text_section(&func_map, ndata_rva, pe_stub_total);
    let mut ndata_section = vec![0u8; SECTION_FILE_SIZE as usize];
    write_ascii_z(&mut ndata_section, 0x3E0, "ProgramFiles");

    let pe_stub = assemble_pe32(
        &text_section,
        &data_section,
        &idata,
        &rsrc_section,
        &ndata_section,
        rsrc_file_size,
        rsrc_virtual_pages,
    );

    let stub_len = pe_stub.len() as u32;

    // Build the archive overlay.
    // The overlay starts with the 28-byte NsisFirstHeader at offset stub_len,
    // followed by the ZIP local headers, central directory, and EOCD.
    let first_header_size: u32 = if config.embed_first_header { 28 } else { 0 };
    let mut local_headers = Vec::new();
    let mut central_directory = Vec::new();
    let mut current_offset = stub_len + first_header_size;

    for entry in files {
        let crc = crc32(entry.data);
        let uncompressed_size = entry.data.len() as u32;
        let name_bytes = entry.name.as_bytes();
        let name_len = name_bytes.len() as u16;

        let compression_method: u16 = 0; // Store
        let compressed_data = entry.data;
        let compressed_size = compressed_data.len() as u32;

        let local_hdr_offset = current_offset;
        local_headers.extend_from_slice(&0x04034b50u32.to_le_bytes()); // Local File Header signature
        local_headers.extend_from_slice(&20u16.to_le_bytes());
        local_headers.extend_from_slice(&0u16.to_le_bytes());
        local_headers.extend_from_slice(&compression_method.to_le_bytes());
        local_headers.extend_from_slice(&0u16.to_le_bytes());
        local_headers.extend_from_slice(&0u16.to_le_bytes());
        local_headers.extend_from_slice(&crc.to_le_bytes());
        local_headers.extend_from_slice(&compressed_size.to_le_bytes());
        local_headers.extend_from_slice(&uncompressed_size.to_le_bytes());
        local_headers.extend_from_slice(&name_len.to_le_bytes());
        local_headers.extend_from_slice(&0u16.to_le_bytes());
        local_headers.extend_from_slice(name_bytes);
        local_headers.extend_from_slice(compressed_data);

        current_offset += 30 + (name_len as u32) + compressed_size;

        central_directory.extend_from_slice(&0x02014b50u32.to_le_bytes());
        central_directory.extend_from_slice(&20u16.to_le_bytes());
        central_directory.extend_from_slice(&20u16.to_le_bytes());
        central_directory.extend_from_slice(&0u16.to_le_bytes());
        central_directory.extend_from_slice(&compression_method.to_le_bytes());
        central_directory.extend_from_slice(&0u16.to_le_bytes());
        central_directory.extend_from_slice(&0u16.to_le_bytes());
        central_directory.extend_from_slice(&crc.to_le_bytes());
        central_directory.extend_from_slice(&compressed_size.to_le_bytes());
        central_directory.extend_from_slice(&uncompressed_size.to_le_bytes());
        central_directory.extend_from_slice(&name_len.to_le_bytes());
        central_directory.extend_from_slice(&0u16.to_le_bytes());
        central_directory.extend_from_slice(&0u16.to_le_bytes());
        central_directory.extend_from_slice(&0u16.to_le_bytes());
        central_directory.extend_from_slice(&0u16.to_le_bytes());
        central_directory.extend_from_slice(&0x20u32.to_le_bytes());
        central_directory.extend_from_slice(&local_hdr_offset.to_le_bytes());
        central_directory.extend_from_slice(name_bytes);
    }

    let cd_offset = current_offset;
    let cd_size = central_directory.len() as u32;
    let num_entries = files.len() as u16;
    let comment = b"NullsoftInst";
    let comment_len = comment.len() as u16;

    let mut eocd = Vec::with_capacity(22 + comment.len());
    eocd.extend_from_slice(&0x06054b50u32.to_le_bytes());
    eocd.extend_from_slice(&0u16.to_le_bytes());
    eocd.extend_from_slice(&0u16.to_le_bytes());
    eocd.extend_from_slice(&num_entries.to_le_bytes());
    eocd.extend_from_slice(&num_entries.to_le_bytes());
    eocd.extend_from_slice(&cd_size.to_le_bytes());
    eocd.extend_from_slice(&cd_offset.to_le_bytes());
    eocd.extend_from_slice(&comment_len.to_le_bytes());
    eocd.extend_from_slice(comment);

    // NSIS FirstHeader (28 bytes) matching Source/exehead/fileform.h (if requested)
    let total_len = pe_stub.len()
        + (if config.embed_first_header { 28 } else { 0 })
        + local_headers.len()
        + central_directory.len()
        + eocd.len();
    let mut output = Vec::with_capacity(total_len);
    output.extend_from_slice(&pe_stub);
    if config.embed_first_header {
        let overlay_total_len = (28 + local_headers.len() + central_directory.len() + eocd.len()) as i32;
        let nsis_fh = NsisFirstHeader {
            flags: FH_FLAGS_NO_CRC,
            siginfo: FH_SIG,
            nsinst: [FH_INT1, FH_INT2, FH_INT3],
            length_of_header: 0,
            length_of_all_following_data: overlay_total_len,
        };
        output.extend_from_slice(&nsis_fh.to_bytes());
    }
    output.extend_from_slice(&local_headers);
    output.extend_from_slice(&central_directory);
    output.extend_from_slice(&eocd);

    Ok(output)
}



/// Generates a valid 24-bit uncompressed BMP image of given dimensions and background color.
pub fn create_bmp(width: u32, height: u32, r: u8, g: u8, b: u8) -> Vec<u8> {
    let row_size = (width * 3).div_ceil(4) * 4;
    let image_size = row_size * height;
    let file_size = 54 + image_size;
    let mut out = Vec::with_capacity(file_size as usize);

    // BITMAPFILEHEADER (14 bytes)
    out.extend_from_slice(b"BM");
    out.extend_from_slice(&file_size.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());
    out.extend_from_slice(&54u32.to_le_bytes());

    // BITMAPINFOHEADER (40 bytes)
    out.extend_from_slice(&40u32.to_le_bytes());
    out.extend_from_slice(&(width as i32).to_le_bytes());
    out.extend_from_slice(&(height as i32).to_le_bytes());
    out.extend_from_slice(&1u16.to_le_bytes());
    out.extend_from_slice(&24u16.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());
    out.extend_from_slice(&image_size.to_le_bytes());
    out.extend_from_slice(&2835u32.to_le_bytes());
    out.extend_from_slice(&2835u32.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());

    let padding = (row_size - width * 3) as usize;
    for _ in 0..height {
        for _ in 0..width {
            out.push(b);
            out.push(g);
            out.push(r);
        }
        out.extend(std::iter::repeat_n(0, padding));
    }
    out
}

/// Generates a valid 32-bit RGBA Windows icon (.ico) file of given dimensions and background color.
pub fn create_ico(width: u32, height: u32, r: u8, g: u8, b: u8) -> Vec<u8> {
    let w = width.min(256) as u8;
    let h = height.min(256) as u8;
    let pixel_bytes = (width * height * 4) as usize;
    let mask_row_bytes = (width.div_ceil(32) * 4) as usize;
    let mask_bytes = mask_row_bytes * height as usize;
    let image_bytes = 40 + pixel_bytes + mask_bytes;
    let file_size = 6 + 16 + image_bytes;

    let mut out = Vec::with_capacity(file_size);

    // 1. ICONDIR (6 bytes)
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&1u16.to_le_bytes());
    out.extend_from_slice(&1u16.to_le_bytes());

    // 2. ICONDIRENTRY (16 bytes)
    out.push(w);
    out.push(h);
    out.push(0);
    out.push(0);
    out.extend_from_slice(&1u16.to_le_bytes());
    out.extend_from_slice(&32u16.to_le_bytes());
    out.extend_from_slice(&(image_bytes as u32).to_le_bytes());
    out.extend_from_slice(&22u32.to_le_bytes());

    // 3. BITMAPINFOHEADER (40 bytes)
    out.extend_from_slice(&40u32.to_le_bytes());
    out.extend_from_slice(&(width as i32).to_le_bytes());
    out.extend_from_slice(&((height * 2) as i32).to_le_bytes());
    out.extend_from_slice(&1u16.to_le_bytes());
    out.extend_from_slice(&32u16.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());
    out.extend_from_slice(&(image_bytes as u32 - 40).to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());

    // 4. Pixel data (BGRA, bottom-to-top)
    for _ in 0..(width * height) {
        out.push(b);
        out.push(g);
        out.push(r);
        out.push(255);
    }

    // 5. AND mask (1 bit per pixel, 0 = opaque)
    out.resize(out.len() + mask_bytes, 0);

    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pe_stub_generation() {
        let pe32 = create_pe_stub(false);
        assert!(!pe32.is_empty());
        assert_eq!(&pe32[0..2], b"MZ");
        assert_eq!(&pe32[64..68], b"PE\x00\x00");

        let machine = u16::from_le_bytes([pe32[68], pe32[69]]);
        assert_eq!(machine, 0x014C); // i386

        let num_sections = u16::from_le_bytes([pe32[70], pe32[71]]);
        assert_eq!(num_sections, NUM_SECTIONS);

        let magic = u16::from_le_bytes([pe32[88], pe32[89]]);
        assert_eq!(magic, 0x010B); // PE32

        let entry = u32::from_le_bytes([pe32[104], pe32[105], pe32[106], pe32[107]]);
        assert_eq!(entry, TEXT_RVA);

        let subsystem = u16::from_le_bytes([pe32[156], pe32[157]]);
        assert_eq!(subsystem, 2); // Windows GUI

        // Verify Import directory (DataDirectory[1])
        let import_rva = u32::from_le_bytes([pe32[192], pe32[193], pe32[194], pe32[195]]);
        assert_eq!(import_rva, IDATA_RVA);

        // Verify Resource directory (DataDirectory[2]) points to RSRC_RVA
        let rsrc_dir_rva = u32::from_le_bytes([pe32[200], pe32[201], pe32[202], pe32[203]]);
        assert_eq!(rsrc_dir_rva, RSRC_RVA);
    }

    #[test]
    fn test_create_bmp() {
        let bmp = create_bmp(150, 57, 30, 60, 90);
        assert_eq!(&bmp[0..2], b"BM");
        assert!(bmp.len() > 54);
    }

    #[test]
    fn test_create_ico() {
        let ico = create_ico(32, 32, 24, 119, 242);
        assert_eq!(&ico[0..4], &[0x00, 0x00, 0x01, 0x00]);
        assert_eq!(ico[4], 1);
        assert_eq!(ico[6], 32);
        assert_eq!(ico[7], 32);
        assert!(ico.len() > 100);
    }

    #[test]
    fn test_crc32() {
        assert_eq!(crc32(b""), 0x00000000);
        assert_eq!(crc32(b"hello"), 0x3610A686);
    }

    #[test]
    fn test_pe_installer_store_mode() {
        let files = vec![
            PeFileEntry {
                name: "test.txt",
                data: b"Hello, World!",
            },
            PeFileEntry {
                name: "readme.md",
                data: b"# README\nThis is a test.",
            },
        ];

        // 1. Default config: clean overlay that standard tools open directly
        let exe = create_pe_installer(false, &files).expect("installer should build");
        assert_eq!(&exe[0..2], b"MZ");
        assert_eq!(&exe[64..68], b"PE\x00\x00");

        let comment = b"NullsoftInst";
        assert_eq!(&exe[exe.len() - comment.len()..], comment);

        // 2. Config with embed_first_header = true: embeds authentic NSIS FirstHeader
        let config_nsis = NsisInstallerConfig {
            embed_first_header: true,
            ..Default::default()
        };
        let exe_nsis = create_pe_installer_with_config(false, &files, &config_nsis)
            .expect("nsis installer should build");
        let fh_sig_bytes = FH_SIG.to_le_bytes();
        let overlay_pos = exe_nsis
            .windows(4)
            .rposition(|w| w == fh_sig_bytes)
            .expect("must contain NSIS FirstHeader signature in overlay");
        let fh_start = overlay_pos - 4;
        let flags = i32::from_le_bytes([exe_nsis[fh_start], exe_nsis[fh_start + 1], exe_nsis[fh_start + 2], exe_nsis[fh_start + 3]]);
        assert_eq!(flags, FH_FLAGS_NO_CRC);
        let magic = &exe_nsis[fh_start + 8..fh_start + 20];
        assert_eq!(magic, b"NullsoftInst");
        assert_eq!(
            &exe_nsis[fh_start + 28..fh_start + 32],
            &0x04034b50u32.to_le_bytes()
        );
    }

    #[test]
    fn test_pe_installer_with_config() {
        let ico_bytes = create_ico(32, 32, 24, 119, 242);
        let config = NsisInstallerConfig {
            app_name: "TestApp",
            version: "2.0.0",
            manufacturer: "TestCorp",
            install_dir: "TestApp",
            main_exe: "testapp.exe",
            icon_bytes: Some(&ico_bytes),
            embed_first_header: false,
        };
        let files = vec![PeFileEntry {
            name: "testapp.exe",
            data: b"MZ\x90\x00\x03\x00\x00\x00FakeExePayload",
        }];

        let exe = create_pe_installer_with_config(false, &files, &config)
            .expect("installer with config should build");
        assert_eq!(&exe[0..2], b"MZ");

        let data_start = DATA_FILE_OFFSET as usize;
        let data_slice = &exe[data_start..data_start + SECTION_FILE_SIZE as usize];
        assert_eq!(&data_slice[0..7], b"TestApp");
        assert_eq!(&data_slice[0x080..0x085], b"2.0.0");
        assert_eq!(&data_slice[0x0A0..0x0A8], b"TestCorp");
    }

    #[test]
    fn test_import_section_structure() {
        let (idata, func_map) = build_import_section();
        assert_eq!(idata.len(), SECTION_FILE_SIZE as usize);

        let expected = &[
            "GetModuleFileNameA",
            "CreateFileA",
            "ReadFile",
            "WriteFile",
            "SetFilePointer",
            "CloseHandle",
            "CreateDirectoryA",
            "ExitProcess",
            "GetFileSize",
            "LocalAlloc",
            "LocalFree",
            "GetEnvironmentVariableA",
            "SetCurrentDirectoryA",
            "GetLastError",
            "GetCommandLineA",
            "MessageBoxA",
        ];
        assert_eq!(func_map.len(), expected.len());
        for name in expected {
            assert!(
                func_map.iter().any(|(n, _)| *n == *name),
                "Missing function: {}",
                name
            );
        }

        let ilt_rva = u32::from_le_bytes([idata[0], idata[1], idata[2], idata[3]]);
        assert!(ilt_rva >= IDATA_RVA);
    }

    #[test]
    fn test_data_section_layout() {
        let config = NsisInstallerConfig {
            app_name: "MyApp",
            version: "3.1.4",
            manufacturer: "MyCorp",
            install_dir: "MyAppDir",
            main_exe: "myapp.exe",
            icon_bytes: None,
            embed_first_header: false,
        };
        let data = build_data_section(&config, 42);

        assert_eq!(&data[0..5], b"MyApp");
        assert_eq!(&data[0x080..0x085], b"3.1.4");
        assert_eq!(&data[0x0A0..0x0A6], b"MyCorp");
        assert_eq!(&data[0x120..0x128], b"MyAppDir");
        assert_eq!(&data[0x1A0..0x1A9], b"myapp.exe");
        assert_eq!(&data[0x220..0x22C], b"NullsoftInst");

        let count = u32::from_le_bytes([data[0x238], data[0x239], data[0x23A], data[0x23B]]);
        assert_eq!(count, 42);
    }

    #[test]
    fn test_resource_section_and_manifest() {
        let config = NsisInstallerConfig {
            app_name: "ResourceTest",
            version: "1.2.3.4",
            manufacturer: "ResCorp",
            install_dir: "ResDir",
            main_exe: "res.exe",
            icon_bytes: None,
            embed_first_header: false,
        };

        let rsrc = build_resource_section(&config, None, RSRC_RVA);
        assert!(rsrc.len() > 1000);

        // Check root directory has 4 ID entries
        let num_id_entries = u16::from_le_bytes([rsrc[14], rsrc[15]]);
        assert_eq!(num_id_entries, 4);

        // Manifest XML should be contained in the resource section
        let manifest_str = String::from_utf8_lossy(&rsrc);
        assert!(manifest_str.contains("Nullsoft.NSIS.exehead"));
        assert!(manifest_str.contains("asInvoker"));
        assert!(manifest_str.contains("{8e0f7a12-bfb3-4fe8-b9a5-48fd50a15a9a}"));

        // VS_VERSION_INFO signature FEEF04BD must be present
        let sig = 0xFEEF_04BDu32.to_le_bytes();
        assert!(rsrc.windows(4).any(|w| w == sig));
    }

    #[test]
    fn test_nsis_first_header() {
        assert_eq!(std::mem::size_of::<NsisFirstHeader>(), 28);

        let fh = NsisFirstHeader {
            flags: FH_FLAGS_NO_CRC,
            siginfo: FH_SIG,
            nsinst: [FH_INT1, FH_INT2, FH_INT3],
            length_of_header: 1234,
            length_of_all_following_data: 5678,
        };
        let b = fh.to_bytes();
        assert_eq!(b.len(), 28);
        assert_eq!(&b[4..8], &FH_SIG.to_le_bytes());
        assert_eq!(&b[8..20], b"NullsoftInst");
    }
}

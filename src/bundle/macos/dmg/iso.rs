use std::fs;
use std::path::Path;

const SECTOR_SIZE: usize = 2048;

fn both_u16(val: u16) -> [u8; 4] {
    let le = val.to_le_bytes();
    let be = val.to_be_bytes();
    [le[0], le[1], be[0], be[1]]
}

fn both_u32(val: u32) -> [u8; 8] {
    let le = val.to_le_bytes();
    let be = val.to_be_bytes();
    [le[0], le[1], le[2], le[3], be[0], be[1], be[2], be[3]]
}

fn ucs2_be(text: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(text.len() * 2);
    for c in text.encode_utf16() {
        out.extend_from_slice(&c.to_be_bytes());
    }
    out
}

pub fn make_px_record(mode: u32) -> Vec<u8> {
    let mut px = Vec::with_capacity(36);
    px.extend_from_slice(b"PX"); // Signature
    px.push(36); // Length
    px.push(1); // Version
    px.extend_from_slice(&both_u32(mode)); // POSIX file mode
    px.extend_from_slice(&both_u32(1)); // Links
    px.extend_from_slice(&both_u32(0)); // UID
    px.extend_from_slice(&both_u32(0)); // GID
    px
}

pub fn make_sl_record(target: &str) -> Vec<u8> {
    let mut sl = Vec::new();
    sl.extend_from_slice(b"SL"); // Signature
    sl.push(0); // Length placeholder
    sl.push(1); // Version
    sl.push(0); // Flags: not continued

    if target.starts_with('/') {
        sl.push(0x02); // Flag: ROOT component ("/")
        sl.push(0); // Component length: 0
    }
    let trimmed = target.trim_start_matches('/');
    for part in trimmed.split('/') {
        if !part.is_empty() {
            sl.push(0x00); // Flag: normal component
            sl.push(part.len() as u8);
            sl.extend_from_slice(part.as_bytes());
        }
    }
    sl[2] = sl.len() as u8;
    sl
}

fn make_dir_record(
    extent_sector: u32,
    data_length: u32,
    flags: u8,
    name_bytes: &[u8],
    system_use: &[u8],
) -> Vec<u8> {
    let name_len = name_bytes.len();
    let mut rec_len = 33 + name_len;
    let mut pad_after_name = 0;
    if !rec_len.is_multiple_of(2) {
        pad_after_name = 1;
        rec_len += 1;
    }
    rec_len += system_use.len();
    if !rec_len.is_multiple_of(2) {
        rec_len += 1;
    }
    let mut rec = vec![0u8; rec_len];
    rec[0] = rec_len as u8;
    rec[1] = 0; // Extended attribute length
    rec[2..10].copy_from_slice(&both_u32(extent_sector));
    rec[10..18].copy_from_slice(&both_u32(data_length));
    // Recording date/time: 7 bytes (year - 1900, month, day, hour, min, sec, tz offset)
    rec[18..25].copy_from_slice(&crate::repro::iso9660_datetime(crate::repro::timestamp()));
    rec[25] = flags;
    rec[26] = 0; // File unit size
    rec[27] = 0; // Interleave gap size
    rec[28..32].copy_from_slice(&both_u16(1)); // Volume sequence number
    rec[32] = name_len as u8;
    rec[33..33 + name_len].copy_from_slice(name_bytes);
    let offset = 33 + name_len + pad_after_name;
    if !system_use.is_empty() {
        rec[offset..offset + system_use.len()].copy_from_slice(system_use);
    }
    rec
}

#[derive(Debug, Clone)]
pub struct IsoNode {
    name: String,
    is_dir: bool,
    is_symlink: bool,
    symlink_target: String,
    data: Vec<u8>,
    children: Vec<IsoNode>,
    is_executable: bool,
}

impl IsoNode {
    pub fn from_path(path: &Path) -> Result<Self, Box<dyn std::error::Error>> {
        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("")
            .to_string();

        let meta = fs::symlink_metadata(path)?;
        if meta.file_type().is_symlink() {
            let target = fs::read_link(path)?;
            let target_str = target.to_string_lossy().to_string();
            Ok(Self {
                name,
                is_dir: false,
                is_symlink: true,
                symlink_target: target_str,
                data: Vec::new(),
                children: Vec::new(),
                is_executable: false,
            })
        } else if meta.is_dir() {
            let mut children = Vec::new();
            let mut entries: Vec<_> = fs::read_dir(path)?.filter_map(|e| e.ok()).collect();
            entries.sort_by_key(|e| e.file_name());

            for entry in entries {
                children.push(Self::from_path(&entry.path())?);
            }

            Ok(Self {
                name,
                is_dir: true,
                is_symlink: false,
                symlink_target: String::new(),
                data: Vec::new(),
                children,
                is_executable: false,
            })
        } else {
            let data = fs::read(path)?;
            let mut is_executable = false;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                if (meta.permissions().mode() & 0o111) != 0 {
                    is_executable = true;
                }
            }
            if data.starts_with(b"\xfe\xed\xfa\xce")
                || data.starts_with(b"\xfe\xed\xfa\xcf")
                || data.starts_with(b"\xca\xfe\xba\xbe")
                || data.starts_with(b"\xcf\xfa\xed\xfe")
            {
                is_executable = true;
            }

            Ok(Self {
                name,
                is_dir: false,
                is_symlink: false,
                symlink_target: String::new(),
                data,
                children: Vec::new(),
                is_executable,
            })
        }
    }
}

#[derive(Debug, Clone)]
struct FlatNode {
    name: String,
    is_dir: bool,
    is_symlink: bool,
    symlink_target: String,
    data: Vec<u8>,
    sector: u32,
    size: u32,
    parent_sector: u32,
    parent_size: u32,
    children_indices: Vec<usize>,
    is_executable: bool,
}

fn flatten_tree(root: IsoNode) -> (Vec<FlatNode>, Vec<usize>, Vec<usize>) {
    let mut nodes = Vec::new();
    let mut dir_indices = Vec::new();
    let mut file_indices = Vec::new();

    fn convert(
        node: IsoNode,
        nodes: &mut Vec<FlatNode>,
        dirs: &mut Vec<usize>,
        files: &mut Vec<usize>,
    ) -> usize {
        let idx = nodes.len();
        let is_dir = node.is_dir;
        let children = node.children;
        nodes.push(FlatNode {
            name: node.name,
            is_dir,
            is_symlink: node.is_symlink,
            symlink_target: node.symlink_target,
            data: node.data,
            sector: 0,
            size: 0,
            parent_sector: 0,
            parent_size: 0,
            children_indices: Vec::new(),
            is_executable: node.is_executable,
        });

        if is_dir {
            dirs.push(idx);
            let mut child_ids = Vec::new();
            for child in children {
                let c_idx = convert(child, nodes, dirs, files);
                child_ids.push(c_idx);
            }
            nodes[idx].children_indices = child_ids;
        } else {
            files.push(idx);
        }
        idx
    }

    convert(root, &mut nodes, &mut dir_indices, &mut file_indices);
    (nodes, dir_indices, file_indices)
}

fn make_system_use_for_flat(node: &FlatNode) -> Vec<u8> {
    let mut su = Vec::new();
    if node.is_symlink {
        su.extend_from_slice(&make_px_record(0o120777));
        su.extend_from_slice(&make_sl_record(&node.symlink_target));
    } else if node.is_dir {
        su.extend_from_slice(&make_px_record(0o040755));
    } else if node.is_executable {
        su.extend_from_slice(&make_px_record(0o100755));
    } else {
        su.extend_from_slice(&make_px_record(0o100644));
    }
    su
}

/// Generate an ISO-9660 + Joliet disk image filesystem containing all files from `root_dir`.
/// Safe implementation with Rock Ridge PX/SL records and zero unsafe blocks.
pub fn generate_iso_image(
    root_dir: &Path,
    volume_name: &str,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut root_node = IsoNode::from_path(root_dir)?;
    root_node.name = volume_name.to_string();

    let (mut nodes, dir_indices, file_indices) = flatten_tree(root_node);

    // Two-pass layout:
    // Pass 1: compute directory record sizes and sector layout
    let mut cur_sector = 20u32;
    for &d_idx in &dir_indices {
        nodes[d_idx].sector = cur_sector;
        let mut rec_size = make_dir_record(0, 0, 2, b"\x00", &[]).len()
            + make_dir_record(0, 0, 2, b"\x01", &[]).len();
        for &c_idx in &nodes[d_idx].children_indices {
            let child = &nodes[c_idx];
            let name_bytes = ucs2_be(&child.name);
            let su = make_system_use_for_flat(child);
            rec_size +=
                make_dir_record(0, 0, if child.is_dir { 2 } else { 0 }, &name_bytes, &su).len();
        }
        let sec_count = rec_size.div_ceil(SECTOR_SIZE).max(1) as u32;
        nodes[d_idx].size = sec_count * SECTOR_SIZE as u32;
        cur_sector += sec_count;
    }

    for &f_idx in &file_indices {
        nodes[f_idx].sector = cur_sector;
        let sec_count = (nodes[f_idx].data.len()).div_ceil(SECTOR_SIZE).max(1) as u32;
        nodes[f_idx].size = nodes[f_idx].data.len() as u32;
        cur_sector += sec_count;
    }

    // Pass 2: assign parent sectors and sizes
    for &d_idx in &dir_indices {
        let parent_sec = nodes[d_idx].sector;
        let parent_sz = nodes[d_idx].size;
        let children = nodes[d_idx].children_indices.clone();
        for c_idx in children {
            nodes[c_idx].parent_sector = parent_sec;
            nodes[c_idx].parent_size = parent_sz;
        }
    }

    let total_sectors = cur_sector;
    let mut iso = Vec::with_capacity(total_sectors as usize * SECTOR_SIZE);

    // 0..15: System area (32768 bytes zeros)
    iso.resize(16 * SECTOR_SIZE, 0u8);

    // Sector 16: Primary Volume Descriptor (PVD)
    let mut pvd = vec![0u8; SECTOR_SIZE];
    pvd[0] = 1; // Type: PVD
    pvd[1..6].copy_from_slice(b"CD001");
    pvd[6] = 1; // Version
    let vol_ascii = volume_name.as_bytes();
    let copy_len = vol_ascii.len().min(32);
    pvd[40..40 + copy_len].copy_from_slice(&vol_ascii[..copy_len]);
    pvd[80..88].copy_from_slice(&both_u32(total_sectors));
    pvd[120..124].copy_from_slice(&both_u16(1)); // Volume set size
    pvd[124..128].copy_from_slice(&both_u16(1)); // Volume sequence number
    pvd[128..132].copy_from_slice(&both_u16(2048)); // Logical block size
    let pvd_root = make_dir_record(19, 2048, 2, b"\x00", &[]);
    pvd[156..156 + pvd_root.len()].copy_from_slice(&pvd_root);
    iso.extend_from_slice(&pvd);

    // Sector 17: Supplementary Volume Descriptor (SVD) for Joliet
    let mut svd = vec![0u8; SECTOR_SIZE];
    svd[0] = 2; // Type: SVD
    svd[1..6].copy_from_slice(b"CD001");
    svd[6] = 1; // Version
    let vol_ucs2 = ucs2_be(volume_name);
    let copy_len = vol_ucs2.len().min(32);
    svd[40..40 + copy_len].copy_from_slice(&vol_ucs2[..copy_len]);
    svd[80..88].copy_from_slice(&both_u32(total_sectors));
    svd[88..91].copy_from_slice(&[0x25, 0x2F, 0x45]); // Joliet escape sequence %/E (UCS-2 Level 3)
    svd[120..124].copy_from_slice(&both_u16(1));
    svd[124..128].copy_from_slice(&both_u16(1));
    svd[128..132].copy_from_slice(&both_u16(2048));
    let svd_root = make_dir_record(nodes[0].sector, nodes[0].size, 2, b"\x00", &[]);
    svd[156..156 + svd_root.len()].copy_from_slice(&svd_root);
    iso.extend_from_slice(&svd);

    // Sector 18: Volume Descriptor Set Terminator (VDST)
    let mut term = vec![0u8; SECTOR_SIZE];
    term[0] = 255;
    term[1..6].copy_from_slice(b"CD001");
    term[6] = 1;
    iso.extend_from_slice(&term);

    // Sector 19: ISO root directory (dummy minimal)
    let mut iso_root = vec![0u8; SECTOR_SIZE];
    let r0 = make_dir_record(19, 2048, 2, b"\x00", &[]);
    let r1 = make_dir_record(19, 2048, 2, b"\x01", &[]);
    iso_root[..r0.len()].copy_from_slice(&r0);
    iso_root[r0.len()..r0.len() + r1.len()].copy_from_slice(&r1);
    iso.extend_from_slice(&iso_root);

    // Joliet directories
    for &d_idx in &dir_indices {
        let d = &nodes[d_idx];
        let mut d_block = vec![0u8; d.size as usize];
        let parent_sec = if d.parent_sector != 0 {
            d.parent_sector
        } else {
            d.sector
        };
        let parent_sz = if d.parent_size != 0 {
            d.parent_size
        } else {
            d.size
        };

        let dot_rec = make_dir_record(d.sector, d.size, 2, b"\x00", &[]);
        let dotdot_rec = make_dir_record(parent_sec, parent_sz, 2, b"\x01", &[]);
        let mut off = 0;
        d_block[off..off + dot_rec.len()].copy_from_slice(&dot_rec);
        off += dot_rec.len();
        d_block[off..off + dotdot_rec.len()].copy_from_slice(&dotdot_rec);
        off += dotdot_rec.len();

        for &c_idx in &d.children_indices {
            let child = &nodes[c_idx];
            let name_bytes = ucs2_be(&child.name);
            let su = make_system_use_for_flat(child);
            let rec = make_dir_record(
                child.sector,
                child.size,
                if child.is_dir { 2 } else { 0 },
                &name_bytes,
                &su,
            );
            if off + rec.len() <= d_block.len() {
                d_block[off..off + rec.len()].copy_from_slice(&rec);
                off += rec.len();
            }
        }
        iso.extend_from_slice(&d_block);
    }

    // File contents
    for &f_idx in &file_indices {
        let f = &nodes[f_idx];
        if !f.data.is_empty() {
            let sec_count = f.data.len().div_ceil(SECTOR_SIZE).max(1);
            let mut f_block = vec![0u8; sec_count * SECTOR_SIZE];
            f_block[..f.data.len()].copy_from_slice(&f.data);
            iso.extend_from_slice(&f_block);
        }
    }

    Ok(iso)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_iso_has_symlink_and_exec_records() {
        let tmp =
            std::env::temp_dir().join(format!("test_iso_{}", uuid::Uuid::new_v4().hyphenated()));
        fs::create_dir_all(&tmp).unwrap();

        // Create executable binary
        let bin_path = tmp.join("app");
        fs::write(&bin_path, b"\xfe\xed\xfa\xcf\x00\x00\x00\x00binary").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&bin_path, fs::Permissions::from_mode(0o755)).unwrap();
        }

        // Create symlink to /Applications
        let link_path = tmp.join("Applications");
        #[cfg(unix)]
        {
            let _ = std::os::unix::fs::symlink("/Applications", &link_path);
        }
        #[cfg(not(unix))]
        {
            let _ = fs::write(&link_path, b"/Applications");
        }

        let iso_bytes = generate_iso_image(&tmp, "TESTVOL").expect("generate ISO");
        assert!(iso_bytes.len() > 20 * SECTOR_SIZE);

        // Verify PVD signature
        assert_eq!(
            &iso_bytes[16 * SECTOR_SIZE + 1..16 * SECTOR_SIZE + 6],
            b"CD001"
        );
        // Verify SVD Joliet signature
        assert_eq!(
            &iso_bytes[17 * SECTOR_SIZE + 1..17 * SECTOR_SIZE + 6],
            b"CD001"
        );

        // Verify SL record exists in the directory sector
        let sl_found = iso_bytes.windows(2).any(|w| w == b"SL");
        assert!(sl_found, "ISO image must contain Rock Ridge SL record");

        // Verify PX record exists in the directory sector
        let px_found = iso_bytes.windows(2).any(|w| w == b"PX");
        assert!(px_found, "ISO image must contain Rock Ridge PX record");

        let _ = fs::remove_dir_all(&tmp);
    }
}

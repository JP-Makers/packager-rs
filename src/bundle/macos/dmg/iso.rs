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

fn make_dir_record(extent_sector: u32, data_length: u32, flags: u8, name_bytes: &[u8]) -> Vec<u8> {
    let name_len = name_bytes.len();
    let mut rec_len = 33 + name_len;
    if !rec_len.is_multiple_of(2) {
        rec_len += 1;
    }
    let mut rec = vec![0u8; rec_len];
    rec[0] = rec_len as u8;
    rec[1] = 0; // Extended attribute length
    rec[2..10].copy_from_slice(&both_u32(extent_sector));
    rec[10..18].copy_from_slice(&both_u32(data_length));
    // Recording date/time: 7 bytes (year - 1900, month, day, hour, min, sec, tz offset)
    rec[18..25].copy_from_slice(&[126, 11, 15, 12, 0, 0, 0]);
    rec[25] = flags;
    rec[26] = 0; // File unit size
    rec[27] = 0; // Interleave gap size
    rec[28..32].copy_from_slice(&both_u16(1)); // Volume sequence number
    rec[32] = name_len as u8;
    rec[33..33 + name_len].copy_from_slice(name_bytes);
    rec
}

#[derive(Debug, Clone)]
struct IsoNode {
    name: String,
    is_dir: bool,
    data: Vec<u8>,
    children: Vec<IsoNode>,
    sector: u32,
    size: u32,
    parent_sector: u32,
    parent_size: u32,
}

impl IsoNode {
    fn from_path(path: &Path) -> Result<Self, Box<dyn std::error::Error>> {
        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("")
            .to_string();

        let meta = fs::symlink_metadata(path)?;
        if meta.file_type().is_symlink() {
            let target = fs::read_link(path)?;
            let target_str = target.to_string_lossy().to_string();
            let data = target_str.into_bytes();
            let size = data.len() as u32;
            Ok(Self {
                name,
                is_dir: false,
                data,
                children: Vec::new(),
                sector: 0,
                size,
                parent_sector: 0,
                parent_size: 0,
            })
        } else if meta.is_dir() {
            let mut children = Vec::new();
            let mut entries: Vec<_> = fs::read_dir(path)?
                .filter_map(|e| e.ok())
                .collect();
            entries.sort_by_key(|e| e.file_name());

            for entry in entries {
                children.push(Self::from_path(&entry.path())?);
            }

            Ok(Self {
                name,
                is_dir: true,
                data: Vec::new(),
                children,
                sector: 0,
                size: 0,
                parent_sector: 0,
                parent_size: 0,
            })
        } else {
            let data = fs::read(path)?;
            let size = data.len() as u32;
            Ok(Self {
                name,
                is_dir: false,
                data,
                children: Vec::new(),
                sector: 0,
                size,
                parent_sector: 0,
                parent_size: 0,
            })
        }
    }
}

/// Generate an ISO-9660 + Joliet disk image filesystem containing all files from `root_dir`.
pub fn generate_iso_image(
    root_dir: &Path,
    volume_name: &str,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut root_node = IsoNode::from_path(root_dir)?;
    root_node.name = volume_name.to_string();

    // Collect all directory nodes and file nodes in order
    fn collect_nodes(
        node: &mut IsoNode,
        parent_sec: u32,
        parent_sz: u32,
        dirs: &mut Vec<*mut IsoNode>,
        files: &mut Vec<*mut IsoNode>,
    ) {
        node.parent_sector = parent_sec;
        node.parent_size = parent_sz;
        if node.is_dir {
            dirs.push(node as *mut IsoNode);
            let cur_sec = node.sector;
            let cur_sz = node.size;
            for child in &mut node.children {
                collect_nodes(child, cur_sec, cur_sz, dirs, files);
            }
        } else {
            files.push(node as *mut IsoNode);
        }
    }

    // Two-pass layout:
    // Pass 1: compute directory record sizes and sector layout
    // Sectors:
    // 0..15: system area (32768 bytes)
    // 16: PVD
    // 17: SVD (Joliet)
    // 18: VDST (Terminator)
    // 19: ISO root
    // 20+: Joliet directories, followed by files
    let mut dirs_ptrs = Vec::new();
    let mut files_ptrs = Vec::new();
    collect_nodes(&mut root_node, 20, 2048, &mut dirs_ptrs, &mut files_ptrs);

    let mut cur_sector = 20u32;
    for &d_ptr in &dirs_ptrs {
        let d = unsafe { &mut *d_ptr };
        d.sector = cur_sector;
        let mut rec_size = make_dir_record(0, 0, 2, b"\x00").len()
            + make_dir_record(0, 0, 2, b"\x01").len();
        for child in &d.children {
            let name_bytes = ucs2_be(&child.name);
            rec_size += make_dir_record(0, 0, if child.is_dir { 2 } else { 0 }, &name_bytes).len();
        }
        let sec_count = rec_size.div_ceil(SECTOR_SIZE).max(1) as u32;
        d.size = sec_count * SECTOR_SIZE as u32;
        cur_sector += sec_count;
    }

    for &f_ptr in &files_ptrs {
        let f = unsafe { &mut *f_ptr };
        f.sector = cur_sector;
        let sec_count = (f.size as usize).div_ceil(SECTOR_SIZE).max(1) as u32;
        cur_sector += sec_count;
    }

    // Update parent sectors and sizes now that sectors are assigned
    dirs_ptrs.clear();
    files_ptrs.clear();
    let root_sec = root_node.sector;
    let root_sz = root_node.size;
    collect_nodes(&mut root_node, root_sec, root_sz, &mut dirs_ptrs, &mut files_ptrs);

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
    let pvd_root = make_dir_record(19, 2048, 2, b"\x00");
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
    let svd_root = make_dir_record(root_node.sector, root_node.size, 2, b"\x00");
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
    let r0 = make_dir_record(19, 2048, 2, b"\x00");
    let r1 = make_dir_record(19, 2048, 2, b"\x01");
    iso_root[..r0.len()].copy_from_slice(&r0);
    iso_root[r0.len()..r0.len() + r1.len()].copy_from_slice(&r1);
    iso.extend_from_slice(&iso_root);

    // Joliet directories
    for &d_ptr in &dirs_ptrs {
        let d = unsafe { &*d_ptr };
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

        let dot_rec = make_dir_record(d.sector, d.size, 2, b"\x00");
        let dotdot_rec = make_dir_record(parent_sec, parent_sz, 2, b"\x01");
        let mut off = 0;
        d_block[off..off + dot_rec.len()].copy_from_slice(&dot_rec);
        off += dot_rec.len();
        d_block[off..off + dotdot_rec.len()].copy_from_slice(&dotdot_rec);
        off += dotdot_rec.len();

        for child in &d.children {
            let name_bytes = ucs2_be(&child.name);
            let rec = make_dir_record(
                child.sector,
                child.size,
                if child.is_dir { 2 } else { 0 },
                &name_bytes,
            );
            if off + rec.len() <= d_block.len() {
                d_block[off..off + rec.len()].copy_from_slice(&rec);
                off += rec.len();
            }
        }
        iso.extend_from_slice(&d_block);
    }

    // File contents
    for &f_ptr in &files_ptrs {
        let f = unsafe { &*f_ptr };
        let sec_count = (f.size as usize).div_ceil(SECTOR_SIZE).max(1);
        let mut f_block = vec![0u8; sec_count * SECTOR_SIZE];
        f_block[..f.data.len()].copy_from_slice(&f.data);
        iso.extend_from_slice(&f_block);
    }

    Ok(iso)
}

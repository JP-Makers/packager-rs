// Pure-Rust Microsoft Cabinet (.cab) builder for Windows Installer (MSI) embedded payloads.
// Implements the MSCF specification without external tools or dependencies.

/// Represents a file entry to be stored inside a cabinet.
pub struct CabFileEntry<'a> {
    /// File identifier or name inside the cabinet (in embedded MSI CABs, this matches the File table key).
    pub name: &'a str,
    /// Uncompressed file payload.
    pub data: &'a [u8],
}

/// Computes the MS-CAB block checksum for the given data bytes with an initial seed.
pub fn compute_cab_checksum(data: &[u8], seed: u32) -> u32 {
    let mut sum = seed;
    let (chunks, rem) = data.as_chunks::<4>();
    for chunk in chunks {
        let val = u32::from_le_bytes(*chunk);
        sum ^= val;
    }
    if !rem.is_empty() {
        let mut last = 0u32;
        for (i, &b) in rem.iter().enumerate() {
            last |= (b as u32) << (i * 8);
        }
        sum ^= last;
    }
    sum
}

/// Builds a pure-Rust uncompressed Microsoft Cabinet (.cab) binary containing the given files.
pub fn create_cabinet(files: &[CabFileEntry<'_>]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    const CHUNK_SIZE: usize = 32768; // 32 KiB uncompressed CFDATA block size

    // Concatenate all uncompressed file payloads into one folder
    let mut folder_payload = Vec::new();
    let mut file_offsets = Vec::with_capacity(files.len());

    for entry in files {
        let offset = folder_payload.len() as u32;
        file_offsets.push(offset);
        folder_payload.extend_from_slice(entry.data);
    }

    // Number of CFDATA blocks
    let num_cfdata = if folder_payload.is_empty() {
        1
    } else {
        folder_payload.len().div_ceil(CHUNK_SIZE)
    };

    // Calculate sizes and offsets
    let cfheader_size: u32 = 36;
    let cffolder_size: u32 = 8;
    let coff_files: u32 = cfheader_size + cffolder_size;

    let mut cffiles_size: u32 = 0;
    for entry in files {
        // cbFile (4) + uoffFolderStart (4) + iFolder (2) + date (2) + time (2) + attribs (2) + name + null terminator
        cffiles_size += 16 + (entry.name.len() as u32) + 1;
    }

    let coff_cab_start: u32 = coff_files + cffiles_size;

    // Calculate total cabinet size
    let mut total_cfdata_size: u32 = 0;
    if folder_payload.is_empty() {
        total_cfdata_size += 8; // empty CFDATA block: 4 (csum) + 2 (cbData) + 2 (cbUncomp)
    } else {
        for chunk in folder_payload.chunks(CHUNK_SIZE) {
            total_cfdata_size += 8 + (chunk.len() as u32);
        }
    }
    let total_cabinet_size: u32 = coff_cab_start + total_cfdata_size;

    let mut out = Vec::with_capacity(total_cabinet_size as usize);

    // 1. Write CFHEADER (36 bytes)
    out.extend_from_slice(b"MSCF"); // signature
    out.extend_from_slice(&0u32.to_le_bytes()); // reserved1
    out.extend_from_slice(&total_cabinet_size.to_le_bytes()); // cbCabinet
    out.extend_from_slice(&0u32.to_le_bytes()); // reserved2
    out.extend_from_slice(&coff_files.to_le_bytes()); // coffFiles
    out.extend_from_slice(&0u32.to_le_bytes()); // reserved3
    out.push(3); // versionMinor (1.3)
    out.push(1); // versionMajor
    out.extend_from_slice(&1u16.to_le_bytes()); // cFolders (1 folder)
    out.extend_from_slice(&(files.len() as u16).to_le_bytes()); // cFiles
    out.extend_from_slice(&0u16.to_le_bytes()); // flags
    out.extend_from_slice(&1u16.to_le_bytes()); // setID
    out.extend_from_slice(&0u16.to_le_bytes()); // iCabinet

    // 2. Write CFFOLDER (8 bytes)
    out.extend_from_slice(&coff_cab_start.to_le_bytes()); // coffCabStart
    out.extend_from_slice(&(num_cfdata as u16).to_le_bytes()); // cCFData
    out.extend_from_slice(&0u16.to_le_bytes()); // typeCompress (0x0000 = tcompTYPE_NONE)

    // Fixed MS-DOS date & time (2026-01-01 00:00:00)
    let dos_date: u16 = (46 << 9) | (1 << 5) | 1;
    let dos_time: u16 = 0;

    // 3. Write CFFILE entries
    for (i, entry) in files.iter().enumerate() {
        out.extend_from_slice(&(entry.data.len() as u32).to_le_bytes()); // cbFile
        out.extend_from_slice(&file_offsets[i].to_le_bytes()); // uoffFolderStart
        out.extend_from_slice(&0u16.to_le_bytes()); // iFolder (folder index 0)
        out.extend_from_slice(&dos_date.to_le_bytes()); // date
        out.extend_from_slice(&dos_time.to_le_bytes()); // time
        out.extend_from_slice(&0x20u16.to_le_bytes()); // attribs (_A_ARCH = archive)
        out.extend_from_slice(entry.name.as_bytes()); // szName
        out.push(0); // null terminator
    }

    assert_eq!(out.len() as u32, coff_cab_start);

    // 4. Write CFDATA blocks
    if folder_payload.is_empty() {
        let mut header_buf = [0u8; 4];
        header_buf[0..2].copy_from_slice(&0u16.to_le_bytes());
        header_buf[2..4].copy_from_slice(&0u16.to_le_bytes());
        let csum = compute_cab_checksum(&header_buf, 0);
        out.extend_from_slice(&csum.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes()); // cbData
        out.extend_from_slice(&0u16.to_le_bytes()); // cbUncomp
    } else {
        for chunk in folder_payload.chunks(CHUNK_SIZE) {
            let cb_data = chunk.len() as u16;
            let cb_uncomp = chunk.len() as u16;
            let mut header_buf = [0u8; 4];
            header_buf[0..2].copy_from_slice(&cb_data.to_le_bytes());
            header_buf[2..4].copy_from_slice(&cb_uncomp.to_le_bytes());
            let mut csum = compute_cab_checksum(&header_buf, 0);
            csum = compute_cab_checksum(chunk, csum);

            out.extend_from_slice(&csum.to_le_bytes());
            out.extend_from_slice(&cb_data.to_le_bytes());
            out.extend_from_slice(&cb_uncomp.to_le_bytes());
            out.extend_from_slice(chunk);
        }
    }

    assert_eq!(out.len() as u32, total_cabinet_size);

    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_cabinet_structure() {
        let files = vec![
            CabFileEntry {
                name: "fil_main.exe",
                data: b"MZ\x90\x00\x03\x00\x00\x00This is executable payload",
            },
            CabFileEntry {
                name: "fil_notice.txt",
                data: b"Sample notice text",
            },
        ];

        let cab_bytes = create_cabinet(&files).expect("failed to create cabinet");
        assert!(cab_bytes.len() > 36 + 8);
        assert_eq!(&cab_bytes[0..4], b"MSCF");

        // Verify total size in header matches actual bytes
        let total_size = u32::from_le_bytes(cab_bytes[8..12].try_into().unwrap());
        assert_eq!(total_size as usize, cab_bytes.len());

        // Verify number of folders and files
        let num_folders = u16::from_le_bytes(cab_bytes[26..28].try_into().unwrap());
        assert_eq!(num_folders, 1);
        let num_files = u16::from_le_bytes(cab_bytes[28..30].try_into().unwrap());
        assert_eq!(num_files, 2);
    }
}

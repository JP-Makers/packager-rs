// Pure-Rust Microsoft Cabinet (.cab) builder for Windows Installer (MSI) embedded payloads.
// Implements the MSCF specification without external tools or dependencies.

use flate2::Compression;
use flate2::write::DeflateEncoder;
use std::io::Write;

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

/// Builds a pure-Rust Microsoft Cabinet (.cab) binary containing the given files with MSZIP compression.
pub fn create_cabinet(files: &[CabFileEntry<'_>]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    create_cabinet_with_compression(files, true)
}

/// Builds a pure-Rust Microsoft Cabinet (.cab) binary with optional MSZIP compression.
pub fn create_cabinet_with_compression(
    files: &[CabFileEntry<'_>],
    compress: bool,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    const CHUNK_SIZE: usize = 32768; // 32 KiB uncompressed CFDATA block size

    // Concatenate all uncompressed file payloads into one folder
    let mut folder_payload = Vec::new();
    let mut file_offsets = Vec::with_capacity(files.len());

    for entry in files {
        let offset = u32::try_from(folder_payload.len())
            .map_err(|_| "folder payload exceeds 4GB limit for CAB")?;
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
        let name_len =
            u32::try_from(entry.name.len()).map_err(|_| "file entry name exceeds 4GB limit")?;
        // cbFile (4) + uoffFolderStart (4) + iFolder (2) + date (2) + time (2) + attribs (2) + name + null terminator
        cffiles_size = cffiles_size
            .checked_add(16 + name_len + 1)
            .ok_or("file table size overflow in CAB")?;
    }

    let coff_cab_start: u32 = coff_files
        .checked_add(cffiles_size)
        .ok_or("CAB offset overflow")?;

    // Compress chunks ahead of time if MSZIP is enabled
    enum PreparedBlock {
        Empty,
        Uncompressed(Vec<u8>),
        Mszip {
            compressed: Vec<u8>,
            uncompressed_len: u16,
        },
    }

    let mut prepared_blocks = Vec::new();
    let mut total_cfdata_size: u32 = 0;

    if folder_payload.is_empty() {
        prepared_blocks.push(PreparedBlock::Empty);
        total_cfdata_size += 8;
    } else {
        for chunk in folder_payload.chunks(CHUNK_SIZE) {
            let uncomp_len =
                u16::try_from(chunk.len()).map_err(|_| "chunk size exceeds 65535 bytes")?;

            if compress {
                let mut encoder = DeflateEncoder::new(Vec::new(), Compression::default());
                encoder.write_all(chunk)?;
                let deflated = encoder.finish()?;

                let mut mszip_data = Vec::with_capacity(2 + deflated.len());
                mszip_data.extend_from_slice(b"CK");
                mszip_data.extend_from_slice(&deflated);

                let cb_data = u16::try_from(mszip_data.len())
                    .map_err(|_| "compressed block exceeds 65535 bytes")?;

                total_cfdata_size = total_cfdata_size
                    .checked_add(8 + u32::from(cb_data))
                    .ok_or("CFDATA size overflow")?;

                prepared_blocks.push(PreparedBlock::Mszip {
                    compressed: mszip_data,
                    uncompressed_len: uncomp_len,
                });
            } else {
                total_cfdata_size = total_cfdata_size
                    .checked_add(8 + u32::from(uncomp_len))
                    .ok_or("CFDATA size overflow")?;
                prepared_blocks.push(PreparedBlock::Uncompressed(chunk.to_vec()));
            }
        }
    }

    let total_cabinet_size: u32 = coff_cab_start
        .checked_add(total_cfdata_size)
        .ok_or("CAB total size overflow")?;

    let cap = usize::try_from(total_cabinet_size)
        .map_err(|_| "CAB total size exceeds platform memory capacity")?;
    let mut out = Vec::with_capacity(cap);

    let num_files_u16 =
        u16::try_from(files.len()).map_err(|_| "file count exceeds 65535 limit for CAB")?;
    let num_cfdata_u16 =
        u16::try_from(num_cfdata).map_err(|_| "CFDATA block count exceeds 65535 limit for CAB")?;

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
    out.extend_from_slice(&num_files_u16.to_le_bytes()); // cFiles
    out.extend_from_slice(&0u16.to_le_bytes()); // flags
    out.extend_from_slice(&1u16.to_le_bytes()); // setID
    out.extend_from_slice(&0u16.to_le_bytes()); // iCabinet

    // 2. Write CFFOLDER (8 bytes)
    let type_compress: u16 = if compress { 0x0001 } else { 0x0000 }; // 0x0001 = tcompTYPE_MSZIP
    out.extend_from_slice(&coff_cab_start.to_le_bytes()); // coffCabStart
    out.extend_from_slice(&num_cfdata_u16.to_le_bytes()); // cCFData
    out.extend_from_slice(&type_compress.to_le_bytes()); // typeCompress

    // Fixed MS-DOS date & time (2026-01-01 00:00:00)
    let dos_date: u16 = (46 << 9) | (1 << 5) | 1;
    let dos_time: u16 = 0;

    // 3. Write CFFILE entries
    for (i, entry) in files.iter().enumerate() {
        let entry_len =
            u32::try_from(entry.data.len()).map_err(|_| "file size exceeds 4GB limit for CAB")?;
        out.extend_from_slice(&entry_len.to_le_bytes()); // cbFile
        out.extend_from_slice(&file_offsets[i].to_le_bytes()); // uoffFolderStart
        out.extend_from_slice(&0u16.to_le_bytes()); // iFolder (folder index 0)
        out.extend_from_slice(&dos_date.to_le_bytes()); // date
        out.extend_from_slice(&dos_time.to_le_bytes()); // time
        out.extend_from_slice(&0x20u16.to_le_bytes()); // attribs (_A_ARCH = archive)
        out.extend_from_slice(entry.name.as_bytes()); // szName
        out.push(0); // null terminator
    }

    let current_len = u32::try_from(out.len()).map_err(|_| "CAB size exceeds 4GB")?;
    if current_len != coff_cab_start {
        return Err(format!(
            "internal error: CAB header and file table offset mismatch: expected {coff_cab_start}, got {current_len}"
        )
        .into());
    }

    // 4. Write CFDATA blocks
    for block in prepared_blocks {
        match block {
            PreparedBlock::Empty => {
                let mut header_buf = [0u8; 4];
                header_buf[0..2].copy_from_slice(&0u16.to_le_bytes());
                header_buf[2..4].copy_from_slice(&0u16.to_le_bytes());
                let csum = compute_cab_checksum(&header_buf, 0);
                out.extend_from_slice(&csum.to_le_bytes());
                out.extend_from_slice(&0u16.to_le_bytes()); // cbData
                out.extend_from_slice(&0u16.to_le_bytes()); // cbUncomp
            }
            PreparedBlock::Uncompressed(chunk) => {
                let cb_data =
                    u16::try_from(chunk.len()).map_err(|_| "chunk length exceeds u16 limit")?;
                let cb_uncomp = cb_data;
                let mut header_buf = [0u8; 4];
                header_buf[0..2].copy_from_slice(&cb_data.to_le_bytes());
                header_buf[2..4].copy_from_slice(&cb_uncomp.to_le_bytes());
                let mut csum = compute_cab_checksum(&header_buf, 0);
                csum = compute_cab_checksum(&chunk, csum);

                out.extend_from_slice(&csum.to_le_bytes());
                out.extend_from_slice(&cb_data.to_le_bytes());
                out.extend_from_slice(&cb_uncomp.to_le_bytes());
                out.extend_from_slice(&chunk);
            }
            PreparedBlock::Mszip {
                compressed,
                uncompressed_len,
            } => {
                let cb_data = u16::try_from(compressed.len())
                    .map_err(|_| "compressed length exceeds u16 limit")?;
                let cb_uncomp = uncompressed_len;
                let mut header_buf = [0u8; 4];
                header_buf[0..2].copy_from_slice(&cb_data.to_le_bytes());
                header_buf[2..4].copy_from_slice(&cb_uncomp.to_le_bytes());
                let mut csum = compute_cab_checksum(&header_buf, 0);
                csum = compute_cab_checksum(&compressed, csum);

                out.extend_from_slice(&csum.to_le_bytes());
                out.extend_from_slice(&cb_data.to_le_bytes());
                out.extend_from_slice(&cb_uncomp.to_le_bytes());
                out.extend_from_slice(&compressed);
            }
        }
    }

    let final_len = u32::try_from(out.len()).map_err(|_| "CAB size exceeds 4GB")?;
    if final_len != total_cabinet_size {
        return Err(format!(
            "internal error: CAB total size mismatch: expected {total_cabinet_size}, got {final_len}"
        )
        .into());
    }

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

        // Verify MSZIP compression signature
        let type_compress = u16::from_le_bytes(cab_bytes[42..44].try_into().unwrap());
        assert_eq!(type_compress, 0x0001); // MSZIP
    }

    #[test]
    fn test_create_cabinet_uncompressed() {
        let files = vec![CabFileEntry {
            name: "test.txt",
            data: b"Uncompressed test payload",
        }];
        let cab_bytes =
            create_cabinet_with_compression(&files, false).expect("uncompressed cabinet");
        assert_eq!(&cab_bytes[0..4], b"MSCF");
        let type_compress = u16::from_le_bytes(cab_bytes[42..44].try_into().unwrap());
        assert_eq!(type_compress, 0x0000);
    }
}

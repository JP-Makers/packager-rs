use xml::reader::EventReader;
use xml::writer::{EmitterConfig, XmlEvent};

/// Calculate standard CRC32 (polynomial 0xEDB88320).
pub fn crc32(data: &[u8]) -> u32 {
    let mut crc: u32 = 0xFFFF_FFFF;
    for &byte in data {
        crc ^= byte as u32;
        for _ in 0..8 {
            let mask = -((crc & 1) as i32) as u32;
            crc = (crc >> 1) ^ (0xEDB8_8320 & mask);
        }
    }
    !crc
}

/// Standard Base64 encoding without external dependencies.
pub fn base64_encode(data: &[u8]) -> String {
    const CHARSET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let b0 = chunk[0] as usize;
        let b1 = if chunk.len() > 1 {
            chunk[1] as usize
        } else {
            0
        };
        let b2 = if chunk.len() > 2 {
            chunk[2] as usize
        } else {
            0
        };

        out.push(CHARSET[b0 >> 2] as char);
        out.push(CHARSET[((b0 & 0x03) << 4) | (b1 >> 4)] as char);
        if chunk.len() > 1 {
            out.push(CHARSET[((b1 & 0x0F) << 2) | (b2 >> 6)] as char);
        } else {
            out.push('=');
        }
        if chunk.len() > 2 {
            out.push(CHARSET[b2 & 0x3F] as char);
        } else {
            out.push('=');
        }
    }
    out
}

/// Build a 136-byte UDIF checksum descriptor (Type 2 = CRC32, size = 32 bits).
pub fn build_udif_checksum(crc: u32) -> [u8; 136] {
    let mut buf = [0u8; 136];
    buf[0..4].copy_from_slice(&2u32.to_be_bytes()); // Type: 2 (CRC32)
    buf[4..8].copy_from_slice(&32u32.to_be_bytes()); // Bit size: 32
    buf[8..12].copy_from_slice(&crc.to_be_bytes()); // CRC value
    buf
}

/// Build the binary `mish` block descriptor for the UDIF resource fork.
pub fn build_mish_block(data_len: u64, num_sectors: u64, data_crc: u32) -> Vec<u8> {
    let mut mish = Vec::with_capacity(204 + 40 + 40);

    // mish header (204 bytes)
    mish.extend_from_slice(b"mish"); // 0..4: Signature
    mish.extend_from_slice(&1u32.to_be_bytes()); // 4..8: Version 1
    mish.extend_from_slice(&0u64.to_be_bytes()); // 8..16: SectorNumber
    mish.extend_from_slice(&num_sectors.to_be_bytes()); // 16..24: SectorCount
    mish.extend_from_slice(&0u64.to_be_bytes()); // 24..32: DataOffset
    mish.extend_from_slice(&0u32.to_be_bytes()); // 32..36: BuffersNeeded
    mish.extend_from_slice(&0u32.to_be_bytes()); // 36..40: BlockDescriptors
    mish.extend_from_slice(&[0u8; 24]); // 40..64: Reserved
    mish.extend_from_slice(&build_udif_checksum(data_crc)); // 64..200: Checksum (136 bytes)
    mish.extend_from_slice(&2u32.to_be_bytes()); // 200..204: NumberOfBlockChunks: 2

    // Chunk 0: Raw copy chunk (40 bytes)
    mish.extend_from_slice(&1u32.to_be_bytes()); // Type: 1 (raw)
    mish.extend_from_slice(&0u32.to_be_bytes()); // Comment
    mish.extend_from_slice(&0u64.to_be_bytes()); // SectorNumber
    mish.extend_from_slice(&num_sectors.to_be_bytes()); // SectorCount
    mish.extend_from_slice(&0u64.to_be_bytes()); // CompressedOffset
    mish.extend_from_slice(&data_len.to_be_bytes()); // CompressedLength

    // Chunk 1: Terminator chunk (40 bytes)
    mish.extend_from_slice(&0xFFFF_FFFFu32.to_be_bytes()); // Type: 0xFFFFFFFF (terminator)
    mish.extend_from_slice(&0u32.to_be_bytes()); // Comment
    mish.extend_from_slice(&num_sectors.to_be_bytes()); // SectorNumber
    mish.extend_from_slice(&0u64.to_be_bytes()); // SectorCount: 0
    mish.extend_from_slice(&data_len.to_be_bytes()); // CompressedOffset: data_len
    mish.extend_from_slice(&0u64.to_be_bytes()); // CompressedLength: 0

    mish
}

/// Build the embedded XML plist describing the disk image and its `blkx` block using `xml::writer`.
pub fn create_udif_plist(volume_name: &str, mish_bytes: &[u8]) -> Vec<u8> {
    let mish_b64 = base64_encode(mish_bytes);
    let mut body_bytes = Vec::new();
    {
        let mut writer = EmitterConfig::new()
            .perform_indent(true)
            .indent_string("    ")
            .write_document_declaration(false)
            .create_writer(&mut body_bytes);

        writer
            .write(XmlEvent::start_element("plist").attr("version", "1.0"))
            .expect("Failed plist start");
        writer
            .write(XmlEvent::start_element("dict"))
            .expect("Failed dict");

        writer
            .write(XmlEvent::start_element("key"))
            .expect("Failed key");
        writer
            .write(XmlEvent::characters("resource-fork"))
            .expect("Failed chars");
        writer.write(XmlEvent::end_element()).expect("Failed end");

        writer
            .write(XmlEvent::start_element("dict"))
            .expect("Failed dict");

        writer
            .write(XmlEvent::start_element("key"))
            .expect("Failed key");
        writer
            .write(XmlEvent::characters("blkx"))
            .expect("Failed chars");
        writer.write(XmlEvent::end_element()).expect("Failed end");

        writer
            .write(XmlEvent::start_element("array"))
            .expect("Failed array");

        writer
            .write(XmlEvent::start_element("dict"))
            .expect("Failed dict");

        writer
            .write(XmlEvent::start_element("key"))
            .expect("Failed key");
        writer
            .write(XmlEvent::characters("Attributes"))
            .expect("Failed chars");
        writer.write(XmlEvent::end_element()).expect("Failed end");
        writer
            .write(XmlEvent::start_element("string"))
            .expect("Failed string");
        writer
            .write(XmlEvent::characters("0x00000000"))
            .expect("Failed chars");
        writer.write(XmlEvent::end_element()).expect("Failed end");

        writer
            .write(XmlEvent::start_element("key"))
            .expect("Failed key");
        writer
            .write(XmlEvent::characters("Data"))
            .expect("Failed chars");
        writer.write(XmlEvent::end_element()).expect("Failed end");
        writer
            .write(XmlEvent::start_element("data"))
            .expect("Failed data");
        writer
            .write(XmlEvent::characters(&mish_b64))
            .expect("Failed chars");
        writer.write(XmlEvent::end_element()).expect("Failed end");

        writer
            .write(XmlEvent::start_element("key"))
            .expect("Failed key");
        writer
            .write(XmlEvent::characters("ID"))
            .expect("Failed chars");
        writer.write(XmlEvent::end_element()).expect("Failed end");
        writer
            .write(XmlEvent::start_element("string"))
            .expect("Failed string");
        writer
            .write(XmlEvent::characters("-1"))
            .expect("Failed chars");
        writer.write(XmlEvent::end_element()).expect("Failed end");

        writer
            .write(XmlEvent::start_element("key"))
            .expect("Failed key");
        writer
            .write(XmlEvent::characters("Name"))
            .expect("Failed chars");
        writer.write(XmlEvent::end_element()).expect("Failed end");
        writer
            .write(XmlEvent::start_element("string"))
            .expect("Failed string");
        writer
            .write(XmlEvent::characters(volume_name))
            .expect("Failed chars");
        writer.write(XmlEvent::end_element()).expect("Failed end");

        // Close dict, array, dict, dict, plist
        writer.write(XmlEvent::end_element()).expect("Failed end");
        writer.write(XmlEvent::end_element()).expect("Failed end");
        writer.write(XmlEvent::end_element()).expect("Failed end");
        writer.write(XmlEvent::end_element()).expect("Failed end");
        writer.write(XmlEvent::end_element()).expect("Failed end");
    }

    let body_str = String::from_utf8(body_bytes).expect("Valid UTF-8 XML");
    let xml = format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n{}\n",
        body_str
    );

    // Validate with EventReader
    let reader = EventReader::from_str(&xml);
    for event in reader {
        let _ = event.expect("UDIF plist must be well-formed XML");
    }

    xml.into_bytes()
}

/// Build the 512-byte Apple UDIF `koly` trailer.
pub fn build_koly_trailer(
    data_len: u64,
    num_sectors: u64,
    xml_offset: u64,
    xml_len: u64,
    data_crc: u32,
) -> [u8; 512] {
    let mut koly = [0u8; 512];

    koly[0..4].copy_from_slice(b"koly"); // Signature
    koly[4..8].copy_from_slice(&4u32.to_be_bytes()); // Version 4
    koly[8..12].copy_from_slice(&512u32.to_be_bytes()); // Header size 512
    koly[12..16].copy_from_slice(&1u32.to_be_bytes()); // Flags: 1
    koly[16..24].copy_from_slice(&0u64.to_be_bytes()); // RunningDataForkOffset
    koly[24..32].copy_from_slice(&0u64.to_be_bytes()); // DataForkOffset
    koly[32..40].copy_from_slice(&data_len.to_be_bytes()); // DataForkLength
    koly[40..48].copy_from_slice(&0u64.to_be_bytes()); // RsrcForkOffset
    koly[48..56].copy_from_slice(&0u64.to_be_bytes()); // RsrcForkLength
    koly[56..60].copy_from_slice(&1u32.to_be_bytes()); // SegmentNumber
    koly[60..64].copy_from_slice(&1u32.to_be_bytes()); // SegmentCount
    // 64..80: SegmentID (16 bytes zeros)
    let data_cs = build_udif_checksum(data_crc);
    koly[80..216].copy_from_slice(&data_cs); // DataForkChecksum
    koly[216..224].copy_from_slice(&xml_offset.to_be_bytes()); // XMLOffset
    koly[224..232].copy_from_slice(&xml_len.to_be_bytes()); // XMLLength
    // 232..352: Reserved (120 bytes zeros)
    // 352..488: MasterChecksum (136 bytes zeros, Type 0)
    koly[488..492].copy_from_slice(&1u32.to_be_bytes()); // ImageVariant: 1
    koly[492..500].copy_from_slice(&num_sectors.to_be_bytes()); // SectorCount
    // 500..512: Reserved (12 bytes zeros)

    koly
}

/// Pack raw filesystem payload bytes into an Apple UDIF (.dmg) container.
pub fn create_udif_dmg_image(volume_name: &str, payload: &[u8]) -> Vec<u8> {
    let data_len = payload.len() as u64;
    let num_sectors = data_len.div_ceil(512);
    let data_crc = crc32(payload);

    let mish = build_mish_block(data_len, num_sectors, data_crc);
    let plist = create_udif_plist(volume_name, &mish);

    let xml_offset = data_len;
    let xml_len = plist.len() as u64;

    let koly = build_koly_trailer(data_len, num_sectors, xml_offset, xml_len, data_crc);

    let mut output = Vec::with_capacity(payload.len() + plist.len() + 512);
    output.extend_from_slice(payload);
    output.extend_from_slice(&plist);
    output.extend_from_slice(&koly);

    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_crc32() {
        assert_eq!(crc32(b"Hello from DMG!"), 0xB9830F71);
    }

    #[test]
    fn test_base64() {
        assert_eq!(base64_encode(b""), "");
        assert_eq!(base64_encode(b"f"), "Zg==");
        assert_eq!(base64_encode(b"fo"), "Zm8=");
        assert_eq!(base64_encode(b"foo"), "Zm9v");
    }

    #[test]
    fn test_koly_trailer_size() {
        let koly = build_koly_trailer(2048, 4, 2048, 500, 0x12345678);
        assert_eq!(koly.len(), 512);
        assert_eq!(&koly[0..4], b"koly");
    }
}

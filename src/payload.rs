//! Executable payload identification.
//!
//! The macOS and Windows writers must never package a binary built for a
//! different operating system. Both checks only inspect the first few bytes, so
//! they are cheap enough to run before any artifact is written.

/// Return true when `bytes` starts with a Mach-O thin or fat binary magic.
pub(crate) fn is_macho(bytes: &[u8]) -> bool {
    matches!(
        bytes.get(..4),
        Some(
            // 32-bit big endian, 32-bit little endian
            [0xfe, 0xed, 0xfa, 0xce] | [0xce, 0xfa, 0xed, 0xfe]
            // 64-bit big endian, 64-bit little endian
            | [0xfe, 0xed, 0xfa, 0xcf] | [0xcf, 0xfa, 0xed, 0xfe]
            // fat binary, fat binary with 64-bit offsets
            | [0xca, 0xfe, 0xba, 0xbe] | [0xca, 0xfe, 0xba, 0xbf]
        )
    )
}

const CPU_TYPE_X86_64: u32 = 0x01000007;
const CPU_TYPE_ARM64: u32 = 0x0100000c;

/// Return true when `bytes` is a Mach-O binary compatible with `declared_arch`.
pub(crate) fn macho_matches_arch(bytes: &[u8], declared_arch: &str) -> bool {
    let magic = match bytes.get(..4) {
        Some(m) => m,
        None => return false,
    };

    let target_cpu = match declared_arch {
        "x86_64" | "amd64" => Some(CPU_TYPE_X86_64),
        "aarch64" | "arm64" => Some(CPU_TYPE_ARM64),
        "universal" => None,
        _ => return true,
    };

    match magic {
        // Thin 64-bit little endian
        [0xcf, 0xfa, 0xed, 0xfe] => {
            if let Some(target) = target_cpu {
                let cputype = bytes
                    .get(4..8)
                    .map(|b| u32::from_le_bytes(b.try_into().unwrap()));
                cputype == Some(target)
            } else {
                true
            }
        }
        // Thin 64-bit big endian
        [0xfe, 0xed, 0xfa, 0xcf] => {
            if let Some(target) = target_cpu {
                let cputype = bytes
                    .get(4..8)
                    .map(|b| u32::from_be_bytes(b.try_into().unwrap()));
                cputype == Some(target)
            } else {
                true
            }
        }
        // Fat binary (big-endian)
        [0xca, 0xfe, 0xba, 0xbe] => {
            let Some(count_bytes) = bytes.get(4..8) else {
                return false;
            };
            let nfat = u32::from_be_bytes(count_bytes.try_into().unwrap()) as usize;
            if let Some(target) = target_cpu {
                for i in 0..nfat {
                    let offset = 8 + i * 20;
                    if let Some(arch_bytes) = bytes.get(offset..offset + 4) {
                        let cputype = u32::from_be_bytes(arch_bytes.try_into().unwrap());
                        if cputype == target {
                            return true;
                        }
                    }
                }
                false
            } else {
                true
            }
        }
        [0xce, 0xfa, 0xed, 0xfe] | [0xfe, 0xed, 0xfa, 0xce] => true,
        _ => false,
    }
}

/// Return true when `bytes` is a Windows PE image (`MZ` header plus `PE\0\0`).
pub(crate) fn is_pe(bytes: &[u8]) -> bool {
    if !bytes.starts_with(b"MZ") {
        return false;
    }
    let Some(offset_bytes) = bytes.get(0x3c..0x40) else {
        return false;
    };
    let offset = u32::from_le_bytes([
        offset_bytes[0],
        offset_bytes[1],
        offset_bytes[2],
        offset_bytes[3],
    ]) as usize;
    bytes
        .get(offset..offset + 4)
        .is_some_and(|signature| signature == b"PE\0\0")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pe_fixture() -> Vec<u8> {
        let mut bytes = vec![0u8; 0x80];
        bytes[0] = b'M';
        bytes[1] = b'Z';
        bytes[0x3c..0x40].copy_from_slice(&0x40u32.to_le_bytes());
        bytes[0x40..0x44].copy_from_slice(b"PE\0\0");
        bytes
    }

    #[test]
    fn test_is_pe_accepts_valid_header() {
        assert!(is_pe(&pe_fixture()));
    }

    #[test]
    fn test_is_pe_rejects_elf_and_truncated() {
        assert!(!is_pe(b"\x7fELF\x02\x01\x01"));
        assert!(!is_pe(b"MZ"));
        let mut broken = pe_fixture();
        broken[0x40..0x44].copy_from_slice(b"PE\0\x01");
        assert!(!is_pe(&broken));
    }

    #[test]
    fn test_is_macho_accepts_all_magics() {
        for magic in [
            [0xfe, 0xed, 0xfa, 0xce],
            [0xce, 0xfa, 0xed, 0xfe],
            [0xfe, 0xed, 0xfa, 0xcf],
            [0xcf, 0xfa, 0xed, 0xfe],
            [0xca, 0xfe, 0xba, 0xbe],
            [0xca, 0xfe, 0xba, 0xbf],
        ] {
            assert!(is_macho(&magic), "magic {magic:02x?} must be accepted");
        }
    }

    #[test]
    fn test_is_macho_rejects_elf_and_short_input() {
        assert!(!is_macho(b"\x7fELF"));
        assert!(!is_macho(b"\xcf\xfa"));
        assert!(!is_macho(&[]));
    }

    #[test]
    fn test_macho_matches_arch() {
        // x86_64 Mach-O fixture (little endian 64-bit)
        let mut x86_64_bin = vec![0u8; 16];
        x86_64_bin[..4].copy_from_slice(&[0xcf, 0xfa, 0xed, 0xfe]);
        x86_64_bin[4..8].copy_from_slice(&0x01000007u32.to_le_bytes());

        // arm64 Mach-O fixture (little endian 64-bit)
        let mut arm64_bin = vec![0u8; 16];
        arm64_bin[..4].copy_from_slice(&[0xcf, 0xfa, 0xed, 0xfe]);
        arm64_bin[4..8].copy_from_slice(&0x0100000cu32.to_le_bytes());

        assert!(macho_matches_arch(&x86_64_bin, "x86_64"));
        assert!(!macho_matches_arch(&x86_64_bin, "arm64"));

        assert!(macho_matches_arch(&arm64_bin, "arm64"));
        assert!(macho_matches_arch(&arm64_bin, "aarch64"));
        assert!(!macho_matches_arch(&arm64_bin, "x86_64"));

        assert!(macho_matches_arch(&x86_64_bin, "universal"));
    }
}

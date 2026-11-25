//! `MacBinary` header detection, stripping and writing
//!
//! Many classic Mac files transferred to non-HFS media are wrapped in a
//! 128-byte `MacBinary` header that encodes the resource/data fork lengths,
//! type/creator codes, and Finder flags. The wrapper is detected and stripped,
//! so the caller can pass in either raw data forks or `MacBinary`-wrapped files.
//! Extracted files can be written in the same form, which keeps both forks
//! and the Finder information together in one file

/// If `data` begins with a plausible `MacBinary` header and its data fork
/// starts with an archive header, returns a copy of the data fork (skipping
/// the 128-byte header). Otherwise returns the input unchanged
#[must_use]
pub fn strip(data: Vec<u8>) -> Vec<u8> {
    if data.len() <= 128 {
        return data;
    }

    // MacBinary: byte 0 zero, byte 1 a filename length (1..63), and an SVCT tag
    // at offset 128, all required to strip a wrapper so a stray header match
    // can't mis-strip a non-VISE file
    let name_len = data[1];
    let data_len = u32::from_be_bytes([data[83], data[84], data[85], data[86]]) as usize;
    let fork = data[128..].get(..data_len);
    let wrapped = data[0] == 0
        && (1..=63).contains(&name_len)
        && data_len != 0
        && fork.is_some_and(|fork| fork.starts_with(b"SVCT"));

    match fork {
        Some(fork) if wrapped => fork.to_vec(),
        _ => data,
    }
}

/// The resource fork of a `MacBinary` file, if `data` is one and has a
/// resource fork that lies inside it
#[must_use]
pub fn resource_fork(data: &[u8]) -> Option<&[u8]> {
    let header = data.get(..BLOCK)?;
    if header[0] != 0 || !(1..=63).contains(&header[1]) {
        return None;
    }
    let data_len = u32::from_be_bytes(header[83..87].try_into().ok()?) as usize;
    let rsrc_len = u32::from_be_bytes(header[87..91].try_into().ok()?) as usize;
    let start = BLOCK.checked_add(data_len.checked_next_multiple_of(BLOCK)?)?;
    data.get(start..start.checked_add(rsrc_len)?)
        .filter(|fork| !fork.is_empty())
}

/// The region code of a `MacBinary` file's `vers` resource: the system
/// region the application was built for, such as 0 for the United States or
/// 14 for Japan. Resource ID 1 is the file's own version; if there is none,
/// any `vers` resource is used
#[must_use]
pub fn region(data: &[u8]) -> Option<u16> {
    let fork = resource_fork(data)?;
    let be32 =
        |at: usize| Some(u32::from_be_bytes(fork.get(at..at + 4)?.try_into().ok()?) as usize);
    let be16 =
        |buf: &[u8], at: usize| Some(u16::from_be_bytes(buf.get(at..at + 2)?.try_into().ok()?));

    // header: offsets and lengths of the resource data and the resource map
    let (data_at, map_at, map_len) = (be32(0)?, be32(4)?, be32(12)?);
    let map = fork.get(map_at..map_at.checked_add(map_len)?)?;
    let types_at = usize::from(be16(map, 24)?);
    let type_count = usize::from(be16(map, types_at)?).wrapping_add(1) & 0xffff;

    let mut fallback = None;
    for i in 0..type_count {
        let entry = types_at + 2 + i * 8;
        if map.get(entry..entry + 4)? != b"vers" {
            continue;
        }
        let count = usize::from(be16(map, entry + 4)?) + 1;
        let refs_at = types_at + usize::from(be16(map, entry + 6)?);
        for k in 0..count {
            let reference = refs_at + k * 12;
            let id = be16(map, reference)?;
            // the low three bytes are the offset of the resource's data
            let offset = u32::from_be_bytes(map.get(reference + 4..reference + 8)?.try_into().ok()?)
                as usize
                & 0x00ff_ffff;
            let body = data_at.checked_add(offset)?.checked_add(4)?;
            // version bytes, then the region code
            let Some(code) = be16(fork, body + 4) else {
                continue;
            };
            if id == 1 {
                return Some(code);
            }
            fallback.get_or_insert(code);
        }
        // a map lists each type once, so one that repeats `vers` is not
        // read again
        break;
    }
    fallback
}

/// Header size, and the multiple each fork is padded to
const BLOCK: usize = 128;
/// Longest file name the header has room for
const MAX_NAME: usize = 63;
/// Version byte of `MacBinary` II, written and required to read
const VERSION_II: u8 = 129;
/// Name stored for an entry whose own name is empty
const UNNAMED: &[u8] = b"Untitled";

/// Wraps both forks of `entry` and its Finder information in one
/// `MacBinary` II file: a 128-byte header, the data fork, then the resource
/// fork, each fork padded to a multiple of 128 bytes
#[must_use]
pub fn encode(entry: &crate::FileEntry, data: &[u8], rsrc: &[u8]) -> Vec<u8> {
    let name = if entry.name_bytes.is_empty() {
        UNNAMED
    } else {
        &entry.name_bytes[..entry.name_bytes.len().min(MAX_NAME)]
    };
    let [flags_high, flags_low] = entry.finder_flags.to_be_bytes();

    let mut header = [0u8; BLOCK];
    // at most MAX_NAME, so it fits the length byte
    #[allow(clippy::cast_possible_truncation)]
    {
        header[1] = name.len() as u8;
    }
    header[2..2 + name.len()].copy_from_slice(name);
    header[65..69].copy_from_slice(&entry.file_type);
    header[69..73].copy_from_slice(&entry.creator);
    header[73] = flags_high;
    header[83..87].copy_from_slice(&fork_len(data));
    header[87..91].copy_from_slice(&fork_len(rsrc));
    header[91..95].copy_from_slice(&entry.created.to_be_bytes());
    header[95..99].copy_from_slice(&entry.modified.to_be_bytes());
    header[101] = flags_low;
    header[122] = VERSION_II;
    header[123] = VERSION_II;
    let crc = crc16(&header[..124]);
    header[124..126].copy_from_slice(&crc.to_be_bytes());

    let padded = |len: usize| len.next_multiple_of(BLOCK);
    let mut out = Vec::with_capacity(BLOCK + padded(data.len()) + padded(rsrc.len()));
    out.extend_from_slice(&header);
    for fork in [data, rsrc] {
        out.extend_from_slice(fork);
        out.resize(padded(out.len()), 0);
    }
    out
}

/// Fork sizes in the archive are 32-bit, so every length here fits
fn fork_len(fork: &[u8]) -> [u8; 4] {
    u32::try_from(fork.len()).unwrap_or(u32::MAX).to_be_bytes()
}

/// CRC-16 as `MacBinary` II uses it over the header: polynomial 0x1021,
/// starting from zero, high bit first (CRC-16/XMODEM)
fn crc16(bytes: &[u8]) -> u16 {
    let mut crc = 0u16;
    for &byte in bytes {
        crc ^= u16::from(byte) << 8;
        for _ in 0..8 {
            crc = if crc & 0x8000 == 0 {
                crc << 1
            } else {
                (crc << 1) ^ 0x1021
            };
        }
    }
    crc
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crc16_matches_the_standard_check_value() {
        assert_eq!(crc16(b"123456789"), 0x31C3);
    }

    #[test]
    fn encodes_header_and_padded_forks() {
        let mut entry = crate::mac::testutil::blank_entry();
        entry.name_bytes = b"Read Me".to_vec();
        entry.file_type = *b"TEXT";
        entry.creator = *b"ttxt";
        entry.finder_flags = 0x2140;
        entry.created = 3_061_152_000;
        entry.modified = 3_061_238_400;
        let data = vec![0xAA; 130];
        let rsrc = vec![0xBB; 5];

        let bin = encode(&entry, &data, &rsrc);
        // header, two blocks of data fork, one of resource fork
        assert_eq!(bin.len(), 128 + 256 + 128);
        assert_eq!(bin[0], 0);
        assert_eq!(bin[1], 7);
        assert_eq!(&bin[2..9], b"Read Me");
        assert_eq!(&bin[65..73], b"TEXTttxt");
        assert_eq!((bin[73], bin[101]), (0x21, 0x40));
        assert_eq!(&bin[83..87], &130u32.to_be_bytes());
        assert_eq!(&bin[87..91], &5u32.to_be_bytes());
        assert_eq!(&bin[91..95], &3_061_152_000u32.to_be_bytes());
        assert_eq!(&bin[95..99], &3_061_238_400u32.to_be_bytes());
        assert_eq!((bin[122], bin[123]), (129, 129));
        assert_eq!(&bin[124..126], &crc16(&bin[..124]).to_be_bytes());

        assert_eq!(&bin[128..258], &data[..]);
        assert!(bin[258..384].iter().all(|&b| b == 0));
        assert_eq!(&bin[384..389], &rsrc[..]);
        assert!(bin[389..].iter().all(|&b| b == 0));
    }

    #[test]
    fn long_and_empty_names_still_give_a_valid_header() {
        let mut entry = crate::mac::testutil::blank_entry();
        entry.name_bytes = vec![b'n'; 200];
        let bin = encode(&entry, b"", b"");
        assert_eq!(bin.len(), 128);
        assert_eq!(usize::from(bin[1]), MAX_NAME);

        entry.name_bytes.clear();
        let bin = encode(&entry, b"", b"");
        assert_eq!(&bin[2..2 + usize::from(bin[1])], UNNAMED);
    }

    /// A resource fork holding `vers` resources with the given IDs and
    /// region codes, plus one resource of another type in front of them
    fn fork_with_vers(versions: &[(u16, u16)]) -> Vec<u8> {
        let mut data = Vec::new();
        let mut offsets = Vec::new();
        let add = |body: &[u8], data: &mut Vec<u8>| {
            let at = u32::try_from(data.len()).unwrap();
            data.extend_from_slice(&u32::try_from(body.len()).unwrap().to_be_bytes());
            data.extend_from_slice(body);
            at
        };
        let other = add(b"some other resource", &mut data);
        for &(_, region) in versions {
            let mut body = vec![1, 0, 0x80, 0];
            body.extend_from_slice(&region.to_be_bytes());
            body.extend_from_slice(b"\x031.0");
            offsets.push(add(&body, &mut data));
        }

        // map: 28 bytes of header, the type list, then the reference lists
        let mut types: Vec<(&[u8; 4], usize)> = vec![(b"STR ", 1)];
        if !versions.is_empty() {
            types.push((b"vers", versions.len()));
        }
        let mut map = vec![0u8; 24];
        map.extend_from_slice(&28u16.to_be_bytes());
        map.extend_from_slice(&0u16.to_be_bytes());
        // the number of types, stored as count - 1
        map.extend_from_slice(&u16::try_from(types.len() - 1).unwrap().to_be_bytes());
        let mut refs_at = 2 + types.len() * 8;
        for (tag, count) in types {
            map.extend_from_slice(tag);
            map.extend_from_slice(&u16::try_from(count - 1).unwrap().to_be_bytes());
            map.extend_from_slice(&u16::try_from(refs_at).unwrap().to_be_bytes());
            refs_at += count * 12;
        }
        let reference = |id: u16, offset: u32, map: &mut Vec<u8>| {
            map.extend_from_slice(&id.to_be_bytes());
            map.extend_from_slice(&0xffffu16.to_be_bytes());
            map.extend_from_slice(&offset.to_be_bytes());
            map.extend_from_slice(&[0; 4]);
        };
        reference(128, other, &mut map);
        for (&(id, _), &offset) in versions.iter().zip(&offsets) {
            reference(id, offset, &mut map);
        }

        let mut fork = Vec::new();
        for field in [16, 16 + data.len(), data.len(), map.len()] {
            fork.extend_from_slice(&u32::try_from(field).unwrap().to_be_bytes());
        }
        fork.extend_from_slice(&data);
        fork.extend_from_slice(&map);
        fork
    }

    #[test]
    fn region_comes_from_the_vers_resource() {
        let mut entry = crate::mac::testutil::blank_entry();
        entry.name_bytes = b"Installer".to_vec();
        let wrap = |fork: &[u8]| encode(&entry, b"SVCT data fork", fork);

        // resource ID 1 is the file's own version and wins over ID 2
        assert_eq!(region(&wrap(&fork_with_vers(&[(2, 0), (1, 14)]))), Some(14));
        assert_eq!(region(&wrap(&fork_with_vers(&[(1, 1)]))), Some(1));
        // without ID 1, any version resource will do
        assert_eq!(region(&wrap(&fork_with_vers(&[(2, 23)]))), Some(23));
        // no version resource, no resource fork, or not MacBinary at all
        assert_eq!(region(&wrap(&fork_with_vers(&[]))), None);
        assert_eq!(region(&wrap(b"")), None);
        assert_eq!(region(b"SVCT a bare data fork"), None);
        assert_eq!(
            crate::mac_name_encoding(b"SVCT a bare data fork"),
            crate::NameEncoding::MacRoman
        );
        assert_eq!(
            crate::mac_name_encoding(&wrap(&fork_with_vers(&[(1, 14)]))),
            crate::NameEncoding::MacJapanese
        );

        // a damaged resource fork is not an error and does not panic
        let whole = wrap(&fork_with_vers(&[(1, 14)]));
        for cut in 128..whole.len() {
            let _ = region(&whole[..cut]);
        }
        let mut scrambled = whole.clone();
        for at in 160..scrambled.len() {
            scrambled[at] = scrambled[at].wrapping_mul(31).wrapping_add(7);
            let _ = region(&scrambled);
        }
    }

    #[test]
    fn a_wrapped_archive_strips_back_to_its_data_fork() {
        let mut entry = crate::mac::testutil::blank_entry();
        entry.name_bytes = b"Installer".to_vec();
        let archive = b"SVCT and the rest of an archive".to_vec();
        let wrapped = encode(&entry, &archive, b"rsrc");
        assert_eq!(strip(wrapped), archive);
    }
}

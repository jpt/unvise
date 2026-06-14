//! VISE archive file table parser
//!
//! Parses the SVCT/CVCT/DVCT/FVCT chunk structure present in all observed
//! VISE versions from 00 01 through 03 0e. The parser scans for tags rather
//! than relying on fixed offsets, and infers per-version name field positions
//! dynamically from tag stride patterns

use crate::{deflate, Error};

const FVCT_FLAGS: usize = 12;
const FVCT_TYPE: usize = 44;
const FVCT_CREATOR: usize = 48;
const FVCT_COMP_DATA: usize = 68;
const FVCT_UNCOMP_DATA: usize = 72;
const FVCT_COMP_RSRC: usize = 76;
const FVCT_UNCOMP_RSRC: usize = 80;
const FVCT_SEGMENT: usize = 98;
const FVCT_DATA_OFFSET: usize = 100;
const FVCT_BLOCK_DATA_OFF: usize = 104;
const FVCT_BLOCK_RSRC_OFF: usize = 108;
const FVCT_NLEN: usize = 122;
const FVCT_MIN_RECORD: usize = FVCT_NLEN + 1;
const DVCT_NLEN: usize = 80;
const DVCT_MIN_RECORD: usize = DVCT_NLEN + 1;

/// v3.06+ CVCT uses a 100-byte header with chunk-type offsets before the body
const NEWSTYLE_CVCT_BODY: usize = 0x64;
/// When non-zero, the CVCT body is compressed with word-aligned DEFLATE (no cipher)
const NEWSTYLE_CVCT_COMPRESSED: usize = 0x08;

/// A parsed entry from the VISE file table
#[derive(Debug)]
pub enum Entry {
    Dir(String),
    File(FileEntry),
}

impl Entry {
    #[must_use]
    pub fn as_file(&self) -> Option<&FileEntry> {
        match self {
            Self::File(f) => Some(f),
            Self::Dir(_) => None,
        }
    }
}

/// Metadata and location info for a single archived file
#[derive(Debug)]
pub struct FileEntry {
    pub name: String,
    pub file_type: [u8; 4],
    pub creator: [u8; 4],
    pub flags: u32,
    pub segment: u16,
    pub comp_data: usize,
    pub uncomp_data: usize,
    pub comp_rsrc: usize,
    pub uncomp_rsrc: usize,
    pub data_offset: usize,
    pub block_data_off: usize,
    pub block_rsrc_off: usize,
}

impl FileEntry {
    /// Installer condition records masquerade as file entries but carry
    /// control-flow semantics rather than file data. Identified by bit 27
    /// of the flags field
    #[must_use]
    pub const fn is_stub(&self) -> bool {
        (self.flags & 0x0800_0000) != 0
    }
}

/// Top-level archive metadata produced by parsing
#[derive(Debug)]
pub struct ArchiveInfo {
    pub entries: Vec<Entry>,
    pub num_segments: usize,
    pub fmt_major: u8,
    pub fmt_minor: u8,
}

/// Parses the SVCT header and CVCT file table from raw archive data
///
/// # Errors
///
/// Returns [`Error::InvalidArchive`] if the data lacks an SVCT header or
/// the CVCT pointer is invalid
pub fn parse(data: &[u8]) -> Result<ArchiveInfo, Error> {
    if data.len() < 0x28 || &data[..4] != b"SVCT" {
        return Err(Error::InvalidArchive("missing SVCT header".into()));
    }

    let fmt_major = data[0x12];
    let fmt_minor = data[0x13];
    let num_segments = read_u32(data, 0x14)? as usize;

    let cvct = read_u32(data, 0x24)? as usize;
    if data.len() < cvct + 4 || &data[cvct..cvct + 4] != b"CVCT" {
        return Err(Error::InvalidArchive(format!("missing CVCT at 0x{cvct:x}")));
    }

    let (body_start, decompressed_body);
    if data.len() >= cvct + NEWSTYLE_CVCT_BODY && &data[cvct + 0x14..cvct + 0x18] == b"PACK" {
        if read_u32(data, cvct + NEWSTYLE_CVCT_COMPRESSED)? != 0 {
            let body_size = read_u32(data, cvct + 4)? as usize;
            let comp_start = cvct + NEWSTYLE_CVCT_BODY;
            let comp_end = comp_start + body_size;
            if comp_end > data.len() {
                return Err(Error::InvalidArchive(
                    "compressed CVCT body extends past archive end".into(),
                ));
            }
            decompressed_body =
                deflate::decompress_raw_word_deflate(&data[comp_start..comp_end], 0)?;
            eprintln!(
                "  decompressed CVCT body ({body_size} -> {} bytes)",
                decompressed_body.len()
            );
            body_start = 0;
        } else {
            decompressed_body = Vec::new();
            body_start = cvct + NEWSTYLE_CVCT_BODY;
        }
    } else {
        decompressed_body = Vec::new();
        body_start = cvct + 4;
    }

    let parse_data: &[u8] = if decompressed_body.is_empty() { data } else { &decompressed_body };
    let tags = scan_tags(parse_data, body_start);
    let fvct_name_off = infer_name_off(parse_data, &tags, TagKind::Fvct, FVCT_NLEN);
    let dvct_name_off = infer_name_off(parse_data, &tags, TagKind::Dvct, DVCT_NLEN);

    let mut entries = Vec::with_capacity(tags.len());
    let mut current_dir = String::new();

    for &(pos, kind) in &tags {
        if kind == TagKind::Fvct {
            if pos + FVCT_MIN_RECORD > parse_data.len() {
                continue;
            }
            let nlen = usize::from(parse_data[pos + FVCT_NLEN]);
            let name = if pos + fvct_name_off + nlen <= parse_data.len() {
                mac_str(parse_data, pos + fvct_name_off, nlen)
            } else {
                String::new()
            };

            let flags = read_u32(parse_data, pos + FVCT_FLAGS)?;
            let segment = read_u16(parse_data, pos + FVCT_SEGMENT)?;

            let mut ft = [0u8; 4];
            ft.copy_from_slice(&parse_data[pos + FVCT_TYPE..pos + FVCT_TYPE + 4]);
            let mut cr = [0u8; 4];
            cr.copy_from_slice(&parse_data[pos + FVCT_CREATOR..pos + FVCT_CREATOR + 4]);

            entries.push(Entry::File(FileEntry {
                name,
                file_type: ft,
                creator: cr,
                flags,
                segment,
                comp_data: read_u32(parse_data, pos + FVCT_COMP_DATA)? as usize,
                uncomp_data: read_u32(parse_data, pos + FVCT_UNCOMP_DATA)? as usize,
                comp_rsrc: read_u32(parse_data, pos + FVCT_COMP_RSRC)? as usize,
                uncomp_rsrc: read_u32(parse_data, pos + FVCT_UNCOMP_RSRC)? as usize,
                data_offset: read_u32(parse_data, pos + FVCT_DATA_OFFSET)? as usize,
                block_data_off: read_u32(parse_data, pos + FVCT_BLOCK_DATA_OFF)? as usize,
                block_rsrc_off: read_u32(parse_data, pos + FVCT_BLOCK_RSRC_OFF)? as usize,
            }));
        } else if kind == TagKind::Dvct && pos + DVCT_MIN_RECORD <= parse_data.len() {
            let nlen = usize::from(parse_data[pos + DVCT_NLEN]);
            if pos + dvct_name_off + nlen <= parse_data.len() {
                current_dir = mac_str(parse_data, pos + dvct_name_off, nlen);
            }
            entries.push(Entry::Dir(current_dir.clone()));
        }
    }

    Ok(ArchiveInfo { entries, num_segments, fmt_major, fmt_minor })
}

/// Non-directory CVCT record tags, used only for stride inference
/// FVCT and DVCT are matched explicitly in `scan_tags` and are not in this list
const OTHER_TAGS: &[&[u8; 4]] = &[
    b"PACK", b"BBrd", b"CODE", b"BDIR", b"PROJ", b"INDN", b"DfIl",
];

/// Tag type classification for scan results
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum TagKind { Fvct, Dvct, Other }

/// Scans for known CVCT tags starting at `from`. Returns (offset, kind) pairs
/// All tag types are scanned so stride inference works even with single-record
/// archives; only FVCT and DVCT produce extracted entries
fn scan_tags(data: &[u8], from: usize) -> Vec<(usize, TagKind)> {
    let mut tags = Vec::new();
    let mut p = from;
    while p + 4 <= data.len() {
        let tag = &data[p..p + 4];
        if tag == b"FVCT" {
            tags.push((p, TagKind::Fvct));
            p += 4;
        } else if tag == b"DVCT" {
            tags.push((p, TagKind::Dvct));
            p += 4;
        } else if OTHER_TAGS.iter().any(|t| tag == *t) {
            tags.push((p, TagKind::Other));
            p += 4;
        } else {
            p += 1;
        }
    }
    tags
}

/// Infers the name field offset for a tag type by examining stride patterns.
/// The name is always the last field in a record, so `name_off` = stride - nlen.
/// When there are multiple consecutive same-type tags, stride voting across
/// pairs gives a robust answer. For single-record archives (only one tag of a
/// given type), falls back to using the next tag of any type as a stride bound.
fn infer_name_off(data: &[u8], tags: &[(usize, TagKind)], target: TagKind, nlen_off: usize) -> usize {
    // Precompute each index's next same-type tag in one reverse pass. A naive
    // inner search is O(tags^2), which a body densely packed with markers
    // (post-decompression, attacker-influenced) could exploit to stall the parser
    let mut next_same_pos = vec![None; tags.len()];
    let mut seen: Option<usize> = None;
    for i in (0..tags.len()).rev() {
        next_same_pos[i] = seen;
        if tags[i].1 == target {
            seen = Some(tags[i].0);
        }
    }

    let mut votes: Vec<(usize, usize)> = Vec::new();

    for i in 0..tags.len().saturating_sub(1) {
        let (pos, kind) = tags[i];
        if kind != target {
            continue;
        }
        // Prefer stride to next same-type tag; fall back to next tag of any type
        let stride_to = next_same_pos[i].unwrap_or(tags[i + 1].0);
        let stride = stride_to - pos;
        if pos + nlen_off >= data.len() {
            continue;
        }
        let nlen = usize::from(data[pos + nlen_off]);
        if nlen > 0 && nlen < stride {
            let off = stride - nlen;
            match votes.iter_mut().find(|(o, _)| *o == off) {
                Some(entry) => entry.1 += 1,
                None => votes.push((off, 1)),
            }
        }
    }

    votes.into_iter()
        .max_by_key(|&(_, count)| count)
        .map_or(nlen_off + 2, |(off, _)| off)
}

fn read_u16(data: &[u8], off: usize) -> Result<u16, Error> {
    let bytes = data.get(off..off + 2)
        .ok_or_else(|| Error::InvalidArchive(format!("truncated at 0x{off:x}")))?;
    Ok(u16::from_be_bytes(bytes.try_into().unwrap()))
}

fn read_u32(data: &[u8], off: usize) -> Result<u32, Error> {
    let bytes = data.get(off..off + 4)
        .ok_or_else(|| Error::InvalidArchive(format!("truncated at 0x{off:x}")))?;
    Ok(u32::from_be_bytes(bytes.try_into().unwrap()))
}

/// Mac Roman (bytes 0x80-0xFF) to Unicode
#[rustfmt::skip]
const MACROMAN_HIGH: [char; 128] = [
    '\u{00C4}','\u{00C5}','\u{00C7}','\u{00C9}','\u{00D1}','\u{00D6}','\u{00DC}','\u{00E1}',
    '\u{00E0}','\u{00E2}','\u{00E4}','\u{00E3}','\u{00E5}','\u{00E7}','\u{00E9}','\u{00E8}',
    '\u{00EA}','\u{00EB}','\u{00ED}','\u{00EC}','\u{00EE}','\u{00EF}','\u{00F1}','\u{00F3}',
    '\u{00F2}','\u{00F4}','\u{00F6}','\u{00F5}','\u{00FA}','\u{00F9}','\u{00FB}','\u{00FC}',
    '\u{2020}','\u{00B0}','\u{00A2}','\u{00A3}','\u{00A7}','\u{2022}','\u{00B6}','\u{00DF}',
    '\u{00AE}','\u{00A9}','\u{2122}','\u{00B4}','\u{00A8}','\u{2260}','\u{00C6}','\u{00D8}',
    '\u{221E}','\u{00B1}','\u{2264}','\u{2265}','\u{00A5}','\u{00B5}','\u{2202}','\u{2211}',
    '\u{220F}','\u{03C0}','\u{222B}','\u{00AA}','\u{00BA}','\u{03A9}','\u{00E6}','\u{00F8}',
    '\u{00BF}','\u{00A1}','\u{00AC}','\u{221A}','\u{0192}','\u{2248}','\u{2206}','\u{00AB}',
    '\u{00BB}','\u{2026}','\u{00A0}','\u{00C0}','\u{00C3}','\u{00D5}','\u{0152}','\u{0153}',
    '\u{2013}','\u{2014}','\u{201C}','\u{201D}','\u{2018}','\u{2019}','\u{00F7}','\u{25CA}',
    '\u{00FF}','\u{0178}','\u{2044}','\u{20AC}','\u{2039}','\u{203A}','\u{FB01}','\u{FB02}',
    '\u{2021}','\u{00B7}','\u{201A}','\u{201E}','\u{2030}','\u{00C2}','\u{00CA}','\u{00C1}',
    '\u{00CB}','\u{00C8}','\u{00CD}','\u{00CE}','\u{00CF}','\u{00CC}','\u{00D3}','\u{00D4}',
    '\u{F8FF}','\u{00D2}','\u{00DA}','\u{00DB}','\u{00D9}','\u{0131}','\u{02C6}','\u{02DC}',
    '\u{00AF}','\u{02D8}','\u{02D9}','\u{02DA}','\u{00B8}','\u{02DD}','\u{02DB}','\u{02C7}',
];

fn mac_roman_char(b: u8) -> char {
    if b.is_ascii_graphic() || b == b' ' {
        b as char
    } else if b >= 0x80 {
        MACROMAN_HIGH[(b - 0x80) as usize]
    } else {
        '?'
    }
}

fn mac_str(data: &[u8], off: usize, len: usize) -> String {
    let bytes = &data[off..off + len];
    let start = bytes.iter().position(|&b| b != b' ' && b != 0).unwrap_or(len);
    let end = bytes.iter().rposition(|&b| b != b' ' && b != 0).map_or(start, |i| i + 1);
    bytes[start..end].iter().map(|&b| mac_roman_char(b)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_tag_body(tags: &[(&[u8; 4], usize)]) -> Vec<u8> {
        let total: usize = tags.iter().map(|(_, sz)| 4 + sz).sum();
        let mut buf = vec![0u8; total];
        let mut pos = 0;
        for (tag, body_len) in tags {
            buf[pos..pos + 4].copy_from_slice(*tag);
            pos += 4 + body_len;
        }
        buf
    }

    #[test]
    fn scan_tags_finds_all_types() {
        let data = make_tag_body(&[
            (b"FVCT", 186),
            (b"PACK", 26),
            (b"BBrd", 62),
            (b"INDN", 10),
        ]);
        let tags = scan_tags(&data, 0);
        assert_eq!(tags.len(), 4);
        assert_eq!(tags[0], (0, TagKind::Fvct));
        assert_eq!(tags[1], (190, TagKind::Other));
        assert_eq!(tags[2], (220, TagKind::Other));
        assert_eq!(tags[3], (286, TagKind::Other));
    }

    #[test]
    fn scan_tags_ignores_unknown() {
        let mut data = vec![0u8; 20];
        data[0..4].copy_from_slice(b"FVCT");
        data[8..12].copy_from_slice(b"XXXX");
        data[16..20].copy_from_slice(b"DVCT");
        let tags = scan_tags(&data, 0);
        assert_eq!(tags.len(), 2);
        assert_eq!(tags[0].1, TagKind::Fvct);
        assert_eq!(tags[1].1, TagKind::Dvct);
    }

    #[test]
    fn infer_name_off_multi_record() {
        // Two FVCT records 200 bytes apart, name_len=6, so name_off = 194
        let mut data = vec![0u8; 406];
        data[0..4].copy_from_slice(b"FVCT");
        data[FVCT_NLEN] = 6;
        data[200..204].copy_from_slice(b"FVCT");
        data[200 + FVCT_NLEN] = 6;
        data[400..404].copy_from_slice(b"PACK");
        let tags = scan_tags(&data, 0);
        let off = infer_name_off(&data, &tags, TagKind::Fvct, FVCT_NLEN);
        assert_eq!(off, 194);
    }

    #[test]
    fn infer_name_off_single_record_cross_type_fallback() {
        // Single FVCT followed by a different tag type, forcing the cross-type
        // stride fallback (no consecutive same-type tags to vote on)
        let mut data = vec![0u8; 230];
        data[0..4].copy_from_slice(b"FVCT");
        data[FVCT_NLEN] = 6;
        data[184..190].copy_from_slice(b"myfile");
        data[190..194].copy_from_slice(b"PACK");
        let tags = scan_tags(&data, 0);
        assert_eq!(tags.len(), 2);
        let off = infer_name_off(&data, &tags, TagKind::Fvct, FVCT_NLEN);
        assert_eq!(off, 184);
        assert_eq!(mac_str(&data, off, 6), "myfile");
    }

    #[test]
    fn infer_name_off_default_fallback() {
        // Single tag, no next tag, so it falls back to nlen_off + 2
        let mut data = vec![0u8; 200];
        data[0..4].copy_from_slice(b"FVCT");
        data[FVCT_NLEN] = 4;
        let tags = scan_tags(&data, 0);
        assert_eq!(tags.len(), 1);
        let off = infer_name_off(&data, &tags, TagKind::Fvct, FVCT_NLEN);
        assert_eq!(off, FVCT_NLEN + 2);
    }

    /// Minimal v3 archive whose CVCT directory is flagged compressed: `body` is
    /// the raw compressed-directory bytes, `declared` the body-size field (so a
    /// caller can lie about it)
    fn compressed_cvct(body: &[u8], declared: u32) -> Vec<u8> {
        let cvct = 0x80usize;
        let comp_start = cvct + NEWSTYLE_CVCT_BODY;
        let mut buf = vec![0u8; comp_start + body.len()];
        buf[0..4].copy_from_slice(b"SVCT");
        buf[0x12] = 0x03;
        buf[0x14..0x18].copy_from_slice(&1u32.to_be_bytes());
        buf[0x24..0x28].copy_from_slice(&u32::try_from(cvct).unwrap().to_be_bytes());
        buf[cvct..cvct + 4].copy_from_slice(b"CVCT");
        buf[cvct + 4..cvct + 8].copy_from_slice(&declared.to_be_bytes());
        let flag = cvct + NEWSTYLE_CVCT_COMPRESSED;
        buf[flag..flag + 4].copy_from_slice(&1u32.to_be_bytes());
        buf[cvct + 0x14..cvct + 0x18].copy_from_slice(b"PACK");
        buf[comp_start..].copy_from_slice(body);
        buf
    }

    #[test]
    fn parse_rejects_oversized_cvct_body() {
        // body-size field points past the archive; without the bounds check the
        // `data[comp_start..comp_end]` slice would panic
        assert!(parse(&compressed_cvct(&[0xAB; 8], 0xFFFF)).is_err());
    }

    #[test]
    fn parse_survives_garbage_cvct_body() {
        // a non-DEFLATE compressed directory errors cleanly, never panics or hangs
        assert!(parse(&compressed_cvct(&[0xFF; 64], 64)).is_err());
    }

    #[test]
    fn parse_rejects_cvct_pointer_past_end() {
        let mut buf = vec![0u8; 0x40];
        buf[0..4].copy_from_slice(b"SVCT");
        buf[0x24..0x28].copy_from_slice(&0xFFFFu32.to_be_bytes());
        assert!(parse(&buf).is_err());
    }
}

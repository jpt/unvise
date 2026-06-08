//! VISE archive file table parser
//!
//! Parses the SVCT/CVCT/DVCT/FVCT chunk structure present in all observed
//! VISE versions from 00 01 through 03 07, including the new-style CVCT
//! header used by v3.06+. The parser scans for tags rather than relying on
//! fixed offsets, and infers per-version name field positions dynamically
//! from tag stride patterns

use crate::Error;

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
const NEWSTYLE_CVCT_COMPRESSED_FLAG: usize = 0x08;

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

    #[must_use]
    pub fn as_dir(&self) -> Option<&str> {
        match self {
            Self::Dir(d) => Some(d),
            Self::File(_) => None,
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
    pub use_deflate: bool,
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
    let use_deflate = fmt_major == 0x03;
    let num_segments = read_u32(data, 0x14)? as usize;

    let cvct = read_u32(data, 0x24)? as usize;
    if data.len() < cvct + 4 || &data[cvct..cvct + 4] != b"CVCT" {
        return Err(Error::InvalidArchive(format!("missing CVCT at 0x{cvct:x}")));
    }

    let body_start = if data.len() >= cvct + NEWSTYLE_CVCT_BODY
        && &data[cvct + 0x14..cvct + 0x18] == b"PACK"
    {
        if read_u32(data, cvct + NEWSTYLE_CVCT_COMPRESSED_FLAG)? != 0 {
            return Err(Error::InvalidArchive(
                "encrypted CVCT body (v3.08+) is not yet supported".into(),
            ));
        }
        cvct + NEWSTYLE_CVCT_BODY
    } else {
        cvct + 4
    };

    let tags = scan_tags(data, body_start);
    let fvct_name_off = infer_name_off(data, &tags, b"FVCT", FVCT_NLEN);
    let dvct_name_off = infer_name_off(data, &tags, b"DVCT", DVCT_NLEN);

    let mut entries = Vec::with_capacity(tags.len());
    let mut current_dir = String::new();

    for &(pos, is_fvct) in &tags {
        if is_fvct {
            if pos + FVCT_MIN_RECORD > data.len() {
                continue;
            }
            let nlen = usize::from(data[pos + FVCT_NLEN]);
            let name = if pos + fvct_name_off + nlen <= data.len() {
                mac_str(data, pos + fvct_name_off, nlen)
            } else {
                String::new()
            };

            let flags = read_u32(data, pos + FVCT_FLAGS)?;
            let segment = read_u16(data, pos + FVCT_SEGMENT)?;

            let mut ft = [0u8; 4];
            ft.copy_from_slice(&data[pos + FVCT_TYPE..pos + FVCT_TYPE + 4]);
            let mut cr = [0u8; 4];
            cr.copy_from_slice(&data[pos + FVCT_CREATOR..pos + FVCT_CREATOR + 4]);

            entries.push(Entry::File(FileEntry {
                name,
                file_type: ft,
                creator: cr,
                flags,
                segment,
                comp_data: read_u32(data, pos + FVCT_COMP_DATA)? as usize,
                uncomp_data: read_u32(data, pos + FVCT_UNCOMP_DATA)? as usize,
                comp_rsrc: read_u32(data, pos + FVCT_COMP_RSRC)? as usize,
                uncomp_rsrc: read_u32(data, pos + FVCT_UNCOMP_RSRC)? as usize,
                data_offset: read_u32(data, pos + FVCT_DATA_OFFSET)? as usize,
                block_data_off: read_u32(data, pos + FVCT_BLOCK_DATA_OFF)? as usize,
                block_rsrc_off: read_u32(data, pos + FVCT_BLOCK_RSRC_OFF)? as usize,
            }));
        } else if pos + DVCT_MIN_RECORD <= data.len() {
            let nlen = usize::from(data[pos + DVCT_NLEN]);
            if pos + dvct_name_off + nlen <= data.len() {
                current_dir = mac_str(data, pos + dvct_name_off, nlen);
            }
            entries.push(Entry::Dir(current_dir.clone()));
        }
    }

    Ok(ArchiveInfo { entries, use_deflate, num_segments, fmt_major, fmt_minor })
}

/// Scans for DVCT/FVCT tags starting at `from`. Returns (offset, `is_fvct`) pairs.
/// Advances byte-by-byte on non-match because tags are not necessarily aligned
/// within the CVCT; variable-length name fields break any fixed stride
fn scan_tags(data: &[u8], from: usize) -> Vec<(usize, bool)> {
    let mut tags = Vec::new();
    let mut p = from;
    while p + 4 <= data.len() {
        if &data[p..p + 4] == b"FVCT" {
            tags.push((p, true));
            p += 4;
        } else if &data[p..p + 4] == b"DVCT" {
            tags.push((p, false));
            p += 4;
        } else {
            p += 1;
        }
    }
    tags
}

/// Infers the name field offset for a tag type by examining stride patterns.
/// The name is always the last field in a record, so `name_off` = stride - nlen
fn infer_name_off(data: &[u8], tags: &[(usize, bool)], kind: &[u8], nlen_off: usize) -> usize {
    let is_fvct = kind == b"FVCT";
    let mut votes: Vec<(usize, usize)> = Vec::new();

    for i in 0..tags.len().saturating_sub(1) {
        let (pos, tag_is_fvct) = tags[i];
        if tag_is_fvct != is_fvct {
            continue;
        }
        let stride = tags[i + 1].0 - pos;
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

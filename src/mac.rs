//! VISE archive file table parser
//!
//! Parses the SVCT/CVCT/DVCT/FVCT chunk structure of format versions 00 01
//! through 03 0e and 0b 00. The parser scans for tags instead of relying on
//! fixed offsets, and works out where each version keeps its name fields
//! from the spacing of the tags

use std::sync::Arc;
use std::time::{Duration, SystemTime};

use crate::text::NameEncoding;
use crate::{Error, deflate};

const FVCT_FLAGS: usize = 12;
const FVCT_TYPE: usize = 44;
const FVCT_CREATOR: usize = 48;
const FVCT_FINDER_FLAGS: usize = 52;
const FVCT_CREATED: usize = 60;
const FVCT_MODIFIED: usize = 64;
const FVCT_COMP_DATA: usize = 68;
const FVCT_UNCOMP_DATA: usize = 72;
const FVCT_COMP_RSRC: usize = 76;
const FVCT_UNCOMP_RSRC: usize = 80;
const FVCT_CRC: usize = 84;
const FVCT_DEPTH: usize = 96;
const FVCT_SEGMENT: usize = 98;
const FVCT_DATA_OFFSET: usize = 100;
const FVCT_BLOCK_DATA_OFF: usize = 104;
const FVCT_BLOCK_RSRC_OFF: usize = 108;
const FVCT_NLEN: usize = 122;
const DVCT_DEPTH: usize = 72;
const DVCT_NLEN: usize = 80;
/// First format version used by the Mac OS X installers, which keep the
/// table and the data in separate files inside the application bundle
pub(crate) const FMT_OSX: u8 = 0x0b;
/// Deepest folder nesting kept. Real installers stay far below this; the cap
/// bounds the path built for each record of a crafted table
const MAX_DIR_DEPTH: usize = 64;
/// Folder paths may add up to this many times the size of the file table
const PATH_BUDGET_RATIO: usize = 64;

/// v3.06+ CVCT uses a 100-byte header with chunk-type offsets before the body
const NEWSTYLE_CVCT_BODY: usize = 0x64;
/// When non-zero, the CVCT body is compressed with word-aligned DEFLATE (no cipher)
const NEWSTYLE_CVCT_COMPRESSED: usize = 0x08;

/// Separator between folder names in [`Entry::Dir`] and [`FileEntry::dir`].
/// A colon cannot appear in a Mac file name, so the joined path is unambiguous
pub const PATH_SEPARATOR: char = ':';

/// A parsed entry from the VISE file table
#[derive(Debug)]
#[non_exhaustive]
pub enum Entry {
    /// A folder, as its full path from the install root: the names of its
    /// parent folders and its own name, joined with [`PATH_SEPARATOR`]
    Dir(Arc<str>),
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
#[non_exhaustive]
pub struct FileEntry {
    /// The file name, decoded with the encoding the archive was parsed with
    pub name: String,
    /// The file name as the archive stores it, in the Mac text encoding of
    /// the system the installer was built on
    pub name_bytes: Vec<u8>,
    /// Path of the folder holding the file, as folder names joined with
    /// [`PATH_SEPARATOR`]. Empty for a file at the install root
    pub dir: Arc<str>,
    pub file_type: [u8; 4],
    pub creator: [u8; 4],
    pub flags: u32,
    /// Finder flags (`fdFlags`), such as the invisible and custom-icon bits
    pub finder_flags: u16,
    /// Creation time, in seconds since 1904-01-01 local time
    pub created: u32,
    /// Modification time, in seconds since 1904-01-01 local time
    pub modified: u32,
    /// CRC-32 of the data fork followed by the resource fork
    pub crc32: u32,
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

    /// Whether the entry has a resource fork stored in the archive
    #[must_use]
    pub const fn has_rsrc(&self) -> bool {
        self.comp_rsrc > 0 && self.uncomp_rsrc > 0
    }

    /// The modification time as a system time, or `None` if none is recorded.
    /// Mac timestamps carry no time zone; they are read as UTC
    #[must_use]
    pub fn modified_time(&self) -> Option<SystemTime> {
        mac_time(self.modified)
    }

    /// The creation time, read the same way as [`FileEntry::modified_time`]
    #[must_use]
    pub fn created_time(&self) -> Option<SystemTime> {
        mac_time(self.created)
    }

    /// The 32 bytes of Finder information for the file: type, creator and
    /// Finder flags, with the fields the archive does not record left zero
    #[must_use]
    pub fn finder_info(&self) -> [u8; 32] {
        let mut info = [0u8; 32];
        info[..4].copy_from_slice(&self.file_type);
        info[4..8].copy_from_slice(&self.creator);
        info[8..10].copy_from_slice(&self.finder_flags.to_be_bytes());
        info
    }
}

/// Seconds between the Mac epoch (1904-01-01) and the Unix epoch
const MAC_EPOCH_OFFSET: u64 = 2_082_844_800;

fn mac_time(secs: u32) -> Option<SystemTime> {
    if secs == 0 {
        return None;
    }
    let secs = u64::from(secs);
    if secs >= MAC_EPOCH_OFFSET {
        SystemTime::UNIX_EPOCH.checked_add(Duration::from_secs(secs - MAC_EPOCH_OFFSET))
    } else {
        SystemTime::UNIX_EPOCH.checked_sub(Duration::from_secs(MAC_EPOCH_OFFSET - secs))
    }
}

/// Top-level archive metadata produced by parsing
#[derive(Debug)]
#[non_exhaustive]
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
pub fn parse(data: &[u8], encoding: NameEncoding) -> Result<ArchiveInfo, Error> {
    if data.len() < 0x28 || &data[..4] != b"SVCT" {
        return Err(Error::InvalidArchive("missing SVCT header".into()));
    }

    let fmt_major = data[0x12];
    let fmt_minor = data[0x13];
    let num_segments = read_u32(data, 0x14)? as usize;

    let cvct = read_u32(data, 0x24)? as usize;
    // everything from the CVCT tag on; all offsets below are relative to it,
    // so a pointer near the top of the address space cannot overflow
    let table = data
        .get(cvct..)
        .filter(|t| t.starts_with(b"CVCT"))
        .ok_or_else(|| Error::InvalidArchive(format!("missing CVCT at 0x{cvct:x}")))?;

    let (body_start, decompressed_body);
    if table.len() >= NEWSTYLE_CVCT_BODY && &table[0x14..0x18] == b"PACK" {
        if read_u32(table, NEWSTYLE_CVCT_COMPRESSED)? != 0 {
            let body_size = read_u32(table, 4)? as usize;
            let compressed = table[NEWSTYLE_CVCT_BODY..]
                .get(..body_size)
                .ok_or_else(|| {
                    Error::InvalidArchive("compressed CVCT body extends past archive end".into())
                })?;
            decompressed_body = deflate::decompress_raw_word_deflate(compressed, 0)?;
            body_start = 0;
        } else {
            decompressed_body = Vec::new();
            body_start = cvct + NEWSTYLE_CVCT_BODY;
        }
    } else {
        decompressed_body = Vec::new();
        body_start = cvct + 4;
    }

    let parse_data: &[u8] = if decompressed_body.is_empty() {
        data
    } else {
        &decompressed_body
    };
    let tags = scan_tags(parse_data, body_start);
    // From format 0b (the Mac OS X installers) both record kinds have two
    // more bytes of fields before the name length
    let later = if fmt_major >= FMT_OSX { 2 } else { 0 };
    let (fvct_nlen, dvct_nlen) = (FVCT_NLEN + later, DVCT_NLEN + later);
    let fvct_name_off = infer_name_off(parse_data, &tags, TagKind::Fvct, fvct_nlen);
    let dvct_name_off = infer_name_off(parse_data, &tags, TagKind::Dvct, dvct_nlen);

    let mut entries = Vec::with_capacity(tags.len());
    // names of the folders enclosing the current record, outermost first.
    // Every record stores how deep it sits, so a folder at depth `d` replaces
    // whatever was open at that depth and below
    let mut open_dirs: Vec<String> = Vec::new();
    // paths[n] is the path of the first n open folders
    let mut paths: Vec<Arc<str>> = vec![Arc::from("")];
    let mut path_budget = parse_data.len().saturating_mul(PATH_BUDGET_RATIO);

    for &(pos, kind) in &tags {
        if kind == TagKind::Fvct {
            if pos + fvct_nlen + 1 > parse_data.len() {
                continue;
            }
            let depth = usize::from(read_u16(parse_data, pos + FVCT_DEPTH)?);
            // shared with every other file in the folder
            let dir = Arc::clone(&paths[depth.min(open_dirs.len())]);
            let name_at = (pos + fvct_nlen, pos + fvct_name_off);
            entries.push(Entry::File(file_entry(
                parse_data, pos, name_at, encoding, dir,
            )?));
        } else if kind == TagKind::Dvct && pos + dvct_nlen < parse_data.len() {
            let nlen = usize::from(parse_data[pos + dvct_nlen]);
            let name = if pos + dvct_name_off + nlen <= parse_data.len() {
                mac_str(parse_data, pos + dvct_name_off, nlen, encoding)
            } else {
                String::new()
            };
            let depth = usize::from(read_u16(parse_data, pos + DVCT_DEPTH)?);
            open_dirs.truncate(depth.min(MAX_DIR_DEPTH - 1));
            open_dirs.push(name);
            let path: Arc<str> = Arc::from(join_dirs(&open_dirs));
            // every folder record costs a path of its own. Deep nesting of
            // long names repeated through a table would otherwise take far
            // more memory than the table
            path_budget = path_budget.checked_sub(path.len()).ok_or_else(|| {
                Error::InvalidArchive("folder paths are too long for the size of the table".into())
            })?;
            paths.truncate(open_dirs.len());
            paths.push(Arc::clone(&path));
            entries.push(Entry::Dir(path));
        }
    }

    Ok(ArchiveInfo {
        entries,
        num_segments,
        fmt_major,
        fmt_minor,
    })
}

/// Builds the entry for the file record at `pos`. `name_at` is where its
/// name length and its name are
fn file_entry(
    parse_data: &[u8],
    pos: usize,
    (nlen_at, name_off): (usize, usize),
    encoding: NameEncoding,
    dir: Arc<str>,
) -> Result<FileEntry, Error> {
    let nlen = usize::from(parse_data[nlen_at]);
    let name_bytes = if name_off + nlen <= parse_data.len() {
        stored_name(parse_data, name_off, nlen)
    } else {
        &[]
    };
    let name = encoding.decode(name_bytes);
    let name_bytes = name_bytes.to_vec();

    let flags = read_u32(parse_data, pos + FVCT_FLAGS)?;
    let segment = read_u16(parse_data, pos + FVCT_SEGMENT)?;

    Ok(FileEntry {
        name,
        name_bytes,
        dir,
        file_type: read_array(parse_data, pos + FVCT_TYPE)?,
        creator: read_array(parse_data, pos + FVCT_CREATOR)?,
        flags,
        finder_flags: read_u16(parse_data, pos + FVCT_FINDER_FLAGS)?,
        created: read_u32(parse_data, pos + FVCT_CREATED)?,
        modified: read_u32(parse_data, pos + FVCT_MODIFIED)?,
        crc32: read_u32(parse_data, pos + FVCT_CRC)?,
        segment,
        comp_data: read_u32(parse_data, pos + FVCT_COMP_DATA)? as usize,
        uncomp_data: read_u32(parse_data, pos + FVCT_UNCOMP_DATA)? as usize,
        comp_rsrc: read_u32(parse_data, pos + FVCT_COMP_RSRC)? as usize,
        uncomp_rsrc: read_u32(parse_data, pos + FVCT_UNCOMP_RSRC)? as usize,
        data_offset: read_u32(parse_data, pos + FVCT_DATA_OFFSET)? as usize,
        block_data_off: read_u32(parse_data, pos + FVCT_BLOCK_DATA_OFF)? as usize,
        block_rsrc_off: read_u32(parse_data, pos + FVCT_BLOCK_RSRC_OFF)? as usize,
    })
}

fn join_dirs(dirs: &[String]) -> String {
    let mut out = String::new();
    for name in dirs {
        if !out.is_empty() {
            out.push(PATH_SEPARATOR);
        }
        // a colon inside a folder name would read as a separator
        out.extend(
            name.chars()
                .map(|c| if c == PATH_SEPARATOR { '_' } else { c }),
        );
    }
    out
}

/// Non-directory CVCT record tags, used only for stride inference
/// FVCT and DVCT are matched explicitly in `scan_tags` and are not in this list
const OTHER_TAGS: &[&[u8; 4]] = &[
    b"PACK", b"BBrd", b"CODE", b"BDIR", b"PROJ", b"INDN", b"DfIl",
];

/// Tag type classification for scan results
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum TagKind {
    Fvct,
    Dvct,
    Other,
}

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
/// The name is always the last field in a record, so `name_off` = stride - nlen,
/// where the stride is the distance to the next record. Every record of the
/// type votes, and the most common answer wins.
fn infer_name_off(
    data: &[u8],
    tags: &[(usize, TagKind)],
    target: TagKind,
    nlen_off: usize,
) -> usize {
    // Records sit back to back, so a record ends where the next file or
    // folder record starts, whichever kind that is. Measuring to the next
    // record of the same kind instead would count a folder record lying
    // between two files as part of the first file.
    //
    // Precompute each index's next record in one reverse pass. A naive
    // inner search is O(tags^2), which a body densely packed with markers
    // (post-decompression, attacker-influenced) could exploit to stall the parser
    let mut next_record_pos = vec![None; tags.len()];
    let mut seen: Option<usize> = None;
    for i in (0..tags.len()).rev() {
        next_record_pos[i] = seen;
        if tags[i].1 != TagKind::Other {
            seen = Some(tags[i].0);
        }
    }

    let mut votes: Vec<(usize, usize)> = Vec::new();

    for i in 0..tags.len().saturating_sub(1) {
        let (pos, kind) = tags[i];
        if kind != target {
            continue;
        }
        // after the last record, the next tag of any type bounds it
        let stride_to = next_record_pos[i].unwrap_or(tags[i + 1].0);
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

    votes
        .into_iter()
        .max_by_key(|&(_, count)| count)
        .map_or(nlen_off + 2, |(off, _)| off)
}

fn read_array<const N: usize>(data: &[u8], off: usize) -> Result<[u8; N], Error> {
    off.checked_add(N)
        .and_then(|end| data.get(off..end))
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or_else(|| Error::InvalidArchive(format!("truncated at 0x{off:x}")))
}

fn read_u16(data: &[u8], off: usize) -> Result<u16, Error> {
    read_array(data, off).map(u16::from_be_bytes)
}

fn read_u32(data: &[u8], off: usize) -> Result<u32, Error> {
    read_array(data, off).map(u32::from_be_bytes)
}

/// The `len` name bytes at `off` without NUL padding. Spaces are kept: a
/// Mac name may begin or end with them
fn stored_name(data: &[u8], off: usize, len: usize) -> &[u8] {
    let bytes = &data[off..off + len];
    let start = bytes.iter().position(|&b| b != 0).unwrap_or(len);
    let end = bytes.iter().rposition(|&b| b != 0).map_or(start, |i| i + 1);
    &bytes[start..end]
}

fn mac_str(data: &[u8], off: usize, len: usize, encoding: NameEncoding) -> String {
    encoding.decode(stored_name(data, off, len))
}

/// Record builders for tests that assemble whole archives
#[cfg(test)]
pub(crate) mod testutil {
    use super::{
        DVCT_NLEN, FVCT_BLOCK_DATA_OFF, FVCT_BLOCK_RSRC_OFF, FVCT_COMP_DATA, FVCT_COMP_RSRC,
        FVCT_DATA_OFFSET, FVCT_FLAGS, FVCT_NLEN, FVCT_SEGMENT, FVCT_UNCOMP_DATA, FVCT_UNCOMP_RSRC,
    };

    /// A file entry with every field empty or zero
    pub(crate) fn blank_entry() -> super::FileEntry {
        super::FileEntry {
            name: String::new(),
            name_bytes: Vec::new(),
            dir: std::sync::Arc::from(""),
            file_type: [0; 4],
            creator: [0; 4],
            flags: 0,
            finder_flags: 0,
            created: 0,
            modified: 0,
            crc32: 0,
            segment: 0,
            comp_data: 0,
            uncomp_data: 0,
            comp_rsrc: 0,
            uncomp_rsrc: 0,
            data_offset: 0,
            block_data_off: 0,
            block_rsrc_off: 0,
        }
    }

    #[derive(Default)]
    pub(crate) struct TestFile {
        pub name: &'static str,
        pub flags: u32,
        pub segment: u16,
        pub data_offset: u32,
        pub comp_data: u32,
        pub uncomp_data: u32,
        pub comp_rsrc: u32,
        pub uncomp_rsrc: u32,
        pub block_data_off: u32,
        pub block_rsrc_off: u32,
        pub depth: u16,
        pub crc32: u32,
        pub modified: u32,
    }

    /// An FVCT record with the name as its last field, two bytes after the
    /// length byte, which is where the parser looks by default
    pub(crate) fn fvct_record(f: &TestFile) -> Vec<u8> {
        let mut r = vec![0u8; FVCT_NLEN + 2];
        r[..4].copy_from_slice(b"FVCT");
        let mut put = |off: usize, v: u32| r[off..off + 4].copy_from_slice(&v.to_be_bytes());
        put(FVCT_FLAGS, f.flags);
        put(FVCT_COMP_DATA, f.comp_data);
        put(FVCT_UNCOMP_DATA, f.uncomp_data);
        put(FVCT_COMP_RSRC, f.comp_rsrc);
        put(FVCT_UNCOMP_RSRC, f.uncomp_rsrc);
        put(FVCT_DATA_OFFSET, f.data_offset);
        put(FVCT_BLOCK_DATA_OFF, f.block_data_off);
        put(FVCT_BLOCK_RSRC_OFF, f.block_rsrc_off);
        put(super::FVCT_CRC, f.crc32);
        put(super::FVCT_MODIFIED, f.modified);
        r[super::FVCT_DEPTH..super::FVCT_DEPTH + 2].copy_from_slice(&f.depth.to_be_bytes());
        r[FVCT_SEGMENT..FVCT_SEGMENT + 2].copy_from_slice(&f.segment.to_be_bytes());
        r[FVCT_NLEN] = u8::try_from(f.name.len()).unwrap();
        r.extend_from_slice(f.name.as_bytes());
        r
    }

    pub(crate) fn dvct_record(name: &str, depth: u16) -> Vec<u8> {
        let mut r = vec![0u8; DVCT_NLEN + 2];
        r[..4].copy_from_slice(b"DVCT");
        r[super::DVCT_DEPTH..super::DVCT_DEPTH + 2].copy_from_slice(&depth.to_be_bytes());
        r[DVCT_NLEN] = u8::try_from(name.len()).unwrap();
        r.extend_from_slice(name.as_bytes());
        r
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse_roman(data: &[u8]) -> Result<ArchiveInfo, Error> {
        parse(data, NameEncoding::MacRoman)
    }

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
        let data = make_tag_body(&[(b"FVCT", 186), (b"PACK", 26), (b"BBrd", 62), (b"INDN", 10)]);
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
        assert_eq!(mac_str(&data, off, 6, NameEncoding::MacRoman), "myfile");
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
        assert!(parse_roman(&compressed_cvct(&[0xAB; 8], 0xFFFF)).is_err());
    }

    #[test]
    fn parse_survives_garbage_cvct_body() {
        // a non-DEFLATE compressed directory errors cleanly, never panics or hangs
        assert!(parse_roman(&compressed_cvct(&[0xFF; 64], 64)).is_err());
    }

    #[test]
    fn parse_rejects_cvct_pointer_past_end() {
        let mut buf = vec![0u8; 0x40];
        buf[0..4].copy_from_slice(b"SVCT");
        buf[0x24..0x28].copy_from_slice(&0xFFFFu32.to_be_bytes());
        assert!(parse_roman(&buf).is_err());
    }
}

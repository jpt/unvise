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
/// Largest file table a compressed one may decompress to. A record is at
/// least 80 bytes, so this allows several hundred thousand of them
const MAX_TABLE_LEN: usize = 64 << 20;
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
    /// Whether where the records keep their names was assumed. That happens
    /// when the format version is not one of the listed ones and the archive
    /// has too few records to show it. Names can then be wrong
    pub names_assumed: bool,
}

/// Parses the SVCT header and CVCT file table from raw archive data
///
/// # Errors
///
/// Returns [`Error::InvalidArchive`] if the data lacks an SVCT header or
/// the CVCT pointer is invalid
pub fn parse(data: &[u8], encoding: NameEncoding) -> Result<ArchiveInfo, Error> {
    parse_as(data, encoding, true)
}

/// [`parse`], with the format version taken as one that is not listed when
/// `listed` is false, so that a check can compare the two
pub(crate) fn parse_as(
    data: &[u8],
    encoding: NameEncoding,
    listed: bool,
) -> Result<ArchiveInfo, Error> {
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
            decompressed_body = deflate::decompress_raw_word_deflate(compressed, MAX_TABLE_LEN)?;
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
    // From format 0b (the Mac OS X installers) both record kinds have two
    // more bytes of fields before the name length
    let later = if fmt_major >= FMT_OSX { 2 } else { 0 };
    let (fvct_nlen, dvct_nlen) = (FVCT_NLEN + later, DVCT_NLEN + later);
    // which kinds of record had nothing to show where their name is
    let mut assumed = (false, false);
    let known = if listed {
        name_offsets(fmt_major, fmt_minor)
    } else {
        None
    };
    let (fvct_name_off, dvct_name_off) = known.unwrap_or_else(|| {
        // a version that is not listed: the archive's own records show
        // where their names are. With too few records to tell, the name is
        // taken to follow its length directly
        let (fvct, dvct) = infer_name_offsets(parse_data, body_start, fvct_nlen, dvct_nlen);
        assumed = (fvct.is_none(), dvct.is_none());
        (fvct.unwrap_or(fvct_nlen + 2), dvct.unwrap_or(dvct_nlen + 2))
    });
    let tags = scan_tags(
        parse_data,
        body_start,
        (fvct_nlen, fvct_name_off),
        (dvct_nlen, dvct_name_off),
    );
    let names_assumed = tags.iter().any(|&(_, kind)| match kind {
        TagKind::Fvct => assumed.0,
        TagKind::Dvct => assumed.1,
    });

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
        names_assumed,
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

/// The two kinds of record that are read
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum TagKind {
    Fvct,
    Dvct,
}

/// Finds the file and folder records from `from` on, by their tags.
/// `fvct` and `dvct` are where each kind keeps its name length and its
/// name. A record runs at least to the end of its name, so the search for
/// the next one starts there, and a name cannot be taken for a tag
fn scan_tags(
    data: &[u8],
    from: usize,
    fvct: (usize, usize),
    dvct: (usize, usize),
) -> Vec<(usize, TagKind)> {
    record_marks(data, from, Some(fvct), Some(dvct))
        .into_iter()
        .filter(|&(_, record)| record)
        .map(|(at, _)| {
            let kind = if data[at..].starts_with(b"FVCT") {
                TagKind::Fvct
            } else {
                TagKind::Dvct
            };
            (at, kind)
        })
        .collect()
}

/// Tags of the other things a file table holds. A file or folder record
/// ends where the next tag of any kind starts
const OTHER_TAGS: [&[u8; 4]; 7] = [
    b"PACK", b"BBrd", b"CODE", b"BDIR", b"PROJ", b"INDN", b"DfIl",
];

/// Every place from `from` on where a tag stands, and whether it is the tag
/// of a file or folder record. Where `fvct` or `dvct` says where that kind
/// keeps its name length and its name, the name is stepped over, so that it
/// cannot be taken for a tag
fn record_marks(
    data: &[u8],
    from: usize,
    fvct: Option<(usize, usize)>,
    dvct: Option<(usize, usize)>,
) -> Vec<(usize, bool)> {
    let mut marks = Vec::new();
    let mut p = from;
    while let Some(tag) = data.get(p..p + 4) {
        let name = match tag {
            b"FVCT" => Some(fvct),
            b"DVCT" => Some(dvct),
            _ => None,
        };
        if let Some(name) = name {
            marks.push((p, true));
            p += name
                .and_then(|(len_at, name_at)| Some(name_at + usize::from(*data.get(p + len_at)?)))
                .unwrap_or(4);
        } else if OTHER_TAGS.iter().any(|other| tag == *other) {
            marks.push((p, false));
            p += 4;
        } else {
            p += 1;
        }
    }
    marks
}

/// Where file records and folder records keep their names, worked out from
/// the archive. The first round takes every tag it sees for one; the second
/// uses the offsets of the first to step over the names, where a tag can
/// turn up by chance
fn infer_name_offsets(
    data: &[u8],
    from: usize,
    fvct_nlen: usize,
    dvct_nlen: usize,
) -> (Option<usize>, Option<usize>) {
    let infer = |marks: &[(usize, bool)]| {
        (
            infer_name_offset(data, marks, *b"FVCT", fvct_nlen),
            infer_name_offset(data, marks, *b"DVCT", dvct_nlen),
        )
    };
    let (fvct, dvct) = infer(&record_marks(data, from, None, None));
    infer(&record_marks(
        data,
        from,
        fvct.map(|at| (fvct_nlen, at)),
        dvct.map(|at| (dvct_nlen, at)),
    ))
}

/// Where the records with `tag` keep their name, worked out from the
/// records themselves. The name is the last field of a record, so it starts
/// its own length before the next record. Every record that another record
/// follows votes, and the most common answer wins. The last record is gone
/// by only when no other can vote. `None` if no record can
fn infer_name_offset(
    data: &[u8],
    marks: &[(usize, bool)],
    tag: [u8; 4],
    name_len_at: usize,
) -> Option<usize> {
    // where the record after each mark starts, and whether a record does
    // follow. After the last record the next tag of any kind bounds it, but
    // other data can stand between its name and that tag
    let mut next_record = None;
    let mut ends = vec![(None, false); marks.len()];
    for (i, &(pos, record)) in marks.iter().enumerate().rev() {
        ends[i] = match next_record {
            Some(next) => (Some(next), true),
            None => (marks.get(i + 1).map(|&(next, _)| next), false),
        };
        if record {
            next_record = Some(pos);
        }
    }
    let mut votes: Vec<(usize, usize)> = Vec::new();
    let mut last = None;
    for (&(pos, _), (end, followed)) in marks.iter().zip(ends) {
        let (Some(end), Some(&len)) = (end, data.get(pos + name_len_at)) else {
            continue;
        };
        let (len, stride) = (usize::from(len), end - pos);
        if !data[pos..].starts_with(&tag) || len == 0 || len >= stride {
            continue;
        }
        let offset = stride - len;
        if !followed {
            last = Some(offset);
            continue;
        }
        match votes.iter_mut().find(|(o, _)| *o == offset) {
            Some(vote) => vote.1 += 1,
            None => votes.push((offset, 1)),
        }
    }
    votes
        .into_iter()
        .max_by_key(|&(_, count)| count)
        .map(|(offset, _)| offset)
        .or(last)
}

/// Where a file record and a folder record keep their name, counted from
/// the record's tag, for a format version. `None` for a version that is not
/// listed
const fn name_offsets(major: u8, minor: u8) -> Option<(usize, usize)> {
    Some(match (major, minor) {
        (0, 1) | (2, 1..=2) => (124, 82),
        (2, 5) | (3, 0..=3) => (124, 88),
        (3, 4) => (140, 104),
        (3, 5) => (184, 148),
        (3, 6..=7) => (186, 148),
        (3, 8 | 0x0a..=0x0b) => (190, 152),
        (3, 0x0c..=0x0d) => (198, 160),
        (3, 0x0e) => (198, 164),
        (FMT_OSX, 0) => (212, 178),
        _ => return None,
    })
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

    /// An FVCT record as format 03 03 lays it out
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
        let mut r = vec![0u8; super::name_offsets(3, 3).unwrap().1];
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

    #[test]
    fn records_are_found_by_tag_and_names_are_not_searched() {
        let (fvct, dvct) = ((FVCT_NLEN, 124), (DVCT_NLEN, 88));
        // a folder whose name is a tag, then a file
        let mut data = vec![0u8; 88];
        data[..4].copy_from_slice(b"DVCT");
        data[DVCT_NLEN] = 4;
        data.extend_from_slice(b"FVCT");
        let file_at = data.len();
        data.extend_from_slice(b"FVCT");
        data.resize(file_at + 124, 0);
        let tags = scan_tags(&data, 0, fvct, dvct);
        assert_eq!(tags, [(0, TagKind::Dvct), (file_at, TagKind::Fvct)]);
        // other bytes are passed over
        assert_eq!(
            scan_tags(b"....XXXX....", 0, fvct, dvct),
            Vec::<(usize, TagKind)>::new()
        );
    }

    #[test]
    fn an_unlisted_version_gets_its_name_offsets_from_its_records() {
        assert_eq!(name_offsets(2, 3), None);
        // two file records 200 bytes apart with six-byte names, then a tag
        // of another kind: the names start 194 bytes in
        let mut data = vec![0u8; 404];
        for at in [0, 200] {
            data[at..at + 4].copy_from_slice(b"FVCT");
            data[at + FVCT_NLEN] = 6;
        }
        data[400..].copy_from_slice(b"PACK");
        let marks = record_marks(&data, 0, None, None);
        assert_eq!(marks, [(0, true), (200, true), (400, false)]);
        assert_eq!(
            infer_name_offset(&data, &marks, *b"FVCT", FVCT_NLEN),
            Some(194)
        );
        // no folder record, so nothing to go by
        assert_eq!(infer_name_offset(&data, &marks, *b"DVCT", DVCT_NLEN), None);
    }

    #[test]
    fn a_tag_inside_a_name_does_not_count_as_a_record() {
        // five file records 200 bytes apart; the name of the second is a tag
        let mut data = vec![0u8; 1004];
        for at in [0, 200, 400, 600, 800] {
            data[at..at + 4].copy_from_slice(b"FVCT");
            data[at + FVCT_NLEN] = 6;
        }
        data[200 + FVCT_NLEN] = 4;
        data[396..400].copy_from_slice(b"DVCT");
        data[1000..].copy_from_slice(b"PACK");
        assert_eq!(record_marks(&data, 0, None, None).len(), 7);
        let (fvct, dvct) = infer_name_offsets(&data, 0, FVCT_NLEN, DVCT_NLEN);
        assert_eq!(fvct, Some(194));
        // the one folder tag was a name
        assert_eq!(dvct, None);
    }

    #[test]
    fn the_last_record_does_not_outvote_one_that_a_record_follows() {
        // two file records; other data stands between the name of the
        // second and the next tag
        let mut data = vec![0u8; 464];
        for at in [0, 200] {
            data[at..at + 4].copy_from_slice(b"FVCT");
            data[at + FVCT_NLEN] = 6;
        }
        data[460..].copy_from_slice(b"PACK");
        let (fvct, _) = infer_name_offsets(&data, 0, FVCT_NLEN, DVCT_NLEN);
        assert_eq!(fvct, Some(194));
        // on its own, the last record is all there is to go by
        let (fvct, _) = infer_name_offsets(&data, 200, FVCT_NLEN, DVCT_NLEN);
        assert_eq!(fvct, Some(254));
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

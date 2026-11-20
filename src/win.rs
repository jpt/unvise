//! Windows VISE archive parser and extractor
//!
//! Windows VISE payloads live in a PE `_mvdata` section (Apple builds) or
//! PE overlay (all other builds). The payload starts with either an SIVM
//! header (Apple, with trailer offset and session ID) or a bare ESIV header
//! (everyone else). After a variable-length metadata region, a chain of
//! embedded DLL entries follows -- the VISE runtime (`vise32ex.dll`) and
//! resources like language files. The typed record stream comes after
//!
//! Four runtime versions exist, each with slightly different record layouts.
//! Detection is based on the embedded DLL's PE export count, an internal
//! ASCII version table, and the presence of the `vise32qt` string. See
//! `RecordFmt` for details
//!
//! Compression is byte-pair swap + raw DEFLATE (no substitution cipher,
//! unlike the Mac format). Stub installers store the record stream in the
//! `.exe` and file data in a companion `.qdat` volume matched by session ID

use std::fs;
use std::ops::Range;
use std::path::Path;

use crate::{
    Error, ExtractResult, OUTPUT_BUDGET_HEADROOM, OUTPUT_BUDGET_RATIO, Progress, SkipReason,
    clean_name, safe_join,
};

/// SIVM payloads store blob offsets relative to payload byte 8 (after the
/// SIVM magic and trailer-offset fields)
const SIVM_BLOB_OFFSET: usize = 8;

/// Highest record type in mainline 4.x streams
const MAX_RECORD_TYPE: u32 = 0x26;
const MAX_RECORD_COUNT: u32 = 100_000;
const MAX_STRING_LEN: usize = 260;
/// Largest observed feature/condition count is ~22
const MAX_ARRAY_COUNT: u16 = 1000;

/// Archive-header flags value for stub installers (exe+qdat split).
/// Distinct from Mac-side `FileEntry::is_stub` which is a per-entry bitmask
const STUB_FLAG: u32 = 0x0002_0000;
const QDAT_MAGIC: &[u8; 8] = b"ESIVRDLB";
/// Per-file entries in a qdat start at this fixed offset (16-byte header
/// + 4-byte count + 782 bytes of metadata)
const QDAT_ENTRIES_OFFSET: usize = 802;
const QDAT_ENTRY_HEADER: usize = 16;
/// String found only in the Apple fork of the runtime DLL
const APPLE_MARKER: &[u8] = b"vise32qt";

/// Record format version, detected from three properties of the embedded
/// vise32ex.dll: PE export count, ASCII version table contents, and the
/// presence of the string `vise32qt`
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RecordFmt {
    /// Pre-4.x (1998). Single PE export, no version table. Inline strings
    /// use u8 length prefixes, common header lacks the flag byte between
    /// features and conditions and the trailing byte after bitmasks, and
    /// blob offsets are file-relative rather than payload-relative
    Pre4,
    #[allow(clippy::doc_markdown)]
    /// Apple fork, internal version 2.x. Identified by
    /// string `vise32qt` in the decompressed DLL. Install path is read
    /// from the record stream. 33 record types (up to 0x23)
    Apple,
    /// Mainline 4.1 through 4.7. ASCII version table present with first
    /// entry below 4.8. Install path resolved internally (not in stream).
    /// 36 record types (up to 0x26)
    Main4,
    /// Mainline 4.8 and later. Common header layout widens: the four u8
    /// fields after the first skip become u8, u16, u8, u16, and the seven
    /// trailing u8 fields become six
    Main48,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PayloadKind {
    Sivm,
    Esiv,
}

/// A loaded Windows VISE installer ready for extraction
#[derive(Debug)]
pub struct WinArchive {
    data: Vec<u8>,
    /// Where the VISE payload sits inside `data`
    payload: Range<usize>,
    qdat: Option<Vec<u8>>,
    pub info: WinArchiveInfo,
}

#[derive(Debug)]
#[non_exhaustive]
pub struct WinArchiveInfo {
    pub version: u32,
    pub flags: u32,
    pub entries: Vec<WinEntry>,
}

#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct WinEntry {
    pub name: String,
    pub directory: String,
    pub offset: usize,
    pub compressed_len: usize,
    /// Size recorded in the file table, or 0 when the table does not give one
    pub uncompressed_len: usize,
    use_qdat: bool,
}

impl WinEntry {
    /// The install path relative to the output directory: `directory/name`
    #[must_use]
    pub fn path(&self) -> String {
        if self.directory.is_empty() {
            self.name.clone()
        } else {
            format!("{}/{}", self.directory, self.name)
        }
    }
}

impl WinArchive {
    /// Parses an installer executable, locating the VISE payload inside it.
    /// `qdat` is the companion volume of a stub installer, if there is one
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArchive`] if the file is not a PE executable
    /// carrying a VISE payload, or the record stream cannot be parsed
    pub fn from_pe(file: Vec<u8>, qdat: Option<Vec<u8>>) -> Result<Self, Error> {
        let (payload, start) = crate::pe::extract_payload(&file)?;
        let range = start..start + payload.len();
        let info = parse_payload(payload, qdat.as_deref(), start)?;
        Ok(Self {
            data: file,
            payload: range,
            qdat,
            info,
        })
    }

    /// Parses a payload already cut out of its executable.
    /// `payload_file_offset` is the byte position of the payload within the
    /// PE file, needed because Pre4 blob offsets are file-relative
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArchive`] if the data lacks valid SIVM/ESIV
    /// headers or the record stream cannot be parsed
    pub fn parse(
        data: Vec<u8>,
        qdat: Option<Vec<u8>>,
        payload_file_offset: usize,
    ) -> Result<Self, Error> {
        let info = parse_payload(&data, qdat.as_deref(), payload_file_offset)?;
        Ok(Self {
            payload: 0..data.len(),
            data,
            qdat,
            info,
        })
    }

    fn payload(&self) -> &[u8] {
        &self.data[self.payload.clone()]
    }

    /// Session ID from a SIVM (offset 0x0C) or ESIV (offset 0x04) header
    #[must_use]
    pub fn session_id(payload: &[u8]) -> Option<u32> {
        if payload.len() < 16 {
            return None;
        }
        let off = if &payload[..4] == b"SIVM" {
            0x0C
        } else if &payload[..4] == b"ESIV" {
            0x04
        } else {
            return None;
        };
        Some(u32::from_le_bytes(payload[off..off + 4].try_into().ok()?))
    }

    #[must_use]
    pub fn is_stub(payload: &[u8]) -> bool {
        let off = if payload.get(..4) == Some(b"SIVM") {
            0x14
        } else if payload.get(..4) == Some(b"ESIV") {
            0x0C
        } else {
            return false;
        };
        payload.len() > off + 4
            && u32::from_le_bytes(payload[off..off + 4].try_into().unwrap_or([0; 4])) == STUB_FLAG
    }

    /// Checks ESIVRDLB magic and session ID match
    #[must_use]
    pub fn validate_qdat(qdat: &[u8], expected_session: u32) -> bool {
        qdat.len() > QDAT_ENTRIES_OFFSET
            && &qdat[..8] == QDAT_MAGIC
            && u32::from_le_bytes(qdat[0x0C..0x10].try_into().unwrap_or([0; 4])) == expected_session
    }

    /// Decompresses one entry into memory
    ///
    /// # Errors
    ///
    /// Returns [`Error::Skipped`] if the entry's data is in a companion
    /// `.qdat` volume that was not supplied, or [`Error::Decompression`] if
    /// the data is out of range, does not decode, or does not match the size
    /// recorded in the file table
    pub fn read(&self, entry: &WinEntry) -> Result<Vec<u8>, Error> {
        if entry.compressed_len == 0 {
            return Ok(Vec::new());
        }
        let source = if entry.use_qdat {
            self.qdat
                .as_deref()
                .ok_or(Error::Skipped(SkipReason::MissingQdat))?
        } else {
            self.payload()
        };
        let blob = entry
            .offset
            .checked_add(entry.compressed_len)
            .and_then(|end| source.get(entry.offset..end))
            .ok_or_else(|| Error::Decompression("offset out of range".into()))?;
        let out = crate::deflate::swap_and_inflate(blob)
            .ok_or_else(|| Error::Decompression("invalid compressed data".into()))?;
        if entry.uncompressed_len != 0 && out.len() != entry.uncompressed_len {
            return Err(Error::Decompression(format!(
                "decoded {} bytes, file table says {}",
                out.len(),
                entry.uncompressed_len
            )));
        }
        Ok(out)
    }

    /// Extracts all files to `out_dir`, recreating the install directory
    /// structure
    ///
    /// Entries that cannot be decoded are counted in
    /// [`ExtractResult::failed`] and extraction continues
    ///
    /// # Errors
    ///
    /// Returns [`Error::Io`] on filesystem failures
    pub fn extract(&self, out_dir: &Path) -> Result<ExtractResult, Error> {
        self.extract_with(out_dir, |_| {})
    }

    /// Like [`WinArchive::extract`], and reports each entry to `on_progress`
    /// as it is handled
    ///
    /// # Errors
    ///
    /// Returns [`Error::Io`] on filesystem failures
    pub fn extract_with(
        &self,
        out_dir: &Path,
        mut on_progress: impl FnMut(Progress<'_>),
    ) -> Result<ExtractResult, Error> {
        fs::create_dir_all(out_dir)?;

        let budget = self
            .payload
            .len()
            .saturating_add(self.qdat.as_ref().map_or(0, Vec::len))
            .saturating_mul(OUTPUT_BUDGET_RATIO)
            .saturating_add(OUTPUT_BUDGET_HEADROOM);
        let mut total_out: usize = 0;
        let mut result = ExtractResult::default();

        for entry in &self.info.entries {
            let name = clean_name(&entry.path());
            if name.is_empty() {
                on_progress(Progress::Skipped {
                    name: &name,
                    reason: SkipReason::EmptyName,
                });
                result.skipped += 1;
                continue;
            }
            let Some(path) = safe_join(out_dir, &name) else {
                on_progress(Progress::Skipped {
                    name: &name,
                    reason: SkipReason::UnsafePath,
                });
                result.skipped += 1;
                continue;
            };
            if let Some(p) = path.parent() {
                fs::create_dir_all(p)?;
            }

            match self.read(entry) {
                Ok(bytes) => {
                    fs::write(&path, &bytes)?;
                    on_progress(Progress::Extracted {
                        name: &name,
                        data_len: bytes.len(),
                        rsrc_len: None,
                    });
                    result.extracted += 1;
                    total_out = total_out.saturating_add(bytes.len());
                    if total_out > budget {
                        on_progress(Progress::BudgetExceeded { budget });
                        break;
                    }
                }
                Err(Error::Skipped(reason)) => {
                    on_progress(Progress::Skipped {
                        name: &name,
                        reason,
                    });
                    result.skipped += 1;
                }
                Err(error) => {
                    on_progress(Progress::Failed {
                        name: &name,
                        error: &error,
                    });
                    result.failed += 1;
                }
            }
        }

        Ok(result)
    }
}

fn parse_payload(
    data: &[u8],
    qdat: Option<&[u8]>,
    payload_file_offset: usize,
) -> Result<WinArchiveInfo, Error> {
    if data.len() < 16 {
        return Err(Error::InvalidArchive("payload too small".into()));
    }

    let (kind, version, flags) =
        if &data[..4] == b"SIVM" && data.len() >= 0x18 && &data[8..12] == b"ESIV" {
            let v = u32::from_le_bytes(data[0x10..0x14].try_into().unwrap());
            let f = u32::from_le_bytes(data[0x14..0x18].try_into().unwrap());
            (PayloadKind::Sivm, v, f)
        } else if &data[..4] == b"ESIV" {
            let v = u32::from_le_bytes(data[0x08..0x0C].try_into().unwrap());
            let f = u32::from_le_bytes(data[0x0C..0x10].try_into().unwrap());
            (PayloadKind::Esiv, v, f)
        } else {
            return Err(Error::InvalidArchive("not a Windows VISE payload".into()));
        };

    let first_entry = find_first_entry(data)?;
    let mut entries = Vec::new();
    let (chain_end, fmt_hint) = walk_named_chain(data, first_entry, &mut entries);
    let qdat_entries = qdat.map(parse_qdat_entries).transpose()?;

    // Each format is fully specified -- try the hinted one first, fall back
    // to the others if parsing fails
    let try_order: &[RecordFmt] = match fmt_hint {
        RecordFmt::Pre4 => &[
            RecordFmt::Pre4,
            RecordFmt::Apple,
            RecordFmt::Main4,
            RecordFmt::Main48,
        ],
        RecordFmt::Apple => &[
            RecordFmt::Apple,
            RecordFmt::Main4,
            RecordFmt::Main48,
            RecordFmt::Pre4,
        ],
        RecordFmt::Main4 => &[
            RecordFmt::Main4,
            RecordFmt::Apple,
            RecordFmt::Main48,
            RecordFmt::Pre4,
        ],
        RecordFmt::Main48 => &[
            RecordFmt::Main48,
            RecordFmt::Main4,
            RecordFmt::Apple,
            RecordFmt::Pre4,
        ],
    };

    let mut last_err = None;
    for &fmt in try_order {
        // Pre4 blob offsets are absolute file positions; subtract the
        // overlay start to get a payload-relative index. SIVM adds 8
        // (past the magic and trailer-offset fields). ESIV adds 0
        let blob_add: usize = match kind {
            PayloadKind::Sivm => SIVM_BLOB_OFFSET,
            PayloadKind::Esiv => 0,
        };
        let blob_sub: usize = match (kind, fmt) {
            (PayloadKind::Esiv, RecordFmt::Pre4) => payload_file_offset,
            _ => 0,
        };

        let mut trial_entries = entries.clone();
        if let Ok(stream_off) = find_record_stream(data, chain_end, fmt) {
            match parse_record_stream(
                data,
                stream_off,
                &mut trial_entries,
                qdat_entries.as_deref(),
                fmt,
                blob_add,
                blob_sub,
                flags,
            ) {
                Ok(()) => {
                    return Ok(WinArchiveInfo {
                        version,
                        flags,
                        entries: trial_entries,
                    });
                }
                Err(e) => {
                    last_err = Some(e);
                }
            }
        }
    }

    Err(last_err.unwrap_or_else(|| Error::InvalidArchive("record stream not found".into())))
}

fn find_first_entry(data: &[u8]) -> Result<usize, Error> {
    data.windows(12)
        .position(|w| w == b"vise32ex.dll")
        .and_then(|p| p.checked_sub(1))
        .ok_or_else(|| Error::InvalidArchive("no vise32ex.dll in payload".into()))
}

/// Walks the chain of `[u8 name_len][name][12B fields][u32 comp][data]`
/// entries, collecting them. Returns the byte offset where the chain ends
/// and a format hint derived from the decompressed vise32ex.dll
fn walk_named_chain(
    data: &[u8],
    mut pos: usize,
    entries: &mut Vec<WinEntry>,
) -> (usize, RecordFmt) {
    let mut rec_fmt = RecordFmt::Main4;
    loop {
        if pos >= data.len() {
            break;
        }
        let name_len = data[pos] as usize;
        if name_len == 0 || name_len > 63 || pos + 1 + name_len + 16 > data.len() {
            break;
        }
        let name_bytes = &data[pos + 1..pos + 1 + name_len];
        if !name_bytes.iter().all(|&b| (0x20..0x7F).contains(&b)) {
            break;
        }
        let name = String::from_utf8_lossy(name_bytes).into_owned();

        let size_off = pos + 1 + name_len + 12;
        if size_off + 4 > data.len() {
            break;
        }
        let comp_size =
            u32::from_le_bytes(data[size_off..size_off + 4].try_into().unwrap()) as usize;

        let body_off = size_off + 4;
        let Some(body_end) = body_off
            .checked_add(comp_size)
            .filter(|&end| comp_size != 0 && end <= data.len())
        else {
            break;
        };

        if name == "vise32ex.dll" {
            if let Some(dll) = crate::deflate::swap_and_inflate(&data[body_off..body_end]) {
                rec_fmt = detect_record_fmt(&dll);
            }
        }

        entries.push(WinEntry {
            name,
            directory: String::new(),
            offset: body_off,
            compressed_len: comp_size,
            uncompressed_len: 0,
            use_qdat: false,
        });
        pos = body_end;
    }
    (pos, rec_fmt)
}

/// Identifies the record format from the decompressed vise32ex.dll
///
/// Mainline DLLs contain an ASCII version table -- consecutive
/// null-terminated `major.minor.patch` strings starting with `4.`. The
/// first entry is the DLL's own version; runtime 4.8 introduced the
/// wider common header. The Apple fork has no 4.x table but contains
/// the string `vise32qt`. DLLs predating the version table have a single
/// PE export and no identifying string
fn detect_record_fmt(dll: &[u8]) -> RecordFmt {
    if let Some((_, minor)) = find_runtime_version(dll) {
        if minor >= 8 {
            return RecordFmt::Main48;
        }
        return RecordFmt::Main4;
    }
    if dll.windows(APPLE_MARKER.len()).any(|w| w == APPLE_MARKER) {
        return RecordFmt::Apple;
    }
    RecordFmt::Pre4
}

/// Parses the `4.major.minor...` version table embedded in mainline DLLs
fn find_runtime_version(dll: &[u8]) -> Option<(u32, u32)> {
    let mut i = 0;
    while i + 4 < dll.len() {
        if dll[i] == b'4' && dll[i + 1] == b'.' && dll[i + 2].is_ascii_digit() {
            let start = i;
            while i < dll.len() && dll[i] != 0 {
                i += 1;
            }
            let s = &dll[start..i];
            let mut parts = s.splitn(3, |&b| b == b'.');
            let major = parts
                .next()
                .and_then(|p| std::str::from_utf8(p).ok()?.parse().ok());
            let minor = parts
                .next()
                .and_then(|p| std::str::from_utf8(p).ok()?.parse().ok());
            if let (Some(maj), Some(min)) = (major, minor) {
                return Some((maj, min));
            }
        }
        i += 1;
    }
    None
}

/// Scans from `chain_end` for the `[u32 count][u32 type]` pattern that
/// opens the record stream, validating by parsing the first record's
/// common header
fn find_record_stream(data: &[u8], chain_end: usize, fmt: RecordFmt) -> Result<usize, Error> {
    let search_end = data.len().min(chain_end.saturating_add(0x40000));
    for off in chain_end..search_end {
        if off + 8 > data.len() {
            break;
        }
        let count = u32::from_le_bytes(data[off..off + 4].try_into().unwrap());
        if count == 0 || count > MAX_RECORD_COUNT {
            continue;
        }
        let first_type = u32::from_le_bytes(data[off + 4..off + 8].try_into().unwrap());
        if !(1..=MAX_RECORD_TYPE).contains(&first_type) {
            continue;
        }
        let mut probe = Cursor::new(data, off + 8, fmt);
        if probe.common().is_ok() {
            return Ok(off);
        }
    }
    Err(Error::InvalidArchive("record stream not found".into()))
}

struct Cursor<'a> {
    data: &'a [u8],
    pos: usize,
    fmt: RecordFmt,
}

impl<'a> Cursor<'a> {
    fn new(data: &'a [u8], pos: usize, fmt: RecordFmt) -> Self {
        Self { data, pos, fmt }
    }

    fn remaining(&self) -> usize {
        self.data.len().saturating_sub(self.pos)
    }

    fn u8(&mut self) -> Result<u8, Error> {
        if self.pos >= self.data.len() {
            return Err(Error::InvalidArchive(format!(
                "truncated at 0x{:x}",
                self.pos
            )));
        }
        let v = self.data[self.pos];
        self.pos += 1;
        Ok(v)
    }

    fn u16(&mut self) -> Result<u16, Error> {
        if self.pos + 2 > self.data.len() {
            return Err(Error::InvalidArchive(format!(
                "truncated at 0x{:x}",
                self.pos
            )));
        }
        let v = u16::from_le_bytes(self.data[self.pos..self.pos + 2].try_into().unwrap());
        self.pos += 2;
        Ok(v)
    }

    fn u32(&mut self) -> Result<u32, Error> {
        if self.pos + 4 > self.data.len() {
            return Err(Error::InvalidArchive(format!(
                "truncated at 0x{:x}",
                self.pos
            )));
        }
        let v = u32::from_le_bytes(self.data[self.pos..self.pos + 4].try_into().unwrap());
        self.pos += 4;
        Ok(v)
    }

    fn bounded_u16(&mut self, max: u16, field: &str) -> Result<u16, Error> {
        let v = self.u16()?;
        if v > max {
            return Err(Error::InvalidArchive(format!(
                "{field} {v} exceeds limit {max} at 0x{:x}",
                self.pos - 2
            )));
        }
        Ok(v)
    }

    fn skip(&mut self, n: usize) -> Result<(), Error> {
        if self.pos + n > self.data.len() {
            return Err(Error::InvalidArchive(format!(
                "truncated at 0x{:x}",
                self.pos
            )));
        }
        self.pos += n;
        Ok(())
    }

    /// u16-prefixed string. Used by locstring internals and non-Pre4 inline
    /// reads. Pre4 inline strings use [`skip_inline`] instead
    fn string(&mut self) -> Result<Vec<u8>, Error> {
        let len = self.u16()? as usize;
        if len > MAX_STRING_LEN {
            return Err(Error::InvalidArchive(format!(
                "string length {len} exceeds limit at 0x{:x}",
                self.pos
            )));
        }
        if self.pos + len > self.data.len() {
            return Err(Error::InvalidArchive(format!(
                "string len {len} at 0x{:x}",
                self.pos
            )));
        }
        let s = self.data[self.pos..self.pos + len].to_vec();
        self.pos += len;
        Ok(s)
    }

    /// Reads an inline string and returns its bytes. Pre4 uses u8 prefix;
    /// all others use u16
    fn inline_string(&mut self) -> Result<Vec<u8>, Error> {
        if self.fmt == RecordFmt::Pre4 {
            let len = self.u8()? as usize;
            if self.pos + len > self.data.len() {
                return Err(Error::InvalidArchive(format!(
                    "string len {len} at 0x{:x}",
                    self.pos
                )));
            }
            let s = self.data[self.pos..self.pos + len].to_vec();
            self.pos += len;
            Ok(s)
        } else {
            self.string()
        }
    }

    /// Skips an inline string without allocating. Pre4 reads u8 prefix,
    /// all others read u16
    fn skip_inline(&mut self) -> Result<(), Error> {
        let len = if self.fmt == RecordFmt::Pre4 {
            self.u8()? as usize
        } else {
            let n = self.u16()? as usize;
            if n > MAX_STRING_LEN {
                return Err(Error::InvalidArchive(format!(
                    "string length {n} exceeds limit at 0x{:x}",
                    self.pos
                )));
            }
            n
        };
        self.skip(len)
    }

    /// u16-prefixed string followed by optional locale variants (u16 count,
    /// then per-locale: u16 id, u16 len, data). All formats use u16 here,
    /// even Pre4
    fn locstring(&mut self) -> Result<Vec<u8>, Error> {
        let s = self.string()?;
        let lc = self.bounded_u16(MAX_ARRAY_COUNT, "locale count")?;
        for _ in 0..lc {
            self.skip(2)?;
            let ln = self.u16()? as usize;
            if ln > MAX_STRING_LEN {
                return Err(Error::InvalidArchive(format!(
                    "locale string length {ln} exceeds limit at 0x{:x}",
                    self.pos
                )));
            }
            self.skip(ln)?;
        }
        Ok(s)
    }

    /// u16-prefixed variable-length block (alternate filename)
    fn alt_block(&mut self) -> Result<(), Error> {
        let n = self.u16()?;
        if n > 0 {
            self.skip(n as usize)?;
        }
        Ok(())
    }

    /// Common record header, shared by all record types. The fixed-width
    /// fields differ between Main48 and the rest, and Pre4 omits the flag
    /// byte between features and conditions and the trailing byte after
    /// bitmasks. Condition strings in Pre4 use u8 length prefixes
    fn common(&mut self) -> Result<(), Error> {
        self.skip(4 + 4)?;
        if self.fmt == RecordFmt::Main48 {
            self.u8()?;
            self.skip(2)?;
            self.u8()?;
            self.skip(2)?;
            self.skip(4 + 4)?;
            for _ in 0..6 {
                self.u8()?;
            }
        } else {
            for _ in 0..4 {
                self.u8()?;
            }
            self.skip(4 + 4)?;
            for _ in 0..7 {
                self.u8()?;
            }
        }
        let fc = self.bounded_u16(MAX_ARRAY_COUNT, "feature count")?;
        for _ in 0..fc {
            self.skip(4)?;
            self.u8()?;
        }
        if self.fmt != RecordFmt::Pre4 {
            self.u8()?;
        }
        let cc = self.bounded_u16(MAX_ARRAY_COUNT, "condition count")?;
        if self.fmt == RecordFmt::Pre4 {
            for _ in 0..cc {
                self.skip_inline()?;
                self.skip(4)?;
                self.skip_inline()?;
                self.skip_inline()?;
            }
        } else {
            for _ in 0..cc {
                self.string()?;
                self.skip(4)?;
                self.string()?;
                self.string()?;
            }
        }
        let cc2 = self.bounded_u16(MAX_ARRAY_COUNT, "condition2 count")?;
        if self.fmt == RecordFmt::Pre4 {
            for _ in 0..cc2 {
                self.skip_inline()?;
                self.skip(4)?;
                self.skip_inline()?;
                self.skip_inline()?;
            }
        } else {
            for _ in 0..cc2 {
                self.string()?;
                self.skip(4)?;
                self.string()?;
                self.string()?;
            }
        }
        self.skip(32 + 32)?;
        if self.fmt != RecordFmt::Pre4 {
            self.u8()?;
        }
        Ok(())
    }
}

/// Each qdat per-file entry is `[u32][u32 comp][u32 0][u32 0][comp bytes]`
fn parse_qdat_entries(qdat: &[u8]) -> Result<Vec<(usize, usize)>, Error> {
    if qdat.len() < QDAT_ENTRIES_OFFSET {
        return Err(Error::InvalidArchive("qdat too small".into()));
    }
    let mut entries = Vec::new();
    let mut pos = QDAT_ENTRIES_OFFSET;
    while pos + QDAT_ENTRY_HEADER <= qdat.len() {
        let comp = u32::from_le_bytes(qdat[pos + 4..pos + 8].try_into().unwrap()) as usize;
        let z1 = u32::from_le_bytes(qdat[pos + 8..pos + 12].try_into().unwrap());
        let z2 = u32::from_le_bytes(qdat[pos + 12..pos + 16].try_into().unwrap());
        if z1 != 0 || z2 != 0 {
            break;
        }
        let data_off = pos + QDAT_ENTRY_HEADER;
        if comp > 0
            && data_off
                .checked_add(comp)
                .is_none_or(|end| end > qdat.len())
        {
            break;
        }
        entries.push((data_off, comp));
        pos = data_off + comp;
    }
    Ok(entries)
}

#[allow(clippy::too_many_arguments)]
fn parse_record_stream(
    data: &[u8],
    offset: usize,
    entries: &mut Vec<WinEntry>,
    qdat_entries: Option<&[(usize, usize)]>,
    rec_fmt: RecordFmt,
    blob_add: usize,
    blob_sub: usize,
    flags: u32,
) -> Result<(), Error> {
    let mut c = Cursor::new(data, offset, rec_fmt);
    let count = c.u32()?;
    if count > MAX_RECORD_COUNT {
        return Err(Error::InvalidArchive(format!(
            "record count {count} exceeds limit {MAX_RECORD_COUNT}"
        )));
    }

    let stub_installer = flags == STUB_FLAG;
    let mut qdat_idx: usize = 0;

    for _ in 0..count {
        if c.remaining() < 8 {
            break;
        }
        let rtype = c.u32()?;
        c.common()?;

        if rtype == 2 {
            let mut entry = read_type2(&mut c, blob_add, blob_sub)?;

            if stub_installer {
                let in_payload = entry.compressed_len > 0
                    && entry
                        .offset
                        .checked_add(entry.compressed_len)
                        .is_some_and(|end| end <= data.len())
                    && entry.offset >= offset;

                if !in_payload {
                    // qdat entries correspond 1:1 with non-payload type-2 records,
                    // including zero-length ones -- advance the index unconditionally
                    if let Some(&(qdat_off, _)) = qdat_entries.and_then(|qe| qe.get(qdat_idx)) {
                        if entry.compressed_len > 0 {
                            entry.offset = qdat_off;
                            entry.use_qdat = true;
                        }
                        qdat_idx += 1;
                    } else if entry.compressed_len > 0 {
                        entry.use_qdat = true;
                    }
                }
            }

            entries.push(entry);
        } else {
            skip_type(&mut c, rtype)?;
        }
    }

    Ok(())
}

fn read_type2(c: &mut Cursor, blob_add: usize, blob_sub: usize) -> Result<WinEntry, Error> {
    let name_bytes = c.locstring()?;
    if c.fmt == RecordFmt::Pre4 {
        c.skip_inline()?;
    } else {
        c.alt_block()?;
    }
    let path_bytes = match c.fmt {
        RecordFmt::Pre4 | RecordFmt::Apple => c.inline_string()?,
        _ => Vec::new(),
    };
    let uncomp = c.u32()? as usize;
    let comp = c.u32()? as usize;
    let _volume = c.u32()?;
    let blob_off = c.u32()? as usize;
    c.skip(4)?;
    c.skip(24)?;
    c.skip(2 + 2 + 1 + 4)?;
    c.skip_inline()?;
    c.skip(4 + 1 + 1 + 4 + 4 + 4 + 1 + 1 + 1 + 1 + 4)?;
    if c.fmt == RecordFmt::Pre4 {
        c.skip(1 + 2 + 1)?;
    } else {
        let flag_b4 = c.u8()?;
        c.skip_inline()?;
        c.skip(1)?;
        if c.fmt == RecordFmt::Apple {
            if flag_b4 == 4 {
                c.skip(16)?;
            }
            c.skip(1 + 4 + 4)?;
        } else {
            c.skip(1 + 4 + 4 + 1)?;
        }
    }

    let name = String::from_utf8_lossy(&name_bytes).into_owned();
    let directory = resolve_vise_path(&String::from_utf8_lossy(&path_bytes))
        .trim_matches('/')
        .to_string();

    let offset = blob_off.saturating_add(blob_add).saturating_sub(blob_sub);

    Ok(WinEntry {
        name,
        directory,
        offset,
        compressed_len: comp,
        uncompressed_len: uncomp,
        use_qdat: false,
    })
}

#[allow(clippy::too_many_lines)]
#[rustfmt::skip]
fn skip_type(c: &mut Cursor, t: u32) -> Result<(), Error> {
    match (c.fmt, t) {
        // Shared across all formats
        (_, 0x03) => { c.locstring()?; c.skip_inline()?; c.skip_inline()?; c.skip_inline()?; c.skip_inline()?; c.skip(2)?; c.locstring()?; c.skip(1+1+1+1+1)?; }
        (_, 0x04) => { c.skip(1)?; c.skip_inline()?; c.skip_inline()?; c.skip_inline()?; c.skip_inline()?; c.skip_inline()?; c.skip_inline()?; c.skip(1)?; }
        (_, 0x06) => { c.skip(1)?; c.skip_inline()?; c.skip(1+1+2+1+1+2+1+1+4+4)?; c.skip_inline()?; c.skip(1)?; c.skip_inline()?; c.skip(1)?; c.locstring()?; c.skip(1+1+1)?; }
        (_, 0x07) => { c.skip(1)?; c.skip_inline()?; c.skip(1+1+2+1+1+2+1+1+4+4)?; c.skip_inline()?; c.skip(1)?; }
        (_, 0x08 | 0x09) => { c.skip(1)?; c.skip_inline()?; c.skip(1+1+2+1+1+2+1+1+4+4)?; c.skip_inline()?; c.skip(1+1)?; }
        (_, 0x0a) => { c.skip_inline()?; c.skip_inline()?; c.skip(1+1)?; }
        (_, 0x0b) => { c.locstring()?; c.skip_inline()?; c.skip_inline()?; c.skip_inline()?; c.skip_inline()?; c.skip(2+2+1+1+4)?; c.skip_inline()?; }
        (_, 0x0c) => { c.locstring()?; c.locstring()?; c.skip(1+1)?; }
        (_, 0x0d) => { c.skip(1)?; }
        (_, 0x0e) => { c.skip_inline()?; c.skip(4)?; c.skip_inline()?; c.skip_inline()?; }
        (_, 0x10) => { c.skip(1)?; c.skip_inline()?; c.skip(1)?; c.skip_inline()?; c.skip(1)?; c.skip_inline()?; c.skip_inline()?; c.skip_inline()?; }
        (_, 0x12) => { c.skip_inline()?; c.skip(1)?; c.skip_inline()?; c.skip_inline()?; c.skip(1)?; }
        (_, 0x13) => { c.skip_inline()?; c.skip(1+1)?; }
        (_, 0x16) => { c.locstring()?; c.locstring()?; c.skip_inline()?; c.skip_inline()?; }
        (_, 0x18) => { c.skip(1)?; c.skip_inline()?; c.skip(1)?; c.skip_inline()?; c.skip_inline()?; c.skip(1+1)?; }
        (_, 0x19) => { c.skip(1+1)?; c.skip_inline()?; c.skip_inline()?; c.skip(1+1)?; }
        (_, 0x1a) => { c.skip_inline()?; }
        (_, 0x1b) => { c.skip_inline()?; c.skip_inline()?; c.skip_inline()?; c.skip(1)?; c.skip_inline()?; c.skip(1+1)?; }
        (_, 0x1c) => { c.locstring()?; c.locstring()?; c.skip_inline()?; c.skip_inline()?; c.skip_inline()?; c.skip_inline()?; }
        (_, 0x1d) => { c.skip(1)?; c.skip_inline()?; c.skip(1+1)?; c.skip_inline()?; c.skip_inline()?; c.skip(1+1+1+1)?; c.skip_inline()?; c.skip_inline()?; c.skip_inline()?; c.skip(1+4+1)?; c.skip_inline()?; }
        (_, 0x1f) => {}
        (_, 0x20) | (RecordFmt::Main4, 0x24) => { c.skip(4)?; }
        (RecordFmt::Main48, 0x24) => { c.skip(4+1+1)?; c.skip_inline()?; c.skip(1)?; c.skip_inline()?; c.skip_inline()?; c.skip_inline()?; c.skip(20)?; }
        (_, 0x22) => { c.locstring()?; c.locstring()?; c.locstring()?; c.skip_inline()?; c.skip(1+1)?; }

        // Format-specific
        (RecordFmt::Pre4, 0x01) => { c.locstring()?; c.skip_inline()?; c.skip_inline()?; c.skip(4+1+4)?; c.skip_inline()?; c.skip(1+1+1+2+4)?; }
        (RecordFmt::Apple, 0x01) => { c.locstring()?; c.skip(2)?; c.string()?; c.skip(4+1+4)?; c.string()?; c.skip(1+1+1)?; c.string()?; c.skip(4)?; }
        (RecordFmt::Main4 | RecordFmt::Main48, 0x01) => { c.locstring()?; c.alt_block()?; c.skip(4+1+4)?; c.string()?; c.skip(1+1+1)?; c.string()?; c.skip(4+1)?; }

        (RecordFmt::Pre4 | RecordFmt::Apple, 0x05) => { c.skip(1)?; c.skip_inline()?; c.skip(1)?; c.skip_inline()?; c.skip_inline()?; c.skip_inline()?; c.skip(1)?; c.skip_inline()?; c.skip(1)?; }
        (RecordFmt::Main4 | RecordFmt::Main48, 0x05) => { c.skip(1)?; c.skip_inline()?; c.skip(1)?; c.skip_inline()?; c.skip_inline()?; c.skip_inline()?; c.skip(1)?; c.skip_inline()?; c.skip(1+1)?; }

        (RecordFmt::Pre4 | RecordFmt::Apple, 0x0f) => { c.skip_inline()?; c.skip(4+4+4)?; }
        (RecordFmt::Main4 | RecordFmt::Main48, 0x0f) => { c.skip_inline()?; c.skip(4+4+4+2)?; }

        (RecordFmt::Pre4 | RecordFmt::Apple, 0x11) => { c.skip_inline()?; c.skip_inline()?; c.skip(2+1+1)?; }
        (RecordFmt::Main4 | RecordFmt::Main48, 0x11) => { c.skip_inline()?; c.skip_inline()?; c.skip(2+1+1+1)?; }

        (RecordFmt::Pre4, 0x15) => { c.skip_inline()?; c.skip_inline()?; c.skip_inline()?; c.skip(4+4+4+4+4+8+8+8+2+2+4+1+4)?; c.skip_inline()?; c.skip(1+1+1)?; c.skip_inline()?; c.skip(4)?; }
        (RecordFmt::Apple, 0x15) => { c.skip_inline()?; c.skip_inline()?; c.skip(4+4+4+4+4+8+8+8+2+2+4+1+4)?; c.skip_inline()?; c.skip(1+1+1)?; c.skip_inline()?; c.skip(4)?; }
        (RecordFmt::Main4 | RecordFmt::Main48, 0x15) => { c.skip_inline()?; c.alt_block()?; c.skip(4+4+4+4+4+8+8+8+2+2+4+1+4)?; c.skip_inline()?; c.skip(1+1+1)?; c.skip_inline()?; c.skip(4+1)?; }

        (RecordFmt::Pre4 | RecordFmt::Apple, 0x17) => { c.skip(1+4+4)?; }
        (RecordFmt::Main4 | RecordFmt::Main48, 0x17) => { c.skip(1+4+4)?; c.skip_inline()?; c.skip(1)?; c.skip_inline()?; }

        (RecordFmt::Pre4 | RecordFmt::Apple, 0x1e) => { c.skip(1)?; c.skip_inline()?; }
        (RecordFmt::Main4 | RecordFmt::Main48, 0x1e) => { c.skip(1)?; c.skip_inline()?; c.skip(1)?; c.skip_inline()?; }

        (RecordFmt::Pre4 | RecordFmt::Apple, 0x23) => { c.skip_inline()?; c.skip_inline()?; c.skip_inline()?; c.skip_inline()?; c.skip_inline()?; c.skip(1)?; c.skip_inline()?; }
        (RecordFmt::Main4 | RecordFmt::Main48, 0x23) => { c.skip(2+2+2)?; c.skip_inline()?; c.skip_inline()?; c.skip(1)?; c.skip_inline()?; }

        (_, 0x25) => { c.skip(2)?; }
        (_, 0x26) => { c.skip_inline()?; c.skip_inline()?; c.skip_inline()?; c.skip_inline()?; }

        _ => return Err(Error::InvalidArchive(format!("unhandled record type 0x{t:x}"))),
    }
    Ok(())
}

/// Strips VISE install-path variables: `%SysDir%\Qt\f.dll` becomes
/// `SysDir/Qt/f.dll`
fn resolve_vise_path(path: &str) -> String {
    let mut result = path.to_string();
    while let Some(start) = result.find('%') {
        if let Some(end) = result[start + 1..].find('%') {
            let var_name = &result[start + 1..start + 1 + end];
            result = format!(
                "{}{}{}",
                &result[..start],
                var_name,
                &result[start + 2 + end..]
            );
        } else {
            break;
        }
    }
    result.replace('\\', "/")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::safe_join;
    use std::path::Path;

    #[test]
    fn detects_each_runtime_from_its_dll() {
        assert_eq!(
            detect_record_fmt(b"..\x00vise32qt.dll\x00.."),
            RecordFmt::Apple
        );
        assert_eq!(detect_record_fmt(b"..\x004.7.0.2\x00.."), RecordFmt::Main4);
        assert_eq!(detect_record_fmt(b"..\x004.9.0.0\x00.."), RecordFmt::Main48);
        assert_eq!(detect_record_fmt(b"no markers here"), RecordFmt::Pre4);
    }

    #[test]
    fn read_checks_range_size_and_qdat() {
        // "stored size" 5 bytes: a raw DEFLATE stream for b"hello", byte-pair swapped
        let mut comp = flate2::Compress::new(flate2::Compression::best(), false);
        let mut blob = vec![0u8; 64];
        comp.compress(b"hello", &mut blob, flate2::FlushCompress::Finish)
            .unwrap();
        blob.truncate(usize::try_from(comp.total_out()).unwrap());
        for pair in blob.chunks_exact_mut(2) {
            pair.swap(0, 1);
        }

        let entry = |offset, compressed_len, uncompressed_len, use_qdat| WinEntry {
            name: "f".into(),
            directory: String::new(),
            offset,
            compressed_len,
            uncompressed_len,
            use_qdat,
        };
        let archive = WinArchive {
            payload: 0..blob.len(),
            data: blob.clone(),
            qdat: None,
            info: WinArchiveInfo {
                version: 0,
                flags: 0,
                entries: Vec::new(),
            },
        };

        assert_eq!(
            archive.read(&entry(0, blob.len(), 5, false)).unwrap(),
            b"hello"
        );
        // size unknown (0) is accepted; a wrong size is an error
        assert_eq!(
            archive.read(&entry(0, blob.len(), 0, false)).unwrap(),
            b"hello"
        );
        assert!(matches!(
            archive.read(&entry(0, blob.len(), 6, false)),
            Err(Error::Decompression(_))
        ));
        assert!(matches!(
            archive.read(&entry(1, blob.len(), 5, false)),
            Err(Error::Decompression(_))
        ));
        assert!(matches!(
            archive.read(&entry(0, blob.len(), 5, true)),
            Err(Error::Skipped(SkipReason::MissingQdat))
        ));
        assert_eq!(archive.read(&entry(0, 0, 0, false)).unwrap(), b"");
    }

    #[test]
    fn rejects_non_vise() {
        assert!(WinArchive::parse(vec![0; 64], None, 0).is_err());
    }

    #[test]
    fn resolve_strips_vars_and_normalizes() {
        assert_eq!(
            super::resolve_vise_path("%SysDir%\\Example\\file.dll"),
            "SysDir/Example/file.dll"
        );
        assert_eq!(
            super::resolve_vise_path("%TargetDir%\\app.exe"),
            "TargetDir/app.exe"
        );
    }

    #[test]
    fn resolve_traversal_blocked_by_safe_join() {
        let malicious = super::resolve_vise_path("%..%\\..\\..\\etc\\passwd");
        let cleaned = crate::clean_name(&malicious);
        assert_eq!(
            safe_join(Path::new("/out"), &cleaned),
            Some("/out/etc/passwd".into())
        );
        assert_eq!(safe_join(Path::new("/out"), "../escape"), None);
    }

    #[test]
    fn scan_skips_oversized_count() {
        let mut buf = vec![0u8; 0x60000];
        buf[..4].copy_from_slice(b"SIVM");
        buf[8..12].copy_from_slice(b"ESIV");
        buf[0x10..0x14].copy_from_slice(&1u32.to_le_bytes());
        let stream_off = 0x40000;
        buf[stream_off..stream_off + 4].copy_from_slice(&(MAX_RECORD_COUNT + 1).to_le_bytes());
        buf[stream_off + 4..stream_off + 8].copy_from_slice(&5u32.to_le_bytes());
        let result = WinArchive::parse(buf, None, 0);
        assert!(result.is_err());
    }
}

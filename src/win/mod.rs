//! Windows VISE archive parser and extractor
//!
//! The payload sits in one of two places: in a PE `_mvdata` section, under
//! an SIVM header with a trailer offset and session ID, or appended after
//! the executable, 32-bit or 16-bit, under a bare ESIV header. Its header
//! ends with a count of embedded files, which follow: the VISE runtime
//! and what it needs, such as language files. The typed record stream
//! comes after
//!
//! The layout of the records and of what precedes them changed from one
//! Installer VISE release to the next, and the installer does not say which
//! release built it. The layouts in `layouts` are tried in turn, and the one
//! whose sections lead to a record stream that then reads to its end is
//! used. See `LayoutId`
//!
//! Between the embedded files and the record stream lie several sections
//! (language table, installer settings, variables, download servers, support
//! files, packages). They are read through to find where the stream starts;
//! see `sections::skip_to_record_stream`
//!
//! Compression is byte-pair swap + raw DEFLATE (no substitution cipher,
//! unlike the Mac format). Stub installers store the record stream in the
//! `.exe` and file data in a companion `.qdat` volume matched by session ID

use std::borrow::Cow;
use std::collections::VecDeque;
use std::fs;
use std::ops::Range;
use std::path::Path;
use std::time::SystemTime;

use encoding_rs::Encoding;

mod cursor;
mod grammar;
mod layouts;
mod records;
mod sections;

use cursor::Cursor;
use grammar::{Op, Text};
use layouts::{LAYOUTS, LayoutId};
use records::{StreamReading, parse_qdat_entries, parse_record_stream};
use sections::{exact_stream_start, find_first_entry, find_record_stream, walk_named_chain};
// what only the layout trace reaches for
#[cfg(feature = "fuzzing")]
use {records::skip_type, sections::skip_to_record_stream};

use crate::text::{decode_windows, windows_code_page};
use crate::{
    BATCH_BYTES, BATCH_ENTRIES, Error, ExtractResult, OUTPUT_BUDGET_HEADROOM, OUTPUT_BUDGET_RATIO,
    Progress, SkipReason, UsedPaths, clean_name, parallel_map, safe_join, write_file,
};

/// SIVM payloads store blob offsets relative to payload byte 8 (after the
/// SIVM magic and trailer-offset fields)
const SIVM_BLOB_OFFSET: usize = 8;

const MAX_RECORD_COUNT: u32 = 100_000;
/// Longest string a record may hold. Paths stay under 260, but message boxes
/// carry whole paragraphs. The limit is there so a wrong layout fails quickly
/// instead of skipping far ahead
const MAX_STRING_LEN: u16 = 4096;
/// Most features or conditions a record may list. Real counts are a few
/// dozen at most
const MAX_ARRAY_COUNT: u16 = 1000;
/// Record IDs are counters. Most installers stay in the hundreds or thousands,
/// and some pass 200,000
const MAX_RECORD_ID: u32 = 0x0100_0000;
/// Farthest the next record is looked for past the start of a record body
/// that did not read. Bodies hold at most a few screens of text
const MAX_RECORD_BODY: usize = 1 << 18;
/// Deepest folder nesting followed when building an install path
const MAX_FOLDER_DEPTH: usize = 64;
/// Record-stream start positions tried per record layout
const MAX_STREAM_CANDIDATES: usize = 16;

/// Archive-header flags value for stub installers (exe+qdat split).
/// Distinct from Mac-side `FileEntry::is_stub` which is a per-entry bitmask
const STUB_FLAG: u32 = 0x0002_0000;
const QDAT_MAGIC: &[u8; 8] = b"ESIVRDLB";
/// Per-file entries in a qdat start at this fixed offset (16-byte header
/// + 4-byte count + 782 bytes of metadata)
const QDAT_ENTRIES_OFFSET: usize = 802;
const QDAT_ENTRY_HEADER: usize = 16;
/// How much larger than its recorded size a file may turn out to be when
/// its checksum confirms it
const STALE_SIZE_FACTOR: usize = 2;
const STALE_SIZE_HEADROOM: usize = 64 << 10;
/// How far past a doubtful record header a better one is looked for
const PARENT_LOOKAHEAD: usize = 4096;
/// Value of the source byte in a file record's tail when the file comes from
/// a download item, whose GUID then follows
const SOURCE_DOWNLOAD_ITEM: u8 = 4;
/// The embedded file a web installer downloads its files with
const DOWNLOAD_LIBRARY: &str = "tcpip32.dll";
/// Each part of a multi-part installer starts with `ESIV`, the session ID,
/// the part number and the length of the part's data
const VOLUME_HEADER: usize = 16;
/// More parts than any installer would be split into; a volume number
/// above this is not one
const MAX_VOLUMES: u32 = 999;
/// A file that spans parts is gathered into one buffer, which starts no
/// larger than this whatever size the record claims
const MAX_SPANNED_PREALLOC: usize = 1 << 24;

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
    /// The later parts of a multi-part installer, part 2 first
    volumes: Vec<Vec<u8>>,
    /// The highest part number any entry names
    last_volume: u32,
    pub info: WinArchiveInfo,
}

#[derive(Debug)]
#[non_exhaustive]
pub struct WinArchiveInfo {
    pub version: u32,
    pub flags: u32,
    /// The installer embeds the library it downloads files with. Such an
    /// installer may carry only some of the files it lists, or none
    pub web: bool,
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
    /// Last-write time recorded in the file table, if there is one
    pub modified: Option<SystemTime>,
    /// CRC-32 of the file's contents, or 0 when the table does not give one
    pub crc32: u32,
    /// Where the stored data is
    pub location: Location,
    /// The recorded position cannot be this file's data in the executable:
    /// it lies in front of the file data, runs past the end, or is shared
    /// with another file
    misplaced: bool,
}

/// Where an entry's stored data is
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Location {
    /// In the installer executable
    Installer,
    /// In a later part of a multi-part installer; parts count from 1, so
    /// this is 2 or more
    Part(u32),
    /// In the companion `.qdat` volume of a stub installer
    Qdat,
    /// In a download item of a web installer, which fetches it when it runs
    Download,
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

    /// The most bytes this entry can decode to: the size the file table
    /// records, or DEFLATE's maximum expansion when it records none
    fn decoded_bound(&self) -> usize {
        if self.uncompressed_len == 0 {
            self.compressed_len.saturating_mul(OUTPUT_BUDGET_RATIO)
        } else if self.crc32 == 0 {
            self.uncompressed_len
        } else {
            // a recorded size can be out of date when the checksum is not;
            // the file is then allowed to be somewhat larger
            self.uncompressed_len
                .saturating_mul(STALE_SIZE_FACTOR)
                .saturating_add(STALE_SIZE_HEADROOM)
        }
    }
}

impl WinArchive {
    /// Parses an installer executable, 32-bit (PE) or 16-bit (NE), locating
    /// the VISE payload inside it. `qdat` is the companion volume of a stub
    /// installer, if there is one
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArchive`] if the file is not an executable
    /// carrying a VISE payload, or the record stream cannot be parsed
    pub fn from_pe(file: Vec<u8>, qdat: Option<Vec<u8>>) -> Result<Self, Error> {
        let (payload, start) = crate::pe::extract_payload(&file)?;
        let range = start..start + payload.len();
        let info = parse_payload(payload, qdat.as_deref(), start)?;
        Ok(Self::assemble(file, range, qdat, info))
    }

    /// Puts an archive together from its parsed table
    fn assemble(
        data: Vec<u8>,
        payload: Range<usize>,
        qdat: Option<Vec<u8>>,
        info: WinArchiveInfo,
    ) -> Self {
        let parts = info.entries.iter().filter_map(|e| match e.location {
            Location::Part(number) => Some(number),
            _ => None,
        });
        Self {
            last_volume: parts.max().unwrap_or(1),
            data,
            payload,
            qdat,
            volumes: Vec::new(),
            info,
        }
    }

    /// Parses a payload already cut out of its executable.
    /// `payload_file_offset` is the byte position of the payload within the
    /// PE file, which the blob offsets of the older layouts count from
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
        let payload = 0..data.len();
        Ok(Self::assemble(data, payload, qdat, info))
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

    /// The part number of a file that is one of the later parts of a
    /// multi-part installer (`Setup.002` and so on), given the session ID
    /// of the installer it should belong to. Only the first 16 bytes of the
    /// file are looked at
    #[must_use]
    pub fn volume_number(volume: &[u8], session: u32) -> Option<u32> {
        let field = |at: usize| {
            let bytes = volume.get(at..at + 4)?.try_into().ok()?;
            Some(u32::from_le_bytes(bytes))
        };
        let number = field(8)?;
        (volume.get(..4) == Some(b"ESIV") && field(4)? == session && number >= 2).then_some(number)
    }

    /// This installer's session ID, which each of its other files carries
    #[must_use]
    pub fn session(&self) -> Option<u32> {
        Self::session_id(self.payload())
    }

    /// The highest part number any entry names. Above 1, the installer
    /// has further parts, which [`WinArchive::set_volumes`] takes
    #[must_use]
    pub const fn last_volume(&self) -> u32 {
        self.last_volume
    }

    /// Supplies the later parts of a multi-part installer, in any order.
    /// They are given after parsing, unlike a `.qdat`, because the file
    /// table is what says whether there are any: see
    /// [`WinArchive::last_volume`].
    ///
    /// Parts are used as an unbroken run from part 2 upward: one that does
    /// not belong to this installer, repeats a number or follows a gap is
    /// left out. Returns how many are in use
    pub fn set_volumes(&mut self, volumes: Vec<Vec<u8>>) -> usize {
        self.volumes.clear();
        let Some(session) = self.session() else {
            return 0;
        };
        let mut numbered: Vec<(u32, Vec<u8>)> = volumes
            .into_iter()
            .filter_map(|v| Some((Self::volume_number(&v, session)?, v)))
            .collect();
        numbered.sort_by_key(|&(number, _)| number);
        let mut next = 2;
        for (number, volume) in numbered {
            if number == next {
                self.volumes.push(volume);
                next += 1;
            }
        }
        self.volumes.len()
    }

    /// The bytes of part `number`, up to the end of the data it holds
    fn volume(&self, number: u32) -> Option<&[u8]> {
        let whole = match number {
            0 | 1 => self.payload(),
            n => self.volumes.get(usize::try_from(n - 2).ok()?)?,
        };
        // Every part starts with a header that gives the length of the
        // part's data; an installer executable has a short trailer after it
        let declared = whole
            .get(12..16)
            .map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]) as usize);
        Some(match declared {
            Some(len) if (VOLUME_HEADER..=whole.len()).contains(&len) => &whole[..len],
            _ => whole,
        })
    }

    /// The stored bytes of an entry that is not in a `.qdat`. A file that
    /// does not fit in what is left of its part carries on in the next
    /// one, straight after that part's header
    fn stored(&self, entry: &WinEntry) -> Result<Cow<'_, [u8]>, Error> {
        let not_loaded = |number: u32| {
            Error::Skipped(SkipReason::SegmentNotLoaded(
                u16::try_from(number).unwrap_or(u16::MAX),
            ))
        };
        let first = match entry.location {
            Location::Part(number) => number,
            _ => 1,
        };
        let whole = match first {
            1 => self.payload(),
            n => usize::try_from(n - 2)
                .ok()
                .and_then(|i| self.volumes.get(i))
                .ok_or_else(|| not_loaded(n))?,
        };
        let end = entry.offset.checked_add(entry.compressed_len);
        if let Some(blob) = end.and_then(|end| whole.get(entry.offset..end)) {
            return Ok(Cow::Borrowed(blob));
        }
        // Data past the end of the last part there is: the installer was
        // split across disks, or the copy is cut short
        if self.last_volume() <= 1 && self.volumes.is_empty() {
            return Err(Error::Skipped(SkipReason::MissingData));
        }
        let mut blob = Vec::with_capacity(entry.compressed_len.min(MAX_SPANNED_PREALLOC));
        let (mut number, mut offset) = (first, entry.offset);
        while blob.len() < entry.compressed_len {
            let part = self.volume(number).ok_or_else(|| not_loaded(number))?;
            let rest = part
                .get(offset..)
                .filter(|rest| !rest.is_empty())
                .ok_or(Error::Skipped(SkipReason::MissingData))?;
            let take = rest.len().min(entry.compressed_len - blob.len());
            blob.extend_from_slice(&rest[..take]);
            number = number.saturating_add(1);
            offset = VOLUME_HEADER;
        }
        Ok(Cow::Owned(blob))
    }

    /// Decompresses one entry into memory
    ///
    /// # Errors
    ///
    /// Returns [`Error::Skipped`] if the entry's data is in a companion
    /// `.qdat` volume that was not supplied, in a part of a multi-part
    /// installer that was not supplied, past the end of the file, or not stored at all,
    /// [`Error::Decompression`] if the data is out of range, does not decode,
    /// or does not match the size recorded in the file table, or
    /// [`Error::Checksum`] if it does not match the recorded CRC-32
    pub fn read(&self, entry: &WinEntry) -> Result<Vec<u8>, Error> {
        if entry.location == Location::Download {
            return Err(Error::Skipped(SkipReason::Downloaded));
        }
        if entry.compressed_len == 0 {
            // A size with no stored bytes behind it: the record installs a
            // copy of a file the installer gets from elsewhere, typically
            // one it has just installed under another folder
            if entry.uncompressed_len > 0 {
                return Err(Error::Skipped(SkipReason::MissingData));
            }
            return Ok(Vec::new());
        }
        let read = self.read_stored(entry);
        // A web installer lists every file it installs and carries only
        // some of them, and not every file it downloads is marked. One
        // whose recorded position cannot hold its data in the executable,
        // and which does not read there, is taken to be downloaded. A file
        // that sits where a file should and does not read is damaged
        let absent = matches!(
            read,
            Err(Error::Decompression(_)
                | Error::Checksum { .. }
                | Error::Skipped(SkipReason::MissingData))
        );
        if absent && self.info.web && entry.misplaced {
            return Err(Error::Skipped(SkipReason::Downloaded));
        }
        read
    }

    fn read_stored(&self, entry: &WinEntry) -> Result<Vec<u8>, Error> {
        let blob = if entry.location == Location::Qdat {
            let qdat = self
                .qdat
                .as_deref()
                .ok_or(Error::Skipped(SkipReason::MissingQdat))?;
            let end = entry.offset.checked_add(entry.compressed_len);
            Cow::Borrowed(
                end.and_then(|end| qdat.get(entry.offset..end))
                    .ok_or(Error::Skipped(SkipReason::MissingData))?,
            )
        } else {
            self.stored(entry)?
        };
        let blob = &*blob;
        let checksum = |out: &[u8]| {
            let mut crc = flate2::Crc::new();
            crc.update(out);
            crc.sum()
        };
        // the decoder stops as soon as the output passes the recorded size,
        // so a wrong size is an error here and never a larger buffer
        if let Some(out) = crate::deflate::swap_and_inflate(blob, entry.uncompressed_len) {
            let actual = checksum(&out);
            if entry.crc32 != 0 && actual != entry.crc32 {
                return Err(Error::Checksum {
                    expected: entry.crc32,
                    actual,
                });
            }
            return Ok(out);
        }
        // Some installers record a size that is not the size of the file
        // they store, next to a checksum that is right for it. The data is
        // decoded again without the size, and taken only if the checksum
        // matches
        if entry.uncompressed_len != 0 && entry.crc32 != 0 {
            let limit = entry.decoded_bound();
            let whole =
                crate::deflate::swap_and_inflate_within(blob, entry.uncompressed_len, limit);
            if let Some(out) = whole.filter(|out| checksum(out) == entry.crc32) {
                return Ok(out);
            }
        }
        Err(Error::Decompression(if entry.uncompressed_len == 0 {
            "invalid compressed data".into()
        } else {
            format!(
                "data is invalid or does not decode to the {} bytes the file table records",
                entry.uncompressed_len
            )
        }))
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
            .saturating_add(self.volumes.iter().map(Vec::len).sum())
            .saturating_mul(OUTPUT_BUDGET_RATIO)
            .saturating_add(OUTPUT_BUDGET_HEADROOM);
        let mut total_out: usize = 0;
        let mut result = ExtractResult::default();
        let mut used = UsedPaths::default();

        let entries = &self.info.entries;
        let mut next_entry = 0;
        let mut decoded: VecDeque<Result<Vec<u8>, Error>> = VecDeque::new();

        for entry in entries {
            // entries are decoded a batch at a time, on several threads, and
            // handed back here in table order
            if decoded.is_empty() {
                let start = next_entry;
                let mut cost = 0usize;
                while next_entry < entries.len()
                    && (next_entry == start
                        || (cost < BATCH_BYTES && next_entry - start < BATCH_ENTRIES))
                {
                    cost = cost.saturating_add(entries[next_entry].decoded_bound());
                    next_entry += 1;
                }
                decoded =
                    parallel_map(next_entry - start, |i| self.read(&entries[start + i])).into();
            }
            // a batch always holds at least the next entry
            let Some(bytes) = decoded.pop_front() else {
                break;
            };

            let name = clean_name(&entry.path());
            if name.is_empty() {
                on_progress(Progress::Skipped {
                    name: &name,
                    reason: SkipReason::EmptyName,
                });
                result.skipped += 1;
                continue;
            }
            if safe_join(out_dir, &name).is_none() {
                on_progress(Progress::Skipped {
                    name: &name,
                    reason: SkipReason::UnsafePath,
                });
                result.skipped += 1;
                continue;
            }

            let written = bytes.and_then(|bytes| {
                // two entries can map to one path; the later one is renamed
                // so it does not replace the earlier
                let name = used.claim(name.clone(), crate::Companion::None);
                let path =
                    safe_join(out_dir, &name).ok_or(Error::Skipped(SkipReason::UnsafePath))?;
                if let Some(parent) = path.parent() {
                    fs::create_dir_all(parent)?;
                }
                write_file(&path, &bytes, entry.modified)?;
                Ok((name, bytes))
            });
            match written {
                Ok((name, bytes)) => {
                    let name = &name;
                    on_progress(Progress::Extracted {
                        name,
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

/// Which header the payload has, and the two fields after its session ID
fn payload_header(data: &[u8]) -> Result<(PayloadKind, u32, u32), Error> {
    let field = |at: usize| {
        data.get(at..at + 4)
            .map(|b| u32::from_le_bytes(b.try_into().unwrap()))
            .ok_or_else(|| Error::InvalidArchive("payload too small".into()))
    };
    if data.starts_with(b"SIVM") && data.get(8..12) == Some(b"ESIV") {
        Ok((PayloadKind::Sivm, field(0x10)?, field(0x14)?))
    } else if data.starts_with(b"ESIV") {
        Ok((PayloadKind::Esiv, field(0x08)?, field(0x0C)?))
    } else if data.len() < 16 {
        Err(Error::InvalidArchive("payload too small".into()))
    } else {
        Err(Error::InvalidArchive("not a Windows VISE payload".into()))
    }
}

fn parse_payload(
    data: &[u8],
    qdat: Option<&[u8]>,
    payload_file_offset: usize,
) -> Result<WinArchiveInfo, Error> {
    let (kind, version, flags) = payload_header(data)?;

    let (first_entry, count) = find_first_entry(data)?;
    let mut entries = Vec::new();
    let chain_end = walk_named_chain(data, first_entry, count, &mut entries);
    let qdat_entries = qdat.map(parse_qdat_entries).transpose()?;

    let web = entries
        .iter()
        .any(|file| file.name.eq_ignore_ascii_case(DOWNLOAD_LIBRARY));
    let info = |entries| WinArchiveInfo {
        version,
        flags,
        web,
        entries,
    };

    let reading = Reading {
        data,
        qdat_len: qdat.map(<[u8]>::len),
        qdat_entries: qdat_entries.as_deref(),
        kind,
        flags,
        chain_end,
        payload_file_offset,
        embedded: &entries,
    };
    let mut best: Option<(Score, Vec<WinEntry>)> = None;
    let mut keep = |found: Found, exact: bool| {
        // most files placed, then a stream that was not searched for and
        // read to its end, then fewest records that needed realigning: a
        // layout that is slightly off reads the fields of a file record
        // from the wrong place. Last, fewest files that start inside the
        // stream, which is what reading its last record too far looks like
        let trusted = found.complete && exact;
        let score = (
            found.placed,
            trusted,
            usize::MAX - found.realigned,
            usize::MAX - found.overrun,
        );
        if best.as_ref().is_none_or(|(top, _)| score > *top) {
            best = Some((score, found.entries));
        }
    };
    let mut last_err = None;

    // A layout whose sections lead to a record stream, every record of
    // which then reads, is the installer's own, and is taken at once
    let mut unread = Vec::new();
    for layout in LAYOUTS {
        let Some(start) = exact_stream_start(data, chain_end, layout) else {
            unread.push(layout);
            continue;
        };
        match reading.read(layout, start) {
            Ok(found) if found.fits() => {
                debug_assert!(reading.others_agree(layout, &found, chain_end));
                return Ok(info(found.entries));
            }
            Ok(found) => keep(found, true),
            Err(e) => last_err = Some(e),
        }
    }
    // With the layouts whose sections do not lead to one, a stream is
    // searched for. A wrong layout or a wrong position can still read
    // without an error, so such a stream also has to place every file
    for layout in unread {
        let mut from = chain_end;
        for _ in 0..MAX_STREAM_CANDIDATES {
            let Ok(start) = find_record_stream(data, from, chain_end, layout) else {
                break;
            };
            from = start + 1;
            match reading.read(layout, start) {
                Ok(found) if found.fits() && found.files > 0 && found.placed == found.files => {
                    return Ok(info(found.entries));
                }
                Ok(found) => keep(found, false),
                Err(e) => last_err = Some(e),
            }
        }
    }

    // Failing both, the candidate that did best is used. One that placed no
    // file is accepted only if its stream was located by its sections and
    // read to the end. Anything less is not a reading of the stream at all,
    // and returning it would report an installer as holding only its
    // embedded files
    if let Some(((placed, trusted, ..), entries)) = best {
        if trusted || placed > 0 {
            return Ok(info(entries));
        }
    }
    Err(last_err.unwrap_or_else(|| Error::InvalidArchive("record stream not found".into())))
}

/// How well a reading did, for comparing readings: see where it is made
type Score = (usize, bool, usize, usize);

/// What reading a record stream under one layout needs besides the layout
/// and the position
struct Reading<'a> {
    data: &'a [u8],
    qdat_len: Option<usize>,
    qdat_entries: Option<&'a [(usize, usize)]>,
    kind: PayloadKind,
    flags: u32,
    /// Where the embedded files end
    chain_end: usize,
    payload_file_offset: usize,
    /// The embedded files, which every reading starts with, their names
    /// one character to the byte
    embedded: &'a [WinEntry],
}

/// What a record stream read as under one layout
struct Found {
    /// The embedded files, then the files of the stream
    entries: Vec<WinEntry>,
    files: usize,
    /// How many of the files have data where their record says
    placed: usize,
    complete: bool,
    realigned: usize,
    /// How many of the files start before the stream ends
    overrun: usize,
}

impl Found {
    /// Whether every record the stream declares read, one after the other,
    /// and the stream ended before the files. Nothing follows the last
    /// record to show that it was read right, except that the file data
    /// has to start after it
    fn fits(&self) -> bool {
        self.complete && self.realigned == 0 && self.overrun == 0
    }
}

impl Reading<'_> {
    /// Reads the record stream at `start` under `layout`
    fn read(&self, layout: LayoutId, start: usize) -> Result<Found, Error> {
        // SIVM blob offsets count from past the magic and trailer-offset
        // fields, eight bytes into the payload. ESIV ones count from the
        // start of the payload or from the start of the executable; which
        // is settled below by trying a file
        let blob_base = match self.kind {
            PayloadKind::Sivm => SIVM_BLOB_OFFSET,
            PayloadKind::Esiv => 0,
        };
        // where the language table is depends on the layout, and with it
        // the code page of every name
        let text = main_code_page(self.data, self.chain_end, layout);
        let mut entries = self.embedded.to_vec();
        for file in &mut entries {
            if let Some(name) = sections::chain_name_bytes(&file.name) {
                file.name = decode_windows(&name, text);
            }
        }
        let read = parse_record_stream(
            self.data,
            start,
            &StreamReading {
                layout,
                blob_base,
                flags: self.flags,
                text,
                qdat_entries: self.qdat_entries,
            },
            &mut entries,
        )?;
        let files = &mut entries[self.embedded.len()..];
        if self.kind == PayloadKind::Esiv
            && offsets_count_from_file_start(self.data, files, self.payload_file_offset, layout)
        {
            rebase_onto_payload(files, self.payload_file_offset);
        }
        mark_misplaced(files, read.end, self.data.len());
        let overrun = files
            .iter()
            .filter(|f| f.location == Location::Installer && f.compressed_len > 0)
            .filter(|f| f.offset < read.end)
            .count();
        Ok(Found {
            overrun,
            files: files.len(),
            placed: count_placed(files, self.data.len(), self.qdat_len),
            entries,
            complete: read.complete,
            realigned: read.realigned,
        })
    }

    /// Whether every other layout that reads the installer as `layout` does
    /// finds the same files in it. Taking the first layout that fits rests
    /// on this
    fn others_agree(&self, layout: LayoutId, found: &Found, chain_end: usize) -> bool {
        let listing = |found: &Found| format!("{:?}", found.entries);
        let expected = listing(found);
        LAYOUTS
            .into_iter()
            .filter(|&other| other != layout)
            .all(|other| {
                exact_stream_start(self.data, chain_end, other)
                    .and_then(|start| self.read(other, start).ok())
                    .is_none_or(|theirs| !theirs.fits() || listing(&theirs) == expected)
            })
    }
}

/// Whether the entry's data decodes at `offset` to the size and CRC its
/// record gives
fn decodes_at(data: &[u8], entry: &WinEntry, offset: usize) -> bool {
    let Some(blob) = offset
        .checked_add(entry.compressed_len)
        .and_then(|end| data.get(offset..end))
    else {
        return false;
    };
    crate::deflate::swap_and_inflate(blob, entry.uncompressed_len).is_some_and(|out| {
        let mut crc = flate2::Crc::new();
        crc.update(&out);
        entry.crc32 == 0 || crc.sum() == entry.crc32
    })
}

/// Files tried when settling where blob offsets count from
const OFFSET_BASE_TRIES: usize = 3;

/// Whether the blob offsets in `files` count from the start of the
/// executable instead of the start of the payload. The older runtimes do
/// that, and the point where it changed is not known, so it is decided by
/// decoding: the smallest few files are tried at both positions, and the
/// first one that decodes at exactly one of them settles it. If none does,
/// it goes by the layout: one whose file records have a one-byte length on
/// the string after the times is taken to count from the executable
fn offsets_count_from_file_start(
    data: &[u8],
    files: &[WinEntry],
    payload_file_offset: usize,
    layout: LayoutId,
) -> bool {
    if payload_file_offset == 0 {
        return false;
    }
    let mut candidates: Vec<&WinEntry> = files
        .iter()
        .filter(|f| {
            f.location == Location::Installer && f.compressed_len > 0 && f.uncompressed_len > 0
        })
        .collect();
    candidates.sort_by_key(|f| f.compressed_len);
    for file in candidates.into_iter().take(OFFSET_BASE_TRIES) {
        let from_payload = decodes_at(data, file, file.offset);
        let from_file = file
            .offset
            .checked_sub(payload_file_offset)
            .is_some_and(|offset| decodes_at(data, file, offset));
        if from_payload != from_file {
            return from_file;
        }
    }
    layout.table().file.after_times == Text::Short
}

/// How many of `files` have a name and their data inside the source they
/// read from: the payload, or the companion volume of `qdat_len` bytes. A
/// stub read without its volume has nothing to check those offsets against,
/// so they count as placed
fn count_placed(files: &[WinEntry], payload_len: usize, qdat_len: Option<usize>) -> usize {
    files
        .iter()
        .filter(|e| {
            // the other parts of a multi-part installer are not at hand here
            let source_len = match e.location {
                Location::Installer => payload_len,
                Location::Qdat => qdat_len.unwrap_or(usize::MAX),
                Location::Part(number) if number > MAX_VOLUMES => 0,
                Location::Part(_) | Location::Download => usize::MAX,
            };
            // a run of zero bytes reads as a file record with no name
            !e.name.is_empty()
                && e.offset
                    .checked_add(e.compressed_len)
                    .is_some_and(|end| end <= source_len)
        })
        .count()
}

/// Names are stored in the ANSI code page of the installer's main language,
/// whose ID the language table starts with. The table follows the two flag
/// bytes after the embedded files, and in the layouts that have one, the
/// block the second flag byte brings in
fn main_code_page(data: &[u8], chain_end: usize, layout: LayoutId) -> &'static Encoding {
    let table = match layout.table().start {
        start @ [Op::Skip(1), Op::When(..), ..] => {
            let mut c = Cursor::new(data, chain_end, layout);
            grammar::step(&mut c, &start[..2], grammar::Limit::Any)
                .ok()
                .map(|()| c.pos)
        }
        _ => chain_end.checked_add(2),
    };
    let language = table
        .and_then(|at| data.get(at..at.checked_add(2)?))
        .map_or(0, |id| u16::from_le_bytes([id[0], id[1]]));
    windows_code_page(language)
}

/// Marks the files whose recorded position cannot be their data in the
/// executable: it lies before `data_start`, where the record stream ends,
/// runs past the end of the payload, or overlaps another file's
fn mark_misplaced(files: &mut [WinEntry], data_start: usize, payload_len: usize) {
    let end = |f: &WinEntry| f.offset.saturating_add(f.compressed_len);
    let mut order: Vec<usize> = (0..files.len())
        .filter(|&i| files[i].location == Location::Installer && files[i].compressed_len > 0)
        .collect();
    order.sort_by_key(|&i| files[i].offset);
    // overlap with a file that starts earlier, then with one that starts later
    let mut reach = 0;
    for &i in &order {
        let file = &mut files[i];
        file.misplaced = file.offset < data_start || end(file) > payload_len || file.offset < reach;
        reach = reach.max(end(file));
    }
    let mut next_start = usize::MAX;
    for &i in order.iter().rev() {
        let file = &mut files[i];
        file.misplaced |= end(file) > next_start;
        next_start = next_start.min(file.offset);
    }
}

/// Turns offsets counted from the start of the executable into offsets
/// into its payload. Only the executable has anything in front of its data,
/// so files in a `.qdat` or a later part are left alone
fn rebase_onto_payload(files: &mut [WinEntry], payload_file_offset: usize) {
    for file in files
        .iter_mut()
        .filter(|f| f.location == Location::Installer)
    {
        file.offset = file.offset.saturating_sub(payload_file_offset);
    }
}

/// Describes how each record layout fares on a payload: where the stream
/// was found, how many records were read, the types of the last few, and
/// the error that stopped it. For looking into an installer that does not
/// read; not part of the extractor
#[cfg(feature = "fuzzing")]
pub(crate) fn trace_layouts(data: &[u8]) -> Vec<String> {
    let mut lines = Vec::new();
    let Ok(chain_end) = sections::embedded_files_end(data) else {
        return vec!["payload header is cut short".into()];
    };
    lines.push(format!("chain_end={chain_end:#x}"));
    for layout in LAYOUTS {
        let walked = skip_to_record_stream(data, chain_end, layout);
        let found = exact_stream_start(data, chain_end, layout)
            .or_else(|| find_record_stream(data, chain_end, chain_end, layout).ok());
        let Some(start) = found else {
            lines.push(format!("{layout:?}: sections {walked:x?}; no stream found"));
            continue;
        };
        let mut c = Cursor::new(data, start, layout);
        let count = c.u32().unwrap_or(0);
        let mut seen: Vec<(usize, u32)> = Vec::new();
        let mut error = None;
        for _ in 0..count.min(MAX_RECORD_COUNT) {
            let at = c.pos;
            let step = (|| {
                let rtype = c.u32()?;
                seen.push((at, rtype));
                if layout.is_bare(rtype) {
                    return Ok(());
                }
                grammar::record_header(&mut c)?;
                skip_type(&mut c, rtype)
            })();
            if let Err(e) = step {
                error = Some(Error::from(e).to_string());
                break;
            }
        }
        let tail: Vec<String> = seen
            .iter()
            .rev()
            .take(4)
            .rev()
            .map(|(at, t)| format!("{t:#x}@{at:#x}"))
            .collect();
        // the same stream as the extractor reads it, which steps over
        // record bodies it does not understand
        let mut files = Vec::new();
        let read = parse_record_stream(data, start, &StreamReading::plain(layout), &mut files);
        lines.push(format!(
            "{layout:?}: as read: {} files, {:?}",
            files.len(),
            read.map_err(|e| e.to_string())
        ));
        lines.push(format!(
            "{layout:?}: sections {walked:x?}; stream {start:#x}; {}/{count} records; last {}; {}",
            seen.len() - usize::from(error.is_some()),
            tail.join(" "),
            error.unwrap_or_else(|| "complete".into())
        ));
    }
    lines
}

/// Where the sections in front of the record stream end under the layout
/// named `name`, and whether a record stream starts there
#[cfg(feature = "fuzzing")]
pub(crate) fn stream_start(data: &[u8], name: &str) -> Result<(usize, bool), Error> {
    let layout = *LAYOUTS
        .iter()
        .find(|layout| format!("{layout:?}") == name)
        .ok_or_else(|| Error::InvalidArchive("no such layout".into()))?;
    let chain_end = sections::embedded_files_end(data)?;
    let end = skip_to_record_stream(data, chain_end, layout)?;
    Ok((end, sections::starts_record_stream(data, end, layout)))
}

/// Reads the record stream at `start` under the layout named `layout`,
/// with no searching: where each record starts, its type, and the error
/// that stopped the read if one did. For checking a layout against a
/// reference
#[cfg(feature = "fuzzing")]
pub(crate) fn record_spans(
    data: &[u8],
    start: usize,
    name: &str,
) -> (Vec<(usize, u32)>, usize, Option<String>) {
    let Some(&layout) = LAYOUTS.iter().find(|f| format!("{f:?}") == name) else {
        return (Vec::new(), start, Some("no such layout".into()));
    };
    let mut c = Cursor::new(data, start, layout);
    let mut spans = Vec::new();
    let Ok(count) = c.u32() else {
        return (spans, start, Some("no record count".into()));
    };
    for _ in 0..count.min(MAX_RECORD_COUNT) {
        let at = c.pos;
        let step = (|| {
            let rtype = c.u32()?;
            spans.push((at, rtype));
            if layout.is_bare(rtype) {
                return Ok(());
            }
            grammar::record_header(&mut c)?;
            skip_type(&mut c, rtype)
        })();
        if let Err(e) = step {
            return (spans, c.pos, Some(Error::from(e).to_string()));
        }
    }
    (spans, c.pos, None)
}

/// Entries read per fuzz input, so one input cannot spend its whole run
/// decompressing the same bytes
#[cfg(feature = "fuzzing")]
const FUZZ_READ_LIMIT: usize = 64;

/// Parses `data` as a record stream directly, without the header and runtime
/// DLL that a whole payload needs first, then reads the entries it found. The
/// first byte selects stub mode (bit 0), the SIVM offset base (bit 1),
/// whether to treat the input as its own `.qdat` volume (bit 2) and, in its
/// upper five bits, the record layout; the rest is the stream
#[cfg(feature = "fuzzing")]
pub(crate) fn fuzz_records(data: &[u8]) {
    let Some((&selector, stream)) = data.split_first() else {
        return;
    };
    let layout = LAYOUTS[usize::from(selector >> 3) % LAYOUTS.len()];
    let flags = if selector & 1 == 0 { 0 } else { STUB_FLAG };
    let blob_add = if selector & 2 == 0 {
        0
    } else {
        SIVM_BLOB_OFFSET
    };
    let qdat = (selector & 4 != 0).then(|| stream.to_vec());
    let qdat_entries = qdat.as_deref().and_then(|q| parse_qdat_entries(q).ok());

    let mut entries = Vec::new();
    let _ = parse_record_stream(
        stream,
        0,
        &StreamReading {
            layout,
            blob_base: blob_add,
            flags,
            text: encoding_rs::WINDOWS_1252,
            qdat_entries: qdat_entries.as_deref(),
        },
        &mut entries,
    );

    let info = WinArchiveInfo {
        version: 0,
        flags,
        web: false,
        entries,
    };
    let archive = WinArchive::assemble(stream.to_vec(), 0..stream.len(), qdat, info);
    for entry in archive.info.entries.iter().take(FUZZ_READ_LIMIT) {
        let _ = archive.read(entry);
    }
}

#[cfg(test)]
mod testutil;

#[cfg(test)]
mod tests;

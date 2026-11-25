//! Extractor for Installer VISE archives (`MindVision`, 1990s-2000s)
//!
//! Reads Mac archives of format versions 00 01 through 03 0e and 0b 00
//! ([`Archive`]) and Windows installers, which are executables carrying
//! the archive in a `_mvdata` section or after the image ([`WinArchive`])
//!
//! The library never prints. [`Archive::extract`] and [`WinArchive::extract`]
//! write every file to a directory; the `extract_with` variants also report
//! each entry through a callback. To get file contents in memory instead, use
//! [`Archive::reader`] or [`WinArchive::read`]:
//!
//! ```no_run
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let raw = std::fs::read("Installer")?;
//! match unvise::detect_format(raw) {
//!     unvise::InputKind::Mac(data) => {
//!         let archive = unvise::Archive::parse(data)?;
//!         let mut reader = archive.reader();
//!         for file in archive.files() {
//!             if let Ok(forks) = reader.read(file) {
//!                 println!("{}: {} bytes", file.name, forks.data.len());
//!             }
//!         }
//!     }
//!     unvise::InputKind::WinPe(data) => {
//!         let archive = unvise::WinArchive::from_pe(data, None)?;
//!         for entry in &archive.info.entries {
//!             let bytes = archive.read(entry)?;
//!             println!("{}: {} bytes", entry.name, bytes.len());
//!         }
//!     }
//!     _ => eprintln!("not a VISE archive"),
//! }
//! # Ok(())
//! # }
//! ```

#![warn(clippy::pedantic)]

pub mod appledouble;
pub(crate) mod deflate;
mod mac;
pub mod macbinary;
pub mod pe;
mod text;
pub mod win;

use std::borrow::Cow;
use std::collections::{HashMap, HashSet, VecDeque};
use std::fmt;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::SystemTime;

pub use mac::{ArchiveInfo, Entry, FileEntry, PATH_SEPARATOR};
pub use text::NameEncoding;
pub use win::{WinArchive, WinArchiveInfo, WinEntry};

/// Detected input format for auto-dispatch
#[derive(Debug)]
#[non_exhaustive]
pub enum InputKind {
    Mac(Vec<u8>),
    WinPe(Vec<u8>),
    Unknown(Vec<u8>),
}

/// Detects whether `data` is a Mac VISE archive, a Windows VISE PE, or unknown.
/// Mac data is returned after `MacBinary` stripping
#[must_use]
pub fn detect_format(data: Vec<u8>) -> InputKind {
    if data.len() >= 2 && &data[..2] == b"MZ" {
        return InputKind::WinPe(data);
    }
    if data.len() >= 4 && &data[..4] == b"SVCT" {
        return InputKind::Mac(data);
    }
    let stripped = macbinary::strip(data);
    if stripped.len() >= 4 && &stripped[..4] == b"SVCT" {
        return InputKind::Mac(stripped);
    }
    InputKind::Unknown(stripped)
}

/// The encoding of the names in a Mac installer, read from the installer
/// itself. `file` is the installer as stored, still in its `MacBinary`
/// wrapper: the region code in its `vers` resource says which system it was
/// built for. A bare data fork, or an installer without that resource,
/// gives Mac Roman
#[must_use]
pub fn mac_name_encoding(file: &[u8]) -> NameEncoding {
    macbinary::region(file).map_or(NameEncoding::MacRoman, NameEncoding::from_region)
}

/// Internals for the fuzz targets and for checking the parsers from outside,
/// under the `fuzzing` feature only; not public API
#[cfg(feature = "fuzzing")]
#[doc(hidden)]
pub mod fuzzing {
    pub use crate::deflate::decode_and_decompress;
    pub use crate::deflate::word_deflate;

    use std::path::{Path, PathBuf};

    /// Runs the real name sanitizer then the join guard, the way `extract` does,
    /// so a fuzz target can assert the pipeline never escapes the base
    #[must_use]
    pub fn sanitize_and_join(base: &Path, raw: &str) -> Option<PathBuf> {
        let cleaned = super::clean_name(raw);
        super::safe_join(base, &cleaned)
    }

    /// The same for a Mac entry, whose folder path and name go through a
    /// different sanitizer: each name is kept as one path component
    #[must_use]
    pub fn mac_sanitize_and_join(base: &Path, dir: &str, name: &str) -> Option<PathBuf> {
        super::safe_join(base, &super::mac_rel_path(dir, name))
    }

    /// Parses a VISE archive and decompresses all entries, exercising
    /// shared-block reuse and fork slicing without filesystem I/O
    pub fn parse_and_decompress(data: &[u8]) {
        let Ok(archive) = super::Archive::parse(data.to_vec()) else {
            return;
        };
        let mut reader = archive.reader();
        for f in archive.files() {
            let _ = reader.decompress_only(f);
        }
    }

    /// Reads a Mac archive's table as if its format version were not
    /// listed, so the name offsets are worked out from the archive. For
    /// comparing with the ordinary read
    ///
    /// # Errors
    ///
    /// Returns what the ordinary read would
    pub fn mac_parse_unlisted(
        data: &[u8],
        encoding: super::NameEncoding,
    ) -> Result<crate::mac::ArchiveInfo, super::Error> {
        crate::mac::parse_as(data, encoding, false)
    }

    /// Parses the input as a Windows record stream, skipping the header and
    /// runtime DLL a whole payload needs first, and reads the entries found.
    /// The first byte selects the record layout and offset handling
    pub fn parse_win_records(data: &[u8]) {
        crate::win::fuzz_records(data);
    }

    /// For checking a layout table against an installer, outside the
    /// parser's own choice of layout.
    ///
    /// Where the sections in front of the record stream end in an
    /// installer's payload under one named layout, and whether a record
    /// stream starts there
    ///
    /// # Errors
    ///
    /// Returns what stopped the read
    pub fn win_stream_start(file: &[u8], layout: &str) -> Result<(usize, bool), crate::Error> {
        let (payload, _) = crate::pe::extract_payload(file)?;
        crate::win::stream_start(payload, layout)
    }

    /// For checking a layout table against an installer: the positions can
    /// be compared with ones known some other way.
    ///
    /// Reads the record stream at `start` in an installer's payload under
    /// one named layout, without searching: each record's position and type,
    /// where the read ended, and the error that stopped it
    #[must_use]
    pub fn win_record_spans(
        file: &[u8],
        start: usize,
        layout: &str,
    ) -> (Vec<(usize, u32)>, usize, Option<String>) {
        match crate::pe::extract_payload(file) {
            Ok((payload, _)) => crate::win::record_spans(payload, start, layout),
            Err(e) => (Vec::new(), start, Some(e.to_string())),
        }
    }

    /// Reports how each Windows record layout fares on an installer, for
    /// working out why one does not parse
    #[must_use]
    pub fn trace_win_layouts(file: &[u8]) -> Vec<String> {
        match crate::pe::extract_payload(file) {
            Ok((payload, _)) => crate::win::trace_layouts(payload),
            Err(e) => vec![e.to_string()],
        }
    }

    /// Parses a Windows VISE payload (or a whole PE) and decompresses every
    /// entry without filesystem I/O
    pub fn parse_and_decompress_win(data: &[u8]) {
        if let Ok(archive) = super::WinArchive::parse(data.to_vec(), None, 0) {
            for entry in &archive.info.entries {
                let _ = archive.read(entry);
            }
        }
        if let Ok(archive) = super::WinArchive::from_pe(data.to_vec(), None) {
            for entry in &archive.info.entries {
                let _ = archive.read(entry);
            }
        }
    }
}

/// How far total extracted output may exceed the archive size before extraction
/// aborts. DEFLATE's exact maximum expansion is 1032:1, so legitimate output
/// stays well under this; anything beyond is a bomb
pub(crate) const OUTPUT_BUDGET_RATIO: usize = 1032;
/// Floor for the output budget so tiny archives still extract normally
pub(crate) const OUTPUT_BUDGET_HEADROOM: usize = 1 << 20;

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    #[error("invalid archive: {0}")]
    InvalidArchive(String),
    /// A structure in the archive does not read as what should be there.
    /// `offset` counts from the start of the data being parsed
    #[error("invalid archive: {what} at 0x{offset:x}")]
    Malformed { what: &'static str, offset: usize },
    #[error("decompression failed: {0}")]
    Decompression(String),
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    /// The entry exists in the file table but has no data to return
    #[error("entry not extractable: {0}")]
    Skipped(SkipReason),
    /// The decoded contents do not match the CRC-32 stored in the file table
    #[error("checksum mismatch: file table says {expected:08x}, contents give {actual:08x}")]
    Checksum { expected: u32, actual: u32 },
}

/// Why an entry was not extracted
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum SkipReason {
    /// An installer condition record, not a file
    Condition { flags: u32 },
    /// The file lives on the distribution disc, outside the archive
    OnDisc,
    /// The file is in a segment file that was not loaded
    SegmentNotLoaded(u16),
    /// The file's data is not in the loaded archive: it lies past the end,
    /// or the entry records a size but stores no bytes
    MissingData,
    /// The name is empty once sanitized
    EmptyName,
    /// The name would escape the output directory
    UnsafePath,
    /// Windows stub installer whose companion `.qdat` volume was not supplied
    MissingQdat,
    /// A Windows web installer downloads the file when it runs
    Downloaded,
}

impl fmt::Display for SkipReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Condition { flags } => write!(f, "condition record (flags 0x{flags:08x})"),
            Self::OnDisc => f.write_str("on the distribution disc"),
            Self::SegmentNotLoaded(n) => write!(f, "segment {n} not loaded"),
            Self::MissingData => f.write_str("data is not in the archive"),
            Self::EmptyName => f.write_str("empty name"),
            Self::UnsafePath => f.write_str("unsafe path"),
            Self::MissingQdat => f.write_str("companion .qdat not available"),
            Self::Downloaded => f.write_str("downloaded by the installer when it runs"),
        }
    }
}

/// One step of an extraction run, passed to the `extract_with` callback.
/// Every `name` is the entry's path relative to the output directory
#[derive(Debug)]
#[non_exhaustive]
pub enum Progress<'a> {
    /// A file was written. `rsrc_len` is `None` for formats without resource
    /// forks
    Extracted {
        name: &'a str,
        data_len: usize,
        rsrc_len: Option<usize>,
    },
    /// An entry was passed over
    Skipped { name: &'a str, reason: SkipReason },
    /// An entry could not be decoded or written
    Failed { name: &'a str, error: &'a Error },
    /// Extraction stopped early because total output passed the safety budget
    BudgetExceeded { budget: usize },
}

/// Byte offset where segment data begins in each SVCT file
const SEGMENT_DATA_START: usize = 0x2c;

/// A loaded VISE archive ready for extraction
#[derive(Debug)]
pub struct Archive {
    data: Vec<u8>,
    pub info: ArchiveInfo,
    segments_loaded: bool,
    /// Compressed blocks keyed by offset, with how many entries read from each
    groups: HashMap<usize, BlockGroup>,
}

#[derive(Debug, Clone, Copy)]
struct BlockGroup {
    members: usize,
    max_comp: usize,
}

/// Outcome of an extraction run
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct ExtractResult {
    pub extracted: usize,
    pub skipped: usize,
    pub failed: usize,
}

/// How a Mac file's resource fork and Finder information are written out
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ForkFormat {
    /// The data fork as the file, and the resource fork next to it as
    /// `name.rsrc`. Type and creator codes are not written
    #[default]
    Rsrc,
    /// `AppleDouble`: the data fork as the file, and a `._name` file next to
    /// it holding the resource fork, type and creator codes and Finder
    /// flags. macOS reads the pair back as one file
    AppleDouble,
    /// `MacBinary` II: one `name.bin` file holding both forks, type and
    /// creator codes, Finder flags and dates. HFS tools take this form
    MacBinary,
}

/// Settings for [`Archive::extract_with_options`]
#[derive(Debug, Default, Clone)]
#[non_exhaustive]
pub struct ExtractOptions {
    pub forks: ForkFormat,
}

impl ExtractOptions {
    /// These options with resource forks written as `forks`
    #[must_use]
    pub const fn with_forks(mut self, forks: ForkFormat) -> Self {
        self.forks = forks;
        self
    }
}

/// The decompressed contents of one file. Either fork may be empty
#[derive(Debug, Default, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Forks {
    pub data: Vec<u8>,
    pub rsrc: Vec<u8>,
}

/// The most recently used shared block. Entries that share a block are
/// adjacent in the file table, so holding one block bounds memory to the
/// largest block instead of the whole archive's decompressed size
#[derive(Debug, Default)]
struct BlockCache {
    offset: Option<usize>,
    block: Option<Vec<u8>>,
}

/// The data fork and resource fork of one file, borrowed from a shared block
/// where the file reads from one
type ForkPair<'c> = (Cow<'c, [u8]>, Cow<'c, [u8]>);

impl BlockCache {
    /// The cached block, if it is the one at `offset` and it decoded
    fn get(&self, offset: usize) -> Option<&[u8]> {
        if self.offset == Some(offset) {
            self.block.as_deref()
        } else {
            None
        }
    }
}

/// Relative paths already written during one extraction run. Names are
/// compared without regard to case, as most target filesystems do
#[derive(Debug, Default)]
pub(crate) struct UsedPaths {
    taken: HashSet<String>,
    /// Next number to try for a name that has collided before
    next: HashMap<String, usize>,
}

impl UsedPaths {
    /// Returns `rel`, or a numbered variant of it when an earlier entry took
    /// that path: `a/file.txt` becomes `a/file (2).txt`. The second file an
    /// entry writes, if any, is reserved along with it
    pub(crate) fn claim(&mut self, rel: String, companion: Companion) -> String {
        let key = rel.to_lowercase();
        if self.reserve(&key, companion) {
            return rel;
        }
        // the number goes before the extension of the last path component
        let name_start = rel.rfind('/').map_or(0, |i| i + 1);
        let dot = rel[name_start..]
            .rfind('.')
            .filter(|&i| i > 0)
            .map_or(rel.len(), |i| name_start + i);
        let (stem, ext) = rel.split_at(dot);
        let mut n = self.next.get(&key).copied().unwrap_or(2);
        loop {
            let candidate = format!("{stem} ({n}){ext}");
            n += 1;
            if self.reserve(&candidate.to_lowercase(), companion) {
                self.next.insert(key, n);
                return candidate;
            }
        }
    }

    fn reserve(&mut self, key: &str, companion: Companion) -> bool {
        let second = match companion {
            Companion::None => None,
            Companion::Suffix(suffix) => Some(format!("{key}{suffix}")),
            Companion::AppleDouble => {
                let name_start = key.rfind('/').map_or(0, |i| i + 1);
                let (dir, name) = key.split_at(name_start);
                Some(format!("{dir}{}", appledouble::sidecar_name(name)))
            }
        };
        if self.taken.contains(key) || second.as_ref().is_some_and(|s| self.taken.contains(s)) {
            return false;
        }
        self.taken.insert(key.to_owned());
        self.taken.extend(second);
        true
    }
}

/// The second file written next to an extracted entry, which must not
/// collide with anything either
#[derive(Debug, Clone, Copy)]
pub(crate) enum Companion {
    None,
    /// The entry's own path with this appended
    Suffix(&'static str),
    /// An `AppleDouble` `._name` file in the same folder
    AppleDouble,
}

/// Declared output size at which a batch of entries stops growing. Bounds
/// how much decoded data extraction holds in memory at once
pub(crate) const BATCH_BYTES: usize = 64 << 20;
/// Most entries decoded in one batch
pub(crate) const BATCH_ENTRIES: usize = 1024;
/// Most threads used to decode a batch
const MAX_THREADS: usize = 16;

/// Runs `work` on each index in `0..n` across the available cores and
/// returns the results in index order. With one item, one core, or no
/// thread support, it runs on the calling thread
pub(crate) fn parallel_map<T: Send>(n: usize, work: impl Fn(usize) -> T + Sync) -> Vec<T> {
    let threads = std::thread::available_parallelism()
        .map_or(1, std::num::NonZero::get)
        .min(MAX_THREADS)
        .min(n);
    if threads <= 1 {
        return (0..n).map(work).collect();
    }

    // each worker takes the next unclaimed index until none are left
    let next = AtomicUsize::new(0);
    let run = || {
        let mut done = Vec::new();
        loop {
            let i = next.fetch_add(1, Ordering::Relaxed);
            if i >= n {
                break done;
            }
            done.push((i, work(i)));
        }
    };

    let mut slots: Vec<Option<T>> = (0..n).map(|_| None).collect();
    std::thread::scope(|scope| {
        // a thread that cannot be started just leaves more for the others
        let workers: Vec<_> = (1..threads)
            .filter_map(|_| std::thread::Builder::new().spawn_scoped(scope, run).ok())
            .collect();
        let mut finished = run();
        for worker in workers {
            match worker.join() {
                Ok(done) => finished.extend(done),
                Err(panic) => std::panic::resume_unwind(panic),
            }
        }
        for (i, value) in finished {
            slots[i] = Some(value);
        }
    });
    slots
        .into_iter()
        .map(|slot| slot.expect("each index is claimed by exactly one worker"))
        .collect()
}

/// Writes `data` to `path` and stamps it with the archive's modification time
pub(crate) fn write_file(
    path: &Path,
    data: &[u8],
    modified: Option<SystemTime>,
) -> std::io::Result<()> {
    let mut file = fs::File::create(path)?;
    file.write_all(data)?;
    if let Some(time) = modified {
        // a filesystem that cannot store the time still has the file
        let _ = file.set_modified(time);
    }
    Ok(())
}

/// Reads file contents from an [`Archive`] into memory
///
/// Keeps the last shared block it decompressed, so reading entries in table
/// order decodes each block once
#[derive(Debug)]
pub struct Reader<'a> {
    archive: &'a Archive,
    cache: BlockCache,
}

impl Reader<'_> {
    /// Decompresses both forks of `entry`
    ///
    /// # Errors
    ///
    /// Returns [`Error::Skipped`] if the entry has no data in this archive
    /// (a condition record, or a file on another segment or disc),
    /// [`Error::Decompression`] if its data cannot be decoded, or
    /// [`Error::Checksum`] if what it decodes to does not match its CRC-32
    pub fn read(&mut self, entry: &FileEntry) -> Result<Forks, Error> {
        self.archive.decode(entry, &mut self.cache)
    }

    /// Decodes both forks and discards them, without copying shared slices
    #[cfg(feature = "fuzzing")]
    fn decompress_only(&mut self, entry: &FileEntry) -> Result<(), Error> {
        let archive = self.archive;
        if let Some(reason) = archive.skip_reason(entry, &mut self.cache) {
            return Err(Error::Skipped(reason));
        }
        archive.read_forks(entry, &mut self.cache).map(|_| ())
    }
}

impl Archive {
    /// Parses a VISE archive from raw bytes (after `MacBinary` stripping)
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArchive`] if the data is not a recognized VISE
    /// archive format
    pub fn parse(data: Vec<u8>) -> Result<Self, Error> {
        Self::parse_with_encoding(data, NameEncoding::default())
    }

    /// Like [`Archive::parse`], decoding file and folder names with
    /// `encoding`. The archive does not record which one its names use; for
    /// an installer still in its `MacBinary` wrapper, [`mac_name_encoding`]
    /// reads it from the installer's resources
    ///
    /// # Errors
    ///
    /// See [`Archive::parse`]
    pub fn parse_with_encoding(data: Vec<u8>, encoding: NameEncoding) -> Result<Self, Error> {
        let info = mac::parse(&data, encoding)?;
        let data = Self::data_region(data, &info);
        Ok(Self::new(data, info, false))
    }

    /// Parses an installer whose file table and file data are in two files.
    /// The Mac OS X installers are application bundles that keep the table
    /// in `Contents/MacOSClassic/<name>` and the data in
    /// `Contents/InstallerData/Installer.data`; some keep both in the
    /// latter, and those parse on their own
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArchive`] if `table` is not a VISE archive
    /// with a file table, or `data` does not start with an archive header
    pub fn parse_with_data_file(
        table: &[u8],
        data: Vec<u8>,
        encoding: NameEncoding,
    ) -> Result<Self, Error> {
        let info = mac::parse(table, encoding)?;
        if data.len() < SEGMENT_DATA_START || !data.starts_with(b"SVCT") {
            return Err(Error::InvalidArchive(
                "data file missing SVCT header".into(),
            ));
        }
        // the data file is a header followed by nothing but file data
        Ok(Self::new(data, info, false))
    }

    /// Parses a multi-segment archive. `segments` are the companion segment
    /// files (Segment.2, Segment.3, etc.) in any order; each carries its
    /// sequence number at SVCT+0x04. Data from all segments is concatenated
    /// in order after the main archive's data region so that FVCT offsets
    /// resolve correctly
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArchive`] if any segment lacks an SVCT header,
    /// or if the segments are not numbered 2, 3, ... with no gaps or repeats.
    /// File offsets count through the segments in order, so a missing or
    /// doubled segment would shift every file after it
    pub fn parse_with_segments(data: Vec<u8>, segments: &[Vec<u8>]) -> Result<Self, Error> {
        Self::parse_segments_with_encoding(data, segments, NameEncoding::default())
    }

    /// Like [`Archive::parse_with_segments`], decoding names with `encoding`
    ///
    /// # Errors
    ///
    /// See [`Archive::parse_with_segments`]
    pub fn parse_segments_with_encoding(
        data: Vec<u8>,
        segments: &[Vec<u8>],
        encoding: NameEncoding,
    ) -> Result<Self, Error> {
        let info = mac::parse(&data, encoding)?;
        if segments.is_empty() {
            let data = Self::data_region(data, &info);
            return Ok(Self::new(data, info, false));
        }

        let mut numbered: Vec<(u32, &[u8])> = Vec::new();
        for seg in segments {
            if seg.len() < SEGMENT_DATA_START + 4 || &seg[..4] != b"SVCT" {
                return Err(Error::InvalidArchive(
                    "segment file missing SVCT header".into(),
                ));
            }
            let seq = u32::from_be_bytes([seg[4], seg[5], seg[6], seg[7]]);
            numbered.push((seq, seg));
        }
        numbered.sort_by_key(|&(seq, _)| seq);
        for (want, &(seq, _)) in (2u32..).zip(&numbered) {
            if seq != want {
                return Err(Error::InvalidArchive(format!(
                    "segment files must be numbered 2, 3, ... with no gaps or repeats: expected segment {want}, found {seq}"
                )));
            }
        }

        // mac::parse already checked the header is at least 0x28 bytes
        let cvct_off =
            u32::from_be_bytes([data[0x24], data[0x25], data[0x26], data[0x27]]) as usize;
        let main_data_end = cvct_off.min(data.len());

        let mut combined = data[..main_data_end].to_vec();
        for &(_, seg) in &numbered {
            combined.extend_from_slice(&seg[SEGMENT_DATA_START..]);
        }

        Ok(Self::new(combined, info, true))
    }

    /// Reduces the file holding the table to its header and file data, so
    /// that the offsets in the table index it directly.
    ///
    /// The table follows the data, so anything from the table on is not
    /// data. In a Mac OS X installer the file with the table is the
    /// installer program itself: what lies between its header and its table
    /// is that program, whose length is in the header, and the file data is
    /// in a separate file. Removing the program leaves such a file with no
    /// data region, so that every entry reads as missing instead of being
    /// decoded out of program code
    fn data_region(mut data: Vec<u8>, info: &ArchiveInfo) -> Vec<u8> {
        let be32 = |data: &[u8], at: usize| {
            data.get(at..at + 4)
                .map_or(0, |b| u32::from_be_bytes([b[0], b[1], b[2], b[3]]) as usize)
        };
        let table_at = be32(&data, 0x24);
        if (SEGMENT_DATA_START..data.len()).contains(&table_at) {
            data.truncate(table_at);
        }
        if info.fmt_major >= mac::FMT_OSX {
            let program_len = be32(&data, 0x08);
            let end = SEGMENT_DATA_START.saturating_add(program_len);
            if program_len > 0 && end <= data.len() {
                data.drain(SEGMENT_DATA_START..end);
            }
        }
        data
    }

    fn new(data: Vec<u8>, info: ArchiveInfo, segments_loaded: bool) -> Self {
        let mut groups: HashMap<usize, BlockGroup> = HashMap::new();
        for f in info.entries.iter().filter_map(Entry::as_file) {
            if f.comp_data > 0
                && !f.is_stub()
                && f.segment != 0
                && (info.num_segments <= 1 || segments_loaded || f.segment == 1)
            {
                let group = groups.entry(f.data_offset).or_insert(BlockGroup {
                    members: 0,
                    max_comp: 0,
                });
                group.members += 1;
                group.max_comp = group.max_comp.max(f.comp_data);
            }
        }
        Self {
            data,
            info,
            segments_loaded,
            groups,
        }
    }

    /// The file entries in table order, without directory markers
    pub fn files(&self) -> impl Iterator<Item = &FileEntry> {
        self.info.entries.iter().filter_map(Entry::as_file)
    }

    /// Returns a [`Reader`] for decompressing entries into memory
    #[must_use]
    pub fn reader(&self) -> Reader<'_> {
        Reader {
            archive: self,
            cache: BlockCache::default(),
        }
    }

    /// Decompresses both forks of one entry. To read many entries, use
    /// [`Archive::reader`], which decodes each shared block only once
    ///
    /// # Errors
    ///
    /// See [`Reader::read`]
    pub fn read(&self, entry: &FileEntry) -> Result<Forks, Error> {
        self.reader().read(entry)
    }

    /// Extracts all available files to `out_dir`, creating directories as
    /// needed. A resource fork is written next to its file with a `.rsrc`
    /// suffix
    ///
    /// Entries that cannot be decoded are counted in
    /// [`ExtractResult::failed`] and extraction continues
    ///
    /// # Errors
    ///
    /// Returns [`Error::Io`] if the output directory cannot be created
    pub fn extract(&self, out_dir: &Path) -> Result<ExtractResult, Error> {
        self.extract_with(out_dir, |_| {})
    }

    /// Like [`Archive::extract`], and reports each entry to `on_progress` as
    /// it is handled
    ///
    /// # Errors
    ///
    /// Returns [`Error::Io`] if the output directory cannot be created
    pub fn extract_with(
        &self,
        out_dir: &Path,
        on_progress: impl FnMut(Progress<'_>),
    ) -> Result<ExtractResult, Error> {
        self.extract_with_options(out_dir, &ExtractOptions::default(), on_progress)
    }

    /// Like [`Archive::extract_with`], writing resource forks and Finder
    /// information in the form `options` asks for
    ///
    /// # Errors
    ///
    /// Returns [`Error::Io`] if the output directory cannot be created
    pub fn extract_with_options(
        &self,
        out_dir: &Path,
        options: &ExtractOptions,
        mut on_progress: impl FnMut(Progress<'_>),
    ) -> Result<ExtractResult, Error> {
        fs::create_dir_all(out_dir)?;

        let files: Vec<&FileEntry> = self.files().collect();
        let mut next_file = 0;
        let mut decoded: VecDeque<Result<Forks, Error>> = VecDeque::new();
        let mut used = UsedPaths::default();
        let mut result = ExtractResult::default();

        let output_budget = self
            .data
            .len()
            .saturating_mul(OUTPUT_BUDGET_RATIO)
            .saturating_add(OUTPUT_BUDGET_HEADROOM);
        let mut total_out: usize = 0;

        for entry in &self.info.entries {
            match entry {
                Entry::Dir(dir) => {
                    if !make_folder(out_dir, dir, &mut on_progress) {
                        result.failed += 1;
                    }
                }
                Entry::File(f) => {
                    // files are decoded a batch at a time, on several threads,
                    // and handed back here in table order
                    if decoded.is_empty() {
                        decoded = self.decode_batch(&files, &mut next_file);
                    }
                    // a batch always holds at least the next file
                    let Some(mut forks) = decoded.pop_front() else {
                        break;
                    };

                    // reported names are paths relative to `out_dir`
                    let mut shown = mac_rel_path(&f.dir, &f.name);
                    let skip = if let Err(Error::Skipped(reason)) = forks {
                        forks = Ok(Forks::default());
                        Some(reason)
                    } else if clean_component(&f.name).is_empty() {
                        Some(SkipReason::EmptyName)
                    } else {
                        None
                    };
                    if let Some(reason) = skip {
                        on_progress(Progress::Skipped {
                            name: &shown,
                            reason,
                        });
                        result.skipped += 1;
                        continue;
                    }
                    // two entries can map to one path; the later one is renamed
                    // so it does not replace the earlier
                    shown = match options.forks {
                        ForkFormat::Rsrc if f.has_rsrc() => {
                            used.claim(shown, Companion::Suffix(".rsrc"))
                        }
                        ForkFormat::Rsrc => used.claim(shown, Companion::None),
                        ForkFormat::AppleDouble => used.claim(shown, Companion::AppleDouble),
                        ForkFormat::MacBinary => {
                            used.claim(format!("{shown}.bin"), Companion::None)
                        }
                    };
                    let Some(path) = safe_join(out_dir, &shown) else {
                        on_progress(Progress::Skipped {
                            name: &shown,
                            reason: SkipReason::UnsafePath,
                        });
                        result.skipped += 1;
                        continue;
                    };

                    let written =
                        forks.and_then(|forks| Self::write_forks(f, &path, &forks, options.forks));
                    match written {
                        Err(e) => {
                            on_progress(Progress::Failed {
                                name: &shown,
                                error: &e,
                            });
                            result.failed += 1;
                        }
                        Ok((data_len, rsrc_len)) => {
                            on_progress(Progress::Extracted {
                                name: &shown,
                                data_len,
                                rsrc_len: Some(rsrc_len),
                            });
                            result.extracted += 1;
                            total_out = total_out.saturating_add(data_len).saturating_add(rsrc_len);
                            if total_out > output_budget {
                                on_progress(Progress::BudgetExceeded {
                                    budget: output_budget,
                                });
                                break;
                            }
                        }
                    }
                }
            }
        }

        Ok(result)
    }

    fn skip_reason(&self, f: &FileEntry, cache: &mut BlockCache) -> Option<SkipReason> {
        if f.is_stub() {
            return Some(SkipReason::Condition { flags: f.flags });
        }
        // Segment 0 entries live outside the archive, on the distribution disc.
        // Single-segment archives carry them too, as alternates of a file
        // that is stored once under segment 1
        if f.segment == 0 {
            return Some(SkipReason::OnDisc);
        }
        // Without loaded segments, only segment 1 data is available
        if self.info.num_segments > 1 && !self.segments_loaded && f.segment != 1 {
            return Some(SkipReason::SegmentNotLoaded(f.segment));
        }
        // a size with no stored bytes behind it
        if f.comp_data == 0 && f.uncomp_data > 0 {
            return Some(SkipReason::MissingData);
        }
        // What the entry occupies: its two compressed forks back to back,
        // or, for an entry with no data fork inside a block, the block alone
        // (there the second size is not a compressed length)
        let block_only = f.comp_data > 0 && f.uncomp_data == 0;
        let total = f
            .data_offset
            .saturating_add(f.comp_data)
            .saturating_add(if block_only { 0 } else { f.comp_rsrc });
        if total > self.data.len() {
            self.load_block(cache, f.data_offset);
            if cache.get(f.data_offset).is_none() {
                return Some(SkipReason::MissingData);
            }
        }
        None
    }

    /// Decodes and checks both forks of `f`, or says why it has none
    fn decode(&self, f: &FileEntry, cache: &mut BlockCache) -> Result<Forks, Error> {
        if let Some(reason) = self.skip_reason(f, cache) {
            return Err(Error::Skipped(reason));
        }
        let (data, rsrc) = self.read_forks(f, cache)?;
        Ok(Forks {
            data: data.into_owned(),
            rsrc: rsrc.into_owned(),
        })
    }

    /// Decodes the next run of `files`, starting at `*next`, and advances it.
    /// The run is cut off by declared size so the decoded contents held at
    /// once stay bounded, and always holds at least one file
    fn decode_batch(
        &self,
        files: &[&FileEntry],
        next: &mut usize,
    ) -> VecDeque<Result<Forks, Error>> {
        let start = *next;
        let mut end = start;
        let mut cost = 0usize;
        // each task is a range of files one thread handles in order
        let mut tasks: Vec<std::ops::Range<usize>> = Vec::new();
        while end < files.len()
            && (end == start || (cost < BATCH_BYTES && end - start < BATCH_ENTRIES))
        {
            // files reading from one shared block stay in one task, so the
            // block is decoded once. Condition records between them have no
            // data and ride along
            let key = files[end].data_offset;
            let shared = self.groups.get(&key).is_some_and(|g| g.members > 1);
            // A task is cut off by size like the batch is: its files are
            // all held decoded until they are written. The block is then
            // decoded again for the files left over
            let size = |f: &FileEntry| f.uncomp_data.saturating_add(f.uncomp_rsrc);
            let mut task_end = end + 1;
            cost = cost.saturating_add(size(files[end]));
            while shared
                && task_end < files.len()
                && cost < BATCH_BYTES
                && task_end - start < BATCH_ENTRIES
                && (files[task_end].data_offset == key || files[task_end].is_stub())
            {
                cost = cost.saturating_add(size(files[task_end]));
                task_end += 1;
            }
            tasks.push(end..task_end);
            end = task_end;
        }
        *next = end;

        parallel_map(tasks.len(), |t| {
            let mut cache = BlockCache::default();
            tasks[t]
                .clone()
                .map(|i| self.decode(files[i], &mut cache))
                .collect::<Vec<_>>()
        })
        .into_iter()
        .flatten()
        .collect()
    }

    /// Writes both forks in the given form and returns their lengths as
    /// `(data, rsrc)`. `path` is the file to create: for `MacBinary` the one
    /// `.bin` file, otherwise the data fork
    fn write_forks(
        f: &FileEntry,
        path: &Path,
        forks: &Forks,
        format: ForkFormat,
    ) -> Result<(usize, usize), Error> {
        let modified = f.modified_time();
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }

        match format {
            ForkFormat::Rsrc => {
                // the file exists under its own name even when its data
                // fork is empty, whether or not it has a resource fork
                write_file(path, &forks.data, modified)?;
                if f.has_rsrc() {
                    let mut rsrc_path = path.as_os_str().to_owned();
                    rsrc_path.push(".rsrc");
                    write_file(Path::new(&rsrc_path), &forks.rsrc, modified)?;
                }
            }
            ForkFormat::AppleDouble => {
                // the pair is only read back as one file if both halves exist
                write_file(path, &forks.data, modified)?;
                let name = path.file_name().unwrap_or_default().to_string_lossy();
                let sidecar = path.with_file_name(appledouble::sidecar_name(&name));
                write_file(&sidecar, &appledouble::encode(f, &forks.rsrc), modified)?;
            }
            ForkFormat::MacBinary => {
                let wrapped = macbinary::encode(f, &forks.data, &forks.rsrc);
                write_file(path, &wrapped, modified)?;
            }
        }

        Ok((forks.data.len(), forks.rsrc.len()))
    }

    /// Decodes the block at `offset` into the cache if more than one entry
    /// reads from it. Afterwards `cache.get(offset)` is that block, or `None`
    /// for "decompress the entry on its own"
    fn load_block(&self, cache: &mut BlockCache, offset: usize) {
        let Some(group) = self.groups.get(&offset) else {
            return;
        };
        if group.members > 1 && cache.offset != Some(offset) {
            cache.offset = Some(offset);
            cache.block = offset
                .checked_add(group.max_comp)
                .filter(|&end| end <= self.data.len())
                .and_then(|end| deflate::decode_and_decompress(&self.data[offset..end], 0).ok());
        }
    }

    /// Decodes both forks of `f` and checks them against the stored CRC.
    /// A fork the entry does not have comes back empty.
    ///
    /// The forks are slices of the entry's shared block when it reads from
    /// one. Otherwise each is a stream of its own. An entry can also sit in
    /// a block it shares with entries that are not counted as its members,
    /// such as condition records: its stream then holds more than its
    /// forks, and they are the parts at its block offsets. That reading is
    /// tried when the streams do not decode on their own, and the block is
    /// kept in `cache`, so it is decoded once however many entries ask
    fn read_forks<'c>(
        &self,
        f: &FileEntry,
        cache: &'c mut BlockCache,
    ) -> Result<ForkPair<'c>, Error> {
        let at = f.data_offset;
        self.load_block(cache, at);
        let in_block =
            |cache: &BlockCache| cache.get(at).is_some_and(|b| Self::slices(f, b).is_some());

        if !in_block(cache) {
            match self.decode_forks(f) {
                Ok((data, rsrc)) => {
                    Self::check_crc(f, &data, &rsrc)?;
                    return Ok((Cow::Owned(data), Cow::Owned(rsrc)));
                }
                Err(error) => {
                    // one decode of the entry's stream as a block, unless
                    // the block at this offset was already tried
                    if cache.offset != Some(at) {
                        let comp = if f.comp_data > 0 {
                            f.comp_data
                        } else {
                            f.comp_rsrc
                        };
                        cache.offset = Some(at);
                        cache.block = self.decompress_raw(at, comp, 0).ok();
                    }
                    if !in_block(cache) {
                        return Err(error);
                    }
                }
            }
        }
        let (data, rsrc) = cache
            .get(at)
            .and_then(|block| Self::slices(f, block))
            .ok_or_else(|| Error::Decompression("fork lies outside its block".into()))?;
        Self::check_crc(f, data, rsrc)?;
        Ok((Cow::Borrowed(data), Cow::Borrowed(rsrc)))
    }

    /// A data fork exists only if it has a size. For an entry inside a
    /// shared block the compressed size is the block's, and is set even
    /// when the entry has nothing but a resource fork
    const fn has_data(f: &FileEntry) -> bool {
        f.comp_data > 0 && f.uncomp_data > 0
    }

    /// Both forks of `f` as parts of the decoded `block`, if they lie in it
    fn slices<'b>(f: &FileEntry, block: &'b [u8]) -> Option<(&'b [u8], &'b [u8])> {
        let part = |wanted: bool, from: usize, len: usize| {
            if wanted {
                block.get(from..from.checked_add(len)?)
            } else {
                Some(&[][..])
            }
        };
        Some((
            part(Self::has_data(f), f.block_data_off, f.uncomp_data)?,
            part(f.has_rsrc(), f.block_rsrc_off, f.uncomp_rsrc)?,
        ))
    }

    /// Both forks of `f`, each decoded as a stream of its own
    fn decode_forks(&self, f: &FileEntry) -> Result<(Vec<u8>, Vec<u8>), Error> {
        let data = if Self::has_data(f) {
            self.decompress_raw(f.data_offset, f.comp_data, f.uncomp_data)?
        } else {
            Vec::new()
        };
        let rsrc = if f.has_rsrc() {
            let at = f
                .data_offset
                .checked_add(f.comp_data)
                .ok_or_else(|| Error::Decompression("fork offset exceeds archive bounds".into()))?;
            self.decompress_raw(at, f.comp_rsrc, f.uncomp_rsrc)?
        } else {
            Vec::new()
        };
        Ok((data, rsrc))
    }

    /// Checks the forks against the entry's CRC-32, which every format
    /// version stores and which covers the data fork then the resource fork
    fn check_crc(f: &FileEntry, data: &[u8], rsrc: &[u8]) -> Result<(), Error> {
        if data.is_empty() && rsrc.is_empty() {
            return Ok(());
        }
        let mut crc = flate2::Crc::new();
        crc.update(data);
        crc.update(rsrc);
        if crc.sum() == f.crc32 {
            Ok(())
        } else {
            Err(Error::Checksum {
                expected: f.crc32,
                actual: crc.sum(),
            })
        }
    }

    fn decompress_raw(&self, offset: usize, comp: usize, uncomp: usize) -> Result<Vec<u8>, Error> {
        let end = offset
            .checked_add(comp)
            .filter(|&e| e <= self.data.len())
            .ok_or_else(|| {
                Error::Decompression(format!(
                    "data at 0x{offset:x} ({comp} bytes) exceeds archive bounds"
                ))
            })?;
        let src = &self.data[offset..end];
        deflate::decode_and_decompress(src, uncomp)
    }
}

/// Joins a cleaned entry name onto `base`, refusing any name that would escape
/// it. `clean_name` already strips `..` and leading separators, so this is
/// defense in depth and the single enforcement point for no traversal
pub(crate) fn safe_join(base: &Path, name: &str) -> Option<PathBuf> {
    use std::path::Component;
    let escapes = Path::new(name)
        .components()
        .any(|c| !matches!(c, Component::Normal(_) | Component::CurDir));
    if escapes {
        return None;
    }
    Some(base.join(name))
}

/// Creates the folder a Mac folder record names, so that one with nothing in
/// it still exists afterwards. Returns `false` if it could not be created
fn make_folder(out_dir: &Path, dir: &str, on_progress: &mut impl FnMut(Progress<'_>)) -> bool {
    let rel = mac_rel_path(dir, "");
    if rel.is_empty() {
        return true;
    }
    let Some(path) = safe_join(out_dir, &rel) else {
        on_progress(Progress::Skipped {
            name: &rel,
            reason: SkipReason::UnsafePath,
        });
        return true;
    };
    match fs::create_dir_all(&path) {
        Ok(()) => true,
        Err(e) => {
            on_progress(Progress::Failed {
                name: &rel,
                error: &Error::Io(e),
            });
            false
        }
    }
}

/// One Mac file or folder name made safe to use as a single path component.
/// A Mac name may contain `/`, which would otherwise split it into folders
pub(crate) fn clean_component(name: &str) -> String {
    let cleaned: String = name
        .chars()
        .filter(|&c| c != '\0')
        .map(|c| {
            if matches!(c, '/' | '\\' | ':') {
                '_'
            } else {
                c
            }
        })
        .collect();
    if cleaned.trim().is_empty() || cleaned == "." || cleaned == ".." {
        String::new()
    } else {
        cleaned
    }
}

/// The output path, relative to the extraction root, for a Mac entry named
/// `name` in the folder path `dir`. An empty `name` gives the folder itself
pub(crate) fn mac_rel_path(dir: &str, name: &str) -> String {
    let mut out = String::new();
    let parts = dir
        .split(PATH_SEPARATOR)
        .chain(std::iter::once(name))
        .map(clean_component)
        .filter(|part| !part.is_empty());
    for part in parts {
        if !out.is_empty() {
            out.push('/');
        }
        out.push_str(&part);
    }
    out
}

pub(crate) fn clean_name(name: &str) -> String {
    let mut out = String::with_capacity(name.len());
    for segment in name.split([':', '/']) {
        let s = segment.trim().trim_matches('\0');
        if s.is_empty() || s == "." || s == ".." {
            continue;
        }
        if !out.is_empty() {
            out.push('/');
        }
        out.push_str(s);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mac::testutil::{TestFile, dvct_record, fvct_record};

    #[test]
    fn clean_name_neutralizes_traversal() {
        assert_eq!(clean_name("../../etc/passwd"), "etc/passwd");
        assert_eq!(clean_name("/etc/passwd"), "etc/passwd");
        assert_eq!(
            clean_name("Macintosh HD:System:Prefs"),
            "Macintosh HD/System/Prefs"
        );
        assert_eq!(clean_name("a/../../b"), "a/b");
        assert_eq!(clean_name(".."), "");
        assert_eq!(clean_name("."), "");
    }

    #[test]
    fn safe_join_rejects_escapes() {
        let base = Path::new("/out");
        assert_eq!(
            safe_join(base, "sub/file.txt"),
            Some(PathBuf::from("/out/sub/file.txt"))
        );
        assert_eq!(safe_join(base, "../escape"), None);
        assert_eq!(safe_join(base, "a/../b"), None);
        assert_eq!(safe_join(base, "/abs/path"), None);
    }

    #[test]
    fn segment_file_requires_svct() {
        let main = vec![0u8; 64];
        let bad_seg = vec![0u8; 64];
        assert!(Archive::parse_with_segments(main, &[bad_seg]).is_err());
    }

    /// Compresses `raw` and applies the VISE encoding layer, the inverse of
    /// `deflate::decode_and_decompress`
    fn vise_encode(raw: &[u8]) -> Vec<u8> {
        let mut comp = flate2::Compress::new(flate2::Compression::best(), false);
        let mut out = vec![0u8; raw.len() + 4096];
        comp.compress(raw, &mut out, flate2::FlushCompress::Finish)
            .unwrap();
        out.truncate(usize::try_from(comp.total_out()).unwrap());

        let mut inverse = [0u8; 256];
        for (i, &c) in deflate::CIPHER.iter().enumerate() {
            inverse[usize::from(c)] = u8::try_from(i).unwrap();
        }
        let even = out.len() & !1;
        let (pairs, tail) = out.split_at_mut(even);
        for pair in pairs.chunks_exact_mut(2) {
            let (a, b) = (pair[0], pair[1]);
            pair[0] = inverse[usize::from(b)];
            pair[1] = inverse[usize::from(a)];
        }
        if let [last] = tail {
            *last = inverse[usize::from(*last)];
        }
        out
    }

    fn text(seed: &str, repeats: usize) -> Vec<u8> {
        seed.repeat(repeats).into_bytes()
    }

    /// CRC-32 of the forks in order, as the file table stores it
    fn crc(forks: &[&[u8]]) -> u32 {
        let mut crc = flate2::Crc::new();
        for fork in forks {
            crc.update(fork);
        }
        crc.sum()
    }

    /// Assembles a single-file-table archive: SVCT header, the data region,
    /// then an old-style CVCT holding one directory and `files`
    fn build_archive(num_segments: u32, data_region: &[u8], files: &[TestFile]) -> Vec<u8> {
        let mut records = dvct_record("Folder", 0);
        for f in files {
            records.extend_from_slice(&fvct_record(f));
        }
        archive_from_records(num_segments, data_region, &records)
    }

    /// Assembles an archive around an already built run of DVCT and FVCT
    /// records
    fn archive_from_records(num_segments: u32, data_region: &[u8], records: &[u8]) -> Vec<u8> {
        let mut buf = vec![0u8; SEGMENT_DATA_START];
        buf[..4].copy_from_slice(b"SVCT");
        buf[0x12] = 0x03;
        buf[0x13] = 0x03;
        buf[0x14..0x18].copy_from_slice(&num_segments.to_be_bytes());
        buf.extend_from_slice(data_region);
        let cvct = u32::try_from(buf.len()).unwrap();
        buf[0x24..0x28].copy_from_slice(&cvct.to_be_bytes());
        buf.extend_from_slice(b"CVCT");
        buf.extend_from_slice(records);
        buf
    }

    /// An archive of small files, each stored on its own, laid out by
    /// `layout`: `Ok((name, depth, contents))` is a file and
    /// `Err((name, depth))` a folder
    #[allow(clippy::type_complexity)]
    fn tree_archive(layout: &[Result<(&'static str, u16, &[u8]), (&str, u16)>]) -> Vec<u8> {
        let mut region = Vec::new();
        let mut records = Vec::new();
        for item in layout {
            match *item {
                Err((name, depth)) => records.extend(dvct_record(name, depth)),
                Ok((name, depth, contents)) => {
                    let blob = vise_encode(contents);
                    let file = TestFile {
                        name,
                        depth,
                        segment: 1,
                        data_offset: u32::try_from(SEGMENT_DATA_START + region.len()).unwrap(),
                        comp_data: u32::try_from(blob.len()).unwrap(),
                        uncomp_data: u32::try_from(contents.len()).unwrap(),
                        crc32: crc(&[contents]),
                        ..TestFile::default()
                    };
                    region.extend_from_slice(&blob);
                    records.extend(fvct_record(&file));
                }
            }
        }
        archive_from_records(1, &region, &records)
    }

    #[test]
    fn folder_paths_cannot_outgrow_the_table() {
        // 63 nested folders with long names, then many short-named folders
        // at the bottom: each of those costs a path of 12 KB for a record
        // of a hundred bytes
        let long = "n".repeat(200);
        let mut records = Vec::new();
        for depth in 0..63 {
            records.extend(dvct_record(&long, depth));
        }
        let nested = records.clone();
        for _ in 0..2000 {
            records.extend(dvct_record("x", 63));
        }
        let parse = |records: &[u8]| Archive::parse(archive_from_records(1, &[], records));
        assert!(matches!(parse(&records), Err(Error::InvalidArchive(_))));
        // deep nesting on its own is fine
        assert!(parse(&nested).is_ok());
    }

    #[test]
    fn folders_nest_by_depth() {
        let bytes = tree_archive(&[
            Err(("App", 0)),
            Err(("Contents", 1)),
            Ok(("Info", 2, b"app info")),
            Err(("Resources", 2)),
            Ok(("Strings", 3, b"app strings")),
            // back up two levels without a folder record in between
            Ok(("Read Me", 1, b"read me")),
            // a second bundle reuses the same folder and file names
            Err(("Plugin", 0)),
            Err(("Contents", 1)),
            Ok(("Info", 2, b"plugin info")),
            Err(("Empty", 1)),
            Ok(("Loose", 0, b"at the root")),
        ]);
        let archive = Archive::parse(bytes).unwrap();

        let dirs: Vec<&str> = archive.files().map(|f| &*f.dir).collect();
        assert_eq!(
            dirs,
            [
                "App:Contents",
                "App:Contents:Resources",
                "App",
                "Plugin:Contents",
                ""
            ]
        );

        let tmp = tempfile::tempdir().unwrap();
        let result = archive.extract(tmp.path()).unwrap();
        assert_eq!(result.extracted, 5);
        assert_eq!(result.failed, 0);
        let read = |p: &str| fs::read(tmp.path().join(p)).unwrap();
        assert_eq!(read("App/Contents/Info"), b"app info");
        assert_eq!(read("App/Contents/Resources/Strings"), b"app strings");
        assert_eq!(read("App/Read Me"), b"read me");
        assert_eq!(read("Plugin/Contents/Info"), b"plugin info");
        assert_eq!(read("Loose"), b"at the root");
        // a folder with nothing in it is still created
        assert!(tmp.path().join("Plugin/Empty").is_dir());
    }

    #[test]
    fn slash_in_a_name_stays_one_file() {
        let bytes = tree_archive(&[Err(("In/Out", 0)), Ok(("Read/Write", 1, b"one file"))]);
        let archive = Archive::parse(bytes).unwrap();
        // the table keeps the real names
        assert_eq!(archive.files().next().unwrap().name, "Read/Write");

        let tmp = tempfile::tempdir().unwrap();
        archive.extract(tmp.path()).unwrap();
        assert_eq!(
            fs::read(tmp.path().join("In_Out/Read_Write")).unwrap(),
            b"one file"
        );
    }

    #[test]
    fn same_path_twice_keeps_both_files() {
        let bytes = tree_archive(&[
            Ok(("notes.txt", 0, b"first")),
            Ok(("Notes.TXT", 0, b"second")),
            Ok(("notes.txt", 0, b"third")),
        ]);
        let archive = Archive::parse(bytes).unwrap();
        let tmp = tempfile::tempdir().unwrap();
        let mut names = Vec::new();
        let result = archive
            .extract_with(tmp.path(), |p| {
                if let Progress::Extracted { name, .. } = p {
                    names.push(name.to_string());
                }
            })
            .unwrap();
        assert_eq!(result.extracted, 3);
        // names differing only in case count as the same path
        assert_eq!(names, ["notes.txt", "Notes (2).TXT", "notes (3).txt"]);
        assert_eq!(fs::read(tmp.path().join("notes.txt")).unwrap(), b"first");
        assert_eq!(
            fs::read(tmp.path().join("Notes (2).TXT")).unwrap(),
            b"second"
        );
        assert_eq!(
            fs::read(tmp.path().join("notes (3).txt")).unwrap(),
            b"third"
        );
    }

    #[test]
    fn used_paths_numbers_before_the_extension() {
        let mut used = UsedPaths::default();
        assert_eq!(
            used.claim("a/b.tar.gz".into(), Companion::None),
            "a/b.tar.gz"
        );
        assert_eq!(
            used.claim("a/b.tar.gz".into(), Companion::None),
            "a/b.tar (2).gz"
        );
        assert_eq!(used.claim("a/.hidden".into(), Companion::None), "a/.hidden");
        assert_eq!(
            used.claim("a/.hidden".into(), Companion::None),
            "a/.hidden (2)"
        );
        // a dot in a folder name is not an extension
        assert_eq!(used.claim("v1.2/file".into(), Companion::None), "v1.2/file");
        assert_eq!(
            used.claim("v1.2/file".into(), Companion::None),
            "v1.2/file (2)"
        );
        // a file with a resource fork also needs its `.rsrc` name free
        assert_eq!(used.claim("x.rsrc".into(), Companion::None), "x.rsrc");
        assert_eq!(used.claim("x".into(), Companion::Suffix(".rsrc")), "x (2)");
    }

    #[test]
    fn wrong_checksum_fails_the_file_and_writes_nothing() {
        let good = b"contents that match their checksum";
        let blob = vise_encode(good);
        let file = |name, crc32| TestFile {
            name,
            segment: 1,
            data_offset: u32::try_from(SEGMENT_DATA_START).unwrap(),
            comp_data: u32::try_from(blob.len()).unwrap(),
            uncomp_data: u32::try_from(good.len()).unwrap(),
            crc32,
            ..TestFile::default()
        };
        let mut records = fvct_record(&file("Good", crc(&[good])));
        records.extend(fvct_record(&file("Bad", crc(&[good]) ^ 1)));
        let archive = Archive::parse(archive_from_records(1, &blob, &records)).unwrap();

        let files: Vec<&FileEntry> = archive.files().collect();
        assert_eq!(archive.read(files[0]).unwrap().data, good);
        assert!(matches!(
            archive.read(files[1]),
            Err(Error::Checksum { expected, actual })
                if actual == crc(&[good]) && expected == actual ^ 1
        ));

        let tmp = tempfile::tempdir().unwrap();
        let result = archive.extract(tmp.path()).unwrap();
        assert_eq!((result.extracted, result.failed), (1, 1));
        assert!(tmp.path().join("Good").exists());
        assert!(!tmp.path().join("Bad").exists());
    }

    #[test]
    fn segment_zero_is_skipped_in_a_single_segment_archive() {
        let data = b"stored once, under segment 1";
        let blob = vise_encode(data);
        let file = |segment| TestFile {
            name: "File",
            segment,
            data_offset: u32::try_from(SEGMENT_DATA_START).unwrap(),
            comp_data: u32::try_from(blob.len()).unwrap(),
            uncomp_data: u32::try_from(data.len()).unwrap(),
            crc32: crc(&[data]),
            ..TestFile::default()
        };
        let mut records = fvct_record(&file(1));
        records.extend(fvct_record(&file(0)));
        let archive = Archive::parse(archive_from_records(1, &blob, &records)).unwrap();

        let files: Vec<&FileEntry> = archive.files().collect();
        assert_eq!(archive.read(files[0]).unwrap().data, data);
        assert!(matches!(
            archive.read(files[1]),
            Err(Error::Skipped(SkipReason::OnDisc))
        ));
    }

    #[test]
    fn extraction_restores_modification_times() {
        // 2001-01-01 00:00:00 UTC, as seconds since 1904
        let mac_secs = 3_061_152_000u32;
        let data = b"dated";
        let blob = vise_encode(data);
        let records = fvct_record(&TestFile {
            name: "Dated",
            segment: 1,
            data_offset: u32::try_from(SEGMENT_DATA_START).unwrap(),
            comp_data: u32::try_from(blob.len()).unwrap(),
            uncomp_data: u32::try_from(data.len()).unwrap(),
            crc32: crc(&[data]),
            modified: mac_secs,
            ..TestFile::default()
        });
        let archive = Archive::parse(archive_from_records(1, &blob, &records)).unwrap();
        let expected = SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(978_307_200);
        assert_eq!(
            archive.files().next().unwrap().modified_time(),
            Some(expected)
        );

        let tmp = tempfile::tempdir().unwrap();
        archive.extract(tmp.path()).unwrap();
        let on_disk = fs::metadata(tmp.path().join("Dated"))
            .unwrap()
            .modified()
            .unwrap();
        assert_eq!(on_disk, expected);
    }

    fn extract_sample_as(forks: ForkFormat) -> (Sample, tempfile::TempDir, Vec<String>) {
        let s = sample();
        let archive = Archive::parse(s.archive.clone()).unwrap();
        let tmp = tempfile::tempdir().unwrap();
        let options = ExtractOptions::default().with_forks(forks);
        let mut names = Vec::new();
        let result = archive
            .extract_with_options(tmp.path(), &options, |p| {
                if let Progress::Extracted { name, .. } = p {
                    names.push(name.to_string());
                }
            })
            .unwrap();
        assert_eq!((result.extracted, result.failed), (5, 0));
        (s, tmp, names)
    }

    #[test]
    fn appledouble_puts_the_resource_fork_in_a_sidecar() {
        let (s, tmp, names) = extract_sample_as(ForkFormat::AppleDouble);
        let dir = tmp.path().join("Folder");
        assert_eq!(names[1], "Folder/Beta");
        assert_eq!(fs::read(dir.join("Beta")).unwrap(), s.beta_data);
        assert!(!dir.join("Beta.rsrc").exists());

        let sidecar = fs::read(dir.join("._Beta")).unwrap();
        assert_eq!(&sidecar[..4], &[0x00, 0x05, 0x16, 0x07]);
        // the resource fork is the last entry, so it ends the file
        assert!(sidecar.ends_with(&s.beta_rsrc));

        // every file gets a sidecar for its Finder information, with or
        // without a resource fork, and an empty file still exists
        assert!(dir.join("._Alpha").exists());
        assert_eq!(fs::read(dir.join("Empty")).unwrap(), b"");
        assert!(dir.join("._Empty").exists());
    }

    #[test]
    fn macbinary_wraps_both_forks_in_one_file() {
        let (s, tmp, names) = extract_sample_as(ForkFormat::MacBinary);
        let dir = tmp.path().join("Folder");
        assert_eq!(names[1], "Folder/Beta.bin");
        assert!(!dir.join("Beta").exists());
        assert!(!dir.join("Beta.rsrc").exists());

        let bin = fs::read(dir.join("Beta.bin")).unwrap();
        assert_eq!(&bin[2..2 + usize::from(bin[1])], b"Beta");
        let data_len = u32::from_be_bytes(bin[83..87].try_into().unwrap()) as usize;
        let rsrc_len = u32::from_be_bytes(bin[87..91].try_into().unwrap()) as usize;
        assert_eq!(&bin[128..128 + data_len], &s.beta_data[..]);
        let rsrc_at = 128 + data_len.next_multiple_of(128);
        assert_eq!(&bin[rsrc_at..rsrc_at + rsrc_len], &s.beta_rsrc[..]);
        assert_eq!(bin.len(), rsrc_at + rsrc_len.next_multiple_of(128));
    }

    #[test]
    fn appledouble_sidecar_names_are_reserved() {
        let mut used = UsedPaths::default();
        assert_eq!(used.claim("d/._x".into(), Companion::None), "d/._x");
        // "d/x" would need "d/._x" for its sidecar, which is taken
        assert_eq!(used.claim("d/x".into(), Companion::AppleDouble), "d/x (2)");
        assert_eq!(
            used.claim("d/._x (2)".into(), Companion::None),
            "d/._x (2) (2)"
        );
    }

    #[test]
    fn a_lone_entry_inside_a_block_is_read_at_its_block_offset() {
        // one block holding three things; only the first and last belong to
        // file entries, so nothing marks the block as shared
        let icon = text("resource-only icon ", 12);
        let middle = text("bytes of an entry that is not a file ", 9);
        let payload = text("the file's data fork ", 15);
        let block: Vec<u8> = [icon.as_slice(), &middle, &payload].concat();
        let blob = vise_encode(&block);
        let len = |v: &[u8]| u32::try_from(v.len()).unwrap();
        let base = u32::try_from(SEGMENT_DATA_START).unwrap();

        let mut records = fvct_record(&TestFile {
            // no data fork: the compressed size is the block's, the data
            // size is zero, and the resource fork is at the block's start
            name: "Icon",
            segment: 1,
            data_offset: base,
            comp_data: len(&blob),
            uncomp_data: 0,
            comp_rsrc: len(&block),
            uncomp_rsrc: len(&icon),
            block_rsrc_off: 0,
            crc32: crc(&[&icon]),
            ..TestFile::default()
        });
        // a second copy of the same block for the entry read on its own
        let second_at = base + len(&blob);
        records.extend(fvct_record(&TestFile {
            name: "Payload",
            segment: 1,
            data_offset: second_at,
            comp_data: len(&blob),
            uncomp_data: len(&payload),
            block_data_off: len(&icon) + len(&middle),
            crc32: crc(&[&payload]),
            ..TestFile::default()
        }));
        let region: Vec<u8> = [blob.as_slice(), &blob].concat();
        let archive = Archive::parse(archive_from_records(1, &region, &records)).unwrap();

        let files: Vec<&FileEntry> = archive.files().collect();
        let icon_forks = archive.read(files[0]).unwrap();
        assert_eq!(icon_forks.data, b"");
        assert_eq!(icon_forks.rsrc, icon);
        assert_eq!(archive.read(files[1]).unwrap().data, payload);

        // the file with only a resource fork still exists under its own name
        let tmp = tempfile::tempdir().unwrap();
        let result = archive.extract(tmp.path()).unwrap();
        assert_eq!((result.extracted, result.failed), (2, 0));
        assert_eq!(fs::read(tmp.path().join("Icon")).unwrap(), b"");
        assert_eq!(fs::read(tmp.path().join("Icon.rsrc")).unwrap(), icon);
        assert_eq!(fs::read(tmp.path().join("Payload")).unwrap(), payload);
    }

    /// A record as the Mac OS X installers lay it out: two more bytes of
    /// fields before the name length, and the name moved from `name_at.0`
    /// to `name_at.1`
    fn osx_record(mut record: Vec<u8>, name_len_at: usize, name_at: (usize, usize)) -> Vec<u8> {
        record.splice(name_len_at..name_len_at, [0, 0]);
        let (from, to) = (name_at.0 + 2, name_at.1);
        record.splice(from..from, vec![0; to - from]);
        record
    }

    #[test]
    fn osx_installer_reads_its_data_from_the_data_file() {
        let contents = text("a file from an OS X installer bundle ", 10);
        let blob = vise_encode(&contents);
        let len = |v: &[u8]| u32::try_from(v.len()).unwrap();
        let file = TestFile {
            name: "Info.plist",
            segment: 1,
            depth: 1,
            data_offset: u32::try_from(SEGMENT_DATA_START).unwrap(),
            comp_data: len(&blob),
            uncomp_data: len(&contents),
            crc32: crc(&[&contents]),
            ..TestFile::default()
        };
        // name length sits at 80 in a folder record and 122 in a file record
        let mut records = osx_record(dvct_record("Contents", 0), 80, (88, 178));
        records.extend(osx_record(fvct_record(&file), 122, (124, 212)));

        // the table file is the installer program: header, program, table
        let program = vec![0xC3u8; 4000];
        let mut table = archive_from_records(1, &program, &records);
        table[0x12] = 0x0b;
        table[0x13] = 0;
        table[0x08..0x0c].copy_from_slice(&len(&program).to_be_bytes());
        // the data file is a header and the file data
        let mut data_file = table[..SEGMENT_DATA_START].to_vec();
        data_file.extend_from_slice(&blob);

        let paired =
            Archive::parse_with_data_file(&table, data_file.clone(), NameEncoding::MacRoman)
                .unwrap();
        let entry = paired.files().next().unwrap();
        assert_eq!(
            (entry.name.as_str(), &*entry.dir),
            ("Info.plist", "Contents")
        );
        assert_eq!(paired.read(entry).unwrap().data, contents);

        // on its own the table file has no data: nothing is decoded out of
        // the program that sits where data would be
        let alone = Archive::parse(table.clone()).unwrap();
        assert!(matches!(
            alone.read(alone.files().next().unwrap()),
            Err(Error::Skipped(SkipReason::MissingData))
        ));
        // and the data file is not an archive without its table
        assert!(Archive::parse(data_file).is_err());
        assert!(
            Archive::parse_with_data_file(
                &table,
                b"not a data file".to_vec(),
                NameEncoding::MacRoman
            )
            .is_err()
        );

        // an installer that keeps both in one file needs nothing else
        let mut single = archive_from_records(1, &blob, &records);
        single[0x12] = 0x0b;
        single[0x13] = 0;
        let single = Archive::parse(single).unwrap();
        assert_eq!(
            single.read(single.files().next().unwrap()).unwrap().data,
            contents
        );
    }

    #[test]
    fn parallel_map_keeps_index_order() {
        let squares = parallel_map(1000, |i| i * i);
        assert_eq!(squares.len(), 1000);
        assert!(squares.iter().enumerate().all(|(i, &v)| v == i * i));
        assert_eq!(parallel_map(0, |i| i), [] as [usize; 0]);
        assert_eq!(parallel_map(1, |i| i + 7), [7]);
    }

    #[test]
    fn many_files_extract_the_same_across_batches() {
        // more files than one batch holds, mixing lone files and a shared block
        let contents: Vec<Vec<u8>> = (0..BATCH_ENTRIES + 50)
            .map(|i| format!("file number {i} ").repeat(1 + i % 7).into_bytes())
            .collect();
        let names: Vec<&'static str> = (0..contents.len())
            .map(|i| &*Box::leak(format!("f{i}").into_boxed_str()))
            .collect();
        let layout: Vec<_> = contents
            .iter()
            .zip(&names)
            .map(|(c, &n)| Ok((n, 0, c.as_slice())))
            .collect();
        let archive = Archive::parse(tree_archive(&layout)).unwrap();

        let tmp = tempfile::tempdir().unwrap();
        let mut order = Vec::new();
        let result = archive
            .extract_with(tmp.path(), |p| {
                if let Progress::Extracted { name, .. } = p {
                    order.push(name.to_string());
                }
            })
            .unwrap();
        assert_eq!(result.extracted, contents.len());
        // progress arrives in table order whatever order the threads finish in
        assert!(order.iter().map(String::as_str).eq(names.iter().copied()));
        for (name, expected) in names.iter().zip(&contents) {
            assert_eq!(&fs::read(tmp.path().join(name)).unwrap(), expected);
        }
    }

    #[test]
    fn mac_paths_keep_each_name_as_one_component() {
        assert_eq!(mac_rel_path("A:B", "file"), "A/B/file");
        assert_eq!(mac_rel_path("", "file"), "file");
        assert_eq!(mac_rel_path("A:B", ""), "A/B");
        assert_eq!(mac_rel_path("A/B:C\\D", "e/f"), "A_B/C_D/e_f");
        // nothing a name holds can climb out of the output folder
        assert_eq!(mac_rel_path("..:.", ".."), "");
        assert_eq!(mac_rel_path("..:x", "../../y"), "x/.._.._y");
        // leading and trailing spaces are part of a Mac name
        assert_eq!(mac_rel_path(" A ", " b "), " A / b ");
    }

    struct Sample {
        archive: Vec<u8>,
        alpha: Vec<u8>,
        beta_data: Vec<u8>,
        beta_rsrc: Vec<u8>,
        gamma: Vec<u8>,
        delta: Vec<u8>,
    }

    /// One archive covering each storage shape: a lone data fork, data plus
    /// resource fork, two files in one shared block, an empty file, and a
    /// condition record
    fn sample() -> Sample {
        let alpha = text("alpha data fork. ", 40);
        let beta_data = text("beta data. ", 30);
        let beta_rsrc = text("beta resources! ", 25);
        let gamma = text("gamma shares a block. ", 20);
        let delta = text("delta is second in the block. ", 20);

        let mut region = Vec::new();
        let base = u32::try_from(SEGMENT_DATA_START).unwrap();
        let mut place = |blob: &[u8]| {
            let off = base + u32::try_from(region.len()).unwrap();
            region.extend_from_slice(blob);
            (off, u32::try_from(blob.len()).unwrap())
        };

        let (alpha_off, alpha_comp) = place(&vise_encode(&alpha));
        let (beta_off, beta_comp) = place(&vise_encode(&beta_data));
        let (_, beta_rsrc_comp) = place(&vise_encode(&beta_rsrc));
        let shared: Vec<u8> = [gamma.as_slice(), delta.as_slice()].concat();
        let (shared_off, shared_comp) = place(&vise_encode(&shared));

        let len = |v: &[u8]| u32::try_from(v.len()).unwrap();
        // every file sits one level down, inside "Folder", in segment 1
        let in_folder = || TestFile {
            segment: 1,
            depth: 1,
            ..TestFile::default()
        };
        let files = [
            TestFile {
                name: "Alpha",
                data_offset: alpha_off,
                comp_data: alpha_comp,
                uncomp_data: len(&alpha),
                crc32: crc(&[&alpha]),
                ..in_folder()
            },
            TestFile {
                name: "Beta",
                data_offset: beta_off,
                comp_data: beta_comp,
                uncomp_data: len(&beta_data),
                comp_rsrc: beta_rsrc_comp,
                uncomp_rsrc: len(&beta_rsrc),
                crc32: crc(&[&beta_data, &beta_rsrc]),
                ..in_folder()
            },
            TestFile {
                name: "Gamma",
                data_offset: shared_off,
                comp_data: shared_comp,
                uncomp_data: len(&gamma),
                crc32: crc(&[&gamma]),
                ..in_folder()
            },
            TestFile {
                name: "Delta",
                data_offset: shared_off,
                comp_data: shared_comp,
                uncomp_data: len(&delta),
                block_data_off: len(&gamma),
                crc32: crc(&[&delta]),
                ..in_folder()
            },
            TestFile {
                name: "Empty",
                ..in_folder()
            },
            TestFile {
                name: "Condition",
                flags: 0x0800_0000,
                ..in_folder()
            },
        ];

        Sample {
            archive: build_archive(1, &region, &files),
            alpha,
            beta_data,
            beta_rsrc,
            gamma,
            delta,
        }
    }

    #[test]
    fn reads_every_storage_shape() {
        let s = sample();
        let archive = Archive::parse(s.archive).unwrap();
        let files: Vec<&FileEntry> = archive.files().collect();
        let names: Vec<&str> = files.iter().map(|f| f.name.as_str()).collect();
        assert_eq!(
            names,
            ["Alpha", "Beta", "Gamma", "Delta", "Empty", "Condition"]
        );

        let mut reader = archive.reader();
        assert_eq!(reader.read(files[0]).unwrap().data, s.alpha);
        let beta = reader.read(files[1]).unwrap();
        assert_eq!(beta.data, s.beta_data);
        assert_eq!(beta.rsrc, s.beta_rsrc);
        assert_eq!(reader.read(files[2]).unwrap().data, s.gamma);
        assert_eq!(reader.read(files[3]).unwrap().data, s.delta);
        assert_eq!(reader.read(files[4]).unwrap(), Forks::default());
        assert!(matches!(
            reader.read(files[5]),
            Err(Error::Skipped(SkipReason::Condition { flags: 0x0800_0000 }))
        ));

        // out of table order, a fresh read still finds the shared block
        assert_eq!(archive.read(files[3]).unwrap().data, s.delta);
        assert_eq!(archive.read(files[2]).unwrap().data, s.gamma);
    }

    #[test]
    fn extracts_to_disk_and_reports_progress() {
        let s = sample();
        let archive = Archive::parse(s.archive).unwrap();
        let tmp = tempfile::tempdir().unwrap();

        let mut events = Vec::new();
        let result = archive
            .extract_with(tmp.path(), |p| {
                events.push(match p {
                    Progress::Extracted {
                        name,
                        data_len,
                        rsrc_len,
                    } => format!("ok {name} {data_len} {rsrc_len:?}"),
                    Progress::Skipped { name, reason } => format!("skip {name}: {reason}"),
                    other => format!("{other:?}"),
                });
            })
            .unwrap();

        assert_eq!(result.extracted, 5);
        assert_eq!(result.skipped, 1);
        assert_eq!(result.failed, 0);

        let dir = tmp.path().join("Folder");
        assert_eq!(fs::read(dir.join("Alpha")).unwrap(), s.alpha);
        assert_eq!(fs::read(dir.join("Beta")).unwrap(), s.beta_data);
        assert_eq!(fs::read(dir.join("Beta.rsrc")).unwrap(), s.beta_rsrc);
        assert_eq!(fs::read(dir.join("Gamma")).unwrap(), s.gamma);
        assert_eq!(fs::read(dir.join("Delta")).unwrap(), s.delta);
        // a file with both forks empty is still created
        assert_eq!(fs::read(dir.join("Empty")).unwrap(), b"");
        assert!(!dir.join("Alpha.rsrc").exists());
        assert!(!dir.join("Condition").exists());

        assert_eq!(events.len(), 6);
        assert_eq!(
            events[1],
            format!(
                "ok Folder/Beta {} Some({})",
                s.beta_data.len(),
                s.beta_rsrc.len()
            )
        );
        assert_eq!(
            events[5],
            "skip Folder/Condition: condition record (flags 0x08000000)"
        );
    }

    #[test]
    fn corrupt_entry_fails_without_stopping_the_run() {
        let s = sample();
        let mut bytes = s.archive;
        // damage Alpha's compressed data; the other files are untouched
        for b in &mut bytes[SEGMENT_DATA_START..SEGMENT_DATA_START + 8] {
            *b ^= 0xff;
        }
        let archive = Archive::parse(bytes).unwrap();
        let tmp = tempfile::tempdir().unwrap();
        let result = archive.extract(tmp.path()).unwrap();
        assert_eq!(result.failed, 1);
        assert_eq!(result.extracted, 4);
        assert_eq!(fs::read(tmp.path().join("Folder/Delta")).unwrap(), s.delta);
    }

    /// A two-segment set: `Near` is in the main file, `Far` in segment 2
    fn segmented() -> (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>) {
        let near = text("near, in the main file. ", 20);
        let far = text("far, in segment two. ", 20);
        let near_blob = vise_encode(&near);
        let far_blob = vise_encode(&far);

        let len = |v: &[u8]| u32::try_from(v.len()).unwrap();
        let base = u32::try_from(SEGMENT_DATA_START).unwrap();
        // segment data is appended where the main file's table starts
        let main_data_end = base + len(&near_blob);
        let files = [
            TestFile {
                name: "Near",
                segment: 1,
                data_offset: base,
                comp_data: len(&near_blob),
                uncomp_data: len(&near),
                crc32: crc(&[&near]),
                ..TestFile::default()
            },
            TestFile {
                name: "Far",
                segment: 2,
                data_offset: main_data_end,
                comp_data: len(&far_blob),
                uncomp_data: len(&far),
                crc32: crc(&[&far]),
                ..TestFile::default()
            },
        ];
        let main = build_archive(2, &near_blob, &files);
        (main, segment_file(2, &far_blob), near, far)
    }

    fn segment_file(seq: u32, payload: &[u8]) -> Vec<u8> {
        let mut seg = vec![0u8; SEGMENT_DATA_START];
        seg[..4].copy_from_slice(b"SVCT");
        seg[4..8].copy_from_slice(&seq.to_be_bytes());
        seg.extend_from_slice(payload);
        // parse_with_segments wants at least four bytes past the header
        seg.resize(seg.len().max(SEGMENT_DATA_START + 4), 0);
        seg
    }

    #[test]
    fn reads_across_segments() {
        let (main, seg2, near, far) = segmented();

        let archive = Archive::parse_with_segments(main.clone(), &[seg2]).unwrap();
        let files: Vec<&FileEntry> = archive.files().collect();
        assert_eq!(archive.read(files[0]).unwrap().data, near);
        assert_eq!(archive.read(files[1]).unwrap().data, far);

        // without the segment file, only the main file's entry is readable
        let alone = Archive::parse(main).unwrap();
        let files: Vec<&FileEntry> = alone.files().collect();
        assert_eq!(alone.read(files[0]).unwrap().data, near);
        assert!(matches!(
            alone.read(files[1]),
            Err(Error::Skipped(SkipReason::SegmentNotLoaded(2)))
        ));
    }

    #[test]
    fn segments_must_be_contiguous_and_unique() {
        let (main, seg2, _, _) = segmented();
        let seg3 = segment_file(3, b"third");
        let seg4 = segment_file(4, b"fourth");

        // any order is fine
        assert!(Archive::parse_with_segments(main.clone(), &[seg3.clone(), seg2.clone()]).is_ok());
        // a gap, a repeat, and a set that does not start at 2 are all refused
        assert!(Archive::parse_with_segments(main.clone(), &[seg2.clone(), seg4]).is_err());
        assert!(Archive::parse_with_segments(main.clone(), &[seg2.clone(), seg2]).is_err());
        assert!(Archive::parse_with_segments(main, &[seg3]).is_err());
    }
}

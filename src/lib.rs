//! Extractor for Installer VISE archives (`MindVision`, 1990s-2000s)
//!
//! Supports Mac VISE format versions from 00 01 through 03 0e and Windows
//! VISE installers (PE executables with `_mvdata` section or overlay)
//!
//! Mac formats:
//! - v2 (00 01, 02 0x): byte-swap + substitution cipher + DEFLATE (same as v3)
//! - v3 (03 00 - 03 05): byte-swap + substitution cipher + word-aligned DEFLATE
//! - v3.06-07: new-style CVCT header with chunk-type table
//! - v3.08-0e: CVCT body compressed with word-aligned DEFLATE
//!
//! Windows formats:
//! - PE with `_mvdata` section or overlay: byte-swap + DEFLATE
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

pub(crate) mod deflate;
mod mac;
pub mod macbinary;
pub mod pe;
pub mod win;

use std::borrow::Cow;
use std::collections::HashMap;
use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};

pub use mac::{ArchiveInfo, Entry, FileEntry};
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

/// Decompression internals re-exported for the fuzz targets under the `fuzzing`
/// feature only, not public API
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
    #[error("decompression failed: {0}")]
    Decompression(String),
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    /// The entry exists in the file table but has no data to return
    #[error("entry not extractable: {0}")]
    Skipped(SkipReason),
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
    /// The file's data lies past the end of the loaded archive
    MissingData,
    /// The name is empty once sanitized
    EmptyName,
    /// The name would escape the output directory
    UnsafePath,
    /// Windows stub installer whose companion `.qdat` volume was not supplied
    MissingQdat,
}

impl fmt::Display for SkipReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Condition { flags } => write!(f, "condition record (flags 0x{flags:08x})"),
            Self::OnDisc => f.write_str("on the distribution disc"),
            Self::SegmentNotLoaded(n) => write!(f, "segment {n} not loaded"),
            Self::MissingData => f.write_str("data is past the end of the archive"),
            Self::EmptyName => f.write_str("empty name"),
            Self::UnsafePath => f.write_str("unsafe path"),
            Self::MissingQdat => f.write_str("companion .qdat not available"),
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
    /// (a condition record, or a file on another segment or disc), or
    /// [`Error::Decompression`] if its data cannot be decoded
    pub fn read(&mut self, entry: &FileEntry) -> Result<Forks, Error> {
        let archive = self.archive;
        if let Some(reason) = archive.skip_reason(entry, &mut self.cache) {
            return Err(Error::Skipped(reason));
        }
        let data = if entry.comp_data > 0 {
            archive.read_data(entry, &mut self.cache)?.into_owned()
        } else {
            Vec::new()
        };
        let rsrc = if entry.has_rsrc() {
            archive.read_rsrc(entry, &mut self.cache)?.into_owned()
        } else {
            Vec::new()
        };
        Ok(Forks { data, rsrc })
    }

    /// Decodes both forks and discards them, without copying shared slices
    #[cfg(feature = "fuzzing")]
    fn decompress_only(&mut self, entry: &FileEntry) -> Result<(), Error> {
        let archive = self.archive;
        if let Some(reason) = archive.skip_reason(entry, &mut self.cache) {
            return Err(Error::Skipped(reason));
        }
        if entry.comp_data > 0 {
            archive.read_data(entry, &mut self.cache)?;
        }
        if entry.has_rsrc() {
            archive.read_rsrc(entry, &mut self.cache)?;
        }
        Ok(())
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
        let info = mac::parse(&data)?;
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
        let info = mac::parse(&data)?;
        if segments.is_empty() {
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

    fn new(data: Vec<u8>, info: ArchiveInfo, segments_loaded: bool) -> Self {
        let mut groups: HashMap<usize, BlockGroup> = HashMap::new();
        for f in info.entries.iter().filter_map(Entry::as_file) {
            if f.comp_data > 0
                && !f.is_stub()
                && (info.num_segments <= 1
                    || (f.segment != 0 && (segments_loaded || f.segment == 1)))
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
    /// Returns [`Error::Io`] if a directory cannot be created
    pub fn extract(&self, out_dir: &Path) -> Result<ExtractResult, Error> {
        self.extract_with(out_dir, |_| {})
    }

    /// Like [`Archive::extract`], and reports each entry to `on_progress` as
    /// it is handled
    ///
    /// # Errors
    ///
    /// Returns [`Error::Io`] if a directory cannot be created
    pub fn extract_with(
        &self,
        out_dir: &Path,
        mut on_progress: impl FnMut(Progress<'_>),
    ) -> Result<ExtractResult, Error> {
        fs::create_dir_all(out_dir)?;

        let mut cache = BlockCache::default();
        let mut cur_dir = out_dir.to_path_buf();
        // the current directory relative to `out_dir`, for progress reports
        let mut cur_rel = String::new();
        let mut result = ExtractResult::default();

        let output_budget = self
            .data
            .len()
            .saturating_mul(OUTPUT_BUDGET_RATIO)
            .saturating_add(OUTPUT_BUDGET_HEADROOM);
        let mut total_out: usize = 0;

        for entry in &self.info.entries {
            match entry {
                Entry::Dir(name) => {
                    let name = clean_name(name);
                    if name.is_empty() {
                        continue;
                    }
                    match safe_join(out_dir, &name) {
                        Some(dir) => {
                            cur_dir = dir;
                            cur_rel.clone_from(&name);
                            fs::create_dir_all(&cur_dir)?;
                        }
                        None => on_progress(Progress::Skipped {
                            name: &name,
                            reason: SkipReason::UnsafePath,
                        }),
                    }
                }
                Entry::File(f) => {
                    let name = clean_name(&f.name);
                    // reported names are paths relative to `out_dir`
                    let shown = if name.is_empty() || cur_rel.is_empty() {
                        name.clone()
                    } else {
                        format!("{cur_rel}/{name}")
                    };
                    let mut skip = |reason| {
                        on_progress(Progress::Skipped {
                            name: &shown,
                            reason,
                        });
                    };

                    if let Some(reason) = self.skip_reason(f, &mut cache) {
                        skip(reason);
                        result.skipped += 1;
                        continue;
                    }
                    if name.is_empty() {
                        skip(SkipReason::EmptyName);
                        result.skipped += 1;
                        continue;
                    }
                    let Some(path) = safe_join(&cur_dir, &name) else {
                        skip(SkipReason::UnsafePath);
                        result.skipped += 1;
                        continue;
                    };
                    if let Some(p) = path.parent() {
                        fs::create_dir_all(p)?;
                    }

                    match self.extract_file(f, &path, &mut cache) {
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
        if self.info.num_segments > 1 {
            // Segment 0 entries live on the distribution disc, not in the archive
            if f.segment == 0 {
                return Some(SkipReason::OnDisc);
            }
            // Without loaded segments, only segment 1 data is available
            if !self.segments_loaded && f.segment != 1 {
                return Some(SkipReason::SegmentNotLoaded(f.segment));
            }
        }
        let total = f
            .data_offset
            .saturating_add(f.comp_data)
            .saturating_add(f.comp_rsrc);
        if total > self.data.len() && self.shared_block(cache, f.data_offset).is_none() {
            return Some(SkipReason::MissingData);
        }
        None
    }

    /// Writes both forks and returns their lengths as `(data, rsrc)`
    fn extract_file(
        &self,
        f: &FileEntry,
        path: &Path,
        cache: &mut BlockCache,
    ) -> Result<(usize, usize), Error> {
        let mut data_len = 0;
        let mut rsrc_len = 0;

        if f.comp_data > 0 {
            let data = self.read_data(f, cache)?;
            fs::write(path, &data)?;
            data_len = data.len();
        } else if f.uncomp_data == 0 && !f.has_rsrc() {
            // both forks empty: still a file the installer would create
            fs::File::create(path)?;
        }

        if f.has_rsrc() {
            let data = self.read_rsrc(f, cache)?;
            let mut rsrc_path = path.as_os_str().to_owned();
            rsrc_path.push(".rsrc");
            fs::write(&rsrc_path, &data)?;
            rsrc_len = data.len();
        }

        Ok((data_len, rsrc_len))
    }

    /// The decompressed block at `offset`, if more than one entry reads from
    /// it and it decodes. `None` means "decompress the entry on its own"
    fn shared_block<'c>(&self, cache: &'c mut BlockCache, offset: usize) -> Option<&'c [u8]> {
        let group = self.groups.get(&offset)?;
        if group.members <= 1 {
            return None;
        }
        if cache.offset != Some(offset) {
            cache.offset = Some(offset);
            cache.block = offset
                .checked_add(group.max_comp)
                .filter(|&end| end <= self.data.len())
                .and_then(|end| deflate::decode_and_decompress(&self.data[offset..end], 0).ok());
        }
        cache.block.as_deref()
    }

    fn read_data<'c>(
        &self,
        f: &FileEntry,
        cache: &'c mut BlockCache,
    ) -> Result<Cow<'c, [u8]>, Error> {
        self.read_fork(
            cache,
            f.data_offset,
            Some(f.data_offset),
            f.comp_data,
            f.uncomp_data,
            f.block_data_off,
        )
    }

    fn read_rsrc<'c>(
        &self,
        f: &FileEntry,
        cache: &'c mut BlockCache,
    ) -> Result<Cow<'c, [u8]>, Error> {
        self.read_fork(
            cache,
            f.data_offset,
            f.data_offset.checked_add(f.comp_data),
            f.comp_rsrc,
            f.uncomp_rsrc,
            f.block_rsrc_off,
        )
    }

    /// Returns one fork: a slice of the shared block at `block_key` when the
    /// entry shares it, otherwise the `comp` bytes at `raw_off` decompressed
    /// on their own
    fn read_fork<'c>(
        &self,
        cache: &'c mut BlockCache,
        block_key: usize,
        raw_off: Option<usize>,
        comp: usize,
        uncomp: usize,
        block_off: usize,
    ) -> Result<Cow<'c, [u8]>, Error> {
        if let Some(block) = self.shared_block(cache, block_key) {
            let slice = block_off
                .checked_add(uncomp)
                .and_then(|end| block.get(block_off..end));
            if let Some(slice) = slice {
                return Ok(Cow::Borrowed(slice));
            }
        }
        let raw_off = raw_off
            .ok_or_else(|| Error::Decompression("fork offset exceeds archive bounds".into()))?;
        self.decompress_raw(raw_off, comp, uncomp).map(Cow::Owned)
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

    /// Assembles a single-file-table archive: SVCT header, the data region,
    /// then an old-style CVCT holding one directory and `files`
    fn build_archive(num_segments: u32, data_region: &[u8], files: &[TestFile]) -> Vec<u8> {
        let mut buf = vec![0u8; SEGMENT_DATA_START];
        buf[..4].copy_from_slice(b"SVCT");
        buf[0x12] = 0x03;
        buf[0x13] = 0x03;
        buf[0x14..0x18].copy_from_slice(&num_segments.to_be_bytes());
        buf.extend_from_slice(data_region);
        let cvct = u32::try_from(buf.len()).unwrap();
        buf[0x24..0x28].copy_from_slice(&cvct.to_be_bytes());
        buf.extend_from_slice(b"CVCT");
        buf.extend_from_slice(&dvct_record("Folder"));
        for f in files {
            buf.extend_from_slice(&fvct_record(f));
        }
        buf
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
        let files = [
            TestFile {
                name: "Alpha",
                data_offset: alpha_off,
                comp_data: alpha_comp,
                uncomp_data: len(&alpha),
                ..TestFile::default()
            },
            TestFile {
                name: "Beta",
                data_offset: beta_off,
                comp_data: beta_comp,
                uncomp_data: len(&beta_data),
                comp_rsrc: beta_rsrc_comp,
                uncomp_rsrc: len(&beta_rsrc),
                ..TestFile::default()
            },
            TestFile {
                name: "Gamma",
                data_offset: shared_off,
                comp_data: shared_comp,
                uncomp_data: len(&gamma),
                ..TestFile::default()
            },
            TestFile {
                name: "Delta",
                data_offset: shared_off,
                comp_data: shared_comp,
                uncomp_data: len(&delta),
                block_data_off: len(&gamma),
                ..TestFile::default()
            },
            TestFile {
                name: "Empty",
                ..TestFile::default()
            },
            TestFile {
                name: "Condition",
                flags: 0x0800_0000,
                ..TestFile::default()
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
                ..TestFile::default()
            },
            TestFile {
                name: "Far",
                segment: 2,
                data_offset: main_data_end,
                comp_data: len(&far_blob),
                uncomp_data: len(&far),
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

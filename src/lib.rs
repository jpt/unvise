//! Extractor for Installer VISE archives (`MindVision`, 1990s Mac)
//!
//! Supports all observed VISE versions from 00 01 through 03 07:
//! - v2 (00 01, 02 0x): LZSS with a 1024-byte circular window
//! - v3 (03 0x): byte-swap + substitution cipher + word-aligned DEFLATE

#![warn(clippy::pedantic)]

pub(crate) mod deflate;
pub(crate) mod lzss;
pub mod macbinary;
mod parse;

use std::borrow::Cow;
use std::collections::HashMap;
use std::fs;
use std::io::Write;
use std::path::Path;

pub use parse::{ArchiveInfo, Entry, FileEntry};

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    #[error("invalid archive: {0}")]
    InvalidArchive(String),
    #[error("decompression failed: {0}")]
    Decompression(String),
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}

/// A loaded VISE archive ready for extraction
#[derive(Debug)]
pub struct Archive {
    data: Vec<u8>,
    pub info: ArchiveInfo,
}

/// Outcome of an extraction run
#[derive(Debug)]
pub struct ExtractResult {
    pub extracted: usize,
    pub skipped: usize,
    pub failed: usize,
}

type OffsetGroups = HashMap<usize, Vec<usize>>;

impl Archive {
    /// Parses a VISE archive from raw bytes (after `MacBinary` stripping)
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArchive`] if the data is not a recognized VISE
    /// archive format
    pub fn parse(data: Vec<u8>) -> Result<Self, Error> {
        let info = parse::parse(&data)?;
        Ok(Self { data, info })
    }

    /// Extracts all available files to `out_dir`, creating directories as needed.
    /// Prints per-file progress and diagnostics to stderr
    ///
    /// # Errors
    ///
    /// Returns [`Error::Io`] on filesystem failures or [`Error::Decompression`]
    /// if any compressed block cannot be decoded
    pub fn extract(&self, out_dir: &Path) -> Result<ExtractResult, Error> {
        fs::create_dir_all(out_dir)?;

        let files: Vec<&FileEntry> = self.info.entries.iter()
            .filter_map(Entry::as_file)
            .collect();

        let offset_groups = self.build_offset_groups(&files);
        let shared_blocks = self.decompress_shared_blocks(&files, &offset_groups);

        let mut cur_dir = out_dir.to_path_buf();
        let mut result = ExtractResult { extracted: 0, skipped: 0, failed: 0 };

        for entry in &self.info.entries {
            match entry {
                Entry::Dir(name) => {
                    let name = clean_name(name);
                    if !name.is_empty() {
                        cur_dir = out_dir.join(&name);
                        fs::create_dir_all(&cur_dir)?;
                    }
                }
                Entry::File(f) => {
                    if let Some(reason) = self.skip_reason(f, &shared_blocks) {
                        eprintln!("  {reason}");
                        result.skipped += 1;
                        continue;
                    }

                    let name = clean_name(&f.name);
                    if name.is_empty() {
                        result.skipped += 1;
                        continue;
                    }

                    let path = cur_dir.join(&name);
                    if let Some(p) = path.parent() {
                        fs::create_dir_all(p)?;
                    }

                    if let Err(e) = self.extract_file(f, &path, &shared_blocks, &offset_groups) {
                        eprintln!("  FAIL {name}: {e}");
                        result.failed += 1;
                        continue;
                    }

                    eprintln!("  {name} ({} + {} bytes)", f.uncomp_data, f.uncomp_rsrc);
                    result.extracted += 1;
                }
            }
        }

        Ok(result)
    }

    fn skip_reason(&self, f: &FileEntry, shared_blocks: &HashMap<usize, Vec<u8>>) -> Option<String> {
        if f.is_stub() {
            let name = if f.name.is_empty() { "(unnamed)" } else { &f.name };
            return Some(format!("[condition] {name} (flags=0x{:08x})", f.flags));
        }
        if self.info.num_segments > 1 && f.segment != 1 {
            return Some(format!("[segment {}] {}", f.segment, clean_name(&f.name)));
        }
        let total = f.data_offset + f.comp_data + f.comp_rsrc;
        if total > self.data.len() && !shared_blocks.contains_key(&f.data_offset) {
            return Some(format!("[cross-segment] {} (data extends beyond segment 1)", clean_name(&f.name)));
        }
        None
    }

    fn extract_file(
        &self,
        f: &FileEntry,
        path: &Path,
        shared_blocks: &HashMap<usize, Vec<u8>>,
        offset_groups: &OffsetGroups,
    ) -> Result<(), Error> {
        if f.comp_data > 0 {
            let data = self.decompress_fork(
                f.data_offset, f.comp_data, f.uncomp_data,
                f.block_data_off, shared_blocks, offset_groups,
            )?;
            fs::File::create(path)?.write_all(&data)?;
        }

        if f.comp_rsrc > 0 && f.uncomp_rsrc > 0 {
            let data = self.decompress_rsrc(f, shared_blocks, offset_groups)?;
            let mut rsrc_path = path.as_os_str().to_owned();
            rsrc_path.push(".rsrc");
            fs::File::create(&rsrc_path)?.write_all(&data)?;
        }

        Ok(())
    }

    /// Returns a borrowed slice from a pre-decompressed shared block, if this
    /// offset is shared by multiple entries. `None` means "not shared, decompress
    /// individually"
    fn slice_shared<'a>(
        offset: usize,
        block_off: usize,
        len: usize,
        shared_blocks: &'a HashMap<usize, Vec<u8>>,
        offset_groups: &OffsetGroups,
    ) -> Option<Result<&'a [u8], Error>> {
        let block = shared_blocks.get(&offset)?;
        if offset_groups.get(&offset).is_none_or(|v| v.len() <= 1) {
            return None;
        }
        let end = block_off + len;
        if end > block.len() {
            return Some(Err(Error::Decompression(format!(
                "shared block slice out of bounds: {block_off}..{end} in {} byte block",
                block.len()
            ))));
        }
        Some(Ok(&block[block_off..end]))
    }

    fn decompress_rsrc<'a>(
        &self,
        f: &FileEntry,
        shared_blocks: &'a HashMap<usize, Vec<u8>>,
        offset_groups: &OffsetGroups,
    ) -> Result<Cow<'a, [u8]>, Error> {
        if let Some(result) = Self::slice_shared(
            f.data_offset, f.block_rsrc_off, f.uncomp_rsrc, shared_blocks, offset_groups,
        ) {
            return result.map(Cow::Borrowed);
        }
        let rsrc_off = f.data_offset + f.comp_data;
        self.decompress_raw(rsrc_off, f.comp_rsrc, f.uncomp_rsrc).map(Cow::Owned)
    }

    fn decompress_fork<'a>(
        &self,
        data_offset: usize,
        comp: usize,
        uncomp: usize,
        block_off: usize,
        shared_blocks: &'a HashMap<usize, Vec<u8>>,
        offset_groups: &OffsetGroups,
    ) -> Result<Cow<'a, [u8]>, Error> {
        if let Some(result) = Self::slice_shared(
            data_offset, block_off, uncomp, shared_blocks, offset_groups,
        ) {
            return result.map(Cow::Borrowed);
        }
        self.decompress_raw(data_offset, comp, uncomp).map(Cow::Owned)
    }

    fn decompress_raw(&self, offset: usize, comp: usize, uncomp: usize) -> Result<Vec<u8>, Error> {
        if offset + comp > self.data.len() {
            return Err(Error::Decompression(format!(
                "data at 0x{offset:x} ({comp} bytes) exceeds archive bounds"
            )));
        }
        let src = &self.data[offset..offset + comp];

        if self.info.use_deflate {
            deflate::decrypt_and_decompress(src, uncomp)
        } else {
            lzss::decompress(src, uncomp)
        }
    }

    fn build_offset_groups(&self, files: &[&FileEntry]) -> OffsetGroups {
        let mut groups: OffsetGroups = HashMap::new();
        for (i, f) in files.iter().enumerate() {
            if f.comp_data > 0 && !f.is_stub() && (self.info.num_segments <= 1 || f.segment == 1) {
                groups.entry(f.data_offset).or_default().push(i);
            }
        }
        groups
    }

    fn decompress_shared_blocks(
        &self,
        files: &[&FileEntry],
        offset_groups: &OffsetGroups,
    ) -> HashMap<usize, Vec<u8>> {
        let mut blocks = HashMap::new();
        if !self.info.use_deflate {
            return blocks;
        }

        for (&off, indices) in offset_groups {
            if indices.len() <= 1 {
                continue;
            }
            let cd = files[indices[0]].comp_data;
            if off + cd > self.data.len() {
                continue;
            }
            if let Ok(data) = deflate::decrypt_and_decompress(&self.data[off..off + cd], 0) {
                blocks.insert(off, data);
            }
        }

        blocks
    }
}

fn clean_name(name: &str) -> String {
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

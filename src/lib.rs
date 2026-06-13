//! Extractor for Installer VISE archives (`MindVision`, 1990s-2000s Mac)
//!
//! Supports all observed VISE format versions from 00 01 through 03 0e:
//! - v2 (00 01, 02 0x): LZSS with a 1024-byte circular window
//! - v3 (03 00 - 03 05): byte-swap + substitution cipher + word-aligned DEFLATE
//! - v3.06-07: new-style CVCT header with chunk-type table
//! - v3.08-0e: CVCT body compressed with word-aligned DEFLATE

#![warn(clippy::pedantic)]

pub(crate) mod deflate;
pub(crate) mod lzss;
pub mod macbinary;
mod parse;

use std::borrow::Cow;
use std::collections::HashMap;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

pub use parse::{ArchiveInfo, Entry, FileEntry};

/// Decompression internals re-exported for the fuzz targets under the `fuzzing`
/// feature only, not public API
#[cfg(feature = "fuzzing")]
#[doc(hidden)]
pub mod fuzzing {
    pub use crate::deflate::decrypt_and_decompress;
    pub use crate::deflate::word_deflate;
    pub use crate::lzss::decompress as lzss_decompress;

    use std::path::{Path, PathBuf};

    /// Runs the real name sanitizer then the join guard, the way `extract` does,
    /// so a fuzz target can assert the pipeline never escapes the base
    pub fn sanitize_and_join(base: &Path, raw: &str) -> Option<PathBuf> {
        let cleaned = super::clean_name(raw);
        super::safe_join(base, &cleaned)
    }
}

/// How far total extracted output may exceed the archive size before extraction
/// aborts. DEFLATE's exact maximum expansion is 1032:1, so legitimate output
/// stays well under this; anything beyond is a bomb
const OUTPUT_BUDGET_RATIO: usize = 1032;
/// Floor for the output budget so tiny archives still extract normally
const OUTPUT_BUDGET_HEADROOM: usize = 1 << 20;

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

        let output_budget = self.data.len()
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
                            fs::create_dir_all(&cur_dir)?;
                        }
                        None => eprintln!("  [unsafe path] skipping directory {name}"),
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

                    let Some(path) = safe_join(&cur_dir, &name) else {
                        eprintln!("  [unsafe path] skipping {name}");
                        result.skipped += 1;
                        continue;
                    };
                    if let Some(p) = path.parent() {
                        fs::create_dir_all(p)?;
                    }

                    match self.extract_file(f, &path, &shared_blocks, &offset_groups) {
                        Err(e) => {
                            eprintln!("  FAIL {name}: {e}");
                            result.failed += 1;
                        }
                        Ok(written) => {
                            eprintln!("  {name} ({} + {} bytes)", f.uncomp_data, f.uncomp_rsrc);
                            result.extracted += 1;
                            total_out = total_out.saturating_add(written);
                            if total_out > output_budget {
                                eprintln!(
                                    "  aborting: extracted output exceeds {output_budget} byte budget (possible decompression bomb)"
                                );
                                break;
                            }
                        }
                    }
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

    /// Returns the total number of bytes written across both forks
    fn extract_file(
        &self,
        f: &FileEntry,
        path: &Path,
        shared_blocks: &HashMap<usize, Vec<u8>>,
        offset_groups: &OffsetGroups,
    ) -> Result<usize, Error> {
        let mut written = 0usize;

        if f.comp_data > 0 {
            let data = self.decompress_fork(
                f.data_offset, f.comp_data, f.uncomp_data,
                f.block_data_off, shared_blocks, offset_groups,
            )?;
            fs::File::create(path)?.write_all(&data)?;
            written = written.saturating_add(data.len());
        }

        if f.comp_rsrc > 0 && f.uncomp_rsrc > 0 {
            let data = self.decompress_rsrc(f, shared_blocks, offset_groups)?;
            let mut rsrc_path = path.as_os_str().to_owned();
            rsrc_path.push(".rsrc");
            fs::File::create(&rsrc_path)?.write_all(&data)?;
            written = written.saturating_add(data.len());
        }

        Ok(written)
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

        // bound the resident size of the whole cache, not just each block: a
        // crafted archive could otherwise pin many large shared blocks in memory
        // at once. Once the budget is hit, the rest decode per-entry on demand
        let budget = self.data.len()
            .saturating_mul(OUTPUT_BUDGET_RATIO)
            .saturating_add(OUTPUT_BUDGET_HEADROOM);
        let mut resident: usize = 0;

        // iterate in offset order, not HashMap order, so which blocks land in the
        // cache before the budget is hit is deterministic across runs
        let mut offsets: Vec<usize> = offset_groups.keys().copied().collect();
        offsets.sort_unstable();

        for off in offsets {
            let indices = &offset_groups[&off];
            if indices.len() <= 1 {
                continue;
            }
            let cd = files[indices[0]].comp_data;
            if off + cd > self.data.len() {
                continue;
            }
            if let Ok(data) = deflate::decrypt_and_decompress(&self.data[off..off + cd], 0) {
                if resident.saturating_add(data.len()) > budget {
                    eprintln!("  shared-block cache hit {budget} byte budget; remaining blocks decode on demand");
                    break;
                }
                resident = resident.saturating_add(data.len());
                blocks.insert(off, data);
            }
        }

        blocks
    }
}

/// Joins a cleaned entry name onto `base`, refusing any name that would escape
/// it. `clean_name` already strips `..` and leading separators, so this is
/// defense in depth and the single enforcement point for no traversal
fn safe_join(base: &Path, name: &str) -> Option<PathBuf> {
    use std::path::Component;
    let escapes = Path::new(name)
        .components()
        .any(|c| !matches!(c, Component::Normal(_) | Component::CurDir));
    if escapes {
        return None;
    }
    Some(base.join(name))
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clean_name_neutralizes_traversal() {
        assert_eq!(clean_name("../../etc/passwd"), "etc/passwd");
        assert_eq!(clean_name("/etc/passwd"), "etc/passwd");
        assert_eq!(clean_name("Macintosh HD:System:Prefs"), "Macintosh HD/System/Prefs");
        assert_eq!(clean_name("a/../../b"), "a/b");
        assert_eq!(clean_name(".."), "");
        assert_eq!(clean_name("."), "");
    }

    #[test]
    fn safe_join_rejects_escapes() {
        let base = Path::new("/out");
        assert_eq!(safe_join(base, "sub/file.txt"), Some(PathBuf::from("/out/sub/file.txt")));
        // Defense in depth: even if a malformed name reaches here, it cannot escape
        assert_eq!(safe_join(base, "../escape"), None);
        assert_eq!(safe_join(base, "a/../b"), None);
        assert_eq!(safe_join(base, "/abs/path"), None);
    }
}

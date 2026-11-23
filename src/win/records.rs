//! The record stream: finding each record, and reading the folder and file
//! records that extraction needs

use std::collections::{HashMap, HashSet};
use std::time::{Duration, SystemTime};

use encoding_rs::Encoding;

use super::cursor::{Cursor, Malformed};
use super::{
    Error, Location, MAX_ARRAY_COUNT, MAX_FOLDER_DEPTH, MAX_RECORD_BODY, MAX_RECORD_COUNT,
    MAX_RECORD_ID, MAX_RECORD_TYPE, PARENT_LOOKAHEAD, QDAT_ENTRIES_OFFSET, QDAT_ENTRY_HEADER,
    RecordFmt, SOURCE_DOWNLOAD_ITEM, STUB_FLAG, WinEntry,
};
use crate::text::decode_windows;

/// Each qdat per-file entry is `[u32][u32 comp][u32 0][u32 0][comp bytes]`
pub(super) fn parse_qdat_entries(qdat: &[u8]) -> Result<Vec<(usize, usize)>, Error> {
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

/// How a record stream is to be read
#[derive(Clone, Copy)]
pub(super) struct StreamReading<'a> {
    pub(super) fmt: RecordFmt,
    /// Added to every blob offset the records give
    pub(super) blob_base: usize,
    /// The archive header's flags, which mark a stub installer
    pub(super) flags: u32,
    /// The code page of the names
    pub(super) text: &'static Encoding,
    /// Where each file's data is in the `.qdat` volume of a stub installer
    pub(super) qdat_entries: Option<&'a [(usize, usize)]>,
}

impl StreamReading<'_> {
    /// A stream on its own: offsets as recorded, Western European names
    pub(super) const fn plain(fmt: RecordFmt) -> Self {
        Self {
            fmt,
            blob_base: 0,
            flags: 0,
            text: encoding_rs::WINDOWS_1252,
            qdat_entries: None,
        }
    }
}

/// How reading a record stream went
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct StreamRead {
    /// All the records the stream declares were present; `false` means the
    /// data ran out first
    pub(super) complete: bool,
    /// Records whose end was found by searching for the next record, because
    /// stepping over the body did not land on one. Zero when the layout fits
    /// the stream exactly
    pub(super) realigned: usize,
    /// Where reading stopped: the end of the stream when it is complete
    pub(super) end: usize,
}

/// Parses the record stream at `offset`, appending a [`WinEntry`] for each
/// file record
pub(super) fn parse_record_stream(
    data: &[u8],
    offset: usize,
    reading: &StreamReading,
    entries: &mut Vec<WinEntry>,
) -> Result<StreamRead, Error> {
    let StreamReading {
        fmt: rec_fmt,
        blob_base,
        flags,
        text,
        qdat_entries,
    } = *reading;
    let mut c = Cursor::new(data, offset, rec_fmt);
    let count = c.u32()?;
    if count > MAX_RECORD_COUNT {
        return Err(Error::InvalidArchive(format!(
            "record count {count} exceeds limit {MAX_RECORD_COUNT}"
        )));
    }

    let stub_installer = flags == STUB_FLAG;
    let mut qdat_idx: usize = 0;

    let first_file = entries.len();
    // the folder each file record sits in, in step with `entries[first_file..]`
    let mut parents: Vec<u32> = Vec::new();
    // folder records by ID: name and parent folder
    let mut folders: HashMap<u32, (String, u32)> = HashMap::new();
    let mut complete = true;

    // bytes that may be searched for record starts over the whole stream,
    // so a crafted stream cannot make every record cost a long search
    let mut search_budget = data.len().saturating_mul(2);
    let mut realigned = 0usize;
    let mut tails = Tails::default();
    // IDs of the records read so far
    let mut seen = HashSet::new();

    for index in 0..count {
        if c.remaining() < 8 {
            complete = false;
            break;
        }
        let rtype = c.u32()?;
        let (id, parent) = c.common()?;
        seen.insert(id);
        let body = c.pos;
        let mut search_from = body;

        // Only folder and file records are used. What is needed from them
        // sits at the front, where every runtime agrees; a failure there is
        // an error. The rest of a record, and every other record type, only
        // has to be stepped over
        let stepped = if rtype == 1 {
            // a folder; every layout starts the record with its name
            let name = Cursor::new(c.data, c.pos, c.fmt).locstring()?;
            folders.insert(id, (decode_windows(name, text), parent));
            skip_type(&mut c, rtype)
        } else if rtype == 2 {
            parents.push(parent);
            let mut entry = read_type2(&mut c, blob_base, text)?;

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
                            entry.location = Location::Qdat;
                        }
                        qdat_idx += 1;
                    } else if entry.compressed_len > 0 {
                        entry.location = Location::Qdat;
                    }
                }
            }

            entries.push(entry);
            // if the rest of the record does not line up, the next record is
            // looked for from here on: the part just read holds a volume
            // number, an offset and attributes in a row, which can pass for
            // a record header
            search_from = c.pos;
            let tail = skip_type2_tail(&mut c, tails.short);
            if let Some(entry) = entries.last_mut() {
                if tails.downloaded(&tail, &c, index + 1 == count) {
                    entry.location = Location::Download;
                }
            }
            tail.map(|_| ())
        } else {
            skip_type(&mut c, rtype)
        };

        // After the last record there is nothing to line up with
        if index + 1 == count {
            break;
        }
        // The step is right if it ends where a record starts. Record bodies
        // differ between runtime builds in ways that are not all known, so
        // when it does not, the next record is found by its header instead.
        // The declared count still has to come out exactly
        // (a stream that simply ends early is caught at the top of the loop)
        let misplaced = c.remaining() >= 8 && !plausible_record_start(data, c.pos, rec_fmt);
        if stepped.is_err() || misplaced {
            realigned += 1;
            let Some(next) =
                find_next_record(data, search_from, rec_fmt, &seen, &mut search_budget)
            else {
                let lost = Malformed {
                    what: "no record found after this one",
                    offset: body,
                };
                return Err(stepped.err().unwrap_or(lost).into());
            };
            c.pos = next;
        }
    }

    // layouts that store an install path with each file keep it; the others
    // get theirs from the folder records
    for (entry, parent) in entries[first_file..].iter_mut().zip(parents) {
        if entry.directory.is_empty() {
            entry.directory = folder_path(&folders, parent);
        }
    }

    Ok(StreamRead {
        complete,
        realigned,
        end: c.pos,
    })
}

/// The front of a file record, as far as it is used, with its strings
/// still in the payload
pub(super) struct FileFields<'a> {
    name: &'a [u8],
    path: &'a [u8],
    uncomp: usize,
    comp: usize,
    volume: u32,
    blob_off: usize,
    modified: u64,
    crc32: u32,
}

/// Reads the front of a file record without building anything from it, so
/// the search for record starts can try it at every position
pub(super) fn read_file_fields<'a>(c: &mut Cursor<'a>) -> Result<FileFields<'a>, Malformed> {
    let name = c.locstring()?;
    if c.fmt.is_pre4() {
        c.skip_inline()?;
    } else {
        c.alt_block()?;
    }
    let path = match c.fmt.family() {
        RecordFmt::Pre4 | RecordFmt::Apple => c.inline_string()?,
        _ => &[],
    };
    let uncomp = c.u32()? as usize;
    let comp = c.u32()? as usize;
    let volume = c.u32()?;
    let blob_off = c.u32()? as usize;
    // file attributes, then creation and last-access times
    c.skip(4 + 8 + 8)?;
    let modified = c.u64()?;
    c.skip(2 + 2 + 1 + 4)?;
    c.skip_inline()?;
    // 2.4 has two bytes fewer here than every later runtime
    c.skip(if c.fmt == RecordFmt::Pre24 {
        12
    } else {
        4 + 1 + 1 + 4 + 4
    })?;
    let crc32 = c.u32()?;
    Ok(FileFields {
        name,
        path,
        uncomp,
        comp,
        volume,
        blob_off,
        modified,
        crc32,
    })
}

pub(super) fn read_type2(
    c: &mut Cursor,
    blob_base: usize,
    text: &'static Encoding,
) -> Result<WinEntry, Malformed> {
    let fields = read_file_fields(c)?;
    let directory = resolve_vise_path(&decode_windows(fields.path, text))
        .trim_matches('/')
        .to_string();
    Ok(WinEntry {
        name: decode_windows(fields.name, text),
        directory,
        offset: fields.blob_off.saturating_add(blob_base),
        compressed_len: fields.comp,
        uncompressed_len: fields.uncomp,
        modified: filetime(fields.modified),
        crc32: fields.crc32,
        location: if fields.volume > 1 {
            Location::Part(fields.volume)
        } else {
            Location::Installer
        },
        misplaced: false,
    })
}

/// Skips what follows the CRC in a file record. Nothing in it is used, and
/// its length is what varies most between runtime builds, so a failure here
/// is not fatal: the caller finds the next record instead
///
/// Returns where the record says the file comes from. `short` says that
/// earlier records in the stream ended four bytes sooner than the layout
/// allows for, which is how this one is then read
pub(super) fn skip_type2_tail(c: &mut Cursor, short: bool) -> Result<Source, Malformed> {
    if matches!(c.fmt, RecordFmt::Pre24 | RecordFmt::Pre25) {
        // the record ends three bytes after the CRC up to 2.5
        c.skip(3)?;
        return Ok(Source::Installer);
    }
    if c.fmt == RecordFmt::Pre4 {
        c.skip(1 + 1 + 1 + 1 + 4)?;
        c.skip(1 + 2 + 1)?;
        return Ok(Source::Installer);
    }
    c.skip(1 + 1 + 1 + 1 + 4)?;
    let source = c.u8()?;
    if source == SOURCE_DOWNLOAD_ITEM {
        // what follows may not read, and does not need to
        let _ = skip_type2_tail_end(c, source, short);
        return Ok(Source::DownloadItem);
    }
    skip_type2_tail_end(c, source, short)
}

/// The part of a file record's tail after the source byte
pub(super) fn skip_type2_tail_end(
    c: &mut Cursor,
    source: u8,
    short: bool,
) -> Result<Source, Malformed> {
    c.skip_inline()?;
    c.skip(1)?;
    let long_tail = !matches!(c.fmt, RecordFmt::Apple | RecordFmt::Main46);
    if !long_tail && source == SOURCE_DOWNLOAD_ITEM {
        c.skip(16)?;
    }
    c.skip(1 + 4)?;
    // Earlier builds end the record here
    if !long_tail && (short || plausible_record_start(c.data, c.pos, c.fmt)) {
        return Ok(Source::InstallerShort);
    }
    // CRC-32 of the stored bytes, in the builds that fill it in
    c.skip(4)?;
    if long_tail {
        c.skip(1)?;
    }
    Ok(Source::Installer)
}

/// What the file-record tails read so far in a stream have shown
#[derive(Default)]
pub(super) struct Tails {
    /// This build ends a file record four bytes sooner than later ones
    short: bool,
}

impl Tails {
    /// Notes what the file record whose tail was just read, leaving `c` at
    /// its end, shows about the build, and returns whether the record is
    /// for a file kept in a download item instead of in the installer.
    ///
    /// The length of the tail differs between builds. That this one ends
    /// early is taken from a tail only when it ends where the next record
    /// starts, give or take the one byte some builds add
    fn downloaded(&mut self, tail: &Result<Source, Malformed>, c: &Cursor, last: bool) -> bool {
        let lines_up = !last
            && (plausible_record_start(c.data, c.pos, c.fmt)
                || plausible_record_start(c.data, c.pos + 1, c.fmt));
        self.short |= lines_up && matches!(tail, Ok(Source::InstallerShort));
        matches!(tail, Ok(Source::DownloadItem))
    }
}

/// Where a file record says its file comes from
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum Source {
    /// The installer carries it
    Installer,
    /// The same, in a record that ends early
    InstallerShort,
    /// A download item of a web installer, named by GUID
    DownloadItem,
}

/// Whether a record could start at `pos`: a type in range, an ID and parent
/// ID of believable size, a common header that parses, and for a folder or
/// file record, a body that does too
pub(super) fn plausible_record_start(data: &[u8], pos: usize, fmt: RecordFmt) -> bool {
    let Some(head) = pos.checked_add(12).and_then(|end| data.get(pos..end)) else {
        return false;
    };
    let field = |i: usize| u32::from_le_bytes(head[i..i + 4].try_into().unwrap());
    let rtype = field(0);
    if !(1..=MAX_RECORD_TYPE).contains(&rtype)
        || !(1..MAX_RECORD_ID).contains(&field(4))
        || field(8) >= MAX_RECORD_ID
    {
        return false;
    }
    let mut c = Cursor::new(data, pos + 4, fmt);
    if c.common().is_err() {
        return false;
    }
    // the two kinds of record that are used also have to read as far as
    // they are used
    match rtype {
        1 => c.locstring().is_ok(),
        2 => read_file_fields(&mut c).is_ok(),
        _ => true,
    }
}

/// Finds where the next record starts, searching forward from `from`. Used
/// when a record's body is not understood. `budget` is the number of bytes
/// that may still be searched across the whole stream.
///
/// Bytes inside a record can pass for a record header. A real record sits
/// at the top level or inside a record that came before it, so a candidate
/// whose parent is one of the `seen` IDs is taken over an earlier candidate
/// whose parent is not, when one follows closely
pub(super) fn find_next_record(
    data: &[u8],
    from: usize,
    fmt: RecordFmt,
    seen: &HashSet<u32>,
    budget: &mut usize,
) -> Option<usize> {
    let end = data
        .len()
        .min(from.saturating_add(MAX_RECORD_BODY).saturating_add(1));
    let parent_seen = |pos: usize| {
        data.get(pos + 8..pos + 12).is_some_and(|b| {
            let parent = u32::from_le_bytes([b[0], b[1], b[2], b[3]]);
            parent == 0 || seen.contains(&parent)
        })
    };
    // every position looked at is charged, whichever candidate is returned
    let (mut first, mut found, mut scanned) = (None, None, 0usize);
    for pos in from..end {
        if first.is_some_and(|first| pos - first > PARENT_LOOKAHEAD) {
            break;
        }
        scanned += 1;
        if !plausible_record_start(data, pos, fmt) {
            continue;
        }
        if parent_seen(pos) {
            found = Some(pos);
            break;
        }
        first.get_or_insert(pos);
    }
    let found = found.or(first);
    *budget = budget.saturating_sub(scanned);
    if *budget == 0 { None } else { found }
}

/// A Windows `FILETIME`: 100-nanosecond ticks since 1601-01-01 UTC
pub(super) fn filetime(ticks: u64) -> Option<SystemTime> {
    const UNIX_EPOCH_TICKS: u64 = 116_444_736_000_000_000;
    const TICKS_PER_SEC: u64 = 10_000_000;
    let since_unix = ticks.checked_sub(UNIX_EPOCH_TICKS)?;
    let nanos = u32::try_from(since_unix % TICKS_PER_SEC).ok()? * 100;
    SystemTime::UNIX_EPOCH.checked_add(Duration::new(since_unix / TICKS_PER_SEC, nanos))
}

/// The path of the folder record `id`, built by following parent links up to
/// the root. Mainline installers keep the install tree this way instead of
/// storing a path with each file
pub(super) fn folder_path(folders: &HashMap<u32, (String, u32)>, mut id: u32) -> String {
    let mut names = Vec::new();
    while let Some((name, parent)) = folders.get(&id) {
        // also stops a parent link that loops back on itself
        if names.len() == MAX_FOLDER_DEPTH {
            break;
        }
        // a separator inside one folder name would split it in two
        names.push(name.replace(['/', '\\'], "_"));
        id = *parent;
    }
    names.reverse();
    names.join("/")
}

#[allow(clippy::too_many_lines)]
#[rustfmt::skip]
pub(super) fn skip_type(c: &mut Cursor, t: u32) -> Result<(), Malformed> {
    // records that are shorter up to 2.5 than in 2.6
    let early = matches!(c.fmt, RecordFmt::Pre24 | RecordFmt::Pre25);
    match (c.fmt.family(), t) {
        (_, 0x01) if early => { c.locstring()?; c.skip_inline()?; c.skip_inline()?; c.skip(4+1+4)?; c.skip_inline()?; c.skip(1+1)?; }
        (_, 0x03) if early => { c.locstring()?; c.skip_inline()?; c.skip_inline()?; c.skip_inline()?; c.skip_inline()?; c.skip(2)?; c.locstring()?; c.skip(1+1+1)?; }
        (_, 0x1b) if early => { c.skip_inline()?; c.skip_inline()?; c.skip_inline()?; c.skip(1)?; c.skip_inline()?; c.skip(1)?; }

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
        (_, 0x20) => { c.skip(4)?; }
        (RecordFmt::Main46 | RecordFmt::Main4 | RecordFmt::Main48, 0x24) => { skip_screen(c)?; }
        (_, 0x22) => { c.locstring()?; c.locstring()?; c.locstring()?; c.skip_inline()?; c.skip(1+1)?; }

        // Format-specific
        (RecordFmt::Pre4, 0x01) => { c.locstring()?; c.skip_inline()?; c.skip_inline()?; c.skip(4+1+4)?; c.skip_inline()?; c.skip(1+1+1+2+4)?; }
        (RecordFmt::Apple, 0x01) => { c.locstring()?; c.skip(2)?; c.string()?; c.skip(4+1+4)?; c.string()?; c.skip(1+1+1)?; c.string()?; c.skip(4)?; }
        (RecordFmt::Main46, 0x01) => { c.locstring()?; c.alt_block()?; c.skip(4+1+4)?; c.string()?; c.skip(1+1+1)?; c.string()?; c.skip(4)?; }
        (RecordFmt::Main4 | RecordFmt::Main48, 0x01) => { c.locstring()?; c.alt_block()?; c.skip(4+1+4)?; c.string()?; c.skip(1+1+1)?; c.string()?; c.skip(4+1)?; }

        (RecordFmt::Pre4 | RecordFmt::Apple, 0x05) => { c.skip(1)?; c.skip_inline()?; c.skip(1)?; c.skip_inline()?; c.skip_inline()?; c.skip_inline()?; c.skip(1)?; c.skip_inline()?; c.skip(1)?; }
        (RecordFmt::Main46 | RecordFmt::Main4 | RecordFmt::Main48, 0x05) => { c.skip(1)?; c.skip_inline()?; c.skip(1)?; c.skip_inline()?; c.skip_inline()?; c.skip_inline()?; c.skip(1)?; c.skip_inline()?; c.skip(1+1)?; }

        (RecordFmt::Pre4 | RecordFmt::Apple, 0x0f) => { c.skip_inline()?; c.skip(4+4+4)?; }
        (RecordFmt::Main46 | RecordFmt::Main4 | RecordFmt::Main48, 0x0f) => { c.skip_inline()?; c.skip(4+4+4+2)?; }

        (RecordFmt::Pre4 | RecordFmt::Apple, 0x11) => { c.skip_inline()?; c.skip_inline()?; c.skip(2+1+1)?; }
        (RecordFmt::Main46 | RecordFmt::Main4 | RecordFmt::Main48, 0x11) => { c.skip_inline()?; c.skip_inline()?; c.skip(2+1+1+1)?; }

        (RecordFmt::Pre4, 0x15) => { c.skip_inline()?; c.skip_inline()?; c.skip_inline()?; c.skip(4+4+4+4+4+8+8+8+2+2+4+1+4)?; c.skip_inline()?; c.skip(1+1+1)?; c.skip_inline()?; c.skip(4)?; }
        (RecordFmt::Apple, 0x15) => { c.skip_inline()?; c.skip_inline()?; c.skip(4+4+4+4+4+8+8+8+2+2+4+1+4)?; c.skip_inline()?; c.skip(1+1+1)?; c.skip_inline()?; c.skip(4)?; }
        (RecordFmt::Main46 | RecordFmt::Main4 | RecordFmt::Main48, 0x15) => { c.skip_inline()?; c.alt_block()?; c.skip(4+4+4+4+4+8+8+8+2+2+4+1+4)?; c.skip_inline()?; c.skip(1+1+1)?; c.skip_inline()?; c.skip(4+1)?; }

        (RecordFmt::Pre4 | RecordFmt::Apple, 0x17) => { c.skip(1+4+4)?; }
        (RecordFmt::Main46 | RecordFmt::Main4 | RecordFmt::Main48, 0x17) => { c.skip(1+4+4)?; c.skip_inline()?; c.skip(1)?; c.skip_inline()?; }

        (RecordFmt::Pre4 | RecordFmt::Apple, 0x1e) => { c.skip(1)?; c.skip_inline()?; }
        (RecordFmt::Main46 | RecordFmt::Main4 | RecordFmt::Main48, 0x1e) => { c.skip(1)?; c.skip_inline()?; c.skip(1)?; c.skip_inline()?; }

        (RecordFmt::Pre4 | RecordFmt::Apple, 0x23) => { c.skip_inline()?; c.skip_inline()?; c.skip_inline()?; c.skip_inline()?; c.skip_inline()?; c.skip(1)?; c.skip_inline()?; }
        (RecordFmt::Main46 | RecordFmt::Main4 | RecordFmt::Main48, 0x23) => { c.skip(2+2+2)?; c.skip_inline()?; c.skip_inline()?; c.skip(1)?; c.skip_inline()?; }

        (_, 0x25) => { c.skip(2)?; }
        (_, 0x26) => { c.skip_inline()?; c.skip_inline()?; c.skip_inline()?; c.skip_inline()?; }

        _ => return Err(c.bad("unhandled record type")),
    }
    Ok(())
}

/// Subtype of a type 0x24 record that holds a custom dialog
pub(super) const SCREEN_DIALOG: u32 = 0;
/// Subtype of a type 0x24 record for the screen that asks where to install
pub(super) const SCREEN_DESTINATION: u32 = 9;

/// Skips the body of a type 0x24 record, a screen the installer shows. It
/// starts with a u32 subtype. Three are read:
/// - a custom dialog (subtype 0): six bytes, a u16, a control count, then
///   the controls
/// - the destination screen (subtype 9): flags and five strings (image, an
///   empty one, the default folder, an empty one, the variable to set)
/// - the finish screen of 4.8 and later (subtype 0x10): flags and four
///   strings (image, caption, an empty one, the program to launch)
///
/// Before 4.8 any other subtype is taken to be the whole record, and a
/// subtype 0 that does not read as a dialog is too
pub(super) fn skip_screen(c: &mut Cursor) -> Result<(), Malformed> {
    let subtype = c.u32()?;
    if subtype == SCREEN_DIALOG {
        let mut dialog = Cursor::new(c.data, c.pos, c.fmt);
        match skip_dialog(&mut dialog) {
            Ok(()) => c.pos = dialog.pos,
            Err(e) if c.fmt == RecordFmt::Main48 => return Err(e),
            Err(_) => {}
        }
    } else if subtype == SCREEN_DESTINATION {
        c.skip(1 + 1)?;
        c.skip_inline()?;
        c.skip(1)?;
        c.skip_inline()?;
        c.skip(1)?;
        c.skip_inline()?;
        c.skip_inline()?;
        c.skip_inline()?;
    } else if c.fmt == RecordFmt::Main48 {
        c.skip(1 + 1)?;
        c.skip_inline()?;
        c.skip(1)?;
        c.skip_inline()?;
        c.skip_inline()?;
        c.skip_inline()?;
        c.skip(20)?;
    }
    Ok(())
}

/// Skips a custom dialog: its header, then each control as a u16 kind, its
/// text, an 8-byte rectangle, a flag byte, and extra bytes that depend on
/// the kind. Four kinds are accepted: caption (1), button (2), text (3) and
/// bitmap (8)
pub(super) fn skip_dialog(c: &mut Cursor) -> Result<(), Malformed> {
    c.skip(6 + 2)?;
    let controls = c.bounded_u16(MAX_ARRAY_COUNT, "dialog control count")?;
    for _ in 0..controls {
        let kind = c.u16()?;
        let extra = match kind {
            1 | 8 => 0,
            2 => 11,
            3 => 5,
            _ => {
                return Err(Malformed {
                    what: "unhandled dialog control kind",
                    offset: c.pos - 2,
                });
            }
        };
        c.skip_string()?;
        c.skip(8 + 1 + extra)?;
    }
    Ok(())
}

/// Strips VISE install-path variables: `%SysDir%\Qt\f.dll` becomes
/// `SysDir/Qt/f.dll`
pub(super) fn resolve_vise_path(path: &str) -> String {
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

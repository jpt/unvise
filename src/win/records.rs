//! The record stream: finding each record, and reading the folder and file
//! records that extraction needs

use std::collections::{HashMap, HashSet};
use std::time::{Duration, SystemTime};

use encoding_rs::Encoding;

use super::cursor::{Cursor, Malformed};
use super::grammar;
use super::grammar::Text;
use super::layouts::LayoutId;
use super::{
    Error, Location, MAX_FOLDER_DEPTH, MAX_FOLDER_PATH, MAX_RECORD_BODY, MAX_RECORD_COUNT,
    MAX_RECORD_ID, PARENT_LOOKAHEAD, QDAT_ENTRIES_OFFSET, QDAT_ENTRY_HEADER, SOURCE_DOWNLOAD_ITEM,
    STUB_FLAG, WinEntry,
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
    pub(super) layout: LayoutId,
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
    #[cfg(any(test, feature = "fuzzing"))]
    pub(super) const fn plain(layout: LayoutId) -> Self {
        Self {
            layout,
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
    /// stepping over the body did not land on one, and the last record if
    /// its body did not read. Zero when the layout fits the stream exactly
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
        layout,
        blob_base,
        flags,
        text,
        qdat_entries,
    } = *reading;
    let mut c = Cursor::new(data, offset, layout);
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
    // IDs of the records read so far
    let mut seen = HashSet::new();

    for index in 0..count {
        if c.remaining() < 4 {
            complete = false;
            break;
        }
        let rtype = c.u32()?;
        if layout.is_bare(rtype) {
            continue;
        }
        if c.remaining() < 4 {
            complete = false;
            break;
        }
        let (id, parent) = grammar::record_header(&mut c)?;
        seen.insert(id);
        let body = c.pos;
        let mut search_from = body;

        // Only folder and file records are used. A failure in what is used
        // of them is an error. Everything else only has to be stepped over
        let stepped = if rtype == 1 {
            // a folder; every layout starts the record with its name
            let name = Cursor::new(c.data, c.pos, c.layout).locstring()?;
            folders.insert(id, (decode_windows(name, text), parent));
            skip_type(&mut c, rtype)
        } else if rtype == 2 {
            parents.push(parent);
            let (mut entry, fixed) = read_type2(&mut c, blob_base, text)?;
            let download_item = entry.location == Location::Download;

            let in_payload = entry.compressed_len > 0
                && entry
                    .offset
                    .checked_add(entry.compressed_len)
                    .is_some_and(|end| end <= data.len())
                && entry.offset >= offset;
            if stub_installer && !in_payload {
                place_in_qdat(&mut entry, qdat_entries, &mut qdat_idx);
            }

            // a download item stays one whatever the stub handling made of it
            if download_item {
                entry.location = Location::Download;
            }
            entries.push(entry);
            // if the rest of the record does not line up, the next record is
            // looked for from here on: the part just read holds a volume
            // number, an offset and attributes in a row, which can pass for
            // a record header
            search_from = c.pos;
            skip_file_rest(&mut c, fixed)
        } else {
            skip_type(&mut c, rtype)
        };

        // After the last record there is nothing to line up with, so all
        // that shows is whether it read
        if index + 1 == count {
            realigned += usize::from(stepped.is_err());
            break;
        }
        // The step is right if it ends where a record starts. In a damaged
        // copy, or under the wrong layout, it does not, and the next record
        // is found by its header instead. The declared count still has to
        // come out exactly; a stream that simply ends early is caught at
        // the top of the loop
        let off_course = !record_could_follow(data, c.pos, layout);
        if stepped.is_err() || off_course {
            realigned += 1;
            let Some(next) = find_next_record(data, search_from, layout, &seen, &mut search_budget)
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
    /// The file is kept in a download item of a web installer, not in the
    /// installer
    download_item: bool,
    /// Where the fields after the string that follows the times begin
    fixed: usize,
}

/// Reads the front of a file record without building anything from it, so
/// the search for record starts can try it at every position
pub(super) fn read_file_fields<'a>(c: &mut Cursor<'a>) -> Result<FileFields<'a>, Malformed> {
    let file = &c.layout.table().file;
    let string = |c: &mut Cursor<'a>, kind| match kind {
        Text::Short => c.short_string(),
        Text::Long => c.string(),
    };
    let name = c.locstring()?;
    let mut path: &[u8] = &[];
    for (index, &kind) in file.before_sizes.iter().enumerate() {
        let text = string(c, kind)?;
        if file.folder == Some(index) {
            path = text;
        }
    }
    let uncomp = c.len32()?;
    let comp = c.len32()?;
    let volume = c.u32()?;
    let blob_off = c.len32()?;
    // file attributes, then creation and last-access times
    c.skip(4 + 8 + 8)?;
    let modified = c.u64()?;
    c.skip(2 + 2 + 1 + 4)?;
    string(c, file.after_times)?;
    let fixed = c.pos;
    c.skip(file.crc_at)?;
    let crc32 = c.u32()?;
    let download_item = file
        .source_at
        .is_some_and(|at| c.data.get(fixed + at) == Some(&SOURCE_DOWNLOAD_ITEM));
    Ok(FileFields {
        name,
        path,
        uncomp,
        comp,
        volume,
        blob_off,
        modified,
        crc32,
        download_item,
        fixed,
    })
}

/// Steps over what is left of a file record after [`read_file_fields`]:
/// the rest of the fixed fields that start at `fixed`, and what follows
fn skip_file_rest(c: &mut Cursor, fixed: usize) -> Result<(), Malformed> {
    // in front of them: the name, the strings, the sizes and times, and
    // the string after the times
    let front = c.layout.table().file.before_sizes.len() + 3;
    match c.layout.body(2).and_then(|ops| ops.get(front..)) {
        Some(&[grammar::Op::Skip(len), ref rest @ ..]) => {
            c.pos = fixed;
            c.skip(usize::from(len))?;
            grammar::step(c, rest, grammar::Limit::Any)
        }
        _ => Err(c.bad("unhandled record type")),
    }
}

/// Reads a file record as far as it is used. Returns the entry and where
/// the record's fixed fields begin, for [`skip_file_rest`]
pub(super) fn read_type2(
    c: &mut Cursor,
    blob_base: usize,
    text: &'static Encoding,
) -> Result<(WinEntry, usize), Malformed> {
    let fields = read_file_fields(c)?;
    let directory = resolve_vise_path(&decode_windows(fields.path, text))
        .trim_matches('/')
        .to_string();
    let entry = WinEntry {
        name: decode_windows(fields.name, text),
        directory,
        offset: fields.blob_off.saturating_add(blob_base),
        compressed_len: fields.comp,
        uncompressed_len: fields.uncomp,
        modified: filetime(fields.modified),
        crc32: fields.crc32,
        location: if fields.download_item {
            Location::Download
        } else if fields.volume > 1 {
            Location::Part(fields.volume)
        } else {
            Location::Installer
        },
        misplaced: false,
    };
    Ok((entry, fields.fixed))
}

/// Points a file that a stub installer does not carry at its place in the
/// companion volume. `next` counts the files handled so far
fn place_in_qdat(entry: &mut WinEntry, qdat_entries: Option<&[(usize, usize)]>, next: &mut usize) {
    // qdat entries correspond 1:1 with non-payload type-2 records,
    // including zero-length ones -- advance the index unconditionally
    if let Some(&(qdat_off, _)) = qdat_entries.and_then(|qe| qe.get(*next)) {
        if entry.compressed_len > 0 {
            entry.offset = qdat_off;
            entry.location = Location::Qdat;
        }
        *next += 1;
    } else if entry.compressed_len > 0 {
        entry.location = Location::Qdat;
    }
}

/// Whether the stream could go on at `pos`: past any record types that have
/// nothing after their number, either too little is left for a record, or
/// one could start there
fn record_could_follow(data: &[u8], mut pos: usize, layout: LayoutId) -> bool {
    loop {
        let Some(rest) = data.get(pos..).filter(|rest| rest.len() >= 8) else {
            return true;
        };
        let rtype = u32::from_le_bytes(rest[..4].try_into().unwrap());
        if !layout.is_bare(rtype) {
            return plausible_record_start(data, pos, layout);
        }
        pos += 4;
    }
}

/// Whether a record could start at `pos`: a type in range, an ID and parent
/// ID of believable size, a common header that parses, and for a folder or
/// file record, a body that does too
pub(super) fn plausible_record_start(data: &[u8], pos: usize, layout: LayoutId) -> bool {
    let Some(head) = pos.checked_add(12).and_then(|end| data.get(pos..end)) else {
        return false;
    };
    let field = |i: usize| u32::from_le_bytes(head[i..i + 4].try_into().unwrap());
    let rtype = field(0);
    if !layout.has_type(rtype)
        || !(1..MAX_RECORD_ID).contains(&field(4))
        || field(8) >= MAX_RECORD_ID
    {
        return false;
    }
    let mut c = Cursor::new(data, pos + 4, layout);
    if grammar::record_header(&mut c).is_err() {
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
/// when a record's body does not read. `budget` is the number of bytes
/// that may still be searched across the whole stream.
///
/// Bytes inside a record can pass for a record header. A real record sits
/// at the top level or inside a record that came before it, so a candidate
/// whose parent is one of the `seen` IDs is taken over an earlier candidate
/// whose parent is not, when one follows closely
pub(super) fn find_next_record(
    data: &[u8],
    from: usize,
    layout: LayoutId,
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
        if !plausible_record_start(data, pos, layout) {
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
/// the root. The layouts that store no folder with each file keep the
/// install tree this way
///
/// Every file gets a copy of its folder's path, so the path is kept short:
/// the climb stops at [`MAX_FOLDER_DEPTH`] folders, at a folder already
/// passed, or once the names add up to [`MAX_FOLDER_PATH`] bytes
pub(super) fn folder_path(folders: &HashMap<u32, (String, u32)>, mut id: u32) -> String {
    let mut names = Vec::new();
    let mut passed = Vec::new();
    let mut len = 0;
    while let Some((name, parent)) = folders.get(&id) {
        if names.len() == MAX_FOLDER_DEPTH || len >= MAX_FOLDER_PATH || passed.contains(&id) {
            break;
        }
        passed.push(id);
        len += name.len();
        // a separator inside one folder name would split it in two
        names.push(name.replace(['/', '\\'], "_"));
        id = *parent;
    }
    names.reverse();
    names.join("/")
}

/// Steps over the body of a type `t` record, as its layout defines it
pub(super) fn skip_type(c: &mut Cursor, t: u32) -> Result<(), Malformed> {
    match c.layout.body(t) {
        // a screen or message record can hold a whole document
        Some(ops) => grammar::step(c, ops, grammar::Limit::Any),
        None => Err(c.bad("unhandled record type")),
    }
}

/// Strips VISE install-path variables: `%SysDir%\App\f.dll` becomes
/// `SysDir/App/f.dll`
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

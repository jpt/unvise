//! The part of the payload in front of the record stream: the embedded
//! files and the sections the stream follows

use super::cursor::Cursor;
use super::grammar;
use super::layouts::LayoutId;
use super::{Error, Location, MAX_RECORD_COUNT, WinEntry};

/// Where the first embedded file starts, and how many there are. After the
/// 16 bytes of fixed header fields come a string with a one-byte length,
/// one byte, a string that ends with a zero byte, and the two-byte count of
/// embedded files
pub(super) fn find_first_entry(data: &[u8]) -> Result<(usize, usize), Error> {
    let short = || Error::InvalidArchive("payload header is cut short".into());
    // an SIVM header has two fields in front of the rest
    let header = if data.starts_with(b"SIVM") { 8 } else { 0 };
    let first = header + 16;
    let second = first + 1 + usize::from(*data.get(first).ok_or_else(short)?);
    let rest = data.get(second + 1..).ok_or_else(short)?;
    let zero = rest.iter().position(|&b| b == 0).ok_or_else(short)?;
    let count_at = second + 1 + zero + 1;
    let count = data.get(count_at..count_at + 2).ok_or_else(short)?;
    Ok((
        count_at + 2,
        usize::from(u16::from_le_bytes([count[0], count[1]])),
    ))
}

/// Walks the `count` embedded files from `pos`, each `[u8 name_len][name]
/// [12B fields][u32 comp][data]`, collecting them. Returns the byte offset
/// where they end. A file with no name, or one that does not fit in the
/// data, ends the walk early.
///
/// A name is kept one character to the byte. The code page it is in is
/// only known from what follows the files; see [`chain_name_bytes`]
pub(super) fn walk_named_chain(
    data: &[u8],
    mut pos: usize,
    count: usize,
    entries: &mut Vec<WinEntry>,
) -> usize {
    for _ in 0..count {
        let Some(&name_len) = data.get(pos) else {
            break;
        };
        let size_off = pos + 1 + usize::from(name_len) + 12;
        let Some(size) = data.get(size_off..size_off + 4) else {
            break;
        };
        let comp_size = u32::from_le_bytes(size.try_into().unwrap()) as usize;
        let body_off = size_off + 4;
        let Some(body_end) = body_off
            .checked_add(comp_size)
            .filter(|&end| name_len != 0 && end <= data.len())
        else {
            break;
        };

        entries.push(WinEntry {
            name: data[pos + 1..][..usize::from(name_len)]
                .iter()
                .map(|&b| char::from(b))
                .collect(),
            directory: String::new(),
            offset: body_off,
            compressed_len: comp_size,
            uncompressed_len: 0,
            modified: None,
            crc32: 0,
            location: Location::Installer,
            misplaced: false,
        });
        pos = body_end;
    }
    pos
}

/// Where the embedded files of a payload end
#[cfg(any(test, feature = "fuzzing"))]
pub(super) fn embedded_files_end(data: &[u8]) -> Result<usize, Error> {
    let (first, count) = find_first_entry(data)?;
    Ok(walk_named_chain(data, first, count, &mut Vec::new()))
}

/// The bytes of a name that [`walk_named_chain`] gave, if any of them is
/// outside ASCII and so depends on the code page
pub(super) fn chain_name_bytes(name: &str) -> Option<Vec<u8>> {
    if name.is_ascii() {
        return None;
    }
    name.chars().map(|c| u8::try_from(c).ok()).collect()
}

/// Whether `off` could be where a record stream starts: a count in range,
/// then, past any record types that have nothing after their number, a
/// type in range followed by a common header that parses
pub(super) fn starts_record_stream(data: &[u8], off: usize, layout: LayoutId) -> bool {
    has_record_count(data, off)
        && first_record_reads(data, bare_types_end(data, off + 4, layout), layout)
}

fn u32_at(data: &[u8], at: usize) -> Option<u32> {
    let bytes = data.get(at..at.checked_add(4)?)?;
    Some(u32::from_le_bytes(bytes.try_into().unwrap()))
}

fn has_record_count(data: &[u8], off: usize) -> bool {
    u32_at(data, off).is_some_and(|count| (1..=MAX_RECORD_COUNT).contains(&count))
}

/// Where the run of record types with nothing after their number, starting
/// at `at`, ends. That is `at` itself when there is no such type there
fn bare_types_end(data: &[u8], mut at: usize, layout: LayoutId) -> usize {
    while u32_at(data, at).is_some_and(|rtype| layout.is_bare(rtype)) {
        at += 4;
    }
    at
}

/// Whether `at` holds a type in range followed by a common header that
/// parses
fn first_record_reads(data: &[u8], at: usize, layout: LayoutId) -> bool {
    u32_at(data, at).is_some_and(|rtype| layout.has_type(rtype))
        && grammar::record_header(&mut Cursor::new(data, at + 4, layout)).is_ok()
}

/// How far past the embedded files a record stream is searched for
const STREAM_SEARCH: usize = 0x40000;

/// Scans from `from` for something that could start the record stream. Used
/// when the sections before the stream cannot be read (see
/// [`skip_to_record_stream`]). The scan stops a fixed distance past
/// `chain_end`, where the embedded files stop
pub(super) fn find_record_stream(
    data: &[u8],
    from: usize,
    chain_end: usize,
    layout: LayoutId,
) -> Result<usize, Error> {
    let search_end = data.len().min(chain_end.saturating_add(STREAM_SEARCH));
    // A run of types with nothing after their number is walked once for
    // each of the four alignments, not once for every offset inside it
    let mut runs = [(0, 0); 4];
    (from..search_end)
        .find(|&off| {
            if !has_record_count(data, off) {
                return false;
            }
            let at = off + 4;
            let (run_start, run_end) = &mut runs[at % 4];
            if !(*run_start..*run_end).contains(&at) {
                (*run_start, *run_end) = (at, bare_types_end(data, at, layout));
            }
            first_record_reads(data, (*run_end).max(at), layout)
        })
        .ok_or_else(|| Error::InvalidArchive("record stream not found".into()))
}

/// Where the record stream starts, found by reading through the sections
/// that lie between the embedded files and the stream. `None` when the
/// sections do not read cleanly or do not end on something that could start
/// a stream, in which case the caller scans instead
pub(super) fn exact_stream_start(data: &[u8], chain_end: usize, layout: LayoutId) -> Option<usize> {
    skip_to_record_stream(data, chain_end, layout)
        .ok()
        .filter(|&off| starts_record_stream(data, off, layout))
}

/// Reads through everything between the end of the embedded files and the
/// record stream, and returns where the stream starts
///
/// # Errors
///
/// Returns [`Error::Malformed`] if the data ends early or a count is out of
/// range
pub(super) fn skip_to_record_stream(
    data: &[u8],
    chain_end: usize,
    layout: LayoutId,
) -> Result<usize, Error> {
    let mut c = Cursor::new(data, chain_end, layout);
    grammar::step(&mut c, layout.table().start, grammar::Limit::Any)?;
    Ok(c.pos)
}

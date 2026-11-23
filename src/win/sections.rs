//! The part of the payload in front of the record stream: the embedded DLL
//! chain, which names the runtime, and the sections the stream follows

use super::cursor::Cursor;
use super::records::skip_type;
use super::{
    APPLE_MARKER, Error, Location, MAX_ARRAY_COUNT, MAX_RECORD_COUNT, MAX_RECORD_TYPE, RecordFmt,
    WinEntry,
};

pub(super) fn find_first_entry(data: &[u8]) -> Result<usize, Error> {
    data.windows(12)
        .position(|w| w == b"vise32ex.dll")
        .and_then(|p| p.checked_sub(1))
        .ok_or_else(|| Error::InvalidArchive("no vise32ex.dll in payload".into()))
}

/// Walks the chain of `[u8 name_len][name][12B fields][u32 comp][data]`
/// entries, collecting them. Returns the byte offset where the chain ends
/// and a format hint derived from the decompressed vise32ex.dll
pub(super) fn walk_named_chain(
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
            if let Some(dll) = crate::deflate::swap_and_inflate(&data[body_off..body_end], 0) {
                rec_fmt = detect_record_fmt(&dll);
            }
        }

        entries.push(WinEntry {
            name,
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
    (pos, rec_fmt)
}

/// Identifies the record format from the decompressed vise32ex.dll
///
/// Mainline DLLs contain an ASCII version table -- consecutive null-terminated
/// `major.minor.patch` strings starting with `4.`. The first entry is the DLL's
/// own version; runtime 4.8 introduced the wider common header. The Apple fork
/// has no 4.x table but contains the string `vise32qt`. DLLs predating the
/// version table have no identifying string; for those the build date in the PE
/// header picks between the three pre-4.x layouts
pub(super) fn detect_record_fmt(dll: &[u8]) -> RecordFmt {
    if let Some((_, minor)) = find_runtime_version(dll) {
        if minor <= 6 {
            return RecordFmt::Main46;
        }
        if minor >= 8 {
            return RecordFmt::Main48;
        }
        return RecordFmt::Main4;
    }
    if dll.windows(APPLE_MARKER.len()).any(|w| w == APPLE_MARKER) {
        return RecordFmt::Apple;
    }
    pre4_revision(pe_timestamp(dll))
}

/// Build date of the newest runtime DLL seen with the 2.4 record layout
/// (Installer VISE 2.4.5, 1997-11-05) and of the oldest seen with the 2.5
/// layout (2.5, 1998-01-02), as seconds since 1970
pub(super) const PRE24_LAST_SEEN: u32 = 878_688_000;
pub(super) const PRE25_FIRST_SEEN: u32 = 883_699_200;
/// Build date of the oldest runtime DLL seen with the 2.6 layout
/// (Installer VISE 2.6.2, 1998-03-27)
pub(super) const PRE4_FIRST_SEEN: u32 = 890_956_800;

/// Picks the pre-4.x record layout from the build date of the runtime DLL,
/// the only thing in it that differs by version: it has no version resource
/// and no version string. A date between two known ones goes to the nearer
pub(super) fn pre4_revision(timestamp: Option<u32>) -> RecordFmt {
    let midpoint = |a: u32, b: u32| a + (b - a) / 2;
    match timestamp {
        Some(t) if t < midpoint(PRE24_LAST_SEEN, PRE25_FIRST_SEEN) => RecordFmt::Pre24,
        Some(t) if t < midpoint(PRE25_FIRST_SEEN, PRE4_FIRST_SEEN) => RecordFmt::Pre25,
        _ => RecordFmt::Pre4,
    }
}

/// The link time recorded in a PE file's header, as seconds since 1970
pub(super) fn pe_timestamp(pe: &[u8]) -> Option<u32> {
    let header = usize::try_from(u32::from_le_bytes(pe.get(0x3C..0x40)?.try_into().ok()?)).ok()?;
    let fields = pe.get(header..header.checked_add(12)?)?;
    if !pe.starts_with(b"MZ") || !fields.starts_with(b"PE\0\0") {
        return None;
    }
    Some(u32::from_le_bytes(fields[8..12].try_into().ok()?))
}

/// Parses the `4.major.minor...` version table embedded in mainline DLLs
pub(super) fn find_runtime_version(dll: &[u8]) -> Option<(u32, u32)> {
    let mut i = 0;
    while i + 4 < dll.len() {
        // a table entry is a whole string: it starts after a NUL
        let at_start = i == 0 || dll[i - 1] == 0;
        if at_start && dll[i] == b'4' && dll[i + 1] == b'.' && dll[i + 2].is_ascii_digit() {
            let start = i;
            while i < dll.len() && dll[i] != 0 {
                i += 1;
            }
            let s = &dll[start..i];
            // and holds nothing but a dotted version of three or more parts,
            // which other strings that begin "4." do not
            let parts = s.split(|&b| b == b'.').count();
            if parts < 3 || !s.iter().all(|&b| b == b'.' || b.is_ascii_digit()) {
                continue;
            }
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

/// Whether `off` could be where a record stream starts: a `[u32 count]
/// [u32 type]` pair in range, followed by a common header that parses
pub(super) fn starts_record_stream(data: &[u8], off: usize, fmt: RecordFmt) -> bool {
    let Some(head) = off.checked_add(8).and_then(|end| data.get(off..end)) else {
        return false;
    };
    let count = u32::from_le_bytes(head[..4].try_into().unwrap());
    let first_type = u32::from_le_bytes(head[4..].try_into().unwrap());
    (1..=MAX_RECORD_COUNT).contains(&count)
        && (1..=MAX_RECORD_TYPE).contains(&first_type)
        && Cursor::new(data, off + 8, fmt).common().is_ok()
}

/// Scans from `from` for something that could start the record stream. Used
/// when the sections before the stream cannot be read (see
/// [`skip_to_record_stream`]). The scan stops a fixed distance past
/// `chain_end`, where the embedded DLLs stop
pub(super) fn find_record_stream(
    data: &[u8],
    from: usize,
    chain_end: usize,
    fmt: RecordFmt,
) -> Result<usize, Error> {
    let search_end = data.len().min(chain_end.saturating_add(0x40000));
    (from..search_end)
        .find(|&off| starts_record_stream(data, off, fmt))
        .ok_or_else(|| Error::InvalidArchive("record stream not found".into()))
}

/// Where the record stream starts, found by reading through the sections
/// that lie between the embedded DLLs and the stream. `None` when the
/// sections do not read cleanly or do not end on something that could start
/// a stream, in which case the caller scans instead
pub(super) fn exact_stream_start(data: &[u8], chain_end: usize, fmt: RecordFmt) -> Option<usize> {
    skip_to_record_stream(data, chain_end, fmt)
        .ok()
        .filter(|&off| starts_record_stream(data, off, fmt))
}

/// Largest number of support files looked for when anchoring on their chain
pub(super) const MAX_SUPPORT_FILES: usize = 64;

/// Finds the record stream by its two nearest neighbours when the sections
/// before it cannot all be read (the oldest runtimes store their settings
/// inline, in a form that is not decoded).
///
/// The support files sit shortly before the stream as a count followed by
/// `[u8 name length][name][12 bytes][u32 size][data]` entries. A count
/// whose entries all have printable file names and sizes that chain exactly
/// is very unlikely to occur by accident. After them comes the package
/// list, whose entry layout has a few known variants; the right one ends on
/// a record header. Only a position that passes all three checks is
/// returned
pub(super) fn anchored_stream_start(
    data: &[u8],
    chain_end: usize,
    fmt: RecordFmt,
) -> Option<usize> {
    let search_end = data.len().min(chain_end.saturating_add(0x40000));
    (chain_end..search_end).find_map(|pos| {
        // the count is one byte in the older runtimes and two after
        [1usize, 2].into_iter().find_map(|width| {
            let count = match width {
                1 => usize::from(*data.get(pos)?),
                _ => usize::from(u16::from_le_bytes(data.get(pos..pos + 2)?.try_into().ok()?)),
            };
            if count == 0 || count > MAX_SUPPORT_FILES {
                return None;
            }
            let after_files = skip_support_files(data, pos + width, count)?;
            skip_packages(data, after_files, fmt)
        })
    })
}

/// Steps over `count` support-file entries starting at `pos`, or `None` if
/// they are not all well formed
pub(super) fn skip_support_files(data: &[u8], mut pos: usize, count: usize) -> Option<usize> {
    for _ in 0..count {
        let name_len = usize::from(*data.get(pos)?);
        let name = data.get(pos + 1..pos + 1 + name_len)?;
        // a file name with an extension, in printable ASCII
        let printable = name.iter().all(|&b| (0x20..0x7F).contains(&b));
        if name_len < 3 || !printable || !name.contains(&b'.') {
            return None;
        }
        let size_at = pos + 1 + name_len + 12;
        let size = u32::from_le_bytes(data.get(size_at..size_at + 4)?.try_into().ok()?) as usize;
        pos = size_at.checked_add(4)?.checked_add(size)?;
        if size == 0 || pos > data.len() {
            return None;
        }
    }
    Some(pos)
}

/// Steps over the package list at `pos` and returns where it ends, if one of
/// the known entry layouts ends on a record header
pub(super) fn skip_packages(data: &[u8], pos: usize, fmt: RecordFmt) -> Option<usize> {
    // bytes from the description to the mask when the third text is empty,
    // and what follows the mask:
    // nothing, or a feature list closed by one or four bytes
    const VARIANTS: [(usize, Option<usize>); 6] = [
        (36, None),
        (36, Some(1)),
        (36, Some(4)),
        (37, Some(4)),
        (37, Some(1)),
        (37, None),
    ];
    VARIANTS.into_iter().find_map(|(fixed, tail)| {
        let mut c = Cursor::new(data, pos, fmt);
        let walk = (|| -> Result<(), Error> {
            for _ in 0..c.bounded_u16(MAX_ARRAY_COUNT, "package count")? {
                c.skip_package_front(fixed)?;
                if let Some(last) = tail {
                    c.skip(1)?;
                    let features = c.bounded_u16(MAX_ARRAY_COUNT, "package feature count")?;
                    c.skip(usize::from(features) * 5 + last)?;
                }
            }
            Ok(())
        })();
        (walk.is_ok() && starts_record_stream(data, c.pos, fmt)).then_some(c.pos)
    })
}

/// Reads through everything between the end of the embedded DLL chain and
/// the record stream, and returns where the stream starts
///
/// In order, the sections are:
/// - the language table: the main language, the title and prompt of the
///   language dialog, then a count of further languages and, for each, its
///   ID and two names
/// - the installer settings, as one compressed block with a u32 length
/// - (mainline only) billboards, as ordinary type 0x0f records; install
///   variables as name/value pairs; and web-install items, each a GUID and
///   two strings
/// - download servers: a GUID, five strings and a u16 each
/// - support files, in the same `[name][12 bytes][u32 size][data]` form as
///   the embedded DLLs, with a count in front
/// - packages (setup types and components): three localized strings, a block
///   of fixed fields, a feature list like the one in a record's common
///   header, and a last field whose width depends on the runtime
///
/// The oldest runtime (`Pre4`) stores its settings inline and is not decoded.
///
/// Lists whose entries have never been seen are expected to be empty.
///
/// # Errors
///
/// Returns [`Error::InvalidArchive`] if the data ends early, a length or
/// count is out of range, or a list that is not understood has entries
pub(super) fn skip_to_record_stream(
    data: &[u8],
    chain_end: usize,
    fmt: RecordFmt,
) -> Result<usize, Error> {
    // the oldest runtime stores its settings inline, not as one block, and
    // they are not decoded
    if fmt.is_pre4() {
        return Err(Error::InvalidArchive(
            "sections before the record stream are not decoded for this runtime".into(),
        ));
    }
    let not_understood =
        |what: &str| Error::InvalidArchive(format!("{what} before the record stream"));
    let apple = fmt == RecordFmt::Apple;
    let mut c = Cursor::new(data, chain_end, fmt);

    // language table: the main language, the language dialog, then any
    // further languages
    if c.u16()? != 0 {
        return Err(not_understood("an unknown field in the language table"));
    }
    c.skip(2)?; // language ID
    c.skip_string()?; // name of its string file, and its display name
    c.skip_string()?;
    c.skip(2)?;
    c.skip_string()?; // dialog title and prompt
    c.skip_string()?;
    let more_languages = c.bounded_u16(MAX_ARRAY_COUNT, "language count")?;
    for _ in 0..more_languages {
        c.skip(2)?;
        c.skip_string()?;
        c.skip_string()?;
    }

    // installer settings
    let settings_len = c.u32()? as usize;
    c.skip(settings_len)?;

    if apple {
        if c.u32()? != 0 {
            return Err(not_understood("an unknown list"));
        }
    } else {
        c.skip(1)?;
        for _ in 0..c.list_len()? {
            let rtype = c.u32()?;
            c.common()?;
            skip_type(&mut c, rtype)?;
        }
        for _ in 0..c.list_len()? {
            c.skip_string()?;
            c.skip_string()?;
        }
        for _ in 0..c.list_len()? {
            c.skip(16)?;
            c.skip_string()?;
            c.skip_string()?;
        }
    }

    // download servers
    for _ in 0..c.list_len()? {
        c.skip(16)?;
        for _ in 0..5 {
            c.skip_string()?;
        }
        c.skip(2)?;
    }

    // support files
    let support_files = if apple {
        u32::from(c.u8()?)
    } else {
        u32::from(c.u16()?)
    };
    for _ in 0..support_files {
        let name_len = usize::from(c.u8()?);
        c.skip(name_len + 12)?;
        let size = c.u32()? as usize;
        c.skip(size)?;
    }

    // packages
    let fixed = if fmt == RecordFmt::Main48 { 37 } else { 36 };
    // the last field is one byte up to 4.6 and in the Apple fork, four after
    let last = if matches!(fmt, RecordFmt::Apple | RecordFmt::Main46) {
        1
    } else {
        4
    };
    for _ in 0..c.u16()? {
        c.skip_package_front(fixed)?;
        c.skip(1)?;
        let features = c.bounded_u16(MAX_ARRAY_COUNT, "package feature count")?;
        c.skip(usize::from(features) * 5)?;
        c.skip(last)?;
    }

    Ok(c.pos)
}

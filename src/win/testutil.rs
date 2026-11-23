//! Builds small, complete Windows payloads from scratch, one per record
//! layout. They contain nothing from a real installer, so they can back
//! tests and seed the fuzzers

use super::RecordFmt;

pub(super) const HELLO: &[u8] = b"hello from a synthetic installer\n";

/// Raw DEFLATE with adjacent bytes swapped, as Windows VISE stores data
pub(super) fn swap_deflate(raw: &[u8]) -> Vec<u8> {
    let mut comp = flate2::Compress::new(flate2::Compression::best(), false);
    let mut out = vec![0u8; raw.len() + 64];
    comp.compress(raw, &mut out, flate2::FlushCompress::Finish)
        .unwrap();
    out.truncate(usize::try_from(comp.total_out()).unwrap());
    for pair in out.chunks_exact_mut(2) {
        pair.swap(0, 1);
    }
    out
}

/// A stand-in for the runtime DLL, carrying only the marker that
/// identifies its record layout
pub(super) fn fake_dll(fmt: RecordFmt) -> Vec<u8> {
    let marker: &[u8] = match fmt {
        RecordFmt::Pre4 | RecordFmt::Pre25 | RecordFmt::Pre24 => b"",
        RecordFmt::Apple => b"vise32qt.dll",
        RecordFmt::Main46 => b"4.6.2.0",
        RecordFmt::Main4 => b"4.7.0.0",
        RecordFmt::Main48 => b"4.9.0.0",
    };
    [
        b"MZ synthetic runtime\x00".as_slice(),
        marker,
        b"\x00end of image\x00\x00\x00\x00",
    ]
    .concat()
}

pub(super) fn label(fmt: RecordFmt) -> &'static str {
    match fmt {
        RecordFmt::Pre4 => "pre4",
        RecordFmt::Pre25 => "pre25",
        RecordFmt::Pre24 => "pre24",
        RecordFmt::Apple => "apple",
        RecordFmt::Main46 => "main46",
        RecordFmt::Main4 => "main4",
        RecordFmt::Main48 => "main48",
    }
}

/// The directory the layout records for its files. Mainline layouts keep
/// the install path out of the stream
pub(super) fn directory(fmt: RecordFmt) -> &'static str {
    match fmt {
        RecordFmt::Pre4 | RecordFmt::Pre25 | RecordFmt::Pre24 | RecordFmt::Apple => {
            "TargetDir/docs"
        }
        RecordFmt::Main46 | RecordFmt::Main4 | RecordFmt::Main48 => "",
    }
}

fn put_u16(out: &mut Vec<u8>, v: usize) {
    out.extend_from_slice(&u16::try_from(v).unwrap().to_le_bytes());
}

fn put_u32(out: &mut Vec<u8>, v: usize) {
    out.extend_from_slice(&u32::try_from(v).unwrap().to_le_bytes());
}

/// An inline string: one length byte in Pre4, two elsewhere
fn put_inline(out: &mut Vec<u8>, fmt: RecordFmt, s: &[u8]) {
    if fmt.is_pre4() {
        out.push(u8::try_from(s.len()).unwrap());
    } else {
        put_u16(out, s.len());
    }
    out.extend_from_slice(s);
}

/// A record's type tag and an all-zero common header, which declares no
/// features and no conditions
fn record_start(fmt: RecordFmt, rtype: usize) -> Vec<u8> {
    let common = match fmt {
        RecordFmt::Pre4 | RecordFmt::Pre25 | RecordFmt::Pre24 => 97,
        RecordFmt::Apple | RecordFmt::Main46 | RecordFmt::Main4 => 99,
        RecordFmt::Main48 => 100,
    };
    let mut r = Vec::new();
    put_u32(&mut r, rtype);
    r.resize(4 + common, 0);
    // every real record has an ID; they count up from 0x400
    r[4..8].copy_from_slice(&0x400u32.to_le_bytes());
    r
}

/// A type 2 (file) record
pub(super) fn file_record(
    fmt: RecordFmt,
    name: &str,
    uncomp: usize,
    comp: usize,
    blob: usize,
) -> Vec<u8> {
    let mut r = record_start(fmt, 2);
    // name, then a zero count of localized variants
    put_u16(&mut r, name.len());
    r.extend_from_slice(name.as_bytes());
    put_u16(&mut r, 0);
    // alternate name, empty
    put_inline(&mut r, fmt, b"");
    if fmt.is_pre4() || fmt == RecordFmt::Apple {
        put_inline(&mut r, fmt, b"%TargetDir%\\docs");
    }
    put_u32(&mut r, uncomp);
    put_u32(&mut r, comp);
    put_u32(&mut r, 0); // volume
    put_u32(&mut r, blob);
    r.resize(r.len() + 4 + 24 + 9, 0);
    put_inline(&mut r, fmt, b"");
    // fixed fields, with the CRC-32 of the contents among them
    r.resize(r.len() + if fmt == RecordFmt::Pre24 { 12 } else { 14 }, 0);
    let crc = if uncomp == HELLO.len() {
        let mut crc = flate2::Crc::new();
        crc.update(HELLO);
        crc.sum()
    } else {
        0
    };
    r.extend_from_slice(&crc.to_le_bytes());
    if matches!(fmt, RecordFmt::Pre25 | RecordFmt::Pre24) {
        r.resize(r.len() + 3, 0);
        return r;
    }
    r.resize(r.len() + 8, 0);
    match fmt {
        RecordFmt::Pre25 | RecordFmt::Pre24 => unreachable!(),
        RecordFmt::Pre4 => r.resize(r.len() + 4, 0),
        RecordFmt::Apple | RecordFmt::Main46 => {
            r.push(0);
            put_inline(&mut r, fmt, b"");
            r.resize(r.len() + 1 + 9, 0);
        }
        RecordFmt::Main4 | RecordFmt::Main48 => {
            r.push(0);
            put_inline(&mut r, fmt, b"");
            r.resize(r.len() + 1 + 10, 0);
        }
    }
    r
}

/// The size of a type 2 record for a file called `name`
pub(super) fn file_record_len(fmt: RecordFmt, name: &str) -> usize {
    file_record(fmt, name, 0, 0, 0).len()
}

/// A type 1 (folder) record
pub(super) fn folder_record(fmt: RecordFmt, name: &str) -> Vec<u8> {
    let mut r = record_start(fmt, 1);
    // name, then a zero count of localized variants
    put_u16(&mut r, name.len());
    r.extend_from_slice(name.as_bytes());
    put_u16(&mut r, 0);
    // the rest is fixed-size fields and empty strings
    let rest = match fmt {
        RecordFmt::Pre4 => 1 + 1 + 9 + 1 + 9,
        RecordFmt::Pre25 | RecordFmt::Pre24 => 1 + 1 + 9 + 1 + 2,
        RecordFmt::Apple => 2 + 2 + 9 + 2 + 3 + 2 + 4,
        RecordFmt::Main46 => 2 + 9 + 2 + 3 + 2 + 4,
        RecordFmt::Main4 | RecordFmt::Main48 => 2 + 9 + 2 + 3 + 2 + 5,
    };
    r.resize(r.len() + rest, 0);
    r
}

/// Sets the ID of a record and the ID of the folder record holding it
pub(super) fn with_ids(mut record: Vec<u8>, id: u32, parent: u32) -> Vec<u8> {
    record[4..8].copy_from_slice(&id.to_le_bytes());
    record[8..12].copy_from_slice(&parent.to_le_bytes());
    record
}

/// A stream of two nested folders and three empty files: one in each
/// folder and one outside both. The inner folder is declared after the
/// file that names it as its parent
pub(super) fn tree_stream(fmt: RecordFmt) -> Vec<u8> {
    let file = |name| file_record(fmt, name, 0, 0, 0);
    let mut s = Vec::new();
    put_u32(&mut s, 5);
    s.extend(with_ids(folder_record(fmt, "Outer"), 10, 0));
    s.extend(with_ids(file("outer.txt"), 11, 10));
    s.extend(with_ids(file("inner.txt"), 13, 12));
    s.extend(with_ids(folder_record(fmt, "In/ner"), 12, 10));
    s.extend(with_ids(file("top.txt"), 14, 0));
    s
}

fn put_string(out: &mut Vec<u8>, s: &[u8]) {
    put_u16(out, s.len());
    out.extend_from_slice(s);
}

/// The sections a real payload has between its DLL chain and its record
/// stream, with one entry in every list the layout has. The support file
/// is `support_len` bytes, which sets how far away the stream ends up.
/// The oldest layout stores these differently and is not built here
pub(super) fn sections(fmt: RecordFmt, support_len: usize) -> Vec<u8> {
    assert!(!fmt.is_pre4());
    let apple = fmt == RecordFmt::Apple;
    let mut s = Vec::new();

    // language table
    put_u16(&mut s, 0);
    put_u16(&mut s, 9);
    put_string(&mut s, b"English");
    put_string(&mut s, b"English");
    s.extend_from_slice(&[0, 1]);
    put_string(&mut s, b"Select Language");
    put_string(&mut s, b"Please select a language.");
    // one further language
    put_u16(&mut s, 1);
    put_u16(&mut s, 7);
    put_string(&mut s, b"GERMAN");
    put_string(&mut s, b"German");

    // installer settings: opaque, and long enough to hold stray bytes
    // that look like the start of a record stream
    let mut settings = vec![0xEE; 300];
    settings[100..104].copy_from_slice(&1u32.to_le_bytes());
    settings[104..108].copy_from_slice(&2u32.to_le_bytes());
    settings[108..300].fill(0);
    put_u32(&mut s, settings.len());
    s.extend_from_slice(&settings);

    if apple {
        put_u32(&mut s, 0);
    } else {
        s.push(0);
        // one billboard, an ordinary type 0x0f record
        put_u32(&mut s, 1);
        s.extend(record_start(fmt, 0x0f));
        put_string(&mut s, b"C:\\build\\billboard.jpg");
        s.resize(s.len() + 14, 0);
        // one variable
        put_u32(&mut s, 1);
        put_string(&mut s, b"TargetDir");
        put_string(&mut s, b"%ProgramFilesDir%\\Example");
        // one web-install item
        put_u32(&mut s, 1);
        s.extend_from_slice(&[0x11; 16]);
        put_string(&mut s, b"Example Item");
        put_string(&mut s, b"exampleitem");
    }

    // one download server
    put_u32(&mut s, 1);
    s.extend_from_slice(&[0x22; 16]);
    for field in [&b"Server"[..], b"host", b"", b"", b"path/"] {
        put_string(&mut s, field);
    }
    put_u16(&mut s, 1);

    // one support file
    if apple {
        s.push(1);
    } else {
        put_u16(&mut s, 1);
    }
    let name = b"support.bin";
    s.push(u8::try_from(name.len()).unwrap());
    s.extend_from_slice(name);
    s.resize(s.len() + 12, 0);
    put_u32(&mut s, support_len);
    s.resize(s.len() + support_len, 0x5A);

    // two packages, the second with a feature in its list, a
    // description longer than a record string may be, and translations
    // of its texts
    let fixed = if fmt == RecordFmt::Main48 { 37 } else { 36 };
    let tail = if matches!(fmt, RecordFmt::Apple | RecordFmt::Main46) {
        1
    } else {
        4
    };
    put_u16(&mut s, 2);
    for (name, description, features, translations) in [
        (&b"Typical Setup"[..], Vec::new(), 0usize, &[][..]),
        (b"Extras", vec![b'd'; 400], 1, &[&b"Extras"[..], b""][..]),
    ] {
        // name, description, one byte, and a third text; each text is
        // followed by its translations, a language ID in front of each
        for (text, between) in [(name, 0), (&description[..], 1), (&b""[..], 0)] {
            put_string(&mut s, text);
            put_u16(&mut s, translations.len());
            for (language, translated) in translations.iter().enumerate() {
                put_u16(&mut s, 7 + language);
                put_string(&mut s, translated);
            }
            s.resize(s.len() + between, 0);
        }
        s.resize(s.len() + fixed - 5, 0);
        s.resize(s.len() + 36, 0xFF);
        s.push(0);
        put_u16(&mut s, features);
        s.resize(s.len() + features * 5, 0x33);
        s.resize(s.len() + tail, 0);
    }
    s
}

/// Three records: a file, a one-byte record of another type, and an
/// empty file. `blob_field` is what the first file's offset field holds
fn record_stream(fmt: RecordFmt, comp: usize, blob_field: usize) -> Vec<u8> {
    let mut s = Vec::new();
    put_u32(&mut s, 3);
    s.extend(file_record(fmt, "hello.txt", HELLO.len(), comp, blob_field));
    s.extend(record_start(fmt, 0x0d));
    s.push(0);
    s.extend(file_record(fmt, "empty.dat", 0, 0, 0));
    s
}

/// A whole payload: header, a one-entry DLL chain, the record stream, then
/// the file data. `payload_file_offset` is where the payload would sit in
/// its executable, which Pre4 offsets are measured from
pub(super) fn payload(fmt: RecordFmt, payload_file_offset: usize) -> Vec<u8> {
    // a lone zero ends the DLL chain; the stream follows at once
    payload_with_gap(fmt, payload_file_offset, &[0])
}

/// [`payload`] with `gap` between the DLL chain and the record stream
pub(super) fn payload_with_gap(fmt: RecordFmt, payload_file_offset: usize, gap: &[u8]) -> Vec<u8> {
    let blob = swap_deflate(HELLO);
    let dll = swap_deflate(&fake_dll(fmt));

    // the Apple fork wraps the ESIV header in a SIVM one
    let sivm = fmt == RecordFmt::Apple;
    let mut out = Vec::new();
    if sivm {
        out.extend_from_slice(b"SIVM");
        put_u32(&mut out, 0);
    }
    out.extend_from_slice(b"ESIV");
    put_u32(&mut out, 0x5E55_1011); // session id
    put_u32(&mut out, 1); // version
    put_u32(&mut out, 0); // flags
    out.resize(out.len() + 8, 0); // installer metadata

    let name = b"vise32ex.dll";
    out.push(u8::try_from(name.len()).unwrap());
    out.extend_from_slice(name);
    out.resize(out.len() + 12, 0);
    put_u32(&mut out, dll.len());
    out.extend_from_slice(&dll);
    out.extend_from_slice(gap);

    let stream_len = record_stream(fmt, blob.len(), 0).len();
    let blob_at = out.len() + stream_len;
    let blob_field = match fmt {
        RecordFmt::Pre4 | RecordFmt::Pre25 | RecordFmt::Pre24 => blob_at + payload_file_offset,
        RecordFmt::Apple => blob_at - super::SIVM_BLOB_OFFSET,
        RecordFmt::Main46 | RecordFmt::Main4 | RecordFmt::Main48 => blob_at,
    };
    out.extend(record_stream(fmt, blob.len(), blob_field));
    out.extend_from_slice(&blob);
    out
}

/// Input for the record-stream fuzz target: the selector byte for `fmt`,
/// the stream, then the file data it points at
pub(super) fn records_input(fmt: RecordFmt) -> Vec<u8> {
    let blob = swap_deflate(HELLO);
    let stream_len = record_stream(fmt, blob.len(), 0).len();
    let selector = super::FUZZ_SELECT
        .iter()
        .find(|&&(_, f)| f == fmt)
        .map_or_else(
            || {
                let index = super::ALL_FORMATS.iter().position(|&f| f == fmt).unwrap();
                u8::try_from(index).unwrap()
            },
            |&(bit, _)| bit,
        );
    let mut out = vec![selector];
    out.extend(record_stream(fmt, blob.len(), stream_len));
    out.extend_from_slice(&blob);
    out
}

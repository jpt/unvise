//! Builds small, complete Windows payloads from scratch, one per record
//! layout. They contain nothing from a real installer, so they can back
//! tests and seed the fuzzers. Records are built from the layout tables,
//! so a payload exists for every layout there is

use super::LayoutId;
use super::grammar::{Op, Text, Width};

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

/// A stand-in for the runtime DLL
pub(super) fn fake_dll() -> Vec<u8> {
    b"MZ synthetic runtime\x00end of image\x00\x00\x00\x00".to_vec()
}

pub(super) fn label(layout: LayoutId) -> String {
    format!("{layout:?}")
}

/// The directory the layout records for its files. The layouts that keep
/// no folder in a file record leave it to the folder records
pub(super) fn directory(layout: LayoutId) -> &'static str {
    if layout.table().file.folder.is_some() {
        "TargetDir/docs"
    } else {
        ""
    }
}

/// Whether test payloads in this layout count file offsets from the start
/// of the executable. The parser settles it by decoding, so the choice is
/// only what the payload is built with
fn offsets_from_file(layout: LayoutId) -> bool {
    layout.table().file.after_times == Text::Short
}

fn put_u16(out: &mut Vec<u8>, v: usize) {
    out.extend_from_slice(&u16::try_from(v).unwrap().to_le_bytes());
}

fn put_u32(out: &mut Vec<u8>, v: usize) {
    out.extend_from_slice(&u32::try_from(v).unwrap().to_le_bytes());
}

fn put_text(out: &mut Vec<u8>, kind: Text, s: &[u8]) {
    match kind {
        Text::Short => out.push(u8::try_from(s.len()).unwrap()),
        Text::Long => put_u16(out, s.len()),
    }
    out.extend_from_slice(s);
}

fn put_value(out: &mut Vec<u8>, width: Width, v: usize) {
    let bytes = match width {
        Width::W1 => 1,
        Width::W2 => 2,
        Width::W4 => 4,
    };
    out.extend_from_slice(&u32::try_from(v).unwrap().to_le_bytes()[..bytes]);
}

/// What `ops` describes with nothing in it: every count and flag zero and
/// every string empty
fn empty(ops: &[Op], out: &mut Vec<u8>) {
    for op in ops {
        match *op {
            Op::Skip(n) => out.resize(out.len() + usize::from(n), 0),
            Op::Text(Text::Short) => out.push(0),
            Op::Text(Text::Long) => put_u16(out, 0),
            Op::TextThen(kind, when_empty, _) => {
                put_text(out, kind, b"");
                empty(when_empty, out);
            }
            Op::Loc | Op::Block => put_u32(out, 0),
            Op::Repeat(width, _) | Op::When(width, _) | Op::WhenBits(width, _, _) => {
                put_value(out, width, 0);
            }
            Op::Choose(width, choices, otherwise) => {
                put_value(out, width, 0);
                let body = choices
                    .iter()
                    .find(|(values, _)| values.contains(&0))
                    .map_or(otherwise, |&(_, body)| body);
                empty(body, out);
            }
        }
    }
}

/// What `ops` describes with something in everything: one entry in every
/// list, text in every string and `block` bytes in every block. Flags and
/// selectors stay zero
fn filled(ops: &[Op], block: usize, out: &mut Vec<u8>) {
    for op in ops {
        match *op {
            Op::Skip(n) => out.resize(out.len() + usize::from(n), 0),
            Op::Text(kind) => put_text(out, kind, b"some text"),
            Op::TextThen(kind, _, otherwise) => {
                put_text(out, kind, b"some text");
                filled(otherwise, block, out);
            }
            Op::Loc => {
                // a text longer than a record string may be, and a translation
                put_text(out, Text::Long, &[b'd'; 400]);
                put_u16(out, 1);
                put_u16(out, 7);
                put_text(out, Text::Long, b"translated");
            }
            Op::Block => {
                put_u32(out, block);
                // bytes that could pass for the start of a record stream
                let at = out.len();
                out.resize(at + block, 0);
                if block >= 8 {
                    out[at..at + 4].copy_from_slice(&1u32.to_le_bytes());
                    out[at + 4..at + 8].copy_from_slice(&2u32.to_le_bytes());
                }
            }
            Op::Repeat(width, body) => {
                put_value(out, width, 1);
                filled(body, block, out);
            }
            Op::When(width, _) | Op::WhenBits(width, _, _) => put_value(out, width, 0),
            Op::Choose(width, choices, otherwise) => {
                put_value(out, width, 0);
                let body = choices
                    .iter()
                    .find(|(values, _)| values.contains(&0))
                    .map_or(otherwise, |&(_, body)| body);
                filled(body, block, out);
            }
        }
    }
}

/// A record's type tag and a common header that declares no features and
/// no conditions
fn record_start(layout: LayoutId, rtype: usize) -> Vec<u8> {
    let mut r = Vec::new();
    put_u32(&mut r, rtype);
    // every real record has an ID; they count up from 0x400
    put_u32(&mut r, 0x400);
    put_u32(&mut r, 0);
    empty(layout.table().header, &mut r);
    r
}

/// A record of type `rtype` with nothing in its body
pub(super) fn empty_record(layout: LayoutId, rtype: usize) -> Vec<u8> {
    let mut r = record_start(layout, rtype);
    empty(layout.table().bodies[rtype - 1].unwrap(), &mut r);
    r
}

/// Where a file record built by [`file_record_with_offsets`] keeps things,
/// as offsets into the record
pub(super) struct FileOffsets {
    /// The byte that names a download item, in the layouts that have one
    pub(super) source: Option<usize>,
}

/// A type 2 (file) record and where its fields are
pub(super) fn file_record_with_offsets(
    layout: LayoutId,
    name: &str,
    uncomp: usize,
    comp: usize,
    blob: usize,
) -> (Vec<u8>, FileOffsets) {
    let table = layout.table();
    let file = &table.file;
    let body = table.bodies[1].unwrap();
    let mut r = record_start(layout, 2);
    // name, then a zero count of translations
    put_text(&mut r, Text::Long, name.as_bytes());
    put_u16(&mut r, 0);
    for (index, &kind) in file.before_sizes.iter().enumerate() {
        let text: &[u8] = if file.folder == Some(index) {
            b"%TargetDir%\\docs"
        } else {
            b""
        };
        put_text(&mut r, kind, text);
    }
    put_u32(&mut r, uncomp);
    put_u32(&mut r, comp);
    put_u32(&mut r, 0); // volume
    put_u32(&mut r, blob);
    // attributes, three times, and nine bytes more
    r.resize(r.len() + 4 + 24 + 9, 0);
    put_text(&mut r, file.after_times, b"");
    let fixed = r.len();
    // the name, the strings, the block just written and the string after it
    empty(&body[file.before_sizes.len() + 3..], &mut r);
    let crc = if uncomp == HELLO.len() {
        let mut crc = flate2::Crc::new();
        crc.update(HELLO);
        crc.sum()
    } else {
        0
    };
    r[fixed + file.crc_at..fixed + file.crc_at + 4].copy_from_slice(&crc.to_le_bytes());
    let offsets = FileOffsets {
        source: file.source_at.map(|at| fixed + at),
    };
    (r, offsets)
}

/// A type 2 (file) record
pub(super) fn file_record(
    layout: LayoutId,
    name: &str,
    uncomp: usize,
    comp: usize,
    blob: usize,
) -> Vec<u8> {
    file_record_with_offsets(layout, name, uncomp, comp, blob).0
}

/// The size of a type 2 record for a file called `name`
pub(super) fn file_record_len(layout: LayoutId, name: &str) -> usize {
    file_record(layout, name, 0, 0, 0).len()
}

/// A type 1 (folder) record
pub(super) fn folder_record(layout: LayoutId, name: &str) -> Vec<u8> {
    let body = layout.table().bodies[0].unwrap();
    assert!(matches!(body[0], Op::Loc));
    let mut r = record_start(layout, 1);
    // name, then a zero count of translations
    put_text(&mut r, Text::Long, name.as_bytes());
    put_u16(&mut r, 0);
    empty(&body[1..], &mut r);
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
pub(super) fn tree_stream(layout: LayoutId) -> Vec<u8> {
    let file = |name| file_record(layout, name, 0, 0, 0);
    let mut s = Vec::new();
    put_u32(&mut s, 5);
    s.extend(with_ids(folder_record(layout, "Outer"), 10, 0));
    s.extend(with_ids(file("outer.txt"), 11, 10));
    s.extend(with_ids(file("inner.txt"), 13, 12));
    s.extend(with_ids(folder_record(layout, "In/ner"), 12, 10));
    s.extend(with_ids(file("top.txt"), 14, 0));
    s
}

/// What lies between the embedded files and the record stream, with one entry in
/// every list the layout has there. Every block in it, the support file
/// among them, is `block` bytes, which sets how far away the stream ends up
pub(super) fn sections(layout: LayoutId, block: usize) -> Vec<u8> {
    let mut s = Vec::new();
    filled(layout.table().start, block, &mut s);
    s
}

/// What lies between the embedded files and the record stream when every list
/// there is empty
pub(super) fn empty_sections(layout: LayoutId) -> Vec<u8> {
    let mut s = Vec::new();
    empty(layout.table().start, &mut s);
    s
}

/// Three records: a file, a record of another type, and an empty file.
/// `blob_field` is what the first file's offset field holds
fn record_stream(layout: LayoutId, comp: usize, blob_field: usize) -> Vec<u8> {
    stream_ending_with(layout, comp, blob_field, None)
}

/// The stream of [`payload`], or with `last`, the file with contents and
/// then one record of that type with nothing in it
fn stream_ending_with(
    layout: LayoutId,
    comp: usize,
    blob_field: usize,
    last: Option<usize>,
) -> Vec<u8> {
    let mut s = Vec::new();
    if let Some(rtype) = last {
        put_u32(&mut s, 2);
        s.extend(file_record(
            layout,
            "hello.txt",
            HELLO.len(),
            comp,
            blob_field,
        ));
        s.extend(empty_record(layout, rtype));
        return s;
    }
    put_u32(&mut s, 3);
    s.extend(file_record(
        layout,
        "hello.txt",
        HELLO.len(),
        comp,
        blob_field,
    ));
    s.extend(empty_record(layout, 0x0d));
    s.extend(file_record(layout, "empty.dat", 0, 0, 0));
    s
}

/// A whole payload: header, one embedded file, the sections before the
/// record stream with nothing in them, the stream, then the file data.
/// `payload_file_offset` is where the payload would sit in its executable
pub(super) fn payload(layout: LayoutId, payload_file_offset: usize) -> Vec<u8> {
    payload_with_gap(layout, payload_file_offset, &empty_sections(layout))
}

/// [`payload`] with `gap` between the embedded files and the record stream
pub(super) fn payload_with_gap(
    layout: LayoutId,
    payload_file_offset: usize,
    gap: &[u8],
) -> Vec<u8> {
    build_payload(layout, payload_file_offset, gap, false, None)
}

/// [`payload`] under an SIVM header, as it sits in a PE section
pub(super) fn sivm_payload(layout: LayoutId) -> Vec<u8> {
    build_payload(layout, 0, &empty_sections(layout), true, None)
}

/// [`payload`] with a stream of one file and then a record of type `last`
pub(super) fn payload_ending_with(layout: LayoutId, last: usize) -> Vec<u8> {
    build_payload(layout, 0, &empty_sections(layout), false, Some(last))
}

fn build_payload(
    layout: LayoutId,
    payload_file_offset: usize,
    gap: &[u8],
    sivm: bool,
    last: Option<usize>,
) -> Vec<u8> {
    let blob = swap_deflate(HELLO);
    let dll = swap_deflate(&fake_dll());

    let mut out = Vec::new();
    if sivm {
        out.extend_from_slice(b"SIVM");
        put_u32(&mut out, 0);
    }
    out.extend_from_slice(b"ESIV");
    put_u32(&mut out, 0x5E55_1011); // session id
    put_u32(&mut out, 1); // version
    put_u32(&mut out, 0); // flags
    out.push(0); // an empty string
    out.push(0);
    out.push(0); // the end of another
    put_u16(&mut out, 1); // embedded files

    let name = b"vise32ex.dll";
    out.push(u8::try_from(name.len()).unwrap());
    out.extend_from_slice(name);
    out.resize(out.len() + 12, 0);
    put_u32(&mut out, dll.len());
    out.extend_from_slice(&dll);
    out.extend_from_slice(gap);

    let stream_len = stream_ending_with(layout, blob.len(), 0, last).len();
    let blob_at = out.len() + stream_len;
    let blob_field = if sivm {
        blob_at - super::SIVM_BLOB_OFFSET
    } else if offsets_from_file(layout) {
        blob_at + payload_file_offset
    } else {
        blob_at
    };
    out.extend(stream_ending_with(layout, blob.len(), blob_field, last));
    out.extend_from_slice(&blob);
    out
}

/// Input for the record-stream fuzz target: the selector byte for `layout`,
/// the stream, then the file data it points at
pub(super) fn records_input(layout: LayoutId) -> Vec<u8> {
    let blob = swap_deflate(HELLO);
    let stream_len = record_stream(layout, blob.len(), 0).len();
    let index = super::LAYOUTS.iter().position(|&f| f == layout).unwrap();
    let mut out = vec![u8::try_from(index << 3).unwrap()];
    out.extend(record_stream(layout, blob.len(), stream_len));
    out.extend_from_slice(&blob);
    out
}

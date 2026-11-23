#![allow(clippy::wildcard_imports)]

use super::records::*;
use super::sections::*;
use super::*;
use crate::safe_join;
use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::time::Duration;

#[test]
fn detects_each_runtime_from_its_dll() {
    assert_eq!(
        detect_record_fmt(b"..\x00vise32qt.dll\x00.."),
        RecordFmt::Apple
    );
    assert_eq!(detect_record_fmt(b"..\x004.7.0.2\x00.."), RecordFmt::Main4);
    assert_eq!(detect_record_fmt(b"..\x004.6.2.0\x00.."), RecordFmt::Main46);
    assert_eq!(detect_record_fmt(b"..\x004.9.0.0\x00.."), RecordFmt::Main48);
    assert_eq!(detect_record_fmt(b"no markers here"), RecordFmt::Pre4);
}

#[test]
fn read_checks_range_size_and_qdat() {
    // a raw DEFLATE stream for b"hello", byte-pair swapped
    let mut comp = flate2::Compress::new(flate2::Compression::best(), false);
    let mut blob = vec![0u8; 64];
    comp.compress(b"hello", &mut blob, flate2::FlushCompress::Finish)
        .unwrap();
    blob.truncate(usize::try_from(comp.total_out()).unwrap());
    for pair in blob.chunks_exact_mut(2) {
        pair.swap(0, 1);
    }

    let entry = |offset, compressed_len, uncompressed_len, use_qdat| WinEntry {
        name: "f".into(),
        directory: String::new(),
        offset,
        compressed_len,
        uncompressed_len,
        modified: None,
        crc32: 0,
        location: if use_qdat {
            Location::Qdat
        } else {
            Location::Installer
        },
        misplaced: false,
    };
    let info = WinArchiveInfo {
        version: 0,
        flags: 0,
        web: false,
        entries: Vec::new(),
    };
    let archive = WinArchive::assemble(blob.clone(), 0..blob.len(), None, info);

    assert_eq!(
        archive.read(&entry(0, blob.len(), 5, false)).unwrap(),
        b"hello"
    );
    // size unknown (0) is accepted; a wrong size is an error
    assert_eq!(
        archive.read(&entry(0, blob.len(), 0, false)).unwrap(),
        b"hello"
    );
    assert!(matches!(
        archive.read(&entry(0, blob.len(), 6, false)),
        Err(Error::Decompression(_))
    ));
    // data that runs past the end of the file is not there to decode
    assert!(matches!(
        archive.read(&entry(1, blob.len(), 5, false)),
        Err(Error::Skipped(SkipReason::MissingData))
    ));
    assert!(matches!(
        archive.read(&entry(0, blob.len(), 5, true)),
        Err(Error::Skipped(SkipReason::MissingQdat))
    ));
    assert_eq!(archive.read(&entry(0, 0, 0, false)).unwrap(), b"");
    // a size with nothing stored for it is not an empty file
    assert!(matches!(
        archive.read(&entry(0, 0, 5, false)),
        Err(Error::Skipped(SkipReason::MissingData))
    ));
}

/// One part of a multi-part installer: header, data, and whatever
/// trails the data
fn volume_file(session: u32, number: u32, data: &[u8], trailer: &[u8]) -> Vec<u8> {
    let mut out = b"ESIV".to_vec();
    let size = u32::try_from(VOLUME_HEADER + data.len()).unwrap();
    for field in [session, number, size] {
        out.extend_from_slice(&field.to_le_bytes());
    }
    out.extend_from_slice(data);
    out.extend_from_slice(trailer);
    out
}

#[test]
fn multi_part_installer_reads_across_its_parts() {
    const SESSION: u32 = 0x3762_E5A2;
    // incompressible enough that each stored file is a few hundred bytes
    let contents = |seed: u32, len: usize| -> Vec<u8> {
        let mut x = seed;
        (0..len)
            .map(|_| {
                x = x.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
                (x >> 24) as u8
            })
            .collect()
    };
    let (a, b, c) = (contents(1, 300), contents(2, 900), contents(3, 300));
    let (za, zb, zc) = (
        testutil::swap_deflate(&a),
        testutil::swap_deflate(&b),
        testutil::swap_deflate(&c),
    );
    // a sits whole in part 1; b starts in part 1, fills part 2 and ends
    // in part 3; c follows it there
    let (cut1, cut2) = (zb.len() / 3, 2 * zb.len() / 3);
    let part1 = volume_file(SESSION, 1, &[&za[..], &zb[..cut1]].concat(), b"trailer!");
    let part2 = volume_file(SESSION, 2, &zb[cut1..cut2], b"");
    let part3 = volume_file(SESSION, 3, &[&zb[cut2..], &zc[..]].concat(), b"");

    let crc = |data: &[u8]| {
        let mut crc = flate2::Crc::new();
        crc.update(data);
        crc.sum()
    };
    let entry = |name: &str, volume, offset, stored: &[u8], data: &[u8]| WinEntry {
        name: name.into(),
        directory: String::new(),
        offset,
        compressed_len: stored.len(),
        uncompressed_len: data.len(),
        modified: None,
        crc32: crc(data),
        location: if volume > 1 {
            Location::Part(volume)
        } else {
            Location::Installer
        },
        misplaced: false,
    };
    let entries = vec![
        entry("a", 1, VOLUME_HEADER, &za, &a),
        entry("b", 1, VOLUME_HEADER + za.len(), &zb, &b),
        entry("c", 3, VOLUME_HEADER + zb.len() - cut2, &zc, &c),
    ];
    let info = WinArchiveInfo {
        version: 0,
        flags: 0,
        web: false,
        entries,
    };
    let mut archive = WinArchive::assemble(part1.clone(), 0..part1.len(), None, info);
    let read = |archive: &WinArchive, i: usize| archive.read(&archive.info.entries[i]);
    assert_eq!(archive.last_volume(), 3);

    // without the other parts, what part 1 holds whole is still read
    assert_eq!(read(&archive, 0).unwrap(), a);
    assert!(matches!(
        read(&archive, 1),
        Err(Error::Skipped(SkipReason::SegmentNotLoaded(2)))
    ));
    assert!(matches!(
        read(&archive, 2),
        Err(Error::Skipped(SkipReason::SegmentNotLoaded(3)))
    ));

    // part 3 alone follows a gap and is not used
    assert_eq!(archive.set_volumes(vec![part3.clone()]), 0);
    // a part of some other installer is left out; order does not matter
    let stranger = volume_file(SESSION + 1, 2, b"other", b"");
    assert_eq!(
        archive.set_volumes(vec![part3.clone(), stranger, part2.clone()]),
        2
    );
    assert_eq!(read(&archive, 0).unwrap(), a);
    assert_eq!(read(&archive, 1).unwrap(), b);
    assert_eq!(read(&archive, 2).unwrap(), c);

    // with part 3 missing, the file that needs it says so
    assert_eq!(archive.set_volumes(vec![part2]), 1);
    assert!(matches!(
        read(&archive, 1),
        Err(Error::Skipped(SkipReason::SegmentNotLoaded(3)))
    ));

    assert_eq!(WinArchive::volume_number(&part3, SESSION), Some(3));
    assert_eq!(WinArchive::volume_number(&part3, SESSION + 1), None);
    assert_eq!(WinArchive::volume_number(&archive.data, SESSION), None);
    assert_eq!(WinArchive::volume_number(b"ESIV", SESSION), None);
}

#[test]
fn parses_and_reads_each_runtime_variant() {
    for fmt in ALL_FORMATS {
        let archive = WinArchive::parse(testutil::payload(fmt, 0), None, 0)
            .unwrap_or_else(|e| panic!("{}: {e}", testutil::label(fmt)));
        let entries = &archive.info.entries;
        let paths: Vec<String> = entries.iter().map(WinEntry::path).collect();
        let dir = testutil::directory(fmt);
        let in_dir = |name: &str| {
            if dir.is_empty() {
                name.to_string()
            } else {
                format!("{dir}/{name}")
            }
        };
        assert_eq!(
            paths,
            [
                "vise32ex.dll".to_string(),
                in_dir("hello.txt"),
                in_dir("empty.dat")
            ],
            "{}",
            testutil::label(fmt)
        );

        assert_eq!(archive.read(&entries[0]).unwrap(), testutil::fake_dll(fmt));
        assert_eq!(archive.read(&entries[1]).unwrap(), testutil::HELLO);
        assert_eq!(entries[1].uncompressed_len, testutil::HELLO.len());
        assert_eq!(archive.read(&entries[2]).unwrap(), b"");
    }
}

#[test]
fn pre4_offsets_are_measured_from_the_file_start() {
    let at = 0x4000;
    let archive = WinArchive::parse(testutil::payload(RecordFmt::Pre4, at), None, at).unwrap();
    assert_eq!(
        archive.read(&archive.info.entries[1]).unwrap(),
        testutil::HELLO
    );
    // the same payload read as if it sat at offset 0 points past its data
    let wrong = WinArchive::parse(testutil::payload(RecordFmt::Pre4, at), None, 0).unwrap();
    assert!(wrong.read(&wrong.info.entries[1]).is_err());
}

#[test]
fn extracts_a_synthetic_installer_to_disk() {
    let fmt = RecordFmt::Apple;
    let archive = WinArchive::parse(testutil::payload(fmt, 0), None, 0).unwrap();
    let tmp = tempfile::tempdir().unwrap();
    let result = archive.extract(tmp.path()).unwrap();
    assert_eq!(result.extracted, 3);
    assert_eq!(result.failed, 0);

    let docs = tmp.path().join(testutil::directory(fmt));
    assert_eq!(fs::read(docs.join("hello.txt")).unwrap(), testutil::HELLO);
    assert_eq!(fs::read(docs.join("empty.dat")).unwrap(), b"");
    assert_eq!(
        fs::read(tmp.path().join("vise32ex.dll")).unwrap(),
        testutil::fake_dll(fmt)
    );
}

#[test]
fn folder_records_give_files_their_install_path() {
    for fmt in ALL_FORMATS {
        let stream = testutil::tree_stream(fmt);
        let mut entries = Vec::new();
        let read = parse_record_stream(&stream, 0, &StreamReading::plain(fmt), &mut entries)
            .unwrap_or_else(|e| panic!("{}: {e}", testutil::label(fmt)));
        assert!(
            read.complete && read.realigned == 0,
            "{}",
            testutil::label(fmt)
        );
        let paths: Vec<String> = entries.iter().map(WinEntry::path).collect();
        let expected: [&str; 3] = match fmt {
            // these layouts store a path with each file, which wins
            RecordFmt::Pre4 | RecordFmt::Pre25 | RecordFmt::Pre24 | RecordFmt::Apple => [
                "TargetDir/docs/outer.txt",
                "TargetDir/docs/inner.txt",
                "TargetDir/docs/top.txt",
            ],
            // a separator inside a folder name does not split it
            RecordFmt::Main46 | RecordFmt::Main4 | RecordFmt::Main48 => {
                ["Outer/outer.txt", "Outer/In_ner/inner.txt", "top.txt"]
            }
        };
        assert_eq!(paths, expected, "{}", testutil::label(fmt));
    }
}

/// Layouts whose sections before the stream are read through
const SECTIONED: [RecordFmt; 4] = [
    RecordFmt::Apple,
    RecordFmt::Main46,
    RecordFmt::Main4,
    RecordFmt::Main48,
];

#[test]
fn stream_is_found_by_reading_the_sections_before_it() {
    for fmt in SECTIONED {
        let label = testutil::label(fmt);
        // a support file larger than the distance the fallback scan covers
        let gap = testutil::sections(fmt, 0x50000);
        let bytes = testutil::payload_with_gap(fmt, 0, &gap);
        let archive =
            WinArchive::parse(bytes.clone(), None, 0).unwrap_or_else(|e| panic!("{label}: {e}"));
        let names: Vec<&str> = archive
            .info
            .entries
            .iter()
            .map(|e| e.name.as_str())
            .collect();
        assert_eq!(names, ["vise32ex.dll", "hello.txt", "empty.dat"], "{label}");
        assert_eq!(
            archive.read(&archive.info.entries[1]).unwrap(),
            testutil::HELLO
        );

        // exactly one position, right after the sections
        let first = find_first_entry(&bytes).unwrap();
        let (chain_end, _) = walk_named_chain(&bytes, first, &mut Vec::new());
        assert_eq!(
            exact_stream_start(&bytes, chain_end, fmt),
            Some(chain_end + gap.len()),
            "{label}"
        );
    }
}

#[test]
fn sections_that_are_not_understood_fall_back_to_the_scan() {
    for fmt in SECTIONED {
        let label = testutil::label(fmt);
        let mut gap = testutil::sections(fmt, 64);
        // a first field that is not zero is not understood
        gap[0] = 1;
        let bytes = testutil::payload_with_gap(fmt, 0, &gap);
        let first = find_first_entry(&bytes).unwrap();
        let (chain_end, _) = walk_named_chain(&bytes, first, &mut Vec::new());
        assert_eq!(exact_stream_start(&bytes, chain_end, fmt), None, "{label}");

        let archive = WinArchive::parse(bytes, None, 0).unwrap_or_else(|e| panic!("{label}: {e}"));
        assert_eq!(archive.info.entries.len(), 3, "{label}");
        assert_eq!(
            archive.read(&archive.info.entries[1]).unwrap(),
            testutil::HELLO
        );
    }
}

#[test]
fn truncated_sections_are_an_error_not_a_panic() {
    for fmt in SECTIONED {
        let gap = testutil::sections(fmt, 64);
        for len in 0..gap.len() {
            // every prefix either errors or stops somewhere in range
            if let Ok(end) = skip_to_record_stream(&gap[..len], 0, fmt) {
                assert!(end <= len);
            }
        }
    }
}

#[test]
fn read_checks_the_recorded_crc() {
    let bytes = testutil::payload(RecordFmt::Main4, 0);
    let archive = WinArchive::parse(bytes, None, 0).unwrap();
    let mut entry = archive.info.entries[1].clone();
    assert_ne!(entry.crc32, 0);
    assert_eq!(archive.read(&entry).unwrap(), testutil::HELLO);

    entry.crc32 ^= 1;
    assert!(matches!(
        archive.read(&entry),
        Err(Error::Checksum { expected, actual }) if expected == actual ^ 1
    ));
    // no CRC recorded means nothing to check
    entry.crc32 = 0;
    assert_eq!(archive.read(&entry).unwrap(), testutil::HELLO);
}

#[test]
fn read_tells_downloaded_files_from_damaged_ones() {
    let bytes = testutil::payload(RecordFmt::Main4, 0);
    let mut archive = WinArchive::parse(bytes, None, 0).unwrap();
    let entry = archive.info.entries[1].clone();
    assert_eq!(archive.read(&entry).unwrap(), testutil::HELLO);

    // a record that names a download item is not read at all
    let mut item = entry.clone();
    item.location = Location::Download;
    assert!(matches!(
        archive.read(&item),
        Err(Error::Skipped(SkipReason::Downloaded))
    ));

    // data that does not read where the record points is damage in an
    // ordinary installer
    let mut astray = entry.clone();
    astray.offset -= 1;
    astray.misplaced = true;
    let damaged = |r| matches!(r, Err(Error::Decompression(_) | Error::Checksum { .. }));
    assert!(damaged(archive.read(&astray)));
    // in a web installer it is a file left to download, provided the
    // position could not hold the file: one that sits where a file
    // should and does not read is still damage
    archive.info.web = true;
    assert!(matches!(
        archive.read(&astray),
        Err(Error::Skipped(SkipReason::Downloaded))
    ));
    astray.misplaced = false;
    assert!(damaged(archive.read(&astray)));
    // a web installer still yields the files it does carry
    assert_eq!(archive.read(&entry).unwrap(), testutil::HELLO);
}

#[test]
fn record_search_is_charged_for_all_it_scans() {
    let fmt = RecordFmt::Main4;
    // a candidate whose parent was never seen, then nothing: the search
    // goes on past it looking for a better one, and that is not free
    let mut data = testutil::with_ids(testutil::folder_record(fmt, "Stray"), 0x500, 0x7777);
    data.resize(data.len() + 2 * PARENT_LOOKAHEAD, 0);
    let mut budget = 10 * PARENT_LOOKAHEAD;
    assert_eq!(
        find_next_record(&data, 0, fmt, &HashSet::new(), &mut budget),
        Some(0)
    );
    assert!(budget <= 9 * PARENT_LOOKAHEAD);
    // and a budget that runs out ends the search
    let mut budget = PARENT_LOOKAHEAD / 2;
    assert_eq!(
        find_next_record(&data, 0, fmt, &HashSet::new(), &mut budget),
        None
    );
}

#[test]
fn a_wrong_recorded_size_does_not_lift_the_output_limit() {
    // a megabyte of zeros stored in about a kilobyte, recorded as one byte
    // with the right checksum: far more than a stale size explains
    let contents = vec![0u8; 1 << 20];
    let blob = testutil::swap_deflate(&contents);
    let mut crc = flate2::Crc::new();
    crc.update(&contents);
    let entry = |uncompressed_len| WinEntry {
        name: "f".into(),
        directory: String::new(),
        offset: 0,
        compressed_len: blob.len(),
        uncompressed_len,
        modified: None,
        crc32: crc.sum(),
        location: Location::Installer,
        misplaced: false,
    };
    let info = WinArchiveInfo {
        version: 0,
        flags: 0,
        web: false,
        entries: Vec::new(),
    };
    let archive = WinArchive::assemble(blob.clone(), 0..blob.len(), None, info);
    assert!(matches!(
        archive.read(&entry(1)),
        Err(Error::Decompression(_))
    ));
    // within reach of the recorded size it is accepted on the checksum
    assert_eq!(archive.read(&entry((1 << 20) - 5000)).unwrap(), contents);
}

#[test]
fn misplaced_files_are_marked() {
    let file = |offset, compressed_len| WinEntry {
        name: "f".into(),
        directory: String::new(),
        offset,
        compressed_len,
        uncompressed_len: 1,
        modified: None,
        crc32: 0,
        location: Location::Installer,
        misplaced: false,
    };
    // the file data starts at 100 and the payload is 1000 bytes
    let mut files = vec![
        file(40, 10),   // inside the record stream
        file(100, 50),  // sound
        file(150, 50),  // sound, straight after it
        file(300, 100), // shares bytes with the next
        file(350, 10),
        file(990, 20), // runs past the end
        file(500, 0),  // stores nothing, so there is nothing to place
    ];
    mark_misplaced(&mut files, 100, 1000);
    let marked: Vec<bool> = files.iter().map(|f| f.misplaced).collect();
    assert_eq!(marked, [true, false, false, true, true, true, false]);
}

#[test]
fn a_wrong_recorded_size_is_overruled_by_the_checksum() {
    let bytes = testutil::payload(RecordFmt::Main4, 0);
    let archive = WinArchive::parse(bytes, None, 0).unwrap();
    let mut entry = archive.info.entries[1].clone();
    assert_ne!(entry.crc32, 0);
    for wrong in [testutil::HELLO.len() + 7, testutil::HELLO.len() - 2] {
        entry.uncompressed_len = wrong;
        assert_eq!(archive.read(&entry).unwrap(), testutil::HELLO);
    }
    // without a checksum to confirm it, the size stands
    entry.crc32 = 0;
    assert!(matches!(archive.read(&entry), Err(Error::Decompression(_))));
}

fn parse_stream(stream: &[u8], fmt: RecordFmt) -> (StreamRead, Vec<WinEntry>) {
    let mut entries = Vec::new();
    let read = parse_record_stream(stream, 0, &StreamReading::plain(fmt), &mut entries).unwrap();
    (read, entries)
}

#[test]
fn file_record_tail_names_a_download_item() {
    let fmt = RecordFmt::Main46;
    let file =
        |name: &str, id| testutil::with_ids(testutil::file_record(fmt, name, 0, 0, 0), id, 0);
    // the tail ends: source byte, an empty string, one byte, nine bytes.
    // A download item puts its GUID in front of the nine
    let mut item = file("fetched.dat", 0x401);
    let end = item.len();
    item[end - 13] = SOURCE_DOWNLOAD_ITEM;
    item.splice(end - 9..end - 9, [0xAB; 16]);

    let mut stream = 3u32.to_le_bytes().to_vec();
    stream.extend(file("carried.dat", 0x402));
    stream.extend(item);
    stream.extend(file("last.dat", 0x403));
    let (read, entries) = parse_stream(&stream, fmt);
    assert!(read.complete);
    assert_eq!(read.realigned, 0);
    let downloaded: Vec<bool> = entries
        .iter()
        .map(|e| e.location == Location::Download)
        .collect();
    assert_eq!(downloaded, [false, true, false]);
}

#[test]
fn file_records_that_end_early_are_read_in_step() {
    // builds before the stored-data checksum was added end the record
    // four bytes sooner
    let fmt = RecordFmt::Main46;
    let mut stream = 3u32.to_le_bytes().to_vec();
    for (id, name) in (0x410..).zip(["a.dat", "b.dat", "c.dat"]) {
        let mut record = testutil::with_ids(testutil::file_record(fmt, name, 0, 0, 0), id, 0);
        record.truncate(record.len() - 4);
        stream.extend(record);
    }
    // whatever follows the stream is not part of the last record
    stream.extend_from_slice(&[0xEE; 64]);
    let (read, entries) = parse_stream(&stream, fmt);
    assert!(read.complete);
    assert_eq!(read.realigned, 0);
    assert_eq!(entries.len(), 3);
    assert!(entries.iter().all(|e| e.location == Location::Installer));
}

#[test]
fn next_record_search_prefers_a_known_parent() {
    let fmt = RecordFmt::Main4;
    let folder =
        |name, id, parent| testutil::with_ids(testutil::folder_record(fmt, name), id, parent);
    // bytes that read as a record whose parent was never seen, then a
    // record at the top level
    let stray = folder("Stray", 0x500, 0x7777);
    let data = [stray.clone(), folder("Real", 0x501, 0)].concat();
    let mut budget = usize::MAX;
    let none_seen = HashSet::new();
    assert_eq!(
        find_next_record(&data, 0, fmt, &none_seen, &mut budget),
        Some(stray.len())
    );
    // once that parent has been read, the first one is a record
    let seen = HashSet::from([0x7777]);
    assert_eq!(find_next_record(&data, 0, fmt, &seen, &mut budget), Some(0));
    // with nothing better close by, the first candidate stands
    assert_eq!(
        find_next_record(&stray, 0, fmt, &none_seen, &mut budget),
        Some(0)
    );
}

#[test]
fn unreadable_record_stream_is_an_error() {
    // a readable payload, for comparison
    let good = testutil::payload(RecordFmt::Main4, 0);
    assert_eq!(
        WinArchive::parse(good.clone(), None, 0)
            .unwrap()
            .info
            .entries
            .len(),
        3
    );

    // the same payload with the second record's type made one that does
    // not exist. No layout reads past it, and no file is placed, so the
    // installer is not reported as holding just its embedded DLL
    let first = find_first_entry(&good).unwrap();
    let (chain_end, _) = walk_named_chain(&good, first, &mut Vec::new());
    let stream = chain_end + 1;
    let first_record = testutil::file_record_len(RecordFmt::Main4, "hello.txt");
    let mut bad = good;
    // make the first file unplaceable too, so nothing redeems the parse
    let second_type = stream + 4 + first_record;
    bad[second_type..second_type + 4].copy_from_slice(&0xEEu32.to_le_bytes());
    bad[stream + 4..stream + 8].copy_from_slice(&0xEEu32.to_le_bytes());
    assert!(WinArchive::parse(bad, None, 0).is_err());
}

#[test]
fn pre4_layout_follows_the_runtime_build_date() {
    // a PE image reduced to what the detection reads
    let dll_built = |timestamp: u32| {
        let mut dll = vec![0u8; 0x80];
        dll[..2].copy_from_slice(b"MZ");
        dll[0x3C..0x40].copy_from_slice(&0x40u32.to_le_bytes());
        dll[0x40..0x44].copy_from_slice(b"PE\0\0");
        dll[0x48..0x4C].copy_from_slice(&timestamp.to_le_bytes());
        dll
    };
    // build dates of 2.4.3, 2.4.5, 2.5 and 2.6.2
    assert_eq!(detect_record_fmt(&dll_built(872_640_000)), RecordFmt::Pre24);
    assert_eq!(
        detect_record_fmt(&dll_built(PRE24_LAST_SEEN)),
        RecordFmt::Pre24
    );
    assert_eq!(
        detect_record_fmt(&dll_built(PRE25_FIRST_SEEN)),
        RecordFmt::Pre25
    );
    assert_eq!(
        detect_record_fmt(&dll_built(PRE4_FIRST_SEEN)),
        RecordFmt::Pre4
    );
    // later than any known build stays with the newest pre-4.x layout
    assert_eq!(detect_record_fmt(&dll_built(900_000_000)), RecordFmt::Pre4);
    // not a PE image: no date, so the newest layout is tried first
    assert_eq!(pe_timestamp(b"MZ but nothing more"), None);
    assert_eq!(detect_record_fmt(&[0u8; 0x80]), RecordFmt::Pre4);
    // whatever the hint, all three pre-4.x layouts lead the order
    for hint in [RecordFmt::Pre24, RecordFmt::Pre25, RecordFmt::Pre4] {
        let order = try_order(hint);
        assert_eq!(order[0], hint);
        assert!(order[..3].iter().all(|f| f.is_pre4()));
    }
}

/// A u16-prefixed string
fn s16(text: &[u8]) -> Vec<u8> {
    let mut out = u16::try_from(text.len()).unwrap().to_le_bytes().to_vec();
    out.extend_from_slice(text);
    out
}

#[test]
fn screen_records_are_skipped_by_subtype() {
    // a dialog with one control of each kind: caption, button, bitmap, text
    let mut dialog = SCREEN_DIALOG.to_le_bytes().to_vec();
    dialog.extend_from_slice(&[0; 6]);
    dialog.extend_from_slice(&0x1d3u16.to_le_bytes());
    dialog.extend_from_slice(&4u16.to_le_bytes());
    for (kind, text, extra) in [
        (1u16, &b"Requirements"[..], 0usize),
        (2, b"Cancel", 11),
        (8, b"default.bmp", 0),
        (3, &[b't'; 400], 5),
    ] {
        dialog.extend_from_slice(&kind.to_le_bytes());
        dialog.extend(s16(text));
        dialog.extend_from_slice(&[0x11; 9]);
        dialog.resize(dialog.len() + extra, 0);
    }

    let mut destination = SCREEN_DESTINATION.to_le_bytes().to_vec();
    destination.extend_from_slice(&[1, 0]);
    destination.extend(s16(b"default.bmp"));
    destination.push(0);
    destination.extend(s16(b""));
    destination.push(0);
    destination.extend(s16(b"%ProgramFilesDir%\\Example"));
    destination.extend(s16(b""));
    destination.extend(s16(b"TargetDir"));

    for body in [&dialog, &destination] {
        for fmt in [RecordFmt::Main46, RecordFmt::Main4, RecordFmt::Main48] {
            let mut c = Cursor::new(body, 0, fmt);
            skip_screen(&mut c).unwrap();
            assert_eq!(c.pos, body.len(), "{fmt:?}");
        }
    }

    // an unknown control kind is not guessed at. Before 4.8 the record is then
    // taken to be the subtype alone
    let mut unknown = dialog.clone();
    unknown[14] = 0x55;
    let mut c = Cursor::new(&unknown, 0, RecordFmt::Main48);
    assert!(skip_screen(&mut c).is_err());
    let mut c = Cursor::new(&unknown, 0, RecordFmt::Main4);
    skip_screen(&mut c).unwrap();
    assert_eq!(c.pos, 4);
}

#[test]
fn message_text_longer_than_a_path_is_accepted() {
    let mut c = Cursor::new(&[0u8; 0], 0, RecordFmt::Main4);
    assert!(c.string().is_err());
    let long = s16(&[b'm'; 340]);
    assert_eq!(
        Cursor::new(&long, 0, RecordFmt::Main4)
            .string()
            .unwrap()
            .len(),
        340
    );
    let too_long = s16(&vec![b'm'; usize::from(MAX_STRING_LEN) + 1]);
    assert!(
        Cursor::new(&too_long, 0, RecordFmt::Main4)
            .string()
            .is_err()
    );
}

#[test]
fn folder_links_that_loop_end() {
    let mut folders = HashMap::new();
    folders.insert(1, ("a".to_string(), 2));
    folders.insert(2, ("b".to_string(), 1));
    let path = folder_path(&folders, 1);
    assert_eq!(path.split('/').count(), MAX_FOLDER_DEPTH);
    assert_eq!(folder_path(&folders, 99), "");
}

#[test]
fn a_stream_cut_short_is_reported_incomplete() {
    let fmt = RecordFmt::Main4;
    let mut stream = testutil::tree_stream(fmt);
    // claim one more record than the stream holds
    stream[..4].copy_from_slice(&6u32.to_le_bytes());
    let mut entries = Vec::new();
    let read = parse_record_stream(&stream, 0, &StreamReading::plain(fmt), &mut entries).unwrap();
    assert!(!read.complete);
    assert_eq!(entries.len(), 3);
}

#[test]
fn filetime_counts_from_1601() {
    let unix_epoch = 116_444_736_000_000_000u64;
    assert_eq!(filetime(unix_epoch), Some(SystemTime::UNIX_EPOCH));
    assert_eq!(
        filetime(unix_epoch + 15_000_000),
        Some(SystemTime::UNIX_EPOCH + Duration::from_millis(1500))
    );
    // an unset field, and anything else before 1970, gives no time
    assert_eq!(filetime(0), None);
}

#[test]
fn version_table_entry_must_be_a_whole_version_string() {
    // text that merely starts with "4." is not the table
    assert_eq!(
        detect_record_fmt(b"..\x004.0 or later\x00.."),
        RecordFmt::Pre4
    );
    assert_eq!(detect_record_fmt(b"..\x004.9\x00.."), RecordFmt::Pre4);
    assert_eq!(detect_record_fmt(b"..v4.9.0.0\x00.."), RecordFmt::Pre4);
    // the real entry is still found after one that is skipped
    assert_eq!(
        detect_record_fmt(b"\x004.0 or later\x004.9.0.0\x00"),
        RecordFmt::Main48
    );
}

#[test]
fn record_stream_parses_without_a_payload_around_it() {
    // the shape the record-stream fuzz target feeds in
    for fmt in ALL_FORMATS {
        let input = testutil::records_input(fmt);
        let stream = &input[1..];
        let mut entries = Vec::new();
        parse_record_stream(stream, 0, &StreamReading::plain(fmt), &mut entries)
            .unwrap_or_else(|e| panic!("{}: {e}", testutil::label(fmt)));
        assert_eq!(entries.len(), 2, "{}", testutil::label(fmt));
        let blob = &stream[entries[0].offset..][..entries[0].compressed_len];
        assert_eq!(blob, testutil::swap_deflate(testutil::HELLO));
    }
}

/// Writes the synthetic payloads into the fuzz corpora as seeds. They are
/// what gets the fuzzers past the header and runtime-DLL checks. Run with:
/// `cargo test -- --ignored write_fuzz_seeds`
#[test]
#[ignore = "writes files under fuzz/corpus"]
fn write_fuzz_seeds() {
    let corpus = Path::new(env!("CARGO_MANIFEST_DIR")).join("fuzz/corpus");
    for fmt in ALL_FORMATS {
        let name = format!("synthetic-{}", testutil::label(fmt));
        for (target, bytes) in [
            ("winvise", testutil::payload(fmt, 0)),
            ("winvise_records", testutil::records_input(fmt)),
        ] {
            let dir = corpus.join(target);
            fs::create_dir_all(&dir).unwrap();
            fs::write(dir.join(&name), bytes).unwrap();
        }
    }
}

#[test]
fn rejects_non_vise() {
    assert!(WinArchive::parse(vec![0; 64], None, 0).is_err());
}

#[test]
fn resolve_strips_vars_and_normalizes() {
    assert_eq!(
        resolve_vise_path("%SysDir%\\Example\\file.dll"),
        "SysDir/Example/file.dll"
    );
    assert_eq!(
        resolve_vise_path("%TargetDir%\\app.exe"),
        "TargetDir/app.exe"
    );
}

#[test]
fn resolve_traversal_blocked_by_safe_join() {
    let malicious = resolve_vise_path("%..%\\..\\..\\etc\\passwd");
    let cleaned = crate::clean_name(&malicious);
    assert_eq!(
        safe_join(Path::new("/out"), &cleaned),
        Some("/out/etc/passwd".into())
    );
    assert_eq!(safe_join(Path::new("/out"), "../escape"), None);
}

#[test]
fn scan_skips_oversized_count() {
    let mut buf = vec![0u8; 0x60000];
    buf[..4].copy_from_slice(b"SIVM");
    buf[8..12].copy_from_slice(b"ESIV");
    buf[0x10..0x14].copy_from_slice(&1u32.to_le_bytes());
    let stream_off = 0x40000;
    buf[stream_off..stream_off + 4].copy_from_slice(&(MAX_RECORD_COUNT + 1).to_le_bytes());
    buf[stream_off + 4..stream_off + 8].copy_from_slice(&5u32.to_le_bytes());
    let result = WinArchive::parse(buf, None, 0);
    assert!(result.is_err());
}

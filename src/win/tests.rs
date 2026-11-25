#![allow(clippy::wildcard_imports)]

use super::records::*;
use super::sections::*;
use super::*;
use crate::safe_join;
use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::time::Duration;

/// The newest layout, for a test that needs one layout and not all
const NEWEST: LayoutId = LAYOUTS[0];
/// The oldest layout. It keeps a folder with each file
const OLDEST: LayoutId = LAYOUTS[LAYOUTS.len() - 1];

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
    for layout in LAYOUTS {
        let archive = WinArchive::parse(testutil::payload(layout, 0), None, 0)
            .unwrap_or_else(|e| panic!("{}: {e}", testutil::label(layout)));
        let entries = &archive.info.entries;
        let paths: Vec<String> = entries.iter().map(WinEntry::path).collect();
        let dir = testutil::directory(layout);
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
            testutil::label(layout)
        );

        assert_eq!(archive.read(&entries[0]).unwrap(), testutil::fake_dll());
        assert_eq!(archive.read(&entries[1]).unwrap(), testutil::HELLO);
        assert_eq!(entries[1].uncompressed_len, testutil::HELLO.len());
        assert_eq!(archive.read(&entries[2]).unwrap(), b"");
    }
}

#[test]
fn a_payload_under_an_sivm_header_reads_under_every_layout() {
    for layout in LAYOUTS {
        let archive = WinArchive::parse(testutil::sivm_payload(layout), None, 0)
            .unwrap_or_else(|e| panic!("{}: {e}", testutil::label(layout)));
        let entries = &archive.info.entries;
        assert_eq!(entries.len(), 3, "{}", testutil::label(layout));
        assert_eq!(archive.read(&entries[0]).unwrap(), testutil::fake_dll());
        assert_eq!(archive.read(&entries[1]).unwrap(), testutil::HELLO);
    }
}

#[test]
fn a_record_type_with_nothing_after_its_number_is_stepped_over() {
    for layout in LAYOUTS {
        let label = testutil::label(layout);
        let file = |name: &str, id| {
            testutil::with_ids(testutil::file_record(layout, name, 0, 0, 0), id, 0)
        };
        let bare = layout.table().bare;
        assert!(!bare.is_empty(), "{label}");
        let count = u32::try_from(bare.len()).unwrap() + 2;
        let mut stream = count.to_le_bytes().to_vec();
        stream.extend(file("first.dat", 0x401));
        for rtype in bare {
            stream.extend(rtype.to_le_bytes());
        }
        stream.extend(file("last.dat", 0x402));
        let (read, entries) = parse_stream(&stream, layout);
        assert!(read.complete, "{label}");
        assert_eq!(read.realigned, 0, "{label}");
        assert_eq!(entries.len(), 2, "{label}");
    }
}

#[test]
fn embedded_files_are_counted_not_guessed() {
    let file = |name: &[u8]| {
        let mut out = vec![u8::try_from(name.len()).unwrap()];
        out.extend_from_slice(name);
        out.extend([0; 12]);
        out.extend(3u32.to_le_bytes());
        out.extend(b"xyz");
        out
    };
    // two files are declared. What follows them would pass for a third
    let mut data = 2u16.to_le_bytes().to_vec();
    data.extend(file(b"vise32ex.dll"));
    data.extend(file(b"ESPA\xD1OL.VLG"));
    let end = data.len();
    data.extend(file(b"other.dll"));

    let mut entries = Vec::new();
    // the fixed fields, an empty string, a byte and an empty string that
    // ends with a zero, then the count
    let header = [&b"ESIV"[..], &[0; 15]].concat();
    assert_eq!(
        find_first_entry(&[&header[..], &data[..]].concat()).unwrap(),
        (header.len() + 2, 2)
    );
    assert_eq!(walk_named_chain(&data, 2, 2, &mut entries), end);
    assert_eq!(entries.len(), 2);
    assert_eq!(sections::chain_name_bytes(&entries[0].name), None);
    // a name outside ASCII comes back as the bytes it was stored as
    assert_eq!(
        sections::chain_name_bytes(&entries[1].name).as_deref(),
        Some(&b"ESPA\xD1OL.VLG"[..])
    );

    // a file that runs past the data ends the walk where it starts
    let cut = &data[..end - 1];
    let mut entries = Vec::new();
    assert_eq!(
        walk_named_chain(cut, 2, 2, &mut entries),
        2 + file(b"vise32ex.dll").len()
    );
    assert_eq!(entries.len(), 1);

    // a file with nothing stored is stepped over like any other
    let mut hollow = vec![5];
    hollow.extend_from_slice(b"a.txt");
    hollow.extend([0; 16]);
    let after = hollow.len();
    hollow.extend(file(b"b.dll"));
    let mut entries = Vec::new();
    assert_eq!(walk_named_chain(&hollow, 0, 2, &mut entries), hollow.len());
    assert_eq!(
        (entries[0].compressed_len, entries[1].offset),
        (0, after + 1 + 5 + 16)
    );
}

#[test]
fn the_code_page_is_read_past_the_block_a_flag_brings_in() {
    // Japanese as the main language
    let language = 0x0411u16.to_le_bytes();
    for layout in LAYOUTS {
        let label = testutil::label(layout);
        // the two flag bytes clear: the language table follows them
        let plain = [&[0, 0][..], &language].concat();
        assert_eq!(
            main_code_page(&plain, 0, layout),
            encoding_rs::SHIFT_JIS,
            "{label}"
        );
        // the second flag byte set. Where a layout has a block for it, the
        // block is in front of the table: of zeros, it reads as empty
        let [Op::Skip(1), Op::When(..), ..] = layout.table().start else {
            continue;
        };
        let mut c = Cursor::new(&[0; 256], 2, layout);
        let Some(Op::When(_, block)) = layout.table().start.get(1) else {
            unreachable!()
        };
        grammar::step(&mut c, block, grammar::Limit::Any).unwrap();
        let with_block = [&[0, 1][..], &vec![0; c.pos - 2], &language].concat();
        assert_eq!(
            main_code_page(&with_block, 0, layout),
            encoding_rs::SHIFT_JIS,
            "{label}"
        );
        assert!(c.pos > 2, "{label}");
    }
}

#[test]
fn a_layout_that_reads_the_last_record_into_the_files_is_not_taken() {
    // nothing follows the last record to show where it ends. A newer
    // layout with a longer record of the same type reads on into the file
    // data, and would leave the file marked as misplaced
    for layout in LAYOUTS {
        for rtype in 3..=layout.table().bodies.len() {
            if layout.is_bare(u32::try_from(rtype).unwrap()) {
                continue;
            }
            let label = format!("{} ending with type {rtype}", testutil::label(layout));
            let bytes = testutil::payload_ending_with(layout, rtype);
            let archive =
                WinArchive::parse(bytes, None, 0).unwrap_or_else(|e| panic!("{label}: {e}"));
            let entries = &archive.info.entries;
            assert_eq!(entries.len(), 2, "{label}");
            assert!(!entries[1].misplaced, "{label}");
            assert_eq!(
                archive.read(&entries[1]).unwrap(),
                testutil::HELLO,
                "{label}"
            );
        }
    }
}

#[test]
fn a_last_record_that_does_not_read_is_counted() {
    for layout in LAYOUTS {
        let label = testutil::label(layout);
        let mut stream = 1u32.to_le_bytes().to_vec();
        stream.extend(testutil::empty_record(layout, 3));
        let read = |stream: &[u8]| {
            parse_record_stream(stream, 0, &StreamReading::plain(layout), &mut Vec::new()).unwrap()
        };
        assert_eq!(read(&stream).realigned, 0, "{label}");
        // the same record with its last byte missing
        stream.pop();
        assert_eq!(read(&stream).realigned, 1, "{label}");
    }
}

#[test]
fn a_stream_can_start_with_a_type_that_has_nothing_after_its_number() {
    for layout in LAYOUTS {
        let Some(&bare) = layout.table().bare.first() else {
            continue;
        };
        let mut stream = 2u32.to_le_bytes().to_vec();
        stream.extend(bare.to_le_bytes());
        // a count and such a type with no record after them are no stream
        assert!(!starts_record_stream(&stream, 0, layout));
        stream.extend(testutil::empty_record(layout, 1));
        assert!(
            starts_record_stream(&stream, 0, layout),
            "{}",
            testutil::label(layout)
        );
    }
}

#[test]
fn pre4_offsets_are_measured_from_the_file_start() {
    let at = 0x4000;
    let archive = WinArchive::parse(testutil::payload(OLDEST, at), None, at).unwrap();
    assert_eq!(
        archive.read(&archive.info.entries[1]).unwrap(),
        testutil::HELLO
    );
    // the same payload read as if it sat at offset 0 points past its data
    let wrong = WinArchive::parse(testutil::payload(OLDEST, at), None, 0).unwrap();
    assert!(wrong.read(&wrong.info.entries[1]).is_err());
}

#[test]
fn extracts_a_synthetic_installer_to_disk() {
    let layout = OLDEST;
    let archive = WinArchive::parse(testutil::payload(layout, 0), None, 0).unwrap();
    let tmp = tempfile::tempdir().unwrap();
    let result = archive.extract(tmp.path()).unwrap();
    assert_eq!(result.extracted, 3);
    assert_eq!(result.failed, 0);

    let docs = tmp.path().join(testutil::directory(layout));
    assert_eq!(fs::read(docs.join("hello.txt")).unwrap(), testutil::HELLO);
    assert_eq!(fs::read(docs.join("empty.dat")).unwrap(), b"");
    assert_eq!(
        fs::read(tmp.path().join("vise32ex.dll")).unwrap(),
        testutil::fake_dll()
    );
}

#[test]
fn folder_records_give_files_their_install_path() {
    for layout in LAYOUTS {
        let stream = testutil::tree_stream(layout);
        let mut entries = Vec::new();
        let read = parse_record_stream(&stream, 0, &StreamReading::plain(layout), &mut entries)
            .unwrap_or_else(|e| panic!("{}: {e}", testutil::label(layout)));
        assert!(
            read.complete && read.realigned == 0,
            "{}",
            testutil::label(layout)
        );
        let paths: Vec<String> = entries.iter().map(WinEntry::path).collect();
        // a layout that stores a folder with each file uses that; otherwise
        // the folder records give it, and a separator inside a folder name
        // does not split it
        let expected: [&str; 3] = if testutil::directory(layout).is_empty() {
            ["Outer/outer.txt", "Outer/In_ner/inner.txt", "top.txt"]
        } else {
            [
                "TargetDir/docs/outer.txt",
                "TargetDir/docs/inner.txt",
                "TargetDir/docs/top.txt",
            ]
        };
        assert_eq!(paths, expected, "{}", testutil::label(layout));
    }
}

#[test]
fn stream_is_found_by_reading_the_sections_before_it() {
    for layout in LAYOUTS {
        let label = testutil::label(layout);
        // a support file larger than the distance the fallback scan covers
        let gap = testutil::sections(layout, 0x50000);
        let bytes = testutil::payload_with_gap(layout, 0, &gap);
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
        let chain_end = sections::embedded_files_end(&bytes).unwrap();
        assert_eq!(
            exact_stream_start(&bytes, chain_end, layout),
            Some(chain_end + gap.len()),
            "{label}"
        );
    }
}

#[test]
fn sections_that_are_not_understood_fall_back_to_the_scan() {
    for layout in LAYOUTS {
        let label = testutil::label(layout);
        // nothing a layout could read: every length in it runs past the end
        let gap = [0xFF; 64];
        let bytes = testutil::payload_with_gap(layout, 0, &gap);
        let chain_end = sections::embedded_files_end(&bytes).unwrap();
        assert_eq!(
            exact_stream_start(&bytes, chain_end, layout),
            None,
            "{label}"
        );

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
    for layout in LAYOUTS {
        let gap = testutil::sections(layout, 64);
        for len in 0..gap.len() {
            // every prefix either errors or stops somewhere in range
            if let Ok(end) = skip_to_record_stream(&gap[..len], 0, layout) {
                assert!(end <= len);
            }
        }
    }
}

#[test]
fn read_checks_the_recorded_crc() {
    let bytes = testutil::payload(NEWEST, 0);
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
    let bytes = testutil::payload(NEWEST, 0);
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
    let layout = NEWEST;
    // a candidate whose parent was never seen, then nothing: the search
    // goes on past it looking for a better one, and that is not free
    let mut data = testutil::with_ids(testutil::folder_record(layout, "Stray"), 0x500, 0x7777);
    data.resize(data.len() + 2 * PARENT_LOOKAHEAD, 0);
    let mut budget = 10 * PARENT_LOOKAHEAD;
    assert_eq!(
        find_next_record(&data, 0, layout, &HashSet::new(), &mut budget),
        Some(0)
    );
    assert!(budget <= 9 * PARENT_LOOKAHEAD);
    // and a budget that runs out ends the search
    let mut budget = PARENT_LOOKAHEAD / 2;
    assert_eq!(
        find_next_record(&data, 0, layout, &HashSet::new(), &mut budget),
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
    let bytes = testutil::payload(NEWEST, 0);
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

fn parse_stream(stream: &[u8], layout: LayoutId) -> (StreamRead, Vec<WinEntry>) {
    let mut entries = Vec::new();
    let read = parse_record_stream(stream, 0, &StreamReading::plain(layout), &mut entries).unwrap();
    (read, entries)
}

#[test]
fn file_record_tail_names_a_download_item() {
    let layout = NEWEST;
    let file =
        |name: &str, id| testutil::with_ids(testutil::file_record(layout, name, 0, 0, 0), id, 0);
    // after the source byte come an empty string and one byte. A download
    // item has a 16-byte ID after those
    let (item, offsets) = testutil::file_record_with_offsets(layout, "fetched.dat", 0, 0, 0);
    let mut item = testutil::with_ids(item, 0x401, 0);
    let source = offsets.source.unwrap();
    item[source] = SOURCE_DOWNLOAD_ITEM;
    item.splice(source + 4..source + 4, [0xAB; 16]);

    let mut stream = 3u32.to_le_bytes().to_vec();
    stream.extend(file("carried.dat", 0x402));
    stream.extend(item);
    stream.extend(file("last.dat", 0x403));
    let (read, entries) = parse_stream(&stream, layout);
    assert!(read.complete);
    assert_eq!(read.realigned, 0);
    let downloaded: Vec<bool> = entries
        .iter()
        .map(|e| e.location == Location::Download)
        .collect();
    assert_eq!(downloaded, [false, true, false]);
}

#[test]
fn next_record_search_prefers_a_known_parent() {
    let layout = NEWEST;
    let folder =
        |name, id, parent| testutil::with_ids(testutil::folder_record(layout, name), id, parent);
    // bytes that read as a record whose parent was never seen, then a
    // record at the top level
    let stray = folder("Stray", 0x500, 0x7777);
    let data = [stray.clone(), folder("Real", 0x501, 0)].concat();
    let mut budget = usize::MAX;
    let none_seen = HashSet::new();
    assert_eq!(
        find_next_record(&data, 0, layout, &none_seen, &mut budget),
        Some(stray.len())
    );
    // once that parent has been read, the first one is a record
    let seen = HashSet::from([0x7777]);
    assert_eq!(
        find_next_record(&data, 0, layout, &seen, &mut budget),
        Some(0)
    );
    // with nothing better close by, the first candidate stands
    assert_eq!(
        find_next_record(&stray, 0, layout, &none_seen, &mut budget),
        Some(0)
    );
}

#[test]
fn unreadable_record_stream_is_an_error() {
    // a readable payload, for comparison
    let good = testutil::payload(NEWEST, 0);
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
    // installer is not reported as holding just its embedded file
    let chain_end = sections::embedded_files_end(&good).unwrap();
    let stream = chain_end + testutil::empty_sections(NEWEST).len();
    let first_record = testutil::file_record_len(NEWEST, "hello.txt");
    let mut bad = good;
    // make the first file unplaceable too, so nothing redeems the parse
    let second_type = stream + 4 + first_record;
    bad[second_type..second_type + 4].copy_from_slice(&0xEEu32.to_le_bytes());
    bad[stream + 4..stream + 8].copy_from_slice(&0xEEu32.to_le_bytes());
    assert!(WinArchive::parse(bad, None, 0).is_err());
}

/// A u16-prefixed string
fn s16(text: &[u8]) -> Vec<u8> {
    let mut out = u16::try_from(text.len()).unwrap().to_le_bytes().to_vec();
    out.extend_from_slice(text);
    out
}

#[test]
fn message_text_longer_than_a_path_is_accepted() {
    let mut c = Cursor::new(&[0u8; 0], 0, NEWEST);
    assert!(c.string().is_err());
    let long = s16(&[b'm'; 340]);
    assert_eq!(Cursor::new(&long, 0, NEWEST).string().unwrap().len(), 340);
    let too_long = s16(&vec![b'm'; usize::from(MAX_STRING_LEN) + 1]);
    assert!(Cursor::new(&too_long, 0, NEWEST).string().is_err());
}

#[test]
fn folder_links_that_loop_end() {
    let mut folders = HashMap::new();
    folders.insert(1, ("a".to_string(), 2));
    folders.insert(2, ("b".to_string(), 1));
    assert_eq!(folder_path(&folders, 1), "b/a");
    assert_eq!(folder_path(&folders, 99), "");
}

#[test]
fn a_folder_path_stops_growing_past_its_limit() {
    let name = "n".repeat(usize::from(MAX_STRING_LEN));
    let folders: HashMap<u32, (String, u32)> = (1..=u32::try_from(MAX_FOLDER_DEPTH).unwrap())
        .map(|id| (id, (name.clone(), id + 1)))
        .collect();
    assert_eq!(folder_path(&folders, 1), name);

    let mut short = HashMap::new();
    short.insert(1, ("a".repeat(MAX_FOLDER_PATH - 1), 2));
    short.insert(2, ("b".to_string(), 3));
    short.insert(3, ("c".to_string(), 0));
    assert_eq!(folder_path(&short, 1).split('/').count(), 2);
}

#[test]
fn a_run_of_bare_types_does_not_slow_the_search_for_a_stream() {
    // a count in range at every offset, then bare types to the end
    let bare = (1..64)
        .find(|&t| NEWEST.is_bare(t))
        .expect("the newest layout has a bare type");
    let data: Vec<u8> = std::iter::repeat_n(bare.to_le_bytes(), 1 << 18)
        .flatten()
        .collect();
    assert!(find_record_stream(&data, 0, 0, NEWEST).is_err());
}

#[test]
fn a_stream_cut_short_is_reported_incomplete() {
    let layout = NEWEST;
    let mut stream = testutil::tree_stream(layout);
    // claim one more record than the stream holds
    stream[..4].copy_from_slice(&6u32.to_le_bytes());
    let mut entries = Vec::new();
    let read =
        parse_record_stream(&stream, 0, &StreamReading::plain(layout), &mut entries).unwrap();
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
fn record_stream_parses_without_a_payload_around_it() {
    // the shape the record-stream fuzz target feeds in
    for layout in LAYOUTS {
        let input = testutil::records_input(layout);
        let stream = &input[1..];
        let mut entries = Vec::new();
        parse_record_stream(stream, 0, &StreamReading::plain(layout), &mut entries)
            .unwrap_or_else(|e| panic!("{}: {e}", testutil::label(layout)));
        assert_eq!(entries.len(), 2, "{}", testutil::label(layout));
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
    for layout in LAYOUTS {
        let name = format!("synthetic-{}", testutil::label(layout));
        for (target, bytes) in [
            ("winvise", testutil::payload(layout, 0)),
            ("winvise_records", testutil::records_input(layout)),
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

#[test]
fn file_fields_sit_where_each_layout_says() {
    use super::grammar::{Op, Width};
    // the reader of a file record goes by a few positions; they have to
    // agree with the steps that describe the whole record
    for layout in LAYOUTS {
        let label = testutil::label(layout);
        let table = layout.table();
        let file = &table.file;
        let mut ops = table.bodies[1].expect("a file record").iter();
        assert!(matches!(ops.next(), Some(Op::Loc)), "{label}");
        for &kind in file.before_sizes {
            assert!(
                matches!(ops.next(), Some(&Op::Text(k)) if k == kind),
                "{label}"
            );
        }
        // sizes, volume, offset, attributes, three times and nine bytes
        assert!(matches!(ops.next(), Some(Op::Skip(53))), "{label}");
        assert!(
            matches!(ops.next(), Some(&Op::Text(k)) if k == file.after_times),
            "{label}"
        );
        let Some(&Op::Skip(fixed)) = ops.next() else {
            panic!("{label}: no fixed fields after the times");
        };
        assert!(file.crc_at + 4 <= usize::from(fixed), "{label}");
        if let Some(at) = file.source_at {
            assert_eq!(at, usize::from(fixed), "{label}");
            assert!(
                matches!(ops.next(), Some(Op::Choose(Width::W1, _, _))),
                "{label}"
            );
        }
        assert!(file.folder.is_none_or(|i| i < file.before_sizes.len()));
    }
}

# unvise

Extracts files from Mac and Windows installers made with MindVision's Installer VISE.

## Install

```sh
cargo install unvise
```

To build from source instead:

```sh
git clone git@github.com:jpt/unvise.git
cd unvise
cargo build --release
```

## Usage

```sh
unvise [--forks rsrc|appledouble|macbinary] [--encoding <name>] <installer_file> [output_dir]
```

Output goes to `unvise_out/` unless you name a directory. If the installer came as several files, keep them in one folder and `unvise` finds the rest.

### Resource Forks and Finder Information

Classic Mac files carry a resource fork and Finder information, which other filesystems have no place for. `--forks` sets how they are written:

| Format | Output | Keeps |
|---|---|---|
| `rsrc` (default) | `name` and, if there is a resource fork, `name.rsrc` | Both forks |
| `appledouble` | `name` and `._name` | Both forks, type and creator codes, Finder flags |
| `macbinary` | `name.bin` | Both forks, type and creator codes, Finder flags, creation and modification dates |

On macOS, `dot_clean --keep=dotbar <dir>` merges AppleDouble pairs into native files.

### Name Encodings

Names are stored in pre-Unicode encodings, and the archive doesn't say which one. `unvise` goes by the installer's language.

On the Mac side, that is the region code in the `vers` resource, which maps to Mac Roman, Japanese, Korean, Simplified or Traditional Chinese, or Cyrillic. The resource lives in the resource fork, so it is only there when the input is a MacBinary file. Otherwise names are read as Mac Roman. To override the choice, pass `--encoding` with `macroman`, `macjapanese`, `mackorean`, `macchinesesimp`, `macchinesetrad`, or `maccyrillic`.

On Windows, it is a language ID in the payload, which maps to an ANSI code page: 932 for Japanese, 1252 for Western European languages, and so on.

### HFS Disk Images

`hcopy -m` copies a file out as MacBinary, which keeps its resource fork:

```sh
brew install hfsutils
hmount image.iso
hcopy -m "Installer Name" installer.bin
humount
unvise installer.bin output
```

### Example Output

Each size is the data fork plus the resource fork:

```
VISE format: 03 03
CVCT: 12 entries, 1 segments
12 extractable, 0 condition records

Extracting to output/

  Example Folder/Example App (412876 + 30212 bytes)
  Example Folder/Read Me (4821 + 0 bytes)
  Example Folder/Data/presets.dat (45143 + 0 bytes)
  ...

Done: 12 extracted, 0 skipped, 0 failed
```

## Library

```toml
[dependencies]
unvise = "0.5"
```

This example lists a Mac archive and reads each file into memory:

```rust
let raw = std::fs::read("Installer")?;
if let unvise::InputKind::Mac(data) = unvise::detect_format(raw) {
    let archive = unvise::Archive::parse(data)?;
    let mut reader = archive.reader();
    for file in archive.files() {
        let forks = reader.read(file)?;
        println!("{}: {} + {} bytes", file.name, forks.data.len(), forks.rsrc.len());
    }
}
```

The Mac entry points are on `Archive`:

- `parse` assumes Mac Roman names. `parse_with_encoding` takes the encoding, which `mac_name_encoding` can read from a MacBinary file.
- `reader` decodes entries into memory.
- `extract` writes everything to a directory. `extract_with` adds a progress callback, and `extract_with_options` adds the fork format.

The Windows ones are on `WinArchive`:

- `from_pe` parses an executable.
- `read`, `extract`, and `extract_with` work like their Mac counterparts.
- `set_volumes` supplies the later parts of a multi-part installer.

A `FileEntry` has a folder path (`dir`), type and creator codes, Finder flags, dates, and a CRC-32. A `WinEntry` has an install path, sizes, a modification time, a CRC-32, and a `location` that says where the data is: the executable, a later part, a `.qdat` file, or a download item.

Every read checks the CRC-32 and returns `Error::Checksum` on a mismatch.

## Source Layout

```
src/
├── lib.rs          # public API, format detection, shared helpers
├── mac.rs          # Mac archive parser (SVCT/CVCT/FVCT chunks)
├── win/            # Windows archive parser and extractor
│   ├── mod.rs      #   archive type, layout choice, reading and extraction
│   ├── cursor.rs   #   field reader
│   ├── grammar.rs  #   reader for a layout's lists of steps
│   ├── layouts.rs  #   the record layouts, as lists of steps
│   ├── sections.rs #   embedded files and finding the record stream
│   ├── records.rs  #   record stream, folder and file records
│   ├── testutil.rs #   synthetic payloads for tests and fuzz seeds
│   └── tests.rs    #   unit tests
├── deflate.rs      # decompression pipeline (byte-swap, cipher, DEFLATE)
├── pe.rs           # payload extraction from a Windows executable
├── macbinary.rs    # MacBinary wrapper detection, stripping and writing
├── text.rs         # name encodings: Mac scripts and Windows code pages
├── appledouble.rs  # AppleDouble sidecar writing
└── main.rs         # CLI
```

## Formats

What follows describes what the code reads. It isn't a full account of either format, and some archives surely break it.

### Mac

An archive starts with an `SVCT` header, sometimes inside a MacBinary wrapper. Bytes 0x12 and 0x13 of that header are the format version:

| Format version | Notes |
|---|---|
| 00 01 – 02 0x | Standard DEFLATE; no shared blocks |
| 03 00 – 03 05 | Word-aligned DEFLATE; shared blocks |
| 03 06 – 03 07 | New CVCT header with a chunk-type table |
| 03 08 – 03 0e | CVCT body is compressed |
| 0b 00 | Mac OS X bundles; two more bytes before each record's name length |

There are four kinds of chunk:

- `SVCT`, at offset 0, holds the format version and, at 0x24, a pointer to the CVCT.
- `CVCT` is the file table: a sequence of DVCT and FVCT records. From 03 06, a 100-byte header with chunk-type offsets (PACK, BBrd, CODE, and others) comes first. From 03 08, the records are compressed with word-aligned DEFLATE.
- `DVCT` describes a folder: its name, its ID and its parent's (the root is 2), and its nesting depth.
- `FVCT` describes a file: type and creator codes, Finder flags, dates, compressed and uncompressed sizes for both forks, a CRC-32, the nesting depth, and where the compressed data starts.

Records come in outline order. A folder at depth `d` contains the records after it that are deeper than `d`, up to the next one at depth `d` or less.

These fields sit at fixed offsets from the record tag. All are big-endian, and none moves between format versions. Not all of them are used: folder paths are built from the depths alone, so the IDs and a folder's dates are never read.

| Record | Offset | Field |
|---|---|---|
| DVCT | 20, 24 | Creation and modification dates |
| DVCT | 28, 32 | Folder ID, parent folder ID |
| DVCT | 72 | Depth (u16) |
| FVCT | 12 | Flags |
| FVCT | 44, 48, 52 | Type, creator, Finder flags (u16) |
| FVCT | 60, 64 | Creation and modification dates (seconds since 1904) |
| FVCT | 68 – 80 | Compressed and uncompressed sizes, data fork then resource fork |
| FVCT | 84 | CRC-32 (the zlib one) of the data fork followed by the resource fork |
| FVCT | 88, 92 | Parent folder ID, file ID |
| FVCT | 96, 98 | Depth (u16), segment (u16) |
| FVCT | 100 – 108 | Data offset, offsets within a shared block |

The name does move:

| Format version | File name at | Folder name at |
|---|---|---|
| 00 01, 02 01, 02 02 | 124 | 82 |
| 02 05, 03 00 – 03 03 | 124 | 88 |
| 03 04 | 140 | 104 |
| 03 05 | 184 | 148 |
| 03 06, 03 07 | 186 | 148 |
| 03 08, 03 0a, 03 0b | 190 | 152 |
| 03 0c, 03 0d | 198 | 160 |
| 03 0e | 198 | 164 |
| 0b 00 | 212 | 178 |

For a version that isn't in this table, the offsets are worked out from the archive. A name is the last field of its record, so it starts its own length before the next tag. With too few records to show that, the name is taken to start two bytes past its length byte, and the CLI prints a warning (`ArchiveInfo::names_assumed` in the library).

Decoding file data takes three steps: swap each pair of bytes, put each byte through a 256-byte substitution table, and inflate. From 03 00, stored DEFLATE blocks are aligned to 16-bit words. The result has to match the recorded size exactly, and then the CRC-32.

Also from 03 00, several FVCT entries can share one data offset. Those files are compressed together as a block, and each entry records where its two forks start inside it.

Two kinds of entry are listed but not extracted. One has bit 27 set in its flags, and stands for a condition such as a platform check or an optional component. The other is in segment 0, and has no data in the archive: in a multi-segment set it is a file on the distribution disc, and in a single-segment archive it is an alternate of a file stored once under segment 1.

Mac OS X installers (format 0b 00) are application bundles. Some keep everything in `Contents/InstallerData/Installer.data`. Others put the header, the program, and the file table in `Contents/MacOSClassic/<name>`, and leave only the file data in `Installer.data`. Give `unvise` either half and it finds the other. The table half alone lists every entry as skipped.

### Windows

The input is an executable, 32-bit (PE) or 16-bit (NE). Its payload sits either in a PE section named `_mvdata`, under an `SIVM` header, or after the end of the executable, under an `ESIV` header.

The payload has five parts:

1. A header: 16 bytes of fixed fields, a string with a one-byte length, one byte, a zero-terminated string, and a two-byte count of embedded files.
2. The embedded files: the runtime (`vise32ex.dll` in the 32-bit case), a language file, and other support DLLs.
3. Several sections of settings.
4. The record stream.
5. The file data.

A record is a u32 type, a common header, and then fields that depend on the type. The common header starts with the record's ID and the ID of the folder that holds it (0 at the top level). Type 1 is a folder. Type 2 is a file, with a name, sizes, a data offset, attributes, three timestamps (creation, last access, last write), and a CRC-32.

The settings and the records changed from one Installer VISE release to the next, and nothing in the payload names the release. So there is a layout for each known variant, and they are tried newest first. A layout fits when its settings sections end at a record stream, every declared record reads to its end, and the stream stops before the first file's data. A slightly wrong layout fails within a few records. When two layouts differ only in record types that a given payload lacks, both fit and both read it the same way.

Some layouts store a folder with each file. In the rest, a file's folder comes from following parent IDs up through the folder records.

### Reading the Records

Because a layout describes every record type, a stream is normally read straight through.

Damaged copies need a search. When one record doesn't end where the next begins, the next is found by its header: a type in range, a small ID and parent ID, a common header that parses, and, for a folder or a file, a body that parses too. Bytes inside a record can pass for a header, so a candidate whose parent is 0 or already seen wins over an earlier one whose parent is unknown. The total has to equal the declared count.

When no layout fits that way, each one that couldn't get through the settings sections scans the payload for something that looks like the start of a stream. A stream found by scanning is accepted outright only if it fits, lists at least one file, and every file can be placed. Failing that, the reading that places the most files is used.

Under an `SIVM` header, file offsets count from byte 8 of the payload. Under `ESIV`, they count from the start of the payload in some releases and from the start of the executable in others. To tell which, up to three small files are decoded at both positions, and a match on recorded size and CRC-32 decides. If that settles nothing, the layout does.

A file is skipped when its record names a part that isn't there, or when its data would lie past the end of the executable.

A web installer lists every file but carries only some of them, and downloads the rest when it runs. In the layouts that have download items, a file record has a source byte. A value of 4 marks a file that belongs to a download item, and the item's 16-byte ID follows. Such files are skipped.

Not every downloaded file is marked. So when the download library (`tcpip32.dll`) is among the embedded files, a file that doesn't decode is also skipped if its recorded position couldn't hold its data: before the file data, past the end, or shared with another file. One that sits in a sound position and still doesn't decode counts as failed.

Some records give a size that isn't the size of the stored file, next to a CRC-32 that is right. When a file doesn't decode to its recorded size, it is decoded again without the size, up to a little over twice that length, and accepted if the CRC-32 matches.

### Installers in More Than One File

The other files are looked for in the folder of the one you name.

Mac segment files are recognized by their header and joined by sequence number. File offsets count through the segments in order, so they are used as an unbroken run from 2 upward. A segment that follows a gap is ignored, with a warning.

A Windows stub keeps its record stream in the `.exe` and its file data in a companion `.qdat`. The two are matched by session ID.

A Windows multi-part set has names like `Setup.exe`, `Setup.002`, and `Setup.003`. The record stream is in the `.exe`, and the file data runs on through the parts, so a file can start in one and end in the next. Each part starts with a 16-byte header: `ESIV`, the session ID, the part number, and the length of the part's data. Parts are found by that header, whatever they are called, and used as an unbroken run from 2 upward. Files in a missing part are skipped.

The two halves of a Mac OS X bundle are described at the end of the [Mac](#mac) section.

## Testing

The unit tests cover decompression, parsing, and the safety checks. They also build small archives in memory and extract them:

```sh
cargo test
```

The Windows test payloads are built from the same layout tables that the parser reads with. They test the reader, not the tables: a wrong table would pass them.

CI also runs the formatter and the linter:

```sh
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
cargo clippy --all-targets -- -D warnings
```

## Acknowledgements

This software package is dedicated to the memory of Tyler Kellen

## Disclaimer

This software is provided AS-IS and without any express or implied warranties of safety or suitability for any purpose. Use of this software does not give you the right to access, copy, or use the archived materials; by using this software, you confirm that you have the legal right to access the archived materials, via license or otherwise. By using this software, you agree you are solely responsible for compliance with applicable laws and EULAs. You expressly hold the developers of this software harmless for any misuse or violations resulting from your use of the tool

## Trademarks

"Installer VISE," "MindVision," "Apple," "Mac," "Macintosh," "Microsoft," "Windows," and any other trademarks used throughout this project remain the property of their respective owners and are used herein for identification purposes only

## License

MIT

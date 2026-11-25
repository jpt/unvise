# unvise

unvise unpacks installers that were built with Installer VISE, MindVision's installer builder for Mac and Windows. It reads the archive inside an installer and writes out the files that the installer would have installed.

## Install

Install the command-line tool with Cargo:

```sh
cargo install unvise
```

Or build it from source:

```sh
git clone git@github.com:jpt/unvise.git
cd unvise
cargo build --release
```

## Usage

Give `unvise` an installer and, optionally, a directory to write to:

```sh
unvise [--forks rsrc|appledouble|macbinary] [--encoding <name>] <installer_file> [output_dir]
```

If you don't name an output directory, the files go to `unvise_out/`.

Some installers come in several files. Keep them in one folder, and `unvise` finds the rest.

### Mac Resource Forks and Finder Information

A Mac file can have a resource fork and Finder information, and a plain file has no place for either. The `--forks` option sets how they are written:

| Format | Output | Keeps |
|---|---|---|
| `rsrc` (default) | `name` and, if there is a resource fork, `name.rsrc` | Both forks |
| `appledouble` | `name` and `._name` | Both forks, type and creator codes, Finder flags |
| `macbinary` | `name.bin` | Both forks, type and creator codes, Finder flags, creation and modification dates |

On macOS, `dot_clean --keep=dotbar <dir>` turns AppleDouble pairs into native files with resource forks.

### Name Encodings

Installers store names in an older encoding, not Unicode, and they don't say which one. `unvise` chooses the encoding from the installer's language.

A Mac installer's `vers` resource holds a region code, which gives the script: Mac Roman, Japanese, Korean, Simplified or Traditional Chinese, or Cyrillic. That resource is in the resource fork, so the input has to be a MacBinary file. Without it, names are read as Mac Roman. You can override the choice with `--encoding` and one of `macroman`, `macjapanese`, `mackorean`, `macchinesesimp`, `macchinesetrad`, or `maccyrillic`.

A Windows installer records its main language as a Windows language ID. Names are decoded with that language's ANSI code page: 932 for Japanese, 1252 for Western European languages, and so on.

### Extracting from HFS Disk Images

Copying an installer off an HFS volume as MacBinary keeps its resource fork:

```sh
brew install hfsutils
hmount image.iso
hcopy -m "Installer Name" installer.bin
humount
unvise installer.bin output/
```

### Example Output

The output looks like this. Each size is the data fork plus the resource fork:

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

The same code is available as a library:

```toml
[dependencies]
unvise = "0.5"
```

This example lists the files in a Mac installer and reads each one into memory:

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

For Mac installers:

- `Archive::parse` reads an archive and takes its names as Mac Roman. `Archive::parse_with_encoding` takes the encoding as an argument, and `mac_name_encoding` reads it from a MacBinary-wrapped installer.
- `Archive::reader` reads entries into memory.
- `Archive::extract` writes everything to a directory. `Archive::extract_with` also reports each entry to a callback, and `Archive::extract_with_options` also takes the fork format.

For Windows installers:

- `WinArchive::from_pe` opens an installer.
- `WinArchive::read`, `extract`, and `extract_with` do what their Mac counterparts do.
- `WinArchive::set_volumes` supplies the later parts of a multi-part installer.

A `FileEntry` has its folder path (`dir`), type and creator codes, Finder flags, dates, and CRC-32. A `WinEntry` has its install path, sizes, modification time, CRC-32, and `location`, which says where its data is: the executable, a later part, a `.qdat` file, or a download item.

Reading an entry checks its CRC-32 and returns `Error::Checksum` if it doesn't match.

## Source Layout

The source is organized like this:

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

This section describes what the parser reads. It isn't a complete description of either format, and there are surely installers that it gets wrong.

### Mac

A Mac archive starts with an `SVCT` header, which may sit inside a MacBinary wrapper. The two bytes at 0x12 of that header are the format version:

| Format version | Notes |
|---|---|
| 00 01 – 02 0x | Standard DEFLATE; no shared blocks |
| 03 00 – 03 05 | Word-aligned DEFLATE; shared blocks |
| 03 06 – 03 07 | New CVCT header with a chunk-type table |
| 03 08 – 03 0e | CVCT body is compressed |
| 0b 00 | Mac OS X installer bundles; two more bytes before each record's name length |

An archive is built from four kinds of chunk:

- `SVCT` is the archive header, at offset 0. It holds the format version and, at 0x24, a pointer to the CVCT.
- `CVCT` is the file table. It holds a sequence of DVCT and FVCT records. From 03 06, a 100-byte header with chunk-type offsets (PACK, BBrd, CODE, and others) comes before the records. From 03 08, the records are compressed with word-aligned DEFLATE.
- `DVCT` is a folder. It holds the folder's name, its own ID and its parent's (the root is 2), and its nesting depth.
- `FVCT` is a file. It holds type and creator codes, Finder flags, creation and modification dates, compressed and uncompressed sizes for both forks, a CRC-32 of the contents, the nesting depth, and the offset of the compressed data.

Records are stored in outline order, each with its depth. A folder at depth `d` contains the records after it that are deeper than `d`, up to the next record at depth `d` or less.

These are the fields the parser uses, as offsets from the record tag. All of them are big-endian, and they are the same in every format version:

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

The name is the one field that moves. Its offset depends on the format version:

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

For any other version, the parser works the offsets out from the archive. A name is the last field of its record, so it starts its own length before the next record. If the archive has too few records to show this, the name is taken to follow its length directly, and the CLI prints a warning (`ArchiveInfo::names_assumed` in the library).

To read file data, the parser swaps each pair of bytes, puts each byte through a 256-byte substitution table, and inflates the result. From 03 00, stored DEFLATE blocks are aligned to 16-bit words. The output has to match the recorded size exactly, and then the CRC-32.

From 03 00, several FVCT entries can share one data offset. They are then compressed together as one block, and each entry records where its data fork and resource fork start within the decompressed block. Earlier archives compress each entry on its own.

Two kinds of entry are reported but not extracted:

- An entry with bit 27 set in its flags isn't a file. It encodes an installer condition, such as a platform check or an optional component.
- An entry in segment 0 has no data in the archive. In a multi-segment set, it is a file on the distribution disc. A single-segment archive carries it as an alternate of a file that is stored once under segment 1.

Mac OS X installers (format 0b 00) are application bundles. Some keep everything in one file, `Contents/InstallerData/Installer.data`. Others split it in two: `Contents/MacOSClassic/<name>` holds the header, the installer program, and the file table, and `Installer.data` holds a header and the file data. Give `unvise` either file of the pair, and it finds the other in the bundle. The table file on its own lists every entry and reports each as skipped.

### Windows

A Windows installer is an executable, 32-bit (PE) or 16-bit (NE). Its data, called the payload here, is either in a PE section named `_mvdata` under an `SIVM` header, or appended to the executable under an `ESIV` header.

The payload has five parts, in this order:

1. A header: 16 bytes of fixed fields, a string with a one-byte length, one byte, a zero-terminated string, and a two-byte count of embedded files.
2. The embedded files: the runtime (`vise32ex.dll` in a 32-bit installer), a language file, and other support DLLs.
3. Several sections of installer settings.
4. The record stream.
5. The file data.

Each record has a u32 type and a common header, followed by fields of its own. The common header starts with the record's ID and the ID of the folder record that holds it (0 at the top level). A type 1 record is a folder. A type 2 record is a file: its name, sizes, the offset of its data, attributes, three timestamps (creation, last access, last write), and a CRC-32 of the contents.

The sections and records changed from one Installer VISE release to the next, and an installer doesn't say which release built it. The parser has a layout for each variant it knows, and it chooses by trying them, newest first. A layout fits when its sections end at a record stream, every record that the stream declares reads to its end, and the stream ends before the first file's data. A layout that is slightly wrong fails within a few records. An installer that has none of the record types in which two layouts differ fits both, and both read it the same way.

Some layouts store a folder with each file. In the others, the folder comes from following parent IDs up through the folder records.

### Reading the Records

Each layout describes every record type, so the parser normally reads a stream straight through, from the first record to the last.

Searching is kept for damaged copies. When a record doesn't end where another starts, the parser looks for the next record header: a type in range, a small record ID and parent ID, a common header that parses, and, for a folder or file record, a body that parses too. Bytes inside a record can pass for a header, so a candidate whose parent ID is 0 or the ID of a record already read is preferred over an earlier one whose parent is unknown. The number of records has to equal the count that the stream declares.

If no layout can read the sections in front of the stream, the parser scans the payload for something that looks like the start of a stream. A stream found that way is accepted outright only if every file it lists can be placed. Failing that, the parser uses the reading that places the most files.

File offsets count from the start of the payload in some installers and from the start of the executable in others. The parser decodes a small file at both positions and keeps the one that matches the recorded size and CRC-32.

A file is reported as skipped when its record names a part that isn't there, or when its data would lie past the end of the executable.

A web installer lists every file it installs but carries only some of them, and it downloads the rest when it runs. In the layouts that have download items, a file record has a source byte. A value of 4 means that the file belongs to a download item, and the item's 16-byte ID follows. Those files are reported as skipped.

Not every downloaded file is marked that way. So when an installer embeds the download library (`tcpip32.dll`), a file that doesn't read is also reported as skipped if its recorded position couldn't hold its data: in front of the file data, past the end, or shared with another file. A file that sits where a file should be and still doesn't read is reported as failed.

Some installers record a size that isn't the size of the file they store, next to a CRC-32 that is correct for it. When a file doesn't decode to its recorded size, the parser decodes it again without the size, up to twice the recorded size, and accepts the result if the CRC-32 matches.

### Installers in More Than One File

Some installers span several files. `unvise` looks for the others in the folder of the file you give it.

Mac segment files are recognized by their header and joined by sequence number. File offsets count through the segments in order, so the segments are used as an unbroken run from 2 upward. A segment that follows a gap is ignored with a warning.

A Windows stub installer keeps its record stream in the `.exe` and its file data in a companion `.qdat` file. The two are matched by session ID.

A Windows multi-part installer has names like `Setup.exe`, `Setup.002`, and `Setup.003`. The record stream is in the `.exe`, and the file data continues through the parts. A file can start in one part and end in the next. Each part starts with a 16-byte header: `ESIV`, the session ID, the part number, and the length of the part's data. Parts are found by that header, whatever they are named, and used as an unbroken run from part 2 upward. Files in a part that isn't there are reported as skipped.

A Mac OS X installer can be split across two files in its bundle, as described at the end of the [Mac](#mac) section.

## Testing

The unit tests cover decompression, parsing, and the safety checks. They also build small archives in memory and extract them from start to finish:

```sh
cargo test
```

The Windows test installers are built from the same layout tables that the parser reads with. They test the reader, not the tables: a wrong table would pass them.

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

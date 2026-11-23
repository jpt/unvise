# unvise

Extracts files from Mac and Windows Installer VISE archives, the installer format created by MindVision Software in the 1990s

## Install

```sh
cargo install unvise
```

Or build from source:

```sh
git clone git@github.com:jpt/unvise.git
cd unvise
cargo build --release
```

## Usage

```sh
unvise [--forks rsrc|appledouble|macbinary] [--encoding <name>] <installer_file> [output_dir]
```

The output directory defaults to `unvise_out/`. Both Mac and Windows archives recreate the installer's folder structure, and files get the modification time the archive records. MacBinary wrappers on the input are detected and stripped automatically

Two entries that would land on the same path are both kept: the later one is written as `name (2).ext`

Files that belong with the installer are picked up from the folder it is in: Mac segment files, a Windows `.qdat` volume, the later parts of a multi-part Windows installer, and the other half of a Mac OS X installer bundle. See [Installers in more than one file](#installers-in-more-than-one-file)

### Mac resource forks and Finder information

`--forks` chooses how the parts of a Mac file that a plain file cannot hold are written:

| Format | Output | Keeps |
|---|---|---|
| `rsrc` (default) | `name` and, if there is a resource fork, `name.rsrc` | Both forks |
| `appledouble` | `name` and `._name` | Both forks, type and creator codes, Finder flags |
| `macbinary` | `name.bin` | Both forks, type and creator codes, Finder flags, creation and modification dates |

On macOS, `dot_clean --keep=dotbar <dir>` merges AppleDouble pairs into native files with resource forks. MacBinary is the form emulators and HFS tools take, for example `hcopy -m`

A `/` in a Mac file name is written as `_`, since it would otherwise be read as a folder separator

### Name encodings

Neither format stores names as Unicode, and neither file table says which encoding it uses. Both kinds of installer record their language elsewhere, and that is used:

- **Mac.** The installer application's `vers` resource holds a region code (0 United States, 1 France, 14 Japan and so on), which gives the script: Mac Roman, Japanese, Korean, Simplified or Traditional Chinese, or Cyrillic. That resource is in the resource fork, so it is only there when the input is still a MacBinary file. A bare data fork, or an installer without the resource, is read as Mac Roman. `--encoding macjapanese` (or `macroman`, `mackorean`, `macchinesesimp`, `macchinesetrad`, `maccyrillic`) overrides this
- **Windows.** The language table that follows the embedded DLLs starts with the installer's main language as a Windows language ID. Names are decoded with that language's ANSI code page: 932 for Japanese, 1252 for Western European languages, and so on

The MacBinary output keeps the original name bytes in its header whatever the encoding

### Extracting from HFS disk images

```sh
brew install hfsutils
hmount image.iso
hcopy -m "Installer Name" installer.bin
humount
unvise installer.bin output/
```

### Example output

Illustrative output. Sizes are data fork + resource fork:

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
unvise = "0.4"
```

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

`Archive::parse_with_encoding` takes the encoding of the names, which `mac_name_encoding` reads from a MacBinary-wrapped installer; `Archive::parse` assumes Mac Roman. `Archive::reader` reads entries into memory. `Archive::extract` writes everything to a directory, `Archive::extract_with` does the same while reporting each entry through a callback, and `Archive::extract_with_options` also takes the fork format. Windows installers use `WinArchive::from_pe` with `WinArchive::read`, `extract` and `extract_with`; `set_volumes` supplies the later parts of a multi-part installer. The library prints nothing itself

Each `FileEntry` carries its folder path (`dir`), type and creator codes, Finder flags, dates and stored CRC-32. Each `WinEntry` carries its install path, sizes, modification time, CRC-32 and `location`, which says whether its data is in the executable, a later part, a `.qdat`, or a download item. Reading an entry, Mac or Windows, verifies the CRC and returns `Error::Checksum` on a mismatch. Extraction decodes on several threads; the callback still sees entries in table order

## Source layout

```
src/
├── lib.rs          # public API, format detection, shared helpers
├── mac.rs          # Mac archive parser (SVCT/CVCT/FVCT chunks)
├── win/            # Windows archive: payload, layout choice, extraction
│   ├── cursor.rs   #   field reader
│   ├── sections.rs #   DLL chain and the sections before the record stream
│   └── records.rs  #   record stream, folder and file records
├── deflate.rs      # decompression pipeline (byte-swap, cipher, DEFLATE)
├── pe.rs           # PE payload extraction (_mvdata section or overlay)
├── macbinary.rs    # MacBinary wrapper detection, stripping and writing
├── text.rs         # name encodings: Mac scripts and Windows code pages
├── appledouble.rs  # AppleDouble sidecar writing
└── main.rs         # CLI
```

## Formats

The format is detected from file headers

### Mac

Detected from SVCT header or MacBinary wrapper

| Format bytes | Notes |
|---|---|
| 00 01 - 02 0x | Standard DEFLATE; no shared-block slicing |
| 03 00 - 03 05 | Word-aligned DEFLATE; shared-block slicing |
| 03 06 - 03 07 | New CVCT header with chunk-type table |
| 03 08 - 03 0e | CVCT body is compressed |
| 0b 00 | Mac OS X installer bundles; two more bytes before each record's name |

The format version is at bytes 0x12-0x13 of the SVCT header. These are archive format versions, not product versions. The highest in the 03 series is 03 0e, from Installer VISE 8.5 (July 2005)

Archives are structured around four chunk types:

- `SVCT`: archive header at offset 0. Contains format version and a pointer to the CVCT at 0x24
- `CVCT`: file table container. Holds a sequence of DVCT and FVCT records. v3.06+ adds a 100-byte header with chunk-type offsets (PACK, BBrd, CODE, etc.) before the record body. v3.08+ compresses the record body with word-aligned DEFLATE
- `DVCT`: directory entry. Holds the folder's name, its own ID and its parent's (the root is 2), and its nesting depth
- `FVCT`: file entry. Contains Mac type/creator codes, Finder flags, creation and modification dates, compressed and uncompressed sizes for both data and resource forks, a CRC-32 of the contents, the nesting depth, and the offset to the compressed data within the archive

Records are stored in outline order, each with its depth, so a folder at depth `d` contains the records after it that are deeper than `d`, up to the next record at depth `d` or less. Fields used, as offsets from the record tag, big-endian:

| Record | Offset | Field |
|---|---|---|
| DVCT | 20, 24 | creation and modification dates |
| DVCT | 28, 32 | folder ID, parent folder ID |
| DVCT | 72 | depth (u16) |
| FVCT | 12 | flags |
| FVCT | 44, 48, 52 | type, creator, Finder flags (u16) |
| FVCT | 60, 64 | creation and modification dates (seconds since 1904) |
| FVCT | 68 – 80 | compressed and uncompressed sizes, data fork then resource fork |
| FVCT | 84 | CRC-32 (the zlib one) of the data fork followed by the resource fork |
| FVCT | 88, 92 | parent folder ID, file ID |
| FVCT | 96, 98 | depth (u16), segment (u16) |
| FVCT | 100 – 108 | data offset, offsets within a shared block |

These hold for every format version, 00 01 through 03 0e and 0b 00

All versions use the same byte-swap + substitution cipher + DEFLATE pipeline. The v3 variant aligns stored blocks to 16-bit word boundaries. flate2 is tried first, since it is about twice as fast; a custom word-aligned decoder takes the streams it rejects, which are the ones containing stored blocks. Either way the output has to match the declared size exactly, and then the CRC-32

Multiple FVCT entries can share the same `data_offset`. Each entry's `block_data_off` / `block_rsrc_off` gives its byte offset within the decompressed block. v2 archives predate shared blocks, so each entry is decompressed individually

Entries with bit 27 set in the flags field (offset FVCT+12) are not files; they encode installer conditions (platform checks, optional component toggles). These are reported in output but not extracted

Entries in segment 0 have no data in the archive. In multi-segment sets they are files on the distribution disc; single-segment archives carry them as alternates of a file stored once under segment 1. They are reported and skipped

Mac OS X installers (format 0b 00) are application bundles. Some keep everything in one file, `Contents/InstallerData/Installer.data`. Others split it: `Contents/MacOSClassic/<name>` holds the header, the installer program and the file table, and `Installer.data` holds a header and the file data. Give `unvise` either file of such a pair and it finds the other in the bundle. The table file on its own lists every entry and reports them as skipped

### Windows

Detected from MZ/PE header. Supports PE executables with `_mvdata` section (Apple builds) or PE overlay (all other builds). Seven record layouts are handled. The mainline and Apple ones are chosen from the runtime version in the embedded vise32ex.dll. The pre-4.x DLL has no version string or version resource; its three layouts are told apart by the DLL's build date in the PE header. Whichever layout is chosen, the others are tried if it does not parse:

| Runtime | Notes |
|---|---|
| Pre-4.x: 2.4 (1997) | u8 string prefixes; blob offsets are file-relative |
| Pre-4.x: 2.5 (1998) | As 2.4, with file records two bytes longer |
| Pre-4.x: 2.6 (1998) | As 2.5, with longer folder, shortcut, file-association and file records |
| Apple 2.x | `_mvdata` section; install path in record stream; stub+qdat support |
| Mainline up to 4.6 | PE overlay; install path from folder records; folder records, file records and package entries a few bytes shorter than in 4.7 |
| Mainline 4.7 | PE overlay; install path from folder records |
| Mainline 4.8+ | Wider common header layout; otherwise same as 4.7 |

The payload contains a typed record stream preceded by embedded support DLLs and installer metadata. Each record has a u32 type tag and a common header followed by type-specific fields. The common header starts with the record's ID and the ID of the folder record that holds it (0 at the top level). Type 1 records are folders. Type 2 records are file install entries carrying the filename, sizes, a blob offset, file attributes, three timestamps (creation, last access, last write) and a CRC-32 of the contents, which is checked on extraction

Type 0x24 records are screens the installer shows, with a u32 subtype first. Three subtypes are read: a custom dialog (0), which is a list of controls each with a kind, text and rectangle; the destination screen (9); and the finish screen of 4.8 and later (0x10). Four control kinds are accepted in a dialog: caption, button, text and bitmap

The pre-4.x and Apple runtimes store an install path with each file, which is used as its folder. The mainline 4.x runtimes do not, so there the folder comes from following parent IDs up through the folder records

The stream's position is not stored anywhere in the payload. The installer gets there by reading the sections that come before it, and so does this parser. After the DLL chain, in order:

| Section | Contents |
|---|---|
| Language table | u16 0, language ID, two names, the title and prompt of the language dialog, then a u16 count of further languages, each a language ID and two names |
| Settings | u32 length, then one compressed block that decompresses to data starting `ESIVCSIM` |
| Billboards (mainline only) | u8, u32 count, then ordinary type 0x0f records |
| Variables (mainline only) | u32 count; name and value strings |
| Web-install items (mainline only) | u32 count; a 16-byte GUID and two strings each |
| Download servers | u32 count; a GUID, five strings and a u16 each |
| Support files | count (u16, or u8 in the Apple fork), then `[u8 name length][name][12 bytes][u32 size][data]` entries, the same form as the DLL chain |
| Packages | u16 count; name and description, a u8, a third text, 31 fixed bytes (32 from 4.8), a 36-byte mask, a u8, a feature list (u16 count, 5 bytes each), and a last field of 1 byte (up to 4.6 and Apple) or 4. Each of the three texts is a string followed by a u16 count of translations, each a language ID and a string |

The record stream starts where the packages end

When the sections cannot all be read (the pre-4.x and 1998 runtimes store their settings inline, in a form that is not decoded), the stream is located from its two nearest neighbours instead. The support files are a count followed by named entries whose sizes must chain exactly, which is very unlikely by accident; the package list after them has a few known entry layouts, and the right one ends on a record header. Only if that also fails is the payload scanned for something that looks like a stream start, and a stream found that way has to place at least one file to be accepted

### Reading the records

Only two record types matter for extraction: folders (type 1) and files (type 2). What is needed from them sits at the front of the record, where the runtimes agree. Everything else, including the rest of a file record and all the screens, dialogs, registry and shortcut records, only has to be stepped over, and those bodies differ between runtime builds in ways that are not all known

So each record is stepped over by its known layout, and the result is checked: it has to end where another record starts. A record start is a type in range, a small record ID and parent ID, a common header that parses, and for a folder or file record a body that parses too. When the step does not end on one, the next record is found by searching for its header. Bytes inside a record can pass for a header, so a candidate whose parent ID is 0 or the ID of a record already read is taken over an earlier one whose parent is unknown. Three things keep that honest: the stream declares its record count, which has to come out exactly; a layout that needs no searching is preferred over one that does; and every file is checked against its CRC-32 when read

Blob offsets count from the start of the payload in newer runtimes and from the start of the executable in older ones. Rather than assume where that changed, the parser decodes a small file at both positions and keeps the one that matches the recorded size and CRC

A file whose record names a part that is not there, or whose data lies past the end of the executable, is reported as skipped

What follows the CRC in a file record differs between builds of the same runtime. From it the parser takes one thing: a source byte, which is 4 when the file belongs to a download item of a web installer, whose GUID then follows. Builds from 1999 on also end the record with a CRC-32 of the stored bytes; earlier ones end four bytes sooner, which is noticed from the first file record and applied to the rest

A web installer lists every file it installs and carries only some of them; the rest are fetched when it runs. Files that name a download item are reported as skipped. Not every downloaded file names one. So in an installer that embeds the download library (`tcpip32.dll`), a file that does not read is also reported as skipped when its recorded position could not hold its data: in front of the file data, past the end, or shared with another file. A file that sits where a file should and does not read is reported as failed

Some installers record a size that is not the size of the file they store, next to a CRC-32 that is right for it. When a file does not decode to its recorded size, it is decoded again without the size, up to twice the recorded size, and accepted if the CRC-32 matches

Type 0x15 records are binary patches against files already installed (`name.upd`). They are not extracted

File data is stored as DEFLATE with a byte-pair swap applied to the compressed stream (no substitution cipher, unlike Mac). Each file is compressed independently, and its stream can hold stored blocks aligned to 16-bit words, as on Mac

### Installers in more than one file

Some installers span several files. The others are looked for in the folder of the file given:

- **Mac segments.** Segment files are recognised by their header and joined by sequence number. File offsets count through the segments in order, so they are used as an unbroken run from 2 upward; one that follows a gap is ignored with a warning
- **Windows stub and `.qdat`.** A stub installer keeps its record stream in the `.exe` and its file data in a companion `.qdat`, matched by session ID
- **Windows multi-part installers** (`Setup.exe`, `Setup.002`, `Setup.003`, …). The record stream is in the `.exe` and the file data continues through the parts; a file can start in one part and end in the next. Each part starts with a 16-byte header: `ESIV`, the session ID, the part number and the length of the part's data. Parts are found by that header, whatever they are named, and used as an unbroken run from part 2 upward. Files in a part that is not there are reported as skipped
- **Mac OS X bundles.** See the end of the [Mac](#mac) section

## Testing

Unit tests cover the decompression pipeline, parser, and safety checks, and build small archives in memory to test extraction end to end:

```sh
cargo test
```

CI also runs the formatter and linter:

```sh
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
```

## Acknowledgements

This software package is dedicated to the memory of Tyler Kellen

## Disclaimer

This software is provided AS-IS and without any express or implied warranties of safety or suitability for any purpose. Use of this software does not give you the right to access, copy, or use the archived materials; by using this software, you confirm that you have the legal right to access the archived materials, via license or otherwise. By using this software, you agree you are solely responsible for compliance with applicable laws and EULAs. You expressly hold the developers of this software harmless for any misuse or violations resulting from your use of the tool

## Trademarks

"Installer VISE," "MindVision," "Apple," "Mac," "Macintosh," "Microsoft," "Windows," and any other trademarks used throughout this project remain the property of their respective owners and are used herein for identification purposes only

## License

MIT

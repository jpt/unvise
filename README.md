# unvise

Extracts files from Mac and Windows **Installer VISE** archives, the installer format created by MindVision Software in the 1990s

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
unvise <installer_file> [output_dir]
```

The output directory defaults to `unvise_out/`. Mac archives produce up to two outputs per file: the data fork and the resource fork (`.rsrc`). Windows archives recreate the original directory structure. MacBinary wrappers are detected and stripped automatically

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

  Example App (412876 + 30212 bytes)
  Read Me (4821 + 0 bytes)
  presets.dat (45143 + 0 bytes)
  ...

Done: 12 extracted, 0 skipped, 0 failed
```

## Source layout

```
src/
├── lib.rs          # public API, format detection, shared helpers
├── mac.rs          # Mac archive parser (SVCT/CVCT/FVCT chunks)
├── win.rs          # Windows archive parser (record stream, qdat)
├── deflate.rs      # decompression pipeline (byte-swap, cipher, DEFLATE)
├── pe.rs           # PE payload extraction (_mvdata section or overlay)
├── macbinary.rs    # MacBinary wrapper detection and stripping
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

The format version is at bytes 0x12-0x13 of the SVCT header. These are archive format versions, not product versions. The highest tested was 03 0e, from Installer VISE 8.5 (July 2005)

Archives are structured around four chunk types:

- **SVCT:** archive header at offset 0. Contains format version and a pointer to the CVCT at 0x24
- **CVCT:** file table container. Holds a sequence of DVCT and FVCT records. v3.06+ adds a 100-byte header with chunk-type offsets (PACK, BBrd, CODE, etc.) before the record body. v3.08+ compresses the record body with word-aligned DEFLATE
- **DVCT:** directory entry. Names the folder that subsequent files belong to
- **FVCT:** file entry. Contains Mac type/creator codes, compressed and uncompressed sizes for both data and resource forks, and the offset to the compressed data within the archive

All versions use the same byte-swap + substitution cipher + DEFLATE pipeline. The v3 variant aligns stored blocks to 16-bit word boundaries. The fast path uses flate2; a custom word-aligned decoder handles the v3 variant

Multiple FVCT entries can share the same `data_offset`. Each entry's `block_data_off` / `block_rsrc_off` gives its byte offset within the decompressed block. v2 archives predate shared blocks, so each entry is decompressed individually

Entries with bit 27 set in the flags field (offset FVCT+12) are not files; they encode installer conditions (platform checks, optional component toggles). These are reported in output but not extracted

### Windows

Detected from MZ/PE header. Supports PE executables with `_mvdata` section (Apple builds) or PE overlay (all other builds). Four runtime versions are handled, detected from the embedded vise32ex.dll:

| Runtime | Notes |
|---|---|
| Pre-4.x (1998) | u8 string prefixes; blob offsets are file-relative |
| Apple 2.x | `_mvdata` section; install path in record stream; stub+qdat support |
| Mainline 4.1-4.7 | PE overlay; install path resolved internally |
| Mainline 4.8+ | Wider common header layout; otherwise same as 4.1-4.7 |

The payload contains a typed record stream preceded by embedded support DLLs and installer metadata. Each record has a u32 type tag and a common header followed by type-specific fields; type 2 records are file install entries carrying the filename, install path, sizes, and a blob offset

File data is stored as DEFLATE with a byte-pair swap applied to the compressed stream (no substitution cipher, unlike Mac). Each file is compressed independently; the record stream provides the offset and size for each one. Blob offsets are payload-relative in most formats but file-relative in the oldest (pre-4.x) runtime. Files are extracted with their original directory structure reconstructed from install path variables

### Multi-segment installers

Some installers span multiple files. On Mac, segment files are discovered automatically in the same directory as the main archive and concatenated by sequence number. On Windows, stub installers store the record stream in the `.exe` and file data in a companion `.qdat`; place the `.qdat` in the same directory as the `.exe` and it will be discovered

## Testing

Unit tests cover the decompression pipeline, parser, and safety checks:

```sh
cargo test
```

## Acknowledgements

This software package is dedicated to the memory of Tyler Kellen

## Disclaimer

This software is provided AS-IS and without any express or implied warranties of safety or suitability for any purpose. Use of this software does not give you the right to access, copy, or use the archived materials; by using this software, you confirm that you have the legal right to access the archived materials, via license or otherwise. By using this software, you agree you are solely responsible for compliance with applicable laws and EULAs. You expressly hold the developers of this software harmless for any misuse or violations resulting from your use of the tool

## Trademarks

"Installer VISE," "MindVision," "Apple," "Mac," "Macintosh," "Microsoft," "Windows," and any other trademarks used throughout this project remain the property of their respective owners and are used herein for identification purposes only

## License

MIT

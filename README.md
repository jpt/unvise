# unvise

Extracts files from Mac-based Installer VISE archives, the installer format created by MindVision Software in the 1990s and used widely through the classic Mac OS era

## Supported versions

| Format bytes | Notes |
|---|---|
| 00 01, 02 0x | Standard DEFLATE; no shared-block slicing |
| 03 00 - 03 05 | Word-aligned DEFLATE; shared-block slicing |
| 03 06 - 03 07 | New CVCT header with chunk-type table |
| 03 08 - 03 0e | CVCT body is compressed |

All versions use the same byte-swap + substitution cipher + DEFLATE pipeline. The v3 DEFLATE variant aligns stored blocks to 16-bit word boundaries

The format version is at bytes 0x12-0x13 of the SVCT header. These are archive format versions, not product versions. The highest format version tested was 03 0e, from Installer VISE 8.5 (July 2005)

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

The output directory defaults to `unvise_out/`. Each archived file produces up to two outputs: the data fork (`filename`) and the resource fork (`filename.rsrc`)

MacBinary wrappers are detected and stripped automatically. You can pass either a raw data fork or a MacBinary-wrapped file

### Extracting from HFS disk images

```sh
brew install hfsutils
hmount image.iso
hcopy -m "Installer Name" installer.bin
humount
unvise installer.bin output/
```

### Example output

```
VISE format: 03 03
CVCT: 87 entries, 1 segments
87 extractable, 0 condition records

Extracting to output/

  Example App (2863460 + 78667 bytes)
  addpreset.dat (45143 + 0 bytes)
  billboard.dat (61531 + 0 bytes)
  ...

Done: 87 extracted, 0 skipped, 0 failed
```

## Archive format

VISE archives are structured around four chunk types:

- **SVCT:** archive header at offset 0. Contains format version at bytes 0x12-0x13 and a pointer to the CVCT at 0x24
- **CVCT:** file table container. Holds a sequence of DVCT and FVCT records. v3.06+ adds a 100-byte header with chunk-type offsets (PACK, BBrd, CODE, etc.) before the record body. v3.08+ compresses the record body with word-aligned DEFLATE
- **DVCT:** directory entry. Names the folder that subsequent files belong to
- **FVCT:** file entry. Contains Mac type/creator codes, compressed and uncompressed sizes for both data and resource forks, and the offset to the compressed data within the archive

### Compression

All observed VISE versions use the same obfuscation layer: adjacent byte pairs are swapped, then each byte passes through a 256-byte substitution cipher. The decrypted result is standard DEFLATE.

The v3 decompressor (PPC Dcmp 1005) reads bits from big-endian 16-bit words and aligns stored blocks to word boundaries (`bits & 0xf` instead of zlib's `bits & 0x7`). For streams without stored blocks the output is bit-identical to standard DEFLATE, so the fast path uses flate2/zlib and only falls back to the custom word-aligned decoder when needed.

### Shared compressed blocks

Multiple FVCT entries can share the same `data_offset`, meaning their forks are packed into a single compressed block. Each entry's `block_data_off` / `block_rsrc_off` fields give the byte offset within the decompressed block where that entry's fork starts. The actual compressed size is the maximum `comp_data` across all entries sharing the offset.

In v2 archives, `block_data_off` contains garbage values; shared-block slicing is skipped and each entry is decompressed individually.

### Multi-segment installers

Some format 3 installers span multiple disks. The SVCT header at offset 0x14 records the total segment count, and each FVCT entry has a segment number at offset +98. Files on segment 0 are stored on the distribution media (e.g. a CD), not in the installer archive itself. Files from segments not present in the provided file are reported as skipped

### Condition records

Entries with bit 27 set in the flags field (offset FVCT+12) are not files; they encode installer conditions (platform checks, optional component toggles). These are reported in output but not extracted

## Testing

Unit tests cover the decompression pipeline, parser, and safety checks:

```sh
cargo test
```

## Limitations

- **VISE for Windows** is not supported (untested)
- **Multi-segment installers** require all segments in one file. Files on missing segments are reported and skipped
- **Resource fork semantics** are not preserved beyond raw byte extraction. No AppleDouble or MacBinary output is generated

## License

MIT

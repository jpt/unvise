# unvise

Extracts files from Installer VISE archives, the Mac installer format created by MindVision Software in the 1990s and used widely through the classic Mac OS era

## Supported versions

| Format bytes | VISE version | Compression | Status |
|---|---|---|---|
| 00 01 | VISE 1.x | LZSS | Working |
| 02 00 - 02 02 | VISE 2.x | LZSS | Working |
| 03 00 - 03 07 | VISE 3.x - 5.x | Cipher + DEFLATE | Working |
| 03 08+ | VISE 6.x+ | Different structure (PACK) | Not supported |

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
- **CVCT:** file table container. Holds a sequence of DVCT and FVCT records
- **DVCT:** directory entry. Names the folder that subsequent files belong to
- **FVCT:** file entry. Contains Mac type/creator codes, compressed and uncompressed sizes for both data and resource forks, and the offset to the compressed data within the archive

### Compression

**v2 (LZSS):** A 1024-byte circular window with 10-bit absolute position references and 6-bit match lengths (minimum 2). Flag bytes are MSB-first: 0 = literal, 1 = back-reference

**v3 (Cipher + DEFLATE):** Data passes through a byte-pair swap, then a 256-byte substitution cipher, then DEFLATE decompression. The DEFLATE variant aligns stored blocks to 16-bit word boundaries rather than byte boundaries

### Multi-segment installers

Some format 3 installers span multiple disks. The SVCT header at offset 0x14 records the total segment count, and each FVCT entry has a segment number at offset +98. Files from segments not present in the provided file are reported as skipped

### Condition records

Entries with bit 27 set in the flags field (offset FVCT+12) are not files; they encode installer conditions (platform checks, optional component toggles). These are reported in output but not extracted

## Limitations

- **VISE 6.0.1+ (format 03 08 and above)** uses a different file table structure (PACK/BBrd/CODE chunks) that this tool does not parse
- **Multi-segment installers** require all segments in one file. Files on missing segments are reported and skipped
- **Resource fork semantics** are not preserved beyond raw byte extraction. No AppleDouble or MacBinary output is generated

## License

MIT

# Changelog

## 0.1.8

### Added
- `archive` fuzz target covering the full parse-through-decompress pipeline (shared-block cache, offset groups, fork slicing) without filesystem I/O

### Fixed
- `decompress_raw` bounds check uses `checked_add` to prevent theoretical `usize` overflow on offset + length

## 0.1.7

### Added
- Integration test suite against public VISE corpus (21 archives across format versions)

### Changed
- Improved v2 archive support (format 00 01, 02 0x)
- Unified decompression pipeline across all format versions
- Shared-block handling is more robust when block offsets are unavailable

### Removed
- LZSS module (unused; all observed archives use the DEFLATE pipeline)

## 0.1.6

### Added
- cargo-fuzz harness over the untrusted-input surface. `fuzzing` feature is off by default. Six targets: `parse`, `deflate`, `lzss`, `macbinary`, `word_deflate` (word aligned DEFLATE decoder, no cipher layer), and `name_sanitizer` (the `clean_name` then `safe_join` path traversal guard). All ran clean: no panic, OOM, or hang

## 0.1.5

### Added
- `--version` / `-V` flag

### Security
- Bound the total memory of all decompressed shared blocks (not just each block), so a crafted archive can't hold many large blocks in memory at once

### Changed
- Decompress in chunks and never allocate from the archive's declared size, so a small file can't force a huge buffer (output unchanged)
- Cap decompression at each format's exact maximum expansion (DEFLATE 1032:1, LZSS ~33:1)
- Strip a MacBinary wrapper only when the data under it actually starts with SVCT
- Decode shared blocks in a fixed order, so extraction is identical run to run
- `deflate` is no longer a public module

## 0.1.4

### Security
- Cap DEFLATE output at the input's expansion limit (~1032:1) to stop decompression bombs
- Size buffers from the input, not the untrusted declared uncompressed size (DEFLATE and LZSS)
- Reject empty non-final DEFLATE blocks that force endless Huffman-table rebuilds (CPU exhaustion)
- Cap total extracted output relative to archive size, bounding on-disk expansion
- Keep extracted paths within the output directory

### Changed
- `infer_name_off` tag-stride inference is now linear instead of quadratic in the tag count

## 0.1.3

### Changed
- Huffman table builder uses stack arrays instead of heap allocations for code-length counts
- Dynamic tree decoder returns a single allocation instead of two copies

## 0.1.2

### Added
- Support for v3.08+ archives (format 03 08 through 03 0e). The CVCT body in these versions is compressed with word-aligned DEFLATE
- Tag scanner now recognizes all CVCT record types (PACK, BBrd, CODE, etc.) for stride inference, fixing name resolution in single-entry archives

## 0.1.1

### Added
- Support for v3.06/07 archives (new-style CVCT header with chunk-type table)

## 0.1.0

Initial release

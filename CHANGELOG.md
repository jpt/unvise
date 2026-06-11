# Changelog

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

# Changelog

## 0.1.2

### Added
- Support for v3.08+ archives (format 03 08 through 03 0e). The CVCT body in these versions is compressed with word-aligned DEFLATE
- Tag scanner now recognizes all CVCT record types (PACK, BBrd, CODE, etc.) for stride inference, fixing name resolution in single-entry archives

## 0.1.1

### Added
- Support for v3.06/07 archives (new-style CVCT header with chunk-type table)

## 0.1.0

Initial release

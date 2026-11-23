# Changelog

## 0.4.0

### Added
- Files are checked against the CRC-32 the archive stores for them: per file record on Windows, and over the data fork followed by the resource fork on Mac. A mismatch is `Error::Checksum` and the file is not written
- Three more Windows record layouts: runtimes up to 4.6, and the pre-4.x runtimes of Installer VISE 2.4 and 2.5. Installers from these previously yielded only their embedded support DLLs, reported as a successful extraction
- `--forks appledouble` and `--forks macbinary` keep type and creator codes, Finder flags and the resource fork: as a `._name` sidecar that macOS merges back, or as one `name.bin` file. In the library: `ExtractOptions`, `ForkFormat` and `Archive::extract_with_options`. The default is still `name.rsrc`
- Extracted files get the modification time the archive records, Mac and Windows
- `FileEntry` has `dir`, `name_bytes`, `finder_flags`, `created`, `modified` and `crc32`, with `modified_time`, `created_time` and `finder_info`. `WinEntry` has `modified` and `crc32`
- `macbinary::encode` and the `appledouble` module
- Names are decoded in the installer's own encoding instead of always Mac Roman (Mac) or UTF-8 (Windows). A Mac installer's script is read from the region code of its `vers` resource when the input is a MacBinary file, and `--encoding` overrides it; a Windows installer's code page follows from the language ID in its language table. In the library: `NameEncoding`, `mac_name_encoding`, `Archive::parse_with_encoding`, `Archive::parse_segments_with_encoding`, `macbinary::resource_fork` and `macbinary::region`. Japanese, Korean, Chinese and Cyrillic names now come out readable
- Mac OS X installer bundles (format 0b 00), including those that keep the file table and the file data in separate files inside the bundle; given either file, the CLI finds the other. In the library: `Archive::parse_with_data_file`
- Windows multi-part installers (`Setup.exe`, `Setup.002`, …): the later parts are found next to the executable and read, including files that run from one part into the next. In the library: `WinArchive::set_volumes`, `last_volume`, `session` and `volume_number`
- Windows web installers: a file kept in a download item is reported as skipped with `SkipReason::Downloaded` instead of failed. So is a file that does not read in an installer that embeds the download library, when its recorded position could not hold its data. `WinArchiveInfo` has `web`
- `WinEntry` has `location` (`Location::Installer`, `Part(n)`, `Qdat` or `Download`), which says where its data is
- `Error::Malformed { what, offset }` for a structure that does not read. Parse errors from the Windows record reader are of this kind and no longer carry formatted text
- Dependency: `encoding_rs`

### Changed
- Extraction decodes entries on several threads, in batches bounded by declared size, and still writes and reports them in table order
- `Entry::Dir` holds the folder's full path from the install root, joined with `PATH_SEPARATOR` (`:`), not just its own name. It and `FileEntry::dir` are `Arc<str>`, shared between a folder and the files in it
- The word-aligned decoder reads through a 64-bit buffer and copies overlapping matches in doubling runs
- Output buffers are sized from the declared size when the compressed size makes it plausible, and flate2 writes into them directly
- A Windows entry's recorded size now bounds the decoder's output instead of being compared afterwards
- Mac names keep leading and trailing spaces, which some installers use to control load order

### Fixed
- Mac folders were all created at the top level, so nested folders with the same name were merged and their files overwrote each other. Each record stores its depth; the tree is rebuilt from that
- Windows mainline (4.x) installers were extracted into one flat folder. Folder records and each record's parent ID give the install tree
- Two entries that map to the same output path no longer overwrite: the later one is written as `name (2).ext`
- A `/` in a Mac file name created a folder. It is written as `_`
- A Mac entry with no data fork that sits in a shared block was decoded as if the whole block were its data fork, which then failed its checksum. A data fork is now read only when it has a size
- A Mac entry that is the only file entry reading from its block had its block offset ignored and failed to decode. Its fork is now taken from the block at that offset, with the checksum confirming it
- A Mac file with only a resource fork was written as `name.rsrc` alone in some cases and with an empty `name` beside it in others. The file is now always created under its own name
- A file that holds a table but no data past it (the table half of an OS X bundle) had its entries decoded out of the table and installer program, and reported as failures. They are skipped as `MissingData`
- Segment 0 entries were decoded in single-segment archives, where they point at no data, and reported as failures
- An entry with a size but no stored data, Mac or Windows, was counted as extracted, with nothing written or an empty file. It is now skipped as `MissingData`
- The Mac name-offset guess measured each record to the next one of the same kind, so a folder record between two files skewed it
- The word-aligned decoder accepted up to 258 bytes more than the declared size and cut them off
- The Windows record stream was located by scanning up to 256 KB past the embedded DLLs for bytes that looked like its start. Its position now comes from reading the sections in front of it (language table, settings, variables, download servers, support files, packages). The scan remains for the pre-4.x runtime and for sections that do not read cleanly
- Windows record-layout detection took the first layout and start position that parsed without an error. Candidates are now compared by how many named files they place inside the payload, and a stream that ends early no longer counts as complete
- Windows runtime-version detection matched any string starting with `4.` and a digit; it now needs a whole dotted version string
- A Windows installer whose record stream could not be read was returned as holding only its embedded DLLs. It is now an error
- Windows screen records (type 0x24) were assumed to be four bytes before 4.8. They carry a subtype; custom dialogs and the destination screen are now read
- Windows record strings were limited to 260 bytes, which rejected installers with longer message-box text. The limit is 4096
- The pre-4.x record layout is picked from the build date of the runtime DLL, which separates 2.4, 2.5 and 2.6
- Windows records whose body is not understood no longer stop the parse. Only folder and file records are used; any other record, and the tail of a file record, is stepped over, and if that does not end on a record header the next header is searched for. The declared record count must still come out exactly.
- When the sections before the Windows record stream cannot be read, the stream is located from the support-file chain and package list in front of it instead of by a blind scan
- Whether Windows blob offsets count from the payload or from the executable is settled by decoding a file at both positions
- Windows files in a part of a multi-part installer that is not there, or past the end of the executable, are reported as skipped instead of failed.
- The Windows language table may list further languages after the first
- Mac region codes: Korea is 51, not 23 (Cyprus), and the Cyrillic regions are Russia, Belarus, Ukraine, Serbia, Macedonia and Bulgaria. Korean installers were decoded as Mac Roman
- Croatian and Serbian (Latin) Windows installers were decoded with the Cyrillic code page
- Given a bare file name from inside an OS X installer bundle, the other half of the bundle was looked for in the wrong folder
- A Windows download-item record with no stored data was written as an empty file
- Limits on hostile input: a wrong recorded size lets a file grow to twice that size and no further; files reading one Mac shared block are decoded in bounded groups; the fallback that reads a Mac entry's stream as a block decodes it once; the search for the next Windows record is charged for every position it examines; Mac folder paths may not add up to more than 64 times the file table
- A file that could not be written stopped the whole Windows extraction; it is now reported as failed and the rest continues
- A Windows file whose recorded size is wrong but whose recorded CRC-32 matches the stored data failed to decode. It is decoded without the size and accepted on the CRC
- Windows package entries hold three localized texts, not two; an installer with translated package names (several languages) could not have its record stream located
- The search for the next Windows record took bytes inside a record for a record header in installers made of patch records, which then lost count and failed. A folder or file record now has to parse as far as it is used, and a candidate whose parent is a record already read is preferred
- Windows file records from builds before mid-1999 end four bytes sooner than later ones. Each one was found by searching; they are now read in step

## 0.3.0

### Added
- Read entries into memory: `Archive::reader` and `Archive::read` return both forks of a Mac entry, `WinArchive::read` returns a Windows entry
- `extract_with` on both archive types reports each entry through a callback (`Progress`), with a typed `SkipReason`
- `Archive::files`, `FileEntry::has_rsrc`, `WinEntry::path`, and `WinArchive::from_pe`, which takes the whole executable
- `Error::Skipped` for entries that have no data in the archive
- `--help`
- End-to-end tests that build small archives in memory, Mac and Windows, with no third-party files
- `winvise_records` fuzz target, which fuzzes the Windows record stream directly
- `cargo test -- --ignored write_fuzz_seeds` writes synthetic payloads into the Windows fuzz corpora
- CI running `cargo fmt --check`, clippy, and the tests

### Changed
- The library no longer prints; the CLI does all output. Reported names are paths relative to the output directory
- `Archive::parse_with_segments` takes `&[Vec<u8>]` and rejects segment sets with gaps or repeats. The CLI uses the unbroken run from segment 2 and warns about the rest
- Shared blocks are decompressed one at a time, so peak memory follows the largest block instead of the total
- Huffman tables are sized per block with a 10-bit fast path. A stream of many tiny dynamic blocks decodes about 70 times faster
- Stored blocks are copied in one step, and output buffers start at the declared size instead of 1 MB
- Windows extraction no longer copies the payload out of the executable
- Public structs and enums are `#[non_exhaustive]`

### Fixed
- Apple-variant runtime detection never matched, because a 9-byte window was compared with an 8-byte string. Those installers parsed only through the fallback order
- A bare filename (`unvise Installer`) never found segment files or the `.qdat`
- The word-aligned decoder accepted output shorter than the declared size
- A stored block cut off by the end of input was padded with zeros
- Mac files with both forks empty were not created
- Windows entries are now checked against the size in the file table
- The `winvise` fuzz target never reached decompression
- Offset arithmetic on header fields could wrap on 32-bit targets
- Non-UTF-8 paths on the command line caused a panic

## 0.2.1

### Added
- Windows VISE support: extracts files from PE executables with `_mvdata` section or overlay
- Companion `.qdat` volume support for Windows stub installers, with automatic discovery by session ID
- Multi-segment Mac archive support: segment files are discovered and concatenated automatically
- PE parser (`pe` module) for locating VISE payloads in Windows executables
- Auto-detection of Mac vs Windows format from file headers
- Directory structure reconstruction from VISE install path variables

## 0.2.0

### Added
- Criterion benchmark harness over the public VISE corpus (`cargo bench --features fuzzing`)

### Changed
- Public decoding functions renamed to `decode_in_place` and `decode_and_decompress`
- DEFLATE backend switched from miniz_oxide to zlib-ng (SIMD-optimized), ~25% faster decompression across the corpus
- Reuse `flate2::Decompress` and scratch buffer across entries via thread-locals, avoiding repeated zlib init and scratch allocation (~10-30% faster on small/many-entry archives)
- Docs and comments revised for clarity

### Fixed
- `decompress_shared_blocks` bounds check uses `checked_add` (same fix as `decompress_raw` in 0.1.8)

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

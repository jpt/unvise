# Fuzzing unvise

Coverage-guided targets over the untrusted-input surface, via [`cargo-fuzz`](https://github.com/rust-fuzz/cargo-fuzz) (libFuzzer + ASan). The fuzz profile enables `overflow-checks` and `debug-assertions`, so integer overflow and `debug_assert!`s surface as crashes. Invariant for every target: no panic, no OOM, no hang on any input

| Target           | Entry point                                                         |
|------------------|---------------------------------------------------------------------|
| `parse`          | `Archive::parse` - header / CVCT / FVCT, incl. compressed directory |
| `deflate`        | `decrypt_and_decompress` - cipher + word-aligned DEFLATE            |
| `lzss`           | `lzss::decompress` - v2 LZSS                                        |
| `macbinary`      | `macbinary::strip` - wrapper detection                             |
| `word_deflate`   | `deflate::word_deflate` - word-aligned DEFLATE, no cipher           |
| `name_sanitizer` | `clean_name` then `safe_join` - path traversal guard               |

`deflate`, `lzss`, and `word_deflate` read the first 4 bytes as the declared uncompressed size (the attacker-controlled field) and the rest as the body

## Setup

```sh
rustup toolchain install nightly
cargo install cargo-fuzz
fuzz/fetch-corpus.sh          # seed corpus/parse + corpus/macbinary (needs curl)
```

## Run

```sh
cargo +nightly fuzz run parse     -- -dict=fuzz/vise.dict -max_len=65536
cargo +nightly fuzz run deflate   -- -max_len=65536
cargo +nightly fuzz run lzss      -- -max_len=65536
cargo +nightly fuzz run macbinary -- -max_len=65536
cargo +nightly fuzz run word_deflate   -- -max_len=65536
cargo +nightly fuzz run name_sanitizer -- -max_len=4096
```

`-max_len=65536`: decompression is bounded to ~`input * 1032` (DEFLATE's max expansion), and libFuzzer reports a false OOM at its 2 GB RSS ceiling, so capping input length keeps legitimate expansion (~66 MB here) well under it - any OOM is then real. For larger inputs raise both: `-max_len=1048576 -rss_limit_mb=4096`

## Triage

A crash writes a reproducer to `fuzz/artifacts/<target>/`:

```sh
RUST_BACKTRACE=1 cargo +nightly fuzz run <target> fuzz/artifacts/<target>/<file>
cargo +nightly fuzz tmin <target> fuzz/artifacts/<target>/<file>   # minimize
```

Lift each reproducer into a unit test in the owning module so it can't regress

## Corpus

```sh
cargo +nightly fuzz cmin <target>        # minimize
cargo +nightly fuzz coverage <target>    # measure reached code
```

The `.profdata` and any HTML report are build and host specific and are not
committed; regenerate them with the command above. The `llvm-cov report` for a
run is recorded below

## Coverage

Measured 2026-06-13 by replaying each target corpus through a
`cargo fuzz coverage` build. Per file, for the `parse` target:

| File          | Region | Line  | Note                                              |
|---------------|--------|-------|---------------------------------------------------|
| `parse.rs`    | 90.8%  | 91.2% | The target's own surface                          |
| `deflate.rs`  | 78.8%  | 80.6% | `parse` decompresses CVCT bodies                  |
| `lib.rs`      |  1.9%  |  1.8% | `extract()` path, not called by `parse` by design |
| `lzss.rs`     |  0.0%  |  0.0% | v2 path, covered by the `lzss` target             |
| `macbinary.rs`|  0.0%  |  0.0% | wrapper path, covered by the `macbinary` target   |

A file reading as cold under `parse` is expected: each target drives one entry
point, so coverage of another file comes from its own target, not from `parse`.
For `parse` itself, the parser and the decompression of the directory are well
covered

`name_sanitizer` covers a path the others miss; `word_deflate` sharpens one they
already reach:

- `clean_name` and `safe_join` guard against path traversal but sit behind `extract()`, which no other target calls. `name_sanitizer` runs them on arbitrary names and checks the result cannot escape the output folder
- `word_deflate` runs the decoder on its own, without the cipher step in front. The `parse` target already reaches it through real archive directories, so this one mainly pins down the error-handling corners

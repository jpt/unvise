#![no_main]

use libfuzzer_sys::fuzz_target;

// Exercises the full Windows VISE path: PE extraction, record stream
// parsing, and decompression of every entry, in memory with no filesystem I/O.
// The input is tried both as a bare payload and as a whole PE file
fuzz_target!(|data: &[u8]| {
    unvise::fuzzing::parse_and_decompress_win(data);
});

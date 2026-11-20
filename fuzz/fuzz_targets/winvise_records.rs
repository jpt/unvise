#![no_main]

use libfuzzer_sys::fuzz_target;

// The Windows record stream on its own: the 30-odd record layouts of each
// runtime variant, offset handling, and decompression of the entries found.
// A whole payload must first carry a valid compressed runtime DLL, which a
// fuzzer rarely produces; this target starts past that point.
// first byte = record layout and offset handling, rest = the record stream
fuzz_target!(|data: &[u8]| {
    unvise::fuzzing::parse_win_records(data);
});

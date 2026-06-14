#![no_main]

use libfuzzer_sys::fuzz_target;

// full parse-to-decompress pipeline: shared-block caching, offset groups,
// and fork slicing, without filesystem I/O
fuzz_target!(|data: &[u8]| {
    unvise::fuzzing::parse_and_decompress(data);
});

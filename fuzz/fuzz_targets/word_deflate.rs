#![no_main]

use libfuzzer_sys::fuzz_target;

// Direct path to the word aligned DEFLATE decoder, with no cipher layer in
// front of it, so the corpus exercises stored blocks and error branches the
// archive corpus rarely produces.
// first 4 bytes = declared uncompressed size (untrusted), rest = DEFLATE body
fuzz_target!(|data: &[u8]| {
    if data.len() < 4 {
        return;
    }
    let expected = u32::from_le_bytes([data[0], data[1], data[2], data[3]]) as usize;
    let _ = unvise::fuzzing::word_deflate(&data[4..], expected);
});

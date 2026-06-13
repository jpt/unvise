#![no_main]

use libfuzzer_sys::fuzz_target;

// first 4 bytes = declared uncompressed size (untrusted), rest = cipher+DEFLATE body
fuzz_target!(|data: &[u8]| {
    if data.len() < 4 {
        return;
    }
    let expected = u32::from_le_bytes([data[0], data[1], data[2], data[3]]) as usize;
    let _ = unvise::fuzzing::decrypt_and_decompress(&data[4..], expected);
});

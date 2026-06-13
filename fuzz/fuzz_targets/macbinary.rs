#![no_main]

use libfuzzer_sys::fuzz_target;

// MacBinary detect/strip on arbitrary bytes
fuzz_target!(|data: &[u8]| {
    let _ = unvise::macbinary::strip(data.to_vec());
});

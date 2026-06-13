#![no_main]

use libfuzzer_sys::fuzz_target;

// full header/CVCT/FVCT parse on arbitrary bytes
fuzz_target!(|data: &[u8]| {
    let _ = unvise::Archive::parse(data.to_vec());
});

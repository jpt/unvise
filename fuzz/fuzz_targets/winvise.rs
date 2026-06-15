#![no_main]

use libfuzzer_sys::fuzz_target;

// Exercises the full Windows VISE path: PE extraction, record stream
// parsing, and decompression. Extract writes to /dev/null so no I/O
fuzz_target!(|data: &[u8]| {
    // Direct payload parse (as if _mvdata was already extracted)
    if let Ok(archive) = unvise::win::WinArchive::parse(data.to_vec(), None, 0) {
        let _ = archive.extract(std::path::Path::new("/dev/null"));
    }

    // Full PE -> payload -> parse chain
    if let Ok((payload, off)) = unvise::pe::extract_payload(data) {
        if let Ok(archive) = unvise::win::WinArchive::parse(payload.to_vec(), None, off) {
            let _ = archive.extract(std::path::Path::new("/dev/null"));
        }
    }
});

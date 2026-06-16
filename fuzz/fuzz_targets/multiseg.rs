#![no_main]

use libfuzzer_sys::fuzz_target;

// multi-segment archive: splits input into main + 1-3 synthetic segments
fuzz_target!(|data: &[u8]| {
    if data.len() < 8 { return; }

    let n_segs = (data[0] % 3) as usize + 1;
    let rest = &data[1..];
    let chunk = rest.len() / (n_segs + 1);
    if chunk < 0x30 { return; }

    let main_data = rest[..chunk].to_vec();
    let mut segments = Vec::new();
    for i in 0..n_segs {
        let start = chunk * (i + 1);
        let end = if i + 1 == n_segs { rest.len() } else { chunk * (i + 2) };
        let mut seg = rest[start..end].to_vec();
        if seg.len() >= 0x2c {
            seg[..4].copy_from_slice(b"SVCT");
            seg[4..8].copy_from_slice(&(i as u32 + 2).to_be_bytes());
        }
        segments.push(seg);
    }

    let _ = unvise::Archive::parse_with_segments(main_data, segments);
});

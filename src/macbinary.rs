//! `MacBinary` header detection and stripping
//!
//! Many classic Mac files transferred to non-HFS media are wrapped in a
//! 128-byte `MacBinary` header that encodes the resource/data fork lengths,
//! type/creator codes, and Finder flags. We detect and strip this wrapper
//! so the caller can pass in either raw data forks or `MacBinary`-wrapped files

/// If `data` begins with a plausible `MacBinary` header, returns a copy of the
/// data fork payload (skipping the 128-byte header). Otherwise returns the
/// input unchanged
#[must_use]
pub fn strip(data: Vec<u8>) -> Vec<u8> {
    if data.len() <= 128 {
        return data;
    }

    // MacBinary: byte 0 zero, byte 1 a filename length (1..63), and an SVCT tag
    // at offset 128, all required to strip a wrapper so a stray header match
    // can't mis-strip a non-VISE file
    let name_len = data[1];
    let data_len = u32::from_be_bytes([data[83], data[84], data[85], data[86]]) as usize;
    let fork = data[128..].get(..data_len);
    let wrapped = data[0] == 0
        && (1..=63).contains(&name_len)
        && data_len != 0
        && fork.is_some_and(|fork| fork.starts_with(b"SVCT"));

    match fork {
        Some(fork) if wrapped => fork.to_vec(),
        _ => data,
    }
}

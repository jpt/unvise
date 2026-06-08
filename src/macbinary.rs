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

    // MacBinary: byte 0 is zero, byte 1 is filename length (1..63),
    // and the data at offset 65 is NOT already an SVCT tag
    let name_len = data[1];
    if data[0] != 0 || !(1..=63).contains(&name_len) || &data[65..69] == b"SVCT" {
        return data;
    }

    let data_len = u32::from_be_bytes([data[83], data[84], data[85], data[86]]) as usize;
    if data_len == 0 || 128 + data_len > data.len() {
        return data;
    }

    data[128..128 + data_len].to_vec()
}

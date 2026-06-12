//! LZSS decompressor for VISE v2 archives
//!
//! The algorithm uses a 1024-byte circular window with 10-bit absolute position
//! references and 6-bit match lengths (minimum match length 2). Flag bytes are
//! processed MSB-first: 0 = literal byte, 1 = back-reference pair

use crate::Error;

const WIN_SIZE: usize = 1024;
const WIN_MASK: usize = WIN_SIZE - 1;

/// LZSS's maximum expansion: a 2-byte back-reference token copies at most a
/// 65-byte match (6-bit length field, +2), so 65/2 = 32.5, rounded up to 33.
/// Bounds the up-front capacity reservation against an attacker-inflated
/// `expected` size
const MAX_EXPANSION_RATIO: usize = 33;
const MIN_HEADROOM: usize = 65536;

/// Decompresses LZSS-encoded data, returning exactly `expected` bytes
///
/// Returns the input unchanged when its length already matches `expected`
/// (some v2 archives store uncompressed files verbatim)
///
/// # Errors
///
/// Returns [`Error::Decompression`] if the stream does not yield `expected` bytes
pub fn decompress(src: &[u8], expected: usize) -> Result<Vec<u8>, Error> {
    if src.len() == expected {
        return Ok(src.to_vec());
    }

    // Cap the reservation by what the input could expand to; the loop still
    // stops at `expected`, so this only limits the up-front allocation
    let reserve_cap = src.len()
        .saturating_mul(MAX_EXPANSION_RATIO)
        .saturating_add(MIN_HEADROOM);
    let mut window = [0u8; WIN_SIZE];
    let mut wp = 0usize;
    let mut out = Vec::with_capacity(expected.min(reserve_cap));
    let mut pos = 0usize;

    while pos < src.len() && out.len() < expected {
        let flags = src[pos];
        pos += 1;

        for bit in 0..8u8 {
            if out.len() >= expected || pos >= src.len() {
                break;
            }

            if (flags & (0x80 >> bit)) == 0 {
                let b = src[pos];
                pos += 1;
                out.push(b);
                window[wp] = b;
                wp = (wp + 1) & WIN_MASK;
            } else {
                if pos + 1 >= src.len() {
                    break;
                }
                let pair = u16::from_be_bytes([src[pos], src[pos + 1]]);
                pos += 2;
                let length = ((pair >> 10) as usize + 2).min(expected - out.len());
                let mut rp = (pair as usize) & WIN_MASK;
                for _ in 0..length {
                    let b = window[rp & WIN_MASK];
                    out.push(b);
                    window[wp] = b;
                    wp = (wp + 1) & WIN_MASK;
                    rp += 1;
                }
            }
        }
    }

    if out.len() < expected {
        return Err(Error::Decompression(format!(
            "LZSS: expected {expected} bytes, got {}", out.len()
        )));
    }
    out.truncate(expected);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_literals() {
        let src = vec![0x00, b'A', b'B', b'C', b'D', b'E', b'F', b'G', b'H'];
        assert_eq!(decompress(&src, 8).unwrap(), b"ABCDEFGH");
    }

    #[test]
    fn backref() {
        let src = vec![
            0x01, b'A', b'B', b'C', b'D', b'E', b'F', b'G', 0x08, 0x00,
        ];
        assert_eq!(decompress(&src, 11).unwrap(), b"ABCDEFGABCD");
    }

    #[test]
    fn passthrough_when_sizes_match() {
        let data = b"already the right size";
        assert_eq!(decompress(data, data.len()).unwrap(), data);
    }

    #[test]
    fn synthetic_roundtrip() {
        let plaintext = b"Hello, VISE archive world! This tests the LZSS path.";
        let mut encoded = Vec::new();
        for chunk in plaintext.chunks(8) {
            encoded.push(0x00u8);
            encoded.extend_from_slice(chunk);
        }
        assert_eq!(decompress(&encoded, plaintext.len()).unwrap(), plaintext);
    }

    #[test]
    fn synthetic_with_backref() {
        let mut encoded = Vec::new();
        encoded.push(0x08);
        encoded.extend_from_slice(b"ABCD");
        encoded.push(0x08);
        encoded.push(0x00);
        assert_eq!(decompress(&encoded, 8).unwrap(), b"ABCDABCD");
    }

    #[test]
    fn truncated_input_is_err() {
        let src = vec![0x00, b'A'];
        assert!(decompress(&src, 8).is_err());
    }
}

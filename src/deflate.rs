//! DEFLATE decompression pipeline for VISE v3 archives
//!
//! All v3 compressed data passes through three stages: byte-pair swap, a
//! 256-byte substitution cipher, then DEFLATE decompression. The DEFLATE
//! variant is word-aligned: the PPC Dcmp 1005 decompressor reads bits from
//! big-endian 16-bit words and aligns stored blocks to 16-bit boundaries
//! (using `bits & 0xf` rather than standard zlib's `bits & 0x7`)
//!
//! For streams without stored blocks the output is bit-identical to standard
//! DEFLATE, so we try flate2 first and fall back to the custom word-aligned
//! decoder only when needed

use std::sync::LazyLock;

use crate::Error;

/// Typical worst-case expansion for VISE shared blocks (~10-20x observed)
const EXPANSION_RATIO: usize = 20;
/// Minimum output buffer headroom to avoid realloc on small inputs
const MIN_HEADROOM: usize = 65536;

/// Substitution cipher shared across all observed VISE v3 versions.
///
/// A bijective 256-byte permutation extracted from the PPC Dcmp 1005 resource
/// in a known v3 installer binary, confirmed identical in others
pub const CIPHER: [u8; 256] = [
    0x6a, 0xb7, 0x36, 0xec, 0x15, 0xd9, 0xc8, 0x73, 0xe8, 0x38, 0x9a, 0xdf, 0x21, 0x25, 0xd0, 0xcc,
    0xfd, 0xdc, 0x16, 0xd7, 0xe3, 0x43, 0x05, 0xc5, 0x8f, 0x48, 0xda, 0xf2, 0x3f, 0x10, 0x23, 0x6c,
    0x77, 0x7c, 0xf9, 0xa0, 0xa3, 0xe9, 0xed, 0x46, 0x8b, 0xd8, 0xac, 0x54, 0xce, 0x2d, 0x19, 0x5e,
    0x6d, 0x7d, 0x87, 0x5d, 0xfa, 0x5b, 0x9b, 0xe0, 0xc7, 0xee, 0x9f, 0x52, 0xa9, 0xb9, 0x0a, 0xd1,
    0xfe, 0x78, 0x76, 0x4a, 0x3d, 0x44, 0x5a, 0x96, 0x90, 0x1f, 0x26, 0x9d, 0x58, 0x1b, 0x8e, 0x57,
    0x59, 0xc3, 0x0b, 0x6b, 0xfc, 0x1d, 0xe6, 0xa2, 0x7f, 0x92, 0x4f, 0x40, 0xb4, 0x06, 0x72, 0x4d,
    0xf4, 0x34, 0xaa, 0xd2, 0x49, 0xad, 0xef, 0x22, 0x1a, 0xb5, 0xba, 0xbf, 0x29, 0x68, 0x89, 0x93,
    0x3e, 0x32, 0x04, 0xf5, 0xde, 0xe1, 0x6f, 0xfb, 0x67, 0xe4, 0x7e, 0x08, 0xaf, 0xf0, 0xab, 0x41,
    0x82, 0xea, 0x50, 0x0f, 0x2a, 0xc6, 0x35, 0xb3, 0xa8, 0xca, 0xe5, 0x4c, 0x45, 0x8a, 0x97, 0xae,
    0xd6, 0x66, 0x27, 0x53, 0xc9, 0x1c, 0x3c, 0x03, 0x99, 0xc1, 0x09, 0x2e, 0x69, 0x37, 0x8d, 0x2f,
    0x60, 0xc2, 0xa6, 0x18, 0x4e, 0x7a, 0xb8, 0xcf, 0xa7, 0x3a, 0x17, 0xd5, 0x9e, 0xf1, 0x84, 0x51,
    0x0d, 0xa4, 0x64, 0xc4, 0x1e, 0xb1, 0x30, 0x98, 0xbb, 0x79, 0x01, 0xf6, 0x62, 0x0e, 0xb2, 0x63,
    0x91, 0xcb, 0xff, 0x80, 0x71, 0xe7, 0xd4, 0x00, 0xdb, 0x75, 0x2c, 0xbd, 0x39, 0x33, 0x94, 0xbc,
    0x8c, 0x3b, 0xb6, 0x20, 0x85, 0x24, 0x88, 0x2b, 0x70, 0x83, 0x6e, 0x7b, 0x9c, 0xbe, 0x14, 0x47,
    0x65, 0x4b, 0x56, 0x81, 0xf8, 0x12, 0x11, 0x28, 0xeb, 0x55, 0x74, 0xa1, 0x31, 0xf7, 0xb0, 0x13,
    0x86, 0xdd, 0x5f, 0x42, 0xd3, 0x02, 0x61, 0x95, 0x0c, 0x5c, 0xa5, 0xcd, 0xc0, 0x07, 0xe2, 0xf3,
];

/// Applies the VISE obfuscation layer in place.
///
/// Adjacent byte pairs are swapped, then each byte is substituted through the
/// cipher table. This transformation precedes DEFLATE decompression in all v3
/// archives
pub fn decrypt_in_place(buf: &mut [u8]) {
    let (pairs, tail) = buf.split_at_mut(buf.len() & !1);
    for pair in pairs.chunks_exact_mut(2) {
        let a = pair[0];
        let b = pair[1];
        pair[0] = CIPHER[b as usize];
        pair[1] = CIPHER[a as usize];
    }
    if let [last] = tail {
        *last = CIPHER[*last as usize];
    }
}

/// Decrypts and decompresses a v3 compressed block
///
/// Tries standard DEFLATE via flate2 first. Falls back to the word-aligned
/// decoder when flate2 produces a length mismatch or decompression error.
/// Pass `expected = 0` when the output size is unknown (shared blocks)
///
/// # Errors
///
/// Returns [`Error::Decompression`] if both the flate2 fast path and the
/// word-aligned fallback fail to produce `expected` bytes
pub fn decrypt_and_decompress(src: &[u8], expected: usize) -> Result<Vec<u8>, Error> {
    let mut decrypted = src.to_vec();
    decrypt_in_place(&mut decrypted);

    let alloc = if expected > 0 {
        expected + 1024
    } else {
        src.len() * EXPANSION_RATIO + MIN_HEADROOM
    };
    let mut buf = vec![0u8; alloc];
    let mut decomp = flate2::Decompress::new(false);

    if let Ok(flate2::Status::StreamEnd) =
        decomp.decompress(&decrypted, &mut buf, flate2::FlushDecompress::Finish)
    {
        // total_out is u64; VISE archives are well under 4 GB
        #[allow(clippy::cast_possible_truncation)]
        let n = decomp.total_out() as usize;
        if expected == 0 || n == expected {
            buf.truncate(n);
            return Ok(buf);
        }
    }

    word_deflate(&decrypted, expected)
}

/// Temporary public entry point for probing
pub fn word_deflate_pub(input: &[u8], expected: usize) -> Result<Vec<u8>, Error> {
    word_deflate(input, expected)
}

fn word_deflate(input: &[u8], expected: usize) -> Result<Vec<u8>, Error> {
    let mut br = WordBitReader::new(input);
    let mut out = Vec::with_capacity(expected);

    loop {
        let bfinal = br.read_bits(1);
        let btype = br.read_bits(2);

        match btype {
            0 => {
                br.align16();
                let len = br.read_bits(16) as usize;
                let nlen = br.read_bits(16);
                if len != ((!nlen) & 0xffff) as usize {
                    return Err(Error::Decompression(format!(
                        "stored block LEN/NLEN mismatch: {len} vs {nlen}"
                    )));
                }
                for _ in 0..len {
                    #[allow(clippy::cast_possible_truncation)]
                    out.push(br.read_bits(8) as u8);
                }
                // Odd stored length leaves us mid-word; realign before next block
                br.align16();
            }
            1 => decode_huffman_block(&mut br, &mut out, true)?,
            2 => decode_huffman_block(&mut br, &mut out, false)?,
            _ => return Err(Error::Decompression(format!("invalid block type {btype}"))),
        }

        if bfinal != 0 {
            break;
        }
    }

    if expected > 0 {
        out.truncate(expected);
    }
    Ok(out)
}

struct WordBitReader<'a> {
    data: &'a [u8],
    pos: usize,
    bits: u32,
    nbits: u32,
}

impl<'a> WordBitReader<'a> {
    const fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0, bits: 0, nbits: 0 }
    }

    #[inline]
    fn ensure_bits(&mut self, need: u32) {
        while self.nbits < need {
            if self.pos + 1 < self.data.len() {
                let lo = u32::from(self.data[self.pos]);
                let hi = u32::from(self.data[self.pos + 1]);
                self.bits |= lo << self.nbits;
                self.bits |= hi << (self.nbits + 8);
                self.nbits += 16;
                self.pos += 2;
            } else if self.pos < self.data.len() {
                self.bits |= u32::from(self.data[self.pos]) << self.nbits;
                self.nbits += 8;
                self.pos += 1;
            } else {
                return;
            }
        }
    }

    #[inline]
    fn read_bits(&mut self, n: u32) -> u32 {
        if n == 0 {
            return 0;
        }
        self.ensure_bits(n);
        let val = self.bits & ((1u32 << n) - 1);
        self.bits >>= n;
        self.nbits -= n;
        val
    }

    /// Discards bits until the accumulator is at a 16-bit boundary.
    ///
    /// Matches PPC Dcmp behavior (`bits & 0xf`) not zlib (`bits & 0x7`)
    #[inline]
    const fn align16(&mut self) {
        let discard = self.nbits % 16;
        if discard > 0 {
            self.bits >>= discard;
            self.nbits -= discard;
        }
    }
}

const TABLE_BITS: u32 = 15;
const TABLE_SIZE: usize = 1 << TABLE_BITS;

struct HuffmanTable {
    entries: Box<[(u16, u8)]>,
}

fn build_huffman_table(lengths: &[u8]) -> HuffmanTable {
    let max_bits = u32::from(*lengths.iter().max().unwrap_or(&0));
    if max_bits == 0 {
        return HuffmanTable { entries: vec![(0, 0); TABLE_SIZE].into_boxed_slice() };
    }

    let mut bl_count = vec![0u32; max_bits as usize + 1];
    for &len in lengths {
        if len > 0 {
            bl_count[usize::from(len)] += 1;
        }
    }

    let mut next_code = vec![0u32; max_bits as usize + 1];
    let mut code = 0u32;
    for bits in 1..=max_bits {
        code = (code + bl_count[bits as usize - 1]) << 1;
        next_code[bits as usize] = code;
    }

    let mut entries = vec![(0u16, 0u8); TABLE_SIZE];
    for (sym, &len) in lengths.iter().enumerate() {
        if len == 0 {
            continue;
        }
        let c = next_code[usize::from(len)];
        next_code[usize::from(len)] += 1;
        let rev = reverse_bits(c, len);
        let fill = TABLE_BITS - u32::from(len);
        for i in 0..(1u32 << fill) {
            let idx = rev as usize | ((i as usize) << len);
            #[allow(clippy::cast_possible_truncation)]
            let sym = sym as u16;
            entries[idx] = (sym, len);
        }
    }

    HuffmanTable { entries: entries.into_boxed_slice() }
}

#[inline]
fn reverse_bits(val: u32, len: u8) -> u32 {
    val.reverse_bits() >> (32 - u32::from(len))
}

#[inline]
fn decode_symbol(reader: &mut WordBitReader, table: &HuffmanTable) -> Result<u32, Error> {
    reader.ensure_bits(TABLE_BITS);
    #[allow(clippy::cast_possible_truncation)]
    let peek = (reader.bits & (TABLE_SIZE as u32 - 1)) as usize;
    let (sym, len) = table.entries[peek];
    if len > 0 {
        reader.bits >>= len;
        reader.nbits -= u32::from(len);
        return Ok(u32::from(sym));
    }
    Err(Error::Decompression("invalid Huffman code".into()))
}

static FIXED_LIT: LazyLock<HuffmanTable> = LazyLock::new(|| {
    let mut ll = vec![0u8; 288];
    ll[..144].fill(8);
    ll[144..256].fill(9);
    ll[256..280].fill(7);
    ll[280..288].fill(8);
    build_huffman_table(&ll)
});

static FIXED_DIST: LazyLock<HuffmanTable> = LazyLock::new(|| {
    build_huffman_table(&[5u8; 32])
});

fn decode_huffman_block(
    reader: &mut WordBitReader,
    out: &mut Vec<u8>,
    fixed: bool,
) -> Result<(), Error> {
    let (dyn_lit, dyn_dist);
    let (lit_table, dist_table) = if fixed {
        (&*FIXED_LIT, &*FIXED_DIST)
    } else {
        let (ll, dl) = decode_dynamic_trees(reader)?;
        dyn_lit = build_huffman_table(&ll);
        dyn_dist = build_huffman_table(&dl);
        (&dyn_lit, &dyn_dist)
    };

    loop {
        let sym = decode_symbol(reader, lit_table)?;
        if sym == 256 {
            break;
        }
        if sym < 256 {
            #[allow(clippy::cast_possible_truncation)]
            out.push(sym as u8);
        } else {
            let length = decode_length(reader, sym)?;
            let dist_sym = decode_symbol(reader, dist_table)?;
            let distance = decode_distance(reader, dist_sym)?;
            if distance > out.len() {
                return Err(Error::Decompression(format!(
                    "back-reference distance {distance} exceeds output length {}",
                    out.len()
                )));
            }
            if distance >= length {
                let start = out.len() - distance;
                out.extend_from_within(start..start + length);
            } else {
                for _ in 0..length {
                    let idx = out.len() - distance;
                    out.push(out[idx]);
                }
            }
        }
    }
    Ok(())
}

const CL_ORDER: [usize; 19] = [16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15];

fn decode_dynamic_trees(reader: &mut WordBitReader) -> Result<(Vec<u8>, Vec<u8>), Error> {
    let hlit = reader.read_bits(5) as usize + 257;
    let hdist = reader.read_bits(5) as usize + 1;
    let hclen = reader.read_bits(4) as usize + 4;
    let mut cl_lengths = [0u8; 19];
    for i in 0..hclen {
        #[allow(clippy::cast_possible_truncation)]
        let bits = reader.read_bits(3) as u8;
        cl_lengths[CL_ORDER[i]] = bits;
    }

    let cl_table = build_huffman_table(&cl_lengths);
    let total = hlit + hdist;
    let mut lengths = Vec::with_capacity(total);

    while lengths.len() < total {
        let sym = decode_symbol(reader, &cl_table)?;
        match sym {
            0..=15 => {
                #[allow(clippy::cast_possible_truncation)]
                lengths.push(sym as u8);
            }
            16 => {
                let repeat = reader.read_bits(2) as usize + 3;
                let last = *lengths.last().unwrap_or(&0);
                lengths.extend(std::iter::repeat_n(last, repeat));
            }
            17 => {
                let repeat = reader.read_bits(3) as usize + 3;
                lengths.extend(std::iter::repeat_n(0u8, repeat));
            }
            18 => {
                let repeat = reader.read_bits(7) as usize + 11;
                lengths.extend(std::iter::repeat_n(0u8, repeat));
            }
            _ => return Err(Error::Decompression(format!("invalid code length symbol {sym}"))),
        }
    }

    Ok((lengths[..hlit].to_vec(), lengths[hlit..hlit + hdist].to_vec()))
}

const LEN_BASE: [u16; 29] = [
    3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31,
    35, 43, 51, 59, 67, 83, 99, 115, 131, 163, 195, 227, 258,
];
const LEN_EXTRA: [u8; 29] = [
    0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2,
    3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0,
];
const DIST_BASE: [u16; 30] = [
    1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193,
    257, 385, 513, 769, 1025, 1537, 2049, 3073, 4097, 6145, 8193, 12289, 16385, 24577,
];
const DIST_EXTRA: [u8; 30] = [
    0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6,
    7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13, 13,
];

#[inline]
fn decode_length(reader: &mut WordBitReader, sym: u32) -> Result<usize, Error> {
    let idx = (sym - 257) as usize;
    if idx >= LEN_BASE.len() {
        return Err(Error::Decompression(format!("invalid length symbol {sym}")));
    }
    Ok(usize::from(LEN_BASE[idx]) + reader.read_bits(u32::from(LEN_EXTRA[idx])) as usize)
}

#[inline]
fn decode_distance(reader: &mut WordBitReader, sym: u32) -> Result<usize, Error> {
    let idx = sym as usize;
    if idx >= DIST_BASE.len() {
        return Err(Error::Decompression(format!("invalid distance symbol {sym}")));
    }
    Ok(usize::from(DIST_BASE[idx]) + reader.read_bits(u32::from(DIST_EXTRA[idx])) as usize)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decrypt_swaps_and_ciphers() {
        let mut buf = vec![0x00, 0x01, 0x02, 0x03];
        decrypt_in_place(&mut buf);
        assert_eq!(buf[0], CIPHER[0x01]);
        assert_eq!(buf[1], CIPHER[0x00]);
        assert_eq!(buf[2], CIPHER[0x03]);
        assert_eq!(buf[3], CIPHER[0x02]);
    }

    #[test]
    fn decrypt_odd_length() {
        let mut buf = vec![0x10, 0x20, 0x30];
        decrypt_in_place(&mut buf);
        assert_eq!(buf[0], CIPHER[0x20]);
        assert_eq!(buf[1], CIPHER[0x10]);
        assert_eq!(buf[2], CIPHER[0x30]);
    }

    #[test]
    fn reverse_bits_basic() {
        assert_eq!(reverse_bits(0b110, 3), 0b011);
        assert_eq!(reverse_bits(0b1010, 4), 0b0101);
        assert_eq!(reverse_bits(0b1, 1), 0b1);
    }

    #[test]
    fn decrypt_pair_semantics() {
        for a in 0..=255u8 {
            for b in [0u8, 127, 255] {
                let mut buf = [a, b];
                decrypt_in_place(&mut buf);
                assert_eq!(buf[0], CIPHER[b as usize]);
                assert_eq!(buf[1], CIPHER[a as usize]);
            }
        }
    }
}

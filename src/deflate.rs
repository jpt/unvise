//! DEFLATE decompression pipeline for VISE archives
//!
//! All compressed data passes through three stages: byte-pair swap, a
//! 256-byte substitution table, then DEFLATE decompression. This pipeline
//! is shared across all observed VISE format versions (v2 and v3).
//!
//! The v3 variant reads bits from big-endian 16-bit words and aligns stored
//! blocks to 16-bit boundaries (`bits & 0xf` rather than zlib's `bits & 0x7`).
//! For streams without stored blocks the output is bit-identical to standard
//! DEFLATE, so flate2 is the fast path and the custom word-aligned decoder is
//! the fallback

use std::sync::LazyLock;

use crate::Error;

/// Headroom added to the ratio ceiling so tiny inputs aren't capped below what
/// they legitimately decompress to
const MIN_HEADROOM: usize = 65536;
/// Hard cap on output size relative to input: DEFLATE's exact maximum expansion.
/// A 258-byte match (the longest back-reference) can be encoded in as little as
/// 2 bits, so 258*8/2 = 1032 bytes out per byte in. No valid stream exceeds this,
/// so anything past it is a decompression bomb
const MAX_EXPANSION_RATIO: usize = 1032;
/// Longest DEFLATE back-reference (max match length). The final match of a
/// stream may copy this far past `expected` before the trailing `truncate`, so
/// the cap adds it as slack
const MAX_MATCH: usize = 258;
/// Output chunk pulled from flate2 per iteration when decompressing incrementally
const INFLATE_CHUNK: usize = 64 * 1024;
/// Ceiling on the starting output capacity. The declared `expected` is used as
/// a hint only up to this, so a bogus header can't request a huge reservation
/// up front
const INITIAL_OUTPUT_CAP: usize = 1 << 20;

/// Substitution table: a bijective 256-byte permutation found in every
/// observed Mac VISE installer binary
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

/// Reverses the VISE encoding layer in place
///
/// Adjacent byte pairs are swapped, then each byte is substituted through the
/// permutation table. This transformation precedes DEFLATE decompression in all
/// VISE archives
pub fn decode_in_place(buf: &mut [u8]) {
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

/// Decrypts and decompresses a VISE compressed block
///
/// Tries standard DEFLATE via flate2 first. Falls back to the word-aligned
/// decoder when flate2 produces a length mismatch or decompression error.
/// Pass `expected = 0` when the output size is unknown (shared blocks)
///
/// # Errors
///
/// Returns [`Error::Decompression`] if both the flate2 fast path and the
/// word-aligned fallback fail to produce `expected` bytes
pub fn decode_and_decompress(src: &[u8], expected: usize) -> Result<Vec<u8>, Error> {
    let mut decoded = src.to_vec();
    decode_in_place(&mut decoded);

    match inflate(&decoded, expected) {
        Some(out) => Ok(out),
        // word-aligned stored blocks defeat standard inflate; the custom decoder
        // handles those and applies the same output bound
        None => word_deflate(&decoded, expected),
    }
}

/// Standard DEFLATE via flate2, pulled in fixed chunks so the output bound is
/// enforced as bytes are produced and no buffer is ever sized from the
/// attacker-controlled `expected`. Returns `None` to signal the caller should
/// fall back to the word-aligned decoder: flate2 declined the stream, stalled,
/// the output ran past what the input could legitimately produce, or it did not
/// yield exactly `expected` bytes
fn inflate(input: &[u8], expected: usize) -> Option<Vec<u8>> {
    thread_local! {
        static SCRATCH: std::cell::RefCell<Vec<u8>> = std::cell::RefCell::new(vec![0u8; INFLATE_CHUNK]);
        static DEC: std::cell::RefCell<flate2::Decompress> = std::cell::RefCell::new(flate2::Decompress::new(false));
    }

    let max_out = output_ceiling(input.len(), expected);
    let hint = if expected > 0 {
        expected
    } else {
        input.len().saturating_mul(4)
    };
    let mut out = Vec::with_capacity(hint.min(INITIAL_OUTPUT_CAP).min(max_out));

    let result = SCRATCH.with(|scratch_cell| {
        DEC.with(|dec_cell| {
            let mut scratch = scratch_cell.borrow_mut();
            let mut dec = dec_cell.borrow_mut();
            dec.reset(false);
            inflate_inner(input, expected, max_out, &mut out, &mut scratch, &mut dec)
        })
    });

    if result { Some(out) } else { None }
}

fn inflate_inner(
    input: &[u8],
    expected: usize,
    max_out: usize,
    out: &mut Vec<u8>,
    scratch: &mut [u8],
    dec: &mut flate2::Decompress,
) -> bool {
    loop {
        let in_before = dec.total_in();
        let out_before = dec.total_out();
        #[allow(clippy::cast_possible_truncation)]
        let status = dec.decompress(
            &input[in_before as usize..],
            scratch,
            flate2::FlushDecompress::None,
        );
        // total_in/total_out are u64; VISE archives are well under 4 GB
        #[allow(clippy::cast_possible_truncation)]
        let produced = (dec.total_out() - out_before) as usize;
        out.extend_from_slice(&scratch[..produced]);

        // beyond what this input could legitimately expand to: a bomb, bail out
        if out.len() > max_out {
            return false;
        }

        match status {
            Ok(flate2::Status::StreamEnd) => break,
            Ok(_) => {
                #[allow(clippy::cast_possible_truncation)]
                let consumed = (dec.total_in() - in_before) as usize;
                // no input taken and no output made: stalled (e.g. truncated stream)
                if consumed == 0 && produced == 0 {
                    return false;
                }
            }
            Err(_) => return false,
        }
    }

    // accept only an exact match (or an unknown size); a short or long result
    // defers to the word-aligned decoder, preserving the prior fall-back behavior
    expected == 0 || out.len() == expected
}

/// Byte-pair swap + standard DEFLATE without the substitution cipher.
/// Used by Windows VISE archives which omit the cipher table
pub(crate) fn swap_and_inflate(src: &[u8]) -> Option<Vec<u8>> {
    if src.len() < 2 {
        return None;
    }
    let mut swapped = src.to_vec();
    for pair in swapped.chunks_exact_mut(2) {
        pair.swap(0, 1);
    }
    match inflate(&swapped, 0) {
        Some(out) => Some(out),
        None => word_deflate(&swapped, 0).ok(),
    }
}

/// Decompresses raw word-aligned DEFLATE without the byte-swap + substitution layer
///
/// Used for v3.08+ CVCT bodies where the directory is compressed without the
/// encoding layer. The raw bytes are byte-pair swapped to match `WordBitReader`'s
/// LE byte order, then passed through the standard word-aligned DEFLATE decoder.
///
/// # Errors
///
/// Returns [`Error::Decompression`] if the input is not valid word-aligned DEFLATE
pub fn decompress_raw_word_deflate(input: &[u8], expected: usize) -> Result<Vec<u8>, Error> {
    swap_and_deflate_with_consumed(input, expected).map(|(data, _)| data)
}

/// Byte-swap + word-aligned DEFLATE, returning input bytes consumed
pub fn swap_and_deflate_with_consumed(
    input: &[u8],
    expected: usize,
) -> Result<(Vec<u8>, usize), Error> {
    let mut swapped = input.to_vec();
    for pair in swapped.chunks_exact_mut(2) {
        pair.swap(0, 1);
    }
    word_deflate_with_consumed(&swapped, expected)
}

/// Largest output `comp_len` compressed bytes could legitimately produce. A
/// declared size (`expected > 0`) is trusted only up to this physical ceiling,
/// so a lie in the header cannot enlarge the bound
fn output_ceiling(comp_len: usize, expected: usize) -> usize {
    let ratio_cap = comp_len
        .saturating_mul(MAX_EXPANSION_RATIO)
        .saturating_add(MIN_HEADROOM);
    if expected > 0 {
        expected.saturating_add(MAX_MATCH).min(ratio_cap)
    } else {
        ratio_cap
    }
}

/// Decompresses word-aligned DEFLATE. `expected` is the declared output size,
/// or 0 when it is unknown
///
/// # Errors
///
/// Returns [`Error::Decompression`] if the stream is malformed, ends before
/// `expected` bytes are produced, or expands past what its input could
/// legitimately produce
pub fn word_deflate(input: &[u8], expected: usize) -> Result<Vec<u8>, Error> {
    word_deflate_with_consumed(input, expected).map(|(data, _)| data)
}

/// Like [`word_deflate`], but also returns the number of input bytes consumed
pub fn word_deflate_with_consumed(
    input: &[u8],
    expected: usize,
) -> Result<(Vec<u8>, usize), Error> {
    let max_out = output_ceiling(input.len(), expected);

    let mut br = WordBitReader::new(input);
    let mut out = Vec::with_capacity(expected.min(max_out));

    loop {
        let bfinal = br.read_bits(1);
        let btype = br.read_bits(2);
        let progress_mark = out.len();

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
                if out.len() + len > max_out {
                    return Err(bomb_error(max_out));
                }
                br.copy_stored(len, &mut out)?;
            }
            1 => decode_huffman_block(&mut br, &mut out, true, max_out)?,
            2 => decode_huffman_block(&mut br, &mut out, false, max_out)?,
            _ => return Err(Error::Decompression(format!("invalid block type {btype}"))),
        }

        if bfinal != 0 {
            break;
        }

        // A crafted stream can chain empty non-final blocks to burn CPU
        // without ever growing output past the size cap
        if out.len() == progress_mark {
            return Err(Error::Decompression(
                "non-final block produced no output".into(),
            ));
        }
    }

    if expected > 0 {
        if out.len() < expected {
            return Err(Error::Decompression(format!(
                "stream ended after {} of {expected} bytes",
                out.len()
            )));
        }
        out.truncate(expected);
    }
    Ok((out, br.pos))
}

struct WordBitReader<'a> {
    data: &'a [u8],
    pos: usize,
    bits: u32,
    nbits: u32,
}

impl<'a> WordBitReader<'a> {
    const fn new(data: &'a [u8]) -> Self {
        Self {
            data,
            pos: 0,
            bits: 0,
            nbits: 0,
        }
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
        // saturating: at end-of-input ensure_bits cannot supply `n` bits, so
        // avoid underflowing nbits (which would panic in debug and wrap to a
        // huge value in release, spinning the decoder)
        self.nbits = self.nbits.saturating_sub(n);
        val
    }

    /// Discards bits until the accumulator is at a 16-bit boundary.
    ///
    /// 16-bit alignment (`bits & 0xf`) not zlib's 8-bit (`bits & 0x7`)
    #[inline]
    const fn align16(&mut self) {
        let discard = self.nbits % 16;
        if discard > 0 {
            self.bits >>= discard;
            self.nbits -= discard;
        }
    }

    /// Copies the `len` bytes of a stored block to `out`, then skips the pad
    /// byte that follows an odd-length run so the next block starts on a
    /// 16-bit boundary. Call after the LEN/NLEN words have been read
    ///
    /// Errors if the input ends before `len` bytes are available
    fn copy_stored(&mut self, len: usize, out: &mut Vec<u8>) -> Result<(), Error> {
        let mut remaining = len;
        // whole bytes already pulled into the bit buffer come first
        while remaining > 0 && self.nbits >= 8 {
            #[allow(clippy::cast_possible_truncation)]
            out.push(self.bits as u8);
            self.bits >>= 8;
            self.nbits -= 8;
            remaining -= 1;
        }
        if remaining > 0 {
            // the buffer holds no whole byte, so the rest is copied straight
            // from the input
            self.bits = 0;
            self.nbits = 0;
            let end = self
                .pos
                .checked_add(remaining)
                .filter(|&e| e <= self.data.len())
                .ok_or_else(|| {
                    Error::Decompression("stored block runs past end of input".into())
                })?;
            out.extend_from_slice(&self.data[self.pos..end]);
            self.pos = end;
        }
        if len % 2 == 1 {
            if self.nbits >= 8 {
                self.bits >>= 8;
                self.nbits -= 8;
            } else if self.pos < self.data.len() {
                self.pos += 1;
            }
        }
        self.align16();
        Ok(())
    }
}

/// Longest Huffman code DEFLATE allows
const MAX_CODE_BITS: u32 = 15;
/// Codes up to this many bits resolve with a single table lookup. Longer
/// codes are rare and take the bit-by-bit canonical path, which keeps the
/// per-block table small: a stream of tiny blocks cannot force a large table
/// to be rebuilt for each one
const FAST_BITS: u32 = 10;

struct HuffmanTable {
    /// `(symbol, code length)` indexed by the next input bits. Length 0 marks
    /// the prefix of a longer code, or no code at all
    fast: Box<[(u16, u8)]>,
    fast_mask: u32,
    /// Number of codes of each length, for the canonical path
    count: [u16; MAX_CODE_BITS as usize + 1],
    /// Symbols ordered by code length, then by symbol value
    symbols: Box<[u16]>,
}

/// Builds a decoding table from per-symbol code lengths (each 0..=15)
fn build_huffman_table(lengths: &[u8]) -> HuffmanTable {
    const N: usize = MAX_CODE_BITS as usize + 1;

    let mut count = [0u16; N];
    for &len in lengths {
        if len > 0 {
            count[usize::from(len)] += 1;
        }
    }
    let max_bits = (1..N).rev().find(|&b| count[b] > 0).unwrap_or(0);
    #[allow(clippy::cast_possible_truncation)]
    let fast_bits = (max_bits as u32).min(FAST_BITS);

    // first canonical code of each length, and where each length's symbols
    // start in the sorted list
    let mut next_code = [0u32; N];
    let mut offset = [0usize; N];
    let mut code = 0u32;
    for bits in 1..N {
        code = (code + u32::from(count[bits - 1])) << 1;
        next_code[bits] = code;
        offset[bits] = offset[bits - 1] + usize::from(count[bits - 1]);
    }

    let coded = lengths.iter().filter(|&&len| len > 0).count();
    let mut symbols = vec![0u16; coded];
    let mut fast = vec![(0u16, 0u8); 1usize << fast_bits];

    for (sym, &len) in lengths.iter().enumerate() {
        if len == 0 {
            continue;
        }
        #[allow(clippy::cast_possible_truncation)]
        let sym = sym as u16;
        let slot = usize::from(len);
        symbols[offset[slot]] = sym;
        offset[slot] += 1;

        let c = next_code[slot];
        next_code[slot] += 1;
        if u32::from(len) > fast_bits {
            continue;
        }
        let mut idx = reverse_bits(c, len) as usize;
        while idx < fast.len() {
            fast[idx] = (sym, len);
            idx += 1usize << len;
        }
    }

    HuffmanTable {
        fast: fast.into_boxed_slice(),
        fast_mask: (1u32 << fast_bits) - 1,
        count,
        symbols: symbols.into_boxed_slice(),
    }
}

#[inline]
fn reverse_bits(val: u32, len: u8) -> u32 {
    val.reverse_bits() >> (32 - u32::from(len))
}

#[inline]
fn decode_symbol(reader: &mut WordBitReader, table: &HuffmanTable) -> Result<u32, Error> {
    reader.ensure_bits(MAX_CODE_BITS);
    let (sym, len) = table.fast[(reader.bits & table.fast_mask) as usize];
    // Require the matched code to fit within the bits actually read from input.
    // At end-of-input ensure_bits pads with zeros; without this check a truncated
    // stream would decode phantom symbols forever and underflow nbits.
    if len > 0 && u32::from(len) <= reader.nbits {
        reader.bits >>= len;
        reader.nbits -= u32::from(len);
        return Ok(u32::from(sym));
    }
    decode_symbol_canonical(reader, table)
}

/// Decodes one symbol a bit at a time from the code-length counts. Handles the
/// codes too long for the fast table, and reports anything that is not a code.
/// Only bits actually read from the input are considered
#[cold]
fn decode_symbol_canonical(reader: &mut WordBitReader, table: &HuffmanTable) -> Result<u32, Error> {
    let mut code = 0u32;
    let mut first = 0u32;
    let mut index = 0usize;
    for len in 1..=reader.nbits.min(MAX_CODE_BITS) {
        code |= (reader.bits >> (len - 1)) & 1;
        let count = u32::from(table.count[len as usize]);
        if code < first + count {
            let sym = table
                .symbols
                .get(index + (code - first) as usize)
                .ok_or_else(|| Error::Decompression("invalid Huffman code".into()))?;
            reader.bits >>= len;
            reader.nbits -= len;
            return Ok(u32::from(*sym));
        }
        index += count as usize;
        first = (first + count) << 1;
        code <<= 1;
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

static FIXED_DIST: LazyLock<HuffmanTable> = LazyLock::new(|| build_huffman_table(&[5u8; 32]));

fn bomb_error(max_out: usize) -> Error {
    Error::Decompression(format!(
        "output exceeds {max_out} byte limit (possible decompression bomb)"
    ))
}

fn decode_huffman_block(
    reader: &mut WordBitReader,
    out: &mut Vec<u8>,
    fixed: bool,
    max_out: usize,
) -> Result<(), Error> {
    let (dyn_lit, dyn_dist);
    let (lit_table, dist_table) = if fixed {
        (&*FIXED_LIT, &*FIXED_DIST)
    } else {
        let (lengths, hlit) = decode_dynamic_trees(reader)?;
        dyn_lit = build_huffman_table(&lengths[..hlit]);
        dyn_dist = build_huffman_table(&lengths[hlit..]);
        (&dyn_lit, &dyn_dist)
    };

    loop {
        let sym = decode_symbol(reader, lit_table)?;
        if sym == 256 {
            break;
        }
        if sym < 256 {
            if out.len() >= max_out {
                return Err(bomb_error(max_out));
            }
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
            if out.len() + length > max_out {
                return Err(bomb_error(max_out));
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

const CL_ORDER: [usize; 19] = [
    16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15,
];

fn decode_dynamic_trees(reader: &mut WordBitReader) -> Result<(Vec<u8>, usize), Error> {
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
            _ => {
                return Err(Error::Decompression(format!(
                    "invalid code length symbol {sym}"
                )));
            }
        }
    }

    Ok((lengths, hlit))
}

const LEN_BASE: [u16; 29] = [
    3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31, 35, 43, 51, 59, 67, 83, 99, 115, 131,
    163, 195, 227, 258,
];
const LEN_EXTRA: [u8; 29] = [
    0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0,
];
const DIST_BASE: [u16; 30] = [
    1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193, 257, 385, 513, 769, 1025, 1537,
    2049, 3073, 4097, 6145, 8193, 12289, 16385, 24577,
];
const DIST_EXTRA: [u8; 30] = [
    0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13,
    13,
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
        return Err(Error::Decompression(format!(
            "invalid distance symbol {sym}"
        )));
    }
    Ok(usize::from(DIST_BASE[idx]) + reader.read_bits(u32::from(DIST_EXTRA[idx])) as usize)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Deflates `raw` with no zlib header. Without stored blocks the output is
    /// bit-identical to what `WordBitReader` expects, so it round-trips through
    /// `word_deflate`
    fn raw_deflate(raw: &[u8]) -> Vec<u8> {
        let mut comp = flate2::Compress::new(flate2::Compression::best(), false);
        let mut out = vec![0u8; raw.len() + 4096];
        comp.compress(raw, &mut out, flate2::FlushCompress::Finish)
            .unwrap();
        #[allow(clippy::cast_possible_truncation)]
        out.truncate(comp.total_out() as usize);
        out
    }

    /// Packs values least-significant bit first, the order DEFLATE uses
    struct BitWriter {
        out: Vec<u8>,
        acc: u64,
        n: u32,
    }

    impl BitWriter {
        fn new() -> Self {
            Self {
                out: Vec::new(),
                acc: 0,
                n: 0,
            }
        }

        fn put(&mut self, val: u32, bits: u32) {
            self.acc |= u64::from(val) << self.n;
            self.n += bits;
            while self.n >= 8 {
                self.out.push((self.acc & 0xff) as u8);
                self.acc >>= 8;
                self.n -= 8;
            }
        }

        /// Writes a Huffman code, which goes out most-significant bit first
        fn put_code(&mut self, code: u32, len: u8) {
            self.put(reverse_bits(code, len), u32::from(len));
        }

        fn finish(mut self) -> Vec<u8> {
            if self.n > 0 {
                self.out.push((self.acc & 0xff) as u8);
            }
            self.out
        }
    }

    /// A stored block in the word-aligned layout: the 3 header bits are padded
    /// to a 16-bit word, and an odd-length run is followed by one pad byte
    fn stored_block(data: &[u8], last: bool) -> Vec<u8> {
        let len = u16::try_from(data.len()).unwrap();
        let mut out = vec![u8::from(last), 0];
        out.extend_from_slice(&len.to_le_bytes());
        out.extend_from_slice(&(!len).to_le_bytes());
        out.extend_from_slice(data);
        if data.len() % 2 == 1 {
            out.push(0xEE);
        }
        out
    }

    #[test]
    fn stored_blocks_realign_after_odd_lengths() {
        let mut input = stored_block(b"odd", false);
        input.extend(stored_block(b"even", false));
        input.extend(stored_block(b"x", true));
        assert_eq!(word_deflate(&input, 0).unwrap(), b"oddevenx");
        assert_eq!(word_deflate(&input, 8).unwrap(), b"oddevenx");
        let (_, consumed) = word_deflate_with_consumed(&input, 0).unwrap();
        assert_eq!(consumed, input.len());
    }

    #[test]
    fn truncated_stored_block_is_an_error() {
        // the block declares 1000 bytes; only 10 follow. The missing bytes must
        // not be invented
        let mut input = stored_block(&[0xAA; 1000], true);
        input.truncate(6 + 10);
        let Err(Error::Decompression(msg)) = word_deflate(&input, 0) else {
            panic!("expected a decompression error");
        };
        assert!(msg.contains("past end of input"), "unexpected error: {msg}");
    }

    #[test]
    fn short_output_is_an_error() {
        // a complete stream that holds fewer bytes than the header declared
        let input = stored_block(b"four", true);
        assert_eq!(word_deflate(&input, 4).unwrap(), b"four");
        let Err(Error::Decompression(msg)) = word_deflate(&input, 1000) else {
            panic!("expected a decompression error");
        };
        assert!(msg.contains("4 of 1000"), "unexpected error: {msg}");
        // the cipher-layer entry point reports it too, not a short success
        assert!(decode_and_decompress(&[0u8; 8], 1000).is_err());
    }

    #[test]
    fn decodes_codes_longer_than_the_fast_table() {
        // a complete code with lengths 1 through 15: symbol i has length i + 1,
        // and the last two symbols share the longest length
        let lengths: Vec<u8> = (1..=15).chain([15]).collect();
        assert!(u32::from(*lengths.iter().max().unwrap()) > FAST_BITS);
        let table = build_huffman_table(&lengths);

        // canonical codes, as the table builder assigns them
        let mut codes = vec![0u32; lengths.len()];
        let mut code = 0u32;
        let mut prev = lengths[0];
        for (sym, &len) in lengths.iter().enumerate() {
            code <<= len - prev;
            codes[sym] = code;
            code += 1;
            prev = len;
        }

        let order: Vec<usize> = (0..lengths.len()).chain((0..lengths.len()).rev()).collect();
        let mut w = BitWriter::new();
        for &sym in &order {
            w.put_code(codes[sym], lengths[sym]);
        }
        let input = w.finish();

        let mut reader = WordBitReader::new(&input);
        for &sym in &order {
            let got = decode_symbol(&mut reader, &table).unwrap();
            assert_eq!(got as usize, sym);
        }
        // what is left is zero padding, which reads as the 1-bit code for
        // symbol 0 until the input runs out
        let mut leftover = 0;
        while let Ok(sym) = decode_symbol(&mut reader, &table) {
            assert_eq!(sym, 0);
            leftover += 1;
        }
        assert!(leftover < 8);
    }

    #[test]
    fn skewed_data_roundtrips_through_long_codes() {
        // byte frequencies fall off geometrically, which drives the rarest
        // symbols to code lengths past the fast table
        let mut state = 0x2545_F491u32;
        let raw: Vec<u8> = (0..300_000)
            .map(|_| {
                state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
                let r = state >> 8;
                // leading_zeros of a 24-bit value gives a geometric spread
                let bucket = (r | 1).trailing_zeros().min(23);
                u8::try_from(bucket * 9 + ((r >> 12) % 9)).unwrap()
            })
            .collect();
        let compressed = raw_deflate(&raw);
        assert!(compressed.len() < raw.len());
        assert_eq!(word_deflate(&compressed, raw.len()).unwrap(), raw);
    }

    /// One dynamic-Huffman block that emits the single literal `A`. The
    /// literal alphabet is `A` and end-of-block, one bit each
    fn tiny_dynamic_block(w: &mut BitWriter, last: bool) {
        w.put(u32::from(last), 1);
        w.put(2, 2); // dynamic Huffman
        w.put(0, 5); // 257 literal/length codes
        w.put(0, 5); // 1 distance code
        w.put(14, 4); // 18 code-length codes
        for &sym in CL_ORDER.iter().take(18) {
            w.put(u32::from(sym == 18 || sym == 1), 3);
        }
        // code-length alphabet: symbol 1 is code 0, symbol 18 is code 1
        w.put(1, 1);
        w.put(65 - 11, 7); // 65 zero lengths, symbols 0..=64
        w.put(0, 1); // 'A' gets length 1
        w.put(1, 1);
        w.put(138 - 11, 7);
        w.put(1, 1);
        w.put(52 - 11, 7); // zeros through symbol 255
        w.put(0, 1); // end-of-block gets length 1
        w.put(0, 1); // the one distance code gets length 1
        w.put(0, 1); // 'A'
        w.put(1, 1); // end of block
    }

    #[test]
    fn many_tiny_dynamic_blocks_decode() {
        // each block carries its own code tables; the per-block cost has to stay
        // small or a stream of these stalls the decoder
        let blocks = 5_000;
        let mut w = BitWriter::new();
        for i in 0..blocks {
            tiny_dynamic_block(&mut w, i + 1 == blocks);
        }
        let out = word_deflate(&w.finish(), blocks).unwrap();
        assert_eq!(out, vec![b'A'; blocks]);
    }

    #[test]
    fn output_cap_rejects_bomb() {
        // 200 KB of zeros deflates to a tiny stream. With expected = 1 the cap is
        // 1 + MAX_MATCH, so the expansion must be rejected, not allocated
        let compressed = raw_deflate(&vec![0u8; 200_000]);
        let Err(Error::Decompression(msg)) = word_deflate(&compressed, 1) else {
            panic!("expected a decompression-bomb error");
        };
        assert!(msg.contains("bomb"), "unexpected error: {msg}");
    }

    #[test]
    fn empty_nonfinal_block_is_rejected() {
        // bfinal=0, btype=0 (stored), then a zero-length stored block: produces
        // no output. The forward-progress guard must reject it so a stream can't
        // chain empty blocks to burn CPU without tripping the size cap
        let input = [0x00, 0x00, 0x00, 0x00, 0xff, 0xff];
        let Err(Error::Decompression(msg)) = word_deflate(&input, 0) else {
            panic!("expected a decompression error");
        };
        assert!(msg.contains("no output"), "unexpected error: {msg}");
    }

    #[test]
    fn output_cap_allows_legitimate_expansion() {
        // The same payload decodes cleanly when the expected size leaves room
        let raw = vec![0u8; 200_000];
        let compressed = raw_deflate(&raw);
        assert_eq!(word_deflate(&compressed, raw.len()).unwrap(), raw);
    }

    #[test]
    fn inflate_roundtrips_across_chunks() {
        // ~200 KB output spans several INFLATE_CHUNK iterations, with a size that
        // is not a chunk multiple, exercising the incremental loop boundaries
        let raw: Vec<u8> = (0..200_000u32).map(|i| (i % 251) as u8).collect();
        let compressed = raw_deflate(&raw);
        assert_eq!(inflate(&compressed, raw.len()).unwrap(), raw);
        // the unknown-size (shared-block) path returns everything as well
        assert_eq!(inflate(&compressed, 0).unwrap(), raw);
    }

    #[test]
    fn inflate_bails_on_bomb() {
        // 200 KB of zeros -> tiny stream; with expected = 1 the ceiling is ~259,
        // so the chunk loop stops and signals fall-back rather than expanding
        let compressed = raw_deflate(&vec![0u8; 200_000]);
        assert!(inflate(&compressed, 1).is_none());
    }

    #[test]
    fn inflate_bails_on_truncated_stream() {
        let raw = vec![7u8; 100_000];
        let mut compressed = raw_deflate(&raw);
        compressed.truncate(compressed.len() / 2);
        assert!(inflate(&compressed, raw.len()).is_none());
    }

    #[test]
    fn decrypt_swaps_and_ciphers() {
        let mut buf = vec![0x00, 0x01, 0x02, 0x03];
        decode_in_place(&mut buf);
        assert_eq!(buf[0], CIPHER[0x01]);
        assert_eq!(buf[1], CIPHER[0x00]);
        assert_eq!(buf[2], CIPHER[0x03]);
        assert_eq!(buf[3], CIPHER[0x02]);
    }

    #[test]
    fn decrypt_odd_length() {
        let mut buf = vec![0x10, 0x20, 0x30];
        decode_in_place(&mut buf);
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
                decode_in_place(&mut buf);
                assert_eq!(buf[0], CIPHER[b as usize]);
                assert_eq!(buf[1], CIPHER[a as usize]);
            }
        }
    }

    #[test]
    fn decompress_raw_word_deflate_real_cvct() {
        // Captured 194-byte compressed CVCT body; decompresses to a 432-byte
        // record stream starting with an FVCT tag
        #[rustfmt::skip]
        const BODY: [u8; 194] = [
            0x90, 0xcd, 0x0a, 0xbd, 0x60, 0x82, 0x86, 0x14, 0x4f, 0xdf, 0x24, 0x2d, 0xba, 0x0c, 0xdb, 0x04,
            0x08, 0x2b, 0xa5, 0xa1, 0x7f, 0xc5, 0x41, 0x11, 0xa2, 0x3f, 0x03, 0x1a, 0x25, 0xa1, 0x86, 0x92,
            0x69, 0x6c, 0x5a, 0x13, 0x46, 0xea, 0x02, 0xba, 0x5a, 0xe7, 0x84, 0xbb, 0xe6, 0xc6, 0xb6, 0xd6,
            0xe9, 0x06, 0xa5, 0x4b, 0xa8, 0x86, 0x67, 0xb9, 0x07, 0x38, 0xf3, 0xde, 0x72, 0xf7, 0xb1, 0xec,
            0x24, 0x31, 0xc0, 0x48, 0x01, 0x10, 0xc2, 0x59, 0x2a, 0x37, 0x1a, 0x20, 0x06, 0xa5, 0x1c, 0xf5,
            0x09, 0xa5, 0x40, 0xf4, 0x74, 0x80, 0x1a, 0x73, 0xbb, 0xa5, 0x0a, 0x9a, 0xd1, 0x72, 0x64, 0x21,
            0x10, 0x19, 0x81, 0xdc, 0x7e, 0xa3, 0x77, 0xdb, 0x6c, 0xfa, 0x03, 0x82, 0xbe, 0x77, 0xcc, 0xb2,
            0xd1, 0x3a, 0xed, 0x7a, 0xf3, 0xe1, 0xa3, 0x0a, 0xa3, 0xca, 0x6a, 0x51, 0xc7, 0xdc, 0x7a, 0xb5,
            0xdf, 0x82, 0x3c, 0x90, 0xaf, 0x52, 0x28, 0xed, 0xd5, 0x1a, 0x0f, 0x0c, 0xb2, 0x44, 0x78, 0xc2,
            0xbb, 0x2d, 0x78, 0x8b, 0x46, 0x15, 0x61, 0x51, 0xa0, 0xf9, 0x59, 0x6e, 0x88, 0xa7, 0x42, 0x3f,
            0x97, 0xd7, 0xd2, 0xd3, 0x8c, 0x3c, 0xb4, 0xc0, 0xd7, 0x00, 0x7d, 0x37, 0x55, 0x70, 0x16, 0x73,
            0xe5, 0xcf, 0x53, 0x2e, 0xe7, 0x85, 0x54, 0x93, 0xc2, 0x14, 0x2d, 0xe4, 0xce, 0xd8, 0x02, 0x80,
            0x00, 0x0f,
        ];
        let result = decompress_raw_word_deflate(&BODY, 0).unwrap();
        assert_eq!(result.len(), 432);
        assert_eq!(&result[0..4], b"FVCT");
    }

    #[test]
    fn truncated_stream_errors_instead_of_spinning() {
        // The same valid CVCT body cut off mid-stream. Before the EOF guards a
        // truncated stream could decode phantom symbols until it filled the
        // output cap (or panicked in debug); now it must terminate with an Err.
        const BODY: [u8; 32] = [
            0x90, 0xcd, 0x0a, 0xbd, 0x60, 0x82, 0x86, 0x14, 0x4f, 0xdf, 0x24, 0x2d, 0xba, 0x0c,
            0xdb, 0x04, 0x08, 0x2b, 0xa5, 0xa1, 0x7f, 0xc5, 0x41, 0x11, 0xa2, 0x3f, 0x03, 0x1a,
            0x25, 0xa1, 0x86, 0x92,
        ];
        assert!(decompress_raw_word_deflate(&BODY, 0).is_err());
    }
}

//! Reading fields out of the payload

use super::{Error, MAX_ARRAY_COUNT, MAX_STRING_LEN, RecordFmt};

/// Something in the payload that does not read as the structure expected
/// there. Parsing tries many positions and layouts and most of them fail,
/// so this carries no formatted text
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct Malformed {
    pub(super) what: &'static str,
    pub(super) offset: usize,
}

impl From<Malformed> for Error {
    fn from(e: Malformed) -> Self {
        Self::Malformed {
            what: e.what,
            offset: e.offset,
        }
    }
}

pub(super) struct Cursor<'a> {
    pub(super) data: &'a [u8],
    pub(super) pos: usize,
    pub(super) fmt: RecordFmt,
}

impl<'a> Cursor<'a> {
    pub(super) fn new(data: &'a [u8], pos: usize, fmt: RecordFmt) -> Self {
        Self { data, pos, fmt }
    }

    pub(super) fn remaining(&self) -> usize {
        self.data.len().saturating_sub(self.pos)
    }

    /// The error for something wrong at the current position
    pub(super) fn bad(&self, what: &'static str) -> Malformed {
        Malformed {
            what,
            offset: self.pos,
        }
    }

    /// The next `n` bytes
    pub(super) fn take(&mut self, n: usize) -> Result<&'a [u8], Malformed> {
        let end = self.pos.checked_add(n).ok_or(self.bad("truncated"))?;
        let bytes = self.data.get(self.pos..end).ok_or(self.bad("truncated"))?;
        self.pos = end;
        Ok(bytes)
    }

    pub(super) fn u8(&mut self) -> Result<u8, Malformed> {
        Ok(self.take(1)?[0])
    }

    pub(super) fn u16(&mut self) -> Result<u16, Malformed> {
        let b = self.take(2)?;
        Ok(u16::from_le_bytes([b[0], b[1]]))
    }

    pub(super) fn u32(&mut self) -> Result<u32, Malformed> {
        let b = self.take(4)?;
        Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }

    pub(super) fn u64(&mut self) -> Result<u64, Malformed> {
        let lo = u64::from(self.u32()?);
        let hi = u64::from(self.u32()?);
        Ok(hi << 32 | lo)
    }

    /// A u16 count that may not pass `max`; `what` names it in the error
    pub(super) fn bounded_u16(&mut self, max: u16, what: &'static str) -> Result<u16, Malformed> {
        let at = self.pos;
        let v = self.u16()?;
        if v > max {
            return Err(Malformed { what, offset: at });
        }
        Ok(v)
    }

    pub(super) fn skip(&mut self, n: usize) -> Result<(), Malformed> {
        self.take(n).map(|_| ())
    }

    /// u16-prefixed string. Used by locstring internals and non-Pre4 inline
    /// reads. Pre4 inline strings have a one-byte length: see
    /// [`Cursor::inline_string`]
    pub(super) fn string(&mut self) -> Result<&'a [u8], Malformed> {
        let len = usize::from(self.bounded_u16(MAX_STRING_LEN, "string too long")?);
        self.take(len)
    }

    /// Reads an inline string and returns its bytes. Pre4 uses u8 prefix;
    /// all others use u16
    pub(super) fn inline_string(&mut self) -> Result<&'a [u8], Malformed> {
        if self.fmt.is_pre4() {
            let len = usize::from(self.u8()?);
            self.take(len)
        } else {
            self.string()
        }
    }

    /// Steps over an inline string
    pub(super) fn skip_inline(&mut self) -> Result<(), Malformed> {
        self.inline_string().map(|_| ())
    }

    /// u16-prefixed string followed by optional locale variants (u16 count,
    /// then per-locale: u16 id, u16 len, data). All formats use u16 here,
    /// even Pre4
    pub(super) fn locstring(&mut self) -> Result<&'a [u8], Malformed> {
        let s = self.string()?;
        let lc = self.bounded_u16(MAX_ARRAY_COUNT, "too many translations")?;
        for _ in 0..lc {
            self.skip(2)?;
            self.string()?;
        }
        Ok(s)
    }

    /// u16-prefixed variable-length block (alternate filename)
    pub(super) fn alt_block(&mut self) -> Result<(), Malformed> {
        let n = usize::from(self.u16()?);
        self.skip(n)
    }

    /// Skips a u16-prefixed string of any length. Record strings are capped
    /// at [`MAX_STRING_LEN`]; text outside the record stream, such as a
    /// package description, runs longer
    pub(super) fn skip_string(&mut self) -> Result<(), Malformed> {
        self.alt_block()
    }

    /// Skips a u16-prefixed string of any length and its locale variants
    pub(super) fn skip_locstring(&mut self) -> Result<(), Malformed> {
        self.skip_string()?;
        let locales = self.bounded_u16(MAX_ARRAY_COUNT, "too many translations")?;
        for _ in 0..locales {
            self.skip(2)?;
            self.skip_string()?;
        }
        Ok(())
    }

    /// A u32 entry count for a list outside the record stream. Every entry
    /// takes at least one byte, so a count past the remaining data is wrong
    pub(super) fn list_len(&mut self) -> Result<u32, Malformed> {
        let at = self.pos;
        let n = self.u32()?;
        if n as usize > self.remaining() {
            return Err(Malformed {
                what: "list longer than the data left",
                offset: at,
            });
        }
        Ok(n)
    }

    /// Skips a package entry up to the end of its mask: name and
    /// description, one byte, a third text, fixed fields and the mask. Each
    /// text carries its translations. `fixed` is the distance from the
    /// description to the mask when the third text is empty
    pub(super) fn skip_package_front(&mut self, fixed: usize) -> Result<(), Malformed> {
        // a localized string with no text and no translations: two zero counts
        const EMPTY_LOCSTRING: usize = 4;
        self.skip_locstring()?;
        self.skip_locstring()?;
        self.skip(1)?;
        self.skip_locstring()?;
        self.skip(fixed - 1 - EMPTY_LOCSTRING + 36)
    }

    /// Common record header, shared by all record types. The fixed-width
    /// fields differ between Main48 and the rest, and Pre4 omits the flag
    /// byte between features and conditions and the trailing byte after
    /// bitmasks. Condition strings in Pre4 use u8 length prefixes
    ///
    /// Returns the record's ID and the ID of the folder record that holds it
    /// (0 at the top level)
    pub(super) fn common(&mut self) -> Result<(u32, u32), Malformed> {
        let id = self.u32()?;
        let parent = self.u32()?;
        if self.fmt == RecordFmt::Main48 {
            self.u8()?;
            self.skip(2)?;
            self.u8()?;
            self.skip(2)?;
            self.skip(4 + 4)?;
            for _ in 0..6 {
                self.u8()?;
            }
        } else {
            for _ in 0..4 {
                self.u8()?;
            }
            self.skip(4 + 4)?;
            for _ in 0..7 {
                self.u8()?;
            }
        }
        let fc = self.bounded_u16(MAX_ARRAY_COUNT, "feature count")?;
        for _ in 0..fc {
            self.skip(4)?;
            self.u8()?;
        }
        if !self.fmt.is_pre4() {
            self.u8()?;
        }
        let cc = self.bounded_u16(MAX_ARRAY_COUNT, "condition count")?;
        if self.fmt.is_pre4() {
            for _ in 0..cc {
                self.skip_inline()?;
                self.skip(4)?;
                self.skip_inline()?;
                self.skip_inline()?;
            }
        } else {
            for _ in 0..cc {
                self.string()?;
                self.skip(4)?;
                self.string()?;
                self.string()?;
            }
        }
        let cc2 = self.bounded_u16(MAX_ARRAY_COUNT, "condition2 count")?;
        if self.fmt.is_pre4() {
            for _ in 0..cc2 {
                self.skip_inline()?;
                self.skip(4)?;
                self.skip_inline()?;
                self.skip_inline()?;
            }
        } else {
            for _ in 0..cc2 {
                self.string()?;
                self.skip(4)?;
                self.string()?;
                self.string()?;
            }
        }
        self.skip(32 + 32)?;
        if !self.fmt.is_pre4() {
            self.u8()?;
        }
        Ok((id, parent))
    }
}

//! Reading fields out of the payload

use super::layouts::LayoutId;
use super::{Error, MAX_ARRAY_COUNT, MAX_STRING_LEN};

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
    pub(super) layout: LayoutId,
}

impl<'a> Cursor<'a> {
    pub(super) fn new(data: &'a [u8], pos: usize, layout: LayoutId) -> Self {
        Self { data, pos, layout }
    }

    pub(super) fn remaining(&self) -> usize {
        self.data.len().saturating_sub(self.pos)
    }

    /// The error for something wrong at the current position
    pub(super) fn bad(&self, what: &'static str) -> Malformed {
        Self::bad_at(self.pos, what)
    }

    /// The error for something wrong at `offset`
    pub(super) fn bad_at(offset: usize, what: &'static str) -> Malformed {
        Malformed { what, offset }
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

    /// A four-byte length or count
    pub(super) fn len32(&mut self) -> Result<usize, Malformed> {
        let at = self.pos;
        usize::try_from(self.u32()?).map_err(|_| Self::bad_at(at, "length out of range"))
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
            return Err(Self::bad_at(at, what));
        }
        Ok(v)
    }

    pub(super) fn skip(&mut self, n: usize) -> Result<(), Malformed> {
        self.take(n).map(|_| ())
    }

    /// A string with a two-byte length
    pub(super) fn string(&mut self) -> Result<&'a [u8], Malformed> {
        let len = usize::from(self.bounded_u16(MAX_STRING_LEN, "string too long")?);
        self.take(len)
    }

    /// A string with a two-byte length, then a count of translations, each a
    /// language ID and a string
    pub(super) fn locstring(&mut self) -> Result<&'a [u8], Malformed> {
        let s = self.string()?;
        let lc = self.bounded_u16(MAX_ARRAY_COUNT, "too many translations")?;
        for _ in 0..lc {
            self.skip(2)?;
            self.string()?;
        }
        Ok(s)
    }

    /// Steps over a string with a two-byte length, however long
    pub(super) fn skip_string(&mut self) -> Result<(), Malformed> {
        let n = usize::from(self.u16()?);
        self.skip(n)
    }

    /// A string with a one-byte length
    pub(super) fn short_string(&mut self) -> Result<&'a [u8], Malformed> {
        let len = usize::from(self.u8()?);
        self.take(len)
    }
}

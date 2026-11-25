//! Lists of steps that describe how part of a payload is laid out, and the
//! reader that follows one. A record's header, a record's body and the
//! sections in front of the record stream are each such a list; the lists
//! are in `layouts`

use super::MAX_ARRAY_COUNT;
use super::cursor::{Cursor, Malformed};

/// How many bytes a count, a flag or a selector takes
#[derive(Clone, Copy)]
pub(super) enum Width {
    W1,
    W2,
    W4,
}

/// How long the length in front of a string is
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum Text {
    /// One byte
    Short,
    /// Two bytes
    Long,
}

/// One step in reading
pub(super) enum Op {
    /// Bytes that are not used
    Skip(u16),
    /// A string
    Text(Text),
    /// A string, then the first steps if it is empty and the second if it
    /// is not. Empty is no length or a first byte of zero, which is how the
    /// runtime tells
    TextThen(Text, &'static [Op], &'static [Op]),
    /// A string with a two-byte length, then a count of translations, each
    /// a language ID and a string
    Loc,
    /// A four-byte length, then that many bytes
    Block,
    /// A count, then the steps once for each
    Repeat(Width, &'static [Op]),
    /// A value, then the steps if it is not zero
    When(Width, &'static [Op]),
    /// A value, then the steps if it has any of the bits of the mask set
    WhenBits(Width, u32, &'static [Op]),
    /// A value that selects the steps listed for it, or the last ones if it
    /// is listed nowhere
    Choose(
        Width,
        &'static [(&'static [u32], &'static [Op])],
        &'static [Op],
    ),
}

/// What may be taken on trust while reading
#[derive(Clone, Copy)]
pub(super) enum Limit {
    /// Strings no longer than [`super::MAX_STRING_LEN`] and lists no longer
    /// than [`MAX_ARRAY_COUNT`]. For telling whether bytes could be a
    /// record at all
    Record,
    /// Whatever fits in the data. A screen or a setting can hold a whole
    /// document, such as a license
    Any,
}

/// Reads a little-endian value
fn value(c: &mut Cursor, width: Width) -> Result<u32, Malformed> {
    Ok(match width {
        Width::W1 => u32::from(c.u8()?),
        Width::W2 => u32::from(c.u16()?),
        Width::W4 => c.u32()?,
    })
}

/// Steps over a string with a two-byte length
fn long_text(c: &mut Cursor, limit: Limit) -> Result<(), Malformed> {
    match limit {
        Limit::Record => c.string().map(|_| ()),
        Limit::Any => c.skip_string(),
    }
}

/// Steps over what `ops` describes
pub(super) fn step(c: &mut Cursor, ops: &[Op], limit: Limit) -> Result<(), Malformed> {
    for op in ops {
        match *op {
            Op::Skip(n) => c.skip(usize::from(n))?,
            Op::Text(Text::Short) => {
                c.short_string()?;
            }
            Op::Text(Text::Long) => long_text(c, limit)?,
            Op::TextThen(kind, when_empty, otherwise) => {
                let text = match (kind, limit) {
                    (Text::Short, _) => c.short_string()?,
                    (Text::Long, Limit::Record) => c.string()?,
                    (Text::Long, Limit::Any) => {
                        let len = usize::from(c.u16()?);
                        c.take(len)?
                    }
                };
                let empty = text.first().is_none_or(|&first| first == 0);
                step(c, if empty { when_empty } else { otherwise }, limit)?;
            }
            Op::Loc => {
                long_text(c, limit)?;
                let at = c.pos;
                let translations = c.u16()?;
                if matches!(limit, Limit::Record) && translations > MAX_ARRAY_COUNT {
                    return Err(Cursor::bad_at(at, "too many translations"));
                }
                for _ in 0..translations {
                    c.skip(2)?;
                    long_text(c, limit)?;
                }
            }
            Op::Block => {
                let len = c.len32()?;
                c.skip(len)?;
            }
            Op::Repeat(width, body) => {
                let at = c.pos;
                // every entry takes at least a byte
                let most = match limit {
                    Limit::Record => usize::from(MAX_ARRAY_COUNT),
                    Limit::Any => c.remaining(),
                };
                let count = usize::try_from(value(c, width)?)
                    .ok()
                    .filter(|&count| count <= most)
                    .ok_or(Cursor::bad_at(at, "count out of range"))?;
                for _ in 0..count {
                    step(c, body, limit)?;
                }
            }
            Op::When(width, body) => {
                if value(c, width)? != 0 {
                    step(c, body, limit)?;
                }
            }
            Op::WhenBits(width, mask, body) => {
                if value(c, width)? & mask != 0 {
                    step(c, body, limit)?;
                }
            }
            Op::Choose(width, choices, otherwise) => {
                let v = value(c, width)?;
                let body = choices
                    .iter()
                    .find(|(values, _)| values.contains(&v))
                    .map_or(otherwise, |&(_, body)| body);
                step(c, body, limit)?;
            }
        }
    }
    Ok(())
}

/// Reads the header every record starts with: the record's ID, the ID of
/// the folder record that holds it (0 at the top level), then fields that
/// are stepped over. Returns the two IDs
pub(super) fn record_header(c: &mut Cursor) -> Result<(u32, u32), Malformed> {
    let id = c.u32()?;
    let parent = c.u32()?;
    step(c, c.layout.table().header, Limit::Record)?;
    Ok((id, parent))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::win::LAYOUTS;

    fn end(data: &[u8], ops: &[Op]) -> Option<usize> {
        let mut c = Cursor::new(data, 0, LAYOUTS[0]);
        step(&mut c, ops, Limit::Any).ok().map(|()| c.pos)
    }

    #[test]
    fn each_step_takes_what_it_describes() {
        use Width::{W1, W2};
        assert_eq!(end(&[0; 5], &[Op::Skip(5)]), Some(5));
        assert_eq!(end(b"\x02ab", &[Op::Text(Text::Short)]), Some(3));
        assert_eq!(end(b"\x02\x00ab", &[Op::Text(Text::Long)]), Some(4));
        // a string, then one translation: a language ID and a string
        assert_eq!(
            end(b"\x01\x00a\x01\x00\x09\x04\x01\x00b", &[Op::Loc]),
            Some(10)
        );
        assert_eq!(end(b"\x03\x00\x00\x00abc", &[Op::Block]), Some(7));
        // two entries of one byte each
        assert_eq!(
            end(b"\x02\x00xy", &[Op::Repeat(W2, &[Op::Skip(1)])]),
            Some(4)
        );
        assert_eq!(end(b"\x00x", &[Op::When(W1, &[Op::Skip(1)])]), Some(1));
        assert_eq!(end(b"\x07x", &[Op::When(W1, &[Op::Skip(1)])]), Some(2));
        // the high bit alone does not count under a mask of 0x7f
        assert_eq!(
            end(b"\x80x", &[Op::WhenBits(W1, 0x7f, &[Op::Skip(1)])]),
            Some(1)
        );
        assert_eq!(
            end(b"\x81x", &[Op::WhenBits(W1, 0x7f, &[Op::Skip(1)])]),
            Some(2)
        );
        // a string with text is followed by two bytes, one without by one
        let then = [Op::TextThen(Text::Long, &[Op::Skip(1)], &[Op::Skip(2)])];
        assert_eq!(end(b"\x01\x00axyz", &then), Some(5));
        assert_eq!(end(b"\x00\x00xyz", &then), Some(3));
        // a length with a zero byte first is no text
        assert_eq!(end(b"\x01\x00\x00xyz", &then), Some(4));
        let choose = [Op::Choose(W1, &[(&[4], &[Op::Skip(2)])], &[Op::Skip(1)])];
        assert_eq!(end(b"\x04xy", &choose), Some(3));
        assert_eq!(end(b"\x05xy", &choose), Some(2));
    }

    #[test]
    fn data_that_ends_early_is_an_error() {
        use Width::W2;
        assert_eq!(end(b"\x05ab", &[Op::Text(Text::Short)]), None);
        assert_eq!(end(b"\xff\xff", &[Op::Repeat(W2, &[Op::Skip(1)])]), None);
    }

    /// The fewest bytes `ops` can take
    fn least(ops: &[Op]) -> usize {
        let wide = |w: Width| match w {
            Width::W1 => 1,
            Width::W2 => 2,
            Width::W4 => 4,
        };
        ops.iter()
            .map(|op| match *op {
                Op::Skip(n) => usize::from(n),
                Op::Text(Text::Short) => 1,
                Op::Text(Text::Long) => 2,
                Op::TextThen(kind, a, b) => {
                    usize::from(kind == Text::Long) + 1 + least(a).min(least(b))
                }
                Op::Loc | Op::Block => 4,
                Op::Repeat(w, _) | Op::When(w, _) | Op::WhenBits(w, _, _) => wide(w),
                Op::Choose(w, choices, otherwise) => {
                    let bodies = choices.iter().map(|&(_, body)| body);
                    wide(w) + bodies.chain([otherwise]).map(least).min().unwrap_or(0)
                }
            })
            .sum()
    }

    /// Calls `check` with the body of every list that is repeated
    fn repeated(ops: &[Op], check: &mut impl FnMut(&[Op])) {
        for op in ops {
            match *op {
                Op::Repeat(_, body) => {
                    check(body);
                    repeated(body, check);
                }
                Op::When(_, body) | Op::WhenBits(_, _, body) => repeated(body, check),
                Op::TextThen(_, a, b) => {
                    repeated(a, check);
                    repeated(b, check);
                }
                Op::Choose(_, choices, otherwise) => {
                    for &(_, body) in choices {
                        repeated(body, check);
                    }
                    repeated(otherwise, check);
                }
                _ => {}
            }
        }
    }

    #[test]
    fn nothing_repeated_is_empty() {
        // a count is trusted up to the bytes that are left, which only bounds
        // the work if every entry takes at least one
        for layout in LAYOUTS {
            let table = layout.table();
            let bodies = table.bodies.iter().flatten().copied();
            for ops in bodies.chain([table.header, table.start]) {
                repeated(ops, &mut |body| assert!(least(body) > 0, "{layout:?}"));
            }
        }
    }
}

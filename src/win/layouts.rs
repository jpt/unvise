//! The layouts: for each, the header of a record, the body of every record
//! type, where a file record keeps what extraction uses, and the sections in
//! front of the record stream, in the form `grammar` reads

#![cfg_attr(rustfmt, rustfmt::skip)]

use super::grammar::{Op, Text, Width::{W1, W2, W4}};

/// A layout: a group of runtime DLLs that read their installers alike.
///
/// A name in `V` is the earliest release whose own installer is known to carry
/// one of those runtimes; the layout may be older than that release, and other
/// releases may use it. Any other name is the link stamp of the oldest of the
/// runtimes, with `Fork` when they carry the string `vise32qt`
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum LayoutId {
    Built33739B9E, Built33D3713B, V2_4_3, V2_5, V2_6, Built35071525, V2_6_2, V2_6_3, V2_7, V2_7_1,
    Built36101749, V2_8, Built370902B8, Fork37150603, Built3717A989, Built3741ED89, Built377CCE3C,
    V3_1, V3_1_1, V3_5, Built39EB21BD, V3_6_1,
}

/// Every layout, from the one with the newest runtimes to the one with the
/// oldest: the order they are tried in
pub(super) const LAYOUTS: [LayoutId; 22] = [
    LayoutId::V3_6_1, LayoutId::Built39EB21BD, LayoutId::V3_5, LayoutId::V3_1_1, LayoutId::V3_1,
    LayoutId::Built377CCE3C, LayoutId::Built3741ED89, LayoutId::Built3717A989,
    LayoutId::Fork37150603, LayoutId::Built370902B8, LayoutId::V2_8, LayoutId::Built36101749,
    LayoutId::V2_7_1, LayoutId::V2_7, LayoutId::V2_6_3, LayoutId::V2_6_2, LayoutId::Built35071525,
    LayoutId::V2_6, LayoutId::V2_5, LayoutId::V2_4_3, LayoutId::Built33D3713B,
    LayoutId::Built33739B9E,
];

/// Where a file record keeps what extraction uses
pub(super) struct FileRecord {
    /// The strings between the name and the sizes
    pub(super) before_sizes: &'static [Text],
    /// Which of those strings is the folder the file installs to, if one is
    pub(super) folder: Option<usize>,
    /// The string after the times
    pub(super) after_times: Text,
    /// How far past that string the CRC-32 of the contents is
    pub(super) crc_at: usize,
    /// How far past that string the byte that names a download item is, in
    /// the layouts that have download items
    pub(super) source_at: Option<usize>,
}

/// What a layout consists of
pub(super) struct Layout {
    /// The header every record starts with, after its ID and its parent's
    pub(super) header: &'static [Op],
    /// The body of each record type, the first being type 1. `None` where
    /// the runtime has no record of that type
    pub(super) bodies: &'static [Option<&'static [Op]>],
    pub(super) file: FileRecord,
    /// From the end of the embedded DLLs to the record stream
    pub(super) start: &'static [Op],
    /// Types that are no record: nothing follows the type number
    pub(super) bare: &'static [u32],
}

// A list of steps is defined once, under the first layout and part that has it,
// and used by every later layout that reads the same. `T02` is the body of a
// type 2 record

static BUILT33739B9E_HEADER: &[Op] = &[
    Op::Skip(19),
    Op::Repeat(W2, &[Op::Skip(5)]),
    Op::Repeat(W2, &[Op::Text(Text::Short), Op::Skip(4), Op::Text(Text::Short), Op::Text(Text::Short)]),
    Op::Repeat(W2, &[Op::Text(Text::Short), Op::Skip(4), Op::Text(Text::Short), Op::Text(Text::Short)]),
    Op::Skip(64),
];
static BUILT33739B9E_T01: &[Op] = &[
    Op::Loc,
    Op::Text(Text::Short),
    Op::Text(Text::Short),
    Op::Skip(9),
    Op::Text(Text::Short),
    Op::Skip(2),
];
static BUILT33739B9E_T02: &[Op] = &[
    Op::Loc,
    Op::Text(Text::Short),
    Op::Text(Text::Short),
    Op::Skip(53),
    Op::Text(Text::Short),
    Op::Skip(19),
];
static BUILT33739B9E_T03: &[Op] = &[
    Op::Loc,
    Op::Text(Text::Short),
    Op::Text(Text::Short),
    Op::Text(Text::Short),
    Op::Text(Text::Short),
    Op::Skip(2),
    Op::Loc,
    Op::Skip(3),
];
static BUILT33739B9E_T04: &[Op] = &[
    Op::Skip(1),
    Op::Text(Text::Short),
    Op::Text(Text::Short),
    Op::Text(Text::Short),
    Op::Text(Text::Short),
    Op::Text(Text::Short),
    Op::Text(Text::Short),
    Op::Skip(1),
];
static BUILT33739B9E_T05: &[Op] = &[
    Op::Skip(1),
    Op::Text(Text::Short),
    Op::Skip(1),
    Op::Text(Text::Short),
    Op::Text(Text::Short),
    Op::Text(Text::Short),
    Op::Skip(1),
    Op::Text(Text::Short),
    Op::Skip(1),
];
static BUILT33739B9E_T06: &[Op] = &[
    Op::Skip(1),
    Op::Text(Text::Short),
    Op::Skip(18),
    Op::Text(Text::Short),
    Op::Skip(1),
    Op::Text(Text::Short),
    Op::Skip(1),
    Op::Loc,
];
static BUILT33739B9E_T07: &[Op] = &[Op::Skip(1), Op::Text(Text::Short), Op::Skip(18), Op::Text(Text::Short), Op::Skip(1)];
static BUILT33739B9E_T08: &[Op] = &[Op::Skip(1), Op::Text(Text::Short), Op::Skip(18), Op::Text(Text::Short), Op::Skip(2)];
static BUILT33739B9E_T10: &[Op] = &[Op::Text(Text::Short), Op::Text(Text::Short), Op::Skip(2)];
static BUILT33739B9E_T11: &[Op] = &[
    Op::Loc,
    Op::Text(Text::Short),
    Op::Text(Text::Short),
    Op::Text(Text::Short),
    Op::Text(Text::Short),
    Op::Skip(10),
    Op::Text(Text::Short),
];
static BUILT33739B9E_T12: &[Op] = &[Op::Loc, Op::Loc, Op::Skip(2)];
static BUILT33739B9E_T13: &[Op] = &[];
static BUILT33739B9E_T14: &[Op] = &[Op::Text(Text::Short), Op::Skip(4), Op::Text(Text::Short), Op::Text(Text::Short)];
static BUILT33739B9E_T15: &[Op] = &[Op::Text(Text::Short), Op::Skip(10)];
static BUILT33739B9E_T16: &[Op] = &[Op::Skip(1), Op::Text(Text::Short), Op::Skip(1), Op::Text(Text::Short)];
static BUILT33739B9E_T17: &[Op] = &[Op::Text(Text::Short), Op::Text(Text::Short), Op::Skip(4)];
static BUILT33739B9E_T18: &[Op] = &[Op::Text(Text::Short), Op::Skip(1), Op::Text(Text::Short), Op::Text(Text::Short), Op::Skip(1)];
static BUILT33739B9E_T19: &[Op] = &[Op::Text(Text::Short), Op::Skip(2)];
static BUILT33739B9E_T21: &[Op] = &[Op::Text(Text::Short), Op::Text(Text::Short), Op::Skip(57), Op::Text(Text::Short), Op::Skip(2)];
static BUILT33739B9E_T22: &[Op] = &[Op::Loc, Op::Loc, Op::Text(Text::Short)];
static BUILT33739B9E_T23: &[Op] = &[Op::Skip(9)];
static BUILT33739B9E_T24: &[Op] = &[
    Op::Skip(1),
    Op::Text(Text::Short),
    Op::Skip(1),
    Op::Text(Text::Short),
    Op::Text(Text::Short),
    Op::Skip(2),
];
static BUILT33739B9E_T25: &[Op] = &[Op::Skip(2), Op::Text(Text::Short), Op::Text(Text::Short), Op::Skip(2)];
static BUILT33739B9E_T26: &[Op] = &[Op::Text(Text::Short)];
static BUILT33739B9E_T27: &[Op] = &[
    Op::Text(Text::Short),
    Op::Text(Text::Short),
    Op::Text(Text::Short),
    Op::Skip(1),
    Op::Text(Text::Short),
    Op::Skip(1),
];
static BUILT33739B9E_START: &[Op] = &[
    Op::Skip(4),
    Op::Text(Text::Short),
    Op::Skip(1),
    Op::Text(Text::Short),
    Op::Text(Text::Short),
    Op::Repeat(W2, &[Op::Skip(2), Op::Text(Text::Short)]),
    Op::Loc,
    Op::Skip(5),
    Op::WhenBits(W1, 0x7f, &[
        Op::Skip(1),
        Op::Loc,
        Op::Loc,
        Op::Loc,
        Op::Text(Text::Long),
        Op::Skip(2),
        Op::Text(Text::Long),
        Op::Skip(4),
        Op::Text(Text::Long),
    ]),
    Op::Text(Text::Short),
    Op::Skip(4),
    Op::Text(Text::Short),
    Op::Text(Text::Short),
    Op::Text(Text::Short),
    Op::Skip(4),
    Op::Text(Text::Short),
    Op::Text(Text::Short),
    Op::Text(Text::Short),
    Op::Skip(4),
    Op::Text(Text::Short),
    Op::Text(Text::Short),
    Op::Skip(26),
    Op::When(W1, &[Op::Skip(9), Op::Text(Text::Long), Op::Skip(2), Op::Loc, Op::Skip(3)]),
    Op::When(W1, &[Op::Loc, Op::Text(Text::Long)]),
    Op::When(W1, &[Op::Loc, Op::Loc, Op::Text(Text::Long)]),
    Op::When(W1, &[Op::Loc, Op::Loc, Op::Text(Text::Long)]),
    Op::Loc,
    Op::Loc,
    Op::Text(Text::Long),
    Op::When(W1, &[Op::Loc, Op::Loc, Op::Loc, Op::Loc]),
    Op::When(W1, &[Op::Loc, Op::Loc, Op::Text(Text::Long), Op::Text(Text::Long)]),
    Op::When(W1, &[
        Op::Loc,
        Op::Loc,
        Op::Loc,
        Op::Loc,
        Op::Loc,
        Op::Text(Text::Long),
        Op::Text(Text::Long),
        Op::Skip(4),
        Op::Text(Text::Long),
    ]),
    Op::When(W1, &[Op::Loc, Op::Loc, Op::Text(Text::Long)]),
    Op::Loc,
    Op::Loc,
    Op::When(W1, &[Op::Loc, Op::Loc, Op::Loc, Op::Loc, Op::Loc, Op::Loc, Op::Loc, Op::Loc, Op::Text(Text::Long)]),
    Op::Loc,
    Op::Loc,
    Op::Text(Text::Long),
    Op::When(W1, &[Op::Loc, Op::Loc, Op::Text(Text::Long), Op::Skip(1)]),
    Op::Loc,
    Op::When(W1, &[Op::Loc, Op::Loc, Op::Text(Text::Long), Op::Skip(1)]),
    Op::When(W1, &[Op::Loc, Op::Loc, Op::Text(Text::Long)]),
    Op::When(W1, &[
        Op::Loc,
        Op::Loc,
        Op::Loc,
        Op::Loc,
        Op::Loc,
        Op::Loc,
        Op::Text(Text::Long),
        Op::Skip(1),
        Op::Text(Text::Long),
        Op::Text(Text::Long),
        Op::Skip(1),
        Op::Text(Text::Long),
        Op::Text(Text::Long),
        Op::Skip(1),
        Op::Text(Text::Long),
        Op::Text(Text::Long),
    ]),
    Op::When(W1, &[Op::Loc, Op::Loc, Op::Loc, Op::Loc, Op::Loc, Op::Text(Text::Long), Op::Skip(1)]),
    Op::Repeat(W1, &[Op::Text(Text::Short), Op::Skip(12), Op::Block]),
    Op::Repeat(W2, &[Op::Loc, Op::Loc, Op::Skip(1), Op::Loc, Op::Skip(63)]),
];
static BUILT33D3713B_START: &[Op] = &[
    Op::Skip(1),
    Op::When(W1, &[
        Op::Text(Text::Long),
        Op::Text(Text::Long),
        Op::Text(Text::Long),
        Op::Text(Text::Long),
        Op::Text(Text::Long),
        Op::Text(Text::Long),
        Op::Text(Text::Long),
        Op::Text(Text::Long),
        Op::Text(Text::Long),
        Op::Text(Text::Long),
        Op::Text(Text::Long),
        Op::Skip(9),
        Op::Repeat(W2, &[
            Op::Choose(W2, &[
                (&[1, 3], &[Op::Text(Text::Long), Op::Skip(9)]),
                (&[2, 4], &[Op::Text(Text::Long), Op::Skip(8)]),
            ], &[]),
        ]),
    ]),
    Op::Skip(2),
    Op::Text(Text::Short),
    Op::Skip(1),
    Op::Text(Text::Short),
    Op::Text(Text::Short),
    Op::Repeat(W2, &[Op::Skip(2), Op::Text(Text::Short)]),
    Op::Loc,
    Op::Skip(5),
    Op::WhenBits(W1, 0x7f, &[
        Op::Skip(1),
        Op::Loc,
        Op::Loc,
        Op::Loc,
        Op::Text(Text::Long),
        Op::Skip(2),
        Op::Text(Text::Long),
        Op::Skip(4),
        Op::Text(Text::Long),
    ]),
    Op::Text(Text::Short),
    Op::Skip(4),
    Op::Text(Text::Short),
    Op::Text(Text::Short),
    Op::Text(Text::Short),
    Op::Skip(4),
    Op::Text(Text::Short),
    Op::Text(Text::Short),
    Op::Text(Text::Short),
    Op::Skip(4),
    Op::Text(Text::Short),
    Op::Text(Text::Short),
    Op::Skip(26),
    Op::When(W1, &[Op::Skip(9), Op::Text(Text::Long), Op::Skip(2), Op::Loc]),
    Op::Skip(3),
    Op::When(W1, &[Op::Loc, Op::Text(Text::Long)]),
    Op::When(W1, &[Op::Loc, Op::Loc, Op::Text(Text::Long)]),
    Op::When(W1, &[Op::Loc, Op::Loc, Op::Text(Text::Long)]),
    Op::Loc,
    Op::Loc,
    Op::Text(Text::Long),
    Op::When(W1, &[Op::Loc, Op::Loc, Op::Loc, Op::Loc]),
    Op::When(W1, &[Op::Loc, Op::Loc, Op::Text(Text::Long), Op::Text(Text::Long)]),
    Op::When(W1, &[
        Op::Loc,
        Op::Loc,
        Op::Loc,
        Op::Loc,
        Op::Loc,
        Op::Text(Text::Long),
        Op::Text(Text::Long),
        Op::Skip(4),
        Op::Text(Text::Long),
    ]),
    Op::When(W1, &[Op::Loc, Op::Loc, Op::Text(Text::Long)]),
    Op::Loc,
    Op::Loc,
    Op::When(W1, &[Op::Loc, Op::Loc, Op::Loc, Op::Loc, Op::Loc, Op::Loc, Op::Loc, Op::Loc, Op::Text(Text::Long)]),
    Op::Loc,
    Op::Loc,
    Op::Text(Text::Long),
    Op::When(W1, &[Op::Loc, Op::Loc, Op::Text(Text::Long), Op::Skip(1)]),
    Op::Loc,
    Op::When(W1, &[Op::Loc, Op::Loc, Op::Text(Text::Long), Op::Skip(1)]),
    Op::When(W1, &[Op::Loc, Op::Loc, Op::Text(Text::Long)]),
    Op::When(W1, &[
        Op::Loc,
        Op::Loc,
        Op::Loc,
        Op::Loc,
        Op::Loc,
        Op::Loc,
        Op::Text(Text::Long),
        Op::Skip(1),
        Op::Text(Text::Long),
        Op::Text(Text::Long),
        Op::Skip(1),
        Op::Text(Text::Long),
        Op::Text(Text::Long),
        Op::Skip(1),
        Op::Text(Text::Long),
        Op::Text(Text::Long),
    ]),
    Op::When(W1, &[Op::Loc, Op::Loc, Op::Loc, Op::Loc, Op::Loc, Op::Text(Text::Long), Op::Skip(1)]),
    Op::Repeat(W1, &[Op::Text(Text::Short), Op::Skip(12), Op::Block]),
    Op::Repeat(W2, &[Op::Loc, Op::Loc, Op::Skip(1), Op::Loc, Op::Skip(67)]),
];
static V2_4_3_T15: &[Op] = &[Op::Text(Text::Short), Op::Skip(12)];
static V2_4_3_START: &[Op] = &[
    Op::Skip(1),
    Op::When(W1, &[
        Op::Text(Text::Long),
        Op::Text(Text::Long),
        Op::Text(Text::Long),
        Op::Text(Text::Long),
        Op::Text(Text::Long),
        Op::Text(Text::Long),
        Op::Text(Text::Long),
        Op::Text(Text::Long),
        Op::Text(Text::Long),
        Op::Text(Text::Long),
        Op::Text(Text::Long),
        Op::Skip(9),
        Op::Repeat(W2, &[
            Op::Choose(W2, &[
                (&[1, 3], &[Op::Text(Text::Long), Op::Skip(9)]),
                (&[2, 4], &[Op::Text(Text::Long), Op::Skip(8)]),
            ], &[]),
        ]),
    ]),
    Op::Skip(2),
    Op::Text(Text::Short),
    Op::Skip(1),
    Op::Text(Text::Short),
    Op::Text(Text::Short),
    Op::Repeat(W2, &[Op::Skip(2), Op::Text(Text::Short)]),
    Op::Loc,
    Op::Skip(5),
    Op::WhenBits(W1, 0x7f, &[
        Op::Skip(1),
        Op::Loc,
        Op::Loc,
        Op::Loc,
        Op::Text(Text::Long),
        Op::Skip(2),
        Op::Text(Text::Long),
        Op::Skip(4),
        Op::Text(Text::Long),
    ]),
    Op::Text(Text::Short),
    Op::Skip(4),
    Op::Text(Text::Short),
    Op::Text(Text::Short),
    Op::Text(Text::Short),
    Op::Skip(4),
    Op::Text(Text::Short),
    Op::Text(Text::Short),
    Op::Text(Text::Short),
    Op::Skip(4),
    Op::Text(Text::Short),
    Op::Text(Text::Short),
    Op::Skip(26),
    Op::When(W1, &[Op::Skip(9), Op::Text(Text::Long), Op::Skip(4), Op::Loc]),
    Op::Skip(3),
    Op::When(W1, &[Op::Loc, Op::Text(Text::Long)]),
    Op::When(W1, &[Op::Loc, Op::Loc, Op::Text(Text::Long)]),
    Op::When(W1, &[Op::Loc, Op::Loc, Op::Text(Text::Long)]),
    Op::Loc,
    Op::Loc,
    Op::Text(Text::Long),
    Op::When(W1, &[Op::Loc, Op::Loc, Op::Loc, Op::Loc]),
    Op::When(W1, &[Op::Loc, Op::Loc, Op::Text(Text::Long), Op::Text(Text::Long)]),
    Op::When(W1, &[
        Op::Loc,
        Op::Loc,
        Op::Loc,
        Op::Loc,
        Op::Loc,
        Op::Text(Text::Long),
        Op::Text(Text::Long),
        Op::Skip(4),
        Op::Text(Text::Long),
    ]),
    Op::When(W1, &[Op::Loc, Op::Loc, Op::Text(Text::Long)]),
    Op::Loc,
    Op::Loc,
    Op::When(W1, &[Op::Loc, Op::Loc, Op::Loc, Op::Loc, Op::Loc, Op::Loc, Op::Loc, Op::Loc, Op::Text(Text::Long)]),
    Op::Loc,
    Op::Loc,
    Op::Text(Text::Long),
    Op::When(W1, &[Op::Loc, Op::Loc, Op::Text(Text::Long), Op::Skip(1)]),
    Op::Loc,
    Op::When(W1, &[Op::Loc, Op::Loc, Op::Text(Text::Long), Op::Skip(1)]),
    Op::When(W1, &[Op::Loc, Op::Loc, Op::Text(Text::Long)]),
    Op::When(W1, &[
        Op::Loc,
        Op::Loc,
        Op::Loc,
        Op::Loc,
        Op::Loc,
        Op::Loc,
        Op::Text(Text::Long),
        Op::Skip(1),
        Op::Text(Text::Long),
        Op::Text(Text::Long),
        Op::Skip(1),
        Op::Text(Text::Long),
        Op::Text(Text::Long),
        Op::Skip(1),
        Op::Text(Text::Long),
        Op::Text(Text::Long),
    ]),
    Op::When(W1, &[Op::Loc, Op::Loc, Op::Loc, Op::Loc, Op::Loc, Op::Text(Text::Long), Op::Skip(1)]),
    Op::Repeat(W1, &[Op::Text(Text::Short), Op::Skip(12), Op::Block]),
    Op::Repeat(W2, &[Op::Loc, Op::Loc, Op::Skip(1), Op::Loc, Op::Skip(67)]),
];
static V2_5_T02: &[Op] = &[
    Op::Loc,
    Op::Text(Text::Short),
    Op::Text(Text::Short),
    Op::Skip(53),
    Op::Text(Text::Short),
    Op::Skip(21),
];
static V2_5_T22: &[Op] = &[Op::Loc, Op::Loc, Op::Text(Text::Long), Op::Text(Text::Long)];
static V2_5_START: &[Op] = &[
    Op::Skip(1),
    Op::When(W1, &[
        Op::Text(Text::Long),
        Op::Text(Text::Long),
        Op::Text(Text::Long),
        Op::Text(Text::Long),
        Op::Text(Text::Long),
        Op::Text(Text::Long),
        Op::Text(Text::Long),
        Op::Text(Text::Long),
        Op::Text(Text::Long),
        Op::Text(Text::Long),
        Op::Text(Text::Long),
        Op::Skip(9),
        Op::Repeat(W2, &[
            Op::Choose(W2, &[
                (&[1, 3], &[Op::Text(Text::Long), Op::Skip(9)]),
                (&[2, 4], &[Op::Text(Text::Long), Op::Skip(8)]),
            ], &[]),
        ]),
    ]),
    Op::Skip(2),
    Op::Text(Text::Short),
    Op::Text(Text::Short),
    Op::Skip(1),
    Op::Text(Text::Short),
    Op::Text(Text::Short),
    Op::Repeat(W2, &[Op::Skip(2), Op::Text(Text::Short), Op::Text(Text::Short)]),
    Op::Loc,
    Op::Skip(5),
    Op::WhenBits(W1, 0x7f, &[
        Op::Skip(1),
        Op::Loc,
        Op::Loc,
        Op::Loc,
        Op::Text(Text::Long),
        Op::Skip(2),
        Op::Text(Text::Long),
        Op::Skip(4),
        Op::Text(Text::Long),
    ]),
    Op::Text(Text::Short),
    Op::Skip(4),
    Op::Text(Text::Short),
    Op::Text(Text::Short),
    Op::Text(Text::Short),
    Op::Skip(4),
    Op::Text(Text::Short),
    Op::Text(Text::Short),
    Op::Text(Text::Short),
    Op::Skip(4),
    Op::Text(Text::Short),
    Op::Text(Text::Short),
    Op::Skip(26),
    Op::When(W1, &[Op::Skip(9), Op::Text(Text::Long), Op::Skip(4), Op::Loc]),
    Op::Skip(3),
    Op::When(W1, &[Op::Loc, Op::Text(Text::Long)]),
    Op::When(W1, &[Op::Loc, Op::Loc, Op::Text(Text::Long)]),
    Op::When(W1, &[Op::Loc, Op::Loc, Op::Text(Text::Long)]),
    Op::Loc,
    Op::Loc,
    Op::Text(Text::Long),
    Op::When(W1, &[Op::Loc, Op::Loc, Op::Loc, Op::Loc]),
    Op::When(W1, &[Op::Loc, Op::Loc, Op::Text(Text::Long), Op::Text(Text::Long)]),
    Op::When(W1, &[
        Op::Loc,
        Op::Loc,
        Op::Loc,
        Op::Loc,
        Op::Loc,
        Op::Text(Text::Long),
        Op::Text(Text::Long),
        Op::Skip(4),
        Op::Text(Text::Long),
    ]),
    Op::When(W1, &[Op::Loc, Op::Loc, Op::Text(Text::Long)]),
    Op::Loc,
    Op::Loc,
    Op::When(W1, &[Op::Loc, Op::Loc, Op::Loc, Op::Loc, Op::Loc, Op::Loc, Op::Loc, Op::Loc, Op::Text(Text::Long)]),
    Op::Loc,
    Op::Loc,
    Op::Text(Text::Long),
    Op::When(W1, &[Op::Loc, Op::Loc, Op::Text(Text::Long), Op::Skip(1)]),
    Op::Loc,
    Op::When(W1, &[Op::Loc, Op::Loc, Op::Text(Text::Long), Op::Skip(1)]),
    Op::When(W1, &[Op::Loc, Op::Loc, Op::Text(Text::Long)]),
    Op::When(W1, &[
        Op::Loc,
        Op::Loc,
        Op::Loc,
        Op::Loc,
        Op::Loc,
        Op::Loc,
        Op::Text(Text::Long),
        Op::Skip(1),
        Op::Text(Text::Long),
        Op::Text(Text::Long),
        Op::Skip(1),
        Op::Text(Text::Long),
        Op::Text(Text::Long),
        Op::Skip(1),
        Op::Text(Text::Long),
        Op::Text(Text::Long),
    ]),
    Op::When(W1, &[Op::Loc, Op::Loc, Op::Loc, Op::Loc, Op::Loc, Op::Text(Text::Long), Op::Skip(1)]),
    Op::Repeat(W1, &[Op::Text(Text::Short), Op::Skip(12), Op::Block]),
    Op::Repeat(W2, &[Op::Loc, Op::Loc, Op::Skip(1), Op::Loc, Op::Skip(67)]),
];
static V2_6_T01: &[Op] = &[
    Op::Loc,
    Op::Text(Text::Short),
    Op::Text(Text::Short),
    Op::Skip(9),
    Op::Text(Text::Short),
    Op::Skip(3),
    Op::Text(Text::Long),
    Op::Skip(4),
];
static V2_6_T02: &[Op] = &[
    Op::Loc,
    Op::Text(Text::Short),
    Op::Text(Text::Short),
    Op::Skip(53),
    Op::Text(Text::Short),
    Op::Skip(27),
    Op::Text(Text::Long),
    Op::Skip(1),
];
static V2_6_T03: &[Op] = &[
    Op::Loc,
    Op::Text(Text::Short),
    Op::Text(Text::Short),
    Op::Text(Text::Short),
    Op::Text(Text::Short),
    Op::Skip(2),
    Op::Loc,
    Op::Skip(5),
];
static V2_6_T27: &[Op] = &[
    Op::Text(Text::Short),
    Op::Text(Text::Short),
    Op::Text(Text::Short),
    Op::Skip(1),
    Op::Text(Text::Short),
    Op::Skip(2),
];
static V2_6_T28: &[Op] = &[
    Op::Loc,
    Op::Loc,
    Op::Text(Text::Long),
    Op::Text(Text::Long),
    Op::Text(Text::Long),
    Op::Text(Text::Long),
];
static V2_6_T29: &[Op] = &[
    Op::Skip(1),
    Op::Text(Text::Long),
    Op::Skip(2),
    Op::Text(Text::Long),
    Op::Text(Text::Long),
    Op::Skip(4),
    Op::Text(Text::Long),
    Op::Text(Text::Long),
    Op::Text(Text::Long),
    Op::Skip(5),
];
static V2_6_T30: &[Op] = &[Op::Skip(1), Op::Text(Text::Long)];
static V2_6_START: &[Op] = &[
    Op::Skip(1),
    Op::When(W1, &[
        Op::Text(Text::Long),
        Op::Text(Text::Long),
        Op::Text(Text::Long),
        Op::Text(Text::Long),
        Op::Text(Text::Long),
        Op::Text(Text::Long),
        Op::Text(Text::Long),
        Op::Text(Text::Long),
        Op::Text(Text::Long),
        Op::Text(Text::Long),
        Op::Text(Text::Long),
        Op::Skip(9),
        Op::Repeat(W2, &[
            Op::Choose(W2, &[
                (&[1, 3], &[Op::Text(Text::Long), Op::Skip(9)]),
                (&[2, 4], &[Op::Text(Text::Long), Op::Skip(8)]),
            ], &[]),
        ]),
    ]),
    Op::Skip(2),
    Op::Text(Text::Short),
    Op::Text(Text::Short),
    Op::Skip(1),
    Op::Text(Text::Short),
    Op::Text(Text::Short),
    Op::Repeat(W2, &[Op::Skip(2), Op::Text(Text::Short), Op::Text(Text::Short)]),
    Op::Loc,
    Op::Skip(5),
    Op::WhenBits(W1, 0x7f, &[
        Op::Skip(1),
        Op::Loc,
        Op::Loc,
        Op::Loc,
        Op::Text(Text::Long),
        Op::Skip(4),
        Op::Text(Text::Long),
        Op::Skip(4),
        Op::Text(Text::Long),
    ]),
    Op::Text(Text::Short),
    Op::Skip(4),
    Op::Text(Text::Short),
    Op::Text(Text::Short),
    Op::Text(Text::Short),
    Op::Skip(4),
    Op::Text(Text::Short),
    Op::Text(Text::Short),
    Op::Text(Text::Short),
    Op::Skip(4),
    Op::Text(Text::Short),
    Op::Text(Text::Short),
    Op::Skip(26),
    Op::When(W1, &[Op::Skip(9), Op::Text(Text::Long), Op::Skip(4), Op::Loc]),
    Op::Skip(3),
    Op::When(W1, &[
        Op::Choose(W1, &[
            (&[0], &[Op::Loc, Op::Text(Text::Long)]),
        ], &[Op::Text(Text::Long)]),
    ]),
    Op::When(W1, &[
        Op::Choose(W1, &[
            (&[0], &[Op::Loc, Op::Loc, Op::Text(Text::Long)]),
        ], &[Op::Text(Text::Long)]),
    ]),
    Op::When(W1, &[
        Op::Choose(W1, &[
            (&[0], &[Op::Loc, Op::Loc, Op::Text(Text::Long)]),
        ], &[Op::Loc, Op::Text(Text::Long)]),
    ]),
    Op::Choose(W1, &[
        (&[0], &[Op::Loc, Op::Loc]),
    ], &[]),
    Op::Text(Text::Long),
    Op::When(W1, &[
        Op::Choose(W1, &[
            (&[0], &[Op::Loc, Op::Loc, Op::Loc, Op::Loc]),
        ], &[Op::Loc]),
    ]),
    Op::When(W1, &[
        Op::Choose(W1, &[
            (&[0], &[Op::Loc, Op::Loc, Op::Text(Text::Long), Op::Text(Text::Long)]),
        ], &[Op::Text(Text::Long), Op::Text(Text::Long)]),
    ]),
    Op::When(W1, &[
        Op::Choose(W1, &[
            (&[0], &[
                Op::Loc,
                Op::Loc,
                Op::Loc,
                Op::Loc,
                Op::Loc,
                Op::Text(Text::Long),
                Op::Text(Text::Long),
                Op::Skip(4),
                Op::Text(Text::Long),
            ]),
        ], &[Op::Text(Text::Long), Op::Text(Text::Long), Op::Skip(4), Op::Text(Text::Long)]),
    ]),
    Op::When(W1, &[
        Op::Choose(W1, &[
            (&[0], &[Op::Loc, Op::Loc, Op::Text(Text::Long)]),
        ], &[Op::Text(Text::Long)]),
    ]),
    Op::Loc,
    Op::Loc,
    Op::When(W1, &[
        Op::Choose(W1, &[
            (&[0], &[
                Op::Loc,
                Op::Loc,
                Op::Loc,
                Op::Loc,
                Op::Loc,
                Op::Loc,
                Op::Loc,
                Op::Loc,
                Op::Text(Text::Long),
            ]),
        ], &[Op::Text(Text::Long)]),
    ]),
    Op::Choose(W1, &[
        (&[0], &[Op::Loc, Op::Loc]),
    ], &[]),
    Op::Text(Text::Long),
    Op::When(W1, &[
        Op::Choose(W1, &[
            (&[0], &[Op::Loc, Op::Loc, Op::Text(Text::Long), Op::Skip(1)]),
        ], &[Op::Text(Text::Long), Op::Skip(1)]),
    ]),
    Op::Loc,
    Op::When(W1, &[
        Op::Choose(W1, &[
            (&[0], &[Op::Loc, Op::Loc, Op::Text(Text::Long), Op::Skip(1)]),
        ], &[Op::Text(Text::Long), Op::Skip(1)]),
    ]),
    Op::When(W1, &[
        Op::Choose(W1, &[
            (&[0], &[Op::Loc, Op::Loc, Op::Text(Text::Long)]),
        ], &[Op::Loc, Op::Text(Text::Long)]),
    ]),
    Op::When(W1, &[
        Op::Choose(W1, &[
            (&[0], &[
                Op::Loc,
                Op::Loc,
                Op::Loc,
                Op::Loc,
                Op::Loc,
                Op::Loc,
                Op::Text(Text::Long),
                Op::Skip(1),
                Op::Text(Text::Long),
                Op::Text(Text::Long),
                Op::Skip(1),
                Op::Text(Text::Long),
                Op::Text(Text::Long),
                Op::Skip(1),
                Op::Text(Text::Long),
                Op::Text(Text::Long),
            ]),
        ], &[
            Op::Loc,
            Op::Loc,
            Op::Loc,
            Op::Text(Text::Long),
            Op::Skip(1),
            Op::Text(Text::Long),
            Op::Text(Text::Long),
            Op::Skip(1),
            Op::Text(Text::Long),
            Op::Text(Text::Long),
            Op::Skip(1),
            Op::Text(Text::Long),
            Op::Text(Text::Long),
        ]),
    ]),
    Op::When(W1, &[
        Op::Choose(W1, &[
            (&[0], &[Op::Loc, Op::Loc, Op::Loc, Op::Loc, Op::Loc, Op::Text(Text::Long), Op::Skip(1)]),
        ], &[Op::Text(Text::Long), Op::Skip(1)]),
    ]),
    Op::Repeat(W1, &[Op::Text(Text::Short), Op::Skip(12), Op::Block]),
    Op::Repeat(W2, &[Op::Loc, Op::Loc, Op::Skip(1), Op::Loc, Op::Skip(67)]),
];
static BUILT35071525_T29: &[Op] = &[
    Op::Skip(1),
    Op::Text(Text::Long),
    Op::Skip(2),
    Op::Text(Text::Long),
    Op::Text(Text::Long),
    Op::Skip(4),
    Op::Text(Text::Long),
    Op::Text(Text::Long),
    Op::Text(Text::Long),
    Op::Skip(6),
];
static BUILT35071525_START: &[Op] = &[
    Op::Skip(1),
    Op::When(W1, &[
        Op::Text(Text::Long),
        Op::Text(Text::Long),
        Op::Text(Text::Long),
        Op::Text(Text::Long),
        Op::Text(Text::Long),
        Op::Text(Text::Long),
        Op::Text(Text::Long),
        Op::Text(Text::Long),
        Op::Text(Text::Long),
        Op::Text(Text::Long),
        Op::Text(Text::Long),
        Op::Skip(9),
        Op::Repeat(W2, &[
            Op::Choose(W2, &[
                (&[1, 3], &[Op::Text(Text::Long), Op::Skip(9)]),
                (&[2, 4], &[Op::Text(Text::Long), Op::Skip(8)]),
            ], &[]),
        ]),
    ]),
    Op::Skip(2),
    Op::Text(Text::Short),
    Op::Text(Text::Short),
    Op::Skip(1),
    Op::Text(Text::Short),
    Op::Text(Text::Short),
    Op::Repeat(W2, &[Op::Skip(2), Op::Text(Text::Short), Op::Text(Text::Short)]),
    Op::Loc,
    Op::Skip(5),
    Op::WhenBits(W1, 0x3f, &[
        Op::Skip(1),
        Op::Loc,
        Op::Loc,
        Op::Loc,
        Op::Text(Text::Long),
        Op::Skip(4),
        Op::Text(Text::Long),
        Op::Skip(4),
        Op::Text(Text::Long),
    ]),
    Op::Text(Text::Short),
    Op::Skip(4),
    Op::Text(Text::Short),
    Op::Text(Text::Short),
    Op::Text(Text::Short),
    Op::Skip(4),
    Op::Text(Text::Short),
    Op::Text(Text::Short),
    Op::Text(Text::Short),
    Op::Skip(4),
    Op::Text(Text::Short),
    Op::Text(Text::Short),
    Op::Skip(26),
    Op::When(W1, &[Op::Skip(9), Op::Text(Text::Long), Op::Skip(4), Op::Loc]),
    Op::Skip(3),
    Op::When(W1, &[
        Op::Choose(W1, &[
            (&[0], &[Op::Loc, Op::Text(Text::Long)]),
        ], &[Op::Text(Text::Long)]),
    ]),
    Op::When(W1, &[
        Op::Choose(W1, &[
            (&[0], &[Op::Loc, Op::Loc, Op::Text(Text::Long)]),
        ], &[Op::Text(Text::Long)]),
    ]),
    Op::When(W1, &[
        Op::Choose(W1, &[
            (&[0], &[Op::Loc, Op::Loc, Op::Text(Text::Long)]),
        ], &[Op::Loc, Op::Text(Text::Long)]),
    ]),
    Op::Choose(W1, &[
        (&[0], &[Op::Loc, Op::Loc]),
    ], &[]),
    Op::Text(Text::Long),
    Op::When(W1, &[
        Op::Choose(W1, &[
            (&[0], &[Op::Loc, Op::Loc, Op::Loc, Op::Loc]),
        ], &[Op::Loc]),
    ]),
    Op::When(W1, &[
        Op::Choose(W1, &[
            (&[0], &[Op::Loc, Op::Loc, Op::Text(Text::Long), Op::Text(Text::Long)]),
        ], &[Op::Text(Text::Long), Op::Text(Text::Long)]),
    ]),
    Op::When(W1, &[
        Op::Choose(W1, &[
            (&[0], &[
                Op::Loc,
                Op::Loc,
                Op::Loc,
                Op::Loc,
                Op::Loc,
                Op::Text(Text::Long),
                Op::Text(Text::Long),
                Op::Skip(4),
                Op::Text(Text::Long),
            ]),
        ], &[Op::Text(Text::Long), Op::Text(Text::Long), Op::Skip(4), Op::Text(Text::Long)]),
    ]),
    Op::When(W1, &[
        Op::Choose(W1, &[
            (&[0], &[Op::Loc, Op::Loc, Op::Text(Text::Long)]),
        ], &[Op::Text(Text::Long)]),
    ]),
    Op::Loc,
    Op::Loc,
    Op::When(W1, &[
        Op::Choose(W1, &[
            (&[0], &[
                Op::Loc,
                Op::Loc,
                Op::Loc,
                Op::Loc,
                Op::Loc,
                Op::Loc,
                Op::Loc,
                Op::Loc,
                Op::Text(Text::Long),
            ]),
        ], &[Op::Text(Text::Long)]),
    ]),
    Op::Choose(W1, &[
        (&[0], &[Op::Loc, Op::Loc]),
    ], &[]),
    Op::Text(Text::Long),
    Op::When(W1, &[
        Op::Choose(W1, &[
            (&[0], &[Op::Loc, Op::Loc, Op::Text(Text::Long), Op::Skip(1)]),
        ], &[Op::Text(Text::Long), Op::Skip(1)]),
    ]),
    Op::Loc,
    Op::When(W1, &[
        Op::Choose(W1, &[
            (&[0], &[Op::Loc, Op::Loc, Op::Text(Text::Long), Op::Skip(1)]),
        ], &[Op::Text(Text::Long), Op::Skip(1)]),
    ]),
    Op::When(W1, &[
        Op::Choose(W1, &[
            (&[0], &[Op::Loc, Op::Loc, Op::Text(Text::Long)]),
        ], &[Op::Loc, Op::Text(Text::Long)]),
    ]),
    Op::When(W1, &[
        Op::Choose(W1, &[
            (&[0], &[
                Op::Loc,
                Op::Loc,
                Op::Loc,
                Op::Loc,
                Op::Loc,
                Op::Loc,
                Op::Text(Text::Long),
                Op::Skip(1),
                Op::Text(Text::Long),
                Op::Text(Text::Long),
                Op::Skip(1),
                Op::Text(Text::Long),
                Op::Text(Text::Long),
                Op::Skip(1),
                Op::Text(Text::Long),
                Op::Text(Text::Long),
            ]),
        ], &[
            Op::Loc,
            Op::Loc,
            Op::Loc,
            Op::Text(Text::Long),
            Op::Skip(1),
            Op::Text(Text::Long),
            Op::Text(Text::Long),
            Op::Skip(1),
            Op::Text(Text::Long),
            Op::Text(Text::Long),
            Op::Skip(1),
            Op::Text(Text::Long),
            Op::Text(Text::Long),
        ]),
    ]),
    Op::When(W1, &[
        Op::Choose(W1, &[
            (&[0], &[Op::Loc, Op::Loc, Op::Loc, Op::Loc, Op::Loc, Op::Text(Text::Long), Op::Skip(1)]),
        ], &[Op::Text(Text::Long), Op::Skip(1)]),
    ]),
    Op::Repeat(W1, &[Op::Text(Text::Short), Op::Skip(12), Op::Block]),
    Op::Repeat(W2, &[Op::Loc, Op::Loc, Op::Skip(1), Op::Loc, Op::Skip(67)]),
];
static V2_6_2_T06: &[Op] = &[
    Op::Skip(1),
    Op::Text(Text::Short),
    Op::Skip(18),
    Op::Text(Text::Short),
    Op::Skip(1),
    Op::Text(Text::Short),
    Op::Skip(1),
    Op::Loc,
    Op::Skip(1),
];
static V2_6_3_T16: &[Op] = &[
    Op::Skip(1),
    Op::Text(Text::Long),
    Op::Skip(1),
    Op::Text(Text::Long),
    Op::Skip(1),
    Op::Text(Text::Long),
    Op::Text(Text::Long),
    Op::Text(Text::Long),
];
static V2_6_3_T32: &[Op] = &[Op::Skip(4)];
static V2_6_3_START: &[Op] = &[
    Op::Skip(1),
    Op::When(W1, &[
        Op::Text(Text::Long),
        Op::Text(Text::Long),
        Op::Text(Text::Long),
        Op::Text(Text::Long),
        Op::Text(Text::Long),
        Op::Text(Text::Long),
        Op::Text(Text::Long),
        Op::Text(Text::Long),
        Op::Text(Text::Long),
        Op::Text(Text::Long),
        Op::Text(Text::Long),
        Op::Skip(9),
        Op::Repeat(W2, &[
            Op::Choose(W2, &[
                (&[1, 3], &[Op::Text(Text::Long), Op::Skip(9)]),
                (&[2, 4], &[Op::Text(Text::Long), Op::Skip(8)]),
            ], &[]),
        ]),
    ]),
    Op::Skip(2),
    Op::Text(Text::Short),
    Op::Text(Text::Short),
    Op::Skip(1),
    Op::Text(Text::Short),
    Op::Text(Text::Short),
    Op::Repeat(W2, &[Op::Skip(2), Op::Text(Text::Short), Op::Text(Text::Short)]),
    Op::Loc,
    Op::Skip(6),
    Op::WhenBits(W1, 0x3f, &[
        Op::Skip(1),
        Op::Loc,
        Op::Loc,
        Op::Loc,
        Op::Text(Text::Long),
        Op::Skip(4),
        Op::Text(Text::Long),
        Op::Skip(4),
        Op::Text(Text::Long),
    ]),
    Op::Text(Text::Short),
    Op::Skip(4),
    Op::Text(Text::Short),
    Op::Text(Text::Short),
    Op::Text(Text::Short),
    Op::Skip(4),
    Op::Text(Text::Short),
    Op::Text(Text::Short),
    Op::Text(Text::Short),
    Op::Skip(4),
    Op::Text(Text::Short),
    Op::Text(Text::Short),
    Op::Skip(26),
    Op::When(W1, &[Op::Skip(9), Op::Text(Text::Long), Op::Skip(4), Op::Loc]),
    Op::Skip(3),
    Op::When(W1, &[
        Op::Choose(W1, &[
            (&[0], &[Op::Loc, Op::Text(Text::Long)]),
        ], &[Op::Text(Text::Long)]),
    ]),
    Op::When(W1, &[
        Op::Choose(W1, &[
            (&[0], &[Op::Loc, Op::Loc, Op::Text(Text::Long)]),
        ], &[Op::Text(Text::Long)]),
    ]),
    Op::When(W1, &[
        Op::Choose(W1, &[
            (&[0], &[Op::Loc, Op::Loc, Op::Text(Text::Long)]),
        ], &[Op::Loc, Op::Text(Text::Long)]),
    ]),
    Op::Choose(W1, &[
        (&[0], &[Op::Loc, Op::Loc]),
    ], &[]),
    Op::Text(Text::Long),
    Op::When(W1, &[
        Op::Choose(W1, &[
            (&[0], &[Op::Loc, Op::Loc, Op::Loc, Op::Loc]),
        ], &[Op::Loc]),
    ]),
    Op::When(W1, &[
        Op::Choose(W1, &[
            (&[0], &[Op::Loc, Op::Loc, Op::Text(Text::Long), Op::Text(Text::Long)]),
        ], &[Op::Text(Text::Long), Op::Text(Text::Long)]),
    ]),
    Op::When(W1, &[
        Op::Choose(W1, &[
            (&[0], &[
                Op::Loc,
                Op::Loc,
                Op::Loc,
                Op::Loc,
                Op::Loc,
                Op::Text(Text::Long),
                Op::Text(Text::Long),
                Op::Skip(4),
                Op::Text(Text::Long),
            ]),
        ], &[Op::Text(Text::Long), Op::Text(Text::Long), Op::Skip(4), Op::Text(Text::Long)]),
    ]),
    Op::When(W1, &[
        Op::Choose(W1, &[
            (&[0], &[Op::Loc, Op::Loc, Op::Text(Text::Long)]),
        ], &[Op::Text(Text::Long)]),
    ]),
    Op::Loc,
    Op::Loc,
    Op::When(W1, &[
        Op::Choose(W1, &[
            (&[0], &[
                Op::Loc,
                Op::Loc,
                Op::Loc,
                Op::Loc,
                Op::Loc,
                Op::Loc,
                Op::Loc,
                Op::Loc,
                Op::Text(Text::Long),
            ]),
        ], &[Op::Text(Text::Long)]),
    ]),
    Op::Choose(W1, &[
        (&[0], &[Op::Loc, Op::Loc]),
    ], &[]),
    Op::Text(Text::Long),
    Op::When(W1, &[
        Op::Choose(W1, &[
            (&[0], &[Op::Loc, Op::Loc, Op::Text(Text::Long), Op::Skip(1)]),
        ], &[Op::Text(Text::Long), Op::Skip(1)]),
    ]),
    Op::Loc,
    Op::When(W1, &[
        Op::Choose(W1, &[
            (&[0], &[Op::Loc, Op::Loc, Op::Text(Text::Long), Op::Skip(1)]),
        ], &[Op::Text(Text::Long), Op::Skip(1)]),
    ]),
    Op::When(W1, &[
        Op::Choose(W1, &[
            (&[0], &[Op::Loc, Op::Loc, Op::Text(Text::Long)]),
        ], &[Op::Loc, Op::Text(Text::Long)]),
    ]),
    Op::When(W1, &[
        Op::Choose(W1, &[
            (&[0], &[
                Op::Loc,
                Op::Loc,
                Op::Loc,
                Op::Loc,
                Op::Loc,
                Op::Loc,
                Op::Text(Text::Long),
                Op::Skip(1),
                Op::Text(Text::Long),
                Op::Text(Text::Long),
                Op::Skip(1),
                Op::Text(Text::Long),
                Op::Text(Text::Long),
                Op::Skip(1),
                Op::Text(Text::Long),
                Op::Text(Text::Long),
            ]),
        ], &[
            Op::Loc,
            Op::Loc,
            Op::Loc,
            Op::Text(Text::Long),
            Op::Skip(1),
            Op::Text(Text::Long),
            Op::Text(Text::Long),
            Op::Skip(1),
            Op::Text(Text::Long),
            Op::Text(Text::Long),
            Op::Skip(1),
            Op::Text(Text::Long),
            Op::Text(Text::Long),
        ]),
    ]),
    Op::When(W1, &[
        Op::Choose(W1, &[
            (&[0], &[Op::Loc, Op::Loc, Op::Loc, Op::Loc, Op::Loc, Op::Text(Text::Long), Op::Skip(1)]),
        ], &[Op::Text(Text::Long), Op::Skip(1)]),
    ]),
    Op::Repeat(W1, &[Op::Text(Text::Short), Op::Skip(12), Op::Block]),
    Op::Repeat(W2, &[Op::Loc, Op::Loc, Op::Skip(1), Op::Loc, Op::Skip(67)]),
];
static V2_7_T02: &[Op] = &[
    Op::Loc,
    Op::Text(Text::Short),
    Op::Text(Text::Short),
    Op::Skip(53),
    Op::Text(Text::Short),
    Op::Skip(26),
    Op::Choose(W1, &[
        (&[4], &[Op::Text(Text::Long), Op::Skip(17)]),
    ], &[Op::Text(Text::Long), Op::Skip(1)]),
];
static V2_7_T06: &[Op] = &[
    Op::Skip(1),
    Op::Text(Text::Short),
    Op::Skip(18),
    Op::Text(Text::Short),
    Op::Skip(1),
    Op::Text(Text::Short),
    Op::Skip(1),
    Op::Loc,
    Op::Skip(3),
];
static V2_7_T21: &[Op] = &[
    Op::Text(Text::Short),
    Op::Text(Text::Short),
    Op::Skip(57),
    Op::Text(Text::Short),
    Op::Skip(2),
    Op::Choose(W1, &[
        (&[4], &[Op::Text(Text::Long), Op::Skip(16)]),
    ], &[Op::Text(Text::Long)]),
];
static V2_7_T29: &[Op] = &[
    Op::Skip(1),
    Op::Text(Text::Long),
    Op::Skip(2),
    Op::Text(Text::Long),
    Op::Text(Text::Long),
    Op::Skip(4),
    Op::Text(Text::Long),
    Op::Text(Text::Long),
    Op::Text(Text::Long),
    Op::Skip(6),
    Op::Text(Text::Long),
];
static V2_7_T34: &[Op] = &[Op::Loc, Op::Loc, Op::Loc, Op::Text(Text::Long), Op::Skip(2)];
static V2_7_START: &[Op] = &[
    Op::Skip(1),
    Op::When(W1, &[
        Op::Text(Text::Long),
        Op::Text(Text::Long),
        Op::Text(Text::Long),
        Op::Text(Text::Long),
        Op::Text(Text::Long),
        Op::Text(Text::Long),
        Op::Text(Text::Long),
        Op::Text(Text::Long),
        Op::Text(Text::Long),
        Op::Text(Text::Long),
        Op::Text(Text::Long),
        Op::Skip(9),
        Op::Repeat(W2, &[
            Op::Choose(W2, &[
                (&[1, 3], &[Op::Text(Text::Long), Op::Skip(9)]),
                (&[2, 4], &[Op::Text(Text::Long), Op::Skip(8)]),
            ], &[]),
        ]),
    ]),
    Op::Skip(2),
    Op::Text(Text::Short),
    Op::Text(Text::Short),
    Op::Skip(1),
    Op::Text(Text::Short),
    Op::Text(Text::Short),
    Op::Repeat(W2, &[Op::Skip(2), Op::Text(Text::Short), Op::Text(Text::Short)]),
    Op::Loc,
    Op::Skip(6),
    Op::WhenBits(W1, 0x3f, &[
        Op::Skip(1),
        Op::Loc,
        Op::Loc,
        Op::Loc,
        Op::Text(Text::Long),
        Op::Text(Text::Long),
        Op::Skip(4),
        Op::Text(Text::Long),
        Op::Skip(4),
        Op::Text(Text::Long),
        Op::Text(Text::Long),
        Op::Skip(1),
    ]),
    Op::Text(Text::Short),
    Op::Skip(4),
    Op::Text(Text::Short),
    Op::Text(Text::Short),
    Op::Text(Text::Short),
    Op::Skip(4),
    Op::Text(Text::Short),
    Op::Text(Text::Short),
    Op::Text(Text::Short),
    Op::Skip(4),
    Op::Text(Text::Short),
    Op::Text(Text::Short),
    Op::Skip(26),
    Op::When(W1, &[Op::Skip(9), Op::Text(Text::Long), Op::Skip(4), Op::Loc]),
    Op::Skip(3),
    Op::When(W1, &[
        Op::Choose(W1, &[
            (&[0], &[Op::Loc, Op::Text(Text::Long)]),
        ], &[Op::Text(Text::Long)]),
    ]),
    Op::When(W1, &[
        Op::Choose(W1, &[
            (&[0], &[Op::Loc, Op::Loc, Op::Text(Text::Long)]),
        ], &[Op::Text(Text::Long)]),
    ]),
    Op::When(W1, &[
        Op::Choose(W1, &[
            (&[0], &[Op::Loc, Op::Loc, Op::Text(Text::Long)]),
        ], &[Op::Loc, Op::Text(Text::Long)]),
    ]),
    Op::Choose(W1, &[
        (&[0], &[Op::Loc, Op::Loc]),
    ], &[]),
    Op::Text(Text::Long),
    Op::When(W1, &[
        Op::Choose(W1, &[
            (&[0], &[Op::Loc, Op::Loc, Op::Loc, Op::Loc]),
        ], &[Op::Loc]),
    ]),
    Op::When(W1, &[
        Op::Choose(W1, &[
            (&[0], &[Op::Loc, Op::Loc, Op::Text(Text::Long), Op::Text(Text::Long)]),
        ], &[Op::Text(Text::Long), Op::Text(Text::Long)]),
    ]),
    Op::When(W1, &[
        Op::Choose(W1, &[
            (&[0], &[
                Op::Loc,
                Op::Loc,
                Op::Loc,
                Op::Loc,
                Op::Loc,
                Op::Text(Text::Long),
                Op::Text(Text::Long),
                Op::Skip(4),
                Op::Text(Text::Long),
            ]),
        ], &[Op::Text(Text::Long), Op::Text(Text::Long), Op::Skip(4), Op::Text(Text::Long)]),
    ]),
    Op::When(W1, &[
        Op::Choose(W1, &[
            (&[0], &[Op::Loc, Op::Loc, Op::Text(Text::Long)]),
        ], &[Op::Text(Text::Long)]),
    ]),
    Op::Loc,
    Op::Loc,
    Op::When(W1, &[
        Op::Choose(W1, &[
            (&[0], &[
                Op::Loc,
                Op::Loc,
                Op::Loc,
                Op::Loc,
                Op::Loc,
                Op::Loc,
                Op::Loc,
                Op::Loc,
                Op::Text(Text::Long),
            ]),
        ], &[Op::Text(Text::Long)]),
    ]),
    Op::Choose(W1, &[
        (&[0], &[Op::Loc, Op::Loc]),
    ], &[]),
    Op::Text(Text::Long),
    Op::When(W1, &[
        Op::Choose(W1, &[
            (&[0], &[Op::Loc, Op::Loc, Op::Text(Text::Long), Op::Skip(1)]),
        ], &[Op::Text(Text::Long), Op::Skip(1)]),
    ]),
    Op::Loc,
    Op::When(W1, &[
        Op::Choose(W1, &[
            (&[0], &[Op::Loc, Op::Loc, Op::Text(Text::Long), Op::Skip(1)]),
        ], &[Op::Text(Text::Long), Op::Skip(1)]),
    ]),
    Op::When(W1, &[
        Op::Choose(W1, &[
            (&[0], &[Op::Loc, Op::Loc, Op::Text(Text::Long)]),
        ], &[Op::Loc, Op::Text(Text::Long)]),
    ]),
    Op::When(W1, &[
        Op::Choose(W1, &[
            (&[0], &[
                Op::Loc,
                Op::Loc,
                Op::Loc,
                Op::Loc,
                Op::Loc,
                Op::Loc,
                Op::Text(Text::Long),
                Op::Skip(1),
                Op::Text(Text::Long),
                Op::Text(Text::Long),
                Op::Skip(1),
                Op::Text(Text::Long),
                Op::Text(Text::Long),
                Op::Skip(1),
                Op::Text(Text::Long),
                Op::Text(Text::Long),
            ]),
        ], &[
            Op::Loc,
            Op::Loc,
            Op::Loc,
            Op::Text(Text::Long),
            Op::Skip(1),
            Op::Text(Text::Long),
            Op::Text(Text::Long),
            Op::Skip(1),
            Op::Text(Text::Long),
            Op::Text(Text::Long),
            Op::Skip(1),
            Op::Text(Text::Long),
            Op::Text(Text::Long),
        ]),
    ]),
    Op::When(W1, &[
        Op::Choose(W1, &[
            (&[0], &[Op::Loc, Op::Loc, Op::Loc, Op::Loc, Op::Loc, Op::Text(Text::Long), Op::Skip(1)]),
        ], &[Op::Text(Text::Long), Op::Skip(1)]),
    ]),
    Op::Repeat(W4, &[Op::Skip(16), Op::Text(Text::Long), Op::Text(Text::Long)]),
    Op::Repeat(W4, &[
        Op::Skip(16),
        Op::Text(Text::Long),
        Op::Text(Text::Long),
        Op::Text(Text::Long),
        Op::Text(Text::Long),
        Op::Text(Text::Long),
        Op::Skip(1),
    ]),
    Op::Repeat(W1, &[Op::Text(Text::Short), Op::Skip(12), Op::Block]),
    Op::Repeat(W2, &[Op::Loc, Op::Loc, Op::Skip(1), Op::Loc, Op::Skip(67), Op::Repeat(W2, &[Op::Skip(5)])]),
];
static V2_7_1_HEADER: &[Op] = &[
    Op::Skip(19),
    Op::Repeat(W2, &[Op::Skip(5)]),
    Op::Skip(1),
    Op::Repeat(W2, &[Op::Text(Text::Short), Op::Skip(4), Op::Text(Text::Short), Op::Text(Text::Short)]),
    Op::Repeat(W2, &[Op::Text(Text::Short), Op::Skip(4), Op::Text(Text::Short), Op::Text(Text::Short)]),
    Op::Skip(64),
];
static V2_7_1_START: &[Op] = &[
    Op::Skip(1),
    Op::When(W1, &[
        Op::Text(Text::Long),
        Op::Text(Text::Long),
        Op::Text(Text::Long),
        Op::Text(Text::Long),
        Op::Text(Text::Long),
        Op::Text(Text::Long),
        Op::Text(Text::Long),
        Op::Text(Text::Long),
        Op::Text(Text::Long),
        Op::Text(Text::Long),
        Op::Text(Text::Long),
        Op::Skip(9),
        Op::Repeat(W2, &[
            Op::Choose(W2, &[
                (&[1, 3], &[Op::Text(Text::Long), Op::Skip(9)]),
                (&[2, 4], &[Op::Text(Text::Long), Op::Skip(8)]),
            ], &[]),
        ]),
    ]),
    Op::Skip(2),
    Op::Text(Text::Short),
    Op::Text(Text::Short),
    Op::Skip(1),
    Op::Text(Text::Short),
    Op::Text(Text::Short),
    Op::Repeat(W2, &[Op::Skip(2), Op::Text(Text::Short), Op::Text(Text::Short)]),
    Op::Loc,
    Op::Skip(6),
    Op::WhenBits(W1, 0x3f, &[
        Op::Skip(1),
        Op::Loc,
        Op::Loc,
        Op::Loc,
        Op::Text(Text::Long),
        Op::Text(Text::Long),
        Op::Skip(4),
        Op::Text(Text::Long),
        Op::Skip(4),
        Op::Text(Text::Long),
        Op::Text(Text::Long),
        Op::Skip(1),
    ]),
    Op::Text(Text::Short),
    Op::Skip(4),
    Op::Text(Text::Short),
    Op::Text(Text::Short),
    Op::Text(Text::Short),
    Op::Skip(4),
    Op::Text(Text::Short),
    Op::Text(Text::Short),
    Op::Text(Text::Short),
    Op::Skip(4),
    Op::Text(Text::Short),
    Op::Text(Text::Short),
    Op::Skip(26),
    Op::When(W1, &[Op::Skip(9), Op::Text(Text::Long), Op::Skip(4), Op::Loc]),
    Op::Skip(3),
    Op::When(W1, &[
        Op::Choose(W1, &[
            (&[0], &[Op::Loc, Op::Text(Text::Long)]),
        ], &[Op::Text(Text::Long)]),
    ]),
    Op::When(W1, &[
        Op::Choose(W1, &[
            (&[0], &[Op::Loc, Op::Loc, Op::Text(Text::Long)]),
        ], &[Op::Text(Text::Long)]),
    ]),
    Op::When(W1, &[
        Op::Choose(W1, &[
            (&[0], &[Op::Loc, Op::Loc, Op::Text(Text::Long)]),
        ], &[Op::Loc, Op::Text(Text::Long)]),
    ]),
    Op::Choose(W1, &[
        (&[0], &[Op::Loc, Op::Loc]),
    ], &[]),
    Op::Text(Text::Long),
    Op::When(W1, &[
        Op::Choose(W1, &[
            (&[0], &[Op::Loc, Op::Loc, Op::Loc, Op::Loc]),
        ], &[Op::Loc]),
    ]),
    Op::When(W1, &[
        Op::Choose(W1, &[
            (&[0], &[Op::Loc, Op::Loc, Op::Text(Text::Long), Op::Text(Text::Long)]),
        ], &[Op::Text(Text::Long), Op::Text(Text::Long)]),
    ]),
    Op::When(W1, &[
        Op::Choose(W1, &[
            (&[0], &[
                Op::Loc,
                Op::Loc,
                Op::Loc,
                Op::Loc,
                Op::Loc,
                Op::Text(Text::Long),
                Op::Text(Text::Long),
                Op::Skip(4),
                Op::Text(Text::Long),
            ]),
        ], &[Op::Text(Text::Long), Op::Text(Text::Long), Op::Skip(4), Op::Text(Text::Long)]),
    ]),
    Op::When(W1, &[
        Op::Choose(W1, &[
            (&[0], &[Op::Loc, Op::Loc, Op::Text(Text::Long)]),
        ], &[Op::Text(Text::Long)]),
    ]),
    Op::Loc,
    Op::Loc,
    Op::When(W1, &[
        Op::Choose(W1, &[
            (&[0], &[
                Op::Loc,
                Op::Loc,
                Op::Loc,
                Op::Loc,
                Op::Loc,
                Op::Loc,
                Op::Loc,
                Op::Loc,
                Op::Text(Text::Long),
            ]),
        ], &[Op::Text(Text::Long)]),
    ]),
    Op::Choose(W1, &[
        (&[0], &[Op::Loc, Op::Loc]),
    ], &[]),
    Op::Text(Text::Long),
    Op::When(W1, &[
        Op::Choose(W1, &[
            (&[0], &[Op::Loc, Op::Loc, Op::Text(Text::Long), Op::Skip(1)]),
        ], &[Op::Text(Text::Long), Op::Skip(1)]),
    ]),
    Op::Loc,
    Op::When(W1, &[
        Op::Choose(W1, &[
            (&[0], &[Op::Loc, Op::Loc, Op::Text(Text::Long), Op::Skip(1)]),
        ], &[Op::Text(Text::Long), Op::Skip(1)]),
    ]),
    Op::When(W1, &[
        Op::Choose(W1, &[
            (&[0], &[Op::Loc, Op::Loc, Op::Text(Text::Long)]),
        ], &[Op::Loc, Op::Text(Text::Long)]),
    ]),
    Op::When(W1, &[
        Op::Choose(W1, &[
            (&[0], &[
                Op::Loc,
                Op::Loc,
                Op::Loc,
                Op::Loc,
                Op::Loc,
                Op::Loc,
                Op::Text(Text::Long),
                Op::Skip(1),
                Op::Text(Text::Long),
                Op::Text(Text::Long),
                Op::Skip(1),
                Op::Text(Text::Long),
                Op::Text(Text::Long),
                Op::Skip(1),
                Op::Text(Text::Long),
                Op::Text(Text::Long),
            ]),
        ], &[
            Op::Loc,
            Op::Loc,
            Op::Loc,
            Op::Text(Text::Long),
            Op::Skip(1),
            Op::Text(Text::Long),
            Op::Text(Text::Long),
            Op::Skip(1),
            Op::Text(Text::Long),
            Op::Text(Text::Long),
            Op::Skip(1),
            Op::Text(Text::Long),
            Op::Text(Text::Long),
        ]),
    ]),
    Op::When(W1, &[
        Op::Choose(W1, &[
            (&[0], &[Op::Loc, Op::Loc, Op::Loc, Op::Loc, Op::Loc, Op::Text(Text::Long), Op::Skip(1)]),
        ], &[Op::Text(Text::Long), Op::Skip(1)]),
    ]),
    Op::Repeat(W4, &[Op::Skip(16), Op::Text(Text::Long), Op::Text(Text::Long)]),
    Op::Repeat(W4, &[
        Op::Skip(16),
        Op::Text(Text::Long),
        Op::Text(Text::Long),
        Op::Text(Text::Long),
        Op::Text(Text::Long),
        Op::Text(Text::Long),
        Op::Skip(1),
    ]),
    Op::Repeat(W1, &[Op::Text(Text::Short), Op::Skip(12), Op::Block]),
    Op::Repeat(W2, &[
        Op::Loc,
        Op::Loc,
        Op::Skip(1),
        Op::Loc,
        Op::Skip(67),
        Op::Repeat(W2, &[Op::Skip(5)]),
        Op::Skip(1),
    ]),
];
static BUILT36101749_HEADER: &[Op] = &[
    Op::Skip(19),
    Op::Repeat(W2, &[Op::Skip(5)]),
    Op::Skip(1),
    Op::Repeat(W2, &[Op::Text(Text::Long), Op::Skip(4), Op::Text(Text::Long), Op::Text(Text::Long)]),
    Op::Repeat(W2, &[Op::Text(Text::Long), Op::Skip(4), Op::Text(Text::Long), Op::Text(Text::Long)]),
    Op::Skip(65),
];
static BUILT36101749_T01: &[Op] = &[
    Op::Loc,
    Op::Text(Text::Long),
    Op::Text(Text::Long),
    Op::Skip(9),
    Op::Text(Text::Long),
    Op::Skip(3),
    Op::Text(Text::Long),
    Op::Skip(4),
];
static BUILT36101749_T02: &[Op] = &[
    Op::Loc,
    Op::Text(Text::Long),
    Op::Text(Text::Long),
    Op::Skip(53),
    Op::Text(Text::Long),
    Op::Skip(26),
    Op::Choose(W1, &[
        (&[4], &[Op::Text(Text::Long), Op::Skip(17)]),
    ], &[Op::Text(Text::Long), Op::Skip(1)]),
    Op::Skip(5),
];
static BUILT36101749_T03: &[Op] = &[
    Op::Loc,
    Op::Text(Text::Long),
    Op::Text(Text::Long),
    Op::Text(Text::Long),
    Op::Text(Text::Long),
    Op::Skip(2),
    Op::Loc,
    Op::Skip(5),
];
static BUILT36101749_T04: &[Op] = &[
    Op::Skip(1),
    Op::Text(Text::Long),
    Op::Text(Text::Long),
    Op::Text(Text::Long),
    Op::Text(Text::Long),
    Op::Text(Text::Long),
    Op::Text(Text::Long),
    Op::Skip(1),
];
static BUILT36101749_T05: &[Op] = &[
    Op::Skip(1),
    Op::Text(Text::Long),
    Op::Skip(1),
    Op::Text(Text::Long),
    Op::Text(Text::Long),
    Op::Text(Text::Long),
    Op::Skip(1),
    Op::Text(Text::Long),
    Op::Skip(1),
];
static BUILT36101749_T06: &[Op] = &[
    Op::Skip(1),
    Op::Text(Text::Long),
    Op::Skip(18),
    Op::Text(Text::Long),
    Op::Skip(1),
    Op::Text(Text::Long),
    Op::Skip(1),
    Op::Loc,
    Op::Skip(3),
];
static BUILT36101749_T07: &[Op] = &[Op::Skip(1), Op::Text(Text::Long), Op::Skip(18), Op::Text(Text::Long), Op::Skip(1)];
static BUILT36101749_T08: &[Op] = &[Op::Skip(1), Op::Text(Text::Long), Op::Skip(18), Op::Text(Text::Long), Op::Skip(2)];
static BUILT36101749_T10: &[Op] = &[Op::Text(Text::Long), Op::Text(Text::Long), Op::Skip(2)];
static BUILT36101749_T11: &[Op] = &[
    Op::Loc,
    Op::Text(Text::Long),
    Op::Text(Text::Long),
    Op::Text(Text::Long),
    Op::Text(Text::Long),
    Op::Skip(10),
    Op::Text(Text::Long),
];
static BUILT36101749_T13: &[Op] = &[Op::Skip(1)];
static BUILT36101749_T14: &[Op] = &[Op::Text(Text::Long), Op::Skip(4), Op::Text(Text::Long), Op::Text(Text::Long)];
static BUILT36101749_T15: &[Op] = &[Op::Text(Text::Long), Op::Skip(12)];
static BUILT36101749_T17: &[Op] = &[Op::Text(Text::Long), Op::Text(Text::Long), Op::Skip(4)];
static BUILT36101749_T18: &[Op] = &[Op::Text(Text::Long), Op::Skip(1), Op::Text(Text::Long), Op::Text(Text::Long), Op::Skip(1)];
static BUILT36101749_T19: &[Op] = &[Op::Text(Text::Long), Op::Skip(2)];
static BUILT36101749_T21: &[Op] = &[
    Op::Text(Text::Long),
    Op::Text(Text::Long),
    Op::Skip(57),
    Op::Text(Text::Long),
    Op::Skip(2),
    Op::Choose(W1, &[
        (&[4], &[Op::Text(Text::Long), Op::Skip(16)]),
    ], &[Op::Text(Text::Long)]),
];
static BUILT36101749_T24: &[Op] = &[
    Op::Skip(1),
    Op::Text(Text::Long),
    Op::Skip(1),
    Op::Text(Text::Long),
    Op::Text(Text::Long),
    Op::Skip(2),
];
static BUILT36101749_T25: &[Op] = &[Op::Skip(2), Op::Text(Text::Long), Op::Text(Text::Long), Op::Skip(2)];
static BUILT36101749_T26: &[Op] = &[Op::Text(Text::Long)];
static BUILT36101749_T27: &[Op] = &[
    Op::Text(Text::Long),
    Op::Text(Text::Long),
    Op::Text(Text::Long),
    Op::Skip(1),
    Op::Text(Text::Long),
    Op::Skip(2),
];
static BUILT36101749_T35: &[Op] = &[
    Op::Text(Text::Long),
    Op::Text(Text::Long),
    Op::Text(Text::Long),
    Op::Text(Text::Long),
    Op::Text(Text::Long),
    Op::Skip(1),
    Op::Text(Text::Long),
];
static BUILT36101749_START: &[Op] = &[
    Op::Skip(1),
    Op::When(W1, &[
        Op::Text(Text::Long),
        Op::Text(Text::Long),
        Op::Text(Text::Long),
        Op::Text(Text::Long),
        Op::Text(Text::Long),
        Op::Text(Text::Long),
        Op::Text(Text::Long),
        Op::Text(Text::Long),
        Op::Text(Text::Long),
        Op::Text(Text::Long),
        Op::Text(Text::Long),
        Op::Skip(9),
        Op::Repeat(W2, &[
            Op::Choose(W2, &[
                (&[1, 3], &[Op::Text(Text::Long), Op::Skip(9)]),
                (&[2, 4], &[Op::Text(Text::Long), Op::Skip(8)]),
            ], &[]),
        ]),
    ]),
    Op::Skip(2),
    Op::Text(Text::Long),
    Op::Text(Text::Long),
    Op::Skip(2),
    Op::Text(Text::Long),
    Op::Text(Text::Long),
    Op::Repeat(W2, &[Op::Skip(2), Op::Text(Text::Long), Op::Text(Text::Long)]),
    Op::Loc,
    Op::Skip(7),
    Op::WhenBits(W1, 0x3f, &[
        Op::Skip(1),
        Op::Loc,
        Op::Loc,
        Op::Loc,
        Op::Text(Text::Long),
        Op::Text(Text::Long),
        Op::Skip(4),
        Op::Text(Text::Long),
        Op::Skip(4),
        Op::Text(Text::Long),
        Op::Text(Text::Long),
        Op::Skip(1),
    ]),
    Op::Text(Text::Long),
    Op::Skip(4),
    Op::Text(Text::Long),
    Op::Text(Text::Long),
    Op::Text(Text::Long),
    Op::Skip(4),
    Op::Text(Text::Long),
    Op::Text(Text::Long),
    Op::Text(Text::Long),
    Op::Skip(4),
    Op::Text(Text::Long),
    Op::Text(Text::Long),
    Op::Skip(26),
    Op::When(W1, &[Op::Skip(9), Op::Text(Text::Long), Op::Skip(4), Op::Loc]),
    Op::Skip(3),
    Op::Choose(W1, &[
        (&[0], &[
            Op::TextThen(Text::Long, &[], &[
                Op::Choose(W1, &[
                    (&[0], &[Op::Loc, Op::Text(Text::Long)]),
                ], &[Op::Text(Text::Long)]),
            ]),
        ]),
    ], &[
        Op::Text(Text::Long),
        Op::Choose(W1, &[
            (&[0], &[Op::Loc, Op::Text(Text::Long)]),
        ], &[Op::Text(Text::Long)]),
    ]),
    Op::Choose(W1, &[
        (&[0], &[
            Op::TextThen(Text::Long, &[], &[
                Op::Choose(W1, &[
                    (&[0], &[Op::Loc, Op::Loc, Op::Text(Text::Long)]),
                ], &[Op::Text(Text::Long)]),
            ]),
        ]),
    ], &[
        Op::Text(Text::Long),
        Op::Choose(W1, &[
            (&[0], &[Op::Loc, Op::Loc, Op::Text(Text::Long)]),
        ], &[Op::Text(Text::Long)]),
    ]),
    Op::Choose(W1, &[
        (&[0], &[
            Op::TextThen(Text::Long, &[], &[
                Op::Choose(W1, &[
                    (&[0], &[Op::Loc, Op::Loc, Op::Text(Text::Long)]),
                ], &[Op::Loc, Op::Text(Text::Long)]),
            ]),
        ]),
    ], &[
        Op::Text(Text::Long),
        Op::Choose(W1, &[
            (&[0], &[Op::Loc, Op::Loc, Op::Text(Text::Long)]),
        ], &[Op::Loc, Op::Text(Text::Long)]),
    ]),
    Op::Text(Text::Long),
    Op::Choose(W1, &[
        (&[0], &[Op::Loc, Op::Loc]),
    ], &[]),
    Op::Text(Text::Long),
    Op::Choose(W1, &[
        (&[0], &[
            Op::TextThen(Text::Long, &[], &[
                Op::Choose(W1, &[
                    (&[0], &[Op::Loc, Op::Loc, Op::Loc, Op::Loc]),
                ], &[Op::Loc]),
            ]),
        ]),
    ], &[
        Op::Text(Text::Long),
        Op::Choose(W1, &[
            (&[0], &[Op::Loc, Op::Loc, Op::Loc, Op::Loc]),
        ], &[Op::Loc]),
    ]),
    Op::Choose(W1, &[
        (&[0], &[
            Op::TextThen(Text::Long, &[], &[
                Op::Choose(W1, &[
                    (&[0], &[Op::Loc, Op::Loc, Op::Text(Text::Long), Op::Text(Text::Long)]),
                ], &[Op::Text(Text::Long), Op::Text(Text::Long)]),
            ]),
        ]),
    ], &[
        Op::Text(Text::Long),
        Op::Choose(W1, &[
            (&[0], &[Op::Loc, Op::Loc, Op::Text(Text::Long), Op::Text(Text::Long)]),
        ], &[Op::Text(Text::Long), Op::Text(Text::Long)]),
    ]),
    Op::Choose(W1, &[
        (&[0], &[
            Op::TextThen(Text::Long, &[], &[
                Op::Choose(W1, &[
                    (&[0], &[
                        Op::Loc,
                        Op::Loc,
                        Op::Loc,
                        Op::Loc,
                        Op::Loc,
                        Op::Text(Text::Long),
                        Op::Choose(W1, &[
                            (&[1], &[Op::Text(Text::Long), Op::Skip(3)]),
                            (&[2], &[Op::Text(Text::Long), Op::Skip(4), Op::Text(Text::Long), Op::Skip(3)]),
                        ], &[Op::Skip(3)]),
                    ]),
                ], &[
                    Op::Text(Text::Long),
                    Op::Choose(W1, &[
                        (&[1], &[Op::Text(Text::Long), Op::Skip(3)]),
                        (&[2], &[Op::Text(Text::Long), Op::Skip(4), Op::Text(Text::Long), Op::Skip(3)]),
                    ], &[Op::Skip(3)]),
                ]),
            ]),
        ]),
    ], &[
        Op::Text(Text::Long),
        Op::Choose(W1, &[
            (&[0], &[
                Op::Loc,
                Op::Loc,
                Op::Loc,
                Op::Loc,
                Op::Loc,
                Op::Text(Text::Long),
                Op::Choose(W1, &[
                    (&[1], &[Op::Text(Text::Long), Op::Skip(3)]),
                    (&[2], &[Op::Text(Text::Long), Op::Skip(4), Op::Text(Text::Long), Op::Skip(3)]),
                ], &[Op::Skip(3)]),
            ]),
        ], &[
            Op::Text(Text::Long),
            Op::Choose(W1, &[
                (&[1], &[Op::Text(Text::Long), Op::Skip(3)]),
                (&[2], &[Op::Text(Text::Long), Op::Skip(4), Op::Text(Text::Long), Op::Skip(3)]),
            ], &[Op::Skip(3)]),
        ]),
    ]),
    Op::Choose(W1, &[
        (&[0], &[
            Op::TextThen(Text::Long, &[], &[
                Op::Choose(W1, &[
                    (&[0], &[Op::Loc, Op::Loc, Op::Text(Text::Long)]),
                ], &[Op::Text(Text::Long)]),
            ]),
        ]),
    ], &[
        Op::Text(Text::Long),
        Op::Choose(W1, &[
            (&[0], &[Op::Loc, Op::Loc, Op::Text(Text::Long)]),
        ], &[Op::Text(Text::Long)]),
    ]),
    Op::Loc,
    Op::Loc,
    Op::Choose(W1, &[
        (&[0], &[
            Op::TextThen(Text::Long, &[], &[
                Op::Choose(W1, &[
                    (&[0], &[
                        Op::Loc,
                        Op::Loc,
                        Op::Loc,
                        Op::Loc,
                        Op::Loc,
                        Op::Loc,
                        Op::Loc,
                        Op::Loc,
                        Op::Text(Text::Long),
                    ]),
                ], &[Op::Text(Text::Long)]),
            ]),
        ]),
    ], &[
        Op::Text(Text::Long),
        Op::Choose(W1, &[
            (&[0], &[
                Op::Loc,
                Op::Loc,
                Op::Loc,
                Op::Loc,
                Op::Loc,
                Op::Loc,
                Op::Loc,
                Op::Loc,
                Op::Text(Text::Long),
            ]),
        ], &[Op::Text(Text::Long)]),
    ]),
    Op::Text(Text::Long),
    Op::Choose(W1, &[
        (&[0], &[Op::Loc, Op::Loc]),
    ], &[]),
    Op::Text(Text::Long),
    Op::Choose(W1, &[
        (&[0], &[
            Op::TextThen(Text::Long, &[], &[
                Op::Choose(W1, &[
                    (&[0], &[Op::Loc, Op::Loc, Op::Text(Text::Long), Op::Skip(1)]),
                ], &[Op::Text(Text::Long), Op::Skip(1)]),
            ]),
        ]),
    ], &[
        Op::Text(Text::Long),
        Op::Choose(W1, &[
            (&[0], &[Op::Loc, Op::Loc, Op::Text(Text::Long), Op::Skip(1)]),
        ], &[Op::Text(Text::Long), Op::Skip(1)]),
    ]),
    Op::Loc,
    Op::Choose(W1, &[
        (&[0], &[
            Op::TextThen(Text::Long, &[], &[
                Op::Choose(W1, &[
                    (&[0], &[Op::Loc, Op::Loc, Op::Text(Text::Long), Op::Skip(1)]),
                ], &[Op::Text(Text::Long), Op::Skip(1)]),
            ]),
        ]),
    ], &[
        Op::Text(Text::Long),
        Op::Choose(W1, &[
            (&[0], &[Op::Loc, Op::Loc, Op::Text(Text::Long), Op::Skip(1)]),
        ], &[Op::Text(Text::Long), Op::Skip(1)]),
    ]),
    Op::Choose(W1, &[
        (&[0], &[
            Op::TextThen(Text::Long, &[], &[
                Op::Choose(W1, &[
                    (&[0], &[Op::Loc, Op::Loc, Op::Text(Text::Long)]),
                ], &[Op::Loc, Op::Text(Text::Long)]),
            ]),
        ]),
    ], &[
        Op::Text(Text::Long),
        Op::Choose(W1, &[
            (&[0], &[Op::Loc, Op::Loc, Op::Text(Text::Long)]),
        ], &[Op::Loc, Op::Text(Text::Long)]),
    ]),
    Op::Choose(W1, &[
        (&[0], &[
            Op::TextThen(Text::Long, &[], &[
                Op::Choose(W1, &[
                    (&[0], &[
                        Op::Loc,
                        Op::Loc,
                        Op::Loc,
                        Op::Loc,
                        Op::Loc,
                        Op::Loc,
                        Op::Text(Text::Long),
                        Op::Skip(1),
                        Op::Text(Text::Long),
                        Op::Text(Text::Long),
                        Op::Skip(1),
                        Op::Text(Text::Long),
                        Op::Text(Text::Long),
                        Op::Skip(1),
                        Op::Text(Text::Long),
                        Op::Text(Text::Long),
                    ]),
                ], &[
                    Op::Loc,
                    Op::Loc,
                    Op::Loc,
                    Op::Text(Text::Long),
                    Op::Skip(1),
                    Op::Text(Text::Long),
                    Op::Text(Text::Long),
                    Op::Skip(1),
                    Op::Text(Text::Long),
                    Op::Text(Text::Long),
                    Op::Skip(1),
                    Op::Text(Text::Long),
                    Op::Text(Text::Long),
                ]),
            ]),
        ]),
    ], &[
        Op::Text(Text::Long),
        Op::Choose(W1, &[
            (&[0], &[
                Op::Loc,
                Op::Loc,
                Op::Loc,
                Op::Loc,
                Op::Loc,
                Op::Loc,
                Op::Text(Text::Long),
                Op::Skip(1),
                Op::Text(Text::Long),
                Op::Text(Text::Long),
                Op::Skip(1),
                Op::Text(Text::Long),
                Op::Text(Text::Long),
                Op::Skip(1),
                Op::Text(Text::Long),
                Op::Text(Text::Long),
            ]),
        ], &[
            Op::Loc,
            Op::Loc,
            Op::Loc,
            Op::Text(Text::Long),
            Op::Skip(1),
            Op::Text(Text::Long),
            Op::Text(Text::Long),
            Op::Skip(1),
            Op::Text(Text::Long),
            Op::Text(Text::Long),
            Op::Skip(1),
            Op::Text(Text::Long),
            Op::Text(Text::Long),
        ]),
    ]),
    Op::Choose(W1, &[
        (&[0], &[
            Op::TextThen(Text::Long, &[], &[
                Op::Choose(W1, &[
                    (&[0], &[
                        Op::Loc,
                        Op::Loc,
                        Op::Loc,
                        Op::Loc,
                        Op::Loc,
                        Op::Text(Text::Long),
                        Op::Skip(1),
                    ]),
                ], &[Op::Text(Text::Long), Op::Skip(1)]),
            ]),
        ]),
    ], &[
        Op::Text(Text::Long),
        Op::Choose(W1, &[
            (&[0], &[Op::Loc, Op::Loc, Op::Loc, Op::Loc, Op::Loc, Op::Text(Text::Long), Op::Skip(1)]),
        ], &[Op::Text(Text::Long), Op::Skip(1)]),
    ]),
    Op::Repeat(W4, &[Op::Skip(16), Op::Text(Text::Long), Op::Text(Text::Long)]),
    Op::Repeat(W4, &[
        Op::Skip(16),
        Op::Text(Text::Long),
        Op::Text(Text::Long),
        Op::Text(Text::Long),
        Op::Text(Text::Long),
        Op::Text(Text::Long),
        Op::Skip(1),
    ]),
    Op::Repeat(W1, &[Op::Text(Text::Short), Op::Skip(12), Op::Block]),
    Op::Repeat(W2, &[
        Op::Loc,
        Op::Loc,
        Op::Skip(1),
        Op::Loc,
        Op::Skip(68),
        Op::Repeat(W2, &[Op::Skip(5)]),
        Op::Skip(1),
    ]),
];
static V2_8_START: &[Op] = &[
    Op::Skip(1),
    Op::When(W1, &[
        Op::Text(Text::Long),
        Op::Text(Text::Long),
        Op::Text(Text::Long),
        Op::Text(Text::Long),
        Op::Text(Text::Long),
        Op::Text(Text::Long),
        Op::Text(Text::Long),
        Op::Text(Text::Long),
        Op::Text(Text::Long),
        Op::Text(Text::Long),
        Op::Text(Text::Long),
        Op::Skip(9),
        Op::Repeat(W2, &[
            Op::Choose(W2, &[
                (&[1, 3], &[Op::Text(Text::Long), Op::Skip(9)]),
                (&[2, 4], &[Op::Text(Text::Long), Op::Skip(8)]),
            ], &[]),
        ]),
    ]),
    Op::Skip(2),
    Op::Text(Text::Long),
    Op::Text(Text::Long),
    Op::Skip(2),
    Op::Text(Text::Long),
    Op::Text(Text::Long),
    Op::Repeat(W2, &[Op::Skip(2), Op::Text(Text::Long), Op::Text(Text::Long)]),
    Op::Block,
    Op::Repeat(W4, &[Op::Skip(16), Op::Text(Text::Long), Op::Text(Text::Long)]),
    Op::Repeat(W4, &[
        Op::Skip(16),
        Op::Text(Text::Long),
        Op::Text(Text::Long),
        Op::Text(Text::Long),
        Op::Text(Text::Long),
        Op::Text(Text::Long),
        Op::Skip(1),
    ]),
    Op::Repeat(W1, &[Op::Text(Text::Short), Op::Skip(12), Op::Block]),
    Op::Repeat(W2, &[
        Op::Loc,
        Op::Loc,
        Op::Skip(1),
        Op::Loc,
        Op::Skip(68),
        Op::Repeat(W2, &[Op::Skip(5)]),
        Op::Skip(1),
    ]),
];
static BUILT370902B8_T01: &[Op] = &[
    Op::Loc,
    Op::Text(Text::Long),
    Op::Skip(9),
    Op::Text(Text::Long),
    Op::Skip(3),
    Op::Text(Text::Long),
    Op::Skip(4),
];
static BUILT370902B8_T02: &[Op] = &[
    Op::Loc,
    Op::Text(Text::Long),
    Op::Skip(53),
    Op::Text(Text::Long),
    Op::Skip(26),
    Op::Choose(W1, &[
        (&[4], &[Op::Text(Text::Long), Op::Skip(17)]),
    ], &[Op::Text(Text::Long), Op::Skip(1)]),
    Op::Skip(5),
];
static BUILT370902B8_T05: &[Op] = &[
    Op::Skip(1),
    Op::Text(Text::Long),
    Op::Skip(1),
    Op::Text(Text::Long),
    Op::Text(Text::Long),
    Op::Text(Text::Long),
    Op::Skip(1),
    Op::Text(Text::Long),
    Op::Skip(2),
];
static BUILT370902B8_T15: &[Op] = &[Op::Text(Text::Long), Op::Skip(14)];
static BUILT370902B8_T23: &[Op] = &[Op::Skip(9), Op::Text(Text::Long), Op::Skip(1), Op::Text(Text::Long)];
static BUILT370902B8_T30: &[Op] = &[Op::Skip(1), Op::Text(Text::Long), Op::When(W1, &[Op::Text(Text::Long)])];
static BUILT370902B8_T36: &[Op] = &[
    Op::Choose(W4, &[
        (&[0], &[
            Op::Skip(8),
            Op::Repeat(W2, &[
                Op::Choose(W2, &[
                    (&[1, 8], &[Op::Text(Text::Long), Op::Skip(9)]),
                    (&[2], &[
                        Op::Text(Text::Long),
                        Op::Skip(10),
                        Op::Text(Text::Long),
                        Op::Text(Text::Long),
                        Op::Skip(6),
                    ]),
                    (&[3], &[Op::Text(Text::Long), Op::Skip(14)]),
                    (&[4], &[
                        Op::Text(Text::Long),
                        Op::Skip(21),
                        Op::Text(Text::Long),
                        Op::Text(Text::Long),
                    ]),
                    (&[5, 6], &[Op::Text(Text::Long), Op::Skip(9), Op::Text(Text::Long)]),
                    (&[7], &[Op::Skip(15), Op::Text(Text::Long), Op::Text(Text::Long)]),
                    (&[9], &[Op::Text(Text::Long), Op::Skip(8)]),
                ], &[]),
            ]),
        ]),
        (&[2], &[
            Op::Choose(W1, &[
                (&[0], &[Op::Skip(1), Op::Text(Text::Long), Op::Loc]),
            ], &[Op::Skip(1), Op::Text(Text::Long)]),
        ]),
        (&[3, 5, 13], &[
            Op::Choose(W1, &[
                (&[0], &[Op::Skip(1), Op::Text(Text::Long), Op::Loc, Op::Loc]),
            ], &[Op::Skip(1), Op::Text(Text::Long)]),
        ]),
        (&[4, 15], &[
            Op::Choose(W1, &[
                (&[0], &[Op::Skip(1), Op::Text(Text::Long), Op::Loc, Op::Loc]),
            ], &[Op::Skip(1), Op::Text(Text::Long), Op::Loc]),
        ]),
        (&[6], &[
            Op::Choose(W1, &[
                (&[0], &[Op::Skip(1), Op::Text(Text::Long), Op::Loc, Op::Loc, Op::Loc, Op::Loc]),
            ], &[Op::Skip(1), Op::Text(Text::Long), Op::Loc]),
        ]),
        (&[7], &[
            Op::Choose(W1, &[
                (&[0], &[Op::Skip(1), Op::Text(Text::Long), Op::Loc, Op::Loc, Op::Text(Text::Long)]),
            ], &[Op::Skip(1), Op::Text(Text::Long), Op::Text(Text::Long)]),
        ]),
        (&[8], &[
            Op::Choose(W1, &[
                (&[0], &[
                    Op::Skip(1),
                    Op::Text(Text::Long),
                    Op::Skip(3),
                    Op::Loc,
                    Op::Loc,
                    Op::Loc,
                    Op::Loc,
                    Op::Loc,
                    Op::Loc,
                    Op::Loc,
                    Op::Loc,
                    Op::Text(Text::Long),
                    Op::Text(Text::Long),
                    Op::Text(Text::Long),
                ]),
            ], &[
                Op::Skip(1),
                Op::Text(Text::Long),
                Op::Skip(3),
                Op::Loc,
                Op::Loc,
                Op::Loc,
                Op::Text(Text::Long),
                Op::Text(Text::Long),
                Op::Text(Text::Long),
            ]),
        ]),
        (&[9], &[
            Op::Choose(W1, &[
                (&[0], &[
                    Op::Skip(1),
                    Op::Text(Text::Long),
                    Op::Loc,
                    Op::Loc,
                    Op::Loc,
                    Op::Loc,
                    Op::Text(Text::Long),
                ]),
            ], &[Op::Skip(1), Op::Text(Text::Long), Op::Loc, Op::Loc, Op::Text(Text::Long)]),
        ]),
        (&[10], &[
            Op::Choose(W1, &[
                (&[0], &[
                    Op::Skip(1),
                    Op::Text(Text::Long),
                    Op::Loc,
                    Op::Loc,
                    Op::Loc,
                    Op::Loc,
                    Op::Loc,
                    Op::Loc,
                    Op::Loc,
                    Op::Loc,
                ]),
            ], &[Op::Skip(1), Op::Text(Text::Long)]),
        ]),
        (&[11], &[
            Op::Choose(W1, &[
                (&[0], &[Op::Skip(1), Op::Text(Text::Long), Op::Loc, Op::Loc, Op::Skip(1)]),
            ], &[Op::Skip(1), Op::Text(Text::Long), Op::Skip(1)]),
        ]),
        (&[12], &[
            Op::Choose(W1, &[
                (&[0], &[
                    Op::Skip(1),
                    Op::Text(Text::Long),
                    Op::Loc,
                    Op::Loc,
                    Op::Loc,
                    Op::Skip(1),
                    Op::Text(Text::Long),
                ]),
            ], &[Op::Skip(1), Op::Text(Text::Long), Op::Loc, Op::Skip(1), Op::Text(Text::Long)]),
        ]),
        (&[16], &[
            Op::Choose(W1, &[
                (&[0], &[
                    Op::Skip(1),
                    Op::Text(Text::Long),
                    Op::Loc,
                    Op::Loc,
                    Op::Loc,
                    Op::Skip(1),
                    Op::Loc,
                    Op::Text(Text::Long),
                    Op::Text(Text::Long),
                    Op::Skip(1),
                    Op::Loc,
                    Op::Text(Text::Long),
                    Op::Text(Text::Long),
                    Op::Skip(1),
                    Op::Loc,
                    Op::Text(Text::Long),
                    Op::Text(Text::Long),
                ]),
            ], &[
                Op::Skip(1),
                Op::Text(Text::Long),
                Op::Skip(1),
                Op::Loc,
                Op::Text(Text::Long),
                Op::Text(Text::Long),
                Op::Skip(1),
                Op::Loc,
                Op::Text(Text::Long),
                Op::Text(Text::Long),
                Op::Skip(1),
                Op::Loc,
                Op::Text(Text::Long),
                Op::Text(Text::Long),
            ]),
        ]),
        (&[17], &[
            Op::Choose(W1, &[
                (&[0], &[Op::Skip(1), Op::Text(Text::Long), Op::Loc, Op::Loc, Op::Loc, Op::Loc, Op::Loc]),
            ], &[Op::Skip(1), Op::Text(Text::Long)]),
        ]),
    ], &[]),
];
static BUILT370902B8_T37: &[Op] = &[Op::Skip(2)];
static BUILT370902B8_START: &[Op] = &[
    Op::Skip(4),
    Op::Text(Text::Long),
    Op::Text(Text::Long),
    Op::Skip(2),
    Op::Text(Text::Long),
    Op::Text(Text::Long),
    Op::Repeat(W2, &[Op::Skip(2), Op::Text(Text::Long), Op::Text(Text::Long)]),
    Op::Block,
    Op::Skip(1),
    Op::Repeat(W4, &[
        Op::Skip(31),
        Op::Repeat(W2, &[Op::Skip(5)]),
        Op::Skip(1),
        Op::Repeat(W2, &[Op::Text(Text::Long), Op::Skip(4), Op::Text(Text::Long), Op::Text(Text::Long)]),
        Op::Repeat(W2, &[Op::Text(Text::Long), Op::Skip(4), Op::Text(Text::Long), Op::Text(Text::Long)]),
        Op::Skip(65),
        Op::Text(Text::Long),
        Op::Skip(14),
    ]),
    Op::Repeat(W4, &[Op::Text(Text::Long), Op::Text(Text::Long)]),
    Op::Repeat(W4, &[Op::Skip(16), Op::Text(Text::Long), Op::Text(Text::Long)]),
    Op::Repeat(W4, &[
        Op::Skip(16),
        Op::Text(Text::Long),
        Op::Text(Text::Long),
        Op::Text(Text::Long),
        Op::Text(Text::Long),
        Op::Text(Text::Long),
        Op::Skip(2),
    ]),
    Op::Repeat(W2, &[Op::Text(Text::Short), Op::Skip(12), Op::Block]),
    Op::Repeat(W2, &[
        Op::Loc,
        Op::Loc,
        Op::Skip(1),
        Op::Loc,
        Op::Skip(68),
        Op::Repeat(W2, &[Op::Skip(5)]),
        Op::Skip(1),
    ]),
];
static FORK37150603_T02: &[Op] = &[
    Op::Loc,
    Op::Text(Text::Long),
    Op::Text(Text::Long),
    Op::Skip(53),
    Op::Text(Text::Long),
    Op::Skip(26),
    Op::Choose(W1, &[
        (&[4], &[Op::Text(Text::Long), Op::Skip(17)]),
    ], &[Op::Text(Text::Long), Op::Skip(1)]),
    Op::Skip(9),
];
static FORK37150603_T21: &[Op] = &[
    Op::Text(Text::Long),
    Op::Text(Text::Long),
    Op::Skip(57),
    Op::Text(Text::Long),
    Op::Skip(2),
    Op::Choose(W1, &[
        (&[4], &[Op::Text(Text::Long), Op::Skip(16)]),
    ], &[Op::Text(Text::Long)]),
    Op::Skip(4),
];
static FORK37150603_START: &[Op] = &[
    Op::Skip(1),
    Op::When(W1, &[
        Op::Text(Text::Long),
        Op::Text(Text::Long),
        Op::Text(Text::Long),
        Op::Text(Text::Long),
        Op::Text(Text::Long),
        Op::Text(Text::Long),
        Op::Text(Text::Long),
        Op::Text(Text::Long),
        Op::Text(Text::Long),
        Op::Text(Text::Long),
        Op::Text(Text::Long),
        Op::Skip(9),
        Op::Repeat(W2, &[
            Op::Choose(W2, &[
                (&[1, 3], &[Op::Text(Text::Long), Op::Skip(9)]),
                (&[2, 4], &[Op::Text(Text::Long), Op::Skip(8)]),
            ], &[]),
        ]),
    ]),
    Op::Skip(2),
    Op::Text(Text::Long),
    Op::Text(Text::Long),
    Op::Skip(2),
    Op::Text(Text::Long),
    Op::Text(Text::Long),
    Op::Repeat(W2, &[Op::Skip(2), Op::Text(Text::Long), Op::Text(Text::Long)]),
    Op::Block,
    Op::Repeat(W4, &[Op::Skip(16), Op::Text(Text::Long), Op::Text(Text::Long)]),
    Op::Repeat(W4, &[
        Op::Skip(16),
        Op::Text(Text::Long),
        Op::Text(Text::Long),
        Op::Text(Text::Long),
        Op::Text(Text::Long),
        Op::Text(Text::Long),
        Op::Skip(2),
    ]),
    Op::Repeat(W1, &[Op::Text(Text::Short), Op::Skip(12), Op::Block]),
    Op::Repeat(W2, &[
        Op::Loc,
        Op::Loc,
        Op::Skip(1),
        Op::Loc,
        Op::Skip(68),
        Op::Repeat(W2, &[Op::Skip(5)]),
        Op::Skip(1),
    ]),
];
static BUILT3717A989_T23: &[Op] = &[Op::Skip(9), Op::Text(Text::Long), Op::When(W1, &[Op::Text(Text::Long)])];
static BUILT3741ED89_T02: &[Op] = &[
    Op::Loc,
    Op::Text(Text::Long),
    Op::Skip(53),
    Op::Text(Text::Long),
    Op::Skip(26),
    Op::Choose(W1, &[
        (&[4], &[Op::Text(Text::Long), Op::Skip(17)]),
    ], &[Op::Text(Text::Long), Op::Skip(1)]),
    Op::Skip(9),
];
static BUILT377CCE3C_T17: &[Op] = &[Op::Text(Text::Long), Op::Text(Text::Long), Op::Skip(5)];
static BUILT377CCE3C_T38: &[Op] = &[Op::Text(Text::Long), Op::Text(Text::Long), Op::Text(Text::Long), Op::Text(Text::Long)];
static V3_1_1_T01: &[Op] = &[
    Op::Loc,
    Op::Text(Text::Long),
    Op::Skip(9),
    Op::Text(Text::Long),
    Op::Skip(3),
    Op::Text(Text::Long),
    Op::Skip(5),
];
static V3_5_T02: &[Op] = &[
    Op::Loc,
    Op::Text(Text::Long),
    Op::Skip(53),
    Op::Text(Text::Long),
    Op::Skip(26),
    Op::Choose(W1, &[
        (&[4], &[Op::Text(Text::Long), Op::Skip(17)]),
    ], &[Op::Text(Text::Long), Op::Skip(1)]),
    Op::Skip(10),
];
static V3_5_START: &[Op] = &[
    Op::Skip(4),
    Op::Text(Text::Long),
    Op::Text(Text::Long),
    Op::Skip(2),
    Op::Text(Text::Long),
    Op::Text(Text::Long),
    Op::Repeat(W2, &[Op::Skip(2), Op::Text(Text::Long), Op::Text(Text::Long)]),
    Op::Block,
    Op::Skip(1),
    Op::Repeat(W4, &[
        Op::Skip(31),
        Op::Repeat(W2, &[Op::Skip(5)]),
        Op::Skip(1),
        Op::Repeat(W2, &[Op::Text(Text::Long), Op::Skip(4), Op::Text(Text::Long), Op::Text(Text::Long)]),
        Op::Repeat(W2, &[Op::Text(Text::Long), Op::Skip(4), Op::Text(Text::Long), Op::Text(Text::Long)]),
        Op::Skip(65),
        Op::Text(Text::Long),
        Op::Skip(14),
    ]),
    Op::Repeat(W4, &[Op::Text(Text::Long), Op::Text(Text::Long)]),
    Op::Repeat(W4, &[Op::Skip(16), Op::Text(Text::Long), Op::Text(Text::Long)]),
    Op::Repeat(W4, &[
        Op::Skip(16),
        Op::Text(Text::Long),
        Op::Text(Text::Long),
        Op::Text(Text::Long),
        Op::Text(Text::Long),
        Op::Text(Text::Long),
        Op::Skip(2),
    ]),
    Op::Repeat(W2, &[Op::Text(Text::Short), Op::Skip(12), Op::Block]),
    Op::Repeat(W2, &[
        Op::Loc,
        Op::Loc,
        Op::Skip(1),
        Op::Loc,
        Op::Skip(68),
        Op::Repeat(W2, &[Op::Skip(5)]),
        Op::Skip(2),
        Op::Text(Text::Long),
    ]),
];
static BUILT39EB21BD_T21: &[Op] = &[
    Op::Text(Text::Long),
    Op::Text(Text::Long),
    Op::Skip(57),
    Op::Text(Text::Long),
    Op::Skip(2),
    Op::Choose(W1, &[
        (&[4], &[Op::Text(Text::Long), Op::Skip(16)]),
    ], &[Op::Text(Text::Long)]),
    Op::Skip(5),
];
static V3_6_1_HEADER: &[Op] = &[
    Op::Skip(20),
    Op::Repeat(W2, &[Op::Skip(5)]),
    Op::Skip(1),
    Op::Repeat(W2, &[Op::Text(Text::Long), Op::Skip(4), Op::Text(Text::Long), Op::Text(Text::Long)]),
    Op::Repeat(W2, &[Op::Text(Text::Long), Op::Skip(4), Op::Text(Text::Long), Op::Text(Text::Long)]),
    Op::Skip(65),
];
static V3_6_1_START: &[Op] = &[
    Op::Skip(4),
    Op::Text(Text::Long),
    Op::Text(Text::Long),
    Op::Skip(2),
    Op::Text(Text::Long),
    Op::Text(Text::Long),
    Op::Repeat(W2, &[Op::Skip(2), Op::Text(Text::Long), Op::Text(Text::Long)]),
    Op::Block,
    Op::Skip(1),
    Op::Repeat(W4, &[
        Op::Skip(32),
        Op::Repeat(W2, &[Op::Skip(5)]),
        Op::Skip(1),
        Op::Repeat(W2, &[Op::Text(Text::Long), Op::Skip(4), Op::Text(Text::Long), Op::Text(Text::Long)]),
        Op::Repeat(W2, &[Op::Text(Text::Long), Op::Skip(4), Op::Text(Text::Long), Op::Text(Text::Long)]),
        Op::Skip(65),
        Op::Text(Text::Long),
        Op::Skip(14),
    ]),
    Op::Repeat(W4, &[Op::Text(Text::Long), Op::Text(Text::Long)]),
    Op::Repeat(W4, &[Op::Skip(16), Op::Text(Text::Long), Op::Text(Text::Long)]),
    Op::Repeat(W4, &[
        Op::Skip(16),
        Op::Text(Text::Long),
        Op::Text(Text::Long),
        Op::Text(Text::Long),
        Op::Text(Text::Long),
        Op::Text(Text::Long),
        Op::Skip(2),
    ]),
    Op::Repeat(W2, &[Op::Text(Text::Short), Op::Skip(12), Op::Block]),
    Op::Repeat(W2, &[
        Op::Loc,
        Op::Loc,
        Op::Skip(1),
        Op::Loc,
        Op::Skip(69),
        Op::Repeat(W2, &[Op::Skip(5)]),
        Op::Skip(2),
        Op::Text(Text::Long),
    ]),
];

static BUILT33739B9E: Layout = Layout {
    header: BUILT33739B9E_HEADER,
    bodies: &[
        Some(BUILT33739B9E_T01), Some(BUILT33739B9E_T02), Some(BUILT33739B9E_T03),
        Some(BUILT33739B9E_T04), Some(BUILT33739B9E_T05), Some(BUILT33739B9E_T06),
        Some(BUILT33739B9E_T07), Some(BUILT33739B9E_T08), Some(BUILT33739B9E_T08),
        Some(BUILT33739B9E_T10), Some(BUILT33739B9E_T11), Some(BUILT33739B9E_T12),
        Some(BUILT33739B9E_T13), Some(BUILT33739B9E_T14), Some(BUILT33739B9E_T15),
        Some(BUILT33739B9E_T16), Some(BUILT33739B9E_T17), Some(BUILT33739B9E_T18),
        Some(BUILT33739B9E_T19), None, Some(BUILT33739B9E_T21), Some(BUILT33739B9E_T22),
        Some(BUILT33739B9E_T23), Some(BUILT33739B9E_T24), Some(BUILT33739B9E_T25),
        Some(BUILT33739B9E_T26), Some(BUILT33739B9E_T27),
    ],
    file: FileRecord {
        before_sizes: &[Text::Short, Text::Short],
        folder: Some(1),
        after_times: Text::Short,
        crc_at: 12,
        source_at: None,
    },
    start: BUILT33739B9E_START,
    bare: &[20],
};
static BUILT33D3713B: Layout = Layout {
    header: BUILT33739B9E_HEADER,
    bodies: &[
        Some(BUILT33739B9E_T01), Some(BUILT33739B9E_T02), Some(BUILT33739B9E_T03),
        Some(BUILT33739B9E_T04), Some(BUILT33739B9E_T05), Some(BUILT33739B9E_T06),
        Some(BUILT33739B9E_T07), Some(BUILT33739B9E_T08), Some(BUILT33739B9E_T08),
        Some(BUILT33739B9E_T10), Some(BUILT33739B9E_T11), Some(BUILT33739B9E_T12),
        Some(BUILT33739B9E_T13), Some(BUILT33739B9E_T14), Some(BUILT33739B9E_T15),
        Some(BUILT33739B9E_T16), Some(BUILT33739B9E_T17), Some(BUILT33739B9E_T18),
        Some(BUILT33739B9E_T19), None, Some(BUILT33739B9E_T21), Some(BUILT33739B9E_T22),
        Some(BUILT33739B9E_T23), Some(BUILT33739B9E_T24), Some(BUILT33739B9E_T25),
        Some(BUILT33739B9E_T26), Some(BUILT33739B9E_T27),
    ],
    file: FileRecord {
        before_sizes: &[Text::Short, Text::Short],
        folder: Some(1),
        after_times: Text::Short,
        crc_at: 12,
        source_at: None,
    },
    start: BUILT33D3713B_START,
    bare: &[20],
};
static V2_4_3: Layout = Layout {
    header: BUILT33739B9E_HEADER,
    bodies: &[
        Some(BUILT33739B9E_T01), Some(BUILT33739B9E_T02), Some(BUILT33739B9E_T03),
        Some(BUILT33739B9E_T04), Some(BUILT33739B9E_T05), Some(BUILT33739B9E_T06),
        Some(BUILT33739B9E_T07), Some(BUILT33739B9E_T08), Some(BUILT33739B9E_T08),
        Some(BUILT33739B9E_T10), Some(BUILT33739B9E_T11), Some(BUILT33739B9E_T12),
        Some(BUILT33739B9E_T13), Some(BUILT33739B9E_T14), Some(V2_4_3_T15),
        Some(BUILT33739B9E_T16), Some(BUILT33739B9E_T17), Some(BUILT33739B9E_T18),
        Some(BUILT33739B9E_T19), None, Some(BUILT33739B9E_T21), Some(BUILT33739B9E_T22),
        Some(BUILT33739B9E_T23), Some(BUILT33739B9E_T24), Some(BUILT33739B9E_T25),
        Some(BUILT33739B9E_T26), Some(BUILT33739B9E_T27),
    ],
    file: FileRecord {
        before_sizes: &[Text::Short, Text::Short],
        folder: Some(1),
        after_times: Text::Short,
        crc_at: 12,
        source_at: None,
    },
    start: V2_4_3_START,
    bare: &[20],
};
static V2_5: Layout = Layout {
    header: BUILT33739B9E_HEADER,
    bodies: &[
        Some(BUILT33739B9E_T01), Some(V2_5_T02), Some(BUILT33739B9E_T03), Some(BUILT33739B9E_T04),
        Some(BUILT33739B9E_T05), Some(BUILT33739B9E_T06), Some(BUILT33739B9E_T07),
        Some(BUILT33739B9E_T08), Some(BUILT33739B9E_T08), Some(BUILT33739B9E_T10),
        Some(BUILT33739B9E_T11), Some(BUILT33739B9E_T12), Some(BUILT33739B9E_T13),
        Some(BUILT33739B9E_T14), Some(V2_4_3_T15), Some(BUILT33739B9E_T16),
        Some(BUILT33739B9E_T17), Some(BUILT33739B9E_T18), Some(BUILT33739B9E_T19), None,
        Some(BUILT33739B9E_T21), Some(V2_5_T22), Some(BUILT33739B9E_T23), Some(BUILT33739B9E_T24),
        Some(BUILT33739B9E_T25), Some(BUILT33739B9E_T26), Some(BUILT33739B9E_T27),
    ],
    file: FileRecord {
        before_sizes: &[Text::Short, Text::Short],
        folder: Some(1),
        after_times: Text::Short,
        crc_at: 14,
        source_at: None,
    },
    start: V2_5_START,
    bare: &[20],
};
static V2_6: Layout = Layout {
    header: BUILT33739B9E_HEADER,
    bodies: &[
        Some(V2_6_T01), Some(V2_6_T02), Some(V2_6_T03), Some(BUILT33739B9E_T04),
        Some(BUILT33739B9E_T05), Some(BUILT33739B9E_T06), Some(BUILT33739B9E_T07),
        Some(BUILT33739B9E_T08), Some(BUILT33739B9E_T08), Some(BUILT33739B9E_T10),
        Some(BUILT33739B9E_T11), Some(BUILT33739B9E_T12), Some(BUILT33739B9E_T13),
        Some(BUILT33739B9E_T14), Some(V2_4_3_T15), Some(BUILT33739B9E_T16),
        Some(BUILT33739B9E_T17), Some(BUILT33739B9E_T18), Some(BUILT33739B9E_T19), None,
        Some(BUILT33739B9E_T21), Some(V2_5_T22), Some(BUILT33739B9E_T23), Some(BUILT33739B9E_T24),
        Some(BUILT33739B9E_T25), Some(BUILT33739B9E_T26), Some(V2_6_T27), Some(V2_6_T28),
        Some(V2_6_T29), Some(V2_6_T30),
    ],
    file: FileRecord {
        before_sizes: &[Text::Short, Text::Short],
        folder: Some(1),
        after_times: Text::Short,
        crc_at: 14,
        source_at: None,
    },
    start: V2_6_START,
    bare: &[20],
};
static BUILT35071525: Layout = Layout {
    header: BUILT33739B9E_HEADER,
    bodies: &[
        Some(V2_6_T01), Some(V2_6_T02), Some(V2_6_T03), Some(BUILT33739B9E_T04),
        Some(BUILT33739B9E_T05), Some(BUILT33739B9E_T06), Some(BUILT33739B9E_T07),
        Some(BUILT33739B9E_T08), Some(BUILT33739B9E_T08), Some(BUILT33739B9E_T10),
        Some(BUILT33739B9E_T11), Some(BUILT33739B9E_T12), Some(BUILT33739B9E_T13),
        Some(BUILT33739B9E_T14), Some(V2_4_3_T15), Some(BUILT33739B9E_T16),
        Some(BUILT33739B9E_T17), Some(BUILT33739B9E_T18), Some(BUILT33739B9E_T19), None,
        Some(BUILT33739B9E_T21), Some(V2_5_T22), Some(BUILT33739B9E_T23), Some(BUILT33739B9E_T24),
        Some(BUILT33739B9E_T25), Some(BUILT33739B9E_T26), Some(V2_6_T27), Some(V2_6_T28),
        Some(BUILT35071525_T29), Some(V2_6_T30),
    ],
    file: FileRecord {
        before_sizes: &[Text::Short, Text::Short],
        folder: Some(1),
        after_times: Text::Short,
        crc_at: 14,
        source_at: None,
    },
    start: BUILT35071525_START,
    bare: &[20],
};
static V2_6_2: Layout = Layout {
    header: BUILT33739B9E_HEADER,
    bodies: &[
        Some(V2_6_T01), Some(V2_6_T02), Some(V2_6_T03), Some(BUILT33739B9E_T04),
        Some(BUILT33739B9E_T05), Some(V2_6_2_T06), Some(BUILT33739B9E_T07),
        Some(BUILT33739B9E_T08), Some(BUILT33739B9E_T08), Some(BUILT33739B9E_T10),
        Some(BUILT33739B9E_T11), Some(BUILT33739B9E_T12), Some(BUILT33739B9E_T13),
        Some(BUILT33739B9E_T14), Some(V2_4_3_T15), Some(BUILT33739B9E_T16),
        Some(BUILT33739B9E_T17), Some(BUILT33739B9E_T18), Some(BUILT33739B9E_T19), None,
        Some(BUILT33739B9E_T21), Some(V2_5_T22), Some(BUILT33739B9E_T23), Some(BUILT33739B9E_T24),
        Some(BUILT33739B9E_T25), Some(BUILT33739B9E_T26), Some(V2_6_T27), Some(V2_6_T28),
        Some(BUILT35071525_T29), Some(V2_6_T30),
    ],
    file: FileRecord {
        before_sizes: &[Text::Short, Text::Short],
        folder: Some(1),
        after_times: Text::Short,
        crc_at: 14,
        source_at: None,
    },
    start: BUILT35071525_START,
    bare: &[20],
};
static V2_6_3: Layout = Layout {
    header: BUILT33739B9E_HEADER,
    bodies: &[
        Some(V2_6_T01), Some(V2_6_T02), Some(V2_6_T03), Some(BUILT33739B9E_T04),
        Some(BUILT33739B9E_T05), Some(V2_6_2_T06), Some(BUILT33739B9E_T07),
        Some(BUILT33739B9E_T08), Some(BUILT33739B9E_T08), Some(BUILT33739B9E_T10),
        Some(BUILT33739B9E_T11), Some(BUILT33739B9E_T12), Some(BUILT33739B9E_T13),
        Some(BUILT33739B9E_T14), Some(V2_4_3_T15), Some(V2_6_3_T16), Some(BUILT33739B9E_T17),
        Some(BUILT33739B9E_T18), Some(BUILT33739B9E_T19), None, Some(BUILT33739B9E_T21),
        Some(V2_5_T22), Some(BUILT33739B9E_T23), Some(BUILT33739B9E_T24), Some(BUILT33739B9E_T25),
        Some(BUILT33739B9E_T26), Some(V2_6_T27), Some(V2_6_T28), Some(BUILT35071525_T29),
        Some(V2_6_T30), Some(BUILT33739B9E_T13), Some(V2_6_3_T32),
    ],
    file: FileRecord {
        before_sizes: &[Text::Short, Text::Short],
        folder: Some(1),
        after_times: Text::Short,
        crc_at: 14,
        source_at: None,
    },
    start: V2_6_3_START,
    bare: &[20],
};
static V2_7: Layout = Layout {
    header: BUILT33739B9E_HEADER,
    bodies: &[
        Some(V2_6_T01), Some(V2_7_T02), Some(V2_6_T03), Some(BUILT33739B9E_T04),
        Some(BUILT33739B9E_T05), Some(V2_7_T06), Some(BUILT33739B9E_T07), Some(BUILT33739B9E_T08),
        Some(BUILT33739B9E_T08), Some(BUILT33739B9E_T10), Some(BUILT33739B9E_T11),
        Some(BUILT33739B9E_T12), Some(BUILT33739B9E_T13), Some(BUILT33739B9E_T14),
        Some(V2_4_3_T15), Some(V2_6_3_T16), Some(BUILT33739B9E_T17), Some(BUILT33739B9E_T18),
        Some(BUILT33739B9E_T19), None, Some(V2_7_T21), Some(V2_5_T22), Some(BUILT33739B9E_T23),
        Some(BUILT33739B9E_T24), Some(BUILT33739B9E_T25), Some(BUILT33739B9E_T26), Some(V2_6_T27),
        Some(V2_6_T28), Some(V2_7_T29), Some(V2_6_T30), Some(BUILT33739B9E_T13), Some(V2_6_3_T32),
        None, Some(V2_7_T34),
    ],
    file: FileRecord {
        before_sizes: &[Text::Short, Text::Short],
        folder: Some(1),
        after_times: Text::Short,
        crc_at: 14,
        source_at: Some(26),
    },
    start: V2_7_START,
    bare: &[20, 33],
};
static V2_7_1: Layout = Layout {
    header: V2_7_1_HEADER,
    bodies: &[
        Some(V2_6_T01), Some(V2_7_T02), Some(V2_6_T03), Some(BUILT33739B9E_T04),
        Some(BUILT33739B9E_T05), Some(V2_7_T06), Some(BUILT33739B9E_T07), Some(BUILT33739B9E_T08),
        Some(BUILT33739B9E_T08), Some(BUILT33739B9E_T10), Some(BUILT33739B9E_T11),
        Some(BUILT33739B9E_T12), Some(BUILT33739B9E_T13), Some(BUILT33739B9E_T14),
        Some(V2_4_3_T15), Some(V2_6_3_T16), Some(BUILT33739B9E_T17), Some(BUILT33739B9E_T18),
        Some(BUILT33739B9E_T19), None, Some(V2_7_T21), Some(V2_5_T22), Some(BUILT33739B9E_T23),
        Some(BUILT33739B9E_T24), Some(BUILT33739B9E_T25), Some(BUILT33739B9E_T26), Some(V2_6_T27),
        Some(V2_6_T28), Some(V2_7_T29), Some(V2_6_T30), Some(BUILT33739B9E_T13), Some(V2_6_3_T32),
        None, Some(V2_7_T34),
    ],
    file: FileRecord {
        before_sizes: &[Text::Short, Text::Short],
        folder: Some(1),
        after_times: Text::Short,
        crc_at: 14,
        source_at: Some(26),
    },
    start: V2_7_1_START,
    bare: &[20, 33],
};
static BUILT36101749: Layout = Layout {
    header: BUILT36101749_HEADER,
    bodies: &[
        Some(BUILT36101749_T01), Some(BUILT36101749_T02), Some(BUILT36101749_T03),
        Some(BUILT36101749_T04), Some(BUILT36101749_T05), Some(BUILT36101749_T06),
        Some(BUILT36101749_T07), Some(BUILT36101749_T08), Some(BUILT36101749_T08),
        Some(BUILT36101749_T10), Some(BUILT36101749_T11), Some(BUILT33739B9E_T12),
        Some(BUILT36101749_T13), Some(BUILT36101749_T14), Some(BUILT36101749_T15),
        Some(V2_6_3_T16), Some(BUILT36101749_T17), Some(BUILT36101749_T18),
        Some(BUILT36101749_T19), None, Some(BUILT36101749_T21), Some(V2_5_T22),
        Some(BUILT33739B9E_T23), Some(BUILT36101749_T24), Some(BUILT36101749_T25),
        Some(BUILT36101749_T26), Some(BUILT36101749_T27), Some(V2_6_T28), Some(V2_7_T29),
        Some(V2_6_T30), Some(BUILT33739B9E_T13), Some(V2_6_3_T32), None, Some(V2_7_T34),
        Some(BUILT36101749_T35),
    ],
    file: FileRecord {
        before_sizes: &[Text::Long, Text::Long],
        folder: Some(1),
        after_times: Text::Long,
        crc_at: 14,
        source_at: Some(26),
    },
    start: BUILT36101749_START,
    bare: &[20, 33],
};
static V2_8: Layout = Layout {
    header: BUILT36101749_HEADER,
    bodies: &[
        Some(BUILT36101749_T01), Some(BUILT36101749_T02), Some(BUILT36101749_T03),
        Some(BUILT36101749_T04), Some(BUILT36101749_T05), Some(BUILT36101749_T06),
        Some(BUILT36101749_T07), Some(BUILT36101749_T08), Some(BUILT36101749_T08),
        Some(BUILT36101749_T10), Some(BUILT36101749_T11), Some(BUILT33739B9E_T12),
        Some(BUILT36101749_T13), Some(BUILT36101749_T14), Some(BUILT36101749_T15),
        Some(V2_6_3_T16), Some(BUILT36101749_T17), Some(BUILT36101749_T18),
        Some(BUILT36101749_T19), None, Some(BUILT36101749_T21), Some(V2_5_T22),
        Some(BUILT33739B9E_T23), Some(BUILT36101749_T24), Some(BUILT36101749_T25),
        Some(BUILT36101749_T26), Some(BUILT36101749_T27), Some(V2_6_T28), Some(V2_7_T29),
        Some(V2_6_T30), Some(BUILT33739B9E_T13), Some(V2_6_3_T32), None, Some(V2_7_T34),
        Some(BUILT36101749_T35),
    ],
    file: FileRecord {
        before_sizes: &[Text::Long, Text::Long],
        folder: Some(1),
        after_times: Text::Long,
        crc_at: 14,
        source_at: Some(26),
    },
    start: V2_8_START,
    bare: &[20, 33],
};
static BUILT370902B8: Layout = Layout {
    header: BUILT36101749_HEADER,
    bodies: &[
        Some(BUILT370902B8_T01), Some(BUILT370902B8_T02), Some(BUILT36101749_T03),
        Some(BUILT36101749_T04), Some(BUILT370902B8_T05), Some(BUILT36101749_T06),
        Some(BUILT36101749_T07), Some(BUILT36101749_T08), Some(BUILT36101749_T08),
        Some(BUILT36101749_T10), Some(BUILT36101749_T11), Some(BUILT33739B9E_T12),
        Some(BUILT36101749_T13), Some(BUILT36101749_T14), Some(BUILT370902B8_T15),
        Some(V2_6_3_T16), Some(BUILT36101749_T17), Some(BUILT36101749_T18),
        Some(BUILT36101749_T19), None, Some(BUILT36101749_T21), Some(V2_5_T22),
        Some(BUILT370902B8_T23), Some(BUILT36101749_T24), Some(BUILT36101749_T25),
        Some(BUILT36101749_T26), Some(BUILT36101749_T27), Some(V2_6_T28), Some(V2_7_T29),
        Some(BUILT370902B8_T30), Some(BUILT33739B9E_T13), Some(V2_6_3_T32), None, Some(V2_7_T34),
        Some(BUILT36101749_T35), Some(BUILT370902B8_T36), Some(BUILT370902B8_T37),
    ],
    file: FileRecord {
        before_sizes: &[Text::Long],
        folder: None,
        after_times: Text::Long,
        crc_at: 14,
        source_at: Some(26),
    },
    start: BUILT370902B8_START,
    bare: &[20, 33],
};
static FORK37150603: Layout = Layout {
    header: BUILT36101749_HEADER,
    bodies: &[
        Some(BUILT36101749_T01), Some(FORK37150603_T02), Some(BUILT36101749_T03),
        Some(BUILT36101749_T04), Some(BUILT36101749_T05), Some(BUILT36101749_T06),
        Some(BUILT36101749_T07), Some(BUILT36101749_T08), Some(BUILT36101749_T08),
        Some(BUILT36101749_T10), Some(BUILT36101749_T11), Some(BUILT33739B9E_T12),
        Some(BUILT36101749_T13), Some(BUILT36101749_T14), Some(BUILT36101749_T15),
        Some(V2_6_3_T16), Some(BUILT36101749_T17), Some(BUILT36101749_T18),
        Some(BUILT36101749_T19), None, Some(FORK37150603_T21), Some(V2_5_T22),
        Some(BUILT33739B9E_T23), Some(BUILT36101749_T24), Some(BUILT36101749_T25),
        Some(BUILT36101749_T26), Some(BUILT36101749_T27), Some(V2_6_T28), Some(V2_7_T29),
        Some(V2_6_T30), Some(BUILT33739B9E_T13), Some(V2_6_3_T32), None, Some(V2_7_T34),
        Some(BUILT36101749_T35),
    ],
    file: FileRecord {
        before_sizes: &[Text::Long, Text::Long],
        folder: Some(1),
        after_times: Text::Long,
        crc_at: 14,
        source_at: Some(26),
    },
    start: FORK37150603_START,
    bare: &[20, 33],
};
static BUILT3717A989: Layout = Layout {
    header: BUILT36101749_HEADER,
    bodies: &[
        Some(BUILT370902B8_T01), Some(BUILT370902B8_T02), Some(BUILT36101749_T03),
        Some(BUILT36101749_T04), Some(BUILT370902B8_T05), Some(BUILT36101749_T06),
        Some(BUILT36101749_T07), Some(BUILT36101749_T08), Some(BUILT36101749_T08),
        Some(BUILT36101749_T10), Some(BUILT36101749_T11), Some(BUILT33739B9E_T12),
        Some(BUILT36101749_T13), Some(BUILT36101749_T14), Some(BUILT370902B8_T15),
        Some(V2_6_3_T16), Some(BUILT36101749_T17), Some(BUILT36101749_T18),
        Some(BUILT36101749_T19), None, Some(BUILT36101749_T21), Some(V2_5_T22),
        Some(BUILT3717A989_T23), Some(BUILT36101749_T24), Some(BUILT36101749_T25),
        Some(BUILT36101749_T26), Some(BUILT36101749_T27), Some(V2_6_T28), Some(V2_7_T29),
        Some(BUILT370902B8_T30), Some(BUILT33739B9E_T13), Some(V2_6_3_T32), None, Some(V2_7_T34),
        Some(BUILT36101749_T35), Some(BUILT370902B8_T36), Some(BUILT370902B8_T37),
    ],
    file: FileRecord {
        before_sizes: &[Text::Long],
        folder: None,
        after_times: Text::Long,
        crc_at: 14,
        source_at: Some(26),
    },
    start: BUILT370902B8_START,
    bare: &[20, 33],
};
static BUILT3741ED89: Layout = Layout {
    header: BUILT36101749_HEADER,
    bodies: &[
        Some(BUILT370902B8_T01), Some(BUILT3741ED89_T02), Some(BUILT36101749_T03),
        Some(BUILT36101749_T04), Some(BUILT370902B8_T05), Some(BUILT36101749_T06),
        Some(BUILT36101749_T07), Some(BUILT36101749_T08), Some(BUILT36101749_T08),
        Some(BUILT36101749_T10), Some(BUILT36101749_T11), Some(BUILT33739B9E_T12),
        Some(BUILT36101749_T13), Some(BUILT36101749_T14), Some(BUILT370902B8_T15),
        Some(V2_6_3_T16), Some(BUILT36101749_T17), Some(BUILT36101749_T18),
        Some(BUILT36101749_T19), None, Some(FORK37150603_T21), Some(V2_5_T22),
        Some(BUILT3717A989_T23), Some(BUILT36101749_T24), Some(BUILT36101749_T25),
        Some(BUILT36101749_T26), Some(BUILT36101749_T27), Some(V2_6_T28), Some(V2_7_T29),
        Some(BUILT370902B8_T30), Some(BUILT33739B9E_T13), Some(V2_6_3_T32), None, Some(V2_7_T34),
        Some(BUILT36101749_T35), Some(BUILT370902B8_T36), Some(BUILT370902B8_T37),
    ],
    file: FileRecord {
        before_sizes: &[Text::Long],
        folder: None,
        after_times: Text::Long,
        crc_at: 14,
        source_at: Some(26),
    },
    start: BUILT370902B8_START,
    bare: &[20, 33],
};
static BUILT377CCE3C: Layout = Layout {
    header: BUILT36101749_HEADER,
    bodies: &[
        Some(BUILT370902B8_T01), Some(BUILT370902B8_T02), Some(BUILT36101749_T03),
        Some(BUILT36101749_T04), Some(BUILT370902B8_T05), Some(BUILT36101749_T06),
        Some(BUILT36101749_T07), Some(BUILT36101749_T08), Some(BUILT36101749_T08),
        Some(BUILT36101749_T10), Some(BUILT36101749_T11), Some(BUILT33739B9E_T12),
        Some(BUILT36101749_T13), Some(BUILT36101749_T14), Some(BUILT370902B8_T15),
        Some(V2_6_3_T16), Some(BUILT377CCE3C_T17), Some(BUILT36101749_T18),
        Some(BUILT36101749_T19), None, Some(BUILT36101749_T21), Some(V2_5_T22),
        Some(BUILT3717A989_T23), Some(BUILT36101749_T24), Some(BUILT36101749_T25),
        Some(BUILT36101749_T26), Some(BUILT36101749_T27), Some(V2_6_T28), Some(V2_7_T29),
        Some(BUILT370902B8_T30), Some(BUILT33739B9E_T13), Some(V2_6_3_T32), None, Some(V2_7_T34),
        Some(BUILT36101749_T35), Some(BUILT370902B8_T36), Some(BUILT370902B8_T37),
        Some(BUILT377CCE3C_T38),
    ],
    file: FileRecord {
        before_sizes: &[Text::Long],
        folder: None,
        after_times: Text::Long,
        crc_at: 14,
        source_at: Some(26),
    },
    start: BUILT370902B8_START,
    bare: &[20, 33],
};
static V3_1: Layout = Layout {
    header: BUILT36101749_HEADER,
    bodies: &[
        Some(BUILT370902B8_T01), Some(BUILT3741ED89_T02), Some(BUILT36101749_T03),
        Some(BUILT36101749_T04), Some(BUILT370902B8_T05), Some(BUILT36101749_T06),
        Some(BUILT36101749_T07), Some(BUILT36101749_T08), Some(BUILT36101749_T08),
        Some(BUILT36101749_T10), Some(BUILT36101749_T11), Some(BUILT33739B9E_T12),
        Some(BUILT36101749_T13), Some(BUILT36101749_T14), Some(BUILT370902B8_T15),
        Some(V2_6_3_T16), Some(BUILT377CCE3C_T17), Some(BUILT36101749_T18),
        Some(BUILT36101749_T19), None, Some(FORK37150603_T21), Some(V2_5_T22),
        Some(BUILT3717A989_T23), Some(BUILT36101749_T24), Some(BUILT36101749_T25),
        Some(BUILT36101749_T26), Some(BUILT36101749_T27), Some(V2_6_T28), Some(V2_7_T29),
        Some(BUILT370902B8_T30), Some(BUILT33739B9E_T13), Some(V2_6_3_T32), None, Some(V2_7_T34),
        Some(BUILT36101749_T35), Some(BUILT370902B8_T36), Some(BUILT370902B8_T37),
        Some(BUILT377CCE3C_T38),
    ],
    file: FileRecord {
        before_sizes: &[Text::Long],
        folder: None,
        after_times: Text::Long,
        crc_at: 14,
        source_at: Some(26),
    },
    start: BUILT370902B8_START,
    bare: &[20, 33],
};
static V3_1_1: Layout = Layout {
    header: BUILT36101749_HEADER,
    bodies: &[
        Some(V3_1_1_T01), Some(BUILT3741ED89_T02), Some(BUILT36101749_T03),
        Some(BUILT36101749_T04), Some(BUILT370902B8_T05), Some(BUILT36101749_T06),
        Some(BUILT36101749_T07), Some(BUILT36101749_T08), Some(BUILT36101749_T08),
        Some(BUILT36101749_T10), Some(BUILT36101749_T11), Some(BUILT33739B9E_T12),
        Some(BUILT36101749_T13), Some(BUILT36101749_T14), Some(BUILT370902B8_T15),
        Some(V2_6_3_T16), Some(BUILT377CCE3C_T17), Some(BUILT36101749_T18),
        Some(BUILT36101749_T19), None, Some(FORK37150603_T21), Some(V2_5_T22),
        Some(BUILT3717A989_T23), Some(BUILT36101749_T24), Some(BUILT36101749_T25),
        Some(BUILT36101749_T26), Some(BUILT36101749_T27), Some(V2_6_T28), Some(V2_7_T29),
        Some(BUILT370902B8_T30), Some(BUILT33739B9E_T13), Some(V2_6_3_T32), None, Some(V2_7_T34),
        Some(BUILT36101749_T35), Some(BUILT370902B8_T36), Some(BUILT370902B8_T37),
        Some(BUILT377CCE3C_T38),
    ],
    file: FileRecord {
        before_sizes: &[Text::Long],
        folder: None,
        after_times: Text::Long,
        crc_at: 14,
        source_at: Some(26),
    },
    start: BUILT370902B8_START,
    bare: &[20, 33],
};
static V3_5: Layout = Layout {
    header: BUILT36101749_HEADER,
    bodies: &[
        Some(V3_1_1_T01), Some(V3_5_T02), Some(BUILT36101749_T03), Some(BUILT36101749_T04),
        Some(BUILT370902B8_T05), Some(BUILT36101749_T06), Some(BUILT36101749_T07),
        Some(BUILT36101749_T08), Some(BUILT36101749_T08), Some(BUILT36101749_T10),
        Some(BUILT36101749_T11), Some(BUILT33739B9E_T12), Some(BUILT36101749_T13),
        Some(BUILT36101749_T14), Some(BUILT370902B8_T15), Some(V2_6_3_T16),
        Some(BUILT377CCE3C_T17), Some(BUILT36101749_T18), Some(BUILT36101749_T19), None,
        Some(FORK37150603_T21), Some(V2_5_T22), Some(BUILT3717A989_T23), Some(BUILT36101749_T24),
        Some(BUILT36101749_T25), Some(BUILT36101749_T26), Some(BUILT36101749_T27), Some(V2_6_T28),
        Some(V2_7_T29), Some(BUILT370902B8_T30), Some(BUILT33739B9E_T13), Some(V2_6_3_T32), None,
        Some(V2_7_T34), Some(BUILT36101749_T35), Some(BUILT370902B8_T36), Some(BUILT370902B8_T37),
        Some(BUILT377CCE3C_T38),
    ],
    file: FileRecord {
        before_sizes: &[Text::Long],
        folder: None,
        after_times: Text::Long,
        crc_at: 14,
        source_at: Some(26),
    },
    start: V3_5_START,
    bare: &[20, 33],
};
static BUILT39EB21BD: Layout = Layout {
    header: BUILT36101749_HEADER,
    bodies: &[
        Some(V3_1_1_T01), Some(V3_5_T02), Some(BUILT36101749_T03), Some(BUILT36101749_T04),
        Some(BUILT370902B8_T05), Some(BUILT36101749_T06), Some(BUILT36101749_T07),
        Some(BUILT36101749_T08), Some(BUILT36101749_T08), Some(BUILT36101749_T10),
        Some(BUILT36101749_T11), Some(BUILT33739B9E_T12), Some(BUILT36101749_T13),
        Some(BUILT36101749_T14), Some(BUILT370902B8_T15), Some(V2_6_3_T16),
        Some(BUILT377CCE3C_T17), Some(BUILT36101749_T18), Some(BUILT36101749_T19), None,
        Some(BUILT39EB21BD_T21), Some(V2_5_T22), Some(BUILT3717A989_T23), Some(BUILT36101749_T24),
        Some(BUILT36101749_T25), Some(BUILT36101749_T26), Some(BUILT36101749_T27), Some(V2_6_T28),
        Some(V2_7_T29), Some(BUILT370902B8_T30), Some(BUILT33739B9E_T13), Some(V2_6_3_T32), None,
        Some(V2_7_T34), Some(BUILT36101749_T35), Some(BUILT370902B8_T36), Some(BUILT370902B8_T37),
        Some(BUILT377CCE3C_T38),
    ],
    file: FileRecord {
        before_sizes: &[Text::Long],
        folder: None,
        after_times: Text::Long,
        crc_at: 14,
        source_at: Some(26),
    },
    start: V3_5_START,
    bare: &[20, 33],
};
static V3_6_1: Layout = Layout {
    header: V3_6_1_HEADER,
    bodies: &[
        Some(V3_1_1_T01), Some(V3_5_T02), Some(BUILT36101749_T03), Some(BUILT36101749_T04),
        Some(BUILT370902B8_T05), Some(BUILT36101749_T06), Some(BUILT36101749_T07),
        Some(BUILT36101749_T08), Some(BUILT36101749_T08), Some(BUILT36101749_T10),
        Some(BUILT36101749_T11), Some(BUILT33739B9E_T12), Some(BUILT36101749_T13),
        Some(BUILT36101749_T14), Some(BUILT370902B8_T15), Some(V2_6_3_T16),
        Some(BUILT377CCE3C_T17), Some(BUILT36101749_T18), Some(BUILT36101749_T19), None,
        Some(BUILT39EB21BD_T21), Some(V2_5_T22), Some(BUILT3717A989_T23), Some(BUILT36101749_T24),
        Some(BUILT36101749_T25), Some(BUILT36101749_T26), Some(BUILT36101749_T27), Some(V2_6_T28),
        Some(V2_7_T29), Some(BUILT370902B8_T30), Some(BUILT33739B9E_T13), Some(V2_6_3_T32), None,
        Some(V2_7_T34), Some(BUILT36101749_T35), Some(BUILT370902B8_T36), Some(BUILT370902B8_T37),
        Some(BUILT377CCE3C_T38),
    ],
    file: FileRecord {
        before_sizes: &[Text::Long],
        folder: None,
        after_times: Text::Long,
        crc_at: 14,
        source_at: Some(26),
    },
    start: V3_6_1_START,
    bare: &[20, 33],
};

impl LayoutId {
    pub(super) fn table(self) -> &'static Layout {
        match self {
            Self::Built33739B9E => &BUILT33739B9E,
            Self::Built33D3713B => &BUILT33D3713B,
            Self::V2_4_3 => &V2_4_3,
            Self::V2_5 => &V2_5,
            Self::V2_6 => &V2_6,
            Self::Built35071525 => &BUILT35071525,
            Self::V2_6_2 => &V2_6_2,
            Self::V2_6_3 => &V2_6_3,
            Self::V2_7 => &V2_7,
            Self::V2_7_1 => &V2_7_1,
            Self::Built36101749 => &BUILT36101749,
            Self::V2_8 => &V2_8,
            Self::Built370902B8 => &BUILT370902B8,
            Self::Fork37150603 => &FORK37150603,
            Self::Built3717A989 => &BUILT3717A989,
            Self::Built3741ED89 => &BUILT3741ED89,
            Self::Built377CCE3C => &BUILT377CCE3C,
            Self::V3_1 => &V3_1,
            Self::V3_1_1 => &V3_1_1,
            Self::V3_5 => &V3_5,
            Self::Built39EB21BD => &BUILT39EB21BD,
            Self::V3_6_1 => &V3_6_1,
        }
    }

    /// The steps that read the body of a type `rtype` record, if the layout
    /// has records of that type
    pub(super) fn body(self, rtype: u32) -> Option<&'static [Op]> {
        let index = usize::try_from(rtype).ok()?.checked_sub(1)?;
        self.table().bodies.get(index).copied().flatten()
    }

    /// Whether `rtype` is the type of a record in this layout
    pub(super) fn has_type(self, rtype: u32) -> bool {
        self.body(rtype).is_some()
    }

    /// Whether `rtype` is a type that nothing follows
    pub(super) fn is_bare(self, rtype: u32) -> bool {
        self.table().bare.contains(&rtype)
    }
}

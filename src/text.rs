//! Text encodings of the names stored in archives
//!
//! Neither format stores names as Unicode. A Mac archive holds them in the
//! script of the system the installer was built on, and a Windows one in
//! that system's ANSI code page. The file tables do not say which, but both
//! kinds of installer record their language elsewhere: a Mac installer in
//! the region code of its `vers` resource, a Windows one in the language ID
//! at the head of its language table

use encoding_rs::Encoding;

/// The encoding of the file and folder names in a Mac archive
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum NameEncoding {
    /// Mac OS Roman, used by Western European and American systems
    #[default]
    MacRoman,
    /// Mac OS Japanese, a variant of Shift JIS
    MacJapanese,
    /// Mac OS Korean, a variant of EUC-KR
    MacKorean,
    /// Mac OS Simplified Chinese, a variant of GB 2312
    MacChineseSimplified,
    /// Mac OS Traditional Chinese, a variant of Big5
    MacChineseTraditional,
    /// Mac OS Cyrillic
    MacCyrillic,
}

impl NameEncoding {
    /// The encoding used by systems of the given region, as numbered in a
    /// `vers` resource. Regions that are not listed use Mac Roman
    #[must_use]
    pub const fn from_region(region: u16) -> Self {
        match region {
            14 => Self::MacJapanese,
            51 => Self::MacKorean,
            52 => Self::MacChineseSimplified,
            53 => Self::MacChineseTraditional,
            // Russia, Belarus, Ukraine, Serbia, Macedonia, Bulgaria
            49 | 61 | 62 | 65 | 67 | 72 => Self::MacCyrillic,
            _ => Self::MacRoman,
        }
    }

    /// Parses the name of an encoding as the command line spells it
    #[must_use]
    pub fn from_name(name: &str) -> Option<Self> {
        Some(match name {
            "macroman" => Self::MacRoman,
            "macjapanese" => Self::MacJapanese,
            "mackorean" => Self::MacKorean,
            "macchinesesimp" => Self::MacChineseSimplified,
            "macchinesetrad" => Self::MacChineseTraditional,
            "maccyrillic" => Self::MacCyrillic,
            _ => return None,
        })
    }

    /// Decodes a stored name. A byte that is not a character in the
    /// encoding, and any control character, comes out as `?`
    pub(crate) fn decode(self, bytes: &[u8]) -> String {
        let encoding = match self {
            Self::MacRoman => return bytes.iter().map(|&b| mac_roman_char(b)).collect(),
            Self::MacJapanese => encoding_rs::SHIFT_JIS,
            Self::MacKorean => encoding_rs::EUC_KR,
            Self::MacChineseSimplified => encoding_rs::GBK,
            Self::MacChineseTraditional => encoding_rs::BIG5,
            Self::MacCyrillic => encoding_rs::X_MAC_CYRILLIC,
        };
        tidy(&encoding.decode_without_bom_handling(bytes).0)
    }
}

/// Replaces what cannot be shown in a name: control characters and the
/// marker left where bytes did not decode
fn tidy(decoded: &str) -> String {
    decoded
        .chars()
        .map(|c| {
            if c.is_control() || c == char::REPLACEMENT_CHARACTER {
                '?'
            } else {
                c
            }
        })
        .collect()
}

/// The code page for the names in a Windows installer whose main language
/// has the given Windows language ID. Languages that are not listed use the
/// Western European code page
pub(crate) fn windows_code_page(language: u16) -> &'static Encoding {
    // the low ten bits are the language, the rest the regional variant
    match (language & 0x3ff, language >> 10) {
        (0x11, _) => encoding_rs::SHIFT_JIS,
        (0x12, _) => encoding_rs::EUC_KR,
        // Chinese: Taiwan, Hong Kong and Macau write traditional characters
        (0x04, 1 | 3 | 5) => encoding_rs::BIG5,
        (0x04, _) => encoding_rs::GBK,
        // Russian, Ukrainian, Belarusian, Bulgarian, Macedonian; and Serbian
        // in Cyrillic, which shares its language number with Croatian (1)
        // and Serbian in Latin script (2)
        (0x19 | 0x22 | 0x23 | 0x02 | 0x2f, _) | (0x1a, 3) => encoding_rs::WINDOWS_1251,
        // Czech, Hungarian, Polish, Romanian, Slovak, Slovenian, Croatian
        (0x05 | 0x0e | 0x15 | 0x18 | 0x1b | 0x24 | 0x1a, _) => encoding_rs::WINDOWS_1250,
        (0x08, _) => encoding_rs::WINDOWS_1253,
        (0x1f, _) => encoding_rs::WINDOWS_1254,
        (0x0d, _) => encoding_rs::WINDOWS_1255,
        (0x01, _) => encoding_rs::WINDOWS_1256,
        (0x25..=0x27, _) => encoding_rs::WINDOWS_1257,
        _ => encoding_rs::WINDOWS_1252,
    }
}

/// Decodes a name from a Windows installer
pub(crate) fn decode_windows(bytes: &[u8], code_page: &'static Encoding) -> String {
    tidy(&code_page.decode_without_bom_handling(bytes).0)
}

/// Mac Roman (bytes 0x80-0xFF) to Unicode
#[rustfmt::skip]
const MACROMAN_HIGH: [char; 128] = [
    '\u{00C4}','\u{00C5}','\u{00C7}','\u{00C9}','\u{00D1}','\u{00D6}','\u{00DC}','\u{00E1}',
    '\u{00E0}','\u{00E2}','\u{00E4}','\u{00E3}','\u{00E5}','\u{00E7}','\u{00E9}','\u{00E8}',
    '\u{00EA}','\u{00EB}','\u{00ED}','\u{00EC}','\u{00EE}','\u{00EF}','\u{00F1}','\u{00F3}',
    '\u{00F2}','\u{00F4}','\u{00F6}','\u{00F5}','\u{00FA}','\u{00F9}','\u{00FB}','\u{00FC}',
    '\u{2020}','\u{00B0}','\u{00A2}','\u{00A3}','\u{00A7}','\u{2022}','\u{00B6}','\u{00DF}',
    '\u{00AE}','\u{00A9}','\u{2122}','\u{00B4}','\u{00A8}','\u{2260}','\u{00C6}','\u{00D8}',
    '\u{221E}','\u{00B1}','\u{2264}','\u{2265}','\u{00A5}','\u{00B5}','\u{2202}','\u{2211}',
    '\u{220F}','\u{03C0}','\u{222B}','\u{00AA}','\u{00BA}','\u{03A9}','\u{00E6}','\u{00F8}',
    '\u{00BF}','\u{00A1}','\u{00AC}','\u{221A}','\u{0192}','\u{2248}','\u{2206}','\u{00AB}',
    '\u{00BB}','\u{2026}','\u{00A0}','\u{00C0}','\u{00C3}','\u{00D5}','\u{0152}','\u{0153}',
    '\u{2013}','\u{2014}','\u{201C}','\u{201D}','\u{2018}','\u{2019}','\u{00F7}','\u{25CA}',
    '\u{00FF}','\u{0178}','\u{2044}','\u{20AC}','\u{2039}','\u{203A}','\u{FB01}','\u{FB02}',
    '\u{2021}','\u{00B7}','\u{201A}','\u{201E}','\u{2030}','\u{00C2}','\u{00CA}','\u{00C1}',
    '\u{00CB}','\u{00C8}','\u{00CD}','\u{00CE}','\u{00CF}','\u{00CC}','\u{00D3}','\u{00D4}',
    '\u{F8FF}','\u{00D2}','\u{00DA}','\u{00DB}','\u{00D9}','\u{0131}','\u{02C6}','\u{02DC}',
    '\u{00AF}','\u{02D8}','\u{02D9}','\u{02DA}','\u{00B8}','\u{02DD}','\u{02DB}','\u{02C7}',
];

fn mac_roman_char(b: u8) -> char {
    if b.is_ascii_graphic() || b == b' ' {
        b as char
    } else if b >= 0x80 {
        MACROMAN_HIGH[(b - 0x80) as usize]
    } else {
        '?'
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mac_roman_keeps_ascii_and_maps_the_upper_half() {
        assert_eq!(NameEncoding::MacRoman.decode(b"Read Me"), "Read Me");
        // "Purple Moon" followed by the folder sign, and an accented name
        assert_eq!(NameEncoding::MacRoman.decode(b"Moon \xC4"), "Moon \u{0192}");
        assert_eq!(NameEncoding::MacRoman.decode(b"L\x8Eame"), "L\u{e9}ame");
        // a carriage return, as in the "Icon\r" file, is not a printable name
        assert_eq!(NameEncoding::MacRoman.decode(b"Icon\r"), "Icon?");
    }

    #[test]
    fn mac_japanese_decodes_kana_and_kanji() {
        // katakana for "format", as a folder name
        let bytes = b"\x83t\x83H\x81[\x83}\x83b\x83g";
        assert_eq!(
            NameEncoding::MacJapanese.decode(bytes),
            "\u{30d5}\u{30a9}\u{30fc}\u{30de}\u{30c3}\u{30c8}"
        );
        // the same bytes read as Mac Roman are not a name
        assert_eq!(
            NameEncoding::MacRoman.decode(bytes),
            "\u{c9}t\u{c9}H\u{c5}[\u{c9}}\u{c9}b\u{c9}g"
        );
        // ASCII is unchanged, and a lone lead byte does not swallow the name
        assert_eq!(NameEncoding::MacJapanese.decode(b"ReadMe ja"), "ReadMe ja");
        assert_eq!(NameEncoding::MacJapanese.decode(b"ab\x83"), "ab?");
    }

    #[test]
    fn region_codes_pick_the_script() {
        assert_eq!(NameEncoding::from_region(0), NameEncoding::MacRoman);
        assert_eq!(NameEncoding::from_region(1), NameEncoding::MacRoman);
        assert_eq!(NameEncoding::from_region(14), NameEncoding::MacJapanese);
        assert_eq!(NameEncoding::from_region(51), NameEncoding::MacKorean);
        // 23 is Cyprus and 79 Wales, which wrote Mac Roman or Greek
        assert_eq!(NameEncoding::from_region(23), NameEncoding::MacRoman);
        assert_eq!(NameEncoding::from_region(79), NameEncoding::MacRoman);
        assert_eq!(NameEncoding::from_region(65), NameEncoding::MacCyrillic);
        assert_eq!(
            NameEncoding::from_region(52),
            NameEncoding::MacChineseSimplified
        );
        assert_eq!(
            NameEncoding::from_region(53),
            NameEncoding::MacChineseTraditional
        );
        assert_eq!(
            NameEncoding::from_name("macjapanese"),
            Some(NameEncoding::MacJapanese)
        );
        assert_eq!(NameEncoding::from_name("klingon"), None);
    }

    #[test]
    fn windows_language_picks_the_code_page() {
        assert_eq!(windows_code_page(0x0409), encoding_rs::WINDOWS_1252);
        assert_eq!(windows_code_page(0x0009), encoding_rs::WINDOWS_1252);
        assert_eq!(windows_code_page(0x0411), encoding_rs::SHIFT_JIS);
        assert_eq!(windows_code_page(0x0412), encoding_rs::EUC_KR);
        assert_eq!(windows_code_page(0x0404), encoding_rs::BIG5);
        assert_eq!(windows_code_page(0x0804), encoding_rs::GBK);
        assert_eq!(windows_code_page(0x0419), encoding_rs::WINDOWS_1251);
        assert_eq!(windows_code_page(0x041a), encoding_rs::WINDOWS_1250);
        assert_eq!(windows_code_page(0x081a), encoding_rs::WINDOWS_1250);
        assert_eq!(windows_code_page(0x0c1a), encoding_rs::WINDOWS_1251);
        // a Western name with an accent, which is not valid UTF-8
        assert_eq!(
            decode_windows(b"Fran\xE7ais.txt", encoding_rs::WINDOWS_1252),
            "Fran\u{e7}ais.txt"
        );
        assert_eq!(
            decode_windows(b"\x93\xFA\x96{\x8C\xEA", encoding_rs::SHIFT_JIS),
            "\u{65e5}\u{672c}\u{8a9e}"
        );
    }
}

//! `AppleDouble` sidecar files
//!
//! `AppleDouble` keeps a Mac file on a filesystem without forks as two files:
//! the data fork under the file's own name, and a second file named `._name`
//! holding the resource fork and the Finder information. macOS reads the pair
//! back as one file
//!
//! The format allows any set of entries in any order, but macOS only accepts
//! the exact layout it writes itself: a Finder information entry followed by
//! a resource fork entry. That is the layout produced here. Dates therefore
//! have no entry of their own; the modification time is set on the files

use crate::FileEntry;

const MAGIC: u32 = 0x0005_1607;
const VERSION: u32 = 0x0002_0000;
/// The 16 bytes after the version, as macOS fills them
const FILLER: &[u8; 16] = b"Mac OS X        ";
/// Magic, version, filler and the entry count
const HEADER_LEN: usize = 26;
/// Entry ID, offset and length
const DESCRIPTOR_LEN: usize = 12;
const FINDER_INFO_LEN: usize = 32;

const ENTRY_RESOURCE_FORK: u32 = 2;
const ENTRY_FINDER_INFO: u32 = 9;

/// The name of the sidecar that goes next to a file called `name`
#[must_use]
pub fn sidecar_name(name: &str) -> String {
    format!("._{name}")
}

/// Builds the contents of the `._name` file for `entry`: its Finder
/// information, then its resource fork, which may be empty
#[must_use]
pub fn encode(entry: &FileEntry, rsrc: &[u8]) -> Vec<u8> {
    let finder_info_at = HEADER_LEN + 2 * DESCRIPTOR_LEN;
    let rsrc_at = finder_info_at + FINDER_INFO_LEN;

    let mut out = Vec::with_capacity(rsrc_at + rsrc.len());
    out.extend_from_slice(&MAGIC.to_be_bytes());
    out.extend_from_slice(&VERSION.to_be_bytes());
    out.extend_from_slice(FILLER);
    out.extend_from_slice(&2u16.to_be_bytes());
    for (id, offset, len) in [
        (ENTRY_FINDER_INFO, finder_info_at, FINDER_INFO_LEN),
        (ENTRY_RESOURCE_FORK, rsrc_at, rsrc.len()),
    ] {
        out.extend_from_slice(&id.to_be_bytes());
        out.extend_from_slice(&be32(offset));
        out.extend_from_slice(&be32(len));
    }
    out.extend_from_slice(&entry.finder_info());
    out.extend_from_slice(rsrc);
    out
}

/// Fork sizes in the archive are 32-bit, so every length here fits
fn be32(n: usize) -> [u8; 4] {
    u32::try_from(n).unwrap_or(u32::MAX).to_be_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn u32_at(buf: &[u8], off: usize) -> u32 {
        u32::from_be_bytes(buf[off..off + 4].try_into().unwrap())
    }

    /// The entries of an encoded file as `(id, contents)`
    fn entries(buf: &[u8]) -> Vec<(u32, &[u8])> {
        assert_eq!(u32_at(buf, 0), MAGIC);
        assert_eq!(u32_at(buf, 4), VERSION);
        let count = usize::from(u16::from_be_bytes([buf[24], buf[25]]));
        (0..count)
            .map(|i| {
                let d = HEADER_LEN + i * DESCRIPTOR_LEN;
                let (off, len) = (u32_at(buf, d + 4) as usize, u32_at(buf, d + 8) as usize);
                (u32_at(buf, d), &buf[off..off + len])
            })
            .collect()
    }

    fn entry() -> FileEntry {
        let mut e = crate::mac::testutil::blank_entry();
        e.file_type = *b"TEXT";
        e.creator = *b"ttxt";
        e.finder_flags = 0x2100;
        e
    }

    #[test]
    fn holds_finder_info_then_resource_fork() {
        let rsrc = b"resource fork bytes";
        let buf = encode(&entry(), rsrc);
        let found = entries(&buf);
        assert_eq!(found.len(), 2);

        let (id, info) = found[0];
        assert_eq!(id, ENTRY_FINDER_INFO);
        assert_eq!(info.len(), 32);
        assert_eq!(&info[..10], b"TEXTttxt\x21\x00");
        assert!(info[10..].iter().all(|&b| b == 0));

        assert_eq!(found[1], (ENTRY_RESOURCE_FORK, &rsrc[..]));
        // the two entries follow the header back to back and fill the file
        assert_eq!(buf.len(), 50 + 32 + rsrc.len());
    }

    #[test]
    fn an_empty_resource_fork_keeps_its_entry() {
        let buf = encode(&entry(), b"");
        let found = entries(&buf);
        assert_eq!(found[1], (ENTRY_RESOURCE_FORK, &b""[..]));
        assert_eq!(buf.len(), 82);
    }

    #[test]
    fn sidecar_is_named_with_a_dot_underscore() {
        assert_eq!(sidecar_name("Read Me"), "._Read Me");
    }
}

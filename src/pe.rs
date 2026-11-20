//! Minimal PE parser for extracting VISE payloads from Windows executables
//!
//! Searches for an `_mvdata` section first, then falls back to the PE overlay
//! (data appended past the last section). Only parses enough of the PE headers
//! to locate section boundaries -- no imports, exports, or relocations

use crate::Error;

/// Extracts the VISE payload from a PE executable
///
/// Returns `(payload_slice, file_offset)`: the `_mvdata` section contents if
/// present, otherwise the overlay region past the last section. The file
/// offset is needed to translate V0-era blob offsets (which are file-relative)
///
/// # Errors
///
/// Returns [`Error::InvalidArchive`] if the data is not a valid PE or contains
/// no VISE payload
pub fn extract_payload(data: &[u8]) -> Result<(&[u8], usize), Error> {
    if data.len() < 0x40 || &data[..2] != b"MZ" {
        return Err(Error::InvalidArchive("not a PE executable".into()));
    }

    let pe_off = read_u32(data, 0x3C)? as usize;
    // everything from the PE signature on; header offsets below are relative
    // to it, so a pointer near the top of the address space cannot overflow
    let pe = data
        .get(pe_off..)
        .filter(|pe| pe.len() >= 24 && pe.starts_with(b"PE\x00\x00"))
        .ok_or_else(|| Error::InvalidArchive("invalid PE signature".into()))?;

    let num_sections = read_u16(pe, 6)? as usize;
    let opt_hdr_size = read_u16(pe, 20)? as usize;
    let sections = pe
        .get(24 + opt_hdr_size..)
        .ok_or_else(|| Error::InvalidArchive("section table truncated".into()))?;

    let mut mvdata_off = 0usize;
    let mut mvdata_sz = 0usize;
    let mut last_end = 0usize;

    for i in 0..num_sections {
        let entry = sections
            .get(i * 40..)
            .and_then(|rest| rest.get(..40))
            .ok_or_else(|| Error::InvalidArchive("section table truncated".into()))?;
        let raw_size = read_u32(entry, 16)? as usize;
        let raw_off = read_u32(entry, 20)? as usize;
        let end = raw_off.saturating_add(raw_size);
        if end > last_end {
            last_end = end;
        }

        if entry.starts_with(b"_mvdata") {
            mvdata_off = raw_off;
            mvdata_sz = raw_size;
        }
    }

    if mvdata_sz > 0 {
        let end = mvdata_off
            .checked_add(mvdata_sz)
            .ok_or_else(|| Error::InvalidArchive("_mvdata offset overflow".into()))?;
        if end > data.len() {
            return Err(Error::InvalidArchive(
                "_mvdata section extends past file".into(),
            ));
        }
        return Ok((&data[mvdata_off..end], mvdata_off));
    }

    if last_end < data.len() {
        let overlay = &data[last_end..];
        if overlay.len() > 8 {
            return Ok((overlay, last_end));
        }
    }

    Err(Error::InvalidArchive(
        "no _mvdata section or overlay found".into(),
    ))
}

fn read_array<const N: usize>(data: &[u8], off: usize) -> Result<[u8; N], Error> {
    off.checked_add(N)
        .and_then(|end| data.get(off..end))
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or_else(|| Error::InvalidArchive(format!("PE truncated at 0x{off:x}")))
}

fn read_u16(data: &[u8], off: usize) -> Result<u16, Error> {
    read_array(data, off).map(u16::from_le_bytes)
}

fn read_u32(data: &[u8], off: usize) -> Result<u32, Error> {
    read_array(data, off).map(u32::from_le_bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_pe(sections: &[(&[u8; 8], u32, u32)], extra: &[u8]) -> Vec<u8> {
        let pe_off = 0x80u32;
        let num_sec: u16 = sections.len().try_into().unwrap();
        let opt_hdr_size = 0xE0u16;
        let sec_table = pe_off as usize + 24 + opt_hdr_size as usize;
        let total_headers = sec_table + sections.len() * 40;
        let mut buf = vec![0u8; total_headers];

        buf[0] = b'M';
        buf[1] = b'Z';
        buf[0x3C..0x40].copy_from_slice(&pe_off.to_le_bytes());
        buf[pe_off as usize..pe_off as usize + 4].copy_from_slice(b"PE\x00\x00");
        buf[pe_off as usize + 6..pe_off as usize + 8].copy_from_slice(&num_sec.to_le_bytes());
        buf[pe_off as usize + 20..pe_off as usize + 22]
            .copy_from_slice(&opt_hdr_size.to_le_bytes());

        for (i, (name, raw_off, raw_sz)) in sections.iter().enumerate() {
            let entry = sec_table + i * 40;
            buf[entry..entry + 8].copy_from_slice(*name);
            buf[entry + 16..entry + 20].copy_from_slice(&raw_sz.to_le_bytes());
            buf[entry + 20..entry + 24].copy_from_slice(&raw_off.to_le_bytes());
        }

        let needed = sections
            .iter()
            .map(|(_, off, sz)| *off as usize + *sz as usize)
            .max()
            .unwrap_or(total_headers);
        buf.resize(needed, 0);
        buf.extend_from_slice(extra);
        buf
    }

    #[test]
    fn finds_mvdata_section() {
        let sections = [
            (b".text\x00\x00\x00", 0x200u32, 0x100u32),
            (b"_mvdata\x00", 0x300u32, 0x50u32),
        ];
        let mut pe = make_pe(&sections, &[]);
        pe[0x300..0x304].copy_from_slice(b"SIVM");
        let (payload, off) = extract_payload(&pe).unwrap();
        assert_eq!(payload.len(), 0x50);
        assert_eq!(&payload[..4], b"SIVM");
        assert_eq!(off, 0x300);
    }

    #[test]
    fn falls_back_to_overlay() {
        let sections = [(b".text\x00\x00\x00", 0x200u32, 0x100u32)];
        let pe = make_pe(&sections, b"ESIV overlay data here");
        let (payload, _off) = extract_payload(&pe).unwrap();
        assert_eq!(&payload[..4], b"ESIV");
    }

    #[test]
    fn rejects_non_pe() {
        assert!(extract_payload(b"not a PE file").is_err());
    }
}

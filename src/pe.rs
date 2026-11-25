//! Minimal parser of Windows executables, for extracting VISE payloads
//!
//! In a 32-bit executable (PE) it searches for an `_mvdata` section first,
//! then falls back to the overlay (data appended past the last section). In
//! a 16-bit one (NE) the payload follows the executable. Only enough of the
//! headers is read to find where the executable's own data ends -- no
//! imports, exports, or relocations

use crate::Error;

/// Extracts the VISE payload from a Windows executable
///
/// Returns `(payload_slice, file_offset)`: the `_mvdata` section contents if
/// present, otherwise what follows the executable. The file offset is needed
/// to translate the blob offsets of the older runtimes, which count from the
/// start of the file
///
/// # Errors
///
/// Returns [`Error::InvalidArchive`] if the data is not a valid executable
/// or contains no VISE payload
pub fn extract_payload(data: &[u8]) -> Result<(&[u8], usize), Error> {
    if data.len() < 0x40 || &data[..2] != b"MZ" {
        return Err(Error::InvalidArchive("not a Windows executable".into()));
    }

    let pe_off = read_u32(data, 0x3C)? as usize;
    if data.get(pe_off..).is_some_and(|ne| ne.starts_with(b"NE")) {
        return ne_overlay(data, pe_off);
    }
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

/// The data past the end of a 16-bit executable, whose header is at
/// `ne_off`. The executable ends where the last of its segments, its
/// resources and its table of non-resident names does
fn ne_overlay(data: &[u8], ne_off: usize) -> Result<(&[u8], usize), Error> {
    let ne = &data[ne_off..];
    let u16_at = |off: usize| read_u16(ne, off).map(usize::from);
    let shift =
        |value: usize, by: usize| u32::try_from(by).ok().and_then(|by| value.checked_shl(by));
    let overflow = || Error::InvalidArchive("executable header fields out of range".into());

    let names = (read_u32(ne, 0x2C)? as usize).saturating_add(u16_at(0x20)?);
    let mut end = names;

    let segment_shift = u16_at(0x32)?;
    let segment_table = u16_at(0x22)?;
    for i in 0..u16_at(0x1C)? {
        let entry = segment_table + i * 8;
        let (sector, len) = (u16_at(entry)?, u16_at(entry + 2)?);
        // a segment with no sector has no data in the file; a length of 0
        // stands for 64 KiB
        if sector != 0 {
            let len = if len == 0 { 0x1_0000 } else { len };
            end = end.max(shift(sector, segment_shift).ok_or_else(overflow)? + len);
        }
    }

    // the resource table is a shift, then for each type an ID, a count and
    // four more bytes, followed by 12 bytes for each resource: its offset
    // and its length in units of the shift. A type ID of 0 ends it. The
    // table is absent when the next table starts where it would
    let mut at = u16_at(0x24)?;
    if at != u16_at(0x26)? {
        let resource_shift = u16_at(at)?;
        at += 2;
        while u16_at(at)? != 0 {
            let count = u16_at(at + 2)?;
            at += 8;
            for _ in 0..count {
                let past = u16_at(at)? + u16_at(at + 2)?;
                end = end.max(shift(past, resource_shift).ok_or_else(overflow)?);
                at += 12;
            }
        }
    }

    match data.get(end..) {
        Some(overlay) if overlay.len() > 8 => Ok((overlay, end)),
        _ => Err(Error::InvalidArchive(
            "nothing follows the 16-bit executable".into(),
        )),
    }
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
    fn finds_what_follows_a_16_bit_executable() {
        // one segment of 0x30 bytes in sector 1 (sectors of 0x200), and one
        // resource of two units of 0x10 at unit 0x30: the file ends at 0x320
        let ne_off = 0x40;
        let mut data = vec![0u8; 0x320];
        data[..2].copy_from_slice(b"MZ");
        data[0x3C] = 0x40;
        let put = |data: &mut Vec<u8>, off: usize, v: u16| {
            data[ne_off + off..][..2].copy_from_slice(&v.to_le_bytes());
        };
        data[ne_off..ne_off + 2].copy_from_slice(b"NE");
        put(&mut data, 0x1C, 1); // segments
        put(&mut data, 0x22, 0x40); // segment table
        put(&mut data, 0x24, 0x48); // resource table
        put(&mut data, 0x26, 0x60); // the table after it
        put(&mut data, 0x32, 9); // segment shift
        put(&mut data, 0x40, 1);
        put(&mut data, 0x42, 0x30);
        put(&mut data, 0x48, 4); // resource shift
        put(&mut data, 0x4A, 0x8001); // a type
        put(&mut data, 0x4C, 1); // with one resource
        put(&mut data, 0x52, 0x30);
        put(&mut data, 0x54, 2);
        data.extend_from_slice(b"ESIV and more");
        let (payload, off) = extract_payload(&data).unwrap();
        assert_eq!(off, 0x320);
        assert_eq!(payload, b"ESIV and more");

        // with nothing after it there is no payload
        assert!(extract_payload(&data[..0x320]).is_err());
        // a table that runs off the end is an error, not a panic
        put(&mut data, 0x24, 0xFFF0);
        assert!(extract_payload(&data).is_err());
    }

    #[test]
    fn rejects_non_pe() {
        assert!(extract_payload(b"not a PE file").is_err());
    }
}

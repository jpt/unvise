use std::path::{Path, PathBuf};
use std::process;

use unvise::{Archive, InputKind, Progress, SkipReason, WinArchive};

const USAGE: &str = "\
usage: unvise <vise_installer> [output_dir]

Extracts files from Installer VISE archives (Mac and Windows).
Accepts raw data forks, MacBinary-wrapped files, or Windows PE executables.
The output directory defaults to unvise_out/

options:
  -h, --help       show this help
  -V, --version    show the version";

fn main() {
    let mut args = std::env::args_os().skip(1);
    let Some(first) = args.next() else {
        eprintln!("{USAGE}");
        process::exit(1);
    };
    if first == "--version" || first == "-V" {
        println!("unvise {}", env!("CARGO_PKG_VERSION"));
        return;
    }
    if first == "--help" || first == "-h" {
        println!("{USAGE}");
        return;
    }

    let input = PathBuf::from(first);
    let out_dir = args
        .next()
        .map_or_else(|| PathBuf::from("unvise_out"), PathBuf::from);

    let raw = match std::fs::read(&input) {
        Ok(d) => d,
        Err(e) => fail(&format!("{}: {e}", input.display())),
    };

    match unvise::detect_format(raw) {
        InputKind::Mac(data) => extract_mac(data, &input, &out_dir),
        InputKind::WinPe(data) => extract_win(data, &input, &out_dir),
        _ => fail("not a recognized VISE archive"),
    }
}

fn fail(message: &str) -> ! {
    eprintln!("error: {message}");
    process::exit(1);
}

fn extract_mac(data: Vec<u8>, input: &Path, out_dir: &Path) {
    let segments = find_segments(&data, input);
    let archive = if segments.is_empty() {
        Archive::parse(data)
    } else {
        Archive::parse_with_segments(data, &segments)
    };
    let archive = archive.unwrap_or_else(|e| fail(&e.to_string()));

    let info = &archive.info;
    let files = archive.files().count();
    let stubs = archive.files().filter(|f| f.is_stub()).count();
    eprintln!("VISE format: {:02x} {:02x}", info.fmt_major, info.fmt_minor);
    eprintln!("CVCT: {files} entries, {} segments", info.num_segments);
    eprintln!("{} extractable, {stubs} condition records", files - stubs);
    eprintln!();
    eprintln!("Extracting to {}/", out_dir.display());
    eprintln!();

    let result = archive
        .extract_with(out_dir, report)
        .unwrap_or_else(|e| fail(&e.to_string()));
    finish(result);
}

fn extract_win(data: Vec<u8>, input: &Path, out_dir: &Path) {
    let qdat = match unvise::pe::extract_payload(&data) {
        Ok((payload, _)) => find_qdat(payload, input),
        Err(e) => fail(&e.to_string()),
    };
    let archive = WinArchive::from_pe(data, qdat).unwrap_or_else(|e| fail(&e.to_string()));

    let info = &archive.info;
    eprintln!(
        "Windows VISE (version {}, flags 0x{:08x})",
        info.version, info.flags
    );
    eprintln!("{} entries found", info.entries.len());
    eprintln!();
    eprintln!("Extracting to {}/", out_dir.display());
    eprintln!();

    let result = archive
        .extract_with(out_dir, report)
        .unwrap_or_else(|e| fail(&e.to_string()));
    finish(result);
}

/// Prints one line per entry as the library works through the archive
fn report(progress: Progress<'_>) {
    let shown = |name| {
        if str::is_empty(name) {
            "(unnamed)"
        } else {
            name
        }
    };
    match progress {
        Progress::Extracted {
            name,
            data_len,
            rsrc_len: Some(rsrc_len),
        } => eprintln!("  {name} ({data_len} + {rsrc_len} bytes)"),
        Progress::Extracted {
            name,
            data_len,
            rsrc_len: None,
        } => eprintln!("  {name} ({data_len} bytes)"),
        Progress::Skipped {
            name,
            reason: SkipReason::Condition { flags },
        } => eprintln!("  [condition] {} (flags=0x{flags:08x})", shown(name)),
        Progress::Skipped { name, reason } => eprintln!("  [{reason}] {}", shown(name)),
        Progress::Failed { name, error } => eprintln!("  FAIL {}: {error}", shown(name)),
        Progress::BudgetExceeded { budget } => eprintln!(
            "  aborting: extracted output exceeds {budget} byte budget (possible decompression bomb)"
        ),
        _ => {}
    }
}

fn finish(result: unvise::ExtractResult) {
    eprintln!();
    eprintln!(
        "Done: {} extracted, {} skipped, {} failed",
        result.extracted, result.skipped, result.failed
    );
    if result.failed > 0 {
        process::exit(1);
    }
}

/// The directory holding `path`. A bare filename has an empty parent, which
/// cannot be listed, so that case is the current directory
fn containing_dir(path: &Path) -> &Path {
    match path.parent() {
        Some(dir) if !dir.as_os_str().is_empty() => dir,
        _ => Path::new("."),
    }
}

/// Searches for a companion `.qdat` file in the same directory as the exe.
/// Returns `None` for full installers or if no matching qdat is found
fn find_qdat(payload: &[u8], input: &Path) -> Option<Vec<u8>> {
    if !WinArchive::is_stub(payload) {
        return None;
    }
    let session = WinArchive::session_id(payload)?;
    let dir = containing_dir(input);

    for entry in std::fs::read_dir(dir).ok()?.flatten() {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("qdat") {
            continue;
        }
        if let Ok(data) = std::fs::read(&path) {
            if WinArchive::validate_qdat(&data, session) {
                eprintln!("Companion volume: {}", path.display());
                return Some(data);
            }
        }
    }

    eprintln!(
        "warning: stub installer but no matching .qdat found in {}",
        dir.display()
    );
    None
}

/// Smallest segment file the library accepts: the SVCT header plus four bytes
const MIN_SEGMENT_LEN: usize = 0x30;

/// Scans the same directory as the archive for VISE segment files.
/// A segment file starts with SVCT and carries a segment number > 1
/// at offset 0x04. Reads through MacBinary wrappers
///
/// Returns the unbroken run of segments 2, 3, ... in order. File offsets
/// count through the segments, so one after a gap or a repeat cannot be placed
fn find_segments(main_data: &[u8], input: &Path) -> Vec<Vec<u8>> {
    let num_segments = match main_data.get(..0x18) {
        Some(head) if head.starts_with(b"SVCT") => {
            u32::from_be_bytes([head[0x14], head[0x15], head[0x16], head[0x17]])
        }
        _ => 0,
    };
    if num_segments <= 1 {
        return Vec::new();
    }

    let dir = containing_dir(input);
    let mut found: Vec<(u32, PathBuf, Vec<u8>)> = Vec::new();
    for entry in std::fs::read_dir(dir).into_iter().flatten().flatten() {
        let path = entry.path();
        if !path.is_file() || path.file_name() == input.file_name() {
            continue;
        }

        // Probe the first 132 bytes before reading the full file
        let mut probe = [0u8; 132];
        let Ok(mut f) = std::fs::File::open(&path) else {
            continue;
        };
        let Ok(n) = std::io::Read::read(&mut f, &mut probe) else {
            continue;
        };
        drop(f);

        let is_svct =
            (n >= 0x2c && &probe[..4] == b"SVCT") || (n >= 128 + 4 && &probe[128..132] == b"SVCT");
        if !is_svct {
            continue;
        }

        let Ok(data) = std::fs::read(&path) else {
            continue;
        };
        let seg_data = if data.starts_with(b"SVCT") {
            data
        } else {
            unvise::macbinary::strip(data)
        };
        if seg_data.len() < MIN_SEGMENT_LEN || !seg_data.starts_with(b"SVCT") {
            continue;
        }

        let seq = u32::from_be_bytes([seg_data[4], seg_data[5], seg_data[6], seg_data[7]]);
        if seq > 1 {
            found.push((seq, path, seg_data));
        }
    }
    found.sort_by_key(|&(seq, _, _)| seq);

    let mut segments = Vec::new();
    let mut want = 2u32;
    for (seq, path, data) in found {
        if seq == want {
            eprintln!("Segment {seq}: {}", path.display());
            segments.push(data);
            want += 1;
        } else {
            eprintln!(
                "warning: ignoring segment {seq} ({}): segment {want} is needed next",
                path.display()
            );
        }
    }

    if segments.is_empty() {
        eprintln!(
            "warning: archive declares {num_segments} segments but no usable segment files found in {}",
            dir.display()
        );
    } else {
        eprintln!("{} segment file(s) found", segments.len());
    }

    segments
}

#[cfg(test)]
mod tests {
    use super::containing_dir;
    use std::path::Path;

    #[test]
    fn bare_filename_is_in_the_current_directory() {
        assert_eq!(containing_dir(Path::new("Installer")), Path::new("."));
        assert_eq!(containing_dir(Path::new("./Installer")), Path::new("."));
        assert_eq!(containing_dir(Path::new("a/b/Installer")), Path::new("a/b"));
        assert_eq!(containing_dir(Path::new("/Installer")), Path::new("/"));
    }
}

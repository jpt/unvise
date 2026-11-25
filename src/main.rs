use std::path::{Path, PathBuf};
use std::process;

use unvise::{
    Archive, ExtractOptions, ForkFormat, InputKind, NameEncoding, Progress, SkipReason, WinArchive,
};

const USAGE: &str = "\
usage: unvise [options] <vise_installer> [output_dir]

Extracts files from Installer VISE archives (Mac and Windows).
Accepts raw data forks, MacBinary-wrapped files, or Windows executables.
The output directory defaults to unvise_out/

Files that belong with the installer are picked up from where it sits: Mac
segment files, a Windows .qdat volume, the later parts of a multi-part
Windows installer (Setup.002, ...), and the other half of a Mac OS X
installer bundle.

options:
  --forks <format>   how Mac resource forks and Finder information are written:
                       rsrc         resource fork as name.rsrc (default);
                                    type and creator codes are not kept
                       appledouble  ._name file with the resource fork,
                                    type, creator and Finder flags
                       macbinary    one name.bin file holding both forks,
                                    type, creator, Finder flags and dates
  --encoding <name>  text encoding of the names in a Mac archive: macroman,
                     macjapanese, mackorean, macchinesesimp, macchinesetrad
                     or maccyrillic. By default it is read from the
                     installer's resources when the input is a MacBinary
                     file, and is macroman otherwise. Windows installers
                     record their language and need no option
  -h, --help         show this help
  -V, --version      show the version";

/// What the command line asked for
struct Args {
    input: PathBuf,
    out_dir: PathBuf,
    forks: ForkFormat,
    /// `None` to take the encoding from the installer itself
    encoding: Option<NameEncoding>,
}

fn parse_fork_format(value: &str) -> Result<ForkFormat, String> {
    match value {
        "rsrc" => Ok(ForkFormat::Rsrc),
        "appledouble" => Ok(ForkFormat::AppleDouble),
        "macbinary" => Ok(ForkFormat::MacBinary),
        other => Err(format!(
            "unknown fork format '{other}' (expected rsrc, appledouble or macbinary)"
        )),
    }
}

/// Reads the arguments after the program name. `Ok(None)` means help or the
/// version was asked for and has been printed
fn parse_args(args: impl IntoIterator<Item = std::ffi::OsString>) -> Result<Option<Args>, String> {
    let mut args = args.into_iter();
    let mut positional: Vec<PathBuf> = Vec::new();
    let mut forks = ForkFormat::default();
    let mut encoding = None;
    let parse_encoding = |value: &str| {
        NameEncoding::from_name(value).ok_or_else(|| format!("unknown encoding '{value}'"))
    };
    // after `--`, everything is a path, even if it starts with a dash
    let mut options_done = false;

    while let Some(arg) = args.next() {
        let text = arg.to_str().filter(|t| !options_done && t.starts_with('-'));
        match text {
            None | Some("-") => positional.push(PathBuf::from(arg)),
            Some("--") => options_done = true,
            Some("-V" | "--version") => {
                println!("unvise {}", env!("CARGO_PKG_VERSION"));
                return Ok(None);
            }
            Some("-h" | "--help") => {
                println!("{USAGE}");
                return Ok(None);
            }
            Some("--forks") => {
                let value = args.next().ok_or("--forks needs a format")?;
                forks = parse_fork_format(&value.to_string_lossy())?;
            }
            Some("--encoding") => {
                let value = args.next().ok_or("--encoding needs a name")?;
                encoding = Some(parse_encoding(&value.to_string_lossy())?);
            }
            Some(other) => {
                if let Some(value) = other.strip_prefix("--forks=") {
                    forks = parse_fork_format(value)?;
                } else if let Some(value) = other.strip_prefix("--encoding=") {
                    encoding = Some(parse_encoding(value)?);
                } else {
                    return Err(format!("unknown option '{other}'"));
                }
            }
        }
    }

    let mut positional = positional.into_iter();
    let input = positional.next().ok_or("no installer given")?;
    let out_dir = positional
        .next()
        .unwrap_or_else(|| PathBuf::from("unvise_out"));
    if positional.next().is_some() {
        return Err("too many arguments".into());
    }
    Ok(Some(Args {
        input,
        out_dir,
        forks,
        encoding,
    }))
}

fn main() {
    let args = match parse_args(std::env::args_os().skip(1)) {
        Ok(Some(args)) => args,
        Ok(None) => return,
        Err(message) => {
            eprintln!("error: {message}\n\n{USAGE}");
            process::exit(1);
        }
    };

    let raw = match std::fs::read(&args.input) {
        Ok(d) => d,
        Err(e) => fail(&format!("{}: {e}", args.input.display())),
    };

    // the resource fork that says which script the names are in is dropped
    // when the MacBinary wrapper is, so it is read first
    let encoding = args
        .encoding
        .unwrap_or_else(|| unvise::mac_name_encoding(&raw));

    match unvise::detect_format(raw) {
        InputKind::Mac(data) => extract_mac(data, &args, encoding),
        InputKind::WinPe(data) => extract_win(data, &args.input, &args.out_dir),
        _ => fail("not a recognized VISE archive"),
    }
}

fn fail(message: &str) -> ! {
    eprintln!("error: {message}");
    process::exit(1);
}

fn extract_mac(data: Vec<u8>, args: &Args, encoding: NameEncoding) {
    let (input, out_dir) = (args.input.as_path(), args.out_dir.as_path());
    let options = ExtractOptions::default().with_forks(args.forks);
    let segments = find_segments(&data, input);
    let archive = if let Some(pair) = find_bundle_pair(&data, input) {
        match pair {
            BundlePair::Data(data_file) => {
                Archive::parse_with_data_file(&data, data_file, encoding)
            }
            BundlePair::Table(table) => Archive::parse_with_data_file(&table, data, encoding),
        }
    } else if segments.is_empty() {
        Archive::parse_with_encoding(data, encoding)
    } else {
        Archive::parse_segments_with_encoding(data, &segments, encoding)
    };
    let archive = archive.unwrap_or_else(|e| fail(&e.to_string()));

    let info = &archive.info;
    let files = archive.files().count();
    let stubs = archive.files().filter(|f| f.is_stub()).count();
    eprintln!("VISE format: {:02x} {:02x}", info.fmt_major, info.fmt_minor);
    if info.names_assumed {
        eprintln!(
            "warning: this format version is not a known one and the archive has too few records to show where they keep their names; names may be wrong"
        );
    }
    if encoding != NameEncoding::MacRoman {
        eprintln!("Names: {encoding:?}");
    }
    eprintln!("CVCT: {files} entries, {} segments", info.num_segments);
    eprintln!("{} extractable, {stubs} condition records", files - stubs);
    eprintln!();
    eprintln!("Extracting to {}/", out_dir.display());
    eprintln!();

    let mut stopped = false;
    let result = archive
        .extract_with_options(out_dir, &options, |progress| {
            stopped |= report(progress);
        })
        .unwrap_or_else(|e| fail(&e.to_string()));
    finish(result, stopped);
}

fn extract_win(data: Vec<u8>, input: &Path, out_dir: &Path) {
    let qdat = match unvise::pe::extract_payload(&data) {
        Ok((payload, _)) => find_qdat(payload, input),
        Err(e) => fail(&e.to_string()),
    };
    let mut archive = WinArchive::from_pe(data, qdat).unwrap_or_else(|e| fail(&e.to_string()));
    let last = archive.last_volume();
    if last > 1 {
        let found = archive.set_volumes(find_volumes(&archive, input));
        let have = u32::try_from(found).map_or(last, |n| n.saturating_add(1).min(last));
        if have < last {
            eprintln!(
                "warning: installer has {last} parts; parts {} to {last} were not found next to it",
                have + 1
            );
        }
    }

    let info = &archive.info;
    eprintln!(
        "Windows VISE (version {}, flags 0x{:08x})",
        info.version, info.flags
    );
    eprintln!("{} entries found", info.entries.len());
    eprintln!();
    eprintln!("Extracting to {}/", out_dir.display());
    eprintln!();

    let mut stopped = false;
    let result = archive
        .extract_with(out_dir, |progress| stopped |= report(progress))
        .unwrap_or_else(|e| fail(&e.to_string()));
    finish(result, stopped);
}

/// Prints one line per entry as the library works through the archive.
/// Returns whether the library is stopping before the end of it
fn report(progress: Progress<'_>) -> bool {
    let stopping = matches!(progress, Progress::BudgetExceeded { .. });
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
    stopping
}

/// Prints the totals. The exit status is 1 if an entry failed or the run
/// stopped before the end of the archive
fn finish(result: unvise::ExtractResult, stopped: bool) {
    eprintln!();
    eprintln!(
        "Done: {} extracted, {} skipped, {} failed",
        result.extracted, result.skipped, result.failed
    );
    if result.failed > 0 || stopped {
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

/// The later parts of a multi-part installer (`Setup.002` and so on), looked
/// for in the directory of the executable. A part is known by its header,
/// which carries the installer's session ID, so the name does not matter
fn find_volumes(archive: &WinArchive, input: &Path) -> Vec<Vec<u8>> {
    use std::io::Read;

    let Some(session) = archive.session() else {
        return Vec::new();
    };
    let Ok(dir) = std::fs::read_dir(containing_dir(input)) else {
        return Vec::new();
    };
    let mut volumes = Vec::new();
    for path in dir.flatten().map(|entry| entry.path()) {
        let mut header = [0u8; 16];
        let is_part = std::fs::File::open(&path)
            .and_then(|mut file| file.read_exact(&mut header))
            .is_ok_and(|()| WinArchive::volume_number(&header, session).is_some());
        if !is_part {
            continue;
        }
        if let Ok(data) = std::fs::read(&path) {
            eprintln!(
                "Part {}: {}",
                u32::from_le_bytes([header[8], header[9], header[10], header[11]]),
                path.display()
            );
            volumes.push(data);
        }
    }
    volumes
}

/// The other half of a Mac OS X installer, when the input is one half
enum BundlePair {
    /// The input holds the file table; this is the file data
    Data(Vec<u8>),
    /// The input holds the file data; this is the file table
    Table(Vec<u8>),
}

/// First format version of the Mac OS X installers
const FMT_OSX: u8 = 0x0b;

/// A Mac OS X installer is an application bundle with the file table in
/// `Contents/MacOSClassic/<name>` and the file data in
/// `Contents/InstallerData/Installer.data`. Given either file, this finds
/// the other one in the bundle. Installers that keep both in one file, and
/// every older format, need nothing and get `None`
fn find_bundle_pair(data: &[u8], input: &Path) -> Option<BundlePair> {
    let header = data.get(..0x2c).filter(|h| h.starts_with(b"SVCT"))?;
    if header[0x12] < FMT_OSX {
        return None;
    }
    let be32 = |at: usize| {
        u32::from_be_bytes([header[at], header[at + 1], header[at + 2], header[at + 3]]) as usize
    };
    let table_at = be32(0x24);
    let has_table = data.get(table_at..).is_some_and(|t| t.starts_with(b"CVCT"));
    // the installer program sits between the header and the data; a file
    // whose table follows it directly has no data of its own
    let data_starts = 0x2c + be32(0x08);
    // one level up from the folder the file is in. Spelled with `..` so it
    // also holds when the path given is a bare file name
    let contents = containing_dir(input).join("..");

    if !has_table {
        let dir = contents.join("MacOSClassic");
        for entry in std::fs::read_dir(&dir).ok()?.flatten() {
            let Ok(raw) = std::fs::read(entry.path()) else {
                continue;
            };
            let table = unvise::macbinary::strip(raw);
            let table_at = table.get(0x24..0x28).map_or(usize::MAX, |b| {
                u32::from_be_bytes([b[0], b[1], b[2], b[3]]) as usize
            });
            if table.starts_with(b"SVCT")
                && table
                    .get(table_at..)
                    .is_some_and(|t| t.starts_with(b"CVCT"))
            {
                eprintln!("File table: {}", entry.path().display());
                return Some(BundlePair::Table(table));
            }
        }
        eprintln!(
            "warning: this file holds an installer's data but not its file table, and none was found in {}",
            dir.display()
        );
        None
    } else if table_at <= data_starts {
        let path = contents.join("InstallerData").join("Installer.data");
        match std::fs::read(&path) {
            Ok(data_file) => {
                eprintln!("File data: {}", path.display());
                Some(BundlePair::Data(data_file))
            }
            Err(_) => {
                eprintln!(
                    "warning: this file holds an installer's file table but not its data, and {} was not found",
                    path.display()
                );
                None
            }
        }
    } else {
        None
    }
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
    use super::{containing_dir, parse_args};
    use std::path::Path;
    use unvise::ForkFormat;

    fn args(list: &[&str]) -> Result<Option<super::Args>, String> {
        parse_args(list.iter().map(std::ffi::OsString::from))
    }

    #[test]
    fn arguments_take_options_in_any_position() {
        let a = args(&["Installer"]).unwrap().unwrap();
        assert_eq!(a.input, Path::new("Installer"));
        assert_eq!(a.out_dir, Path::new("unvise_out"));
        assert_eq!(a.forks, ForkFormat::Rsrc);

        let a = args(&["Installer", "--forks", "macbinary", "out"])
            .unwrap()
            .unwrap();
        assert_eq!(a.out_dir, Path::new("out"));
        assert_eq!(a.forks, ForkFormat::MacBinary);

        let a = args(&["--forks=appledouble", "Installer"])
            .unwrap()
            .unwrap();
        assert_eq!(a.forks, ForkFormat::AppleDouble);
        assert_eq!(a.encoding, None);

        let a = args(&["--encoding", "macjapanese", "Installer"])
            .unwrap()
            .unwrap();
        assert_eq!(a.encoding, Some(unvise::NameEncoding::MacJapanese));
        let a = args(&["Installer", "--encoding=macroman"])
            .unwrap()
            .unwrap();
        assert_eq!(a.encoding, Some(unvise::NameEncoding::MacRoman));

        // after `--` a leading dash is part of a file name
        let a = args(&["--", "-odd name"]).unwrap().unwrap();
        assert_eq!(a.input, Path::new("-odd name"));
    }

    #[test]
    fn bad_arguments_are_refused() {
        assert!(args(&[]).is_err());
        assert!(args(&["--forks"]).is_err());
        assert!(args(&["--forks", "zip", "Installer"]).is_err());
        assert!(args(&["--frobnicate", "Installer"]).is_err());
        assert!(args(&["--encoding", "klingon", "Installer"]).is_err());
        assert!(args(&["Installer", "--encoding"]).is_err());
        assert!(args(&["a", "b", "c"]).is_err());
    }

    #[test]
    fn bare_filename_is_in_the_current_directory() {
        assert_eq!(containing_dir(Path::new("Installer")), Path::new("."));
        assert_eq!(containing_dir(Path::new("./Installer")), Path::new("."));
        assert_eq!(containing_dir(Path::new("a/b/Installer")), Path::new("a/b"));
        assert_eq!(containing_dir(Path::new("/Installer")), Path::new("/"));
    }
}

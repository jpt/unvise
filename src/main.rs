use std::path::Path;
use std::process;

use unvise::{Archive, Entry, InputKind};

fn main() {
  let args: Vec<String> = std::env::args().collect();
  if args.get(1).is_some_and(|a| a == "--version" || a == "-V") {
    println!("unvise {}", env!("CARGO_PKG_VERSION"));
    return;
  }
  if args.len() < 2 {
    eprintln!("usage: {} <vise_installer> [output_dir]", args[0]);
    eprintln!();
    eprintln!("Extracts files from Installer VISE archives (Mac and Windows).");
    eprintln!("Accepts raw data forks, MacBinary-wrapped files, or Windows PE executables.");
    process::exit(1);
  }

  let raw = match std::fs::read(&args[1]) {
    Ok(d) => d,
    Err(e) => {
      eprintln!("error: {}: {e}", args[1]);
      process::exit(1);
    }
  };

  let out_dir = args.get(2).map_or("unvise_out", String::as_str);

  match unvise::detect_format(raw) {
    InputKind::Mac(data) => extract_mac(data, out_dir),
    InputKind::WinPe(data) => extract_win(&data, &args[1], out_dir),
    InputKind::Unknown(_) => {
      eprintln!("error: not a recognized VISE archive");
      process::exit(1);
    }
  }
}

fn extract_mac(data: Vec<u8>, out_dir: &str) {
  let archive = match Archive::parse(data) {
    Ok(a) => a,
    Err(e) => {
      eprintln!("error: {e}");
      process::exit(1);
    }
  };

  let info = &archive.info;
  eprintln!("VISE format: {:02x} {:02x}", info.fmt_major, info.fmt_minor);
  eprintln!("CVCT: {} entries, {} segments", count_files(&archive), info.num_segments);

  if info.num_segments > 1 {
    let mut missing: Vec<u16> = archive.info.entries.iter()
      .filter_map(|e| e.as_file().map(|f| f.segment))
      .filter(|&s| s != 1 && s != 0)
      .collect::<std::collections::HashSet<_>>()
      .into_iter()
      .collect();
    missing.sort_unstable();
    if !missing.is_empty() {
      eprintln!("  segments {missing:?} not present in this file");
    }
  }

  let stubs = count_stubs(&archive);
  let extractable = count_files(&archive) - stubs;
  eprintln!("{extractable} extractable, {stubs} condition records");
  eprintln!();
  eprintln!("Extracting to {out_dir}/");
  eprintln!();

  let result = match archive.extract(Path::new(out_dir)) {
    Ok(r) => r,
    Err(e) => {
      eprintln!("error: {e}");
      process::exit(1);
    }
  };

  eprintln!();
  eprintln!(
    "Done: {} extracted, {} skipped, {} failed",
    result.extracted, result.skipped, result.failed
  );

  if result.failed > 0 {
    process::exit(1);
  }
}

fn extract_win(data: &[u8], exe_path: &str, out_dir: &str) {
  let (payload_slice, payload_offset) = match unvise::pe::extract_payload(data) {
    Ok(p) => p,
    Err(e) => {
      eprintln!("error: {e}");
      process::exit(1);
    }
  };

  let payload = payload_slice.to_vec();
  let qdat = find_qdat(&payload, exe_path);

  let archive = match unvise::win::WinArchive::parse(payload, qdat, payload_offset) {
    Ok(a) => a,
    Err(e) => {
      eprintln!("error: {e}");
      process::exit(1);
    }
  };

  let info = &archive.info;
  eprintln!("Windows VISE (version {}, flags 0x{:08x})", info.version, info.flags);
  eprintln!("{} entries found", info.entries.len());
  eprintln!();
  eprintln!("Extracting to {out_dir}/");
  eprintln!();

  let result = match archive.extract(Path::new(out_dir)) {
    Ok(r) => r,
    Err(e) => {
      eprintln!("error: {e}");
      process::exit(1);
    }
  };

  eprintln!();
  eprintln!(
    "Done: {} extracted, {} skipped, {} failed",
    result.extracted, result.skipped, result.failed
  );

  if result.failed > 0 {
    process::exit(1);
  }
}

/// Searches for a companion `.qdat` file in the same directory as the exe.
/// Returns `None` for full installers or if no matching qdat is found
fn find_qdat(payload: &[u8], exe_path: &str) -> Option<Vec<u8>> {
  use unvise::win::WinArchive;

  if !WinArchive::is_stub(payload) {
    return None;
  }
  let session = WinArchive::session_id(payload)?;
  let exe = Path::new(exe_path);
  let dir = exe.parent()?;

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

  eprintln!("warning: stub installer but no matching .qdat found in {}", dir.display());
  None
}


fn count_files(archive: &Archive) -> usize {
  archive.info.entries.iter()
    .filter_map(Entry::as_file)
    .count()
}

fn count_stubs(archive: &Archive) -> usize {
  archive.info.entries.iter()
    .filter_map(Entry::as_file)
    .filter(|f| f.is_stub())
    .count()
}

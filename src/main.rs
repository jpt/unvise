use std::path::Path;
use std::process;

use unvise::{Archive, Entry};

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.get(1).is_some_and(|a| a == "--version" || a == "-V") {
        println!("unvise {}", env!("CARGO_PKG_VERSION"));
        return;
    }
    if args.len() < 2 {
        eprintln!("usage: {} <vise_installer> [output_dir]", args[0]);
        eprintln!();
        eprintln!("Extracts files from Installer VISE archives (format versions 00 01 through 03 0e).");
        eprintln!("Accepts raw data forks or MacBinary-wrapped files.");
        process::exit(1);
    }

    let raw = match std::fs::read(&args[1]) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("error: {}: {e}", args[1]);
            process::exit(1);
        }
    };

    let data = unvise::macbinary::strip(raw);
    let out_dir = args.get(2).map_or("unvise_out", String::as_str);

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

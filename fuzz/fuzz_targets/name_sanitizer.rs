#![no_main]

use std::path::{Component, Path, PathBuf};

use libfuzzer_sys::fuzz_target;

// The path traversal guard. A sanitizer then safe_join is the single enforcement
// point that keeps a malicious entry name from writing outside the output dir.
// Feed arbitrary bytes as a name and assert the result can never escape the base.
// Windows entries and Mac entries are sanitized differently, so both are checked
fuzz_target!(|data: &[u8]| {
    let raw = String::from_utf8_lossy(data);
    let base = Path::new("/out/base");

    check(base, unvise::fuzzing::sanitize_and_join(base, &raw), &raw);

    // a Mac entry has a folder path and a name; split the input between them
    let mut cut = raw.len() / 2;
    while !raw.is_char_boundary(cut) {
        cut -= 1;
    }
    let (dir, name) = raw.split_at(cut);
    check(
        base,
        unvise::fuzzing::mac_sanitize_and_join(base, dir, name),
        &raw,
    );
    check(
        base,
        unvise::fuzzing::mac_sanitize_and_join(base, &raw, ""),
        &raw,
    );
});

fn check(base: &Path, joined: Option<PathBuf>, raw: &str) {
    let Some(joined) = joined else {
        return;
    };
    // Must stay under base, and must contain no parent or root components
    // that could climb out of it
    assert!(
        joined.starts_with(base),
        "sanitized path escaped base: {joined:?} from {raw:?}"
    );
    let escapes = joined
        .strip_prefix(base)
        .unwrap()
        .components()
        .any(|c| !matches!(c, Component::Normal(_) | Component::CurDir));
    assert!(
        !escapes,
        "sanitized path has a climbing component: {joined:?} from {raw:?}"
    );
}

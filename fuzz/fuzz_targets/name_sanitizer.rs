#![no_main]

use std::path::{Component, Path};

use libfuzzer_sys::fuzz_target;

// The path traversal guard. clean_name then safe_join is the single enforcement
// point that keeps a malicious entry name from writing outside the output dir.
// Feed arbitrary bytes as a name and assert the result can never escape the base.
fuzz_target!(|data: &[u8]| {
    let raw = String::from_utf8_lossy(data);
    let base = Path::new("/out/base");

    if let Some(joined) = unvise::fuzzing::sanitize_and_join(base, &raw) {
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
});

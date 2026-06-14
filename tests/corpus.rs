use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};
use std::process::Command;

use sha2::{Digest, Sha256};

const SEMBIANCE_BASE: &str =
    "https://sembiance.com/fileFormatSamples/archive/installerVISE/";

const SEMBIANCE_FILES: &[&str] = &[
    "CleanResource 2.2",
    "Days To Go 2.1.3 Installer",
    "Index-TV PPC Installer ja",
    "Install Flash Player 7 OSX",
    "Install MyEyes 2.3.3",
    "Install ScreenSaver",
    "Install Secret Paths",
    "Installer",
    "Installeur Desktop Terminator",
    "Internet Config Module",
    "LP TableMaker Install",
    "NSA_ES",
    "NUpowr G3 v1.0.1 Installer",
    "PK-G3A Installer",
    "PocketTranser\u{2044}je eco",
    "RealSpace Plugin Installer",
    "Sketch!Net Installer",
    "Type Recorder 1.5.1",
    "WebJPEG 1.2 Install",
    "euro98",
    "\u{30A4}\u{30F3}\u{30B9}\u{30C8}\u{30FC}\u{30E9}",
];

fn expected_content_hashes() -> HashMap<&'static str, &'static str> {
    HashMap::from([
        ("CleanResource 2.2", "1a2d311c680a6eeda223663db6f23204b864280dd223acde3d7566ad6f27888d"),
        ("Days To Go 2.1.3 Installer", "5e34f36a8a2b7127549f8efd906103ab30350a4f558ae7fbd7e0a75a79bcc61f"),
        ("Index-TV PPC Installer ja", "37b8ea1cca0d3f2024cdf714a37004cd375b0f8d2c36c66c4ea5430c4e0dc630"),
        ("Install Flash Player 7 OSX", "af4024cbe735dce3b39601fabb84660eca108d3e852c29f0b3545564d2863e44"),
        ("Install MyEyes 2.3.3", "a401a59e33b0b01e35ae193af321632104aa33ded5231c13f878df6609ed6f68"),
        ("Install ScreenSaver", "05d6892429a5c08e798e0ecbc8fba9c422e8e24d3cea24d1eff6204de049fdd4"),
        ("Install Secret Paths", "0e99fe30ab1b8eb1b66d7f731b1ec8e7193d6f13b3ac7ba12095c29c19e05ad5"),
        ("Installer", "de53f0e1b86d1c70327f4383d9f7b1eb4755d1ec0d2a99c7fe558e69a703c10f"),
        ("Installeur Desktop Terminator", "748c24b59a9bff789904ce0bc23998f937c55280a7a0935864e2b2c9558254d0"),
        ("Internet Config Module", "842bd5e8054d413d304cdceb2743ab5d804e902a2c6eaa899e43a1aac600bc31"),
        ("LP TableMaker Install", "e908aee437b6d7aa53d3ba8b39239852bed39b403c27f5a800ef2e6ef593bb70"),
        ("NSA_ES", "7bfc3bcba1d7743a25c02013a573bffcc1da3e187a69c01a71096157174f1cf9"),
        ("NUpowr G3 v1.0.1 Installer", "378ba680b3bfabb63cec2d01804209671a5efc878984e1f0040e9aea0b48aedb"),
        ("PK-G3A Installer", "9aa9ed9f2a088d4dd2f03d083a1c94146f972674d46ed501b1a8a54ca1e51542"),
        ("PocketTranser\u{2044}je eco", "b8b180c9e8c9e73681e04b6ff424a872469b12cf6aaa2e9ed6d503d7e8af86e5"),
        ("RealSpace Plugin Installer", "bf24d99626beeb06317e09a29cdb8b5ae15ee70ae41d5e166f725a2e1fc52a92"),
        ("Sketch!Net Installer", "dd866536a83d43c294d77714f433ffa8aaf53c2bf08ea191c24145a95af2ca51"),
        ("Type Recorder 1.5.1", "fdd1ddb4582d21554c24d7adf1c969df852533de749595df90da3ed7a4632beb"),
        ("WebJPEG 1.2 Install", "853ca978dde966d889b43dbfe3339b524bcf3435e77d1049f88a1c8c474da305"),
        ("euro98", "1ca787f3b4182e22066382551e66c4f6c01be570b743a9b69f738d76759a9e0c"),
        ("\u{30A4}\u{30F3}\u{30B9}\u{30C8}\u{30FC}\u{30E9}", "6dae18660400255062c7d307d7631350fc1b88a8957312c303fe91c7172e8b1d"),
    ])
}

fn cache_dir() -> PathBuf {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("target")
        .join("corpus");
    std::fs::create_dir_all(&dir).expect("create corpus cache dir");
    dir
}

fn download(name: &str, dest: &Path) {
    if dest.exists() {
        return;
    }
    let url = format!("{}{}", SEMBIANCE_BASE, urlencoding::encode(name));
    let status = Command::new("curl")
        .args(["-fsSL", "-o"])
        .arg(dest)
        .arg(&url)
        .status()
        .expect("curl not found");
    assert!(status.success(), "failed to download {name}");
}

fn content_hash(dir: &Path) -> String {
    let mut files: BTreeMap<String, Vec<u8>> = BTreeMap::new();
    fn collect(dir: &Path, prefix: &str, files: &mut BTreeMap<String, Vec<u8>>) {
        let Ok(entries) = std::fs::read_dir(dir) else { return };
        let mut entries: Vec<_> = entries.filter_map(|e| e.ok()).collect();
        entries.sort_by_key(|e| e.file_name());
        for entry in entries {
            let path = entry.path();
            let name = if prefix.is_empty() {
                entry.file_name().to_string_lossy().into_owned()
            } else {
                format!("{}/{}", prefix, entry.file_name().to_string_lossy())
            };
            if path.is_dir() {
                collect(&path, &name, files);
            } else if let Ok(data) = std::fs::read(&path) {
                files.insert(name, data);
            }
        }
    }
    collect(dir, "", &mut files);

    let mut hasher = Sha256::new();
    for (name, data) in &files {
        hasher.update(name.as_bytes());
        hasher.update(b"\0");
        hasher.update(&data.len().to_le_bytes());
        hasher.update(data);
    }
    format!("{:x}", hasher.finalize())
}

/// Downloads all sembiance.com VISE samples, extracts each one, and verifies
/// the extracted content matches known-good SHA-256 hashes. Catches any
/// regression in parsing or decompression across format versions.
///
/// Requires network access; run with: cargo test --test corpus -- --ignored
#[test]
#[ignore]
fn sembiance_corpus_content_verified() {
    let cache = cache_dir();
    let expected = expected_content_hashes();
    let mut mismatches = Vec::new();

    for &name in SEMBIANCE_FILES {
        let dest = cache.join(name);
        download(name, &dest);

        let raw = std::fs::read(&dest).expect("read downloaded file");
        let data = unvise::macbinary::strip(raw);
        let archive = match unvise::Archive::parse(data) {
            Ok(a) => a,
            Err(e) => {
                mismatches.push(format!("{name}: parse failed: {e}"));
                continue;
            }
        };

        let tmp = tempfile::tempdir().expect("create temp dir");
        match archive.extract(tmp.path()) {
            Ok(result) => {
                let actual = content_hash(tmp.path());
                if let Some(&exp) = expected.get(name) {
                    if actual != exp {
                        mismatches.push(format!(
                            "{name}: content hash mismatch\n  expected: {exp}\n  actual:   {actual}"
                        ));
                    } else {
                        eprintln!(
                            "  OK {name} ({} extracted, {} failed)",
                            result.extracted, result.failed
                        );
                    }
                }
            }
            Err(e) => {
                mismatches.push(format!("{name}: extract failed: {e}"));
            }
        }
    }

    if !mismatches.is_empty() {
        panic!(
            "{} content verification failure(s):\n{}",
            mismatches.len(),
            mismatches.join("\n")
        );
    }
}

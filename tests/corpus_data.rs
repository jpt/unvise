use std::path::PathBuf;
use std::process::Command;

pub const SEMBIANCE_BASE: &str =
    "https://sembiance.com/fileFormatSamples/archive/installerVISE/";

pub const SEMBIANCE_FILES: &[&str] = &[
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

pub fn cache_dir() -> PathBuf {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("target")
        .join("corpus");
    std::fs::create_dir_all(&dir).expect("create corpus cache dir");
    dir
}

pub fn download(name: &str) -> PathBuf {
    let dest = cache_dir().join(name);
    if !dest.exists() {
        let url = format!("{}{}", SEMBIANCE_BASE, urlencoding::encode(name));
        let status = Command::new("curl")
            .args(["-fsSL", "-o"])
            .arg(&dest)
            .arg(&url)
            .status()
            .expect("curl not found");
        assert!(status.success(), "failed to download {name}");
    }
    dest
}

use std::path::PathBuf;

pub struct Sample {
    pub title: &'static str,
    pub blurb: &'static str,
    pub path: PathBuf,
}

const CATALOG: [(&str, &str, &str); 3] = [
    (
        "hello.exe",
        "hello.exe",
        "A tiny native program with named routines, strings, and a few imports.",
    ),
    (
        "encoded.exe",
        "encoded.exe (encrypted strings)",
        "Strings and a URL are XOR-encoded and rebuilt at runtime, so the XOR scanner can find them.",
    ),
    (
        "demo.apk",
        "demo.apk",
        "A synthetic Android package with a manifest, a DEX, and a flagged native library.",
    ),
];

pub fn locate() -> Vec<Sample> {
    let mut found = Vec::new();
    for (file, title, blurb) in CATALOG {
        if let Some(path) = find(file) {
            found.push(Sample { title, blurb, path });
        }
    }
    found
}

pub fn find(file: &str) -> Option<PathBuf> {
    candidates()
        .into_iter()
        .map(|dir| dir.join(file))
        .find(|path| path.is_file())
}

fn candidates() -> Vec<PathBuf> {
    let mut dirs = Vec::new();
    if let Some(value) = std::env::var_os("EUPHORIA_SAMPLES") {
        dirs.push(PathBuf::from(value));
    }
    if let Ok(exe) = std::env::current_exe()
        && let Some(parent) = exe.parent()
    {
        dirs.push(parent.join("samples"));
    }
    dirs.push(PathBuf::from("samples"));
    dirs
}

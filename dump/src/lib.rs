mod zipfile;

use std::fmt::Write as _;
use std::fs::{self, File};
use std::io::BufWriter;
use std::path::Path;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc;
use std::thread;
use std::time::Instant;

use anyhow::{Context, Result, anyhow};
use euphoria_apk::Apk;
use euphoria_engine::{Analysis, Cfg, Line, Listing, entropy, entropy_label, scan_xor};
use serde::Serialize;
use serde_json::json;

use zipfile::{ZipFile, compress};

const DISASSEMBLY_CHUNK_ROWS: usize = 100_000;
const GRAPH_CHUNK_FUNCTIONS: usize = 1_000;
const CLASS_CHUNK: usize = 400;
const FILE_CHUNK: usize = 200;
const WRITE_BUFFER: usize = 1024 * 1024;
const QUEUE_PER_WORKER: usize = 4;

#[derive(Clone, Copy, Debug)]
pub struct Options {
    pub include_original: bool,
}

#[derive(Debug, Default)]
pub struct Progress {
    pub files: AtomicU64,
    pub bytes: AtomicU64,
}

#[derive(Clone, Copy, Debug, Serialize)]
pub struct Summary {
    pub files: u64,
    pub uncompressed_bytes: u64,
    pub zip_bytes: u64,
    pub seconds: f64,
}

type Entry = (String, Vec<u8>);
type Job<'a> = Box<dyn FnOnce() -> Result<Vec<Entry>> + Send + 'a>;

fn entry(name: impl Into<String>, text: impl Into<Vec<u8>>) -> Entry {
    (name.into(), text.into())
}

fn json_entry(name: &str, value: &impl Serialize) -> Result<Entry> {
    Ok(entry(name, serde_json::to_vec_pretty(value)?))
}

fn csv(field: &str) -> String {
    if field.contains([',', '"', '\n', '\r']) {
        format!("\"{}\"", field.replace('"', "\"\""))
    } else {
        field.to_owned()
    }
}

fn one_line(text: &str) -> String {
    text.replace('\r', "\\r").replace('\n', "\\n")
}

fn run_jobs(jobs: Vec<Job<'_>>, out: &Path, progress: &Progress) -> Result<Summary> {
    let started = Instant::now();
    let temporary = out.with_extension("zip.tmp");
    let file = File::create(&temporary)
        .with_context(|| format!("cannot write {}", temporary.display()))?;
    let mut zip = ZipFile::new(BufWriter::with_capacity(WRITE_BUFFER, file));

    let workers = thread::available_parallelism().map_or(4, usize::from);
    let queue = Mutex::new(jobs);
    let (sender, receiver) = mpsc::sync_channel(workers * QUEUE_PER_WORKER);

    let mut uncompressed = 0u64;
    let mut failure: Option<anyhow::Error> = None;

    thread::scope(|scope| {
        for _ in 0..workers {
            let sender = sender.clone();
            let queue = &queue;
            scope.spawn(move || {
                loop {
                    let job = queue.lock().ok().and_then(|mut queue| queue.pop());
                    let Some(job) = job else {
                        return;
                    };
                    match job() {
                        Ok(entries) => {
                            for (name, bytes) in entries {
                                let packed = compress(name, bytes).map_err(anyhow::Error::from);
                                if sender.send(packed).is_err() {
                                    return;
                                }
                            }
                        }
                        Err(error) => {
                            if sender.send(Err(error)).is_err() {
                                return;
                            }
                        }
                    }
                }
            });
        }
        drop(sender);

        for packed in receiver {
            match packed {
                Ok(file) if failure.is_none() => {
                    uncompressed += file.size;
                    match zip.add(file) {
                        Ok(written) => {
                            progress.files.fetch_add(1, Ordering::Relaxed);
                            progress.bytes.fetch_add(written, Ordering::Relaxed);
                        }
                        Err(error) => failure = Some(error.into()),
                    }
                }
                Err(error) if failure.is_none() => failure = Some(error),
                _ => {}
            }
        }
    });

    if let Some(error) = failure {
        let _ = fs::remove_file(&temporary);
        return Err(error);
    }

    let zip_bytes = zip.finish()?;
    fs::rename(&temporary, out).with_context(|| format!("cannot write {}", out.display()))?;
    Ok(Summary {
        files: progress.files.load(Ordering::Relaxed),
        uncompressed_bytes: uncompressed,
        zip_bytes,
        seconds: started.elapsed().as_secs_f64(),
    })
}

const BINARY_README: &str = "Euphoria dump

info.json       File identity, entropy, packers, and counts
sections.json   Every section with its entropy
imports.txt     Imported functions
functions.csv   Every routine
xrefs.csv       Every call, jump, and data reference
strings.txt     Every string, one per line
strings.json    Every string with its address and Base64 text
base64.txt      Strings that decode from Base64
links.txt       Links found in strings
xor.txt         Text found by the single-byte XOR scan
disassembly/    The full listing
graphs/         Control flow graph of every routine, as JSON lines
original/       The file itself, when included
";

fn text_for_line(line: &Line, analysis: &Analysis, listing: &Listing) -> String {
    let bytes: Vec<String> = line
        .bytes
        .iter()
        .map(|byte| format!("{byte:02X}"))
        .collect();
    let code: String = line
        .tokens
        .iter()
        .map(|token| token.text.as_str())
        .collect();
    let mut text = format!("{:#014x}  {:<32} {code}", line.va, bytes.join(" "));

    let target_name = line
        .branch
        .and_then(|va| analysis.function_at(va))
        .and_then(|function| function.name.as_deref());
    if let Some(name) = target_name {
        let _ = write!(text, "  ; {name}");
    } else if let Some(found) = line.data.and_then(|va| listing.string_at(va)) {
        let _ = write!(text, "  ; \"{}\"", one_line(&found.value));
    }
    text
}

fn disassembly_chunk(
    part: usize,
    range: std::ops::Range<usize>,
    analysis: &Analysis,
    listing: &Listing,
) -> Entry {
    let mut text = String::new();
    for line in listing.render(&analysis.data, range) {
        if let Some(function) = analysis.function_at(line.va) {
            let name = function.name.as_deref().unwrap_or("unnamed");
            let _ = writeln!(text, "\n{name}:");
        }
        text.push_str(&text_for_line(&line, analysis, listing));
        text.push('\n');
    }
    entry(format!("disassembly/{part:05}.txt"), text)
}

fn graph_chunk(
    part: usize,
    functions: &[euphoria_engine::Function],
    analysis: &Analysis,
    listing: &Listing,
) -> Result<Entry> {
    let mut text = String::new();
    for function in functions {
        let cfg = Cfg::build(listing, &analysis.data, function);
        let line = json!({ "va": function.va, "name": function.name, "blocks": cfg.blocks });
        text.push_str(&serde_json::to_string(&line)?);
        text.push('\n');
    }
    Ok(entry(format!("graphs/{part:05}.jsonl"), text))
}

fn links_text<'a>(strings: impl Iterator<Item = (&'a str, Option<&'a str>)>) -> String {
    let mut links = std::collections::BTreeSet::new();
    for (value, decoded) in strings {
        links.extend(aero::extract_links(value));
        if let Some(decoded) = decoded {
            links.extend(aero::extract_links(decoded));
        }
    }
    let list: Vec<String> = links.into_iter().collect();
    list.join("\n")
}

pub fn dump_binary(
    analysis: &Analysis,
    listing: &Listing,
    out: &Path,
    options: Options,
    progress: &Progress,
) -> Result<Summary> {
    let mut jobs: Vec<Job<'_>> = Vec::new();

    jobs.push(Box::new(|| Ok(vec![entry("README.txt", BINARY_README)])));
    jobs.push(Box::new(move || {
        let report = analysis.inspect();
        let info = json!({
            "file": analysis.file_name,
            "sha256": analysis.sha256,
            "size": analysis.data.len(),
            "arch": analysis.arch,
            "entry": analysis.entry,
            "entropy": report.entropy,
            "entropy_note": entropy_label(report.entropy),
            "packers": report.detections,
            "import_count": analysis.import_count,
            "functions": analysis.functions.len(),
            "instructions": listing.rows.len(),
            "xrefs": listing.xrefs.len(),
            "strings": listing.strings.len(),
            "tool": concat!("Euphoria ", env!("CARGO_PKG_VERSION")),
        });
        Ok(vec![
            json_entry("info.json", &info)?,
            json_entry("sections.json", &report.sections)?,
        ])
    }));
    jobs.push(Box::new(move || {
        Ok(vec![entry("imports.txt", analysis.imports.join("\n"))])
    }));
    jobs.push(Box::new(move || {
        let mut text = String::from("va,size,name\n");
        for function in &analysis.functions {
            let name = function.name.as_deref().unwrap_or("");
            let _ = writeln!(text, "{:#x},{},{}", function.va, function.size, csv(name));
        }
        Ok(vec![entry("functions.csv", text)])
    }));
    jobs.push(Box::new(move || {
        let mut text = String::from("from,to,kind\n");
        for xref in &listing.xrefs {
            let kind = format!("{:?}", xref.kind).to_lowercase();
            let _ = writeln!(text, "{:#x},{:#x},{kind}", xref.from, xref.to);
        }
        Ok(vec![entry("xrefs.csv", text)])
    }));
    jobs.push(Box::new(move || {
        let mut plain = String::new();
        let mut base64 = String::new();
        for found in &listing.strings {
            let _ = writeln!(plain, "{:#x}  {}", found.va, one_line(&found.value));
            if let Some(decoded) = &found.base64 {
                let _ = writeln!(
                    base64,
                    "{:#x}  {}\n    => {}",
                    found.va,
                    found.value,
                    one_line(decoded)
                );
            }
        }
        let links = links_text(
            listing
                .strings
                .iter()
                .map(|found| (found.value.as_str(), found.base64.as_deref())),
        );
        Ok(vec![
            entry("strings.txt", plain),
            json_entry("strings.json", &listing.strings)?,
            entry("base64.txt", base64),
            entry("links.txt", links),
        ])
    }));
    jobs.push(Box::new(move || {
        let mut text = String::new();
        for hit in scan_xor(&analysis.data, &analysis.sections) {
            let _ = writeln!(text, "{:#x}  key={:02X}  {}", hit.va, hit.key, hit.text);
        }
        Ok(vec![entry("xor.txt", text)])
    }));

    let mut start = 0;
    let mut part = 0;
    while start < listing.rows.len() {
        let end = (start + DISASSEMBLY_CHUNK_ROWS).min(listing.rows.len());
        let index = part;
        jobs.push(Box::new(move || {
            Ok(vec![disassembly_chunk(
                index,
                start..end,
                analysis,
                listing,
            )])
        }));
        start = end;
        part += 1;
    }
    for (index, functions) in analysis.functions.chunks(GRAPH_CHUNK_FUNCTIONS).enumerate() {
        jobs.push(Box::new(move || {
            Ok(vec![graph_chunk(index, functions, analysis, listing)?])
        }));
    }
    if options.include_original {
        jobs.push(Box::new(move || {
            Ok(vec![entry(
                format!("original/{}", analysis.file_name),
                analysis.data.as_slice(),
            )])
        }));
    }

    run_jobs(jobs, out, progress)
}

const APK_README: &str = "Euphoria dump

info.json         Package identity, signing, protectors, and counts
manifest.xml      The decoded Android manifest
manifest.json     The same manifest as data
permissions.txt   Requested permissions, with sensitive ones marked
files.csv         Every file in the APK
native.json       Native libraries with hashes and entropy
classes.csv       Every class
methods.csv       Every method
fields.csv        Every field
strings.txt       Every DEX string
base64.txt        Strings that decode from Base64
links.txt         Links found in strings
smali/            Bytecode of every class, one file per class
original/         The APK itself, when included
files/            Everything unpacked from the APK, when included
";

fn class_chunk(apk: &Apk, dex_index: usize, range: std::ops::Range<usize>) -> Vec<Entry> {
    let dex = &apk.dexes[dex_index];
    let folder = dex.name.trim_end_matches(".dex");
    dex.classes[range]
        .iter()
        .map(|class| {
            let path = dex
                .type_name(class.type_index)
                .trim_start_matches('L')
                .trim_end_matches(';');
            entry(
                format!("smali/{folder}/{path}.smali"),
                dex.class_text(class),
            )
        })
        .collect()
}

fn apk_tables(apk: &Apk) -> Vec<Entry> {
    let mut classes = String::from("dex,class,super,methods,fields,source\n");
    let mut methods = String::from("dex,method,access,code_units\n");
    let mut fields = String::from("dex,field,access\n");

    for dex in &apk.dexes {
        for class in &dex.classes {
            let superclass = class.superclass.map_or("", |index| dex.type_name(index));
            let _ = writeln!(
                classes,
                "{},{},{},{},{},{}",
                dex.name,
                csv(dex.type_name(class.type_index)),
                csv(superclass),
                class.methods.len(),
                class.fields.len(),
                csv(class.source_file.as_deref().unwrap_or(""))
            );
            for method in &class.methods {
                let units = method.code.as_ref().map_or(0, |code| code.units);
                let _ = writeln!(
                    methods,
                    "{},{},{:#x},{units}",
                    dex.name,
                    csv(&dex.method_ref(method.id)),
                    method.access
                );
            }
            for field in &class.fields {
                let _ = writeln!(
                    fields,
                    "{},{},{:#x}",
                    dex.name,
                    csv(&dex.field_ref(field.id)),
                    field.access
                );
            }
        }
    }

    vec![
        entry("classes.csv", classes),
        entry("methods.csv", methods),
        entry("fields.csv", fields),
    ]
}

pub fn dump_apk(apk: &Apk, out: &Path, options: Options, progress: &Progress) -> Result<Summary> {
    let mut jobs: Vec<Job<'_>> = Vec::new();

    jobs.push(Box::new(|| Ok(vec![entry("README.txt", APK_README)])));
    jobs.push(Box::new(move || {
        let info = json!({
            "file": apk.file_name,
            "sha256": apk.sha256,
            "size": apk.data.len(),
            "entropy": entropy(&apk.data),
            "package": apk.manifest.package,
            "version_name": apk.manifest.version_name,
            "version_code": apk.manifest.version_code,
            "min_sdk": apk.manifest.min_sdk,
            "target_sdk": apk.manifest.target_sdk,
            "debuggable": apk.manifest.debuggable,
            "signing": apk.signing,
            "protectors": apk.protectors,
            "dex_files": apk.dexes.iter().map(|dex| &dex.name).collect::<Vec<_>>(),
            "classes": apk.class_count(),
            "methods": apk.method_count(),
            "strings": apk.strings.len(),
            "warnings": apk.warnings,
            "tool": concat!("Euphoria ", env!("CARGO_PKG_VERSION")),
        });

        let mut permissions = String::new();
        for permission in &apk.manifest.permissions {
            let mark = if euphoria_apk::is_dangerous_permission(permission) {
                "sensitive  "
            } else {
                "           "
            };
            let _ = writeln!(permissions, "{mark}{permission}");
        }

        let mut files = String::from("name,size,compressed,crc32\n");
        for file in &apk.files {
            let _ = writeln!(
                files,
                "{},{},{},{:08x}",
                csv(&file.name),
                file.size,
                file.compressed,
                file.crc32
            );
        }

        Ok(vec![
            json_entry("info.json", &info)?,
            entry("manifest.xml", apk.manifest_xml.as_str()),
            json_entry("manifest.json", &apk.manifest)?,
            entry("permissions.txt", permissions),
            entry("files.csv", files),
            json_entry("native.json", &apk.natives)?,
        ])
    }));
    jobs.push(Box::new(move || Ok(apk_tables(apk))));
    jobs.push(Box::new(move || {
        let mut plain = String::new();
        let mut base64 = String::new();
        for found in &apk.strings {
            let _ = writeln!(plain, "{}  {}", found.dex, one_line(&found.value));
            if let Some(decoded) = &found.base64 {
                let _ = writeln!(base64, "{}\n    => {}", found.value, one_line(decoded));
            }
        }
        let links = links_text(
            apk.strings
                .iter()
                .map(|found| (found.value.as_str(), found.base64.as_deref())),
        );
        Ok(vec![
            entry("strings.txt", plain),
            entry("base64.txt", base64),
            entry("links.txt", links),
        ])
    }));

    for (dex_index, dex) in apk.dexes.iter().enumerate() {
        let mut start = 0;
        while start < dex.classes.len() {
            let end = (start + CLASS_CHUNK).min(dex.classes.len());
            jobs.push(Box::new(move || {
                Ok(class_chunk(apk, dex_index, start..end))
            }));
            start = end;
        }
    }

    if options.include_original {
        jobs.push(Box::new(move || {
            Ok(vec![entry(
                format!("original/{}", apk.file_name),
                apk.data.as_slice(),
            )])
        }));
        let mut start = 0;
        while start < apk.files.len() {
            let end = (start + FILE_CHUNK).min(apk.files.len());
            jobs.push(Box::new(move || {
                let files = apk.read_files(start..end).map_err(|error| anyhow!(error))?;
                Ok(files
                    .into_iter()
                    .map(|(name, bytes)| (format!("files/{name}"), bytes))
                    .collect())
            }));
            start = end;
        }
    }

    run_jobs(jobs, out, progress)
}

#[cfg(test)]
mod tests {
    use std::io::Read;

    use super::*;

    fn read_names(path: &Path) -> Vec<String> {
        let archive = zip::ZipArchive::new(File::open(path).unwrap()).unwrap();
        archive.file_names().map(str::to_owned).collect()
    }

    fn read_text(path: &Path, name: &str) -> String {
        let mut archive = zip::ZipArchive::new(File::open(path).unwrap()).unwrap();
        let mut text = String::new();
        archive
            .by_name(name)
            .unwrap()
            .read_to_string(&mut text)
            .unwrap();
        text
    }

    fn scratch(name: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!("euphoria-dump-{}-{name}.zip", std::process::id()))
    }

    #[test]
    fn dumps_this_test_program_with_everything() {
        let exe = std::env::current_exe().unwrap();
        let analysis = Analysis::open(&exe).unwrap();
        let listing = analysis.listing();
        let out = scratch("binary");
        let progress = Progress::default();

        let summary = dump_binary(
            &analysis,
            &listing,
            &out,
            Options {
                include_original: true,
            },
            &progress,
        )
        .unwrap();

        let names = read_names(&out);
        for expected in [
            "README.txt",
            "info.json",
            "sections.json",
            "imports.txt",
            "functions.csv",
            "xrefs.csv",
            "strings.txt",
            "strings.json",
            "base64.txt",
            "links.txt",
            "xor.txt",
            "disassembly/00000.txt",
            "graphs/00000.jsonl",
        ] {
            assert!(
                names.iter().any(|name| name == expected),
                "missing {expected}"
            );
        }
        assert!(names.iter().any(|name| name.starts_with("original/")));
        assert_eq!(summary.files, names.len() as u64);
        assert_eq!(summary.zip_bytes, fs::metadata(&out).unwrap().len());

        let info: serde_json::Value = serde_json::from_str(&read_text(&out, "info.json")).unwrap();
        assert_eq!(info["sha256"], analysis.sha256);
        assert_eq!(info["functions"], analysis.functions.len());

        let functions = read_text(&out, "functions.csv");
        assert_eq!(functions.lines().count(), analysis.functions.len() + 1);
        let listing_text = read_text(&out, "disassembly/00000.txt");
        assert!(listing_text.contains("ret"));

        fs::remove_file(&out).unwrap();
        assert!(!out.with_extension("zip.tmp").exists());
    }

    #[test]
    fn leaves_the_original_out_when_asked() {
        let exe = std::env::current_exe().unwrap();
        let analysis = Analysis::open(&exe).unwrap();
        let listing = analysis.listing();
        let out = scratch("no-original");

        dump_binary(
            &analysis,
            &listing,
            &out,
            Options {
                include_original: false,
            },
            &Progress::default(),
        )
        .unwrap();

        assert!(
            !read_names(&out)
                .iter()
                .any(|name| name.starts_with("original/"))
        );
        fs::remove_file(&out).unwrap();
    }

    #[test]
    fn reports_an_unwritable_path() {
        let exe = std::env::current_exe().unwrap();
        let analysis = Analysis::open(&exe).unwrap();
        let listing = analysis.listing();
        let bad = Path::new("no-such-folder-euphoria/out.zip");

        assert!(
            dump_binary(
                &analysis,
                &listing,
                bad,
                Options {
                    include_original: false
                },
                &Progress::default(),
            )
            .is_err()
        );
    }

    #[test]
    fn quotes_csv_fields_that_need_it() {
        assert_eq!(csv("plain"), "plain");
        assert_eq!(csv("a,b"), "\"a,b\"");
        assert_eq!(csv("say \"hi\""), "\"say \"\"hi\"\"\"");
    }
}

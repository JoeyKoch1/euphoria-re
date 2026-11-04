use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use euphoria_engine::{Analysis, Cfg, entropy_label, scan_xor};
use serde::Serialize;

#[derive(Parser)]
#[command(name = "eu", version, about = "Euphoria disassembly workbench")]
struct Cli {
    #[arg(long, global = true)]
    json: bool,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    Analyze {
        path: PathBuf,
        #[arg(long)]
        save: Option<PathBuf>,
    },
    Functions {
        path: PathBuf,
    },
    Graph {
        path: PathBuf,
        target: String,
    },
    Inspect {
        path: PathBuf,
    },
    Strings {
        path: PathBuf,
    },
    Xor {
        path: PathBuf,
    },
    Links {
        path: PathBuf,
    },
    Redirect {
        path: PathBuf,
        url: String,
        #[arg(short, long)]
        out: PathBuf,
    },
    Sql {
        path: PathBuf,
    },
    Aero {
        #[command(subcommand)]
        command: AeroCommand,
    },
    Plugin {
        #[command(subcommand)]
        command: PluginCommand,
    },
    Apk {
        path: PathBuf,
    },
    Dump {
        path: PathBuf,
        #[arg(short, long)]
        out: PathBuf,
        #[arg(long)]
        no_original: bool,
    },
}

#[derive(Subcommand)]
enum PluginCommand {
    List,
    Run {
        script: PathBuf,
        binary: Option<PathBuf>,
    },
    DiscordCheck {
        application_id: String,
        #[arg(long, default_value = "sample.exe")]
        details: String,
        #[arg(long, default_value = "Tab: Listing")]
        state: String,
        #[arg(long, default_value_t = 20)]
        hold_seconds: u64,
    },
}

#[derive(Subcommand)]
enum AeroCommand {
    Scan {
        domain: String,
        #[arg(long)]
        i_have_permission: bool,
    },
    Send {
        url: String,
        #[arg(short = 'X', long, default_value = "GET")]
        method: String,
        #[arg(short = 'H', long = "header")]
        headers: Vec<String>,
        #[arg(short, long)]
        data: Option<String>,
        #[arg(long)]
        i_have_permission: bool,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Analyze { path, save } => analyze(&path, save.as_deref(), cli.json),
        Command::Functions { path } => functions(&path, cli.json),
        Command::Graph { path, target } => graph(&path, &target, cli.json),
        Command::Inspect { path } => inspect(&path, cli.json),
        Command::Strings { path } => strings(&path, cli.json),
        Command::Xor { path } => xor(&path, cli.json),
        Command::Links { path } => links(&path, cli.json),
        Command::Redirect { path, url, out } => redirect(&path, &url, &out),
        Command::Sql { path } => sql(&path, cli.json),
        Command::Apk { path } => apk(&path, cli.json),
        Command::Dump {
            path,
            out,
            no_original,
        } => dump(&path, &out, !no_original, cli.json),
        Command::Plugin { command } => match command {
            PluginCommand::List => plugin_list(cli.json),
            PluginCommand::Run { script, binary } => plugin_run(&script, binary.as_deref()),
            PluginCommand::DiscordCheck {
                application_id,
                details,
                state,
                hold_seconds,
            } => {
                let reply = euphoria_plugins::check_discord(
                    &application_id,
                    &details,
                    &state,
                    std::time::Duration::from_secs(hold_seconds),
                )
                .map_err(|error| anyhow::anyhow!(error))?;
                print_json(&reply)
            }
        },
        Command::Aero { command } => match command {
            AeroCommand::Scan {
                domain,
                i_have_permission,
            } => aero_scan(&domain, i_have_permission, cli.json),
            AeroCommand::Send {
                url,
                method,
                headers,
                data,
                i_have_permission,
            } => aero_send(url, method, &headers, data, i_have_permission, cli.json),
        },
    }
}

fn links(path: &Path, json: bool) -> Result<()> {
    let listing = Analysis::open(path)?.listing();
    let mut found = Vec::new();
    for entry in &listing.strings {
        found.extend(aero::extract_links(&entry.value));
        if let Some(decoded) = &entry.base64 {
            found.extend(aero::extract_links(decoded));
        }
    }
    found.sort();
    found.dedup();

    if json {
        return print_json(&found);
    }
    for link in &found {
        println!("{link}");
    }
    Ok(())
}

// Redirects a URL stored in the binary to the loopback address and writes a patched copy.
// The input file is only read, never changed.
fn redirect(path: &Path, url: &str, out: &Path) -> Result<()> {
    let analysis = Analysis::open(path)?;
    let listing = analysis.listing();
    let entry = listing
        .strings
        .iter()
        .find(|entry| entry.value.contains(url))
        .with_context(|| format!("no plain-text string contains {url}"))?;
    let position = entry.value.find(url).unwrap_or(0);
    let va = entry.va + position as u64;

    let parsed = aero::Url::parse(url)?;
    let replacement = aero::to_loopback(&parsed, None);
    let patch = analysis.plan_patch(va, url.len(), &replacement)?;
    analysis.save_patched(out, std::slice::from_ref(&patch))?;

    println!("redirected {url}");
    println!("        to {replacement}");
    println!("     saved {}", out.display());
    Ok(())
}

fn sql(path: &Path, json: bool) -> Result<()> {
    let script = euphoria_sql::open(path)?;
    if json {
        return print_json(&script);
    }

    for statement in &script.statements {
        println!(
            "{:>6}  {:<18} {}",
            statement.line, statement.kind, statement.summary
        );
        for flag in &statement.flags {
            println!("        {:?}: {}", flag.level, flag.message);
        }
    }
    println!();
    for relation in &script.relations {
        println!(
            "{} -> {} ({:?})",
            script.objects[relation.from].name, script.objects[relation.to].name, relation.kind
        );
    }
    Ok(())
}

fn apk(path: &Path, json: bool) -> Result<()> {
    let apk = euphoria_apk::Apk::open(path)?;
    if json {
        return print_json(&serde_json::json!({
            "file": apk.file_name,
            "sha256": apk.sha256,
            "manifest": apk.manifest,
            "signing": apk.signing,
            "protectors": apk.protectors,
            "native": apk.natives,
            "classes": apk.class_count(),
            "methods": apk.method_count(),
            "strings": apk.strings.len(),
            "warnings": apk.warnings,
        }));
    }

    println!("package:  {}", apk.manifest.package);
    println!("version:  {}", apk.manifest.version_name);
    println!(
        "sdk:      {} to {}",
        apk.manifest.min_sdk, apk.manifest.target_sdk
    );
    println!("classes:  {}", apk.class_count());
    println!("methods:  {}", apk.method_count());
    println!("strings:  {}", apk.strings.len());
    for permission in &apk.manifest.permissions {
        println!("permission: {permission}");
    }
    for warning in &apk.warnings {
        eprintln!("warning: {warning}");
    }
    Ok(())
}

fn dump(path: &Path, out: &Path, include_original: bool, json: bool) -> Result<()> {
    let options = euphoria_dump::Options { include_original };
    let progress = euphoria_dump::Progress::default();
    let summary = if euphoria_apk::is_apk(path) {
        let apk = euphoria_apk::Apk::open(path)?;
        euphoria_dump::dump_apk(&apk, out, options, &progress)?
    } else {
        let analysis = Analysis::open(path)?;
        let listing = analysis.listing();
        euphoria_dump::dump_binary(&analysis, &listing, out, options, &progress)?
    };

    if json {
        return print_json(&summary);
    }
    println!(
        "{} files, {} bytes packed into {} bytes in {:.2} s",
        summary.files, summary.uncompressed_bytes, summary.zip_bytes, summary.seconds
    );
    Ok(())
}

fn plugin_list(json: bool) -> Result<()> {
    let host = euphoria_plugins::PluginHost::open(euphoria_plugins::default_dir());
    let names: Vec<String> = host
        .entries()
        .iter()
        .map(|entry| entry.meta.name.clone())
        .collect();

    if json {
        return print_json(&names);
    }
    println!("{}", host.dir().display());
    for name in &names {
        println!("{name}");
    }
    Ok(())
}

fn plugin_run(script: &Path, binary: Option<&Path>) -> Result<()> {
    let view = match binary {
        Some(path) => {
            let analysis = Analysis::open(path)?;
            let listing = analysis.listing();
            Some(euphoria_plugins::BinaryView::new(&analysis, &listing))
        }
        None => None,
    };
    let lines = euphoria_plugins::run_once(script, view).map_err(|error| anyhow::anyhow!(error))?;
    for line in lines {
        println!("{line}");
    }
    Ok(())
}

fn require_permission(given: bool) -> Result<()> {
    anyhow::ensure!(
        given,
        "this contacts remote systems from your IP address. Only run it against systems you own \
         or have permission to test, and pass --i-have-permission to confirm"
    );
    Ok(())
}

fn aero_scan(domain: &str, permission: bool, json: bool) -> Result<()> {
    require_permission(permission)?;

    let (sender, receiver) = std::sync::mpsc::channel();
    let target = domain.to_owned();
    let worker = std::thread::spawn(move || aero::scan(&target, &sender));

    let mut found = Vec::new();
    for event in receiver {
        match event {
            aero::ScanEvent::Found(item) => found.push(item),
            aero::ScanEvent::Warning(note) => eprintln!("{note}"),
            aero::ScanEvent::Done => break,
        }
    }
    worker
        .join()
        .map_err(|_| anyhow::anyhow!("the scan thread stopped unexpectedly"))??;
    found.sort_by(|a, b| a.name.cmp(&b.name));

    if json {
        return print_json(&found);
    }
    for item in &found {
        let addresses: Vec<String> = item.addresses.iter().map(ToString::to_string).collect();
        println!("{:<44} {}", item.name, addresses.join(", "));
    }
    Ok(())
}

fn aero_send(
    url: String,
    method: String,
    headers: &[String],
    data: Option<String>,
    permission: bool,
    json: bool,
) -> Result<()> {
    require_permission(permission)?;

    let request = aero::Request {
        method,
        url,
        headers: headers
            .iter()
            .filter_map(|header| header.split_once(':'))
            .map(|(key, value)| (key.trim().to_owned(), value.trim().to_owned()))
            .collect(),
        body: data.unwrap_or_default().into_bytes(),
    };
    let capture = aero::send(&request)?;

    if json {
        return print_json(&capture);
    }
    println!("{} in {} ms", capture.status, capture.elapsed_ms);
    println!("{}", capture.body);
    Ok(())
}

fn graph(path: &Path, target: &str, json: bool) -> Result<()> {
    let analysis = Analysis::open(path)?;
    let function = analysis
        .resolve(target)
        .and_then(|va| analysis.function_containing(va))
        .with_context(|| format!("no function at {target}"))?;
    let cfg = Cfg::build(&analysis.listing(), &analysis.data, function);

    if json {
        return print_json(&cfg);
    }
    for (index, block) in cfg.blocks.iter().enumerate() {
        let edges: Vec<String> = block
            .edges
            .iter()
            .map(|edge| format!("{}:{:?}", edge.to, edge.kind))
            .collect();
        println!(
            "blk_{index:<4} {:#x} {:>5} lines  -> {}",
            block.va,
            block.lines.len(),
            edges.join(" ")
        );
    }
    Ok(())
}

fn inspect(path: &Path, json: bool) -> Result<()> {
    let report = Analysis::open(path)?.inspect();
    if json {
        return print_json(&report);
    }

    println!(
        "entropy: {:.2} / 8.00 ({})",
        report.entropy,
        entropy_label(report.entropy)
    );
    println!("imports: {}", report.import_count);
    for section in &report.sections {
        println!(
            "{:<12} {:#018x} {:>10} {:.2}",
            section.name, section.va, section.size, section.entropy
        );
    }
    if report.detections.is_empty() {
        println!("no packer or protector signature matched");
    }
    for detection in &report.detections {
        println!(
            "{:?}: {} ({})",
            detection.confidence, detection.name, detection.evidence
        );
    }
    Ok(())
}

fn strings(path: &Path, json: bool) -> Result<()> {
    let listing = Analysis::open(path)?.listing();
    if json {
        return print_json(&listing.strings);
    }
    for entry in &listing.strings {
        match &entry.base64 {
            Some(decoded) => println!("{:#018x} {}  [base64: {decoded}]", entry.va, entry.value),
            None => println!("{:#018x} {}", entry.va, entry.value),
        }
    }
    Ok(())
}

fn xor(path: &Path, json: bool) -> Result<()> {
    let analysis = Analysis::open(path)?;
    let hits = scan_xor(&analysis.data, &analysis.sections);
    if json {
        return print_json(&hits);
    }
    for hit in &hits {
        println!("{:#018x} key={:02X} {}", hit.va, hit.key, hit.text);
    }
    Ok(())
}

fn analyze(path: &Path, save: Option<&Path>, json: bool) -> Result<()> {
    let analysis = Analysis::open(path)?;
    if let Some(save) = save {
        let written = analysis.save_dataset(save, serde_json::Value::Null)?;
        eprintln!("saved {written} bytes from {}", analysis.data.len());
    }

    if json {
        return print_json(&Summary::from(&analysis));
    }

    let summary = Summary::from(&analysis);
    println!("arch:      {:?}", summary.arch);
    println!("entry:     {:#x}", summary.entry);
    println!("sections:  {}", summary.sections);
    println!("functions: {}", summary.functions);
    Ok(())
}

fn functions(path: &Path, json: bool) -> Result<()> {
    let analysis = Analysis::open(path)?;
    if json {
        return print_json(&analysis.functions);
    }

    for function in &analysis.functions {
        let name = function.name.as_deref().unwrap_or("-");
        println!("{:#018x} {:>8} {name}", function.va, function.size);
    }
    Ok(())
}

fn print_json(value: &impl Serialize) -> Result<()> {
    println!("{}", serde_json::to_string_pretty(value)?);
    Ok(())
}

#[derive(Serialize)]
struct Summary {
    arch: euphoria_engine::Arch,
    entry: u64,
    sections: usize,
    functions: usize,
}

impl From<&Analysis> for Summary {
    fn from(analysis: &Analysis) -> Self {
        Self {
            arch: analysis.arch,
            entry: analysis.entry,
            sections: analysis.sections.len(),
            functions: analysis.functions.len(),
        }
    }
}

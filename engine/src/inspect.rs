use serde::Serialize;

use crate::{Analysis, Arch, Function, Listing, Section};

pub const PACKED_ENTROPY: f32 = 7.2;
const COMPRESSED_ENTROPY: f32 = 6.5;
const FEW_IMPORTS: usize = 5;
const MAGIC_SEARCH_BYTES: usize = 4096;
const LARGEST_ROUTINES: usize = 10;

const SECTION_SIGNATURES: &[(&str, &str)] = &[
    ("UPX0", "UPX"),
    ("UPX1", "UPX"),
    ("UPX2", "UPX"),
    (".aspack", "ASPack"),
    (".adata", "ASPack"),
    (".themida", "Themida"),
    (".winlice", "WinLicense"),
    (".vmp0", "VMProtect"),
    (".vmp1", "VMProtect"),
    (".vmp2", "VMProtect"),
    (".MPRESS1", "MPRESS"),
    (".MPRESS2", "MPRESS"),
    ("PEC2", "PECompact"),
    ("PEC2TO", "PECompact"),
    ("PEC2MO", "PECompact"),
    ("pec1", "PECompact"),
    (".enigma1", "Enigma Protector"),
    (".enigma2", "Enigma Protector"),
    (".petite", "Petite"),
    (".nsp0", "NsPack"),
    (".nsp1", "NsPack"),
    (".y0da", "yoda's Protector"),
    (".ndata", "NSIS installer"),
];

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Confidence {
    Low,
    Medium,
    High,
}

#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct Detection {
    pub name: String,
    pub confidence: Confidence,
    pub evidence: String,
}

#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct SectionReport {
    pub name: String,
    pub va: u64,
    pub size: u64,
    pub executable: bool,
    pub entropy: f32,
}

#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct Inspection {
    pub size: usize,
    pub entropy: f32,
    pub import_count: usize,
    pub sections: Vec<SectionReport>,
    pub detections: Vec<Detection>,
}

#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct RoutineSummary {
    pub va: u64,
    pub size: u64,
    pub name: Option<String>,
}

// A canonical summary of one binary. Every list has a fixed order so two runs on the same bytes
// produce the same document, byte for byte, which makes diffs and automation reliable.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct Overview {
    pub file: String,
    pub arch: String,
    pub sha256: String,
    pub size: usize,
    pub entry: u64,
    pub entropy: f32,
    pub import_count: usize,
    pub imports: Vec<String>,
    pub sections: Vec<SectionReport>,
    pub detections: Vec<Detection>,
    pub routine_count: usize,
    pub string_count: usize,
    pub xref_count: usize,
    pub code_coverage: f32,
    pub largest: Vec<RoutineSummary>,
    pub findings: Vec<String>,
}

pub fn overview(analysis: &Analysis, listing: &Listing) -> Overview {
    let inspection = analysis.inspect();

    let mut imports = analysis.imports.clone();
    imports.sort();
    imports.dedup();

    let (covered, executable) = function_coverage(&analysis.functions, &analysis.sections);
    let code_coverage = if executable == 0 {
        0.0
    } else {
        (covered as f64 / executable as f64 * 100.0) as f32
    };

    let mut functions: Vec<&Function> = analysis.functions.iter().collect();
    functions.sort_by(|a, b| b.size.cmp(&a.size).then(a.va.cmp(&b.va)));
    let largest = functions
        .into_iter()
        .take(LARGEST_ROUTINES)
        .map(|function| RoutineSummary {
            va: function.va,
            size: function.size,
            name: function.name.clone(),
        })
        .collect();

    let mut findings = Vec::new();
    if analysis.function_containing(analysis.entry).is_none() {
        findings.push("Entry point is outside every known routine".to_owned());
    }
    if analysis.imports.is_empty() {
        findings.push("No imports; the file may be statically linked or packed".to_owned());
    }
    if executable > 0 {
        findings.push(format!(
            "Routines cover {code_coverage:.1}% of executable bytes"
        ));
    }

    Overview {
        file: analysis.file_name.clone(),
        arch: arch_name(analysis.arch).to_owned(),
        sha256: analysis.sha256.clone(),
        size: analysis.data.len(),
        entry: analysis.entry,
        entropy: inspection.entropy,
        import_count: analysis.imports.len(),
        imports,
        sections: inspection.sections,
        detections: inspection.detections,
        routine_count: analysis.functions.len(),
        string_count: listing.strings.len(),
        xref_count: listing.xrefs.len(),
        code_coverage,
        largest,
        findings,
    }
}

// Bytes of executable sections that at least one routine claims, clipped to the section and
// merged so overlapping routines are only counted once.
fn function_coverage(functions: &[Function], sections: &[Section]) -> (u64, u64) {
    let executable: u64 = sections
        .iter()
        .filter(|section| section.executable)
        .map(|section| section.size)
        .sum();

    let mut ranges = Vec::new();
    for function in functions {
        let end = function.va.saturating_add(function.size);
        for section in sections.iter().filter(|section| section.executable) {
            let section_end = section.va.saturating_add(section.size);
            let from = function.va.max(section.va);
            let to = end.min(section_end);
            if from < to {
                ranges.push((from, to));
            }
        }
    }
    ranges.sort_unstable();

    let mut merged: Vec<(u64, u64)> = Vec::new();
    for (from, to) in ranges {
        match merged.last_mut() {
            Some(last) if from <= last.1 => last.1 = last.1.max(to),
            _ => merged.push((from, to)),
        }
    }
    let covered = merged.iter().map(|(from, to)| to - from).sum();
    (covered, executable)
}

fn arch_name(arch: Arch) -> &'static str {
    match arch {
        Arch::X86_64 => "x86_64",
        Arch::X86 => "x86",
        Arch::Aarch64 => "aarch64",
    }
}

// Shannon entropy in bits per byte, from 0.0 to 8.0.
pub fn entropy(bytes: &[u8]) -> f32 {
    if bytes.is_empty() {
        return 0.0;
    }

    let mut counts = [0u64; 256];
    for &byte in bytes {
        counts[usize::from(byte)] += 1;
    }

    let total = bytes.len() as f64;
    let bits: f64 = counts
        .iter()
        .filter(|&&count| count > 0)
        .map(|&count| {
            let share = count as f64 / total;
            -share * share.log2()
        })
        .sum();
    bits.abs() as f32
}

pub fn entropy_label(value: f32) -> &'static str {
    if value >= PACKED_ENTROPY {
        "Likely packed, compressed, or encrypted"
    } else if value >= COMPRESSED_ENTROPY {
        "Dense data or compiled code"
    } else {
        "Typical uncompressed content"
    }
}

pub fn inspect(
    data: &[u8],
    entry: u64,
    sections: &[Section],
    names: &[String],
    import_count: usize,
) -> Inspection {
    let reports: Vec<SectionReport> = sections
        .iter()
        .zip(names)
        .map(|(section, name)| {
            let start = section.offset as usize;
            let end = start.saturating_add(section.size as usize).min(data.len());
            SectionReport {
                name: name.clone(),
                va: section.va,
                size: section.size,
                executable: section.executable,
                entropy: data.get(start..end).map_or(0.0, entropy),
            }
        })
        .collect();

    let mut detections = find_signatures(data, &reports);
    detections.extend(find_heuristics(entry, sections, &reports, import_count));
    detections.sort_by_key(|detection| std::cmp::Reverse(detection.confidence));

    Inspection {
        size: data.len(),
        entropy: entropy(data),
        import_count,
        sections: reports,
        detections,
    }
}

fn find_signatures(data: &[u8], reports: &[SectionReport]) -> Vec<Detection> {
    let mut detections: Vec<Detection> = Vec::new();

    for report in reports {
        let Some((_, packer)) = SECTION_SIGNATURES
            .iter()
            .find(|(name, _)| *name == report.name)
        else {
            continue;
        };
        let dense = report.entropy >= COMPRESSED_ENTROPY;
        let evidence = format!("Section {} (entropy {:.2})", report.name, report.entropy);

        match detections.iter_mut().find(|found| found.name == *packer) {
            Some(found) => {
                found.evidence = format!("{}, {evidence}", found.evidence);
                if dense {
                    found.confidence = Confidence::High;
                }
            }
            None => detections.push(Detection {
                name: (*packer).to_owned(),
                confidence: if dense {
                    Confidence::High
                } else {
                    Confidence::Medium
                },
                evidence,
            }),
        }
    }

    let head = &data[..data.len().min(MAGIC_SEARCH_BYTES)];
    if head.windows(4).any(|window| window == b"UPX!") {
        match detections.iter_mut().find(|found| found.name == "UPX") {
            Some(found) => {
                found.confidence = Confidence::High;
                found.evidence = format!("{}, UPX! marker in the header", found.evidence);
            }
            None => detections.push(Detection {
                name: "UPX".to_owned(),
                confidence: Confidence::High,
                evidence: "UPX! marker in the header".to_owned(),
            }),
        }
    }
    detections
}

fn find_heuristics(
    entry: u64,
    sections: &[Section],
    reports: &[SectionReport],
    import_count: usize,
) -> Vec<Detection> {
    let mut detections = Vec::new();

    let dense_code: Vec<&SectionReport> = reports
        .iter()
        .filter(|report| report.executable && report.entropy >= PACKED_ENTROPY)
        .collect();
    if let Some(densest) = dense_code
        .iter()
        .max_by(|a, b| a.entropy.total_cmp(&b.entropy))
    {
        let few_imports = import_count <= FEW_IMPORTS;
        detections.push(Detection {
            name: "Packed or encrypted code".to_owned(),
            confidence: if few_imports {
                Confidence::High
            } else {
                Confidence::Medium
            },
            evidence: format!(
                "Executable section {} has entropy {:.2}, {import_count} imports",
                densest.name, densest.entropy
            ),
        });
    }

    let first_code = sections.iter().position(|section| section.executable);
    let entry_section = sections
        .iter()
        .position(|s| entry >= s.va && entry - s.va < s.size);
    if let (Some(first), Some(found)) = (first_code, entry_section)
        && first != found
    {
        detections.push(Detection {
            name: "Unusual entry point".to_owned(),
            confidence: Confidence::Low,
            evidence: format!("Entry point is in section {}", reports[found].name),
        });
    }
    detections
}

#[cfg(test)]
mod tests {
    use super::*;

    fn section(offset: u64, size: u64, executable: bool) -> Section {
        Section {
            va: 0x1000 + offset,
            offset,
            size,
            executable,
        }
    }

    fn uniform(len: usize) -> Vec<u8> {
        (0..len).map(|i| i as u8).collect()
    }

    #[test]
    fn entropy_covers_the_full_range() {
        assert_eq!(entropy(&[]), 0.0);
        assert_eq!(entropy(&[7; 100]), 0.0);
        assert!((entropy(&[0, 1]) - 1.0).abs() < 0.001);
        assert!((entropy(&uniform(256)) - 8.0).abs() < 0.001);
    }

    #[test]
    fn identifies_a_packer_from_section_names_and_density() {
        let data = uniform(512);
        let sections = [section(0, 256, false), section(256, 256, true)];
        let names = ["UPX0".to_owned(), "UPX1".to_owned()];

        let report = inspect(&data, 0x1000 + 256, &sections, &names, 40);
        let upx = report.detections.iter().find(|d| d.name == "UPX").unwrap();
        assert_eq!(upx.confidence, Confidence::High);
        assert!(upx.evidence.contains("UPX1"));
    }

    #[test]
    fn a_section_name_alone_is_only_medium_confidence() {
        let data = vec![0u8; 256];
        let sections = [section(0, 256, true)];
        let names = [".vmp0".to_owned()];

        let report = inspect(&data, 0x1000, &sections, &names, 40);
        assert_eq!(report.detections[0].name, "VMProtect");
        assert_eq!(report.detections[0].confidence, Confidence::Medium);
    }

    #[test]
    fn flags_dense_code_with_few_imports() {
        let data = uniform(256);
        let sections = [section(0, 256, true)];
        let names = [".text".to_owned()];

        let few = inspect(&data, 0x1000, &sections, &names, 2);
        assert_eq!(few.detections[0].confidence, Confidence::High);

        let many = inspect(&data, 0x1000, &sections, &names, 50);
        assert_eq!(many.detections[0].confidence, Confidence::Medium);
    }

    #[test]
    fn stays_quiet_on_normal_files() {
        let data = vec![0x90u8; 512];
        let sections = [section(0, 256, true), section(256, 256, false)];
        let names = [".text".to_owned(), ".data".to_owned()];

        assert!(
            inspect(&data, 0x1000, &sections, &names, 40)
                .detections
                .is_empty()
        );
    }

    #[test]
    fn counts_each_executable_byte_once() {
        let code = Section {
            va: 0x1000,
            offset: 0,
            size: 0x100,
            executable: true,
        };
        let data = Section {
            va: 0x2000,
            offset: 0,
            size: 0x100,
            executable: false,
        };
        let functions = [
            Function {
                va: 0x1000,
                size: 0x80,
                name: None,
            },
            Function {
                va: 0x1070,
                size: 0x40,
                name: None,
            },
            Function {
                va: 0x10F0,
                size: 0x20,
                name: None,
            },
            Function {
                va: 0x2000,
                size: 0x100,
                name: None,
            },
        ];

        assert_eq!(function_coverage(&functions, &[code, data]), (0xC0, 0x100));
    }

    #[test]
    fn overview_is_identical_on_every_run() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../samples/hello.exe");
        let analysis = Analysis::open(&path).unwrap();
        let listing = analysis.listing();
        let first = overview(&analysis, &listing);
        let second = overview(&analysis, &listing);
        assert_eq!(first, second);

        let reopened = Analysis::open(&path).unwrap();
        let other = overview(&reopened, &reopened.listing());
        assert_eq!(first, other);
        assert_eq!(
            serde_json::to_string(&first).unwrap(),
            serde_json::to_string(&other).unwrap()
        );

        assert_eq!(first.arch, "x86_64");
        assert!(first.routine_count > 0);
        assert!(first.code_coverage > 0.0 && first.code_coverage <= 100.0);
        assert!(first.imports.windows(2).all(|pair| pair[0] <= pair[1]));
        assert!(
            first
                .largest
                .windows(2)
                .all(|pair| pair[0].size > pair[1].size
                    || (pair[0].size == pair[1].size && pair[0].va < pair[1].va))
        );
    }

    #[test]
    fn notes_an_entry_point_outside_the_first_code_section() {
        let data = vec![0x90u8; 512];
        let sections = [section(0, 256, true), section(256, 256, true)];
        let names = [".text".to_owned(), ".odd".to_owned()];

        let report = inspect(&data, 0x1000 + 256, &sections, &names, 40);
        assert_eq!(report.detections[0].name, "Unusual entry point");
        assert_eq!(report.detections[0].confidence, Confidence::Low);
    }
}

use serde::Serialize;

use crate::Section;

pub const PACKED_ENTROPY: f32 = 7.2;
const COMPRESSED_ENTROPY: f32 = 6.5;
const FEW_IMPORTS: usize = 5;
const MAGIC_SEARCH_BYTES: usize = 4096;

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
    fn notes_an_entry_point_outside_the_first_code_section() {
        let data = vec![0x90u8; 512];
        let sections = [section(0, 256, true), section(256, 256, true)];
        let names = [".text".to_owned(), ".odd".to_owned()];

        let report = inspect(&data, 0x1000 + 256, &sections, &names, 40);
        assert_eq!(report.detections[0].name, "Unusual entry point");
        assert_eq!(report.detections[0].confidence, Confidence::Low);
    }
}

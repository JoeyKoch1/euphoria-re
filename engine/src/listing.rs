use std::ops::Range;

use iced_x86::{
    Decoder, DecoderOptions, FlowControl, Formatter, FormatterOutput, FormatterTextKind,
    Instruction, IntelFormatter, Mnemonic, OpKind, Register,
};
use serde::Serialize;

use crate::decode::base64_text;
use crate::{Arch, Function, Section};

const MIN_STRING_LEN: usize = 5;

#[derive(Clone, Copy, Debug)]
pub struct Row {
    pub va: u64,
    offset: usize,
    len: u8,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum XrefKind {
    Call,
    Jump,
    Data,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct Xref {
    pub from: u64,
    pub to: u64,
    pub kind: XrefKind,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct StringEntry {
    pub va: u64,
    pub value: String,
    pub base64: Option<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Flow {
    Next,
    Jump,
    Branch,
    Stop,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TokenKind {
    Mnemonic,
    Call,
    Register,
    Number,
    Target,
    Text,
}

#[derive(Clone, Debug)]
pub struct Token {
    pub text: String,
    pub kind: TokenKind,
}

#[derive(Clone, Debug)]
pub struct Line {
    pub va: u64,
    pub bytes: Vec<u8>,
    pub tokens: Vec<Token>,
    pub branch: Option<u64>,
    pub data: Option<u64>,
    pub flow: Flow,
}

#[derive(Default)]
pub struct Listing {
    pub rows: Vec<Row>,
    pub xrefs: Vec<Xref>,
    pub strings: Vec<StringEntry>,
    bitness: u32,
    mapped: Vec<(u64, u64)>,
}

impl Listing {
    pub fn build(data: &[u8], arch: Arch, sections: &[Section], functions: &[Function]) -> Self {
        let mut listing = Self {
            strings: find_strings(data, sections),
            bitness: bitness_of(arch).unwrap_or(0),
            mapped: sections
                .iter()
                .filter(|section| section.size > 0)
                .map(|section| (section.va, section.size))
                .collect(),
            ..Self::default()
        };

        if listing.bitness != 0 {
            for function in functions {
                if let Some(offset) = file_offset(sections, function.va) {
                    listing.decode_function(data, offset, function);
                }
            }
        }

        listing.xrefs.sort_by_key(|xref| (xref.to, xref.from));
        listing
    }

    fn data_target(&self, instruction: &Instruction) -> Option<u64> {
        if instruction.is_ip_rel_memory_operand() {
            return Some(instruction.ip_rel_memory_address());
        }

        (0..instruction.op_count())
            .find_map(|operand| match instruction.op_kind(operand) {
                OpKind::Memory
                    if instruction.memory_base() == Register::None
                        && instruction.memory_index() == Register::None =>
                {
                    Some(instruction.memory_displacement64())
                }
                OpKind::Immediate32 => Some(u64::from(instruction.immediate32())),
                OpKind::Immediate32to64 => Some(instruction.immediate32to64() as u64),
                OpKind::Immediate64 => Some(instruction.immediate64()),
                _ => None,
            })
            .filter(|&va| {
                self.mapped
                    .iter()
                    .any(|&(start, size)| va >= start && va - start < size)
            })
    }

    fn decode_function(&mut self, data: &[u8], offset: usize, function: &Function) {
        let end = offset
            .saturating_add(function.size as usize)
            .min(data.len());
        let Some(bytes) = data.get(offset..end) else {
            return;
        };

        let mut decoder = Decoder::with_ip(self.bitness, bytes, function.va, DecoderOptions::NONE);
        let mut instruction = Instruction::default();
        while decoder.can_decode() {
            let position = decoder.position();
            decoder.decode_out(&mut instruction);
            self.rows.push(Row {
                va: instruction.ip(),
                offset: offset + position,
                len: instruction.len() as u8,
            });
            self.record_xrefs(&instruction);
        }
    }

    fn record_xrefs(&mut self, instruction: &Instruction) {
        let from = instruction.ip();
        if let Some(to) = branch_target(instruction) {
            let kind = match instruction.flow_control() {
                FlowControl::Call => XrefKind::Call,
                _ => XrefKind::Jump,
            };
            self.xrefs.push(Xref { from, to, kind });
        }
        if let Some(to) = self.data_target(instruction) {
            self.xrefs.push(Xref {
                from,
                to,
                kind: XrefKind::Data,
            });
        }
    }

    pub fn row_at(&self, va: u64) -> Option<usize> {
        let index = self.rows.partition_point(|row| row.va <= va);
        index.checked_sub(1)
    }

    pub fn rows_of(&self, function: &Function) -> Range<usize> {
        let end = function.va + function.size;
        self.rows.partition_point(|row| row.va < function.va)
            ..self.rows.partition_point(|row| row.va < end)
    }

    pub fn xrefs_to(&self, va: u64) -> &[Xref] {
        let start = self.xrefs.partition_point(|xref| xref.to < va);
        let end = self.xrefs.partition_point(|xref| xref.to <= va);
        &self.xrefs[start..end]
    }

    pub fn string_at(&self, va: u64) -> Option<&StringEntry> {
        let index = self
            .strings
            .binary_search_by_key(&va, |entry| entry.va)
            .ok()?;
        Some(&self.strings[index])
    }

    pub fn jumps(&self, max_rows: usize) -> Vec<(usize, usize)> {
        self.xrefs
            .iter()
            .filter(|xref| xref.kind == XrefKind::Jump)
            .filter_map(|xref| Some((self.exact_row(xref.from)?, self.exact_row(xref.to)?)))
            .filter(|(from, to)| from.abs_diff(*to) <= max_rows)
            .collect()
    }

    fn exact_row(&self, va: u64) -> Option<usize> {
        self.rows.binary_search_by_key(&va, |row| row.va).ok()
    }

    pub fn render(&self, data: &[u8], range: Range<usize>) -> Vec<Line> {
        let mut formatter = IntelFormatter::new();
        let options = formatter.options_mut();
        options.set_hex_prefix("0x");
        options.set_hex_suffix("");
        options.set_uppercase_hex(false);
        options.set_space_after_operand_separator(true);
        options.set_branch_leading_zeros(false);

        self.rows[range]
            .iter()
            .map(|row| self.render_row(data, row, &mut formatter))
            .collect()
    }

    fn render_row(&self, data: &[u8], row: &Row, formatter: &mut IntelFormatter) -> Line {
        let bytes = &data[row.offset..row.offset + usize::from(row.len)];
        let mut decoder = Decoder::with_ip(self.bitness, bytes, row.va, DecoderOptions::NONE);
        let instruction = decoder.decode();

        let is_call = instruction.flow_control() == FlowControl::Call;
        let mut tokens = Tokens {
            is_call,
            tokens: Vec::new(),
        };
        formatter.format(&instruction, &mut tokens);

        Line {
            va: row.va,
            bytes: bytes.to_vec(),
            tokens: tokens.tokens,
            branch: branch_target(&instruction),
            data: self.data_target(&instruction),
            flow: flow_of(&instruction),
        }
    }
}

fn bitness_of(arch: Arch) -> Option<u32> {
    match arch {
        Arch::X86_64 => Some(64),
        Arch::X86 => Some(32),
        Arch::Aarch64 => None,
    }
}

fn flow_of(instruction: &Instruction) -> Flow {
    match instruction.flow_control() {
        FlowControl::UnconditionalBranch => Flow::Jump,
        FlowControl::ConditionalBranch => Flow::Branch,
        FlowControl::IndirectBranch | FlowControl::Return | FlowControl::Exception => Flow::Stop,
        FlowControl::Interrupt if instruction.mnemonic() == Mnemonic::Int3 => Flow::Stop,
        _ => Flow::Next,
    }
}

fn branch_target(instruction: &Instruction) -> Option<u64> {
    match instruction.op0_kind() {
        OpKind::NearBranch64 => Some(instruction.near_branch64()),
        OpKind::NearBranch32 => Some(u64::from(instruction.near_branch32())),
        _ => None,
    }
}

struct Tokens {
    is_call: bool,
    tokens: Vec<Token>,
}

impl FormatterOutput for Tokens {
    fn write(&mut self, text: &str, kind: FormatterTextKind) {
        let kind = match kind {
            FormatterTextKind::Mnemonic if self.is_call => TokenKind::Call,
            FormatterTextKind::Mnemonic => TokenKind::Mnemonic,
            FormatterTextKind::Register => TokenKind::Register,
            FormatterTextKind::Number => TokenKind::Number,
            FormatterTextKind::LabelAddress | FormatterTextKind::FunctionAddress => {
                TokenKind::Target
            }
            _ => TokenKind::Text,
        };
        self.tokens.push(Token {
            text: text.to_owned(),
            kind,
        });
    }
}

fn file_offset(sections: &[Section], va: u64) -> Option<usize> {
    let section = sections
        .iter()
        .find(|s| s.executable && va >= s.va && va - s.va < s.size)?;
    usize::try_from(section.offset + (va - section.va)).ok()
}

fn find_strings(data: &[u8], sections: &[Section]) -> Vec<StringEntry> {
    let mut strings = Vec::new();
    for section in sections.iter().filter(|s| !s.executable && s.size > 0) {
        let start = section.offset as usize;
        let end = start.saturating_add(section.size as usize).min(data.len());
        let Some(bytes) = data.get(start..end) else {
            continue;
        };

        let is_text = |byte: &u8| (0x20..=0x7E).contains(byte);
        let mut at = 0;
        while at < bytes.len() {
            let len = bytes[at..].iter().take_while(|byte| is_text(byte)).count();
            if len >= MIN_STRING_LEN {
                let value = String::from_utf8_lossy(&bytes[at..at + len]).into_owned();
                strings.push(StringEntry {
                    va: section.va + at as u64,
                    base64: base64_text(&value),
                    value,
                });
            }
            at += len.max(1);
        }
    }
    strings.sort_by_key(|entry| entry.va);
    strings
}

#[cfg(test)]
mod tests {
    use super::*;

    const CALL_THEN_JUMP_BACK: [u8; 9] = [
        0xE8, 0x04, 0x00, 0x00, 0x00, // call 0x1009
        0x90, // nop
        0xEB, 0xFD, // jmp 0x1005
        0xC3, // ret
    ];

    fn text(size: u64) -> Section {
        Section {
            va: 0x1000,
            offset: 0,
            size,
            executable: true,
        }
    }

    fn function(va: u64, size: u64) -> Function {
        Function {
            va,
            size,
            name: None,
        }
    }

    fn listing() -> Listing {
        Listing::build(
            &CALL_THEN_JUMP_BACK,
            Arch::X86_64,
            &[text(9)],
            &[function(0x1000, 9)],
        )
    }

    #[test]
    fn decodes_each_instruction_with_its_address() {
        let vas: Vec<u64> = listing().rows.iter().map(|row| row.va).collect();
        assert_eq!(vas, [0x1000, 0x1005, 0x1006, 0x1008]);
    }

    #[test]
    fn records_call_and_jump_references() {
        let listing = listing();
        assert_eq!(listing.xrefs_to(0x1009)[0].kind, XrefKind::Call);
        assert_eq!(listing.xrefs_to(0x1005)[0].from, 0x1006);
        assert_eq!(listing.jumps(16), [(2, 1)]);
    }

    #[test]
    fn renders_tokens_and_branch_targets() {
        let listing = listing();
        let line = &listing.render(&CALL_THEN_JUMP_BACK, 0..1)[0];
        let text: String = line.tokens.iter().map(|t| t.text.as_str()).collect();

        assert_eq!(text, "call 0x1009");
        assert_eq!(line.tokens[0].kind, TokenKind::Call);
        assert_eq!(line.branch, Some(0x1009));
        assert_eq!(line.bytes, CALL_THEN_JUMP_BACK[..5]);
    }

    #[test]
    fn decodes_32_bit_code_with_absolute_data_references() {
        let code: [u8; 13] = [
            0x68, 0x00, 0x20, 0x00, 0x00, // push 0x2000
            0xA1, 0x00, 0x20, 0x00, 0x00, // mov eax, [0x2000]
            0xEB, 0xF2, // jmp 0xFFE
            0xC3, // ret
        ];
        let mut data = code.to_vec();
        data.extend_from_slice(b"hello world\0");
        let rodata = Section {
            va: 0x2000,
            offset: code.len() as u64,
            size: 12,
            executable: false,
        };

        let listing = Listing::build(
            &data,
            Arch::X86,
            &[text(code.len() as u64), rodata],
            &[function(0x1000, code.len() as u64)],
        );

        assert_eq!(listing.rows.len(), 4);
        assert_eq!(listing.xrefs_to(0x2000).len(), 2);

        let lines = listing.render(&data, 0..3);
        assert_eq!(lines[0].data, Some(0x2000));
        assert_eq!(lines[1].data, Some(0x2000));
        assert_eq!(lines[2].branch, Some(0xFFE));
        assert_eq!(listing.string_at(0x2000).unwrap().value, "hello world");
    }

    #[test]
    fn ignores_immediates_outside_the_image() {
        let code = [0x68, 0x34, 0x12, 0x00, 0x00, 0xC3]; // push 0x1234; ret
        let listing = Listing::build(&code, Arch::X86, &[text(6)], &[function(0x1000, 6)]);
        assert_eq!(listing.render(&code, 0..1)[0].data, None);
    }

    #[test]
    fn skips_decoding_for_other_architectures() {
        let listing = Listing::build(
            &CALL_THEN_JUMP_BACK,
            Arch::Aarch64,
            &[text(9)],
            &[function(0x1000, 9)],
        );
        assert!(listing.rows.is_empty());
    }

    #[test]
    fn finds_strings_only_outside_code() {
        let data = b"\x00hello\x00abc\x00secret text\x00";
        let rodata = Section {
            va: 0x2000,
            offset: 0,
            size: data.len() as u64,
            executable: false,
        };

        let strings = Listing::build(data, Arch::X86_64, &[rodata], &[]).strings;
        let values: Vec<&str> = strings.iter().map(|s| s.value.as_str()).collect();
        assert_eq!(values, ["hello", "secret text"]);
        assert_eq!(strings[0].va, 0x2001);

        let code = Listing::build(data, Arch::X86_64, &[text(data.len() as u64)], &[]);
        assert!(code.strings.is_empty());
    }
}

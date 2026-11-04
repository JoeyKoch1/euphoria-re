use std::borrow::Cow;

use crate::dex::{Code, Dex};

const PACKED_SWITCH_PAYLOAD: u16 = 0x0100;
const SPARSE_SWITCH_PAYLOAD: u16 = 0x0200;
const ARRAY_DATA_PAYLOAD: u16 = 0x0300;
const MAX_STRING_CHARS: usize = 200;

const ARRAY_SUFFIXES: [&str; 7] = [
    "", "-wide", "-object", "-boolean", "-byte", "-char", "-short",
];
const UNARY: [&str; 21] = [
    "neg-int",
    "not-int",
    "neg-long",
    "not-long",
    "neg-float",
    "neg-double",
    "int-to-long",
    "int-to-float",
    "int-to-double",
    "long-to-int",
    "long-to-float",
    "long-to-double",
    "float-to-int",
    "float-to-long",
    "float-to-double",
    "double-to-int",
    "double-to-long",
    "double-to-float",
    "int-to-byte",
    "int-to-char",
    "int-to-short",
];
const BINARY: [&str; 32] = [
    "add-int",
    "sub-int",
    "mul-int",
    "div-int",
    "rem-int",
    "and-int",
    "or-int",
    "xor-int",
    "shl-int",
    "shr-int",
    "ushr-int",
    "add-long",
    "sub-long",
    "mul-long",
    "div-long",
    "rem-long",
    "and-long",
    "or-long",
    "xor-long",
    "shl-long",
    "shr-long",
    "ushr-long",
    "add-float",
    "sub-float",
    "mul-float",
    "div-float",
    "rem-float",
    "add-double",
    "sub-double",
    "mul-double",
    "div-double",
    "rem-double",
];
const LIT16: [&str; 8] = [
    "add-int/lit16",
    "rsub-int",
    "mul-int/lit16",
    "div-int/lit16",
    "rem-int/lit16",
    "and-int/lit16",
    "or-int/lit16",
    "xor-int/lit16",
];
const LIT8: [&str; 11] = [
    "add-int/lit8",
    "rsub-int/lit8",
    "mul-int/lit8",
    "div-int/lit8",
    "rem-int/lit8",
    "and-int/lit8",
    "or-int/lit8",
    "xor-int/lit8",
    "shl-int/lit8",
    "shr-int/lit8",
    "ushr-int/lit8",
];
const INVOKES: [&str; 5] = ["virtual", "super", "direct", "static", "interface"];
const COMPARES: [&str; 5] = [
    "cmpl-float",
    "cmpg-float",
    "cmpl-double",
    "cmpg-double",
    "cmp-long",
];
const CONDITIONS: [&str; 6] = ["eq", "ne", "lt", "ge", "gt", "le"];

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Insn {
    pub offset: u32,
    pub mnemonic: String,
    pub operands: String,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Format {
    F10x,
    F12x,
    F11n,
    F11x,
    F10t,
    F20t,
    F22x,
    F21t,
    F21s,
    F21h,
    F21hWide,
    F21c,
    F23x,
    F22b,
    F22t,
    F22s,
    F22c,
    F30t,
    F32x,
    F31i,
    F31t,
    F31c,
    F35c,
    F3rc,
    F45cc,
    F4rcc,
    F51l,
}

impl Format {
    const fn units(self) -> usize {
        match self {
            Self::F10x | Self::F12x | Self::F11n | Self::F11x | Self::F10t => 1,
            Self::F20t
            | Self::F22x
            | Self::F21t
            | Self::F21s
            | Self::F21h
            | Self::F21hWide
            | Self::F21c
            | Self::F23x
            | Self::F22b
            | Self::F22t
            | Self::F22s
            | Self::F22c => 2,
            Self::F30t
            | Self::F32x
            | Self::F31i
            | Self::F31t
            | Self::F31c
            | Self::F35c
            | Self::F3rc => 3,
            Self::F45cc | Self::F4rcc => 4,
            Self::F51l => 5,
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Reference {
    None,
    String,
    Type,
    Field,
    Method,
    CallSite,
    MethodHandle,
    Proto,
}

fn opcode(op: u8) -> (Cow<'static, str>, Format, Reference) {
    use Format as F;
    use Reference as R;

    let fixed = |name: &'static str, format, reference| (Cow::Borrowed(name), format, reference);
    let owned = |name: String, format, reference| (Cow::Owned(name), format, reference);
    let index = usize::from(op);

    match op {
        0x00 => fixed("nop", F::F10x, R::None),
        0x01 => fixed("move", F::F12x, R::None),
        0x02 => fixed("move/from16", F::F22x, R::None),
        0x03 => fixed("move/16", F::F32x, R::None),
        0x04 => fixed("move-wide", F::F12x, R::None),
        0x05 => fixed("move-wide/from16", F::F22x, R::None),
        0x06 => fixed("move-wide/16", F::F32x, R::None),
        0x07 => fixed("move-object", F::F12x, R::None),
        0x08 => fixed("move-object/from16", F::F22x, R::None),
        0x09 => fixed("move-object/16", F::F32x, R::None),
        0x0A => fixed("move-result", F::F11x, R::None),
        0x0B => fixed("move-result-wide", F::F11x, R::None),
        0x0C => fixed("move-result-object", F::F11x, R::None),
        0x0D => fixed("move-exception", F::F11x, R::None),
        0x0E => fixed("return-void", F::F10x, R::None),
        0x0F => fixed("return", F::F11x, R::None),
        0x10 => fixed("return-wide", F::F11x, R::None),
        0x11 => fixed("return-object", F::F11x, R::None),
        0x12 => fixed("const/4", F::F11n, R::None),
        0x13 => fixed("const/16", F::F21s, R::None),
        0x14 => fixed("const", F::F31i, R::None),
        0x15 => fixed("const/high16", F::F21h, R::None),
        0x16 => fixed("const-wide/16", F::F21s, R::None),
        0x17 => fixed("const-wide/32", F::F31i, R::None),
        0x18 => fixed("const-wide", F::F51l, R::None),
        0x19 => fixed("const-wide/high16", F::F21hWide, R::None),
        0x1A => fixed("const-string", F::F21c, R::String),
        0x1B => fixed("const-string/jumbo", F::F31c, R::String),
        0x1C => fixed("const-class", F::F21c, R::Type),
        0x1D => fixed("monitor-enter", F::F11x, R::None),
        0x1E => fixed("monitor-exit", F::F11x, R::None),
        0x1F => fixed("check-cast", F::F21c, R::Type),
        0x20 => fixed("instance-of", F::F22c, R::Type),
        0x21 => fixed("array-length", F::F12x, R::None),
        0x22 => fixed("new-instance", F::F21c, R::Type),
        0x23 => fixed("new-array", F::F22c, R::Type),
        0x24 => fixed("filled-new-array", F::F35c, R::Type),
        0x25 => fixed("filled-new-array/range", F::F3rc, R::Type),
        0x26 => fixed("fill-array-data", F::F31t, R::None),
        0x27 => fixed("throw", F::F11x, R::None),
        0x28 => fixed("goto", F::F10t, R::None),
        0x29 => fixed("goto/16", F::F20t, R::None),
        0x2A => fixed("goto/32", F::F30t, R::None),
        0x2B => fixed("packed-switch", F::F31t, R::None),
        0x2C => fixed("sparse-switch", F::F31t, R::None),
        0x2D..=0x31 => fixed(COMPARES[index - 0x2D], F::F23x, R::None),
        0x32..=0x37 => owned(format!("if-{}", CONDITIONS[index - 0x32]), F::F22t, R::None),
        0x38..=0x3D => owned(
            format!("if-{}z", CONDITIONS[index - 0x38]),
            F::F21t,
            R::None,
        ),
        0x44..=0x4A => owned(
            format!("aget{}", ARRAY_SUFFIXES[index - 0x44]),
            F::F23x,
            R::None,
        ),
        0x4B..=0x51 => owned(
            format!("aput{}", ARRAY_SUFFIXES[index - 0x4B]),
            F::F23x,
            R::None,
        ),
        0x52..=0x58 => owned(
            format!("iget{}", ARRAY_SUFFIXES[index - 0x52]),
            F::F22c,
            R::Field,
        ),
        0x59..=0x5F => owned(
            format!("iput{}", ARRAY_SUFFIXES[index - 0x59]),
            F::F22c,
            R::Field,
        ),
        0x60..=0x66 => owned(
            format!("sget{}", ARRAY_SUFFIXES[index - 0x60]),
            F::F21c,
            R::Field,
        ),
        0x67..=0x6D => owned(
            format!("sput{}", ARRAY_SUFFIXES[index - 0x67]),
            F::F21c,
            R::Field,
        ),
        0x6E..=0x72 => owned(
            format!("invoke-{}", INVOKES[index - 0x6E]),
            F::F35c,
            R::Method,
        ),
        0x74..=0x78 => owned(
            format!("invoke-{}/range", INVOKES[index - 0x74]),
            F::F3rc,
            R::Method,
        ),
        0x7B..=0x8F => fixed(UNARY[index - 0x7B], F::F12x, R::None),
        0x90..=0xAF => fixed(BINARY[index - 0x90], F::F23x, R::None),
        0xB0..=0xCF => owned(format!("{}/2addr", BINARY[index - 0xB0]), F::F12x, R::None),
        0xD0..=0xD7 => fixed(LIT16[index - 0xD0], F::F22s, R::None),
        0xD8..=0xE2 => fixed(LIT8[index - 0xD8], F::F22b, R::None),
        0xFA => fixed("invoke-polymorphic", F::F45cc, R::Method),
        0xFB => fixed("invoke-polymorphic/range", F::F4rcc, R::Method),
        0xFC => fixed("invoke-custom", F::F35c, R::CallSite),
        0xFD => fixed("invoke-custom/range", F::F3rc, R::CallSite),
        0xFE => fixed("const-method-handle", F::F21c, R::MethodHandle),
        0xFF => fixed("const-method-type", F::F21c, R::Proto),
        _ => owned(format!("unused-{op:02x}"), F::F10x, R::None),
    }
}

fn reference_text(dex: &Dex, reference: Reference, index: u32) -> String {
    match reference {
        Reference::None => String::new(),
        Reference::String => format!("\"{}\"", escape(dex.string(index))),
        Reference::Type => dex.type_name(index).to_owned(),
        Reference::Field => dex.field_ref(index),
        Reference::Method => dex.method_ref(index),
        Reference::CallSite => format!("call_site@{index}"),
        Reference::MethodHandle => format!("method_handle@{index}"),
        Reference::Proto => dex.proto_text(index),
    }
}

fn escape(text: &str) -> String {
    let mut out = String::new();
    for (position, character) in text.chars().enumerate() {
        if position == MAX_STRING_CHARS {
            out.push_str("...");
            break;
        }
        match character {
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            _ => out.push(character),
        }
    }
    out
}

fn registers(list: &[u16]) -> String {
    let names: Vec<String> = list.iter().map(|register| format!("v{register}")).collect();
    format!("{{{}}}", names.join(", "))
}

fn register_range(first: u16, count: u16) -> String {
    if count == 0 {
        return "{}".to_owned();
    }
    let last = u32::from(first) + u32::from(count) - 1;
    format!("{{v{first} .. v{last}}}")
}

fn hex(value: i64) -> String {
    if value < 0 {
        format!("#-{:#x}", value.unsigned_abs())
    } else {
        format!("#{value:#x}")
    }
}

fn target(offset: usize, relative: i64) -> String {
    format!(
        ":{:04x}",
        (offset as i64).wrapping_add(relative) & 0xFFFF_FFFF
    )
}

fn operands(
    dex: &Dex,
    units: &[u16],
    offset: usize,
    format: Format,
    reference: Reference,
) -> String {
    use Format as F;

    let unit = |index: usize| units.get(index).copied().unwrap_or(0);
    let wide = |index: usize| u32::from(unit(index)) | (u32::from(unit(index + 1)) << 16);
    let aa = unit(0) >> 8;
    let a4 = (unit(0) >> 8) & 0xF;
    let b4 = unit(0) >> 12;
    let text = |index: u32| reference_text(dex, reference, index);

    match format {
        F::F10x => String::new(),
        F::F12x => format!("v{a4}, v{b4}"),
        F::F11n => {
            let value = i64::from(((unit(0) >> 12) as i8) << 4 >> 4);
            format!("v{a4}, #{value}")
        }
        F::F11x => format!("v{aa}"),
        F::F10t => target(offset, i64::from(aa as u8 as i8)),
        F::F20t => target(offset, i64::from(unit(1) as i16)),
        F::F22x => format!("v{aa}, v{}", unit(1)),
        F::F21t => format!("v{aa}, {}", target(offset, i64::from(unit(1) as i16))),
        F::F21s => format!("v{aa}, {}", hex(i64::from(unit(1) as i16))),
        F::F21h => format!("v{aa}, {}", hex(i64::from(i32::from(unit(1) as i16) << 16))),
        F::F21hWide => format!("v{aa}, {}", hex(i64::from(unit(1) as i16) << 48)),
        F::F21c => format!("v{aa}, {}", text(u32::from(unit(1)))),
        F::F23x => format!("v{aa}, v{}, v{}", unit(1) & 0xFF, unit(1) >> 8),
        F::F22b => format!(
            "v{aa}, v{}, {}",
            unit(1) & 0xFF,
            hex(i64::from((unit(1) >> 8) as u8 as i8))
        ),
        F::F22t => format!(
            "v{a4}, v{b4}, {}",
            target(offset, i64::from(unit(1) as i16))
        ),
        F::F22s => format!("v{a4}, v{b4}, {}", hex(i64::from(unit(1) as i16))),
        F::F22c => format!("v{a4}, v{b4}, {}", text(u32::from(unit(1)))),
        F::F30t => target(offset, i64::from(wide(1) as i32)),
        F::F32x => format!("v{}, v{}", unit(1), unit(2)),
        F::F31i => format!("v{aa}, {}", hex(i64::from(wide(1) as i32))),
        F::F31t => format!("v{aa}, {}", target(offset, i64::from(wide(1) as i32))),
        F::F31c => format!("v{aa}, {}", text(wide(1))),
        F::F35c | F::F45cc => {
            let count = usize::from(b4).min(5);
            let packed = unit(2);
            let all = [
                packed & 0xF,
                (packed >> 4) & 0xF,
                (packed >> 8) & 0xF,
                packed >> 12,
                a4,
            ];
            let list = registers(&all[..count]);
            let base = format!("{list}, {}", text(u32::from(unit(1))));
            if format == F::F45cc {
                format!("{base}, {}", dex.proto_text(u32::from(unit(3))))
            } else {
                base
            }
        }
        F::F3rc | F::F4rcc => {
            let base = format!(
                "{}, {}",
                register_range(unit(2), aa),
                text(u32::from(unit(1)))
            );
            if format == F::F4rcc {
                format!("{base}, {}", dex.proto_text(u32::from(unit(3))))
            } else {
                base
            }
        }
        F::F51l => {
            let value = u64::from(wide(1)) | (u64::from(wide(3)) << 32);
            format!("v{aa}, {}", hex(value as i64))
        }
    }
}

// Switch and array payloads sit between instructions, so they get skipped by their stated size.
fn payload(units: &[u16]) -> Option<(&'static str, usize, String)> {
    let unit = |index: usize| units.get(index).copied();
    match unit(0)? {
        PACKED_SWITCH_PAYLOAD => {
            let size = usize::from(unit(1)?);
            Some((".packed-switch", size * 2 + 4, format!("{size} targets")))
        }
        SPARSE_SWITCH_PAYLOAD => {
            let size = usize::from(unit(1)?);
            Some((".sparse-switch", size * 4 + 2, format!("{size} targets")))
        }
        ARRAY_DATA_PAYLOAD => {
            let width = usize::from(unit(1)?);
            let count = (u32::from(unit(2)?) | (u32::from(unit(3)?) << 16)) as usize;
            let bytes = width.checked_mul(count)?;
            let total = bytes.div_ceil(2).checked_add(4)?;
            Some((
                ".array-data",
                total,
                format!("{count} items of {width} bytes"),
            ))
        }
        _ => None,
    }
}

pub(crate) fn disassemble(dex: &Dex, data: &[u8], code: &Code) -> Vec<Insn> {
    let end = code
        .start
        .saturating_add(code.units.saturating_mul(2))
        .min(data.len());
    let units: Vec<u16> = data[code.start.min(end)..end]
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
        .collect();

    let mut lines = Vec::new();
    let mut at = 0;
    while at < units.len() {
        let rest = &units[at..];
        if let Some((mnemonic, size, detail)) = payload(rest) {
            lines.push(Insn {
                offset: at as u32,
                mnemonic: mnemonic.to_owned(),
                operands: detail,
            });
            at = at.saturating_add(size.max(1));
            continue;
        }

        let (mnemonic, format, reference) = opcode((rest[0] & 0xFF) as u8);
        if format.units() > rest.len() {
            lines.push(Insn {
                offset: at as u32,
                mnemonic: "(truncated)".to_owned(),
                operands: mnemonic.into_owned(),
            });
            break;
        }

        lines.push(Insn {
            offset: at as u32,
            operands: operands(dex, &rest[..format.units()], at, format, reference),
            mnemonic: mnemonic.into_owned(),
        });
        at += format.units();
    }
    lines
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dex::tests::sample_dex;

    fn decode(units: &[u16]) -> Vec<(String, String)> {
        let dex = Dex::parse("x", sample_dex()).unwrap();
        let bytes: Vec<u8> = units.iter().flat_map(|unit| unit.to_le_bytes()).collect();
        let code = Code {
            registers: 0,
            ins: 0,
            outs: 0,
            start: 0,
            units: units.len(),
        };
        disassemble(&dex, &bytes, &code)
            .into_iter()
            .map(|insn| (insn.mnemonic, insn.operands))
            .collect()
    }

    fn one(units: &[u16]) -> String {
        let lines = decode(units);
        assert_eq!(lines.len(), 1, "{lines:?}");
        format!("{} {}", lines[0].0, lines[0].1).trim().to_owned()
    }

    #[test]
    fn knows_the_opcode_table_landmarks() {
        let cases = [
            (0x00, "nop"),
            (0x0E, "return-void"),
            (0x1A, "const-string"),
            (0x28, "goto"),
            (0x2D, "cmpl-float"),
            (0x31, "cmp-long"),
            (0x32, "if-eq"),
            (0x37, "if-le"),
            (0x38, "if-eqz"),
            (0x3D, "if-lez"),
            (0x44, "aget"),
            (0x4A, "aget-short"),
            (0x4B, "aput"),
            (0x52, "iget"),
            (0x59, "iput"),
            (0x5F, "iput-short"),
            (0x60, "sget"),
            (0x67, "sput"),
            (0x6D, "sput-short"),
            (0x6E, "invoke-virtual"),
            (0x71, "invoke-static"),
            (0x72, "invoke-interface"),
            (0x74, "invoke-virtual/range"),
            (0x78, "invoke-interface/range"),
            (0x7B, "neg-int"),
            (0x8F, "int-to-short"),
            (0x90, "add-int"),
            (0x9A, "ushr-int"),
            (0x9B, "add-long"),
            (0xA5, "ushr-long"),
            (0xA6, "add-float"),
            (0xAA, "rem-float"),
            (0xAB, "add-double"),
            (0xAF, "rem-double"),
            (0xB0, "add-int/2addr"),
            (0xCF, "rem-double/2addr"),
            (0xD0, "add-int/lit16"),
            (0xD1, "rsub-int"),
            (0xD7, "xor-int/lit16"),
            (0xD8, "add-int/lit8"),
            (0xE2, "ushr-int/lit8"),
            (0xFA, "invoke-polymorphic"),
            (0xFF, "const-method-type"),
        ];
        for (op, name) in cases {
            assert_eq!(opcode(op).0, name, "opcode {op:#x}");
        }
    }

    #[test]
    fn decodes_every_operand_format() {
        assert_eq!(one(&[0x0000]), "nop");
        assert_eq!(one(&[0x2101]), "move v1, v2");
        assert_eq!(one(&[0x0102, 0x0200]), "move/from16 v1, v512");
        assert_eq!(one(&[0x0003, 0x0100, 0x0200]), "move/16 v256, v512");
        assert_eq!(one(&[0x050A]), "move-result v5");
        assert_eq!(one(&[0xF112]), "const/4 v1, #-1");
        assert_eq!(one(&[0x7012]), "const/4 v0, #7");
        assert_eq!(one(&[0x0113, 0xFFFF]), "const/16 v1, #-0x1");
        assert_eq!(one(&[0x0115, 0x0001]), "const/high16 v1, #0x10000");
        assert_eq!(one(&[0x0114, 0x5678, 0x1234]), "const v1, #0x12345678");
        assert_eq!(
            one(&[0x0018, 0x1111, 0x2222, 0x3333, 0x0444]),
            "const-wide v0, #0x444333322221111"
        );
        assert_eq!(
            one(&[0x0019, 0x0001]),
            "const-wide/high16 v0, #0x1000000000000"
        );
        assert_eq!(one(&[0x0390, 0x0403]), "add-int v3, v3, v4");
        assert_eq!(one(&[0x01D8, 0xFF02]), "add-int/lit8 v1, v2, #-0x1");
        assert_eq!(one(&[0x21D0, 0x0010]), "add-int/lit16 v1, v2, #0x10");
        assert_eq!(
            one(&[0x1022, 0x0000]).as_str(),
            "new-instance v16, Lcom/example/Main;"
        );
    }

    #[test]
    fn resolves_branch_targets_from_the_instruction() {
        let lines = decode(&[0x0000, 0xFF28]);
        assert_eq!(lines[1], ("goto".to_owned(), ":0000".to_owned()));

        assert_eq!(one(&[0x0029, 0x0010]), "goto/16 :0010");
        assert_eq!(one(&[0x002A, 0x0020, 0x0000]), "goto/32 :0020");
        assert_eq!(one(&[0x2132, 0x0005]), "if-eq v1, v2, :0005");
        assert_eq!(one(&[0x0138, 0x0003]), "if-eqz v1, :0003");
        assert_eq!(one(&[0x012B, 0x0010, 0x0000]), "packed-switch v1, :0010");
    }

    #[test]
    fn resolves_references() {
        assert_eq!(
            one(&[0x001A, 0x0000]),
            "const-string v0, \"https://example.com/api\""
        );
        assert_eq!(one(&[0x001C, 0x0001]), "const-class v0, Ljava/lang/Object;");
        assert_eq!(
            one(&[0x0060, 0x0000]),
            "sget v0, Lcom/example/Main;->count:I"
        );
        assert_eq!(
            one(&[0x1052, 0x0000]),
            "iget v0, v1, Lcom/example/Main;->count:I"
        );
        assert_eq!(
            one(&[0x206E, 0x0000, 0x0010]),
            "invoke-virtual {v0, v1}, Lcom/example/Main;->run()V"
        );
        assert_eq!(
            one(&[0x5070, 0x0000, 0x4321]),
            "invoke-direct {v1, v2, v3, v4, v0}, Lcom/example/Main;->run()V"
        );
        assert_eq!(
            one(&[0x0274, 0x0000, 0x0005]),
            "invoke-virtual/range {v5 .. v6}, Lcom/example/Main;->run()V"
        );
        assert_eq!(one(&[0x001A, 0x0999]), "const-string v0, \"?\"");
        assert_eq!(one(&[0x0060, 0x0999]), "sget v0, field@2457");
    }

    #[test]
    fn skips_payloads_by_their_size() {
        let lines = decode(&[0x0000, 0x0100, 0x0002, 0, 0, 1, 0, 2, 0, 0x000E]);
        assert_eq!(lines[1].0, ".packed-switch");
        assert_eq!(lines[1].1, "2 targets");
        assert_eq!(lines[2].0, "return-void");

        let lines = decode(&[0x0300, 0x0001, 0x0003, 0x0000, 0x0201, 0x0003, 0x000E]);
        assert_eq!(lines[0].1, "3 items of 1 bytes");
        assert_eq!(lines[1].0, "return-void");

        let lines = decode(&[0x0200, 0x0001, 0, 0, 0, 0, 0x000E]);
        assert_eq!(lines[0].0, ".sparse-switch");
        assert_eq!(lines[1].0, "return-void");
    }

    #[test]
    fn reports_truncated_code_without_panicking() {
        let lines = decode(&[0x0018, 0x0001]);
        assert_eq!(lines[0].0, "(truncated)");
        assert_eq!(lines[0].1, "const-wide");
    }

    #[test]
    fn every_opcode_decodes_without_panicking() {
        for op in 0..=255u16 {
            let _ = decode(&[op | 0xAB00, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF]);
            let _ = decode(&[op, 0, 0, 0, 0]);
            let _ = decode(&[op]);
        }
    }
}

use std::fmt;

use anyhow::{Result, bail, ensure};

use crate::dalvik::{self, Insn};

const HEADER_SIZE: usize = 0x70;
const NO_INDEX: u32 = 0xFFFF_FFFF;
const MAX_ULEB_BYTES: usize = 5;
const TYPE_ID_SIZE: usize = 4;
const PROTO_ID_SIZE: usize = 12;
const FIELD_ID_SIZE: usize = 8;
const METHOD_ID_SIZE: usize = 8;
const CLASS_DEF_SIZE: usize = 32;
const CODE_HEADER_SIZE: usize = 16;

const ACCESS_NAMES: [(u32, &str); 14] = [
    (0x0001, "public"),
    (0x0002, "private"),
    (0x0004, "protected"),
    (0x0008, "static"),
    (0x0010, "final"),
    (0x0020, "synchronized"),
    (0x0100, "native"),
    (0x0200, "interface"),
    (0x0400, "abstract"),
    (0x0800, "strict"),
    (0x1000, "synthetic"),
    (0x2000, "annotation"),
    (0x4000, "enum"),
    (0x1_0000, "constructor"),
];

#[derive(Clone, Debug, PartialEq, Eq)]
struct Proto {
    return_type: u32,
    params: Vec<u32>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct MemberId {
    class: u32,
    signature: u32,
    name: u32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Code {
    pub registers: u16,
    pub ins: u16,
    pub outs: u16,
    pub start: usize,
    pub units: usize,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Field {
    pub id: u32,
    pub access: u32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Method {
    pub id: u32,
    pub access: u32,
    pub code: Option<Code>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Class {
    pub type_index: u32,
    pub access: u32,
    pub superclass: Option<u32>,
    pub interfaces: Vec<u32>,
    pub source_file: Option<String>,
    pub fields: Vec<Field>,
    pub methods: Vec<Method>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ClassLine {
    Text(String),
    Member(String),
    Insn(Insn),
    Blank,
}

impl fmt::Display for ClassLine {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Text(text) => f.write_str(text),
            Self::Member(text) => write!(f, "{text}"),
            Self::Insn(insn) => {
                write!(
                    f,
                    "    {:04x}: {} {}",
                    insn.offset, insn.mnemonic, insn.operands
                )
            }
            Self::Blank => Ok(()),
        }
    }
}

pub struct Dex {
    pub name: String,
    pub version: String,
    pub strings: Vec<String>,
    pub classes: Vec<Class>,
    types: Vec<u32>,
    protos: Vec<Proto>,
    fields: Vec<MemberId>,
    methods: Vec<MemberId>,
    data: Vec<u8>,
}

struct Reader<'a> {
    data: &'a [u8],
}

impl Reader<'_> {
    fn u16_at(&self, at: usize) -> Option<u16> {
        let bytes = self.data.get(at..at.checked_add(2)?)?;
        Some(u16::from_le_bytes([bytes[0], bytes[1]]))
    }

    fn u32_at(&self, at: usize) -> Option<u32> {
        let bytes = self.data.get(at..at.checked_add(4)?)?;
        Some(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    fn uleb(&self, at: &mut usize) -> Option<u32> {
        let mut value = 0u32;
        for index in 0..MAX_ULEB_BYTES {
            let byte = *self.data.get(*at)?;
            *at += 1;
            value |= u32::from(byte & 0x7F) << (index * 7);
            if byte & 0x80 == 0 {
                return Some(value);
            }
        }
        None
    }

    // A table of `count` items, or None when it would run past the end of the file.
    fn table(&self, count: u32, offset: u32, item: usize) -> Option<(usize, usize)> {
        let count = count as usize;
        let start = offset as usize;
        let bytes = count.checked_mul(item)?;
        (start.checked_add(bytes)? <= self.data.len()).then_some((count, start))
    }

    fn type_list(&self, offset: u32) -> Vec<u32> {
        if offset == 0 {
            return Vec::new();
        }
        let start = offset as usize;
        let Some(count) = self.u32_at(start) else {
            return Vec::new();
        };
        (0..count as usize)
            .map_while(|index| self.u16_at(start + 4 + index * 2).map(u32::from))
            .collect()
    }

    fn string_at(&self, offset: u32) -> Option<String> {
        let mut at = offset as usize;
        let utf16_size = self.uleb(&mut at)?;
        let rest = self.data.get(at..)?;
        let end = rest.iter().position(|&byte| byte == 0)?;
        euphoria_decompiler::java_strings::decode_mutf8(&rest[..end], utf16_size)
    }
}

impl Dex {
    pub fn parse(name: &str, data: Vec<u8>) -> Result<Self> {
        let reader = Reader { data: &data };
        ensure!(
            data.len() >= HEADER_SIZE && data.starts_with(b"dex\n"),
            "this is not a DEX file"
        );

        let header = |at: usize| reader.u32_at(at).unwrap_or(0);
        let version = String::from_utf8_lossy(&data[4..7]).into_owned();

        let Some((string_count, string_start)) = reader.table(header(56), header(60), 4) else {
            bail!("the string table runs past the end of the file");
        };
        let Some((type_count, type_start)) = reader.table(header(64), header(68), TYPE_ID_SIZE)
        else {
            bail!("the type table runs past the end of the file");
        };
        let Some((proto_count, proto_start)) = reader.table(header(72), header(76), PROTO_ID_SIZE)
        else {
            bail!("the prototype table runs past the end of the file");
        };
        let Some((field_count, field_start)) = reader.table(header(80), header(84), FIELD_ID_SIZE)
        else {
            bail!("the field table runs past the end of the file");
        };
        let Some((method_count, method_start)) =
            reader.table(header(88), header(92), METHOD_ID_SIZE)
        else {
            bail!("the method table runs past the end of the file");
        };
        let Some((class_count, class_start)) =
            reader.table(header(96), header(100), CLASS_DEF_SIZE)
        else {
            bail!("the class table runs past the end of the file");
        };

        let strings: Vec<String> = (0..string_count)
            .map(|index| {
                reader
                    .u32_at(string_start + index * 4)
                    .and_then(|offset| reader.string_at(offset))
                    .unwrap_or_else(|| format!("<invalid DEX string #{index}>"))
            })
            .collect();
        let types = (0..type_count)
            .map(|index| {
                reader
                    .u32_at(type_start + index * TYPE_ID_SIZE)
                    .unwrap_or(NO_INDEX)
            })
            .collect();
        let protos = (0..proto_count)
            .map(|index| {
                let at = proto_start + index * PROTO_ID_SIZE;
                Proto {
                    return_type: reader.u32_at(at + 4).unwrap_or(NO_INDEX),
                    params: reader.type_list(reader.u32_at(at + 8).unwrap_or(0)),
                }
            })
            .collect();

        let member = |at: usize| MemberId {
            class: u32::from(reader.u16_at(at).unwrap_or(0)),
            signature: u32::from(reader.u16_at(at + 2).unwrap_or(0)),
            name: reader.u32_at(at + 4).unwrap_or(NO_INDEX),
        };
        let fields = (0..field_count)
            .map(|index| member(field_start + index * FIELD_ID_SIZE))
            .collect();
        let methods = (0..method_count)
            .map(|index| member(method_start + index * METHOD_ID_SIZE))
            .collect();

        let classes = (0..class_count)
            .map(|index| read_class(&reader, class_start + index * CLASS_DEF_SIZE, &strings))
            .collect();

        Ok(Self {
            name: name.to_owned(),
            version,
            strings,
            classes,
            types,
            protos,
            fields,
            methods,
            data,
        })
    }

    pub fn type_name(&self, index: u32) -> &str {
        self.types
            .get(index as usize)
            .and_then(|&name| self.strings.get(name as usize))
            .map_or("?", String::as_str)
    }

    pub fn string(&self, index: u32) -> &str {
        self.strings.get(index as usize).map_or("?", String::as_str)
    }

    pub fn field_ref(&self, index: u32) -> String {
        match self.fields.get(index as usize) {
            Some(field) => format!(
                "{}->{}:{}",
                self.type_name(field.class),
                self.string(field.name),
                self.type_name(field.signature)
            ),
            None => format!("field@{index}"),
        }
    }

    pub fn method_ref(&self, index: u32) -> String {
        match self.methods.get(index as usize) {
            Some(method) => format!(
                "{}->{}{}",
                self.type_name(method.class),
                self.string(method.name),
                self.proto_text(method.signature)
            ),
            None => format!("method@{index}"),
        }
    }

    pub fn proto_text(&self, index: u32) -> String {
        match self.protos.get(index as usize) {
            Some(proto) => {
                let params: String = proto
                    .params
                    .iter()
                    .map(|&param| self.type_name(param))
                    .collect();
                format!("({params}){}", self.type_name(proto.return_type))
            }
            None => format!("proto@{index}"),
        }
    }

    pub fn class_name(&self, class: &Class) -> String {
        java_name(self.type_name(class.type_index))
    }

    pub fn disassemble(&self, code: &Code) -> Vec<Insn> {
        dalvik::disassemble(self, &self.data, code)
    }

    pub fn class_lines(&self, class: &Class) -> Vec<ClassLine> {
        let mut lines = vec![ClassLine::Text(format!(
            ".class {}{}",
            access_text(class.access),
            self.type_name(class.type_index)
        ))];
        if let Some(superclass) = class.superclass {
            lines.push(ClassLine::Text(format!(
                ".super {}",
                self.type_name(superclass)
            )));
        }
        for &interface in &class.interfaces {
            lines.push(ClassLine::Text(format!(
                ".implements {}",
                self.type_name(interface)
            )));
        }
        if let Some(source) = &class.source_file {
            lines.push(ClassLine::Text(format!(".source \"{source}\"")));
        }

        for field in &class.fields {
            lines.push(ClassLine::Member(format!(
                ".field {}{}",
                access_text(field.access),
                self.field_ref(field.id)
            )));
        }
        for method in &class.methods {
            lines.push(ClassLine::Blank);
            lines.push(ClassLine::Member(format!(
                ".method {}{}",
                access_text(method.access),
                self.method_ref(method.id)
            )));
            if let Some(code) = &method.code {
                lines.push(ClassLine::Text(format!(
                    "    .registers {}, ins {}, outs {}",
                    code.registers, code.ins, code.outs
                )));
                lines.extend(self.disassemble(code).into_iter().map(ClassLine::Insn));
            }
            lines.push(ClassLine::Text(".end method".to_owned()));
        }
        lines
    }

    pub fn class_text(&self, class: &Class) -> String {
        let lines: Vec<String> = self
            .class_lines(class)
            .iter()
            .map(ToString::to_string)
            .collect();
        lines.join("\n")
    }
}

fn read_class(reader: &Reader<'_>, at: usize, strings: &[String]) -> Class {
    let read = |offset: usize| reader.u32_at(at + offset).unwrap_or(NO_INDEX);
    let superclass = read(8);
    let source = read(16);

    let mut class = Class {
        type_index: read(0),
        access: read(4),
        superclass: (superclass != NO_INDEX).then_some(superclass),
        interfaces: reader.type_list(reader.u32_at(at + 12).unwrap_or(0)),
        source_file: strings.get(source as usize).cloned(),
        fields: Vec::new(),
        methods: Vec::new(),
    };

    let data_offset = reader.u32_at(at + 24).unwrap_or(0);
    if data_offset != 0 {
        read_class_data(reader, data_offset as usize, &mut class);
    }
    class
}

fn read_class_data(reader: &Reader<'_>, offset: usize, class: &mut Class) -> Option<()> {
    let mut at = offset;
    let static_fields = reader.uleb(&mut at)?;
    let instance_fields = reader.uleb(&mut at)?;
    let direct_methods = reader.uleb(&mut at)?;
    let virtual_methods = reader.uleb(&mut at)?;

    for count in [static_fields, instance_fields] {
        let mut id = 0u32;
        for _ in 0..count {
            id = id.wrapping_add(reader.uleb(&mut at)?);
            let access = reader.uleb(&mut at)?;
            class.fields.push(Field { id, access });
        }
    }
    for count in [direct_methods, virtual_methods] {
        let mut id = 0u32;
        for _ in 0..count {
            id = id.wrapping_add(reader.uleb(&mut at)?);
            let access = reader.uleb(&mut at)?;
            let code_offset = reader.uleb(&mut at)?;
            class.methods.push(Method {
                id,
                access,
                code: read_code(reader, code_offset as usize),
            });
        }
    }
    Some(())
}

fn read_code(reader: &Reader<'_>, offset: usize) -> Option<Code> {
    if offset == 0 {
        return None;
    }
    let units = reader.u32_at(offset + 12)? as usize;
    let start = offset.checked_add(CODE_HEADER_SIZE)?;
    let end = start.checked_add(units.checked_mul(2)?)?;
    (end <= reader.data.len()).then_some(())?;
    Some(Code {
        registers: reader.u16_at(offset)?,
        ins: reader.u16_at(offset + 2)?,
        outs: reader.u16_at(offset + 4)?,
        start,
        units,
    })
}

pub(crate) fn access_text(access: u32) -> String {
    let mut text = String::new();
    for (bit, name) in ACCESS_NAMES {
        if access & bit != 0 {
            text.push_str(name);
            text.push(' ');
        }
    }
    text
}

pub(crate) fn java_name(descriptor: &str) -> String {
    let inner = descriptor
        .strip_prefix('L')
        .and_then(|rest| rest.strip_suffix(';'))
        .unwrap_or(descriptor);
    inner.replace('/', ".")
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    const INTERNET_STRING: usize = 0;

    pub(crate) fn sample_dex() -> Vec<u8> {
        let strings = [
            "https://example.com/api",
            "SGVsbG8gZnJvbSBFdXBob3JpYQ==",
            "Lcom/example/Main;",
            "Ljava/lang/Object;",
            "V",
            "run",
            "count",
            "I",
            "Main.java",
        ];
        let types = [2u32, 3, 4, 7];

        let string_ids = HEADER_SIZE;
        let type_ids = string_ids + strings.len() * 4;
        let proto_ids = type_ids + types.len() * 4;
        let field_ids = proto_ids + PROTO_ID_SIZE;
        let method_ids = field_ids + FIELD_ID_SIZE;
        let class_defs = method_ids + METHOD_ID_SIZE;
        let string_data = class_defs + CLASS_DEF_SIZE;

        let mut body = Vec::new();
        let mut string_offsets = Vec::new();
        for text in strings {
            string_offsets.push((string_data + body.len()) as u32);
            body.push(text.len() as u8);
            body.extend_from_slice(text.as_bytes());
            body.push(0);
        }
        while !(string_data + body.len()).is_multiple_of(4) {
            body.push(0);
        }

        // const-string v0, "https://..."; const/4 v1, #3; return-void
        let code_offset = string_data + body.len();
        let insns: [u16; 4] = [0x001A, INTERNET_STRING as u16, 0x1312, 0x000E];
        for value in [2u16, 0, 0, 0] {
            body.extend_from_slice(&value.to_le_bytes());
        }
        body.extend_from_slice(&0u32.to_le_bytes());
        body.extend_from_slice(&(insns.len() as u32).to_le_bytes());
        for unit in insns {
            body.extend_from_slice(&unit.to_le_bytes());
        }

        let class_data = string_data + body.len();
        // 1 static field, 0 instance fields, 0 direct methods, 1 virtual method
        body.extend_from_slice(&[1, 0, 0, 1]);
        body.extend_from_slice(&[0, 0x09]);
        body.extend_from_slice(&[0, 0x01]);
        let mut value = code_offset as u32;
        while value >= 0x80 {
            body.push((value as u8 & 0x7F) | 0x80);
            value >>= 7;
        }
        body.push(value as u8);

        let mut file = vec![0u8; HEADER_SIZE];
        file[..8].copy_from_slice(b"dex\n039\0");
        let mut set = |at: usize, value: usize| {
            file[at..at + 4].copy_from_slice(&(value as u32).to_le_bytes());
        };
        set(36, HEADER_SIZE);
        set(56, strings.len());
        set(60, string_ids);
        set(64, types.len());
        set(68, type_ids);
        set(72, 1);
        set(76, proto_ids);
        set(80, 1);
        set(84, field_ids);
        set(88, 1);
        set(92, method_ids);
        set(96, 1);
        set(100, class_defs);

        for offset in string_offsets {
            file.extend_from_slice(&offset.to_le_bytes());
        }
        for index in types {
            file.extend_from_slice(&index.to_le_bytes());
        }
        // proto: shorty unused, returns V, no parameters
        for value in [4u32, 2, 0] {
            file.extend_from_slice(&value.to_le_bytes());
        }
        // field: Main.count, type I
        file.extend_from_slice(&0u16.to_le_bytes());
        file.extend_from_slice(&3u16.to_le_bytes());
        file.extend_from_slice(&6u32.to_le_bytes());
        // method: Main.run()V
        file.extend_from_slice(&0u16.to_le_bytes());
        file.extend_from_slice(&0u16.to_le_bytes());
        file.extend_from_slice(&5u32.to_le_bytes());
        // class Main extends Object
        for value in [0u32, 1, 1, 0, 8, 0, class_data as u32, 0] {
            file.extend_from_slice(&value.to_le_bytes());
        }
        file.extend(body);
        file
    }

    #[test]
    fn reads_classes_methods_and_fields() {
        let dex = Dex::parse("classes.dex", sample_dex()).unwrap();

        assert_eq!(dex.version, "039");
        assert_eq!(dex.classes.len(), 1);
        let class = &dex.classes[0];
        assert_eq!(dex.class_name(class), "com.example.Main");
        assert_eq!(
            dex.type_name(class.superclass.unwrap()),
            "Ljava/lang/Object;"
        );
        assert_eq!(class.source_file.as_deref(), Some("Main.java"));
        assert_eq!(
            dex.field_ref(class.fields[0].id),
            "Lcom/example/Main;->count:I"
        );
        assert_eq!(
            dex.method_ref(class.methods[0].id),
            "Lcom/example/Main;->run()V"
        );
        assert_eq!(class.methods[0].code.as_ref().unwrap().units, 4);
    }

    #[test]
    fn writes_a_readable_class() {
        let dex = Dex::parse("classes.dex", sample_dex()).unwrap();
        let text = dex.class_text(&dex.classes[0]);

        assert!(text.contains(".class public Lcom/example/Main;"), "{text}");
        assert!(text.contains(".super Ljava/lang/Object;"), "{text}");
        assert!(text.contains(".source \"Main.java\""), "{text}");
        assert!(
            text.contains(".field public static Lcom/example/Main;->count:I"),
            "{text}"
        );
        assert!(
            text.contains(".method public Lcom/example/Main;->run()V"),
            "{text}"
        );
        assert!(
            text.contains("0000: const-string v0, \"https://example.com/api\""),
            "{text}"
        );
        assert!(text.contains("0002: const/4 v3, #1"), "{text}");
        assert!(text.contains("0003: return-void"), "{text}");
    }

    #[test]
    fn rejects_files_that_are_not_dex() {
        assert!(Dex::parse("x", vec![0; 200]).is_err());
        assert!(Dex::parse("x", b"dex\n".to_vec()).is_err());
    }

    #[test]
    fn rejects_tables_that_run_past_the_end() {
        let mut bad = sample_dex();
        bad[56..60].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(Dex::parse("x", bad).is_err());
    }

    #[test]
    fn survives_damage_anywhere_in_the_file() {
        let good = sample_dex();
        let exercise = |bytes: Vec<u8>| {
            if let Ok(dex) = Dex::parse("x", bytes) {
                for class in &dex.classes {
                    let _ = dex.class_text(class);
                }
            }
        };

        for cut in 0..good.len() {
            exercise(good[..cut].to_vec());
        }
        for at in 0..good.len() {
            for flip in [0xFF, 0x80, 0x01] {
                let mut bad = good.clone();
                bad[at] ^= flip;
                exercise(bad);
            }
        }
    }

    #[test]
    fn reads_multi_byte_leb_values() {
        let reader = Reader {
            data: &[0xE5, 0x8E, 0x26],
        };
        let mut at = 0;
        assert_eq!(reader.uleb(&mut at), Some(624_485));
        assert_eq!(at, 3);

        let reader = Reader { data: &[0xFF; 8] };
        let mut at = 0;
        assert_eq!(reader.uleb(&mut at), None);
    }

    #[test]
    fn converts_descriptors_to_java_names() {
        assert_eq!(java_name("Lcom/foo/Bar;"), "com.foo.Bar");
        assert_eq!(java_name("I"), "I");
    }
}

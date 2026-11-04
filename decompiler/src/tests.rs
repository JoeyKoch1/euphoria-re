use std::collections::BTreeMap;
use std::sync::Arc;

use euphoria_engine::{Analysis, Arch, Function, Listing, Section};

use crate::Decompiler;

const BASE: u64 = 0x1000;

fn analysis(code: &[u8], arch: Arch, is_pe: bool) -> Analysis {
    Analysis {
        path: "test".into(),
        arch,
        entry: BASE,
        image_base: 0,
        is_pe,
        sections: vec![Section {
            va: BASE,
            offset: 0,
            size: code.len() as u64,
            executable: true,
        }],
        functions: vec![Function {
            va: BASE,
            size: code.len() as u64,
            name: Some("target".into()),
        }],
        section_names: vec![".text".into()],
        import_count: 0,
        imports: Vec::new(),
        iat: BTreeMap::new(),
        file_name: "test".into(),
        sha256: String::new(),
        extras: serde_json::Value::Null,
        data: Arc::new(code.to_vec()),
    }
}

fn text(code: &[u8], arch: Arch, is_pe: bool) -> String {
    let analysis = analysis(code, arch, is_pe);
    let listing = Listing::build(
        &analysis.data,
        arch,
        &analysis.sections,
        &analysis.functions,
    );
    let decompiler = Decompiler::new(&analysis, &listing);
    decompiler.decompile_at(BASE).unwrap().text()
}

#[test]
fn adds_two_windows_arguments() {
    // lea eax, [rcx + rdx]; ret
    let out = text(&[0x8D, 0x04, 0x11, 0xC3], Arch::X86_64, true);
    assert!(
        out.contains("int32_t target(int32_t a1, int32_t a2)"),
        "{out}"
    );
    assert!(out.contains("return a1 + a2;"), "{out}");
}

#[test]
fn removes_the_stack_frame_and_keeps_the_logic() {
    // A 32-bit -O0 routine: push ebp; mov ebp, esp; mov eax, [ebp+8]; add eax, 5; pop ebp; ret
    let code = [
        0x55, 0x89, 0xE5, 0x8B, 0x45, 0x08, 0x83, 0xC0, 0x05, 0x5D, 0xC3,
    ];
    let out = text(&code, Arch::X86, true);
    assert!(out.contains("int32_t target(int32_t a1)"), "{out}");
    assert!(out.contains("return a1 + 5;"), "{out}");
    assert!(!out.contains("ebp") && !out.contains("rbp"), "{out}");
}

#[test]
fn turns_a_compare_and_branch_into_an_if() {
    // cmp ecx, 10; jle +5; mov eax, 1; ret; xor eax, eax; ret
    let code = [
        0x83, 0xF9, 0x0A, 0x7E, 0x06, 0xB8, 0x01, 0x00, 0x00, 0x00, 0xC3, 0x31, 0xC0, 0xC3,
    ];
    let out = text(&code, Arch::X86_64, true);
    assert!(
        out.contains("if (a1 > 10)") || out.contains("if (a1 <= 10)"),
        "{out}"
    );
    assert!(
        out.contains("return 1;") && out.contains("return 0;"),
        "{out}"
    );
}

#[test]
fn recovers_a_counting_loop() {
    // xor eax, eax; xor edx, edx; L: cmp edx, ecx; jge end; add eax, edx; inc edx; jmp L; end: ret
    let code = [
        0x31, 0xC0, 0x31, 0xD2, 0x39, 0xCA, 0x7D, 0x06, 0x01, 0xD0, 0xFF, 0xC2, 0xEB, 0xF6, 0xC3,
    ];
    let out = text(&code, Arch::X86_64, true);
    assert!(out.contains("for (") || out.contains("while ("), "{out}");
    assert!(!out.contains("goto"), "{out}");
    assert!(out.contains("return"), "{out}");
}

#[test]
fn undoes_division_by_a_constant() {
    // mov eax, ecx; mov edx, 0x55555556; imul edx; mov eax, ecx; sar eax, 31; sub edx, eax;
    // mov eax, edx; ret
    let code = [
        0x89, 0xC8, 0xBA, 0x56, 0x55, 0x55, 0x55, 0xF7, 0xEA, 0x89, 0xC8, 0xC1, 0xF8, 0x1F, 0x29,
        0xC2, 0x89, 0xD0, 0xC3,
    ];
    let out = text(&code, Arch::X86_64, true);
    assert!(out.contains("a1 / 3"), "{out}");
}

#[test]
fn reports_unsupported_architectures() {
    let analysis = analysis(&[0; 4], Arch::Aarch64, false);
    let listing = Listing::default();
    let decompiler = Decompiler::new(&analysis, &listing);
    assert!(decompiler.decompile_at(BASE).is_err());
}

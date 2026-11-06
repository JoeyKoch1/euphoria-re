use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Instant;

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
fn lifts_bit_scan_and_count_instructions() {
    // bsf eax, ecx; ret
    let out = text(&[0x0F, 0xBC, 0xC1, 0xC3], Arch::X86_64, true);
    assert!(out.contains("__bsf(a1)"), "{out}");

    // tzcnt eax, ecx; ret
    let out = text(&[0xF3, 0x0F, 0xBC, 0xC1, 0xC3], Arch::X86_64, true);
    assert!(out.contains("__tzcnt(a1)"), "{out}");

    // lzcnt eax, ecx; ret
    let out = text(&[0xF3, 0x0F, 0xBD, 0xC1, 0xC3], Arch::X86_64, true);
    assert!(out.contains("__lzcnt(a1)"), "{out}");

    // popcnt eax, ecx; ret
    let out = text(&[0xF3, 0x0F, 0xB8, 0xC1, 0xC3], Arch::X86_64, true);
    assert!(out.contains("__popcnt(a1)"), "{out}");
}

#[test]
fn lifts_bit_test_and_shift_instructions() {
    // bts eax, ecx; ret
    let out = text(&[0x0F, 0xAB, 0xC8, 0xC3], Arch::X86_64, true);
    assert!(out.contains("1 << a1"), "{out}");

    // shld eax, ecx, 2; ret
    let out = text(&[0x0F, 0xA4, 0xC8, 0x02, 0xC3], Arch::X86_64, true);
    assert!(out.contains("__shld("), "{out}");
}

#[test]
fn lifts_movbe_and_rdtsc() {
    // movbe eax, [ecx]; ret
    let out = text(&[0x0F, 0x38, 0xF0, 0x01, 0xC3], Arch::X86_64, true);
    assert!(out.contains("__bswap("), "{out}");

    // rdtsc; ret
    let out = text(&[0x0F, 0x31, 0xC3], Arch::X86_64, true);
    assert!(out.contains("__rdtsc_low()"), "{out}");
}

#[test]
fn lifts_vex_scalar_instructions() {
    // vaddsd xmm0, xmm1, xmm2; vcvttsd2si eax, xmm0; ret
    let out = text(
        &[0xC5, 0xF3, 0x58, 0xC2, 0xC5, 0xFB, 0x2C, 0xC0, 0xC3],
        Arch::X86_64,
        true,
    );
    assert!(out.contains("double a1, double a2"), "{out}");
    assert!(out.contains("(int32_t)(a1 + a2)"), "{out}");

    // vxorps xmm0, xmm0, xmm0; vcvttsd2si eax, xmm0; ret
    let out = text(
        &[0xC5, 0xF8, 0x57, 0xC0, 0xC5, 0xFB, 0x2C, 0xC0, 0xC3],
        Arch::X86_64,
        true,
    );
    assert!(out.contains("return 0;"), "{out}");
}

#[test]
fn reports_unsupported_architectures() {
    let analysis = analysis(&[0; 4], Arch::Aarch64, false);
    let listing = Listing::default();
    let decompiler = Decompiler::new(&analysis, &listing);
    assert!(decompiler.decompile_at(BASE).is_err());
}

#[test]
fn reports_fields_reached_through_a_pointer() {
    // mov eax, [rcx + 0x10]; mov [rcx + 0x14], edx; ret
    let code = [0x8B, 0x41, 0x10, 0x89, 0x51, 0x14, 0xC3];
    let analysis = analysis(&code, Arch::X86_64, true);
    let listing = Listing::build(
        &analysis.data,
        analysis.arch,
        &analysis.sections,
        &analysis.functions,
    );
    let fields = Decompiler::new(&analysis, &listing)
        .field_map(BASE)
        .unwrap();

    assert_eq!(fields.len(), 2, "{fields:?}");
    assert_eq!(fields[0].base, "rcx");
    assert_eq!(fields[0].offset, 0x10);
    assert_eq!((fields[0].reads, fields[0].writes), (1, 0));
    assert_eq!(fields[1].offset, 0x14);
    assert_eq!((fields[1].reads, fields[1].writes), (0, 1));
    assert_eq!(fields[1].type_name(), "dword");
}

#[test]
fn marks_unlifted_instructions_as_guesses() {
    // int3; ret
    let out = text(&[0xCC, 0xC3], Arch::X86_64, true);
    assert!(out.contains(r#"__asm__("int3")"#), "{out}");
    assert!(out.contains("// guessed: raw assembly"), "{out}");
}

#[test]
fn marks_indirect_calls_as_guesses() {
    // call rax; ret
    let out = text(&[0xFF, 0xD0, 0xC3], Arch::X86_64, true);
    assert!(out.contains("((int64_t (*)())"), "{out}");
    assert!(out.contains("// guessed: the callee"), "{out}");
}

#[test]
fn keeps_byte_offsets_when_a_pointer_is_incremented() {
    // xor eax, eax; test edx, edx; jle done; add eax, [rcx]; add rcx, 4; dec rdx;
    // jnz loop; done: ret
    let code = [
        0x31, 0xC0, 0x85, 0xD2, 0x7E, 0x0B, 0x03, 0x01, 0x48, 0x83, 0xC1, 0x04, 0x48, 0xFF, 0xCA,
        0x75, 0xF5, 0xC3,
    ];
    let out = text(&code, Arch::X86_64, true);
    assert!(!out.contains("int32_t *a1"), "{out}");
    assert!(out.contains("*(int32_t *)a1"), "{out}");
    assert!(out.contains("a1 += 4;"), "{out}");
}

#[test]
fn keeps_byte_offsets_through_an_address_temporary() {
    // test edx, edx; jle done; mov eax, [rcx]; lea rdx, [rcx+4]; add eax, 1;
    // mov [rdx-4], eax; mov rcx, rdx; dec edx; jnz loop; done: ret
    let code = [
        0x85, 0xD2, 0x7E, 0x13, 0x8B, 0x01, 0x48, 0x8D, 0x51, 0x04, 0x83, 0xC0, 0x01, 0x89, 0x42,
        0xFC, 0x48, 0x89, 0xD1, 0xFF, 0xCA, 0x75, 0xED, 0xC3,
    ];
    let out = text(&code, Arch::X86_64, true);
    assert!(!out.contains("int32_t *v"), "{out}");
}

// Each routine is a sum loop followed by 0x90 padding so every entry starts 64 bytes after the
// previous one, the same alignment a compiler would pick.
fn padded_routine() -> Vec<u8> {
    let mut code = vec![
        0x31, 0xC0, // xor eax, eax
        0x85, 0xC9, // test ecx, ecx
        0x7E, 0x06, // jle +6 (ret)
        0x01, 0xC8, // loop: add eax, ecx
        0xFF, 0xC9, // dec ecx
        0x75, 0xFA, // jnz loop
        0xC3, // ret
    ];
    code.resize(64, 0x90);
    code
}

fn module(count: usize) -> Analysis {
    let routine = padded_routine();
    let size = routine.len();
    let mut code = Vec::with_capacity(count * size);
    let mut functions = Vec::with_capacity(count);
    for index in 0..count {
        let va = BASE + (index * size) as u64;
        functions.push(Function {
            va,
            size: size as u64,
            name: Some(format!("routine_{index}")),
        });
        code.extend_from_slice(&routine);
    }
    let total = code.len() as u64;
    Analysis {
        path: "stress".into(),
        arch: Arch::X86_64,
        entry: BASE,
        image_base: 0,
        is_pe: true,
        sections: vec![Section {
            va: BASE,
            offset: 0,
            size: total,
            executable: true,
        }],
        functions,
        section_names: vec![".text".into()],
        import_count: 0,
        imports: Vec::new(),
        iat: BTreeMap::new(),
        file_name: "stress".into(),
        sha256: String::new(),
        extras: serde_json::Value::Null,
        data: Arc::new(code),
    }
}

#[test]
fn decompiles_arbitrary_bytes_without_panicking() {
    let mut seed = 0x9E37_79B9_7F4A_7C15u64;
    let mut next = move || {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        seed
    };

    for _ in 0..64 {
        let mut code = [0u8; 256];
        for chunk in code.chunks_mut(8) {
            chunk.copy_from_slice(&next().to_le_bytes());
        }
        let analysis = analysis(&code, Arch::X86_64, true);
        let listing = Listing::build(
            &analysis.data,
            analysis.arch,
            &analysis.sections,
            &analysis.functions,
        );
        let decompiler = Decompiler::new(&analysis, &listing);
        let _ = decompiler.decompile_at(BASE);
        let _ = decompiler.decompile_at(BASE + 128);
        for row in &listing.rows {
            let _ = decompiler.field_map(row.va);
        }
    }
}

#[test]
fn reports_throughput_on_a_large_module() {
    let routines = 500;
    let analysis = module(routines);
    let started = Instant::now();
    let listing = Listing::build(
        &analysis.data,
        analysis.arch,
        &analysis.sections,
        &analysis.functions,
    );
    let listing_time = started.elapsed();

    let started = Instant::now();
    let decompiler = Decompiler::new(&analysis, &listing);
    let mut lines = 0usize;
    for function in &analysis.functions {
        let output = decompiler
            .decompile(function)
            .unwrap_or_else(|error| panic!("{:#x}: {error}", function.va));
        lines += output.text().lines().count();
    }
    let decompile_time = started.elapsed();

    eprintln!(
        "stress: {routines} routines, {} rows, {lines} pseudo-C lines; listing {listing_time:?}, decompiling {decompile_time:?} ({:.1} routines/s)",
        listing.rows.len(),
        routines as f64 / decompile_time.as_secs_f64().max(f64::EPSILON),
    );
    // 7 real instructions plus 51 padding NOPs per 64-byte routine.
    assert_eq!(listing.rows.len(), routines * 58, "row decode drifted");
    assert!(lines >= routines * 4, "pseudo-C output went missing");
}

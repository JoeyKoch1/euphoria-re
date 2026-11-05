mod ir;
pub mod java_strings;
mod lift;
mod print;
mod ssa;
mod structure;

use std::collections::{BTreeSet, HashMap};
use std::sync::Mutex;
use std::thread;

use anyhow::{Context, Result, anyhow};
use euphoria_engine::{Analysis, Arch, Function, Listing};
use iced_x86::{
    Decoder, DecoderOptions, FlowControl, InstructionInfoFactory, Mnemonic, OpAccess, OpKind,
    Register,
};

use ir::{Base, Func, Var};
use lift::{Callee, Callees, lift};
pub use print::{Line, Token, TokenKind};

const STACK_BYTES: usize = 128 * 1024 * 1024;
const MAX_CALLEE_BYTES: u64 = 64 * 1024;
const MAX_CALL_DEPTH: u32 = 12;

pub struct Output {
    pub va: u64,
    pub name: String,
    pub lines: Vec<Line>,
}

impl Output {
    pub fn text(&self) -> String {
        let mut text = String::new();
        for line in &self.lines {
            text.push_str(&line.text());
            text.push('\n');
        }
        text
    }

    pub fn line_of(&self, va: u64) -> Option<usize> {
        self.lines
            .iter()
            .enumerate()
            .filter_map(|(index, line)| line.va.filter(|at| *at <= va).map(|at| (at, index)))
            .max_by_key(|(at, _)| *at)
            .map(|(_, index)| index)
    }
}

// One instance can serve many threads, and what it learns about called routines gets shared.
pub struct Decompiler<'a> {
    analysis: &'a Analysis,
    listing: &'a Listing,
    params: Mutex<HashMap<u64, Option<usize>>>,
    written: Mutex<HashMap<u64, Option<BTreeSet<Register>>>>,
}

struct View<'a, 'b> {
    owner: &'b Decompiler<'a>,
    deep: bool,
}

fn bitness(arch: Arch) -> u32 {
    if arch == Arch::X86 { 32 } else { 64 }
}

impl Callees for View<'_, '_> {
    fn callee(&self, va: u64) -> Callee {
        let analysis = self.owner.analysis;
        let bits = bitness(analysis.arch);
        let function = analysis.function_at(va);
        Callee {
            written: self.owner.written_by(va, 0),
            pops: function.map_or(0, |function| stack_pops(analysis, function, bits)),
            name: thunk_import(analysis, va, bits)
                .or_else(|| function.and_then(|function| function.name.clone())),
        }
    }
}

// Follows a one-instruction `jmp [import]` stub to the name of what it calls.
fn thunk_import(analysis: &Analysis, va: u64, bits: u32) -> Option<String> {
    let bytes = analysis.read(va, 16)?;
    let insn = Decoder::with_ip(bits, bytes, va, DecoderOptions::NONE).decode();
    if insn.flow_control() != FlowControl::IndirectBranch || insn.op0_kind() != OpKind::Memory {
        return None;
    }
    let slot = if insn.is_ip_rel_memory_operand() {
        insn.ip_rel_memory_address()
    } else if insn.memory_base() == Register::None && insn.memory_index() == Register::None {
        insn.memory_displacement64()
    } else {
        return None;
    };
    analysis.iat.get(&slot).cloned()
}

// How many argument bytes a 32-bit routine removes with `ret n`.
fn stack_pops(analysis: &Analysis, function: &Function, bits: u32) -> i64 {
    if bits != 32 {
        return 0;
    }
    let Some(bytes) = analysis.read(function.va, function.size as usize) else {
        return 0;
    };
    let mut decoder = Decoder::with_ip(bits, bytes, function.va, DecoderOptions::NONE);
    for insn in &mut decoder {
        if insn.mnemonic() == Mnemonic::Ret && insn.op_count() == 1 {
            return i64::from(insn.immediate16());
        }
    }
    0
}

impl<'a> Decompiler<'a> {
    pub fn new(analysis: &'a Analysis, listing: &'a Listing) -> Self {
        Self {
            analysis,
            listing,
            params: Mutex::new(HashMap::new()),
            written: Mutex::new(HashMap::new()),
        }
    }

    fn params_of(&self, va: u64) -> Option<usize> {
        if let Some(known) = self.lock().get(&va) {
            return *known;
        }
        // Marked unknown first, so recursion stops here.
        self.lock().insert(va, None);
        let function = self.analysis.function_at(va)?;
        if function.size > MAX_CALLEE_BYTES {
            return None;
        }
        let view = View {
            owner: self,
            deep: true,
        };
        let func = analyze(self.analysis, &view, function).ok()?;
        let count = ssa::parameters(&func).len();
        self.lock().insert(va, Some(count));
        Some(count)
    }

    // Every register a routine or its callees write, or None when that cannot be known because of
    // an indirect call, an import, or code that loops back into itself.
    fn written_by(&self, va: u64, depth: u32) -> Option<BTreeSet<Register>> {
        if let Some(known) = self.lock_written().get(&va) {
            return known.clone();
        }
        if depth > MAX_CALL_DEPTH {
            return None;
        }
        self.lock_written().insert(va, None);

        let function = self.analysis.function_at(va)?;
        if function.size > MAX_CALLEE_BYTES {
            return None;
        }
        let bits = bitness(self.analysis.arch);
        let bytes = self.analysis.read(va, function.size as usize)?;
        let mut factory = InstructionInfoFactory::new();
        let mut written = BTreeSet::new();
        for insn in Decoder::with_ip(bits, bytes, va, DecoderOptions::NONE) {
            match insn.flow_control() {
                FlowControl::Call => {
                    written.extend(self.written_by(insn.near_branch_target(), depth + 1)?);
                }
                FlowControl::IndirectCall | FlowControl::IndirectBranch => return None,
                FlowControl::UnconditionalBranch | FlowControl::ConditionalBranch => {
                    let target = insn.near_branch_target();
                    if target < va || target >= va + function.size {
                        written.extend(self.written_by(target, depth + 1)?);
                    }
                }
                _ => {}
            }
            for used in factory.info(&insn).used_registers() {
                if matches!(
                    used.access(),
                    OpAccess::Write
                        | OpAccess::CondWrite
                        | OpAccess::ReadWrite
                        | OpAccess::ReadCondWrite
                ) {
                    let register = used.register();
                    if register.is_xmm() || register.is_ymm() || register.is_zmm() {
                        written.insert(Register::XMM0 + register.number() as u32);
                    } else {
                        written.insert(register.full_register());
                    }
                }
            }
        }
        self.lock_written().insert(va, Some(written.clone()));
        Some(written)
    }

    fn lock_written(&self) -> std::sync::MutexGuard<'_, HashMap<u64, Option<BTreeSet<Register>>>> {
        self.written
            .lock()
            .unwrap_or_else(|error| error.into_inner())
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<u64, Option<usize>>> {
        self.params
            .lock()
            .unwrap_or_else(|error| error.into_inner())
    }

    fn run(&self, function: &Function) -> Result<Output> {
        let view = View {
            owner: self,
            deep: false,
        };
        let mut func = analyze(self.analysis, &view, function)?;
        let params: Vec<(Var, Base)> = ssa::parameters(&func);
        ssa::leave_ssa(&mut func);
        let (nodes, labels) = structure::build(&mut func);

        let original = function
            .name
            .as_deref()
            .filter(|name| print::function_name(self.analysis, function.va) != *name);
        let printer = print::Printer::new(self.analysis, self.listing, &func, labels);
        let lines = printer.finish(&nodes, &params, original);
        Ok(Output {
            va: function.va,
            name: print::function_name(self.analysis, function.va),
            lines,
        })
    }

    // Runs on its own large stack, so a huge or strange routine reports an error and nothing else
    // goes down with it.
    pub fn decompile(&self, function: &Function) -> Result<Output> {
        thread::scope(|scope| {
            thread::Builder::new()
                .stack_size(STACK_BYTES)
                .spawn_scoped(scope, || self.run(function))
                .context("could not start the decompiler thread")?
                .join()
                .map_err(|_| anyhow!("the decompiler could not handle this routine"))?
        })
    }

    pub fn decompile_at(&self, va: u64) -> Result<Output> {
        let function = self
            .analysis
            .function_containing(va)
            .ok_or_else(|| anyhow!("{va:#x} is not inside a known routine"))?;
        self.decompile(function)
    }
}

fn analyze(analysis: &Analysis, callees: &View<'_, '_>, function: &Function) -> Result<Func> {
    let (mut func, saved) = lift(analysis, callees, function)?;
    ssa::promote_slots(&mut func, &saved);
    ssa::build_ssa(&mut func);
    let owner = callees.owner;
    let deep = callees.deep;
    ssa::resolve_calls(&mut func, &|va| {
        if deep { None } else { owner.params_of(va) }
    });
    ssa::optimize(&mut func);
    ssa::narrow(&mut func);
    ssa::optimize(&mut func);
    ssa::narrow_returns(&mut func);
    Ok(func)
}

#[cfg(test)]
mod tests;

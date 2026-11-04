use std::collections::{BTreeMap, BTreeSet, HashMap};

use euphoria_engine::{Analysis, Arch, Function};
use iced_x86::{
    ConditionCode, Decoder, DecoderOptions, FlowControl, Formatter, Instruction,
    InstructionInfoFactory, IntelFormatter, Mnemonic, OpAccess, OpKind, Register,
};

use crate::ir::{Base, sign_extend};
use crate::ir::{
    BinOp, Block, Candidates, CastKind, CmpOp, Expr, Func, Origin, Stmt, StmtKind, Term, UnOp, Var,
    VarInfo, Width, mask, simplify,
};

pub const MAX_INSTRUCTIONS: usize = 30_000;
const MAX_TABLE_ENTRIES: u64 = 1024;
const MAX_STACK_ARGS: i64 = 12;

const WIN64_ARGS: [Register; 4] = [Register::RCX, Register::RDX, Register::R8, Register::R9];
const SYSV_ARGS: [Register; 6] = [
    Register::RDI,
    Register::RSI,
    Register::RDX,
    Register::RCX,
    Register::R8,
    Register::R9,
];
const NO_RETURN: [&str; 12] = [
    "ExitProcess",
    "ExitThread",
    "TerminateProcess",
    "exit",
    "_exit",
    "_Exit",
    "abort",
    "__stack_chk_fail",
    "_invoke_watson",
    "__fastfail",
    "__report_rangecheckfailure",
    "__assert_fail",
];

// Argument counts of common imports, for calls that pass along a value they were handed untouched
// and so give no other sign of having an argument at all.
const IMPORT_PARAMS: [(&str, usize); 68] = [
    ("strlen", 1),
    ("wcslen", 1),
    ("strcmp", 2),
    ("strncmp", 3),
    ("strcpy", 2),
    ("strncpy", 3),
    ("strcat", 2),
    ("strchr", 2),
    ("strrchr", 2),
    ("strstr", 2),
    ("strdup", 1),
    ("memcpy", 3),
    ("memmove", 3),
    ("memset", 3),
    ("memcmp", 3),
    ("malloc", 1),
    ("calloc", 2),
    ("realloc", 2),
    ("free", 1),
    ("atoi", 1),
    ("atol", 1),
    ("strtol", 3),
    ("abs", 1),
    ("puts", 1),
    ("putchar", 1),
    ("fclose", 1),
    ("fopen", 2),
    ("fread", 4),
    ("fwrite", 4),
    ("fflush", 1),
    ("rand", 0),
    ("srand", 1),
    ("time", 1),
    ("exit", 1),
    ("_exit", 1),
    ("abort", 0),
    ("ExitProcess", 1),
    ("ExitThread", 1),
    ("GetLastError", 0),
    ("SetLastError", 1),
    ("GetCurrentProcess", 0),
    ("GetCurrentProcessId", 0),
    ("GetCurrentThread", 0),
    ("GetCurrentThreadId", 0),
    ("GetTickCount", 0),
    ("GetTickCount64", 0),
    ("GetProcessHeap", 0),
    ("CloseHandle", 1),
    ("Sleep", 1),
    ("LoadLibraryA", 1),
    ("LoadLibraryW", 1),
    ("FreeLibrary", 1),
    ("GetProcAddress", 2),
    ("GetModuleHandleA", 1),
    ("GetModuleHandleW", 1),
    ("HeapAlloc", 3),
    ("HeapFree", 3),
    ("VirtualAlloc", 4),
    ("VirtualFree", 3),
    ("VirtualProtect", 4),
    ("WaitForSingleObject", 2),
    ("CreateFileA", 7),
    ("CreateFileW", 7),
    ("ReadFile", 5),
    ("WriteFile", 5),
    ("TerminateProcess", 2),
    ("IsDebuggerPresent", 0),
    ("OutputDebugStringA", 1),
];

pub fn import_params(name: &str) -> Option<usize> {
    let short = name.rsplit('!').next().unwrap_or(name);
    IMPORT_PARAMS
        .iter()
        .find(|(known, _)| *known == short)
        .map(|(_, count)| *count)
}

pub fn arg_registers(bits: u32, win64: bool) -> &'static [Register] {
    match (bits, win64) {
        (32, _) => &[],
        (_, true) => &WIN64_ARGS,
        _ => &SYSV_ARGS,
    }
}

// The first stack offset that holds an argument. Offset 0 is the return address.
pub fn first_stack_arg(bits: u32, win64: bool) -> i64 {
    match (bits, win64) {
        (32, _) => 4,
        (_, true) => 0x28,
        _ => 8,
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
enum Flags {
    #[default]
    Unknown,
    Compare(Width),
    Result(Width),
    Sum(Width),
    Float,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct State {
    sp: Option<i64>,
    fp: Option<i64>,
    rax_const: Option<i64>,
    flags: Flags,
}

enum Exit {
    Next(usize),
    Branch {
        code: ConditionCode,
        taken: usize,
        not_taken: usize,
    },
    Table(JumpTable),
    Return,
    NoReturn,
    Tail,
    External(u64),
}

// Where to capture the index, which register holds it, and each (case, target) pair.
type FoundTable = (u64, Register, Vec<(u64, u64)>);

struct JumpTable {
    at: u64,
    index: Register,
    cases: Vec<(u64, usize)>,
}

struct RawBlock {
    va: u64,
    code: Vec<Instruction>,
    exit: Exit,
}

pub struct Callee {
    // Registers the routine and everything it calls can change, when that can be worked out.
    // Compilers may rely on this and keep values in registers the normal rules call scratch.
    pub written: Option<BTreeSet<Register>>,
    pub pops: i64,
    pub name: Option<String>,
}

pub trait Callees {
    fn callee(&self, va: u64) -> Callee;
}

pub fn no_return(name: &str) -> bool {
    let short = name.rsplit('!').next().unwrap_or(name);
    NO_RETURN.contains(&short)
}

fn call_target_name(
    analysis: &Analysis,
    callees: &dyn Callees,
    insn: &Instruction,
) -> Option<String> {
    match insn.op0_kind() {
        OpKind::NearBranch64 | OpKind::NearBranch32 => {
            callees.callee(insn.near_branch_target()).name
        }
        OpKind::Memory => {
            let address = if insn.is_ip_rel_memory_operand() {
                insn.ip_rel_memory_address()
            } else if insn.memory_base() == Register::None && insn.memory_index() == Register::None
            {
                insn.memory_displacement64()
            } else {
                return None;
            };
            analysis.iat.get(&address).cloned()
        }
        _ => None,
    }
}

struct Cfg<'a> {
    analysis: &'a Analysis,
    callees: &'a dyn Callees,
    bits: u32,
    start: u64,
    end: u64,
}

impl Cfg<'_> {
    fn decode(&self, va: u64) -> Option<Instruction> {
        let bytes = self.analysis.read(va, 16)?;
        let mut decoder = Decoder::with_ip(self.bits, bytes, va, DecoderOptions::NONE);
        let insn = decoder.decode();
        (!insn.is_invalid()).then_some(insn)
    }

    fn inside(&self, va: u64) -> bool {
        va >= self.start && va < self.end
    }

    fn build(&self) -> anyhow::Result<Vec<RawBlock>> {
        let mut decoded: BTreeMap<u64, Instruction> = BTreeMap::new();
        let mut leaders = BTreeSet::from([self.start]);
        let mut tables: HashMap<u64, FoundTable> = HashMap::new();
        let mut pending = vec![self.start];

        while let Some(mut at) = pending.pop() {
            while self.inside(at) && !decoded.contains_key(&at) {
                let Some(insn) = self.decode(at) else {
                    break;
                };
                decoded.insert(at, insn);
                if decoded.len() > MAX_INSTRUCTIONS {
                    anyhow::bail!("this routine is too large to decompile");
                }
                let next = insn.next_ip();
                match insn.flow_control() {
                    FlowControl::Next => at = next,
                    FlowControl::Call | FlowControl::IndirectCall => {
                        if call_target_name(self.analysis, self.callees, &insn)
                            .is_some_and(|name| no_return(&name))
                        {
                            break;
                        }
                        at = next;
                    }
                    FlowControl::ConditionalBranch => {
                        let target = insn.near_branch_target();
                        if self.inside(target) {
                            leaders.insert(target);
                            pending.push(target);
                        }
                        leaders.insert(next);
                        at = next;
                    }
                    FlowControl::UnconditionalBranch => {
                        let target = insn.near_branch_target();
                        if self.inside(target) {
                            leaders.insert(target);
                            pending.push(target);
                        }
                        break;
                    }
                    FlowControl::IndirectBranch => {
                        if let Some((movsx, index, targets)) = self.jump_table(&decoded, &insn) {
                            for (_, target) in &targets {
                                leaders.insert(*target);
                                pending.push(*target);
                            }
                            tables.insert(at, (movsx, index, targets));
                        }
                        break;
                    }
                    FlowControl::Interrupt if insn.mnemonic() != Mnemonic::Int3 => at = next,
                    _ => break,
                }
            }
        }

        let mut index_of: HashMap<u64, usize> = HashMap::new();
        for &leader in leaders.iter().filter(|va| decoded.contains_key(va)) {
            let index = index_of.len();
            index_of.insert(leader, index);
        }

        let mut blocks = Vec::with_capacity(index_of.len());
        let mut external: Vec<(u64, usize)> = Vec::new();
        let mut external_block = |target: u64, count: &usize| -> usize {
            if let Some((_, index)) = external.iter().find(|(va, _)| *va == target) {
                return *index;
            }
            let index = *count + external.len();
            external.push((target, index));
            index
        };
        let total = index_of.len();

        let mut starts: Vec<u64> = index_of.keys().copied().collect();
        starts.sort_by_key(|va| index_of[va]);
        for leader in starts {
            let mut code = Vec::new();
            let mut at = leader;
            let exit = loop {
                let Some(insn) = decoded.get(&at).copied() else {
                    break Exit::NoReturn;
                };
                code.push(insn);
                let next = insn.next_ip();
                let flow = insn.flow_control();
                let is_no_return = matches!(flow, FlowControl::Call | FlowControl::IndirectCall)
                    && call_target_name(self.analysis, self.callees, &insn)
                        .is_some_and(|name| no_return(&name));
                match flow {
                    _ if is_no_return => break Exit::NoReturn,
                    FlowControl::Return => break Exit::Return,
                    FlowControl::ConditionalBranch => {
                        let target = insn.near_branch_target();
                        let taken = index_of
                            .get(&target)
                            .copied()
                            .unwrap_or_else(|| external_block(target, &total));
                        let not_taken = index_of
                            .get(&next)
                            .copied()
                            .unwrap_or_else(|| external_block(next, &total));
                        break Exit::Branch {
                            code: insn.condition_code(),
                            taken,
                            not_taken,
                        };
                    }
                    FlowControl::UnconditionalBranch => {
                        let target = insn.near_branch_target();
                        break match index_of.get(&target) {
                            Some(&to) => Exit::Next(to),
                            None => Exit::External(target),
                        };
                    }
                    FlowControl::IndirectBranch => {
                        break match tables.get(&at) {
                            Some((movsx, index, targets)) => Exit::Table(JumpTable {
                                at: *movsx,
                                index: *index,
                                cases: targets
                                    .iter()
                                    .filter_map(|(case, target)| {
                                        Some((*case, *index_of.get(target)?))
                                    })
                                    .collect(),
                            }),
                            None => Exit::Tail,
                        };
                    }
                    FlowControl::Exception => break Exit::NoReturn,
                    FlowControl::Interrupt if insn.mnemonic() == Mnemonic::Int3 => {
                        break Exit::NoReturn;
                    }
                    _ => {
                        if let Some(&to) = index_of.get(&next) {
                            break Exit::Next(to);
                        }
                        if !self.inside(next) {
                            break Exit::External(next);
                        }
                        at = next;
                    }
                }
            };
            blocks.push(RawBlock {
                va: leader,
                code,
                exit,
            });
        }

        for (target, _) in external {
            blocks.push(RawBlock {
                va: target,
                code: Vec::new(),
                exit: Exit::External(target),
            });
        }
        Ok(blocks)
    }

    // Recognizes `jmp [index * size + table]` and the position-independent form that loads a
    // 32-bit offset and adds it to a base register before jumping.
    fn jump_table(
        &self,
        decoded: &BTreeMap<u64, Instruction>,
        jump: &Instruction,
    ) -> Option<FoundTable> {
        let recent: Vec<Instruction> = decoded
            .range(..jump.ip())
            .rev()
            .take(16)
            .map(|(_, insn)| *insn)
            .collect();
        let limit = recent
            .iter()
            .find(|insn| {
                insn.mnemonic() == Mnemonic::Cmp
                    && insn.op0_kind() == OpKind::Register
                    && matches!(
                        insn.op1_kind(),
                        OpKind::Immediate8
                            | OpKind::Immediate8to32
                            | OpKind::Immediate8to64
                            | OpKind::Immediate32
                            | OpKind::Immediate32to64
                    )
            })
            .map(|insn| insn.immediate(1) + 1);

        if jump.op0_kind() == OpKind::Memory && jump.memory_index() != Register::None {
            let table = jump.memory_displacement64();
            let size = u64::from(jump.memory_index_scale());
            let index = jump.memory_index();
            return Some((jump.ip(), index, self.read_table(table, size, 0, limit)));
        }
        if jump.op0_kind() != OpKind::Register {
            return None;
        }

        let register = jump.op0_register().full_register();
        let load = recent.iter().find(|insn| {
            matches!(insn.mnemonic(), Mnemonic::Movsxd | Mnemonic::Mov)
                && insn.op0_kind() == OpKind::Register
                && insn.op0_register().full_register() == register
                && insn.op1_kind() == OpKind::Memory
                && insn.memory_index() != Register::None
                && matches!(insn.memory_index_scale(), 1 | 4)
        })?;
        if load.memory_index_scale() == 1 {
            return self.unoptimized_table(&recent, load, limit);
        }
        let lea_target = |register: Register| {
            recent.iter().find_map(|insn| {
                let is_lea = insn.mnemonic() == Mnemonic::Lea
                    && insn.op0_register().full_register() == register.full_register()
                    && insn.is_ip_rel_memory_operand();
                is_lea.then(|| insn.ip_rel_memory_address())
            })
        };
        let base = load.memory_base();
        let anchor = lea_target(base)?;
        let table = anchor.wrapping_add(load.memory_displacement64());
        let targets = self.read_table(table, 4, anchor, limit);
        Some((load.ip(), load.memory_index(), targets))
    }

    // Unoptimized code computes index * 4 in its own instruction before the table load.
    fn unoptimized_table(
        &self,
        recent: &[Instruction],
        load: &Instruction,
        limit: Option<u64>,
    ) -> Option<FoundTable> {
        let position = recent.iter().position(|insn| insn.ip() == load.ip())?;
        let earlier = &recent[position + 1..];
        let lea_of = |register: Register| {
            earlier.iter().find(|insn| {
                insn.mnemonic() == Mnemonic::Lea
                    && insn.op0_register().full_register() == register.full_register()
            })
        };
        let (table_reg, scaled_reg) = (load.memory_base(), load.memory_index());
        let (table, scaled) = match (lea_of(table_reg), lea_of(scaled_reg)) {
            (Some(table), Some(scaled)) if table.is_ip_rel_memory_operand() => (table, scaled),
            (Some(scaled), Some(table)) if table.is_ip_rel_memory_operand() => (table, scaled),
            _ => return None,
        };
        if scaled.memory_index() == Register::None || scaled.memory_index_scale() != 4 {
            return None;
        }
        let address = table.ip_rel_memory_address();
        let targets = self.read_table(address, 4, address, limit);
        Some((scaled.ip(), scaled.memory_index(), targets))
    }

    fn read_table(
        &self,
        table: u64,
        size: u64,
        anchor: u64,
        limit: Option<u64>,
    ) -> Vec<(u64, u64)> {
        let count = limit.unwrap_or(MAX_TABLE_ENTRIES).min(MAX_TABLE_ENTRIES);
        let mut targets = Vec::new();
        for case in 0..count {
            let Some(bytes) = self.analysis.read(table + case * size, size as usize) else {
                break;
            };
            let target = match (size, bytes.len()) {
                (8, 8) => u64::from_le_bytes(bytes.try_into().ok().unwrap_or_default()),
                (4, 4) => {
                    let raw = u32::from_le_bytes(bytes.try_into().ok().unwrap_or_default());
                    if anchor == 0 {
                        u64::from(raw)
                    } else {
                        anchor.wrapping_add_signed(i64::from(raw as i32))
                    }
                }
                _ => break,
            };
            if !self.inside(target) {
                break;
            }
            targets.push((case, target));
        }
        targets
    }
}

struct Lifter<'a> {
    analysis: &'a Analysis,
    callees: &'a dyn Callees,
    bits: u32,
    win64: bool,
    ptr: Width,
    vars: Vec<VarInfo>,
    by_base: HashMap<Base, Var>,
    stmts: Vec<Stmt>,
    state: State,
    va: u64,
    saved_slots: BTreeSet<i64>,
    in_prologue: bool,
    tail: bool,
    info: InstructionInfoFactory,
    formatter: IntelFormatter,
}

fn is_vector(register: Register) -> bool {
    register.is_xmm() || register.is_ymm() || register.is_zmm()
}

fn canonical(register: Register) -> Register {
    if is_vector(register) {
        Register::XMM0 + register.number() as u32
    } else {
        register.full_register()
    }
}

fn is_high_byte(register: Register) -> bool {
    matches!(
        register,
        Register::AH | Register::BH | Register::CH | Register::DH
    )
}

fn compare_condition(code: ConditionCode, a: Expr, b: Expr, width: Width) -> Expr {
    use ConditionCode as C;
    let cmp = |op| Expr::cmp(op, a.clone(), b.clone(), width);
    let intrinsic = |name: &str| Expr::Intrinsic(format!("__flag_{name}"), Vec::new(), 1);
    match code {
        C::e => cmp(CmpOp::Eq),
        C::ne => cmp(CmpOp::Ne),
        C::l => cmp(CmpOp::SLt),
        C::le => cmp(CmpOp::SLe),
        C::g => cmp(CmpOp::SGt),
        C::ge => cmp(CmpOp::SGe),
        C::b => cmp(CmpOp::ULt),
        C::be => cmp(CmpOp::ULe),
        C::a => cmp(CmpOp::UGt),
        C::ae => cmp(CmpOp::UGe),
        C::s | C::ns => {
            let difference = Expr::bin(BinOp::Sub, a.clone(), b.clone(), width);
            let op = if code == C::s { CmpOp::SLt } else { CmpOp::SGe };
            Expr::cmp(op, difference, Expr::Const(0, width), width)
        }
        C::p => Expr::Intrinsic("isunordered".into(), vec![a, b], 1),
        C::np => Expr::Intrinsic("isunordered".into(), vec![a, b], 1).negated(),
        C::o => intrinsic("overflow"),
        C::no => intrinsic("overflow").negated(),
        C::None => intrinsic("loop"),
    }
}

impl Lifter<'_> {
    fn var_for(&mut self, base: Base, width: Width, float: bool) -> Var {
        if let Some(var) = self.by_base.get(&base) {
            return *var;
        }
        let var = Var(self.vars.len() as u32);
        self.vars.push(VarInfo {
            base,
            width,
            float,
            origin: Origin::Unversioned,
        });
        self.by_base.insert(base, var);
        var
    }

    fn reg_var(&mut self, register: Register) -> Var {
        let full = canonical(register);
        if full.is_xmm() {
            self.var_for(Base::Reg(full), 8, true)
        } else {
            let ptr = self.ptr;
            self.var_for(Base::Reg(full), ptr, false)
        }
    }

    fn emit(&mut self, kind: StmtKind) {
        self.stmts.push(Stmt { va: self.va, kind });
    }

    fn assign(&mut self, var: Var, value: Expr) {
        self.emit(StmtKind::Assign { var, value });
    }

    fn known_stack(&self, full: Register) -> Option<i64> {
        match full {
            Register::RSP => self.state.sp,
            Register::RBP => self.state.fp,
            _ => None,
        }
    }

    fn read_reg(&mut self, register: Register) -> Expr {
        let full = canonical(register);
        let value = match self.known_stack(full) {
            Some(offset) => Expr::StackAddr(offset),
            None => Expr::Var(self.reg_var(full)),
        };
        if is_vector(register) {
            return value;
        }

        let ptr = self.ptr;
        if is_high_byte(register) {
            let high = Expr::bin(BinOp::Shr, value, Expr::Const(8, ptr), ptr);
            return Expr::cast(CastKind::Trunc, high, 1);
        }
        let size = register.size() as Width;
        if size >= ptr {
            value
        } else {
            Expr::cast(CastKind::Trunc, value, size)
        }
    }

    fn write_reg(&mut self, register: Register, value: Expr) {
        let full = canonical(register);
        if full == Register::RSP {
            self.state.sp = None;
        }
        if full == Register::RBP {
            self.state.fp = None;
        }
        if full == Register::RAX {
            self.state.rax_const = None;
        }
        let var = self.reg_var(full);
        let ptr = self.ptr;
        let size = register.size() as Width;

        let merged = if is_vector(register) || size >= ptr {
            value
        } else if size == 4 {
            Expr::cast(CastKind::Zext, value, ptr)
        } else if is_high_byte(register) {
            let kept = Expr::bin(BinOp::And, Expr::Var(var), Expr::konst(!0xFF00, ptr), ptr);
            let wide = Expr::cast(CastKind::Zext, value, ptr);
            let moved = Expr::bin(BinOp::Shl, wide, Expr::Const(8, ptr), ptr);
            Expr::bin(BinOp::Or, kept, moved, ptr)
        } else {
            let kept = Expr::bin(
                BinOp::And,
                Expr::Var(var),
                Expr::konst(!mask(size), ptr),
                ptr,
            );
            Expr::bin(BinOp::Or, kept, Expr::cast(CastKind::Zext, value, ptr), ptr)
        };
        self.assign(var, merged);
    }

    fn address(&mut self, insn: &Instruction) -> Expr {
        let ptr = self.ptr;
        if insn.is_ip_rel_memory_operand() {
            return Expr::Const(insn.ip_rel_memory_address(), ptr);
        }

        let mut parts = Vec::new();
        if insn.memory_base() != Register::None {
            parts.push(self.read_reg(insn.memory_base()));
        }
        if insn.memory_index() != Register::None {
            let index = self.read_reg(insn.memory_index());
            let scale = u64::from(insn.memory_index_scale());
            parts.push(Expr::bin(BinOp::Mul, index, Expr::Const(scale, ptr), ptr));
        }
        let displacement = Expr::konst(insn.memory_displacement64(), ptr);
        let mut value = match parts.len() {
            0 => displacement,
            _ => {
                let mut sum = parts.remove(0);
                for part in parts {
                    sum = Expr::bin(BinOp::Add, sum, part, ptr);
                }
                Expr::bin(BinOp::Add, sum, displacement, ptr)
            }
        };
        simplify(&mut value, &self.vars);
        value
    }

    fn segment_name(insn: &Instruction, width: Width) -> Option<String> {
        let prefix = match insn.memory_segment() {
            Register::FS => "__readfs",
            Register::GS => "__readgs",
            _ => return None,
        };
        let size = match width {
            1 => "byte",
            2 => "word",
            4 => "dword",
            _ => "qword",
        };
        Some(format!("{prefix}{size}"))
    }

    fn op_size(&self, insn: &Instruction, operand: u32) -> Width {
        match insn.op_kind(operand) {
            OpKind::Register => insn.op_register(operand).size() as Width,
            OpKind::Memory => insn.memory_size().size() as Width,
            OpKind::Immediate8 | OpKind::Immediate8_2nd => 1,
            OpKind::Immediate16 => 2,
            OpKind::Immediate32 => 4,
            _ => self.ptr,
        }
    }

    fn read_op(&mut self, insn: &Instruction, operand: u32, width: Width) -> Expr {
        match insn.op_kind(operand) {
            OpKind::Register => self.read_reg(insn.op_register(operand)),
            OpKind::Memory => {
                let addr = self.address(insn);
                if let Some(name) = Self::segment_name(insn, width) {
                    return Expr::Intrinsic(name, vec![addr], width);
                }
                Expr::load(addr, width, false)
            }
            _ => Expr::konst(insn.immediate(operand), width),
        }
    }

    fn write_op(&mut self, insn: &Instruction, operand: u32, value: Expr, width: Width) {
        match insn.op_kind(operand) {
            OpKind::Register => self.write_reg(insn.op_register(operand), value),
            OpKind::Memory => {
                let addr = self.address(insn);
                self.emit(StmtKind::Store {
                    addr,
                    value,
                    width,
                    float: false,
                });
            }
            _ => {}
        }
    }

    fn flag_var(&mut self, first: bool, width: Width) -> Var {
        let base = if first {
            Base::FlagA(width)
        } else {
            Base::FlagB(width)
        };
        self.var_for(base, width, false)
    }

    fn set_compare(&mut self, a: Expr, b: Expr, width: Width) -> (Expr, Expr) {
        let va = self.flag_var(true, width);
        let vb = self.flag_var(false, width);
        self.assign(va, a);
        self.assign(vb, b);
        self.state.flags = Flags::Compare(width);
        (Expr::Var(va), Expr::Var(vb))
    }

    fn set_result(&mut self, value: Expr, width: Width) -> Expr {
        let var = self.flag_var(true, width);
        self.assign(var, value);
        self.state.flags = Flags::Result(width);
        Expr::Var(var)
    }

    fn condition(&mut self, code: ConditionCode) -> Expr {
        use ConditionCode as C;
        let intrinsic = |name: &str| Expr::Intrinsic(format!("__flag_{name}"), Vec::new(), 1);
        match self.state.flags {
            Flags::Compare(width) => {
                let a = Expr::Var(self.flag_var(true, width));
                let b = Expr::Var(self.flag_var(false, width));
                compare_condition(code, a, b, width)
            }
            Flags::Float => {
                let a = Expr::Var(self.float_flag(true));
                let b = Expr::Var(self.float_flag(false));
                compare_condition(code, a, b, 8)
            }
            Flags::Result(width) => {
                let r = Expr::Var(self.flag_var(true, width));
                let zero = Expr::Const(0, width);
                let cmp = |op| Expr::cmp(op, r.clone(), zero.clone(), width);
                match code {
                    C::e | C::be => cmp(CmpOp::Eq),
                    C::ne | C::a => cmp(CmpOp::Ne),
                    C::s | C::l => cmp(CmpOp::SLt),
                    C::ns | C::ge => cmp(CmpOp::SGe),
                    C::g => cmp(CmpOp::SGt),
                    C::le => cmp(CmpOp::SLe),
                    C::b | C::o => Expr::Const(0, 1),
                    C::ae | C::no => Expr::Const(1, 1),
                    C::p => intrinsic("parity"),
                    C::np => intrinsic("parity").negated(),
                    C::None => intrinsic("loop"),
                }
            }
            Flags::Sum(width) => {
                let a = Expr::Var(self.flag_var(true, width));
                let b = Expr::Var(self.flag_var(false, width));
                let sum = Expr::bin(BinOp::Add, a.clone(), b, width);
                let zero = Expr::Const(0, width);
                match code {
                    C::e => Expr::cmp(CmpOp::Eq, sum, zero, width),
                    C::ne => Expr::cmp(CmpOp::Ne, sum, zero, width),
                    C::s | C::l => Expr::cmp(CmpOp::SLt, sum, zero, width),
                    C::ns | C::ge => Expr::cmp(CmpOp::SGe, sum, zero, width),
                    C::g => Expr::cmp(CmpOp::SGt, sum, zero, width),
                    C::le => Expr::cmp(CmpOp::SLe, sum, zero, width),
                    C::b => Expr::cmp(CmpOp::ULt, sum, a, width),
                    C::ae => Expr::cmp(CmpOp::UGe, sum, a, width),
                    other => intrinsic(&format!("{other:?}")),
                }
            }
            Flags::Unknown => intrinsic(&format!("{code:?}")),
        }
    }

    fn float_flag(&mut self, first: bool) -> Var {
        let base = if first {
            Base::FlagA(16)
        } else {
            Base::FlagB(16)
        };
        self.var_for(base, 8, true)
    }

    fn arithmetic(&mut self, insn: &Instruction, op: BinOp) {
        let width = self.op_size(insn, 0);
        let is_sp = insn.op0_kind() == OpKind::Register
            && canonical(insn.op0_register()) == Register::RSP
            && self.state.sp.is_some();
        if is_sp && self.adjust_stack(insn, op) {
            return;
        }

        let a = self.read_op(insn, 0, width);
        let b = self.read_op(insn, 1, width);
        match op {
            BinOp::Sub => {
                let (a, b) = self.set_compare(a, b, width);
                self.write_op(insn, 0, Expr::bin(op, a, b, width), width);
            }
            BinOp::Add => {
                let (a, b) = self.set_compare(a, b, width);
                self.state.flags = Flags::Sum(width);
                self.write_op(insn, 0, Expr::bin(op, a, b, width), width);
            }
            _ => {
                let value = self.set_result(Expr::bin(op, a, b, width), width);
                self.write_op(insn, 0, value, width);
            }
        }
    }

    fn adjust_stack(&mut self, insn: &Instruction, op: BinOp) -> bool {
        let amount = match insn.op1_kind() {
            OpKind::Register if canonical(insn.op1_register()) == Register::RAX => {
                self.state.rax_const
            }
            OpKind::Register | OpKind::Memory => None,
            _ => Some(sign_extend(insn.immediate(1), self.ptr)),
        };
        let Some(amount) = amount else {
            return false;
        };
        let Some(sp) = self.state.sp else {
            return false;
        };
        self.state.sp = match op {
            BinOp::Add => Some(sp + amount),
            BinOp::Sub => {
                if self.in_prologue {
                    self.in_prologue = false;
                }
                Some(sp - amount)
            }
            BinOp::And => Some(sp),
            _ => return false,
        };
        self.state.flags = Flags::Unknown;
        true
    }

    fn push(&mut self, value: Expr, register: Option<Register>) {
        let ptr = self.ptr;
        if let Some(sp) = self.state.sp {
            let slot = sp - i64::from(ptr);
            self.state.sp = Some(slot);
            if self.in_prologue && register.is_some() {
                self.saved_slots.insert(slot);
            }
            self.emit(StmtKind::Store {
                addr: Expr::StackAddr(slot),
                value,
                width: ptr,
                float: false,
            });
        } else {
            let var = self.reg_var(Register::RSP);
            let next = Expr::bin(
                BinOp::Sub,
                Expr::Var(var),
                Expr::Const(u64::from(ptr), ptr),
                ptr,
            );
            self.assign(var, next);
            self.emit(StmtKind::Store {
                addr: Expr::Var(var),
                value,
                width: ptr,
                float: false,
            });
        }
    }

    fn pop_value(&mut self) -> Expr {
        let ptr = self.ptr;
        if let Some(sp) = self.state.sp {
            self.state.sp = Some(sp + i64::from(ptr));
            Expr::load(Expr::StackAddr(sp), ptr, false)
        } else {
            let var = self.reg_var(Register::RSP);
            let value = Expr::load(Expr::Var(var), ptr, false);
            let next = Expr::bin(
                BinOp::Add,
                Expr::Var(var),
                Expr::Const(u64::from(ptr), ptr),
                ptr,
            );
            let temp = self.flag_var(true, ptr);
            self.state.flags = Flags::Unknown;
            self.assign(temp, value);
            self.assign(var, next);
            Expr::Var(temp)
        }
    }

    fn call(&mut self, insn: &Instruction) {
        let ptr = self.ptr;
        let target = match insn.op0_kind() {
            OpKind::NearBranch64 | OpKind::NearBranch32 => {
                let va = insn.near_branch_target();
                match self.callees.callee(va).name {
                    Some(name) if self.analysis.iat_name_is(&name) => Expr::Name(name),
                    _ => Expr::Const(va, ptr),
                }
            }
            _ => match call_target_name(self.analysis, self.callees, insn) {
                Some(name) => Expr::Name(name),
                None => self.read_op(insn, 0, ptr),
            },
        };
        self.emit_call(target);
    }

    fn emit_call(&mut self, target: Expr) {
        let ptr = self.ptr;
        let registers: Vec<Var> = arg_registers(self.bits, self.win64)
            .iter()
            .map(|&register| self.reg_var(register))
            .collect();
        let float_count = match (self.bits, self.win64) {
            (32, _) => 0,
            (_, true) => 4,
            _ => 8,
        };
        let floats: Vec<Var> = (0..float_count)
            .map(|index| self.reg_var(Register::XMM0 + index))
            .collect();

        let first = if self.bits == 64 && self.win64 {
            0x20
        } else {
            0
        };
        let slots: Vec<i64> = match self.state.sp {
            Some(sp) => (0..MAX_STACK_ARGS)
                .map(|index| sp + first + index * i64::from(ptr))
                .collect(),
            None => Vec::new(),
        };

        let volatile: &[Register] = match (self.bits, self.win64) {
            (32, _) => &[Register::RCX, Register::RDX],
            (_, true) => &[
                Register::RCX,
                Register::RDX,
                Register::R8,
                Register::R9,
                Register::R10,
                Register::R11,
            ],
            _ => &[
                Register::RCX,
                Register::RDX,
                Register::RSI,
                Register::RDI,
                Register::R8,
                Register::R9,
                Register::R10,
                Register::R11,
            ],
        };
        let written = match &target {
            Expr::Const(va, _) => self.callees.callee(*va).written,
            _ => None,
        };
        let changes = |register: Register| {
            written
                .as_ref()
                .is_none_or(|written| written.contains(&register))
        };
        let mut clobbers: Vec<Var> = volatile
            .iter()
            .filter(|&&register| changes(register))
            .map(|&register| self.reg_var(register))
            .collect();
        let float_clobbers = match (self.bits, self.win64) {
            (32, _) => 0,
            (_, true) => 6,
            _ => 16,
        };
        for index in 0..float_clobbers {
            if changes(Register::XMM0 + index) {
                clobbers.push(self.reg_var(Register::XMM0 + index));
            }
        }

        let ret = self.reg_var(Register::RAX);
        self.emit(StmtKind::Call {
            ret: Some(ret),
            clobbers,
            target: target.clone(),
            args: Vec::new(),
            candidates: Some(Candidates {
                registers,
                floats,
                slots,
                slot_vars: Vec::new(),
                tail: self.tail,
            }),
        });
        self.state.flags = Flags::Unknown;
        self.state.rax_const = None;

        // 32-bit stdcall routines remove their own arguments from the stack.
        if self.bits == 32
            && let Some(sp) = self.state.sp
        {
            let pops = match &target {
                Expr::Const(va, _) => self.callees.callee(*va).pops,
                Expr::Name(_) => self.outgoing_bytes(sp),
                _ => 0,
            };
            self.state.sp = Some(sp + pops);
        }
    }

    // Imports on 32-bit Windows are stdcall, so the bytes stored for the call get popped too.
    fn outgoing_bytes(&self, sp: i64) -> i64 {
        let mut slot = sp;
        let is_stored = |slot: i64| {
            self.stmts.iter().rev().take(64).any(|stmt| {
                matches!(&stmt.kind, StmtKind::Store { addr: Expr::StackAddr(offset), .. } if *offset == slot)
            })
        };
        while is_stored(slot) {
            slot += 4;
        }
        slot - sp
    }

    fn opaque(&mut self, insn: &Instruction) {
        let mut text = String::new();
        self.formatter.format(insn, &mut text);

        let used: Vec<(Register, OpAccess)> = self
            .info
            .info(insn)
            .used_registers()
            .iter()
            .map(|used| (used.register(), used.access()))
            .collect();

        let mut defs = Vec::new();
        let mut uses = Vec::new();
        for (register, access) in used {
            let tracked = register.is_gpr() || is_vector(register);
            let full = canonical(register);
            if !tracked || full == Register::RSP || self.known_stack(full).is_some() {
                continue;
            }
            let var = self.reg_var(full);
            match access {
                OpAccess::Write | OpAccess::CondWrite => defs.push(var),
                OpAccess::ReadWrite | OpAccess::ReadCondWrite => {
                    defs.push(var);
                    uses.push(Expr::Var(var));
                }
                OpAccess::Read | OpAccess::CondRead => uses.push(Expr::Var(var)),
                _ => {}
            }
        }
        for operand in 0..insn.op_count() {
            if insn.op_kind(operand) == OpKind::Memory {
                uses.push(self.address(insn));
                break;
            }
        }
        defs.sort_unstable();
        defs.dedup();
        self.emit(StmtKind::Opaque { text, defs, uses });
        if insn.rflags_modified() != 0 {
            self.state.flags = Flags::Unknown;
        }
    }

    fn float_load(&mut self, insn: &Instruction, operand: u32, width: Width) -> Expr {
        match insn.op_kind(operand) {
            OpKind::Register => self.read_reg(insn.op_register(operand)),
            _ => {
                let addr = self.address(insn);
                if let Expr::Const(va, _) = addr
                    && self.analysis.is_read_only(va)
                    && let Some(bytes) = self.analysis.read(va, usize::from(width))
                {
                    match width {
                        4 if bytes.len() == 4 => {
                            let raw: [u8; 4] = bytes.try_into().unwrap_or_default();
                            return Expr::Float(f64::from(f32::from_le_bytes(raw)));
                        }
                        8 if bytes.len() == 8 => {
                            let raw: [u8; 8] = bytes.try_into().unwrap_or_default();
                            return Expr::Float(f64::from_le_bytes(raw));
                        }
                        _ => {}
                    }
                }
                Expr::load(addr, width, true)
            }
        }
    }

    fn float_binary(&mut self, insn: &Instruction, op: BinOp, width: Width) {
        let a = self.read_reg(insn.op0_register());
        let b = self.float_load(insn, 1, width);
        self.write_reg(insn.op0_register(), Expr::bin(op, a, b, 8));
    }

    fn float_move(&mut self, insn: &Instruction, width: Width) {
        if insn.op0_kind() == OpKind::Register {
            let value = self.float_load(insn, 1, width);
            self.write_reg(insn.op0_register(), value);
        } else {
            let addr = self.address(insn);
            let value = self.read_reg(insn.op1_register());
            self.emit(StmtKind::Store {
                addr,
                value,
                width,
                float: true,
            });
        }
    }

    fn string_op(&mut self, insn: &Instruction) -> bool {
        if !insn.has_rep_prefix() && !insn.has_repe_prefix() {
            return false;
        }
        let width = match insn.mnemonic() {
            Mnemonic::Movsb | Mnemonic::Stosb => 1u64,
            Mnemonic::Movsw | Mnemonic::Stosw => 2,
            Mnemonic::Movsd | Mnemonic::Stosd => 4,
            Mnemonic::Movsq | Mnemonic::Stosq => 8,
            _ => return false,
        };
        let ptr = self.ptr;
        let dest = self.read_reg(Register::RDI);
        let count = self.read_reg(Register::RCX);
        let bytes = Expr::bin(BinOp::Mul, count, Expr::Const(width, ptr), ptr);
        let is_copy = matches!(
            insn.mnemonic(),
            Mnemonic::Movsb | Mnemonic::Movsw | Mnemonic::Movsd | Mnemonic::Movsq
        );
        let (name, args) = if is_copy {
            let source = self.read_reg(Register::RSI);
            ("memcpy", vec![dest, source, bytes])
        } else if width == 1 {
            let value = self.read_reg(Register::AL);
            ("memset", vec![dest, value, bytes])
        } else {
            let value = self.read_reg(Register::RAX);
            ("__fill", vec![dest, value, bytes])
        };
        let clobbers = [Register::RCX, Register::RDI, Register::RSI]
            .map(|register| self.reg_var(register))
            .to_vec();
        self.emit(StmtKind::Call {
            ret: None,
            clobbers,
            target: Expr::Name(name.to_owned()),
            args,
            candidates: None,
        });
        true
    }

    fn lift(&mut self, insn: &Instruction) {
        self.va = insn.ip();
        let ptr = self.ptr;
        use Mnemonic as M;
        match insn.mnemonic() {
            M::Nop
            | M::Endbr64
            | M::Endbr32
            | M::Fnop
            | M::Pause
            | M::Lfence
            | M::Mfence
            | M::Sfence
            | M::Prefetcht0
            | M::Prefetchnta => {}
            M::Mov => {
                if insn.op0_kind() == OpKind::Register && insn.op1_kind() == OpKind::Register {
                    let (to, from) = (
                        canonical(insn.op0_register()),
                        canonical(insn.op1_register()),
                    );
                    if to == Register::RBP && from == Register::RSP && self.state.sp.is_some() {
                        self.state.fp = self.state.sp;
                        self.in_prologue = false;
                        return;
                    }
                    if to == Register::RSP && from == Register::RBP && self.state.fp.is_some() {
                        self.state.sp = self.state.fp;
                        return;
                    }
                }
                let width = self.op_size(insn, 0);
                let value = self.read_op(insn, 1, width);
                if insn.op0_kind() == OpKind::Register
                    && canonical(insn.op0_register()) == Register::RAX
                    && let Expr::Const(constant, _) = value
                {
                    self.write_op(insn, 0, value, width);
                    self.state.rax_const = Some(constant as i64);
                    return;
                }
                self.write_op(insn, 0, value, width);
            }
            M::Movzx | M::Movsx | M::Movsxd => {
                let from = self.op_size(insn, 1);
                let to = self.op_size(insn, 0);
                let value = self.read_op(insn, 1, from);
                let kind = if insn.mnemonic() == M::Movzx {
                    CastKind::Zext
                } else {
                    CastKind::Sext
                };
                self.write_op(insn, 0, Expr::cast(kind, value, to), to);
            }
            M::Lea => {
                let width = self.op_size(insn, 0);
                let addr = self.address(insn);
                if canonical(insn.op0_register()) == Register::RSP
                    && let Expr::StackAddr(offset) = addr
                {
                    self.state.sp = Some(offset);
                    return;
                }
                if canonical(insn.op0_register()) == Register::RBP
                    && let Expr::StackAddr(offset) = addr
                {
                    self.state.fp = Some(offset);
                    self.in_prologue = false;
                    return;
                }
                let value = if width == ptr {
                    addr
                } else {
                    Expr::cast(CastKind::Trunc, addr, width)
                };
                self.write_reg(insn.op0_register(), value);
            }
            M::Push => {
                let width = self.op_size(insn, 0).max(ptr);
                let register = (insn.op0_kind() == OpKind::Register).then(|| insn.op0_register());
                if insn.op0_kind() == OpKind::Memory {
                    self.in_prologue = false;
                }
                let value = match insn.op0_kind() {
                    OpKind::Register | OpKind::Memory => self.read_op(insn, 0, width),
                    _ => Expr::konst(insn.immediate(0), width),
                };
                self.push(value, register);
            }
            M::Pop => {
                let value = self.pop_value();
                self.write_op(insn, 0, value, ptr);
            }
            M::Leave => {
                if self.state.fp.is_some() {
                    self.state.sp = self.state.fp;
                }
                let value = self.pop_value();
                self.write_reg(Register::RBP, value);
            }
            M::Add => self.arithmetic(insn, BinOp::Add),
            M::Sub => self.arithmetic(insn, BinOp::Sub),
            M::And => self.arithmetic(insn, BinOp::And),
            M::Or => self.arithmetic(insn, BinOp::Or),
            M::Xor => {
                let same = insn.op0_kind() == OpKind::Register
                    && insn.op1_kind() == OpKind::Register
                    && insn.op0_register() == insn.op1_register()
                    && !is_vector(insn.op0_register());
                if same {
                    let width = self.op_size(insn, 0);
                    let zero = self.set_result(Expr::Const(0, width), width);
                    self.write_op(insn, 0, zero, width);
                } else {
                    self.arithmetic(insn, BinOp::Xor);
                }
            }
            M::Inc | M::Dec => {
                let width = self.op_size(insn, 0);
                let a = self.read_op(insn, 0, width);
                let op = if insn.mnemonic() == M::Inc {
                    BinOp::Add
                } else {
                    BinOp::Sub
                };
                let value = self.set_result(Expr::bin(op, a, Expr::Const(1, width), width), width);
                self.write_op(insn, 0, value, width);
            }
            M::Neg | M::Not => {
                let width = self.op_size(insn, 0);
                let a = self.read_op(insn, 0, width);
                let op = if insn.mnemonic() == M::Neg {
                    UnOp::Neg
                } else {
                    UnOp::Not
                };
                let result = Expr::Un(op, Box::new(a), width);
                if insn.mnemonic() == M::Neg {
                    let value = self.set_result(result, width);
                    self.write_op(insn, 0, value, width);
                } else {
                    self.write_op(insn, 0, result, width);
                }
            }
            M::Shl | M::Sal | M::Shr | M::Sar => {
                let width = self.op_size(insn, 0);
                let a = self.read_op(insn, 0, width);
                let count = self.read_op(insn, 1, 1);
                let op = match insn.mnemonic() {
                    M::Shr => BinOp::Shr,
                    M::Sar => BinOp::Sar,
                    _ => BinOp::Shl,
                };
                let is_constant = matches!(count, Expr::Const(..));
                let count = match count {
                    Expr::Const(value, _) => Expr::Const(value, width),
                    other => Expr::cast(CastKind::Zext, other, width),
                };
                let result = Expr::bin(op, a, count, width);
                if is_constant {
                    let value = self.set_result(result, width);
                    self.write_op(insn, 0, value, width);
                } else {
                    self.write_op(insn, 0, result, width);
                    self.state.flags = Flags::Unknown;
                }
            }
            M::Rol | M::Ror => {
                let width = self.op_size(insn, 0);
                let a = self.read_op(insn, 0, width);
                let count = self.read_op(insn, 1, 1);
                let name = if insn.mnemonic() == M::Rol {
                    "__rotl"
                } else {
                    "__rotr"
                };
                let value = Expr::Intrinsic(name.into(), vec![a, count], width);
                self.write_op(insn, 0, value, width);
                self.state.flags = Flags::Unknown;
            }
            M::Imul => self.imul(insn),
            M::Mul => {
                let width = self.op_size(insn, 0);
                let a = self.read_op(insn, 0, width);
                self.wide_multiply(a, width, BinOp::MulHiU);
            }
            M::Div | M::Idiv => self.divide(insn),
            M::Cdq | M::Cqo | M::Cwd => {
                let (from, to, size) = match insn.mnemonic() {
                    M::Cdq => (Register::EAX, Register::EDX, 4),
                    M::Cqo => (Register::RAX, Register::RDX, 8),
                    _ => (Register::AX, Register::DX, 2),
                };
                let value = self.read_reg(from);
                let bits = u64::from(size as u32) * 8 - 1;
                let sign = Expr::bin(BinOp::Sar, value, Expr::Const(bits, size), size);
                self.write_reg(to, sign);
            }
            M::Cdqe | M::Cwde | M::Cbw => {
                let (from, to, size) = match insn.mnemonic() {
                    M::Cdqe => (Register::EAX, Register::RAX, 8),
                    M::Cwde => (Register::AX, Register::EAX, 4),
                    _ => (Register::AL, Register::AX, 2),
                };
                let value = self.read_reg(from);
                self.write_reg(to, Expr::cast(CastKind::Sext, value, size));
            }
            M::Cmp => {
                let width = self.op_size(insn, 0);
                let a = self.read_op(insn, 0, width);
                let b = self.read_op(insn, 1, width);
                self.set_compare(a, b, width);
            }
            M::Test => {
                let width = self.op_size(insn, 0);
                let a = self.read_op(insn, 0, width);
                let b = self.read_op(insn, 1, width);
                let same = a == b;
                let value = if same {
                    a
                } else {
                    Expr::bin(BinOp::And, a, b, width)
                };
                self.set_result(value, width);
            }
            M::Xchg => {
                let width = self.op_size(insn, 0);
                let a = self.read_op(insn, 0, width);
                let b = self.read_op(insn, 1, width);
                if a == b {
                    return;
                }
                let temp_a = self.flag_var(true, width);
                let temp_b = self.flag_var(false, width);
                self.assign(temp_a, a);
                self.assign(temp_b, b);
                self.state.flags = Flags::Unknown;
                self.write_op(insn, 0, Expr::Var(temp_b), width);
                self.write_op(insn, 1, Expr::Var(temp_a), width);
            }
            M::Bswap => {
                let width = self.op_size(insn, 0);
                let a = self.read_op(insn, 0, width);
                let value = Expr::Intrinsic("__bswap".into(), vec![a], width);
                self.write_op(insn, 0, value, width);
            }
            M::Adc | M::Sbb => {
                let width = self.op_size(insn, 0);
                let carry = self.condition(ConditionCode::b);
                let a = self.read_op(insn, 0, width);
                let b = self.read_op(insn, 1, width);
                let op = if insn.mnemonic() == M::Adc {
                    BinOp::Add
                } else {
                    BinOp::Sub
                };
                let carry = Expr::cast(CastKind::Zext, carry, width);
                let value = Expr::bin(op, Expr::bin(op, a, b, width), carry, width);
                self.write_op(insn, 0, value, width);
                self.state.flags = Flags::Unknown;
            }
            M::Call => self.call(insn),
            M::Int3 => self.emit(StmtKind::Opaque {
                text: "int3".into(),
                defs: Vec::new(),
                uses: Vec::new(),
            }),
            M::Movss | M::Cvtss2sd => self.float_move(insn, 4),
            M::Movsd
                if insn.op0_kind() == OpKind::Register || insn.op1_kind() == OpKind::Register =>
            {
                self.float_move(insn, 8);
            }
            M::Cvtsd2ss => self.float_move(insn, 8),
            M::Movaps | M::Movapd | M::Movups | M::Movupd | M::Movdqa | M::Movdqu
                if insn.op0_kind() == OpKind::Register && insn.op1_kind() == OpKind::Register =>
            {
                let value = self.read_reg(insn.op1_register());
                self.write_reg(insn.op0_register(), value);
            }
            M::Xorps | M::Xorpd | M::Pxor
                if insn.op0_kind() == OpKind::Register
                    && insn.op1_kind() == OpKind::Register
                    && insn.op0_register() == insn.op1_register() =>
            {
                self.write_reg(insn.op0_register(), Expr::Float(0.0));
            }
            M::Addss => self.float_binary(insn, BinOp::FAdd, 4),
            M::Addsd => self.float_binary(insn, BinOp::FAdd, 8),
            M::Subss => self.float_binary(insn, BinOp::FSub, 4),
            M::Subsd => self.float_binary(insn, BinOp::FSub, 8),
            M::Mulss => self.float_binary(insn, BinOp::FMul, 4),
            M::Mulsd => self.float_binary(insn, BinOp::FMul, 8),
            M::Divss => self.float_binary(insn, BinOp::FDiv, 4),
            M::Divsd => self.float_binary(insn, BinOp::FDiv, 8),
            M::Sqrtsd | M::Sqrtss => {
                let width = if insn.mnemonic() == M::Sqrtsd { 8 } else { 4 };
                let value = self.float_load(insn, 1, width);
                let root = Expr::Intrinsic("sqrt".into(), vec![value], 8);
                self.write_reg(insn.op0_register(), root);
            }
            M::Cvtsi2sd | M::Cvtsi2ss => {
                let width = self.op_size(insn, 1);
                let value = self.read_op(insn, 1, width);
                self.write_reg(insn.op0_register(), Expr::cast(CastKind::ToFloat, value, 8));
            }
            M::Cvttsd2si | M::Cvttss2si | M::Cvtsd2si | M::Cvtss2si => {
                let is_single = matches!(insn.mnemonic(), M::Cvttss2si | M::Cvtss2si);
                let value = self.float_load(insn, 1, if is_single { 4 } else { 8 });
                let width = self.op_size(insn, 0);
                self.write_reg(
                    insn.op0_register(),
                    Expr::cast(CastKind::FromFloat, value, width),
                );
            }
            M::Ucomisd | M::Comisd | M::Ucomiss | M::Comiss => {
                let is_single = matches!(insn.mnemonic(), M::Ucomiss | M::Comiss);
                let a = self.read_reg(insn.op0_register());
                let b = self.float_load(insn, 1, if is_single { 4 } else { 8 });
                let va = self.float_flag(true);
                let vb = self.float_flag(false);
                self.assign(va, a);
                self.assign(vb, b);
                self.state.flags = Flags::Float;
            }
            mnemonic => {
                if insn.condition_code() != ConditionCode::None {
                    if self.conditional(insn, mnemonic) {
                        return;
                    }
                } else if self.string_op(insn) {
                    return;
                }
                self.opaque(insn);
            }
        }
    }

    fn conditional(&mut self, insn: &Instruction, mnemonic: Mnemonic) -> bool {
        let name = format!("{mnemonic:?}");
        if name.starts_with("Set") {
            let value = self.condition(insn.condition_code());
            self.write_op(insn, 0, value, 1);
            return true;
        }
        if name.starts_with("Cmov") {
            let width = self.op_size(insn, 0);
            let cond = self.condition(insn.condition_code());
            let new = self.read_op(insn, 1, width);
            let old = self.read_reg(insn.op0_register());
            let value = Expr::Select(Box::new(cond), Box::new(new), Box::new(old), width);
            self.write_reg(insn.op0_register(), value);
            return true;
        }
        false
    }

    fn imul(&mut self, insn: &Instruction) {
        let width = self.op_size(insn, 0);
        match insn.op_count() {
            1 => {
                let a = self.read_op(insn, 0, width);
                self.wide_multiply(a, width, BinOp::MulHiS);
            }
            2 => {
                let a = self.read_op(insn, 0, width);
                let b = self.read_op(insn, 1, width);
                self.write_reg(insn.op0_register(), Expr::bin(BinOp::Mul, a, b, width));
                self.state.flags = Flags::Unknown;
            }
            _ => {
                let a = self.read_op(insn, 1, width);
                let b = Expr::konst(insn.immediate(2), width);
                self.write_reg(insn.op0_register(), Expr::bin(BinOp::Mul, a, b, width));
                self.state.flags = Flags::Unknown;
            }
        }
    }

    fn accumulator(width: Width) -> (Register, Register) {
        match width {
            1 => (Register::AL, Register::AH),
            2 => (Register::AX, Register::DX),
            4 => (Register::EAX, Register::EDX),
            _ => (Register::RAX, Register::RDX),
        }
    }

    fn wide_multiply(&mut self, operand: Expr, width: Width, high: BinOp) {
        let (low_reg, high_reg) = Self::accumulator(width);
        let accumulator = self.read_reg(low_reg);
        let temp = self.flag_var(false, width);
        self.assign(temp, operand);
        let hi = Expr::bin(high, accumulator.clone(), Expr::Var(temp), width);
        let lo = Expr::bin(BinOp::Mul, accumulator, Expr::Var(temp), width);
        self.write_reg(high_reg, hi);
        self.write_reg(low_reg, lo);
        self.state.flags = Flags::Unknown;
    }

    fn divide(&mut self, insn: &Instruction) {
        let width = self.op_size(insn, 0);
        let signed = insn.mnemonic() == Mnemonic::Idiv;
        let (low_reg, high_reg) = Self::accumulator(width);
        let divisor = self.read_op(insn, 0, width);
        let temp = self.flag_var(false, width);
        self.assign(temp, divisor);
        let low = self.read_reg(low_reg);
        let (div, rem) = if signed {
            (BinOp::SDiv, BinOp::SRem)
        } else {
            (BinOp::UDiv, BinOp::URem)
        };
        let quotient = Expr::bin(div, low.clone(), Expr::Var(temp), width);
        let remainder = Expr::bin(rem, low, Expr::Var(temp), width);
        let saved = self.flag_var(true, width);
        self.assign(saved, quotient);
        self.write_reg(high_reg, remainder);
        self.write_reg(low_reg, Expr::Var(saved));
        self.state.flags = Flags::Unknown;
    }

    fn finish(&mut self, exit: &Exit, last: u64) -> (Term, Vec<Stmt>) {
        self.va = last;
        let ptr = self.ptr;
        let term = match exit {
            Exit::Next(to) => Term::Jump(*to),
            Exit::Branch {
                code,
                taken,
                not_taken,
            } => Term::Branch {
                cond: self.condition(*code),
                taken: *taken,
                not_taken: *not_taken,
            },
            Exit::Table(table) => {
                let var = self.var_for(Base::SwitchIndex, ptr, false);
                Term::Switch {
                    value: Expr::Var(var),
                    cases: table.cases.clone(),
                }
            }
            Exit::Return => Term::Return(Some(Expr::Var(self.reg_var(Register::RAX)))),
            Exit::NoReturn => Term::Stop(None),
            Exit::Tail | Exit::External(_) => {
                Term::Return(Some(Expr::Var(self.reg_var(Register::RAX))))
            }
        };
        (term, std::mem::take(&mut self.stmts))
    }
}

pub fn lift(
    analysis: &Analysis,
    callees: &dyn Callees,
    function: &Function,
) -> anyhow::Result<(Func, BTreeSet<i64>)> {
    let bits = match analysis.arch {
        Arch::X86_64 => 64,
        Arch::X86 => 32,
        Arch::Aarch64 => anyhow::bail!("ARM64 decompiling is not supported yet"),
    };
    let win64 = analysis.is_pe && bits == 64;
    let cfg = Cfg {
        analysis,
        callees,
        bits,
        start: function.va,
        end: function.va + function.size.max(1),
    };
    let raw = cfg.build()?;
    if raw.is_empty() {
        anyhow::bail!("no code could be decoded at {:#x}", function.va);
    }

    let mut lifter = Lifter {
        analysis,
        callees,
        bits,
        win64,
        ptr: (bits / 8) as Width,
        vars: Vec::new(),
        by_base: HashMap::new(),
        stmts: Vec::new(),
        state: State::default(),
        va: function.va,
        saved_slots: BTreeSet::new(),
        in_prologue: true,
        tail: false,
        info: InstructionInfoFactory::new(),
        formatter: IntelFormatter::new(),
    };

    let mut preds: Vec<Vec<usize>> = vec![Vec::new(); raw.len()];
    let successors = |exit: &Exit| -> Vec<usize> {
        match exit {
            Exit::Next(to) => vec![*to],
            Exit::Branch {
                taken, not_taken, ..
            } => vec![*taken, *not_taken],
            Exit::Table(table) => table.cases.iter().map(|(_, to)| *to).collect(),
            _ => Vec::new(),
        }
    };
    for (index, block) in raw.iter().enumerate() {
        for to in successors(&block.exit) {
            preds[to].push(index);
        }
    }

    let mut order: Vec<usize> = Vec::with_capacity(raw.len());
    {
        let mut seen = vec![false; raw.len()];
        let mut stack = vec![(0usize, 0usize)];
        seen[0] = true;
        while let Some((block, position)) = stack.pop() {
            let next = successors(&raw[block].exit);
            if let Some(&to) = next.get(position) {
                stack.push((block, position + 1));
                if !seen[to] {
                    seen[to] = true;
                    stack.push((to, 0));
                }
            } else {
                order.push(block);
            }
        }
        order.reverse();
    }

    // Two passes, because a loop's back edge can only be read after the loop body was lifted.
    let entry_state = State {
        sp: Some(0),
        ..State::default()
    };
    let mut out_states: Vec<Option<State>> = vec![None; raw.len()];
    let mut blocks: Vec<Option<Block>> = vec![None; raw.len()];
    for _ in 0..2 {
        for &index in &order {
            let incoming: Vec<State> = preds[index]
                .iter()
                .filter_map(|&pred| out_states[pred])
                .collect();
            let mut state = incoming.first().copied().unwrap_or(entry_state);
            if index == 0 {
                state = entry_state;
            }
            if incoming.iter().any(|other| other.flags != state.flags) {
                state.flags = Flags::Unknown;
            }
            lifter.state = state;
            lifter.in_prologue = index == 0;

            let block = &raw[index];
            for insn in &block.code {
                if let Exit::Table(table) = &block.exit
                    && table.at == insn.ip()
                {
                    lifter.va = insn.ip();
                    let var = lifter.var_for(Base::SwitchIndex, lifter.ptr, false);
                    let ptr = lifter.ptr;
                    let index_value = lifter.read_reg(table.index);
                    let widened = if table.index.size() as Width == ptr {
                        index_value
                    } else {
                        Expr::cast(CastKind::Zext, index_value, ptr)
                    };
                    lifter.assign(var, widened);
                }
                let is_indirect_jump = insn.flow_control() == FlowControl::IndirectBranch;
                let is_tail = is_indirect_jump && matches!(block.exit, Exit::Tail);
                if is_tail {
                    lifter.va = insn.ip();
                    let target = match call_target_name(analysis, callees, insn) {
                        Some(name) => Expr::Name(name),
                        None => {
                            let ptr = lifter.ptr;
                            lifter.read_op(insn, 0, ptr)
                        }
                    };
                    lifter.tail = true;
                    lifter.emit_call(target);
                    lifter.tail = false;
                } else if !matches!(
                    insn.flow_control(),
                    FlowControl::ConditionalBranch
                        | FlowControl::UnconditionalBranch
                        | FlowControl::IndirectBranch
                        | FlowControl::Return
                ) {
                    lifter.lift(insn);
                }
            }
            if let Exit::External(target) = block.exit {
                lifter.va = block.code.last().map_or(block.va, Instruction::ip);
                let name = callees.callee(target).name;
                let expr = match name {
                    Some(name) if analysis.iat_name_is(&name) => Expr::Name(name),
                    _ => Expr::Const(target, lifter.ptr),
                };
                lifter.tail = true;
                lifter.emit_call(expr);
                lifter.tail = false;
            }

            let last = block.code.last().map_or(block.va, Instruction::ip);
            let (term, stmts) = lifter.finish(&block.exit, last);
            out_states[index] = Some(lifter.state);
            blocks[index] = Some(Block {
                va: block.va,
                stmts,
                term,
                term_va: last,
                preds: Vec::new(),
            });
        }
    }

    // Blocks no path reaches become empty stops, so indexes stay valid until the SSA pass drops them.
    let blocks = blocks
        .into_iter()
        .zip(&raw)
        .map(|(block, source)| {
            block.unwrap_or(Block {
                va: source.va,
                stmts: Vec::new(),
                term: Term::Stop(None),
                term_va: source.va,
                preds: Vec::new(),
            })
        })
        .collect();

    let mut func = Func {
        va: function.va,
        bits,
        win64,
        blocks,
        vars: lifter.vars,
    };
    func.compute_preds();
    Ok((func, lifter.saved_slots))
}

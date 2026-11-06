use iced_x86::Register;

pub type Width = u8;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Var(pub u32);

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Base {
    Reg(Register),
    Slot(i64),
    FlagA(Width),
    FlagB(Width),
    SwitchIndex,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Origin {
    Unversioned,
    Entry,
    Clobber,
    Defined,
}

#[derive(Clone, Copy, Debug)]
pub struct VarInfo {
    pub base: Base,
    pub width: Width,
    pub float: bool,
    pub origin: Origin,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BinOp {
    Add,
    Sub,
    Mul,
    MulHiS,
    MulHiU,
    SDiv,
    UDiv,
    SRem,
    URem,
    And,
    Or,
    Xor,
    Shl,
    Shr,
    Sar,
    FAdd,
    FSub,
    FMul,
    FDiv,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UnOp {
    Neg,
    Not,
    BoolNot,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CastKind {
    Trunc,
    Zext,
    Sext,
    ToFloat,
    FromFloat,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CmpOp {
    Eq,
    Ne,
    SLt,
    SLe,
    SGt,
    SGe,
    ULt,
    ULe,
    UGt,
    UGe,
}

impl CmpOp {
    pub fn negated(self) -> Self {
        match self {
            Self::Eq => Self::Ne,
            Self::Ne => Self::Eq,
            Self::SLt => Self::SGe,
            Self::SLe => Self::SGt,
            Self::SGt => Self::SLe,
            Self::SGe => Self::SLt,
            Self::ULt => Self::UGe,
            Self::ULe => Self::UGt,
            Self::UGt => Self::ULe,
            Self::UGe => Self::ULt,
        }
    }

    fn swapped(self) -> Self {
        match self {
            Self::Eq | Self::Ne => self,
            Self::SLt => Self::SGt,
            Self::SLe => Self::SGe,
            Self::SGt => Self::SLt,
            Self::SGe => Self::SLe,
            Self::ULt => Self::UGt,
            Self::ULe => Self::UGe,
            Self::UGt => Self::ULt,
            Self::UGe => Self::ULe,
        }
    }

    pub fn is_signed(self) -> bool {
        matches!(self, Self::SLt | Self::SLe | Self::SGt | Self::SGe)
    }

    pub fn is_unsigned(self) -> bool {
        matches!(self, Self::ULt | Self::ULe | Self::UGt | Self::UGe)
    }
}

#[derive(Clone, Debug, PartialEq)]
pub enum Expr {
    Const(u64, Width),
    Float(f64),
    Var(Var),
    StackAddr(i64),
    Name(String),
    Load {
        addr: Box<Expr>,
        width: Width,
        float: bool,
    },
    Bin(BinOp, Box<Expr>, Box<Expr>, Width),
    Un(UnOp, Box<Expr>, Width),
    Cast(CastKind, Box<Expr>, Width),
    Cmp(CmpOp, Box<Expr>, Box<Expr>, Width),
    Both(Box<Expr>, Box<Expr>),
    Either(Box<Expr>, Box<Expr>),
    Select(Box<Expr>, Box<Expr>, Box<Expr>, Width),
    Intrinsic(String, Vec<Expr>, Width),
}

pub fn mask(width: Width) -> u64 {
    if width >= 8 {
        u64::MAX
    } else {
        (1u64 << (u32::from(width) * 8)) - 1
    }
}

pub fn sign_extend(value: u64, width: Width) -> i64 {
    if width >= 8 {
        return value as i64;
    }
    let shift = 64 - u32::from(width) * 8;
    ((value << shift) as i64) >> shift
}

impl Expr {
    pub fn bin(op: BinOp, left: Expr, right: Expr, width: Width) -> Self {
        Self::Bin(op, Box::new(left), Box::new(right), width)
    }

    pub fn cast(kind: CastKind, inner: Expr, width: Width) -> Self {
        Self::Cast(kind, Box::new(inner), width)
    }

    pub fn cmp(op: CmpOp, left: Expr, right: Expr, width: Width) -> Self {
        Self::Cmp(op, Box::new(left), Box::new(right), width)
    }

    pub fn load(addr: Expr, width: Width, float: bool) -> Self {
        Self::Load {
            addr: Box::new(addr),
            width,
            float,
        }
    }

    pub fn konst(value: u64, width: Width) -> Self {
        Self::Const(value & mask(width), width)
    }

    pub fn width(&self, vars: &[VarInfo]) -> Width {
        match self {
            Self::Const(_, width)
            | Self::Bin(_, _, _, width)
            | Self::Un(_, _, width)
            | Self::Cast(_, _, width)
            | Self::Select(_, _, _, width)
            | Self::Intrinsic(_, _, width)
            | Self::Load { width, .. } => *width,
            Self::Var(var) => vars[var.0 as usize].width,
            Self::Float(_) | Self::StackAddr(_) | Self::Name(_) => 8,
            Self::Cmp(..) | Self::Both(..) | Self::Either(..) => 1,
        }
    }

    pub fn children(&self) -> Vec<&Expr> {
        match self {
            Self::Const(..)
            | Self::Float(_)
            | Self::Var(_)
            | Self::StackAddr(_)
            | Self::Name(_) => Vec::new(),
            Self::Load { addr, .. } => vec![addr],
            Self::Un(_, inner, _) | Self::Cast(_, inner, _) => vec![inner],
            Self::Bin(_, a, b, _)
            | Self::Cmp(_, a, b, _)
            | Self::Both(a, b)
            | Self::Either(a, b) => vec![a, b],
            Self::Select(a, b, c, _) => vec![a, b, c],
            Self::Intrinsic(_, args, _) => args.iter().collect(),
        }
    }

    pub fn children_mut(&mut self) -> Vec<&mut Expr> {
        match self {
            Self::Const(..)
            | Self::Float(_)
            | Self::Var(_)
            | Self::StackAddr(_)
            | Self::Name(_) => Vec::new(),
            Self::Load { addr, .. } => vec![addr],
            Self::Un(_, inner, _) | Self::Cast(_, inner, _) => vec![inner],
            Self::Bin(_, a, b, _)
            | Self::Cmp(_, a, b, _)
            | Self::Both(a, b)
            | Self::Either(a, b) => vec![a, b],
            Self::Select(a, b, c, _) => vec![a, b, c],
            Self::Intrinsic(_, args, _) => args.iter_mut().collect(),
        }
    }

    pub fn visit(&self, f: &mut impl FnMut(&Expr)) {
        f(self);
        for child in self.children() {
            child.visit(f);
        }
    }

    pub fn for_each_var(&self, f: &mut impl FnMut(Var)) {
        self.visit(&mut |expr| {
            if let Self::Var(var) = expr {
                f(*var);
            }
        });
    }

    // Applies `f` bottom up, so a replacement never gets visited again.
    pub fn rewrite(&mut self, f: &mut impl FnMut(&mut Expr)) {
        for child in self.children_mut() {
            child.rewrite(f);
        }
        f(self);
    }

    pub fn reads_memory(&self) -> bool {
        let mut found = false;
        self.visit(&mut |expr| {
            found |= matches!(expr, Self::Load { .. } | Self::Intrinsic(..));
        });
        found
    }

    pub fn negated(self) -> Self {
        match self {
            Self::Cmp(op, a, b, width) => Self::Cmp(op.negated(), a, b, width),
            Self::Un(UnOp::BoolNot, inner, _) => *inner,
            Self::Both(a, b) => Self::Either(Box::new(a.negated()), Box::new(b.negated())),
            Self::Either(a, b) => Self::Both(Box::new(a.negated()), Box::new(b.negated())),
            other => Self::Un(UnOp::BoolNot, Box::new(other), 1),
        }
    }
}

#[derive(Clone, Debug)]
pub struct Stmt {
    pub va: u64,
    pub kind: StmtKind,
}

// Everything a call might be reading. Which of these are real arguments gets decided once SSA
// shows which values were actually set up for the call.
#[derive(Clone, Debug, Default)]
pub struct Candidates {
    pub registers: Vec<Var>,
    pub floats: Vec<Var>,
    pub slots: Vec<i64>,
    pub slot_vars: Vec<Var>,
    // A tail call hands over whatever it was given, so even untouched registers count.
    pub tail: bool,
}

#[derive(Clone, Debug)]
pub enum StmtKind {
    Assign {
        var: Var,
        value: Expr,
    },
    Store {
        addr: Expr,
        value: Expr,
        width: Width,
        float: bool,
    },
    Phi {
        var: Var,
        inputs: Vec<(usize, Var)>,
    },
    Call {
        ret: Option<Var>,
        clobbers: Vec<Var>,
        target: Expr,
        args: Vec<Expr>,
        candidates: Option<Candidates>,
    },
    Opaque {
        text: String,
        defs: Vec<Var>,
        uses: Vec<Expr>,
    },
}

#[derive(Clone, Debug)]
pub enum Term {
    Jump(usize),
    Branch {
        cond: Expr,
        taken: usize,
        not_taken: usize,
    },
    Switch {
        value: Expr,
        cases: Vec<(u64, usize)>,
    },
    Return(Option<Expr>),
    Stop(Option<Expr>),
}

impl Term {
    pub fn successors(&self) -> Vec<usize> {
        match self {
            Self::Jump(to) => vec![*to],
            Self::Branch {
                taken, not_taken, ..
            } => {
                if taken == not_taken {
                    vec![*taken]
                } else {
                    vec![*taken, *not_taken]
                }
            }
            Self::Switch { cases, .. } => {
                let mut targets: Vec<usize> = cases.iter().map(|(_, to)| *to).collect();
                targets.sort_unstable();
                targets.dedup();
                targets
            }
            Self::Return(_) | Self::Stop(_) => Vec::new(),
        }
    }

    pub fn exprs(&self) -> Vec<&Expr> {
        match self {
            Self::Branch { cond, .. } => vec![cond],
            Self::Switch { value, .. } => vec![value],
            Self::Return(Some(value)) | Self::Stop(Some(value)) => vec![value],
            _ => Vec::new(),
        }
    }

    pub fn exprs_mut(&mut self) -> Vec<&mut Expr> {
        match self {
            Self::Branch { cond, .. } => vec![cond],
            Self::Switch { value, .. } => vec![value],
            Self::Return(Some(value)) | Self::Stop(Some(value)) => vec![value],
            _ => Vec::new(),
        }
    }

    pub fn replace_target(&mut self, from: usize, to: usize) {
        match self {
            Self::Jump(target) if *target == from => *target = to,
            Self::Branch {
                taken, not_taken, ..
            } => {
                if *taken == from {
                    *taken = to;
                }
                if *not_taken == from {
                    *not_taken = to;
                }
            }
            Self::Switch { cases, .. } => {
                for (_, target) in cases {
                    if *target == from {
                        *target = to;
                    }
                }
            }
            _ => {}
        }
    }
}

#[derive(Clone, Debug)]
pub struct Block {
    pub va: u64,
    pub stmts: Vec<Stmt>,
    pub term: Term,
    pub term_va: u64,
    pub preds: Vec<usize>,
}

pub struct Func {
    pub va: u64,
    pub bits: u32,
    pub win64: bool,
    pub blocks: Vec<Block>,
    pub vars: Vec<VarInfo>,
}

impl Func {
    pub fn compute_preds(&mut self) {
        for block in &mut self.blocks {
            block.preds.clear();
        }
        for index in 0..self.blocks.len() {
            for successor in self.blocks[index].term.successors() {
                self.blocks[successor].preds.push(index);
            }
        }
    }

    pub fn reverse_post_order(&self) -> Vec<usize> {
        let mut order = Vec::with_capacity(self.blocks.len());
        if self.blocks.is_empty() {
            return order;
        }
        let mut seen = vec![false; self.blocks.len()];
        let mut stack = vec![(0usize, 0usize)];
        seen[0] = true;
        while let Some((block, position)) = stack.pop() {
            let successors = self.blocks[block].term.successors();
            if let Some(&next) = successors.get(position) {
                stack.push((block, position + 1));
                if !seen[next] {
                    seen[next] = true;
                    stack.push((next, 0));
                }
            } else {
                order.push(block);
            }
        }
        order.reverse();
        order
    }
}

fn eval_bin(op: BinOp, a: u64, b: u64, width: Width) -> Option<u64> {
    let signed = |value| sign_extend(value, width);
    let bits = u32::from(width) * 8;
    let value = match op {
        BinOp::Add => a.wrapping_add(b),
        BinOp::Sub => a.wrapping_sub(b),
        BinOp::Mul => a.wrapping_mul(b),
        BinOp::And => a & b,
        BinOp::Or => a | b,
        BinOp::Xor => a ^ b,
        BinOp::Shl if b < u64::from(bits) => a << b,
        BinOp::Shr if b < u64::from(bits) => (a & mask(width)) >> b,
        BinOp::Sar if b < u64::from(bits) => (signed(a) >> b) as u64,
        BinOp::UDiv if b & mask(width) != 0 => (a & mask(width)) / (b & mask(width)),
        BinOp::URem if b & mask(width) != 0 => (a & mask(width)) % (b & mask(width)),
        BinOp::SDiv if b & mask(width) != 0 => signed(a).wrapping_div(signed(b)) as u64,
        BinOp::SRem if b & mask(width) != 0 => signed(a).wrapping_rem(signed(b)) as u64,
        _ => return None,
    };
    Some(value & mask(width))
}

fn eval_cmp(op: CmpOp, a: u64, b: u64, width: Width) -> bool {
    let (ua, ub) = (a & mask(width), b & mask(width));
    let (sa, sb) = (sign_extend(a, width), sign_extend(b, width));
    match op {
        CmpOp::Eq => ua == ub,
        CmpOp::Ne => ua != ub,
        CmpOp::SLt => sa < sb,
        CmpOp::SLe => sa <= sb,
        CmpOp::SGt => sa > sb,
        CmpOp::SGe => sa >= sb,
        CmpOp::ULt => ua < ub,
        CmpOp::ULe => ua <= ub,
        CmpOp::UGt => ua > ub,
        CmpOp::UGe => ua >= ub,
    }
}

fn is_zero(expr: &Expr) -> bool {
    matches!(expr, Expr::Const(0, _))
}

pub fn simplify(expr: &mut Expr, vars: &[VarInfo]) {
    for child in expr.children_mut() {
        simplify(child, vars);
    }
    for _ in 0..4 {
        let Some(next) = simplify_node(expr, vars) else {
            return;
        };
        *expr = next;
        for child in expr.children_mut() {
            simplify(child, vars);
        }
    }
}

fn simplify_node(expr: &Expr, vars: &[VarInfo]) -> Option<Expr> {
    match expr {
        Expr::Bin(op, a, b, width) => simplify_bin(*op, a, b, *width),
        Expr::Cast(CastKind::FromFloat, inner, width) => match inner.as_ref() {
            Expr::Float(value) => Some(Expr::Const(*value as u64 & mask(*width), *width)),
            _ => simplify_cast(CastKind::FromFloat, inner, *width, vars),
        },
        Expr::Cast(CastKind::ToFloat, inner, _) => match inner.as_ref() {
            Expr::Const(value, width) => Some(Expr::Float(sign_extend(*value, *width) as f64)),
            _ => simplify_cast(CastKind::ToFloat, inner, 8, vars),
        },
        Expr::Cast(kind, inner, width) => simplify_cast(*kind, inner, *width, vars),
        Expr::Cmp(op, a, b, width) => simplify_cmp(*op, a, b, *width),
        Expr::Un(UnOp::BoolNot, inner, _) => match inner.as_ref() {
            Expr::Cmp(..) | Expr::Both(..) | Expr::Either(..) | Expr::Un(UnOp::BoolNot, ..) => {
                Some((**inner).clone().negated())
            }
            _ => None,
        },
        Expr::Un(UnOp::Neg, inner, width) => match inner.as_ref() {
            Expr::Const(value, _) => Some(Expr::konst(value.wrapping_neg(), *width)),
            _ => None,
        },
        Expr::Un(UnOp::Not, inner, width) => match inner.as_ref() {
            Expr::Const(value, _) => Some(Expr::konst(!value, *width)),
            _ => None,
        },
        Expr::Select(_, a, b, _) if a == b => Some((**a).clone()),
        _ => None,
    }
}

fn simplify_bin(op: BinOp, a: &Expr, b: &Expr, width: Width) -> Option<Expr> {
    if let (Expr::Const(x, _), Expr::Const(y, _)) = (a, b)
        && let Some(value) = eval_bin(op, *x, *y, width)
    {
        return Some(Expr::Const(value, width));
    }

    let commutes = matches!(
        op,
        BinOp::Add | BinOp::Mul | BinOp::And | BinOp::Or | BinOp::Xor
    );
    if commutes && matches!(a, Expr::Const(..)) && !matches!(b, Expr::Const(..)) {
        return Some(Expr::bin(op, b.clone(), a.clone(), width));
    }

    match (op, a, b) {
        (BinOp::Add | BinOp::Sub, Expr::StackAddr(offset), Expr::Const(value, _)) => {
            let value = sign_extend(*value, width);
            let delta = if op == BinOp::Add { value } else { -value };
            return Some(Expr::StackAddr(offset + delta));
        }
        (
            BinOp::Add | BinOp::Sub | BinOp::Or | BinOp::Xor | BinOp::Shl | BinOp::Shr | BinOp::Sar,
            x,
            zero,
        ) if is_zero(zero) => return Some(x.clone()),
        (BinOp::And | BinOp::Mul, _, zero) if is_zero(zero) => return Some(Expr::Const(0, width)),
        (BinOp::Mul, x, Expr::Const(1, _)) => return Some(x.clone()),
        (BinOp::And, x, Expr::Const(value, _)) if *value == mask(width) => return Some(x.clone()),
        (BinOp::Xor | BinOp::Sub, x, y) if x == y => return Some(Expr::Const(0, width)),
        (BinOp::And | BinOp::Or, x, y) if x == y => return Some(x.clone()),
        _ => {}
    }

    if let (BinOp::Add | BinOp::Sub, Expr::Const(value, _)) = (op, b) {
        // Folds (x + 1) + 2 into x + 3.
        if let Expr::Bin(inner @ (BinOp::Add | BinOp::Sub), x, c, _) = a
            && let Expr::Const(other, _) = c.as_ref()
        {
            let first = if *inner == BinOp::Add {
                *other
            } else {
                other.wrapping_neg()
            };
            let second = if op == BinOp::Add {
                *value
            } else {
                value.wrapping_neg()
            };
            return Some(Expr::bin(
                BinOp::Add,
                (**x).clone(),
                Expr::konst(first.wrapping_add(second), width),
                width,
            ));
        }
        // Reads better as x - 4 than x + -4.
        let signed = sign_extend(*value, width);
        if signed < 0 && signed != i64::MIN && (width < 8 || signed > -0x1_0000_0000) {
            let flipped = if op == BinOp::Add {
                BinOp::Sub
            } else {
                BinOp::Add
            };
            return Some(Expr::bin(
                flipped,
                a.clone(),
                Expr::konst(signed.unsigned_abs(), width),
                width,
            ));
        }
    }

    if op == BinOp::Mul
        && let (Expr::Bin(BinOp::Mul, x, inner, _), Expr::Const(outer, _)) = (a, b)
        && let Expr::Const(inner, _) = inner.as_ref()
    {
        return Some(Expr::bin(
            BinOp::Mul,
            (**x).clone(),
            Expr::konst(inner.wrapping_mul(*outer), width),
            width,
        ));
    }

    // Address arithmetic turns x * 3 into x + x * 2.
    if op == BinOp::Add {
        if a == b {
            return Some(Expr::bin(
                BinOp::Mul,
                a.clone(),
                Expr::Const(2, width),
                width,
            ));
        }
        for (x, y) in [(a, b), (b, a)] {
            if let Expr::Bin(BinOp::Mul, inner, c, _) = y
                && **inner == *x
                && let Expr::Const(value, _) = c.as_ref()
            {
                return Some(Expr::bin(
                    BinOp::Mul,
                    x.clone(),
                    Expr::konst(value + 1, width),
                    width,
                ));
            }
        }
    }

    recover_remainder(op, a, b, width).or_else(|| recover_division(op, a, b, width))
}

// Compilers divide by a constant with a multiply and shifts, so this undoes the 32-bit forms.
fn recover_division(op: BinOp, a: &Expr, b: &Expr, width: Width) -> Option<Expr> {
    if width != 4 {
        return None;
    }

    if op == BinOp::Sub
        && let Expr::Bin(BinOp::Sar, x, c, _) = b
        && matches!(c.as_ref(), Expr::Const(31, _))
    {
        let (high, shift) = match a {
            Expr::Bin(BinOp::Sar, inner, count, _) => match count.as_ref() {
                Expr::Const(count, _) => (inner.as_ref(), *count),
                _ => return None,
            },
            other => (other, 0),
        };
        let multiplier = match high {
            Expr::Bin(BinOp::MulHiS, value, m, _) if value == x => m,
            Expr::Bin(BinOp::Add, hi, value, _) if value == x => match hi.as_ref() {
                Expr::Bin(BinOp::MulHiS, inner, m, _) if inner == x => m,
                _ => return None,
            },
            _ => return None,
        };
        let Expr::Const(multiplier, _) = multiplier.as_ref() else {
            return None;
        };
        let divisor = divisor_for(*multiplier, 32 + shift)?;
        return Some(Expr::bin(
            BinOp::SDiv,
            (**x).clone(),
            Expr::Const(divisor, 4),
            4,
        ));
    }

    if op == BinOp::Shr
        && let Expr::Const(shift, _) = b
        && let Expr::Bin(BinOp::MulHiU, x, m, _) = a
        && let Expr::Const(multiplier, _) = m.as_ref()
    {
        let divisor = divisor_for(*multiplier, 32 + shift)?;
        return Some(Expr::bin(
            BinOp::UDiv,
            (**x).clone(),
            Expr::Const(divisor, 4),
            4,
        ));
    }
    None
}

fn recover_remainder(op: BinOp, a: &Expr, b: &Expr, width: Width) -> Option<Expr> {
    if op != BinOp::Sub {
        return None;
    }
    let Expr::Bin(BinOp::Mul, quotient, factor, _) = b else {
        return None;
    };
    let Expr::Const(factor, _) = factor.as_ref() else {
        return None;
    };
    let Expr::Bin(division @ (BinOp::SDiv | BinOp::UDiv), x, divisor, _) = quotient.as_ref() else {
        return None;
    };
    if **x != *a || !matches!(divisor.as_ref(), Expr::Const(d, _) if d == factor) {
        return None;
    }
    let remainder = if *division == BinOp::SDiv {
        BinOp::SRem
    } else {
        BinOp::URem
    };
    Some(Expr::bin(remainder, a.clone(), (**divisor).clone(), width))
}

// Finds the d whose compiler-generated multiplier for 2^power is `multiplier`.
fn divisor_for(multiplier: u64, power: u64) -> Option<u64> {
    if multiplier == 0 || power > 62 {
        return None;
    }
    let numerator = 1u128 << power;
    let estimate = (numerator / u128::from(multiplier)) as u64;
    [estimate, estimate + 1].into_iter().find(|&divisor| {
        divisor > 1
            && divisor < 0x8000_0000
            && (numerator / u128::from(divisor)) as u64 + 1 == multiplier
    })
}

fn truncatable(op: BinOp) -> bool {
    matches!(
        op,
        BinOp::Add | BinOp::Sub | BinOp::Mul | BinOp::And | BinOp::Or | BinOp::Xor | BinOp::Shl
    )
}

fn simplify_cast(kind: CastKind, inner: &Expr, width: Width, vars: &[VarInfo]) -> Option<Expr> {
    if matches!(kind, CastKind::ToFloat | CastKind::FromFloat) {
        return None;
    }
    if inner.width(vars) == width {
        return Some(inner.clone());
    }

    match (kind, inner) {
        (CastKind::Trunc | CastKind::Zext, Expr::Const(value, _)) => {
            Some(Expr::konst(*value, width))
        }
        (CastKind::Sext, Expr::Const(value, from)) => {
            Some(Expr::konst(sign_extend(*value, *from) as u64, width))
        }
        (CastKind::Trunc, Expr::Cast(inner_kind @ (CastKind::Zext | CastKind::Sext), value, _)) => {
            let source = value.width(vars);
            if source == width {
                Some((**value).clone())
            } else if source > width {
                Some(Expr::cast(CastKind::Trunc, (**value).clone(), width))
            } else {
                Some(Expr::cast(*inner_kind, (**value).clone(), width))
            }
        }
        (CastKind::Trunc, Expr::Cast(CastKind::Trunc, value, _))
        | (CastKind::Zext, Expr::Cast(CastKind::Zext, value, _))
        | (CastKind::Sext, Expr::Cast(CastKind::Sext, value, _)) => {
            Some(Expr::cast(kind, (**value).clone(), width))
        }
        (CastKind::Trunc, Expr::Bin(op, a, b, _)) if truncatable(*op) => {
            let right = if *op == BinOp::Shl {
                (**b).clone()
            } else {
                Expr::cast(CastKind::Trunc, (**b).clone(), width)
            };
            Some(Expr::bin(
                *op,
                Expr::cast(CastKind::Trunc, (**a).clone(), width),
                right,
                width,
            ))
        }
        (CastKind::Trunc, Expr::Bin(BinOp::Shr | BinOp::Sar, product, count, _)) if width == 4 => {
            high_half_of_product(product, count, vars)
        }
        (CastKind::Trunc, Expr::Un(op @ (UnOp::Neg | UnOp::Not), value, _)) => Some(Expr::Un(
            *op,
            Box::new(Expr::cast(CastKind::Trunc, (**value).clone(), width)),
            width,
        )),
        _ => None,
    }
}

// 64-bit code takes the high half of a 32-bit product by widening and shifting by 32 or more.
fn high_half_of_product(product: &Expr, count: &Expr, vars: &[VarInfo]) -> Option<Expr> {
    let Expr::Const(count, _) = count else {
        return None;
    };
    let Expr::Bin(BinOp::Mul, x, m, _) = product else {
        return None;
    };
    let Expr::Const(multiplier, _) = m.as_ref() else {
        return None;
    };
    if *count < 32 {
        return None;
    }

    let (high, shift, source) = match x.as_ref() {
        Expr::Cast(CastKind::Sext, source, _) if source.width(vars) == 4 => {
            (BinOp::MulHiS, BinOp::Sar, source)
        }
        Expr::Cast(CastKind::Zext, source, _) if source.width(vars) == 4 => {
            (BinOp::MulHiU, BinOp::Shr, source)
        }
        _ => return None,
    };
    let product = Expr::bin(high, (**source).clone(), Expr::konst(*multiplier, 4), 4);
    if *count == 32 {
        return Some(product);
    }
    Some(Expr::bin(shift, product, Expr::Const(*count - 32, 4), 4))
}

fn simplify_cmp(op: CmpOp, a: &Expr, b: &Expr, width: Width) -> Option<Expr> {
    if let (Expr::Const(x, _), Expr::Const(y, _)) = (a, b) {
        return Some(Expr::Const(u64::from(eval_cmp(op, *x, *y, width)), 1));
    }
    if matches!(a, Expr::Const(..)) {
        return Some(Expr::cmp(op.swapped(), b.clone(), a.clone(), width));
    }
    if !is_zero(b) {
        return None;
    }

    // A boolean compared with zero is the boolean or its negation.
    let boolean = match a {
        Expr::Cast(CastKind::Zext, inner, _) if matches!(inner.as_ref(), Expr::Cmp(..)) => {
            Some(inner.as_ref())
        }
        Expr::Cmp(..) => Some(a),
        _ => None,
    };
    match (op, boolean) {
        (CmpOp::Ne, Some(value)) => Some(value.clone()),
        (CmpOp::Eq, Some(value)) => Some(value.clone().negated()),
        (CmpOp::UGt, _) => Some(Expr::cmp(CmpOp::Ne, a.clone(), b.clone(), width)),
        (CmpOp::ULe, _) => Some(Expr::cmp(CmpOp::Eq, a.clone(), b.clone(), width)),
        _ => None,
    }
}

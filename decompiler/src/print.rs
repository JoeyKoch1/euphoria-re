use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

use euphoria_engine::{Analysis, Listing};
use iced_x86::Register;

use crate::ir::{
    Base, BinOp, CastKind, CmpOp, Expr, Func, Origin, Stmt, StmtKind, UnOp, Var, Width, mask,
    sign_extend,
};
use crate::structure::Node;

const MAX_STRING: usize = 120;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TokenKind {
    Plain,
    Keyword,
    Type,
    Variable,
    Number,
    Text,
    Call,
    Comment,
    Label,
}

#[derive(Clone, Debug)]
pub struct Token {
    pub text: String,
    pub kind: TokenKind,
    pub target: Option<u64>,
}

#[derive(Clone, Debug, Default)]
pub struct Line {
    pub indent: usize,
    pub tokens: Vec<Token>,
    pub va: Option<u64>,
}

impl Line {
    pub fn text(&self) -> String {
        if self.tokens.is_empty() {
            return String::new();
        }
        let mut text = "    ".repeat(self.indent);
        for token in &self.tokens {
            text.push_str(&token.text);
        }
        text
    }
}

fn int_type(width: Width, signed: bool) -> &'static str {
    match (width, signed) {
        (1, true) => "int8_t",
        (1, false) => "uint8_t",
        (2, true) => "int16_t",
        (2, false) => "uint16_t",
        (4, true) => "int32_t",
        (4, false) => "uint32_t",
        (_, true) => "int64_t",
        (_, false) => "uint64_t",
    }
}

fn is_identifier(name: &str) -> bool {
    let mut chars = name.chars();
    chars
        .next()
        .is_some_and(|first| first.is_ascii_alphabetic() || first == '_')
        && chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

pub fn function_name(analysis: &Analysis, va: u64) -> String {
    analysis
        .function_at(va)
        .and_then(|function| function.name.as_deref())
        .filter(|name| is_identifier(name))
        .map_or_else(|| format!("sub_{va:x}"), str::to_owned)
}

fn short_import(name: &str) -> &str {
    name.rsplit('!').next().unwrap_or(name)
}

fn c_string(text: &str) -> String {
    let mut out = String::with_capacity(text.len() + 2);
    out.push('"');
    for c in text.chars().take(MAX_STRING) {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            other => out.push(other),
        }
    }
    if text.chars().count() > MAX_STRING {
        out.push_str("...");
    }
    out.push('"');
    out
}

// Binding strength, higher binds tighter. Used to decide where parentheses belong.
fn precedence(expr: &Expr) -> u8 {
    match expr {
        Expr::Select(..) => 1,
        Expr::Either(..) => 2,
        Expr::Both(..) => 3,
        Expr::Bin(BinOp::Or, ..) => 4,
        Expr::Bin(BinOp::Xor, ..) => 5,
        Expr::Bin(BinOp::And, ..) => 6,
        Expr::Cmp(CmpOp::Eq | CmpOp::Ne, ..) => 7,
        Expr::Cmp(..) => 8,
        Expr::Bin(BinOp::Shl | BinOp::Shr | BinOp::Sar, ..) => 9,
        Expr::Bin(BinOp::Add | BinOp::Sub | BinOp::FAdd | BinOp::FSub, ..) => 10,
        Expr::Bin(
            BinOp::Mul
            | BinOp::SDiv
            | BinOp::UDiv
            | BinOp::SRem
            | BinOp::URem
            | BinOp::FMul
            | BinOp::FDiv,
            ..,
        ) => 11,
        Expr::Un(..) | Expr::Cast(..) | Expr::Load { .. } => 12,
        _ => 13,
    }
}

pub struct Printer<'a> {
    analysis: &'a Analysis,
    listing: &'a Listing,
    func: &'a Func,
    names: HashMap<Var, String>,
    pointers: HashSet<Var>,
    memory_slots: BTreeMap<i64, Width>,
    array_slots: BTreeSet<i64>,
    labels: BTreeSet<usize>,
    lines: Vec<Line>,
    tokens: Vec<Token>,
    indent: usize,
    line_va: Option<u64>,
    nested: bool,
}

impl<'a> Printer<'a> {
    pub fn new(
        analysis: &'a Analysis,
        listing: &'a Listing,
        func: &'a Func,
        labels: BTreeSet<usize>,
    ) -> Self {
        Self {
            analysis,
            listing,
            func,
            names: HashMap::new(),
            pointers: HashSet::new(),
            memory_slots: BTreeMap::new(),
            array_slots: BTreeSet::new(),
            labels,
            lines: Vec::new(),
            tokens: Vec::new(),
            indent: 0,
            line_va: None,
            nested: false,
        }
    }

    fn put(&mut self, text: impl Into<String>, kind: TokenKind) {
        self.tokens.push(Token {
            text: text.into(),
            kind,
            target: None,
        });
    }

    fn plain(&mut self, text: &str) {
        self.put(text, TokenKind::Plain);
    }

    fn keyword(&mut self, text: &str) {
        self.put(text, TokenKind::Keyword);
    }

    fn end_line(&mut self) {
        let tokens = std::mem::take(&mut self.tokens);
        self.lines.push(Line {
            indent: self.indent,
            tokens,
            va: self.line_va.take(),
        });
    }

    fn line_at(&mut self, va: u64) {
        self.line_va = Some(va);
    }

    fn collect_vars(&mut self, nodes: &[Node], used: &mut Vec<Var>, seen: &mut HashSet<Var>) {
        let mut add = |var: Var| {
            if seen.insert(var) {
                used.push(var);
            }
        };
        fn walk(nodes: &[Node], f: &mut impl FnMut(&Stmt), g: &mut impl FnMut(&Expr)) {
            for node in nodes {
                match node {
                    Node::Stmts(stmts) => stmts.iter().for_each(&mut *f),
                    Node::If {
                        cond, then, other, ..
                    } => {
                        g(cond);
                        walk(then, f, g);
                        walk(other, f, g);
                    }
                    Node::Loop { body, .. } => walk(body, f, g),
                    Node::While { cond, body, .. } | Node::DoWhile { cond, body, .. } => {
                        g(cond);
                        walk(body, f, g);
                    }
                    Node::For {
                        init,
                        cond,
                        step,
                        body,
                        ..
                    } => {
                        f(init);
                        g(cond);
                        f(step);
                        walk(body, f, g);
                    }
                    Node::Switch { value, cases, .. } => {
                        g(value);
                        for (_, body) in cases {
                            walk(body, f, g);
                        }
                    }
                    Node::Return(Some(value), _) => g(value),
                    _ => {}
                }
            }
        }

        let mut exprs: Vec<Expr> = Vec::new();
        let mut stmts: Vec<Stmt> = Vec::new();
        walk(nodes, &mut |stmt| stmts.push(stmt.clone()), &mut |expr| {
            exprs.push(expr.clone())
        });
        for stmt in &stmts {
            match &stmt.kind {
                StmtKind::Assign { var, value } => {
                    add(*var);
                    exprs.push(value.clone());
                }
                StmtKind::Store { addr, value, .. } => {
                    exprs.push(addr.clone());
                    exprs.push(value.clone());
                }
                StmtKind::Call {
                    ret,
                    clobbers,
                    target,
                    args,
                    ..
                } => {
                    ret.iter().for_each(|var| add(*var));
                    clobbers.iter().for_each(|var| add(*var));
                    exprs.push(target.clone());
                    exprs.extend(args.iter().cloned());
                }
                StmtKind::Opaque { defs, uses, .. } => {
                    defs.iter().for_each(|var| add(*var));
                    exprs.extend(uses.iter().cloned());
                }
                StmtKind::Phi { .. } => {}
            }
        }
        for expr in &exprs {
            expr.for_each_var(&mut add);
        }

        self.find_stack_memory(&stmts, &exprs);
        self.find_pointers(&stmts, &exprs);
    }

    fn find_stack_memory(&mut self, stmts: &[Stmt], exprs: &[Expr]) {
        let mut addressed = BTreeSet::new();
        fn scan(expr: &Expr, memory: &mut BTreeMap<i64, Width>, addressed: &mut BTreeSet<i64>) {
            match expr {
                Expr::Load { addr, width, .. } => {
                    if let Expr::StackAddr(offset) = addr.as_ref() {
                        memory.entry(*offset).or_insert(*width);
                    } else {
                        scan(addr, memory, addressed);
                    }
                }
                Expr::StackAddr(offset) => {
                    addressed.insert(*offset);
                }
                other => {
                    for child in other.children() {
                        scan(child, memory, addressed);
                    }
                }
            }
        }
        let mut memory = BTreeMap::new();
        for expr in exprs {
            scan(expr, &mut memory, &mut addressed);
        }
        for stmt in stmts {
            if let StmtKind::Store {
                addr: Expr::StackAddr(offset),
                width,
                ..
            } = &stmt.kind
            {
                memory.entry(*offset).or_insert(*width);
                addressed.remove(offset);
            }
        }
        let accessed: BTreeSet<i64> = memory.keys().copied().collect();
        self.array_slots = addressed.difference(&accessed).copied().collect();
        self.memory_slots = memory;
    }

    // A pointer-width variable that gets dereferenced and never used for other math reads best as
    // a byte pointer, since offsets then count bytes just like the machine code does.
    fn find_pointers(&mut self, stmts: &[Stmt], exprs: &[Expr]) {
        let mut bases = HashSet::new();
        let mut blocked = HashSet::new();

        fn collect_base(addr: &Expr, bases: &mut HashSet<Var>) {
            match addr {
                Expr::Var(var) => {
                    bases.insert(*var);
                }
                Expr::Bin(BinOp::Add | BinOp::Sub, left, ..) => collect_base(left, bases),
                _ => {}
            }
        }
        fn scan(expr: &Expr, bases: &mut HashSet<Var>, blocked: &mut HashSet<Var>) {
            match expr {
                Expr::Load { addr, .. } => {
                    collect_base(addr, bases);
                    scan(addr, bases, blocked);
                }
                Expr::Bin(BinOp::Add | BinOp::Sub, left, right, _) => {
                    scan(left, bases, blocked);
                    if let Expr::Var(var) = right.as_ref() {
                        blocked.insert(*var);
                    } else {
                        scan(right, bases, blocked);
                    }
                }
                Expr::Bin(_, left, right, _) => {
                    for side in [left, right] {
                        if let Expr::Var(var) = side.as_ref() {
                            blocked.insert(*var);
                        } else {
                            scan(side, bases, blocked);
                        }
                    }
                }
                Expr::Un(_, inner, _) | Expr::Cast(_, inner, _) => {
                    if let Expr::Var(var) = inner.as_ref() {
                        blocked.insert(*var);
                    } else {
                        scan(inner, bases, blocked);
                    }
                }
                other => {
                    for child in other.children() {
                        scan(child, bases, blocked);
                    }
                }
            }
        }

        for expr in exprs {
            scan(expr, &mut bases, &mut blocked);
        }
        for stmt in stmts {
            if let StmtKind::Store { addr, .. } = &stmt.kind {
                collect_base(addr, &mut bases);
            }
        }
        let ptr = (self.func.bits / 8) as Width;
        self.pointers = bases
            .into_iter()
            .filter(|var| {
                let info = self.func.vars[var.0 as usize];
                info.width == ptr && !info.float && !blocked.contains(var)
            })
            .collect();
    }

    fn var_type(&self, var: Var) -> &'static str {
        let info = self.func.vars[var.0 as usize];
        if info.float {
            "double"
        } else if self.pointers.contains(&var) {
            "char *"
        } else {
            int_type(info.width, true)
        }
    }

    fn name_vars(&mut self, used: &[Var], params: &[(Var, Base)]) {
        for (index, (var, _)) in params.iter().enumerate() {
            if var.0 != u32::MAX {
                self.names.insert(*var, format!("a{}", index + 1));
            }
        }
        let mut counter = 0;
        for var in used {
            if self.names.contains_key(var) {
                continue;
            }
            let info = self.func.vars[var.0 as usize];
            let name = match (info.base, info.origin) {
                (Base::Slot(offset), _) if offset < 0 => format!("var_{:x}", -offset),
                (Base::Slot(offset), _) => format!("arg_{offset:x}"),
                (Base::Reg(register), Origin::Entry) => register_name(register),
                _ => {
                    counter += 1;
                    format!("v{counter}")
                }
            };
            self.names.insert(*var, name);
        }
    }

    pub fn finish(
        mut self,
        nodes: &[Node],
        params: &[(Var, Base)],
        original: Option<&str>,
    ) -> Vec<Line> {
        let mut used = Vec::new();
        let mut seen = HashSet::new();
        self.collect_vars(nodes, &mut used, &mut seen);
        self.name_vars(&used, params);

        let va = self.func.va;
        if let Some(original) = original {
            self.put(format!("// {original}"), TokenKind::Comment);
            self.end_line();
        }

        let ret_width = returned_width(nodes, self.func);
        let ret_type = match ret_width {
            Some((_, true)) => "double",
            Some((width, false)) => int_type(width, true),
            None => "void",
        };
        self.put(ret_type, TokenKind::Type);
        self.plain(" ");
        let name = function_name(self.analysis, va);
        self.put(name, TokenKind::Call);
        self.plain("(");
        for (index, (var, _)) in params.iter().enumerate() {
            if index > 0 {
                self.plain(", ");
            }
            if var.0 == u32::MAX {
                let ptr = (self.func.bits / 8) as Width;
                self.put(int_type(ptr, true), TokenKind::Type);
                self.plain(" ");
                self.put(format!("unused{}", index + 1), TokenKind::Variable);
            } else {
                let kind = self.var_type(*var);
                self.put(kind, TokenKind::Type);
                if !kind.ends_with('*') {
                    self.plain(" ");
                }
                let name = self.names[var].clone();
                self.put(name, TokenKind::Variable);
            }
        }
        if params.is_empty() {
            self.put("void", TokenKind::Type);
        }
        self.plain(")");
        self.line_at(va);
        self.end_line();
        self.plain("{");
        self.end_line();
        self.indent = 1;

        let param_vars: HashSet<Var> = params.iter().map(|(var, _)| *var).collect();
        let mut declared = false;
        for var in used.iter().filter(|var| !param_vars.contains(var)) {
            let kind = self.var_type(*var);
            self.put(kind, TokenKind::Type);
            if !kind.ends_with('*') {
                self.plain(" ");
            }
            let name = self.names[var].clone();
            self.put(name, TokenKind::Variable);
            self.plain(";");
            self.end_line();
            declared = true;
        }
        let memory: Vec<(i64, Width)> = self.memory_slots.iter().map(|(a, b)| (*a, *b)).collect();
        for (offset, width) in memory {
            self.put(int_type(width, true), TokenKind::Type);
            self.plain(" ");
            self.put(slot_name(offset), TokenKind::Variable);
            self.plain(";");
            self.end_line();
            declared = true;
        }
        let arrays: Vec<i64> = self.array_slots.iter().copied().collect();
        for offset in arrays {
            let next = self
                .memory_slots
                .range(offset + 1..)
                .next()
                .map(|(slot, _)| *slot)
                .into_iter()
                .chain(self.array_slots.range(offset + 1..).next().copied())
                .min()
                .unwrap_or(0);
            let size = (next.min(0) - offset).max(1);
            self.put("char", TokenKind::Type);
            self.plain(" ");
            self.put(slot_name(offset), TokenKind::Variable);
            self.plain("[");
            self.put(size.to_string(), TokenKind::Number);
            self.plain("];");
            self.end_line();
            declared = true;
        }
        if declared {
            self.end_line();
        }

        self.nodes(nodes);
        self.indent = 0;
        self.plain("}");
        self.end_line();
        self.lines
    }

    fn nodes(&mut self, nodes: &[Node]) {
        for node in nodes {
            self.node(node);
        }
    }

    fn block(&mut self, nodes: &[Node]) {
        self.indent += 1;
        self.nodes(nodes);
        self.indent -= 1;
    }

    fn node(&mut self, node: &Node) {
        match node {
            Node::Stmts(stmts) => {
                for stmt in stmts {
                    self.line_at(stmt.va);
                    self.stmt(stmt);
                    self.plain(";");
                    self.end_line();
                }
            }
            Node::If {
                cond,
                then,
                other,
                va,
            } => {
                self.line_at(*va);
                self.keyword("if");
                self.plain(" (");
                self.expr(cond, 0);
                self.plain(") {");
                self.end_line();
                self.block(then);
                if other.is_empty() {
                    self.plain("}");
                    self.end_line();
                } else {
                    self.plain("} ");
                    self.keyword("else");
                    self.plain(" {");
                    self.end_line();
                    self.block(other);
                    self.plain("}");
                    self.end_line();
                }
            }
            Node::Loop { body, va } => {
                self.line_at(*va);
                self.keyword("while");
                self.plain(" (");
                self.put("1", TokenKind::Number);
                self.plain(") {");
                self.end_line();
                self.block(body);
                self.plain("}");
                self.end_line();
            }
            Node::While { cond, body, va } => {
                self.line_at(*va);
                self.keyword("while");
                self.plain(" (");
                self.expr(cond, 0);
                self.plain(") {");
                self.end_line();
                self.block(body);
                self.plain("}");
                self.end_line();
            }
            Node::DoWhile { body, cond, va } => {
                self.keyword("do");
                self.plain(" {");
                self.end_line();
                self.block(body);
                self.line_at(*va);
                self.plain("} ");
                self.keyword("while");
                self.plain(" (");
                self.expr(cond, 0);
                self.plain(");");
                self.end_line();
            }
            Node::For {
                init,
                cond,
                step,
                body,
                va,
            } => {
                self.line_at(*va);
                self.keyword("for");
                self.plain(" (");
                self.stmt(init);
                self.plain("; ");
                self.expr(cond, 0);
                self.plain("; ");
                self.stmt(step);
                self.plain(") {");
                self.end_line();
                self.block(body);
                self.plain("}");
                self.end_line();
            }
            Node::Switch { value, cases, va } => {
                self.line_at(*va);
                self.keyword("switch");
                self.plain(" (");
                self.expr(value, 0);
                self.plain(") {");
                self.end_line();
                for (values, body) in cases {
                    for case in values {
                        self.keyword("case");
                        self.plain(" ");
                        self.put(case.to_string(), TokenKind::Number);
                        self.plain(":");
                        self.end_line();
                    }
                    self.block(body);
                    if !body.last().is_some_and(is_jump) {
                        self.indent += 1;
                        self.keyword("break");
                        self.plain(";");
                        self.end_line();
                        self.indent -= 1;
                    }
                }
                self.plain("}");
                self.end_line();
            }
            Node::Return(value, va) => {
                self.line_at(*va);
                self.keyword("return");
                if let Some(value) = value {
                    self.plain(" ");
                    self.expr(value, 0);
                }
                self.plain(";");
                self.end_line();
            }
            Node::Break => {
                self.keyword("break");
                self.plain(";");
                self.end_line();
            }
            Node::Continue => {
                self.keyword("continue");
                self.plain(";");
                self.end_line();
            }
            Node::Goto(block) => {
                self.keyword("goto");
                self.plain(" ");
                let label = self.label_name(*block);
                self.put(label, TokenKind::Label);
                self.plain(";");
                self.end_line();
            }
            Node::Label(block) => {
                if self.labels.contains(block) {
                    let saved = self.indent;
                    self.indent = saved.saturating_sub(1);
                    let label = self.label_name(*block);
                    self.put(label, TokenKind::Label);
                    self.plain(":");
                    self.end_line();
                    self.indent = saved;
                }
            }
        }
    }

    fn label_name(&self, block: usize) -> String {
        format!("loc_{:x}", self.func.blocks[block].va)
    }

    fn stmt(&mut self, stmt: &Stmt) {
        match &stmt.kind {
            StmtKind::Assign { var, value } => self.assign(*var, value),
            StmtKind::Store {
                addr,
                value,
                width,
                float,
            } => {
                self.place(addr, *width, *float);
                self.plain(" = ");
                self.expr(value, 0);
            }
            StmtKind::Call {
                ret,
                clobbers,
                target,
                args,
                ..
            } => {
                let float_ret = clobbers
                    .iter()
                    .find(|var| self.func.vars[var.0 as usize].float);
                if let Some(var) = ret.as_ref().or(float_ret) {
                    let name = self.names[var].clone();
                    self.put(name, TokenKind::Variable);
                    self.plain(" = ");
                }
                self.call_target(target);
                self.plain("(");
                for (index, arg) in args.iter().enumerate() {
                    if index > 0 {
                        self.plain(", ");
                    }
                    self.expr(arg, 0);
                }
                self.plain(")");
            }
            StmtKind::Opaque { text, .. } => {
                self.keyword("__asm__");
                self.plain("(");
                self.put(c_string(text), TokenKind::Text);
                self.plain(")");
            }
            StmtKind::Phi { .. } => {}
        }
    }

    fn assign(&mut self, var: Var, value: &Expr) {
        let name = self.names[&var].clone();
        self.put(name, TokenKind::Variable);
        if let Expr::Bin(op, left, right, width) = value
            && *width >= 4
            && matches!(left.as_ref(), Expr::Var(source) if *source == var)
        {
            let compound = match op {
                BinOp::Add => Some(" += "),
                BinOp::Sub => Some(" -= "),
                BinOp::Mul => Some(" *= "),
                BinOp::And => Some(" &= "),
                BinOp::Or => Some(" |= "),
                BinOp::Xor => Some(" ^= "),
                BinOp::Shl => Some(" <<= "),
                _ => None,
            };
            if let Some(compound) = compound {
                self.plain(compound);
                self.expr(right, 0);
                return;
            }
        }
        self.plain(" = ");
        self.expr(value, 0);
    }

    fn call_target(&mut self, target: &Expr) {
        match target {
            Expr::Const(va, _) => {
                let name = function_name(self.analysis, *va);
                self.tokens.push(Token {
                    text: name,
                    kind: TokenKind::Call,
                    target: Some(*va),
                });
            }
            Expr::Name(name) => {
                self.put(short_import(name), TokenKind::Call);
            }
            other => {
                let ptr = (self.func.bits / 8) as Width;
                self.plain("((");
                self.put(int_type(ptr, true), TokenKind::Type);
                self.plain(" (*)())");
                self.expr(other, 13);
                self.plain(")");
            }
        }
    }

    // Writes the thing at `addr` as something you can read or assign to.
    fn place(&mut self, addr: &Expr, width: Width, float: bool) {
        if let Expr::StackAddr(offset) = addr {
            self.put(slot_name(*offset), TokenKind::Variable);
            return;
        }
        if let Expr::Const(va, _) = addr {
            self.put(format!("g_{va:x}"), TokenKind::Variable);
            return;
        }
        let kind = if float {
            if width == 4 { "float" } else { "double" }
        } else {
            int_type(width, true)
        };

        // base + index * size is array indexing.
        if let Expr::Bin(BinOp::Add, base, index, _) = addr
            && let Expr::Bin(BinOp::Mul, value, scale, _) = index.as_ref()
            && matches!(scale.as_ref(), Expr::Const(size, _) if *size == u64::from(width))
        {
            self.plain("((");
            self.put(kind, TokenKind::Type);
            self.plain(" *)");
            self.expr(base, 12);
            self.plain(")[");
            self.expr(value, 0);
            self.plain("]");
            return;
        }

        self.plain("*(");
        self.put(kind, TokenKind::Type);
        self.plain(" *)");
        self.expr(addr, 12);
    }

    fn cast_prefix(&mut self, width: Width, signed: bool) {
        self.plain("(");
        self.put(int_type(width, signed), TokenKind::Type);
        self.plain(")");
    }

    fn is_float(&self, expr: &Expr) -> bool {
        match expr {
            Expr::Float(_) => true,
            Expr::Var(var) => self.func.vars[var.0 as usize].float,
            Expr::Load { float, .. } => *float,
            Expr::Bin(BinOp::FAdd | BinOp::FSub | BinOp::FMul | BinOp::FDiv, ..) => true,
            Expr::Cast(CastKind::ToFloat, ..) => true,
            Expr::Intrinsic(name, ..) => name == "sqrt",
            _ => false,
        }
    }

    fn signed_view(&mut self, expr: &Expr, width: Width) {
        let plain = match expr {
            Expr::Var(var) => !self.pointers.contains(var),
            Expr::Const(..) | Expr::Load { .. } => true,
            Expr::Cast(CastKind::Sext | CastKind::Trunc, ..) => true,
            _ => false,
        };
        if plain {
            self.expr(expr, 12);
        } else {
            self.cast_prefix(width, true);
            self.expr(expr, 12);
        }
    }

    fn unsigned_view(&mut self, expr: &Expr, width: Width) {
        if let Expr::Const(value, _) = expr {
            self.number(*value, width, false);
            return;
        }
        self.cast_prefix(width, false);
        self.expr(expr, 12);
    }

    fn number(&mut self, value: u64, width: Width, signed: bool) {
        let value = value & mask(width);
        let signed_value = sign_extend(value, width);
        let text = if signed && signed_value < 0 && signed_value > -0x1_0000 {
            signed_value.to_string()
        } else if value < 0x100 {
            value.to_string()
        } else {
            format!("{value:#x}")
        };
        self.put(text, TokenKind::Number);
    }

    fn constant(&mut self, value: u64, width: Width) {
        let ptr = (self.func.bits / 8) as Width;
        if width == ptr {
            if let Some(entry) = self.listing.string_at(value) {
                self.put(c_string(&entry.value), TokenKind::Text);
                return;
            }
            if self.analysis.function_at(value).is_some() {
                let name = function_name(self.analysis, value);
                self.tokens.push(Token {
                    text: name,
                    kind: TokenKind::Call,
                    target: Some(value),
                });
                return;
            }
            if let Some(name) = self.analysis.iat.get(&value) {
                let name = short_import(name).to_owned();
                self.put(name, TokenKind::Call);
                return;
            }
        }
        self.number(value, width, true);
    }

    pub fn expr(&mut self, expr: &Expr, parent: u8) {
        let own = precedence(expr);
        let wrap = own < parent;
        self.nested = parent > 0;
        if wrap {
            self.plain("(");
        }
        self.expr_inner(expr);
        if wrap {
            self.plain(")");
        }
    }

    fn binary(&mut self, left: &Expr, op: &str, right: &Expr, own: u8) {
        self.expr(left, own);
        self.plain(op);
        self.expr(right, own + 1);
    }

    fn expr_inner(&mut self, expr: &Expr) {
        let own = precedence(expr);
        match expr {
            Expr::Const(value, width) => self.constant(*value, *width),
            Expr::Float(value) => {
                let text = if value.fract() == 0.0 && value.abs() < 1e15 {
                    format!("{value:.1}")
                } else {
                    format!("{value}")
                };
                self.put(text, TokenKind::Number);
            }
            Expr::Var(var) => {
                let name = self
                    .names
                    .get(var)
                    .cloned()
                    .unwrap_or_else(|| "undefined".into());
                self.put(name, TokenKind::Variable);
            }
            Expr::StackAddr(offset) => {
                if !self.array_slots.contains(offset) {
                    self.plain("&");
                }
                self.put(slot_name(*offset), TokenKind::Variable);
            }
            Expr::Name(name) => {
                self.put(short_import(name), TokenKind::Call);
            }
            Expr::Load { addr, width, float } => self.place(addr, *width, *float),
            Expr::Bin(op, a, b, width) => {
                let narrow = *width < 4
                    && !matches!(op, BinOp::And | BinOp::Or | BinOp::Xor)
                    && !matches!(op, BinOp::FAdd | BinOp::FSub | BinOp::FMul | BinOp::FDiv);
                if narrow {
                    self.cast_prefix(*width, true);
                    self.plain("(");
                }
                match op {
                    BinOp::Add | BinOp::FAdd => self.binary(a, " + ", b, own),
                    BinOp::Sub | BinOp::FSub => self.binary(a, " - ", b, own),
                    BinOp::Mul | BinOp::FMul => self.binary(a, " * ", b, own),
                    BinOp::FDiv => self.binary(a, " / ", b, own),
                    BinOp::And => self.binary(a, " & ", b, own),
                    BinOp::Or => self.binary(a, " | ", b, own),
                    BinOp::Xor => self.binary(a, " ^ ", b, own),
                    BinOp::Shl => self.binary(a, " << ", b, own),
                    BinOp::Shr => {
                        self.unsigned_view(a, *width);
                        self.plain(" >> ");
                        self.expr(b, own + 1);
                    }
                    BinOp::Sar => {
                        self.signed_view(a, *width);
                        self.plain(" >> ");
                        self.expr(b, own + 1);
                    }
                    BinOp::SDiv | BinOp::SRem => {
                        self.signed_view(a, *width);
                        self.plain(if *op == BinOp::SDiv { " / " } else { " % " });
                        self.signed_view(b, *width);
                    }
                    BinOp::UDiv | BinOp::URem => {
                        self.unsigned_view(a, *width);
                        self.plain(if *op == BinOp::UDiv { " / " } else { " % " });
                        self.unsigned_view(b, *width);
                    }
                    BinOp::MulHiS | BinOp::MulHiU => {
                        let name = if *op == BinOp::MulHiS {
                            "__mulhs"
                        } else {
                            "__mulhu"
                        };
                        self.put(name, TokenKind::Call);
                        self.plain("(");
                        self.expr(a, 0);
                        self.plain(", ");
                        self.expr(b, 0);
                        self.plain(")");
                    }
                }
                if narrow {
                    self.plain(")");
                }
            }
            Expr::Un(op, inner, _) => {
                self.plain(match op {
                    UnOp::Neg => "-",
                    UnOp::Not => "~",
                    UnOp::BoolNot => "!",
                });
                self.expr(inner, own);
            }
            Expr::Cast(kind, inner, width) => match kind {
                CastKind::Trunc | CastKind::FromFloat => {
                    self.cast_prefix(*width, true);
                    self.expr(inner, own);
                }
                CastKind::ToFloat => {
                    self.plain("(");
                    self.put("double", TokenKind::Type);
                    self.plain(")");
                    self.expr(inner, own);
                }
                CastKind::Zext => {
                    let from = inner.width(&self.func.vars);
                    if matches!(
                        inner.as_ref(),
                        Expr::Cmp(..) | Expr::Both(..) | Expr::Either(..)
                    ) {
                        self.expr(inner, own);
                    } else {
                        // Inside a larger expression, C would otherwise do the math at the
                        // narrow width.
                        if self.nested && *width == 8 {
                            self.cast_prefix(8, true);
                        }
                        self.cast_prefix(from, false);
                        self.expr(inner, own);
                    }
                }
                CastKind::Sext => {
                    let from = inner.width(&self.func.vars);
                    self.cast_prefix(*width, true);
                    if !matches!(inner.as_ref(), Expr::Var(_) | Expr::Load { .. }) {
                        self.cast_prefix(from, true);
                    }
                    self.expr(inner, own);
                }
            },
            Expr::Cmp(op, a, b, width) => {
                let text = match op {
                    CmpOp::Eq => " == ",
                    CmpOp::Ne => " != ",
                    CmpOp::SLt | CmpOp::ULt => " < ",
                    CmpOp::SLe | CmpOp::ULe => " <= ",
                    CmpOp::SGt | CmpOp::UGt => " > ",
                    CmpOp::SGe | CmpOp::UGe => " >= ",
                };
                let is_float = self.is_float(a) || self.is_float(b);
                if is_float || matches!(op, CmpOp::Eq | CmpOp::Ne) {
                    self.binary(a, text, b, own);
                } else if op.is_signed() {
                    self.signed_view(a, *width);
                    self.plain(text);
                    self.signed_view(b, *width);
                } else {
                    debug_assert!(op.is_unsigned());
                    self.unsigned_view(a, *width);
                    self.plain(text);
                    self.unsigned_view(b, *width);
                }
            }
            Expr::Both(a, b) => self.binary(a, " && ", b, own),
            Expr::Either(a, b) => self.binary(a, " || ", b, own),
            Expr::Select(cond, a, b, _) => {
                self.expr(cond, own + 1);
                self.plain(" ? ");
                self.expr(a, own + 1);
                self.plain(" : ");
                self.expr(b, own);
            }
            Expr::Intrinsic(name, args, _) => {
                self.put(name.clone(), TokenKind::Call);
                self.plain("(");
                for (index, arg) in args.iter().enumerate() {
                    if index > 0 {
                        self.plain(", ");
                    }
                    self.expr(arg, 0);
                }
                self.plain(")");
            }
        }
    }
}

fn is_jump(node: &Node) -> bool {
    matches!(
        node,
        Node::Return(..) | Node::Break | Node::Continue | Node::Goto(_)
    )
}

fn slot_name(offset: i64) -> String {
    if offset < 0 {
        format!("var_{:x}", -offset)
    } else {
        format!("arg_{offset:x}")
    }
}

fn register_name(register: Register) -> String {
    format!("{register:?}").to_lowercase()
}

fn returned_width(nodes: &[Node], func: &Func) -> Option<(Width, bool)> {
    let mut best: Option<(Width, bool)> = None;
    fn walk(nodes: &[Node], func: &Func, best: &mut Option<(Width, bool)>) {
        for node in nodes {
            match node {
                Node::Return(Some(value), _) => {
                    let width = value.width(&func.vars);
                    let current = best.get_or_insert((width, false));
                    current.0 = current.0.max(width);
                }
                Node::If { then, other, .. } => {
                    walk(then, func, best);
                    walk(other, func, best);
                }
                Node::Loop { body, .. }
                | Node::While { body, .. }
                | Node::DoWhile { body, .. }
                | Node::For { body, .. } => walk(body, func, best),
                Node::Switch { cases, .. } => {
                    for (_, body) in cases {
                        walk(body, func, best);
                    }
                }
                _ => {}
            }
        }
    }
    walk(nodes, func, &mut best);
    best
}

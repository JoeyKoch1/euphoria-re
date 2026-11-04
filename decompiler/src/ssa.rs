use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

use iced_x86::Register;

use crate::ir::{
    Base, BinOp, Block, CastKind, Expr, Func, Origin, Stmt, StmtKind, Term, Var, VarInfo, simplify,
};
use crate::lift::{arg_registers, first_stack_arg, import_params};

const OPTIMIZE_ROUNDS: usize = 24;

// Stack slots whose address never escapes behave like registers, so they join SSA as variables.
pub fn promote_slots(func: &mut Func, saved: &BTreeSet<i64>) {
    let mut accesses: BTreeMap<(i64, u8), (bool, bool, bool)> = BTreeMap::new();
    let mut escaped: BTreeSet<i64> = BTreeSet::new();

    fn scan(
        expr: &Expr,
        accesses: &mut BTreeMap<(i64, u8), (bool, bool, bool)>,
        escaped: &mut BTreeSet<i64>,
    ) {
        match expr {
            Expr::Load { addr, width, float } => {
                if let Expr::StackAddr(offset) = addr.as_ref() {
                    let entry = accesses.entry((*offset, *width)).or_default();
                    entry.0 = true;
                    entry.2 |= *float;
                } else {
                    scan(addr, accesses, escaped);
                }
            }
            Expr::StackAddr(offset) => {
                escaped.insert(*offset);
            }
            other => {
                for child in other.children() {
                    scan(child, accesses, escaped);
                }
            }
        }
    }

    for block in &func.blocks {
        for stmt in &block.stmts {
            match &stmt.kind {
                StmtKind::Assign { value, .. } => scan(value, &mut accesses, &mut escaped),
                StmtKind::Store {
                    addr,
                    value,
                    width,
                    float,
                } => {
                    if let Expr::StackAddr(offset) = addr {
                        let entry = accesses.entry((*offset, *width)).or_default();
                        entry.1 = true;
                        entry.2 |= *float;
                    } else {
                        scan(addr, &mut accesses, &mut escaped);
                    }
                    scan(value, &mut accesses, &mut escaped);
                }
                StmtKind::Call { target, args, .. } => {
                    scan(target, &mut accesses, &mut escaped);
                    for arg in args {
                        scan(arg, &mut accesses, &mut escaped);
                    }
                }
                StmtKind::Opaque { uses, .. } => {
                    for used in uses {
                        scan(used, &mut accesses, &mut escaped);
                    }
                }
                StmtKind::Phi { .. } => {}
            }
        }
        for expr in block.term.exprs() {
            scan(expr, &mut accesses, &mut escaped);
        }
    }

    let keys: Vec<(i64, u8)> = accesses.keys().copied().collect();
    let mut memory: BTreeSet<(i64, u8)> = BTreeSet::new();
    for (position, &(offset, width)) in keys.iter().enumerate() {
        for &(other, other_width) in &keys[position + 1..] {
            if other >= offset + i64::from(width) {
                break;
            }
            memory.insert((offset, width));
            memory.insert((other, other_width));
        }
        // A pointer into the frame can reach anything above it, up to the saved registers.
        let reachable = escaped.contains(&offset)
            || escaped
                .iter()
                .any(|&start| offset >= start && offset < 0 && !saved.contains(&offset));
        if reachable {
            memory.insert((offset, width));
        }
    }

    let mut slot_vars: HashMap<i64, Var> = HashMap::new();
    let mut write_only: HashSet<i64> = HashSet::new();
    for (&(offset, width), &(read, written, float)) in &accesses {
        if memory.contains(&(offset, width)) {
            continue;
        }
        let var = Var(func.vars.len() as u32);
        func.vars.push(VarInfo {
            base: Base::Slot(offset),
            width,
            float,
            origin: Origin::Unversioned,
        });
        slot_vars.insert(offset, var);
        if written && !read {
            write_only.insert(offset);
        }
    }

    let rewrite = |expr: &mut Expr| {
        expr.rewrite(&mut |node| {
            if let Expr::Load { addr, .. } = node
                && let Expr::StackAddr(offset) = addr.as_ref()
                && let Some(var) = slot_vars.get(offset)
            {
                *node = Expr::Var(*var);
            }
        });
    };

    for block in &mut func.blocks {
        for stmt in &mut block.stmts {
            match &mut stmt.kind {
                StmtKind::Assign { value, .. } => rewrite(value),
                StmtKind::Store { addr, value, .. } => {
                    rewrite(addr);
                    rewrite(value);
                    if let Expr::StackAddr(offset) = addr
                        && let Some(var) = slot_vars.get(offset)
                    {
                        stmt.kind = StmtKind::Assign {
                            var: *var,
                            value: value.clone(),
                        };
                    }
                }
                StmtKind::Call {
                    target,
                    args,
                    candidates,
                    clobbers,
                    ..
                } => {
                    rewrite(target);
                    args.iter_mut().for_each(&rewrite);
                    if let Some(candidates) = candidates {
                        candidates.slot_vars = candidates
                            .slots
                            .iter()
                            .map_while(|offset| {
                                write_only.contains(offset).then(|| slot_vars[offset])
                            })
                            .collect();
                        clobbers.extend(candidates.slot_vars.iter().copied());
                    }
                }
                StmtKind::Opaque { uses, .. } => uses.iter_mut().for_each(&rewrite),
                StmtKind::Phi { .. } => {}
            }
        }
        for expr in block.term.exprs_mut() {
            rewrite(expr);
        }
    }
}

const NO_BLOCK: usize = usize::MAX;

pub fn dominators(preds: &[Vec<usize>], order: &[usize], entry: usize) -> Vec<usize> {
    let mut rank = vec![NO_BLOCK; preds.len()];
    for (position, &block) in order.iter().enumerate() {
        rank[block] = position;
    }
    let mut idom = vec![NO_BLOCK; preds.len()];
    idom[entry] = entry;

    let mut changed = true;
    while changed {
        changed = false;
        for &block in order.iter().filter(|&&block| block != entry) {
            let mut best = NO_BLOCK;
            for &pred in &preds[block] {
                if idom[pred] == NO_BLOCK {
                    continue;
                }
                best = if best == NO_BLOCK {
                    pred
                } else {
                    let (mut a, mut b) = (pred, best);
                    while a != b {
                        while rank[a] > rank[b] {
                            a = idom[a];
                        }
                        while rank[b] > rank[a] {
                            b = idom[b];
                        }
                    }
                    a
                };
            }
            if best != NO_BLOCK && idom[block] != best {
                idom[block] = best;
                changed = true;
            }
        }
    }
    idom
}

pub fn drop_unreachable(func: &mut Func) {
    let order = func.reverse_post_order();
    let mut remap = vec![NO_BLOCK; func.blocks.len()];
    let mut sorted = order.clone();
    sorted.sort_unstable();
    for (new, &old) in sorted.iter().enumerate() {
        remap[old] = new;
    }

    let mut blocks = Vec::with_capacity(sorted.len());
    for &old in &sorted {
        let mut block = func.blocks[old].clone();
        match &mut block.term {
            Term::Jump(to) => *to = remap[*to],
            Term::Branch {
                taken, not_taken, ..
            } => {
                *taken = remap[*taken];
                *not_taken = remap[*not_taken];
            }
            Term::Switch { cases, .. } => {
                for (_, to) in cases {
                    *to = remap[*to];
                }
            }
            _ => {}
        }
        for stmt in &mut block.stmts {
            if let StmtKind::Phi { inputs, .. } = &mut stmt.kind {
                inputs.retain(|(pred, _)| remap[*pred] != NO_BLOCK);
                for (pred, _) in inputs {
                    *pred = remap[*pred];
                }
            }
        }
        blocks.push(block);
    }
    func.blocks = blocks;
    func.compute_preds();
}

fn defs_of(stmt: &Stmt) -> Vec<Var> {
    match &stmt.kind {
        StmtKind::Assign { var, .. } | StmtKind::Phi { var, .. } => vec![*var],
        StmtKind::Call { ret, clobbers, .. } => {
            ret.iter().chain(clobbers.iter()).copied().collect()
        }
        StmtKind::Opaque { defs, .. } => defs.clone(),
        StmtKind::Store { .. } => Vec::new(),
    }
}

fn for_each_use(stmt: &Stmt, f: &mut impl FnMut(Var)) {
    match &stmt.kind {
        StmtKind::Assign { value, .. } => value.for_each_var(f),
        StmtKind::Store { addr, value, .. } => {
            addr.for_each_var(f);
            value.for_each_var(f);
        }
        StmtKind::Phi { inputs, .. } => {
            for (_, var) in inputs {
                f(*var);
            }
        }
        StmtKind::Call {
            target,
            args,
            candidates,
            ..
        } => {
            target.for_each_var(f);
            for arg in args {
                arg.for_each_var(f);
            }
            if let Some(candidates) = candidates {
                for var in candidates
                    .registers
                    .iter()
                    .chain(&candidates.floats)
                    .chain(&candidates.slot_vars)
                {
                    f(*var);
                }
            }
        }
        StmtKind::Opaque { uses, .. } => {
            for used in uses {
                used.for_each_var(f);
            }
        }
    }
}

fn map_uses(stmt: &mut Stmt, f: &mut impl FnMut(&mut Expr)) {
    match &mut stmt.kind {
        StmtKind::Assign { value, .. } => f(value),
        StmtKind::Store { addr, value, .. } => {
            f(addr);
            f(value);
        }
        StmtKind::Call { target, args, .. } => {
            f(target);
            args.iter_mut().for_each(&mut *f);
        }
        StmtKind::Opaque { uses, .. } => uses.iter_mut().for_each(&mut *f),
        StmtKind::Phi { .. } => {}
    }
}

pub fn build_ssa(func: &mut Func) {
    drop_unreachable(func);
    let order = func.reverse_post_order();
    let preds: Vec<Vec<usize>> = func.blocks.iter().map(|b| b.preds.clone()).collect();
    let idom = dominators(&preds, &order, 0);

    let mut frontier: Vec<BTreeSet<usize>> = vec![BTreeSet::new(); func.blocks.len()];
    for (block, block_preds) in preds.iter().enumerate() {
        if block_preds.len() < 2 {
            continue;
        }
        for &pred in block_preds {
            let mut runner = pred;
            while runner != idom[block] && runner != NO_BLOCK {
                frontier[runner].insert(block);
                if runner == idom[runner] {
                    break;
                }
                runner = idom[runner];
            }
        }
    }

    let mut def_blocks: BTreeMap<Var, BTreeSet<usize>> = BTreeMap::new();
    for (index, block) in func.blocks.iter().enumerate() {
        for stmt in &block.stmts {
            for var in defs_of(stmt) {
                def_blocks.entry(var).or_default().insert(index);
            }
        }
    }

    for (&var, blocks) in &def_blocks {
        let mut placed = BTreeSet::new();
        let mut work: Vec<usize> = blocks.iter().copied().collect();
        while let Some(block) = work.pop() {
            for &target in &frontier[block] {
                if placed.insert(target) {
                    let va = func.blocks[target].va;
                    func.blocks[target].stmts.insert(
                        0,
                        Stmt {
                            va,
                            kind: StmtKind::Phi {
                                var,
                                inputs: Vec::new(),
                            },
                        },
                    );
                    work.push(target);
                }
            }
        }
    }

    let mut children: Vec<Vec<usize>> = vec![Vec::new(); func.blocks.len()];
    for &block in &order {
        if block != 0 && idom[block] != NO_BLOCK {
            children[idom[block]].push(block);
        }
    }

    let unversioned = func.vars.len();
    let mut current: Vec<Vec<Var>> = vec![Vec::new(); unversioned];
    let mut entry: Vec<Option<Var>> = vec![None; unversioned];
    enum Step {
        Enter(usize),
        Leave(Vec<usize>),
    }
    let mut stack = vec![Step::Enter(0)];

    let new_version = |vars: &mut Vec<VarInfo>, var: Var, origin: Origin| -> Var {
        let mut info = vars[var.0 as usize];
        info.origin = origin;
        vars.push(info);
        Var(vars.len() as u32 - 1)
    };

    while let Some(step) = stack.pop() {
        let block_index = match step {
            Step::Leave(pushed) => {
                for var in pushed {
                    current[var].pop();
                }
                continue;
            }
            Step::Enter(block) => block,
        };

        let mut pushed = Vec::new();
        let mut block = std::mem::replace(
            &mut func.blocks[block_index],
            Block {
                va: 0,
                stmts: Vec::new(),
                term: Term::Stop(None),
                term_va: 0,
                preds: Vec::new(),
            },
        );

        let mut read = |vars: &mut Vec<VarInfo>, current: &Vec<Vec<Var>>, var: Var| -> Var {
            let index = var.0 as usize;
            if index >= unversioned {
                return var;
            }
            if let Some(top) = current[index].last() {
                return *top;
            }
            *entry[index].get_or_insert_with(|| new_version(vars, var, Origin::Entry))
        };

        for stmt in &mut block.stmts {
            if !matches!(stmt.kind, StmtKind::Phi { .. }) {
                map_uses(stmt, &mut |expr| {
                    expr.rewrite(&mut |node| {
                        if let Expr::Var(var) = node {
                            *var = read(&mut func.vars, &current, *var);
                        }
                    });
                });
                if let StmtKind::Call {
                    candidates: Some(candidates),
                    ..
                } = &mut stmt.kind
                {
                    for var in candidates
                        .registers
                        .iter_mut()
                        .chain(&mut candidates.floats)
                        .chain(&mut candidates.slot_vars)
                    {
                        *var = read(&mut func.vars, &current, *var);
                    }
                }
            }

            let mut define = |var: &mut Var, origin: Origin| {
                let base = var.0 as usize;
                let next = new_version(&mut func.vars, *var, origin);
                current[base].push(next);
                pushed.push(base);
                *var = next;
            };
            match &mut stmt.kind {
                StmtKind::Assign { var, .. } | StmtKind::Phi { var, .. } => {
                    define(var, Origin::Defined);
                }
                StmtKind::Call { ret, clobbers, .. } => {
                    if let Some(var) = ret {
                        define(var, Origin::Defined);
                    }
                    for var in clobbers {
                        define(var, Origin::Clobber);
                    }
                }
                StmtKind::Opaque { defs, .. } => {
                    for var in defs {
                        define(var, Origin::Defined);
                    }
                }
                StmtKind::Store { .. } => {}
            }
        }
        for expr in block.term.exprs_mut() {
            expr.rewrite(&mut |node| {
                if let Expr::Var(var) = node {
                    *var = read(&mut func.vars, &current, *var);
                }
            });
        }

        let successors = block.term.successors();
        func.blocks[block_index] = block;

        for successor in successors {
            // Phi statements still hold their unversioned variable until this point.
            let phi_count = func.blocks[successor]
                .stmts
                .iter()
                .take_while(|stmt| matches!(stmt.kind, StmtKind::Phi { .. }))
                .count();
            for position in 0..phi_count {
                let original = phi_original(
                    &func.blocks[successor].stmts[position],
                    &func.vars,
                    unversioned,
                );
                let value = read(&mut func.vars, &current, original);
                if let StmtKind::Phi { inputs, .. } =
                    &mut func.blocks[successor].stmts[position].kind
                {
                    inputs.push((block_index, value));
                }
            }
        }

        stack.push(Step::Leave(pushed));
        for &child in children[block_index].iter().rev() {
            stack.push(Step::Enter(child));
        }
    }
}

// Maps a renamed phi back to its unversioned variable through the base it was made from.
fn phi_original(stmt: &Stmt, vars: &[VarInfo], unversioned: usize) -> Var {
    let StmtKind::Phi { var, .. } = &stmt.kind else {
        return Var(0);
    };
    if (var.0 as usize) < unversioned {
        return *var;
    }
    let base = vars[var.0 as usize].base;
    let found = vars[..unversioned]
        .iter()
        .position(|info| info.base == base);
    Var(found.unwrap_or(0) as u32)
}

fn is_defined(
    var: Var,
    func: &Func,
    phis: &HashMap<Var, Vec<Var>>,
    seen: &mut HashSet<Var>,
) -> bool {
    if !seen.insert(var) {
        return false;
    }
    match func.vars[var.0 as usize].origin {
        Origin::Entry | Origin::Clobber | Origin::Unversioned => false,
        Origin::Defined => match phis.get(&var) {
            Some(inputs) => inputs
                .iter()
                .any(|input| is_defined(*input, func, phis, seen)),
            None => true,
        },
    }
}

fn phi_inputs(func: &Func) -> HashMap<Var, Vec<Var>> {
    let mut phis = HashMap::new();
    for block in &func.blocks {
        for stmt in &block.stmts {
            if let StmtKind::Phi { var, inputs } = &stmt.kind {
                phis.insert(*var, inputs.iter().map(|(_, input)| *input).collect());
            }
        }
    }
    phis
}

// Decides which candidates are real arguments, and whether the routine returns anything.
pub fn resolve_calls(func: &mut Func, params_of: &dyn Fn(u64) -> Option<usize>) {
    let phis = phi_inputs(func);
    let mut resolved: Vec<(usize, usize, Vec<Expr>)> = Vec::new();

    for (block_index, block) in func.blocks.iter().enumerate() {
        for (stmt_index, stmt) in block.stmts.iter().enumerate() {
            let StmtKind::Call {
                target,
                candidates: Some(candidates),
                ..
            } = &stmt.kind
            else {
                continue;
            };
            let known = match target {
                Expr::Const(va, _) => params_of(*va),
                Expr::Name(name) => import_params(name),
                _ => None,
            };
            let tail = candidates.tail;
            let defined = |var: Var| {
                let entry = tail && func.vars[var.0 as usize].origin == Origin::Entry;
                entry || is_defined(var, func, &phis, &mut HashSet::new())
            };

            let positional = candidates.registers.len();
            let slot_count = candidates.slot_vars.len();
            let total = positional + slot_count;
            let last_used = (0..total)
                .rev()
                .find(|&index| {
                    let is_float = candidates
                        .floats
                        .get(index)
                        .is_some_and(|var| defined(*var));
                    if index < positional {
                        defined(candidates.registers[index]) || is_float
                    } else {
                        defined(candidates.slot_vars[index - positional])
                    }
                })
                .map_or(0, |index| index + 1);
            let count = known.map_or(last_used, |known| known.min(total));

            let args = (0..count)
                .map(|index| {
                    if index < positional {
                        let integer = candidates.registers[index];
                        match candidates.floats.get(index) {
                            Some(float) if !defined(integer) && defined(*float) => {
                                Expr::Var(*float)
                            }
                            _ => Expr::Var(integer),
                        }
                    } else {
                        Expr::Var(candidates.slot_vars[index - positional])
                    }
                })
                .collect();
            resolved.push((block_index, stmt_index, args));
        }
    }

    for (block, stmt, new_args) in resolved {
        if let StmtKind::Call {
            args, candidates, ..
        } = &mut func.blocks[block].stmts[stmt].kind
        {
            *args = new_args;
            *candidates = None;
        }
    }

    let phis = phi_inputs(func);
    let returns_value = func.blocks.iter().any(|block| {
        matches!(&block.term, Term::Return(Some(Expr::Var(var)))
            if is_defined(*var, func, &phis, &mut HashSet::new()))
    });
    if !returns_value {
        for block in &mut func.blocks {
            if let Term::Return(value) = &mut block.term {
                *value = None;
            }
        }
    }
}

fn stmt_has_effect(stmt: &Stmt) -> bool {
    matches!(
        stmt.kind,
        StmtKind::Store { .. } | StmtKind::Call { .. } | StmtKind::Opaque { .. }
    )
}

pub fn eliminate_dead(func: &mut Func) {
    let mut live: HashSet<Var> = HashSet::new();
    let mut work: Vec<Var> = Vec::new();
    let mut defs: HashMap<Var, (usize, usize)> = HashMap::new();

    for (block_index, block) in func.blocks.iter().enumerate() {
        for (stmt_index, stmt) in block.stmts.iter().enumerate() {
            for var in defs_of(stmt) {
                defs.insert(var, (block_index, stmt_index));
            }
            if stmt_has_effect(stmt) {
                for_each_use(stmt, &mut |var| work.push(var));
            }
        }
        for expr in block.term.exprs() {
            expr.for_each_var(&mut |var| work.push(var));
        }
    }

    while let Some(var) = work.pop() {
        if !live.insert(var) {
            continue;
        }
        if let Some(&(block, stmt)) = defs.get(&var) {
            let stmt = &func.blocks[block].stmts[stmt];
            if !stmt_has_effect(stmt) {
                for_each_use(stmt, &mut |used| work.push(used));
            }
        }
    }

    for block in &mut func.blocks {
        block.stmts.retain_mut(|stmt| match &mut stmt.kind {
            StmtKind::Assign { var, .. } | StmtKind::Phi { var, .. } => live.contains(var),
            StmtKind::Call { ret, clobbers, .. } => {
                if ret.is_some_and(|var| !live.contains(&var)) {
                    *ret = None;
                }
                clobbers.retain(|var| live.contains(var));
                true
            }
            StmtKind::Opaque { defs, .. } => {
                defs.retain(|var| live.contains(var));
                true
            }
            StmtKind::Store { .. } => true,
        });
    }
}

fn count_uses(func: &Func) -> HashMap<Var, usize> {
    let mut counts = HashMap::new();
    for block in &func.blocks {
        for stmt in &block.stmts {
            for_each_use(stmt, &mut |var| *counts.entry(var).or_insert(0) += 1);
        }
        for expr in block.term.exprs() {
            expr.for_each_var(&mut |var| *counts.entry(var).or_insert(0) += 1);
        }
    }
    counts
}

fn is_cheap(value: &Expr) -> bool {
    matches!(
        value,
        Expr::Const(..) | Expr::Float(_) | Expr::Var(_) | Expr::StackAddr(_) | Expr::Name(_)
    )
}

fn barrier(stmt: &Stmt) -> bool {
    stmt_has_effect(stmt)
}

// Replaces uses of a variable with its definition wherever that cannot change the meaning.
fn propagate(func: &mut Func) -> bool {
    let counts = count_uses(func);
    let mut replacements: HashMap<Var, Expr> = HashMap::new();
    let mut copies: HashMap<Var, Var> = HashMap::new();

    for block in &func.blocks {
        for stmt in &block.stmts {
            let StmtKind::Assign { var, value } = &stmt.kind else {
                continue;
            };
            let same_width = value.width(&func.vars) == func.vars[var.0 as usize].width;
            if let Expr::Var(source) = value
                && same_width
                && func.vars[source.0 as usize].float == func.vars[var.0 as usize].float
            {
                copies.insert(*var, *source);
            }
            let uses = counts.get(var).copied().unwrap_or(0);
            if same_width && (is_cheap(value) || (uses == 1 && !value.reads_memory())) {
                replacements.insert(*var, value.clone());
            }
        }
    }

    // Reads can only move forward inside their block, and only past statements that leave memory
    // alone.
    let mut in_block: HashMap<Var, Expr> = HashMap::new();
    let mut phi_used: HashSet<Var> = HashSet::new();
    for block in &func.blocks {
        for stmt in &block.stmts {
            if let StmtKind::Phi { inputs, .. } = &stmt.kind {
                phi_used.extend(inputs.iter().map(|(_, var)| *var));
            }
        }
    }
    let mut changed = false;
    let replacements = &replacements;
    let vars_snapshot = func.vars.clone();
    let resolve_copy = |mut var: Var, copies: &HashMap<Var, Var>| {
        let mut guard = 0;
        while let Some(next) = copies.get(&var) {
            var = *next;
            guard += 1;
            if guard > 64 {
                break;
            }
        }
        var
    };

    for block in &mut func.blocks {
        in_block.clear();
        for stmt in &mut block.stmts {
            let replace = |expr: &mut Expr, changed: &mut bool, in_block: &HashMap<Var, Expr>| {
                expr.rewrite(&mut |node| {
                    if let Expr::Var(var) = node
                        && let Some(value) = replacements.get(var).or_else(|| in_block.get(var))
                    {
                        *node = value.clone();
                        *changed = true;
                    }
                });
            };
            match &mut stmt.kind {
                StmtKind::Phi { inputs, .. } => {
                    for (_, var) in inputs {
                        let source = resolve_copy(*var, &copies);
                        if source != *var {
                            *var = source;
                            changed = true;
                        }
                    }
                }
                _ => map_uses(stmt, &mut |expr| replace(expr, &mut changed, &in_block)),
            }

            if barrier(stmt) {
                in_block.clear();
            }
            if let StmtKind::Assign { var, value } = &stmt.kind {
                let uses = counts.get(var).copied().unwrap_or(0);
                let same_width = value.width(&vars_snapshot) == vars_snapshot[var.0 as usize].width;
                if uses == 1 && value.reads_memory() && same_width && !phi_used.contains(var) {
                    in_block.insert(*var, value.clone());
                }
            }
        }
        for expr in block.term.exprs_mut() {
            expr.rewrite(&mut |node| {
                if let Expr::Var(var) = node
                    && let Some(value) = replacements.get(var).or_else(|| in_block.get(var))
                {
                    *node = value.clone();
                    changed = true;
                }
            });
        }
    }
    changed
}

fn simplify_all(func: &mut Func) {
    let vars = std::mem::take(&mut func.vars);
    for block in &mut func.blocks {
        for stmt in &mut block.stmts {
            map_uses(stmt, &mut |expr| simplify(expr, &vars));
        }
        for expr in block.term.exprs_mut() {
            simplify(expr, &vars);
        }
    }
    func.vars = vars;
}

// A phi whose inputs all agree is just a copy, and a branch on a constant has one way out.
fn simplify_phis(func: &mut Func) {
    for block in &mut func.blocks {
        for stmt in &mut block.stmts {
            if let StmtKind::Phi { var, inputs } = &stmt.kind {
                let mut distinct = inputs
                    .iter()
                    .map(|(_, input)| *input)
                    .filter(|input| input != var);
                let first = distinct.next();
                if let Some(first) = first
                    && distinct.all(|other| other == first)
                {
                    stmt.kind = StmtKind::Assign {
                        var: *var,
                        value: Expr::Var(first),
                    };
                }
            }
        }
    }
}

fn fold_constant_branches(func: &mut Func) -> bool {
    let mut changed = false;
    for index in 0..func.blocks.len() {
        if let Term::Branch {
            cond: Expr::Const(value, _),
            taken,
            not_taken,
        } = &func.blocks[index].term
        {
            let (keep, drop) = if *value != 0 {
                (*taken, *not_taken)
            } else {
                (*not_taken, *taken)
            };
            func.blocks[index].term = Term::Jump(keep);
            if keep != drop {
                for stmt in &mut func.blocks[drop].stmts {
                    if let StmtKind::Phi { inputs, .. } = &mut stmt.kind {
                        inputs.retain(|(pred, _)| *pred != index);
                    }
                }
            }
            changed = true;
        }
    }
    if changed {
        func.compute_preds();
    }
    changed
}

pub fn optimize(func: &mut Func) {
    for _ in 0..OPTIMIZE_ROUNDS {
        simplify_all(func);
        simplify_phis(func);
        let folded = fold_constant_branches(func);
        if folded {
            drop_unreachable(func);
        }
        let propagated = propagate(func);
        eliminate_dead(func);
        if !propagated && !folded {
            break;
        }
    }
    simplify_all(func);
}

// Writing a 32-bit register clears the top half, so `return (uint32_t)x` is just a 32-bit return.
pub fn narrow_returns(func: &mut Func) {
    let vars = &func.vars;
    let fits = |value: &Expr| match value {
        Expr::Cast(CastKind::Zext, inner, _) => inner.width(vars) <= 4,
        Expr::Const(constant, _) => *constant <= 0xFFFF_FFFF,
        other => other.width(vars) <= 4,
    };
    let all_fit = func.blocks.iter().all(|block| match &block.term {
        Term::Return(Some(value)) => fits(value),
        _ => true,
    });
    if !all_fit {
        return;
    }

    let vars = std::mem::take(&mut func.vars);
    for block in &mut func.blocks {
        if let Term::Return(Some(value)) = &mut block.term {
            match value {
                Expr::Cast(CastKind::Zext, inner, _) if inner.width(&vars) == 4 => {
                    *value = (**inner).clone();
                }
                Expr::Cast(CastKind::Zext, _, width) => *width = 4,
                Expr::Const(_, width) => *width = 4,
                _ => {}
            }
        }
    }
    func.vars = vars;
}

// Registers often hold a 32-bit value zero-extended to 64 bits. When every reader only wants the
// low half, the variable can simply be a 32-bit one.
pub fn narrow(func: &mut Func) {
    let mut wanted: HashMap<Var, u8> = HashMap::new();
    let mut blocked: HashSet<Var> = HashSet::new();

    fn scan(expr: &Expr, wanted: &mut HashMap<Var, u8>, blocked: &mut HashSet<Var>) {
        match expr {
            Expr::Cast(CastKind::Trunc, inner, width) => {
                if let Expr::Var(var) = inner.as_ref() {
                    let entry = wanted.entry(*var).or_insert(0);
                    *entry = (*entry).max(*width);
                } else {
                    scan(inner, wanted, blocked);
                }
            }
            Expr::Var(var) => {
                blocked.insert(*var);
            }
            other => {
                for child in other.children() {
                    scan(child, wanted, blocked);
                }
            }
        }
    }

    let mut phi_edges: Vec<(Var, Var)> = Vec::new();
    for block in &func.blocks {
        for stmt in &block.stmts {
            match &stmt.kind {
                StmtKind::Phi { var, inputs } => {
                    phi_edges.extend(inputs.iter().map(|(_, input)| (*var, *input)));
                }
                StmtKind::Assign { value, .. } => scan(value, &mut wanted, &mut blocked),
                StmtKind::Store { addr, value, .. } => {
                    scan(addr, &mut wanted, &mut blocked);
                    scan(value, &mut wanted, &mut blocked);
                }
                StmtKind::Call { target, args, .. } => {
                    scan(target, &mut wanted, &mut blocked);
                    for arg in args {
                        scan(arg, &mut wanted, &mut blocked);
                    }
                }
                StmtKind::Opaque { uses, .. } => {
                    for used in uses {
                        scan(used, &mut wanted, &mut blocked);
                    }
                }
            }
        }
        for expr in block.term.exprs() {
            if matches!(block.term, Term::Return(_))
                && let Expr::Var(var) = expr
            {
                let entry = wanted.entry(*var).or_insert(0);
                *entry = (*entry).max(4);
                continue;
            }
            scan(expr, &mut wanted, &mut blocked);
        }
    }

    // Which definitions already produce a value that fits in the narrow width.
    let mut fits: HashMap<Var, bool> = HashMap::new();
    for block in &func.blocks {
        for stmt in &block.stmts {
            match &stmt.kind {
                StmtKind::Assign { var, value } => {
                    let fit = match value {
                        Expr::Cast(CastKind::Zext, inner, _) => inner.width(&func.vars) <= 4,
                        Expr::Const(constant, _) => *constant <= 0xFFFF_FFFF,
                        Expr::Bin(BinOp::Shr, _, count, _) => {
                            matches!(count.as_ref(), Expr::Const(count, _) if *count >= 32)
                        }
                        _ => false,
                    };
                    fits.insert(*var, fit);
                }
                StmtKind::Call { ret: Some(var), .. } => {
                    fits.insert(*var, true);
                }
                StmtKind::Phi { var, .. } => {
                    fits.insert(*var, true);
                }
                _ => {}
            }
        }
    }

    let is_candidate = |var: Var, info: &[VarInfo]| {
        let var_info = info[var.0 as usize];
        var_info.width == 8 && !var_info.float
    };
    let mut narrow: HashSet<Var> = func
        .vars
        .iter()
        .enumerate()
        .map(|(index, _)| Var(index as u32))
        .filter(|var| {
            is_candidate(*var, &func.vars)
                && !blocked.contains(var)
                && wanted.get(var).is_some_and(|width| *width <= 4)
                && (func.vars[var.0 as usize].origin == Origin::Entry
                    || fits.get(var).copied().unwrap_or(false))
        })
        .collect();
    // Phi webs narrow together or not at all.
    let mut phi_vars: HashSet<Var> = phi_edges.iter().map(|(var, _)| *var).collect();
    phi_vars.extend(phi_edges.iter().map(|(_, input)| *input));
    for var in &phi_vars {
        let info = func.vars[var.0 as usize];
        if info.width == 8
            && !info.float
            && !blocked.contains(var)
            && (info.origin == Origin::Entry || fits.get(var).copied().unwrap_or(false))
        {
            narrow.insert(*var);
        }
    }
    loop {
        let before = narrow.len();
        for (a, b) in &phi_edges {
            if !narrow.contains(a) || !narrow.contains(b) {
                narrow.remove(a);
                narrow.remove(b);
            }
        }
        if narrow.len() == before {
            break;
        }
    }
    if narrow.is_empty() {
        return;
    }

    for var in &narrow {
        func.vars[var.0 as usize].width = 4;
    }
    let vars = std::mem::take(&mut func.vars);
    for block in &mut func.blocks {
        for stmt in &mut block.stmts {
            if let StmtKind::Assign { var, value } = &mut stmt.kind
                && narrow.contains(var)
            {
                match value {
                    Expr::Cast(CastKind::Zext, inner, _) => {
                        let inner = (**inner).clone();
                        *value = if inner.width(&vars) == 4 {
                            inner
                        } else {
                            Expr::cast(CastKind::Zext, inner, 4)
                        };
                    }
                    Expr::Const(constant, _) => *value = Expr::Const(*constant, 4),
                    Expr::Bin(BinOp::Shr, ..) => {
                        *value = Expr::cast(CastKind::Trunc, value.clone(), 4);
                    }
                    _ => {}
                }
            }
            map_uses(stmt, &mut |expr| simplify(expr, &vars));
        }
        for expr in block.term.exprs_mut() {
            simplify(expr, &vars);
        }
    }
    func.vars = vars;
}

fn split_edge(func: &mut Func, from: usize, to: usize) -> usize {
    let new = func.blocks.len();
    let va = func.blocks[to].va;
    func.blocks.push(Block {
        va,
        stmts: Vec::new(),
        term: Term::Jump(to),
        term_va: va,
        preds: Vec::new(),
    });
    func.blocks[from].term.replace_target(to, new);
    new
}

// Turns phis into plain copies on the incoming edges. Copies run as one parallel step, so a swap
// needs a temporary.
pub fn leave_ssa(func: &mut Func) {
    let mut edges: BTreeMap<(usize, usize), Vec<(Var, Var)>> = BTreeMap::new();
    for (index, block) in func.blocks.iter_mut().enumerate() {
        block.stmts.retain(|stmt| {
            if let StmtKind::Phi { var, inputs } = &stmt.kind {
                for (pred, input) in inputs {
                    edges
                        .entry((*pred, index))
                        .or_default()
                        .push((*var, *input));
                }
                false
            } else {
                true
            }
        });
    }

    for ((pred, block), copies) in edges {
        let many_successors = func.blocks[pred].term.successors().len() > 1;
        let target = if many_successors {
            split_edge(func, pred, block)
        } else {
            pred
        };
        let va = func.blocks[pred].term_va;
        let mut pending: Vec<(Var, Var)> =
            copies.into_iter().filter(|(to, from)| to != from).collect();
        while !pending.is_empty() {
            let ready = pending
                .iter()
                .position(|(to, _)| !pending.iter().any(|(_, from)| from == to));
            match ready {
                Some(position) => {
                    let (to, from) = pending.remove(position);
                    func.blocks[target].stmts.push(Stmt {
                        va,
                        kind: StmtKind::Assign {
                            var: to,
                            value: Expr::Var(from),
                        },
                    });
                }
                None => {
                    let (to, _) = pending[0];
                    let mut info = func.vars[to.0 as usize];
                    info.origin = Origin::Defined;
                    func.vars.push(info);
                    let temp = Var(func.vars.len() as u32 - 1);
                    func.blocks[target].stmts.push(Stmt {
                        va,
                        kind: StmtKind::Assign {
                            var: temp,
                            value: Expr::Var(to),
                        },
                    });
                    for (_, from) in &mut pending {
                        if *from == to {
                            *from = temp;
                        }
                    }
                }
            }
        }
    }
    func.compute_preds();
    coalesce(func);
}

fn find(parent: &mut [u32], var: u32) -> u32 {
    let mut root = var;
    while parent[root as usize] != root {
        root = parent[root as usize];
    }
    let mut at = var;
    while parent[at as usize] != root {
        let next = parent[at as usize];
        parent[at as usize] = root;
        at = next;
    }
    root
}

// Merges variables joined by a copy whenever their lifetimes never overlap.
fn coalesce(func: &mut Func) {
    let count = func.vars.len();
    let blocks = func.blocks.len();
    let mut live_in: Vec<HashSet<u32>> = vec![HashSet::new(); blocks];
    let mut live_out: Vec<HashSet<u32>> = vec![HashSet::new(); blocks];
    let order: Vec<usize> = func.reverse_post_order().into_iter().rev().collect();

    let transfer = |block: &Block, out: &HashSet<u32>| -> HashSet<u32> {
        let mut live = out.clone();
        for expr in block.term.exprs() {
            expr.for_each_var(&mut |var| {
                live.insert(var.0);
            });
        }
        for stmt in block.stmts.iter().rev() {
            for var in defs_of(stmt) {
                live.remove(&var.0);
            }
            for_each_use(stmt, &mut |var| {
                live.insert(var.0);
            });
        }
        live
    };

    let mut changed = true;
    while changed {
        changed = false;
        for &index in &order {
            let mut out = HashSet::new();
            for successor in func.blocks[index].term.successors() {
                out.extend(live_in[successor].iter().copied());
            }
            let incoming = transfer(&func.blocks[index], &out);
            if incoming.len() != live_in[index].len() {
                live_in[index] = incoming;
                changed = true;
            }
            live_out[index] = out;
        }
    }

    let mut adjacency: Vec<HashSet<u32>> = vec![HashSet::new(); count];
    let mut copies: Vec<(u32, u32)> = Vec::new();
    for (index, block) in func.blocks.iter().enumerate() {
        let mut live = live_out[index].clone();
        for expr in block.term.exprs() {
            expr.for_each_var(&mut |var| {
                live.insert(var.0);
            });
        }
        for stmt in block.stmts.iter().rev() {
            let copy_source = match &stmt.kind {
                StmtKind::Assign {
                    var,
                    value: Expr::Var(source),
                } => {
                    copies.push((var.0, source.0));
                    Some(source.0)
                }
                _ => None,
            };
            let defs = defs_of(stmt);
            for var in &defs {
                for &other in &live {
                    if other != var.0 && Some(other) != copy_source {
                        adjacency[var.0 as usize].insert(other);
                        adjacency[other as usize].insert(var.0);
                    }
                }
            }
            for var in &defs {
                live.remove(&var.0);
            }
            for_each_use(stmt, &mut |var| {
                live.insert(var.0);
            });
        }
    }
    // Everything live on entry exists at the same moment.
    let at_entry: Vec<u32> = live_in
        .first()
        .map_or(Vec::new(), |set| set.iter().copied().collect());
    for (position, &a) in at_entry.iter().enumerate() {
        for &b in &at_entry[position + 1..] {
            adjacency[a as usize].insert(b);
            adjacency[b as usize].insert(a);
        }
    }

    let mut parent: Vec<u32> = (0..count as u32).collect();
    for (to, from) in copies {
        let a = find(&mut parent, to);
        let b = find(&mut parent, from);
        if a == b {
            continue;
        }
        let (info_a, info_b) = (func.vars[a as usize], func.vars[b as usize]);
        let compatible = info_a.width == info_b.width && info_a.float == info_b.float;
        if !compatible || adjacency[a as usize].contains(&b) {
            continue;
        }
        // Keep whichever name means more: a parameter, then a stack slot, then anything else.
        let rank = |info: VarInfo| match (info.origin, info.base) {
            (Origin::Entry, _) => 0,
            (_, Base::Slot(_)) => 1,
            _ => 2,
        };
        let (keep, gone) = if rank(info_a) <= rank(info_b) {
            (a, b)
        } else {
            (b, a)
        };
        let merged: Vec<u32> = adjacency[gone as usize].iter().copied().collect();
        for other in merged {
            adjacency[other as usize].remove(&gone);
            adjacency[other as usize].insert(keep);
            adjacency[keep as usize].insert(other);
        }
        parent[gone as usize] = keep;
    }

    for block in &mut func.blocks {
        for stmt in &mut block.stmts {
            map_uses(stmt, &mut |expr| {
                expr.rewrite(&mut |node| {
                    if let Expr::Var(var) = node {
                        *var = Var(find(&mut parent, var.0));
                    }
                });
            });
            match &mut stmt.kind {
                StmtKind::Assign { var, .. } => *var = Var(find(&mut parent, var.0)),
                StmtKind::Call { ret, clobbers, .. } => {
                    if let Some(var) = ret {
                        *var = Var(find(&mut parent, var.0));
                    }
                    for var in clobbers {
                        *var = Var(find(&mut parent, var.0));
                    }
                }
                StmtKind::Opaque { defs, .. } => {
                    for var in defs {
                        *var = Var(find(&mut parent, var.0));
                    }
                }
                _ => {}
            }
        }
        for expr in block.term.exprs_mut() {
            expr.rewrite(&mut |node| {
                if let Expr::Var(var) = node {
                    *var = Var(find(&mut parent, var.0));
                }
            });
        }
        block.stmts.retain(|stmt| {
            !matches!(&stmt.kind, StmtKind::Assign { var, value: Expr::Var(source) } if var == source)
        });
    }
}

// The argument list in declaration order, read from which entry values the code still uses.
pub fn parameters(func: &Func) -> Vec<(Var, Base)> {
    let mut used: HashSet<Var> = HashSet::new();
    for block in &func.blocks {
        for stmt in &block.stmts {
            for_each_use(stmt, &mut |var| {
                used.insert(var);
            });
        }
        for expr in block.term.exprs() {
            expr.for_each_var(&mut |var| {
                used.insert(var);
            });
        }
    }

    let entries: HashMap<Base, Var> = used
        .iter()
        .filter(|var| func.vars[var.0 as usize].origin == Origin::Entry)
        .map(|var| (func.vars[var.0 as usize].base, *var))
        .collect();

    let mut params: Vec<(Option<Var>, Base)> = arg_registers(func.bits, func.win64)
        .iter()
        .map(|&register: &Register| {
            let base = Base::Reg(register);
            (entries.get(&base).copied(), base)
        })
        .collect();

    let first = first_stack_arg(func.bits, func.win64);
    let ptr = i64::from(func.bits / 8);
    let last_slot = entries
        .keys()
        .filter_map(|base| match base {
            Base::Slot(offset) if *offset >= first => Some(*offset),
            _ => None,
        })
        .max();
    if let Some(last) = last_slot {
        let mut offset = first;
        while offset <= last {
            let base = Base::Slot(offset);
            params.push((entries.get(&base).copied(), base));
            offset += ptr;
        }
    }

    let count = params
        .iter()
        .rposition(|(var, _)| var.is_some())
        .map_or(0, |at| at + 1);
    params.truncate(count);

    params
        .into_iter()
        .map(|(var, base)| (var.unwrap_or(Var(u32::MAX)), base))
        .collect()
}

// Immediate post-dominators, with `blocks.len()` standing in for "the routine has ended".
pub fn reverse_dominators(func: &Func) -> Vec<usize> {
    let count = func.blocks.len();
    let exit = count;
    let mut successors: Vec<Vec<usize>> = vec![Vec::new(); count + 1];
    let mut reverse_preds: Vec<Vec<usize>> = vec![Vec::new(); count + 1];
    for (index, block) in func.blocks.iter().enumerate() {
        let next = block.term.successors();
        if next.is_empty() {
            successors[exit].push(index);
            reverse_preds[index].push(exit);
        }
        for successor in next {
            successors[successor].push(index);
            reverse_preds[index].push(successor);
        }
    }

    let mut seen = vec![false; count + 1];
    let mut order = Vec::with_capacity(count + 1);
    let mut stack = vec![(exit, 0usize)];
    seen[exit] = true;
    while let Some((block, position)) = stack.pop() {
        if let Some(&next) = successors[block].get(position) {
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

    let mut idom = dominators(&reverse_preds, &order, exit);
    idom.truncate(count);
    idom
}

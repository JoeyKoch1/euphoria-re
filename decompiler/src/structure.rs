use std::collections::{BTreeMap, BTreeSet};

use crate::ir::{Expr, Func, Stmt, StmtKind, Term};
use crate::ssa::{drop_unreachable, reverse_dominators};

const NO_BLOCK: usize = usize::MAX;

#[derive(Clone, Debug)]
pub enum Node {
    Stmts(Vec<Stmt>),
    If {
        cond: Expr,
        then: Vec<Node>,
        other: Vec<Node>,
        va: u64,
    },
    Loop {
        body: Vec<Node>,
        va: u64,
    },
    While {
        cond: Expr,
        body: Vec<Node>,
        va: u64,
    },
    DoWhile {
        body: Vec<Node>,
        cond: Expr,
        va: u64,
    },
    For {
        init: Box<Stmt>,
        cond: Expr,
        step: Box<Stmt>,
        body: Vec<Node>,
        va: u64,
    },
    Switch {
        value: Expr,
        cases: Vec<(Vec<u64>, Vec<Node>)>,
        va: u64,
    },
    Return(Option<Expr>, u64),
    Break,
    Continue,
    Goto(usize),
    Label(usize),
}

fn forward_empty_blocks(func: &mut Func) {
    for index in 1..func.blocks.len() {
        let target = match &func.blocks[index].term {
            Term::Jump(to) if func.blocks[index].stmts.is_empty() && *to != index => *to,
            _ => continue,
        };
        for block in &mut func.blocks {
            block.term.replace_target(index, target);
        }
    }
    func.compute_preds();
}

// Two conditional blocks in a row that share an exit are one && or || condition.
fn merge_conditions(func: &mut Func) {
    let mut changed = true;
    while changed {
        changed = false;
        for first in 0..func.blocks.len() {
            let Term::Branch {
                cond,
                taken,
                not_taken,
            } = func.blocks[first].term.clone()
            else {
                continue;
            };
            for (second, second_is_taken) in [(taken, true), (not_taken, false)] {
                if second == first
                    || !func.blocks[second].stmts.is_empty()
                    || func.blocks[second].preds.len() != 1
                {
                    continue;
                }
                let Term::Branch {
                    cond: inner,
                    taken: inner_taken,
                    not_taken: inner_not_taken,
                } = func.blocks[second].term.clone()
                else {
                    continue;
                };
                let shared = if second_is_taken { not_taken } else { taken };
                let both = |a: Expr, b: Expr| Expr::Both(Box::new(a), Box::new(b));
                let either = |a: Expr, b: Expr| Expr::Either(Box::new(a), Box::new(b));

                let merged = if second_is_taken {
                    if inner_not_taken == shared {
                        Some((both(cond.clone(), inner), inner_taken, shared))
                    } else if inner_taken == shared {
                        Some((both(cond.clone(), inner.negated()), inner_not_taken, shared))
                    } else {
                        None
                    }
                } else if inner_taken == shared {
                    Some((either(cond.clone(), inner), shared, inner_not_taken))
                } else if inner_not_taken == shared {
                    Some((either(cond.clone(), inner.negated()), shared, inner_taken))
                } else {
                    None
                };
                if let Some((cond, taken, not_taken)) = merged {
                    func.blocks[first].term = Term::Branch {
                        cond,
                        taken,
                        not_taken,
                    };
                    func.compute_preds();
                    changed = true;
                    break;
                }
            }
            if changed {
                break;
            }
        }
    }
}

struct Loop {
    body: BTreeSet<usize>,
}

struct Builder<'a> {
    func: &'a Func,
    ipdom: Vec<usize>,
    loops: BTreeMap<usize, Loop>,
    emitted: Vec<bool>,
    labeled: BTreeSet<usize>,
}

#[derive(Clone, Default)]
struct Ctx {
    header: Option<usize>,
    exit: Option<usize>,
    in_switch: bool,
    enclosing: Vec<usize>,
    body: Option<BTreeSet<usize>>,
}

impl Ctx {
    fn with_stop(&self, stop: Option<usize>) -> Self {
        let mut next = self.clone();
        next.enclosing.extend(stop);
        next
    }
}

impl Builder<'_> {
    fn join(&self, block: usize, ctx: &Ctx) -> Option<usize> {
        let join = *self.ipdom.get(block)?;
        if join >= self.func.blocks.len() {
            return None;
        }
        match &ctx.body {
            Some(body) if !body.contains(&join) => None,
            _ => Some(join),
        }
    }

    fn jump_node(&mut self, block: usize, ctx: &Ctx) -> Option<Node> {
        if ctx.header == Some(block) {
            return Some(Node::Continue);
        }
        if ctx.exit == Some(block) {
            if ctx.in_switch {
                self.labeled.insert(block);
                return Some(Node::Goto(block));
            }
            return Some(Node::Break);
        }
        if ctx.enclosing.contains(&block) {
            self.labeled.insert(block);
            return Some(Node::Goto(block));
        }
        None
    }

    fn sequence(&mut self, start: usize, stop: Option<usize>, ctx: &Ctx) -> Vec<Node> {
        let mut out = Vec::new();
        let mut block = start;
        loop {
            if Some(block) == stop {
                break;
            }
            if let Some(node) = self.jump_node(block, ctx) {
                out.push(node);
                break;
            }
            if self.emitted[block] {
                self.labeled.insert(block);
                out.push(Node::Goto(block));
                break;
            }
            out.push(Node::Label(block));

            if self.loops.contains_key(&block) {
                let exit = self.loop_exit(block);
                let mut inner = ctx.clone();
                inner.enclosing.extend(stop);
                inner.enclosing.extend(ctx.header);
                inner.enclosing.extend(ctx.exit);
                inner.header = Some(block);
                inner.exit = exit;
                inner.in_switch = false;
                inner.body = self.loops.get(&block).map(|found| found.body.clone());
                let body = self.body(block, None, &inner);
                out.push(Node::Loop {
                    body,
                    va: self.func.blocks[block].va,
                });
                match exit {
                    Some(next) => {
                        block = next;
                        continue;
                    }
                    None => break,
                }
            }

            let (nodes, next) = self.block(block, stop, ctx);
            out.extend(nodes);
            match next {
                Some(next) => block = next,
                None => break,
            }
        }
        out
    }

    fn body(&mut self, block: usize, stop: Option<usize>, ctx: &Ctx) -> Vec<Node> {
        let (mut out, next) = self.block(block, stop, ctx);
        if let Some(next) = next {
            out.extend(self.sequence(next, stop, ctx));
        }
        out
    }

    fn block(
        &mut self,
        block: usize,
        stop: Option<usize>,
        ctx: &Ctx,
    ) -> (Vec<Node>, Option<usize>) {
        self.emitted[block] = true;
        let source = &self.func.blocks[block];
        let va = source.term_va;
        let mut out = Vec::new();
        if !source.stmts.is_empty() {
            out.push(Node::Stmts(source.stmts.clone()));
        }

        let next = match source.term.clone() {
            Term::Jump(to) => Some(to),
            Term::Return(value) => {
                out.push(Node::Return(value, va));
                None
            }
            Term::Stop(_) => None,
            Term::Branch {
                cond,
                taken,
                not_taken,
            } => {
                let join = self.join(block, ctx);
                let arm_stop = join.or(stop);
                let arm_ctx = match (join, stop) {
                    (Some(join), Some(stop)) if join != stop => ctx.with_stop(Some(stop)),
                    _ => ctx.clone(),
                };
                let then = self.sequence(taken, arm_stop, &arm_ctx);
                let other = self.sequence(not_taken, arm_stop, &arm_ctx);
                out.push(Node::If {
                    cond,
                    then,
                    other,
                    va,
                });
                join
            }
            Term::Switch { value, cases } => {
                let join = self.join(block, ctx);
                let arm_stop = join.or(stop);
                let mut arm_ctx = match (join, stop) {
                    (Some(join), Some(stop)) if join != stop => ctx.with_stop(Some(stop)),
                    _ => ctx.clone(),
                };
                arm_ctx.in_switch = true;

                let mut groups: BTreeMap<usize, Vec<u64>> = BTreeMap::new();
                for (case, target) in cases {
                    groups.entry(target).or_default().push(case);
                }
                let mut rendered = Vec::new();
                for (target, values) in groups {
                    rendered.push((values, self.sequence(target, arm_stop, &arm_ctx)));
                }
                rendered.sort_by_key(|(values, _)| values[0]);
                out.push(Node::Switch {
                    value,
                    cases: rendered,
                    va,
                });
                join
            }
        };
        (out, next)
    }

    fn loop_exit(&self, header: usize) -> Option<usize> {
        let body = &self.loops[&header].body;
        let mut exits = BTreeSet::new();
        for &member in body {
            for successor in self.func.blocks[member].term.successors() {
                if !body.contains(&successor) {
                    exits.insert(successor);
                }
            }
        }
        let join = self.ipdom[header];
        if exits.contains(&join) {
            return Some(join);
        }
        // Among several exits, prefer the one that continues the routine over one that returns.
        exits.iter().copied().max_by_key(|&exit| {
            let keeps_going = !self.func.blocks[exit].term.successors().is_empty();
            (keeps_going, self.func.blocks[exit].preds.len())
        })
    }
}

fn ends_in_jump(nodes: &[Node]) -> bool {
    match nodes
        .iter()
        .rev()
        .find(|node| !matches!(node, Node::Label(_)))
    {
        Some(Node::Return(..) | Node::Break | Node::Continue | Node::Goto(_)) => true,
        Some(Node::If { then, other, .. }) => ends_in_jump(then) && ends_in_jump(other),
        _ => false,
    }
}

fn contains_continue(nodes: &[Node]) -> bool {
    nodes.iter().any(|node| match node {
        Node::Continue => true,
        Node::If { then, other, .. } => contains_continue(then) || contains_continue(other),
        Node::Switch { cases, .. } => cases.iter().any(|(_, body)| contains_continue(body)),
        _ => false,
    })
}

fn tidy(nodes: Vec<Node>, labeled: &BTreeSet<usize>) -> Vec<Node> {
    let mut out: Vec<Node> = Vec::with_capacity(nodes.len());
    for node in nodes {
        match node {
            Node::Label(block) if !labeled.contains(&block) => {}
            Node::Stmts(stmts) => match out.last_mut() {
                Some(Node::Stmts(previous)) => previous.extend(stmts),
                _ => out.push(Node::Stmts(stmts)),
            },
            Node::If {
                cond,
                then,
                other,
                va,
            } => tidy_if(cond, then, other, va, labeled, &mut out),
            Node::Loop { body, va } => {
                let body = tidy(body, labeled);
                push_loop(body, va, labeled, &mut out);
            }
            Node::Switch { value, cases, va } => out.push(Node::Switch {
                value,
                cases: cases
                    .into_iter()
                    .map(|(values, body)| (values, tidy(body, labeled)))
                    .collect(),
                va,
            }),
            other => out.push(other),
        }
    }
    out
}

fn tidy_if(
    cond: Expr,
    then: Vec<Node>,
    other: Vec<Node>,
    va: u64,
    labeled: &BTreeSet<usize>,
    out: &mut Vec<Node>,
) {
    let mut then = tidy(then, labeled);
    let mut other = tidy(other, labeled);
    let mut cond = cond;

    if then.is_empty() && other.is_empty() {
        return;
    }
    // The shorter way out goes first, so the main path keeps reading downward.
    let other_is_shorter =
        ends_in_jump(&other) && (!ends_in_jump(&then) || other.len() < then.len());
    if then.is_empty() || other_is_shorter {
        std::mem::swap(&mut then, &mut other);
        cond = cond.negated();
    }

    // Nothing after a jump can run, so what would be the else branch moves up a level.
    if ends_in_jump(&then) && !other.is_empty() {
        out.push(Node::If {
            cond,
            then,
            other: Vec::new(),
            va,
        });
        out.extend(other);
        return;
    }

    if other.is_empty()
        && then.len() == 1
        && matches!(&then[0], Node::If { other, .. } if other.is_empty())
        && let Some(Node::If {
            cond: inner,
            then: inner_then,
            ..
        }) = then.pop()
    {
        out.push(Node::If {
            cond: Expr::Both(Box::new(cond), Box::new(inner)),
            then: inner_then,
            other: Vec::new(),
            va,
        });
        return;
    }

    out.push(Node::If {
        cond,
        then,
        other,
        va,
    });
}

fn is_lone(nodes: &[Node], want: fn(&Node) -> bool) -> bool {
    nodes.len() == 1 && want(&nodes[0])
}

fn push_loop(mut body: Vec<Node>, va: u64, labeled: &BTreeSet<usize>, out: &mut Vec<Node>) {
    if matches!(body.last(), Some(Node::Continue)) {
        body.pop();
    }

    // if (c) break; at the top is a while loop.
    if let Some(Node::If { then, other, .. }) = body.first()
        && other.is_empty()
        && is_lone(then, |node| matches!(node, Node::Break))
        && !contains_labels(&body, labeled)
        && let Node::If { cond, .. } = body.remove(0)
    {
        push_while(cond.negated(), body, va, out);
        return;
    }

    // if (c) break; at the bottom is a do-while loop, unless a continue would skip its test.
    if let Some(Node::If { then, other, .. }) = body.last()
        && other.is_empty()
        && is_lone(then, |node| matches!(node, Node::Break))
        && !contains_continue(&body)
        && !contains_labels(&body, labeled)
        && let Some(Node::If { cond, .. }) = body.pop()
    {
        out.push(Node::DoWhile {
            body,
            cond: cond.negated(),
            va,
        });
        return;
    }
    // if (c) continue; break; at the bottom is a do-while loop too.
    if matches!(body.last(), Some(Node::Break)) && body.len() >= 2 {
        let test = body.len() - 2;
        let is_test = matches!(&body[test], Node::If { then, other, .. }
            if other.is_empty() && is_lone(then, |node| matches!(node, Node::Continue)));
        if is_test && !contains_continue(&body[..test]) && !contains_labels(&body, labeled) {
            body.pop();
            if let Some(Node::If { cond, .. }) = body.pop() {
                out.push(Node::DoWhile { body, cond, va });
                return;
            }
        }
    }

    out.push(Node::Loop { body, va });
}

fn contains_labels(nodes: &[Node], labeled: &BTreeSet<usize>) -> bool {
    nodes.iter().any(|node| match node {
        Node::Label(block) => labeled.contains(block),
        _ => false,
    })
}

fn push_while(cond: Expr, mut body: Vec<Node>, va: u64, out: &mut Vec<Node>) {
    // A while with a counter set just before it and stepped at its end reads better as a for.
    let counter = match body.last() {
        Some(Node::Stmts(stmts)) => stmts.last().and_then(|stmt| match &stmt.kind {
            StmtKind::Assign { var, value } if mentions(value, *var) && mentions(&cond, *var) => {
                Some(*var)
            }
            _ => None,
        }),
        _ => None,
    };
    let init_matches = counter.is_some_and(|var| {
        matches!(out.last(), Some(Node::Stmts(stmts))
            if matches!(stmts.last().map(|stmt| &stmt.kind),
                Some(StmtKind::Assign { var: first, .. }) if *first == var))
    });

    if init_matches && !contains_continue(&body) {
        let step = match body.last_mut() {
            Some(Node::Stmts(stmts)) => stmts.pop(),
            _ => None,
        };
        if matches!(body.last(), Some(Node::Stmts(stmts)) if stmts.is_empty()) {
            body.pop();
        }
        let init = match out.last_mut() {
            Some(Node::Stmts(stmts)) => stmts.pop(),
            _ => None,
        };
        if matches!(out.last(), Some(Node::Stmts(stmts)) if stmts.is_empty()) {
            out.pop();
        }
        if let (Some(init), Some(step)) = (init, step) {
            out.push(Node::For {
                init: Box::new(init),
                cond,
                step: Box::new(step),
                body,
                va,
            });
            return;
        }
    }
    out.push(Node::While { cond, body, va });
}

fn mentions(expr: &Expr, target: crate::ir::Var) -> bool {
    let mut found = false;
    expr.for_each_var(&mut |var| found |= var == target);
    found
}

pub fn build(func: &mut Func) -> (Vec<Node>, BTreeSet<usize>) {
    forward_empty_blocks(func);
    drop_unreachable(func);
    merge_conditions(func);
    drop_unreachable(func);

    let order = func.reverse_post_order();
    let preds: Vec<Vec<usize>> = func
        .blocks
        .iter()
        .map(|block| block.preds.clone())
        .collect();
    let idom = crate::ssa::dominators(&preds, &order, 0);
    let ipdom = reverse_dominators(func);

    let dominated_by = |mut block: usize, header: usize| loop {
        if block == header {
            return true;
        }
        if block == 0 || idom[block] == NO_BLOCK {
            return false;
        }
        block = idom[block];
    };

    let mut loops: BTreeMap<usize, Loop> = BTreeMap::new();
    for (block, source) in func.blocks.iter().enumerate() {
        for header in source.term.successors() {
            if !dominated_by(block, header) {
                continue;
            }
            let entry = loops.entry(header).or_insert_with(|| Loop {
                body: BTreeSet::from([header]),
            });
            let mut work = vec![block];
            while let Some(member) = work.pop() {
                if entry.body.insert(member) {
                    work.extend(func.blocks[member].preds.iter().copied());
                }
            }
        }
    }

    let mut builder = Builder {
        func,
        ipdom,
        loops,
        emitted: vec![false; func.blocks.len()],
        labeled: BTreeSet::new(),
    };
    let nodes = builder.sequence(0, None, &Ctx::default());
    let labeled = builder.labeled;
    (tidy(nodes, &labeled), labeled)
}

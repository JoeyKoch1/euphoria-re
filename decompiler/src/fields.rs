use std::collections::BTreeMap;

use iced_x86::Register;

use crate::ir::{Base, BinOp, Expr, Func, StmtKind, VarInfo, sign_extend};

// One place a routine reads or writes through a base pointer, grouped by base and offset.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FieldAccess {
    pub base: String,
    pub offset: i64,
    pub width: u8,
    pub float: bool,
    pub reads: usize,
    pub writes: usize,
}

impl FieldAccess {
    pub fn count(&self) -> usize {
        self.reads + self.writes
    }

    pub fn type_name(&self) -> &'static str {
        if self.float {
            match self.width {
                4 => "float",
                16 | 32 => "vector",
                _ => "double",
            }
        } else {
            match self.width {
                1 => "byte",
                2 => "word",
                4 => "dword",
                16 => "xmmword",
                32 => "ymmword",
                _ => "qword",
            }
        }
    }
}

pub fn collect(func: &Func) -> Vec<FieldAccess> {
    let mut fields: BTreeMap<(String, i64, u8, bool), (usize, usize)> = BTreeMap::new();
    let mut note = |addr: &Expr, width: u8, float: bool, write: bool| {
        let Some((base, offset)) = decompose(addr, &func.vars) else {
            return;
        };
        let entry = fields.entry((base, offset, width, float)).or_default();
        if write {
            entry.1 += 1;
        } else {
            entry.0 += 1;
        }
    };

    for block in &func.blocks {
        for stmt in &block.stmts {
            match &stmt.kind {
                StmtKind::Assign { value, .. } => scan(value, &mut note),
                StmtKind::Store {
                    addr,
                    value,
                    width,
                    float,
                } => {
                    note(addr, *width, *float, true);
                    scan(value, &mut note);
                }
                StmtKind::Call { target, args, .. } => {
                    scan(target, &mut note);
                    for arg in args {
                        scan(arg, &mut note);
                    }
                }
                StmtKind::Opaque { uses, .. } => {
                    for expr in uses {
                        scan(expr, &mut note);
                    }
                }
                StmtKind::Phi { .. } => {}
            }
        }
        for expr in block.term.exprs() {
            scan(expr, &mut note);
        }
    }

    fields
        .into_iter()
        .map(
            |((base, offset, width, float), (reads, writes))| FieldAccess {
                base,
                offset,
                width,
                float,
                reads,
                writes,
            },
        )
        .collect()
}

fn scan(expr: &Expr, note: &mut impl FnMut(&Expr, u8, bool, bool)) {
    match expr {
        Expr::Load { addr, width, float } => {
            note(addr, *width, *float, false);
            scan(addr, note);
        }
        other => {
            for child in other.children() {
                scan(child, note);
            }
        }
    }
}

// Splits `base + constant` address forms, ignoring index scaling and plain stack slots, which are
// locals rather than fields of a structure.
fn decompose(addr: &Expr, vars: &[VarInfo]) -> Option<(String, i64)> {
    match addr {
        Expr::Cast(_, inner, _) => decompose(inner, vars),
        Expr::Bin(BinOp::Add, a, b, width) => match (a.as_ref(), b.as_ref()) {
            (base, Expr::Const(value, _)) => {
                let (base, offset) = decompose(base, vars)?;
                Some((base, offset + sign_extend(*value, *width)))
            }
            (Expr::Const(value, _), base) => {
                let (base, offset) = decompose(base, vars)?;
                Some((base, offset + sign_extend(*value, *width)))
            }
            _ => None,
        },
        Expr::Bin(BinOp::Sub, a, b, width) => {
            let Expr::Const(value, _) = b.as_ref() else {
                return None;
            };
            let (base, offset) = decompose(a, vars)?;
            Some((base, offset - sign_extend(*value, *width)))
        }
        Expr::Var(var) => base_name(vars[var.0 as usize].base),
        Expr::Const(value, _) if *value != 0 => Some((format!("g_{value:x}"), 0)),
        _ => None,
    }
}

fn base_name(base: Base) -> Option<(String, i64)> {
    match base {
        Base::Reg(register) if !matches!(register, Register::RSP | Register::RBP) => {
            Some((format!("{register:?}").to_lowercase(), 0))
        }
        Base::Slot(offset) if offset < 0 => Some((format!("var_{:x}", -offset), 0)),
        Base::Slot(offset) => Some((format!("arg_{offset:x}"), 0)),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::{Block, Origin, Stmt, Term, Var, VarInfo};

    fn var(base: Base, width: u8, float: bool) -> VarInfo {
        VarInfo {
            base,
            width,
            float,
            origin: Origin::Entry,
        }
    }

    fn address(var: Var, offset: u64) -> Expr {
        Expr::bin(BinOp::Add, Expr::Var(var), Expr::Const(offset, 8), 8)
    }

    fn load(addr: Expr, width: u8, float: bool) -> Expr {
        Expr::load(addr, width, float)
    }

    fn stmt(kind: StmtKind) -> Stmt {
        Stmt { va: 0x1000, kind }
    }

    fn func(vars: Vec<VarInfo>, stmts: Vec<Stmt>) -> Func {
        Func {
            va: 0x1000,
            bits: 64,
            win64: true,
            blocks: vec![Block {
                va: 0x1000,
                stmts,
                term: Term::Return(None),
                term_va: 0x1010,
                preds: Vec::new(),
            }],
            vars,
        }
    }

    #[test]
    fn groups_pointer_fields_by_base_offset_and_width() {
        let vars = vec![
            var(Base::Reg(Register::RCX), 8, false),
            var(Base::Reg(Register::RDX), 8, false),
            var(Base::Reg(Register::RAX), 4, false),
            var(Base::Slot(-8), 8, false),
            var(Base::Reg(Register::RSP), 8, false),
        ];
        let stmts = vec![
            stmt(StmtKind::Assign {
                var: Var(2),
                value: load(address(Var(0), 0x10), 4, false),
            }),
            stmt(StmtKind::Store {
                addr: address(Var(0), 0x10),
                value: Expr::Const(1, 4),
                width: 4,
                float: false,
            }),
            stmt(StmtKind::Assign {
                var: Var(2),
                value: load(address(Var(1), 8), 8, false),
            }),
            stmt(StmtKind::Assign {
                var: Var(2),
                value: load(Expr::StackAddr(-8), 4, false),
            }),
            stmt(StmtKind::Assign {
                var: Var(2),
                value: load(address(Var(4), 0x20), 8, false),
            }),
            stmt(StmtKind::Assign {
                var: Var(2),
                value: load(Expr::Const(0x1_4003_0000, 8), 4, false),
            }),
            stmt(StmtKind::Assign {
                var: Var(2),
                value: load(
                    Expr::bin(BinOp::Sub, Expr::Var(Var(1)), Expr::Const(8, 8), 8),
                    4,
                    false,
                ),
            }),
        ];

        let fields = collect(&func(vars, stmts));
        let summary: Vec<(String, i64, u8, usize, usize)> = fields
            .iter()
            .map(|field| {
                (
                    field.base.clone(),
                    field.offset,
                    field.width,
                    field.reads,
                    field.writes,
                )
            })
            .collect();

        assert_eq!(
            summary,
            [
                ("g_140030000".to_owned(), 0, 4, 1, 0),
                ("rcx".to_owned(), 0x10, 4, 1, 1),
                ("rdx".to_owned(), -8, 4, 1, 0),
                ("rdx".to_owned(), 8, 8, 1, 0),
            ]
        );
    }

    #[test]
    fn counts_float_accesses_and_names_types() {
        let vars = vec![
            var(Base::Reg(Register::RCX), 8, false),
            var(Base::Reg(Register::XMM0), 8, true),
        ];
        let stmts = vec![
            stmt(StmtKind::Assign {
                var: Var(1),
                value: load(address(Var(0), 0x18), 8, true),
            }),
            stmt(StmtKind::Assign {
                var: Var(1),
                value: load(address(Var(0), 0x18), 8, true),
            }),
        ];

        let fields = collect(&func(vars, stmts));
        assert_eq!(fields.len(), 1);
        assert_eq!(fields[0].base, "rcx");
        assert_eq!(fields[0].offset, 0x18);
        assert_eq!(fields[0].reads, 2);
        assert_eq!(fields[0].writes, 0);
        assert_eq!(fields[0].count(), 2);
        assert_eq!(fields[0].type_name(), "double");
    }
}

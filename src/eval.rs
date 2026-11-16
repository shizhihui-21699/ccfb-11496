//! Condition evaluation over the per-pattern match tables.
//!
//! YARA integer operations can be "undefined" (out-of-range @a[i], division by
//! zero, unknown identifiers). Undefined propagates through arithmetic and
//! makes comparisons false; boolean logic follows YARA's three-valued rules.

use crate::ast::*;
use crate::scanner::Match;

pub struct Eval<'a> {
    rule: &'a Rule,
    matches: &'a [Vec<Match>], // indexed by pattern ordinal
    filesize: i64,
    loop_var: Option<(String, i64)>,
    /// Results of other (already evaluated) rules, keyed by rule name. Used
    /// for cross-rule references such as `condition: some_other_rule`.
    rule_results: &'a std::collections::HashMap<String, bool>,
}

impl<'a> Eval<'a> {
    pub fn new(
        rule: &'a Rule,
        matches: &'a [Vec<Match>],
        filesize: i64,
        rule_results: &'a std::collections::HashMap<String, bool>,
    ) -> Self {
        Eval { rule, matches, filesize, loop_var: None, rule_results }
    }

    fn pat_index(&self, name: &str) -> Option<usize> {
        self.rule.patterns.iter().position(|p| p.id == name)
    }

    fn match_list(&self, name: &str) -> Option<&Vec<Match>> {
        self.pat_index(name).map(|i| &self.matches[i])
    }

    // ---- integer expressions: None means undefined ----------------------

    fn eval_int(&self, e: &IntExpr) -> Option<i64> {
        match e {
            IntExpr::Const(v) => Some(*v),
            IntExpr::Filesize => Some(self.filesize),
            IntExpr::Var(name) => self.loop_var.iter().find(|(n, _)| n == name).map(|(_, v)| *v),
            IntExpr::Count(name) => Some(self.match_list(name).map(|m| m.len() as i64).unwrap_or(0)),
            IntExpr::Offset(name, idx) => {
                let list = self.match_list(name)?;
                let i = match idx {
                    None => 1,
                    Some(expr) => self.eval_int(expr)?,
                };
                if i < 1 {
                    return None;
                }
                list.get(i as usize - 1).map(|m| m.offset as i64)
            }
            IntExpr::Length(name, idx) => {
                let list = self.match_list(name)?;
                let i = match idx {
                    None => 1,
                    Some(expr) => self.eval_int(expr)?,
                };
                if i < 1 {
                    return None;
                }
                list.get(i as usize - 1).map(|m| m.length as i64)
            }
            IntExpr::Neg(x) => self.eval_int(x).and_then(|v| v.checked_neg()),
            IntExpr::Not(x) => self.eval_int(x).map(|v| !v),
            IntExpr::Bin(l, op, r) => {
                let (a, b) = (self.eval_int(l)?, self.eval_int(r)?);
                Some(match op {
                    ArithOp::Add => a.checked_add(b)?,
                    ArithOp::Sub => a.checked_sub(b)?,
                    ArithOp::Mul => a.checked_mul(b)?,
                    ArithOp::Mod => {
                        if b == 0 {
                            return None;
                        }
                        a.checked_rem(b)?
                    }
                    ArithOp::And => a & b,
                    ArithOp::Or => a | b,
                    ArithOp::Xor => a ^ b,
                    ArithOp::Shl => {
                        if !(0..64).contains(&b) {
                            return None;
                        }
                        a.wrapping_shl(b as u32)
                    }
                    ArithOp::Shr => {
                        if !(0..64).contains(&b) {
                            return None;
                        }
                        a.wrapping_shr(b as u32)
                    }
                })
            }
        }
    }

    // ---- boolean conditions ---------------------------------------------

    pub fn eval(&mut self, c: &Condition) -> bool {
        self.eval_tri(c).unwrap_or(false)
    }

    /// Three-valued result: Some(true)/Some(false)/None(undefined).
    fn eval_tri(&self, c: &Condition) -> Option<bool> {
        match c {
            Condition::Bool(b) => Some(*b),
            Condition::IntLeaf(e) => self.eval_int(e).map(|v| v != 0),
            Condition::BoolId(name) => {
                if let Some((_, v)) = self.loop_var.iter().find(|(n, _)| n == name) {
                    Some(*v != 0)
                } else {
                    self.rule_results.get(name).copied()
                }
            }
            Condition::PatternDefined(name) => {
                Some(self.match_list(name).map(|m| !m.is_empty()).unwrap_or(false))
            }
            Condition::Not(x) => self.eval_tri(x).map(|b| !b),
            Condition::Bin(l, op, r) => {
                let (a, b) = (self.eval_tri(l), self.eval_tri(r));
                match op {
                    // YARA: undefined AND false = false; undefined OR true = true
                    BoolOp::And => match (a, b) {
                        (Some(false), _) | (_, Some(false)) => Some(false),
                        (None, _) | (_, None) => None,
                        (Some(x), Some(y)) => Some(x && y),
                    },
                    BoolOp::Or => match (a, b) {
                        (Some(true), _) | (_, Some(true)) => Some(true),
                        (None, _) | (_, None) => None,
                        (Some(x), Some(y)) => Some(x || y),
                    },
                }
            }
            Condition::Cmp(l, op, r) => {
                let (a, b) = (self.eval_int(l)?, self.eval_int(r)?);
                Some(match op {
                    CmpOp::Eq => a == b,
                    CmpOp::Ne => a != b,
                    CmpOp::Lt => a < b,
                    CmpOp::Le => a <= b,
                    CmpOp::Gt => a > b,
                    CmpOp::Ge => a >= b,
                })
            }
            Condition::At(name, off) => {
                let off = self.eval_int(off)?;
                if off < 0 {
                    return Some(false);
                }
                Some(
                    self.match_list(name)
                        .map(|m| m.iter().any(|x| x.offset as i64 == off))
                        .unwrap_or(false),
                )
            }
            Condition::In(name, lo, hi) => {
                let lo = self.eval_int(lo)?;
                let hi = self.eval_int(hi)?;
                Some(
                    self.match_list(name)
                        .map(|m| m.iter().any(|x| (x.offset as i64) >= lo && (x.offset as i64) <= hi))
                        .unwrap_or(false),
                )
            }
            Condition::Of(quant, set) => self.eval_of(quant, set),
            Condition::For { quant, var, lo, hi, body } => self.eval_for(quant, var, lo, hi, body),
        }
    }

    fn resolve_set(&self, set: &StringSet) -> Vec<usize> {
        match set {
            StringSet::Them => (0..self.rule.patterns.len()).collect(),
            StringSet::List(ids) => ids.iter().filter_map(|n| self.pat_index(n)).collect(),
            StringSet::Wildcard(prefix) => self
                .rule
                .patterns
                .iter()
                .enumerate()
                .filter(|(_, p)| p.id.starts_with(prefix))
                .map(|(i, _)| i)
                .collect(),
        }
    }

    fn eval_of(&self, quant: &Quantifier, set: &StringSet) -> Option<bool> {
        let idxs = self.resolve_set(set);
        let defined: Vec<bool> = idxs
            .iter()
            .map(|i| !self.matches[*i].is_empty())
            .collect();
        let total = defined.len() as i64;
        let true_count = defined.iter().filter(|b| **b).count() as i64;
        Some(match quant {
            Quantifier::Any => true_count >= 1,
            Quantifier::All => true_count == total && total > 0,
            Quantifier::None => true_count == 0,
            // `N of (...)` means at least N members match.
            Quantifier::Expr(e) => {
                let n = self.eval_int(e)?;
                true_count >= n
            }
        })
    }

    fn eval_for(
        &self,
        quant: &Quantifier,
        var: &String,
        lo: &IntExpr,
        hi: &IntExpr,
        body: &Condition,
    ) -> Option<bool> {
        let lo = self.eval_int(lo)?;
        let hi = self.eval_int(hi)?;
        if lo < 0 || hi < lo {
            return Some(false);
        }
        // Cap pathological ranges; YARA itself also bounds these.
        let cap = 1_000_000i64;
        let hi = hi.min(lo + cap);
        let total = hi - lo + 1;
        let mut true_count = 0i64;
        for v in lo..=hi {
            let sub = Eval {
                rule: self.rule,
                matches: self.matches,
                filesize: self.filesize,
                loop_var: Some((var.clone(), v)),
                rule_results: self.rule_results,
            };
            if sub.eval_tri(body).unwrap_or(false) {
                true_count += 1;
            }
        }
        Some(match quant {
            Quantifier::Any => true_count >= 1,
            Quantifier::All => true_count == total,
            Quantifier::None => true_count == 0,
            // `for N i in ... : (cond)` means at least N iterations hold.
            Quantifier::Expr(e) => {
                let n = self.eval_int(e)?;
                true_count >= n
            }
        })
    }
}

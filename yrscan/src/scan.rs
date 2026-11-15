//! Per-file scanning and condition evaluation.
//!
//! Pipeline per file:
//! 1. walk the Aho-Corasick prefilter once over the raw bytes, collecting
//!    candidate (string, view) pairs;
//! 2. run full verification for candidate strings (and atomless ones);
//! 3. evaluate each rule's condition against the match table.

use crate::compile::{CompiledRule, CompiledRules, CString, CStringDef};
use crate::hexpat::{find as hex_find, AsciiView, WideView};
use crate::mmap::Mmap;
use crate::parser::{Expr, Quant, StrOp, StringSet};
use crate::regex::find as re_find;
use std::collections::HashSet;
use std::fs::File;
use std::path::Path;

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum ViewKind {
    Ascii,
    Wide,
}

/// One verified match of a string: physical file offset and physical length.
#[derive(Clone, Debug)]
pub struct SMatch {
    pub offset: usize,
    pub length: usize,
}

pub struct ScanResult {
    pub matched: Vec<String>,
}

struct StringState {
    /// matches per view, kept sorted by offset
    per_view: [Vec<SMatch>; 2],
}

impl StringState {
    fn new() -> Self {
        Self { per_view: [Vec::new(), Vec::new()] }
    }
    fn all(&self) -> Vec<&SMatch> {
        let mut v: Vec<&SMatch> = self.per_view.iter().flatten().collect();
        v.sort_by_key(|m| m.offset);
        v
    }
    fn count(&self) -> i64 {
        self.per_view.iter().map(|v| v.len() as i64).sum()
    }
}

pub fn scan_file(rules: &CompiledRules, path: &Path) -> std::io::Result<ScanResult> {
    let file = File::open(path)?;
    let meta = file.metadata()?;
    let mmap = Mmap::open(&file)?;
    let data = mmap.as_slice();
    let _ = meta;
    Ok(scan_bytes(rules, data))
}

pub fn scan_bytes(rules: &CompiledRules, data: &[u8]) -> ScanResult {
    // candidates[rule][string] = physical offsets where a prefilter atom hit,
    // keyed by view. Verification only tests starts anchored at these offsets
    // (atomless strings keep an empty set and scan the whole file).
    let mut candidates: Vec<Vec<HashSet<(usize, ViewKind)>>> =
        (0..rules.rules.len())
            .map(|ri| {
                (0..rules.rules[ri].strings.len())
                    .map(|_| HashSet::new())
                    .collect()
            })
            .collect();

    rules.aho.scan(data, |ri, si, wide, offset, _atom_len| {
        let cs = &rules.rules[ri].strings[si];
        let view = if wide { ViewKind::Wide } else { ViewKind::Ascii };
        let allow = if wide { cs.wide } else { cs.ascii };
        if allow {
            candidates[ri][si].insert((offset, view));
        }
    });

    let mut matched = Vec::new();
    for (ri, rule) in rules.rules.iter().enumerate() {
        let mut states: Vec<StringState> =
            (0..rule.strings.len()).map(|_| StringState::new()).collect();

        for si in 0..rule.strings.len() {
            let cs = &rule.strings[si];
            let mut wants = HashSet::new();
            if cs.atomless {
                if cs.ascii {
                    wants.insert(ViewKind::Ascii);
                }
                if cs.wide {
                    wants.insert(ViewKind::Wide);
                }
            } else {
                for (_off, view) in &candidates[ri][si] {
                    wants.insert(*view);
                }
            }
            for view in wants {
                let anchor_offsets: Vec<usize> = if cs.atomless {
                    Vec::new()
                } else {
                    candidates[ri][si]
                        .iter()
                        .filter(|(_, v)| *v == view)
                        .map(|(off, _)| *off)
                        .collect()
                };
                let ms = verify(cs, data, view, &anchor_offsets);
                let slot = match view {
                    ViewKind::Ascii => 0,
                    ViewKind::Wide => 1,
                };
                states[si].per_view[slot] = ms;
            }
        }

        let mut ctx = EvalCtx { data, rule, states: &states, it: None };
        if let Value::Bool(true) = ctx.eval(&rule.condition) {
            matched.push(rule.name.clone());
        }
    }

    ScanResult { matched }
}

fn verify(
    cs: &CString,
    data: &[u8],
    view: ViewKind,
    anchor_offsets: &[usize],
) -> Vec<SMatch> {
    let mut out = Vec::new();
    match view {
        ViewKind::Ascii => {
            let av = AsciiView { data };
            // ascii stride is 1: physical offset == virtual index
            let virtual_anchors = anchor_offsets.to_vec();
            collect_matches(cs, &av, false, &virtual_anchors, &mut out);
        }
        ViewKind::Wide => {
            // YARA tries wide decoding from every physical byte offset; the
            // stride is 2 so only two parities (origin 0 and 1) are distinct.
            for origin in 0..2usize {
                if origin >= data.len() {
                    continue;
                }
                let wv = WideView::new(data, origin);
                let virtual_anchors: Vec<usize> = anchor_offsets
                    .iter()
                    .filter(|o| **o >= origin && (*o - origin) % 2 == 0)
                    .map(|o| (o - origin) / 2)
                    .collect();
                collect_matches(cs, &wv, true, &virtual_anchors, &mut out);
            }
        }
    }
    out.sort_by_key(|m| m.offset);
    out.dedup_by_key(|m| m.offset);
    out
}

fn collect_matches<V: crate::hexpat::View>(
    cs: &CString,
    view: &V,
    wide: bool,
    // virtual indices where a prefilter atom was seen (already translated
    // from physical offsets by the caller)
    anchor_virtual: &[usize],
    out: &mut Vec<SMatch>,
) {
    // Only a genuinely empty physical buffer yields no matches at all; a
    // wide view over one trailing byte still has a zero-width anchor.
    if view.physical_len() == 0 {
        return;
    }
    if anchor_virtual.is_empty() {
        // atomless: full scan, overlapping matches allowed
        let mut from = 0usize;
        while from <= view.len() {
            let Some((vs, ve)) = find_one(cs, view, wide, from) else { break };
            push_if_fullword(cs, view, vs, ve, out);
            from = vs + 1;
        }
        return;
    }
    // anchored verification: search a window ending at each atom hit, since
    // the extracted atom may sit inside the pattern (not at its start).
    let mut starts = anchor_virtual.to_vec();
    starts.sort_unstable();
    starts.dedup();
    let max_span = max_pattern_span(cs);
    for atom_vs in starts {
        let lo = atom_vs.saturating_sub(max_span);
        // search every candidate start in [lo, atom_vs]; a match whose span
        // covers the atom is accepted (its end must pass the atom position).
        let mut s = lo;
        while s <= atom_vs {
            if let Some((ms, me)) = find_one(cs, view, wide, s) {
                if ms <= atom_vs && me > atom_vs {
                    push_if_fullword(cs, view, ms, me, out);
                    s = ms + 1;
                    continue;
                }
                s = ms + 1;
            } else {
                break;
            }
        }
    }
}

/// Upper bound on how many virtual bytes a match start can sit before its
/// extracted atom. For text it is the full length; for hex/regex we use a
/// generous fixed window covering practical pattern sizes.
fn max_pattern_span(cs: &CString) -> usize {
    match &cs.def {
        CStringDef::Text(b) => b.len(),
        CStringDef::Hex(_) | CStringDef::Regex(_) => 256,
    }
}

fn push_if_fullword<V: crate::hexpat::View>(
    cs: &CString,
    view: &V,
    vs: usize,
    ve: usize,
    out: &mut Vec<SMatch>,
) {
    if cs.fullword && !fullword_ok(view, vs, ve) {
        return;
    }
    let origin = view.physical_origin();
    out.push(SMatch {
        offset: origin + vs * view.stride(),
        length: (ve - vs) * view.stride(),
    });
}

fn find_one<V: crate::hexpat::View>(
    cs: &CString,
    view: &V,
    wide: bool,
    from: usize,
) -> Option<(usize, usize)> {
    match &cs.def {
        CStringDef::Text(bytes) => text_find(view, bytes, cs.nocase, wide, from),
        CStringDef::Hex(pat) => hex_find(view, pat, from, cs.nocase, wide),
        CStringDef::Regex(re) => re_find(view, re, cs.nocase, wide, from),
    }
}

fn fullword_ok<V: crate::hexpat::View>(view: &V, vs: usize, ve: usize) -> bool {
    let before = if vs == 0 { true } else { !is_word_byte(view.at(vs - 1)) };
    let after = if ve >= view.len() { true } else { !is_word_byte(view.at(ve)) };
    before && after
}

fn is_word_byte(c: u8) -> bool {
    c.is_ascii_alphanumeric() || c == b'_'
}

fn text_find<V: crate::hexpat::View>(
    view: &V,
    needle: &[u8],
    nocase: bool,
    wide: bool,
    from: usize,
) -> Option<(usize, usize)> {
    if needle.is_empty() || needle.len() > view.len() {
        return None;
    }
    let last = view.len() - needle.len();
    'outer: for s in from..=last {
        for (i, &n) in needle.iter().enumerate() {
            let vi = s + i;
            if wide && !view.zero_ok(vi) {
                continue 'outer;
            }
            let c = view.at(vi);
            let hit = if nocase { n.eq_ignore_ascii_case(&c) } else { n == c };
            if !hit {
                continue 'outer;
            }
        }
        return Some((s, s + needle.len()));
    }
    None
}

// ---------------------------------------------------------------------------
// Condition evaluation
// ---------------------------------------------------------------------------

#[derive(Clone, Debug)]
enum Value {
    Undef,
    Int(i64),
    Bool(bool),
}

impl Value {
    fn as_bool(&self) -> bool {
        match self {
            Value::Bool(b) => *b,
            Value::Int(n) => *n != 0,
            Value::Undef => false,
        }
    }
    fn as_int(&self) -> i64 {
        match self {
            Value::Int(n) => *n,
            Value::Bool(b) => *b as i64,
            Value::Undef => 0,
        }
    }
}

struct EvalCtx<'a> {
    data: &'a [u8],
    rule: &'a CompiledRule,
    states: &'a [StringState],
    /// binding for `$_` inside a `for ... of` body
    it: Option<usize>,
}

impl<'a> EvalCtx<'a> {
    fn eval(&mut self, e: &Expr) -> Value {
        match e {
            Expr::Bool(b) => Value::Bool(*b),
            Expr::Int(n) => Value::Int(*n),
            Expr::Filesize => Value::Int(self.data.len() as i64),
            Expr::Entrypoint => Value::Undef,
            Expr::Ident(_) => Value::Undef,
            Expr::Not(x) => Value::Bool(!self.eval(x).as_bool()),
            Expr::Neg(x) => match self.eval(x) {
                Value::Int(n) => Value::Int(n.wrapping_neg()),
                _ => Value::Undef,
            },
            Expr::And(a, b) => {
                let x = self.eval(a).as_bool();
                if !x {
                    Value::Bool(false)
                } else {
                    Value::Bool(self.eval(b).as_bool())
                }
            }
            Expr::Or(a, b) => {
                let x = self.eval(a).as_bool();
                if x {
                    Value::Bool(true)
                } else {
                    Value::Bool(self.eval(b).as_bool())
                }
            }
            Expr::StringId { name, op, index } => {
                let si = if name.is_empty() {
                    self.it
                } else {
                    self.rule.strings.iter().position(|s| s.name == *name)
                };
                let Some(si) = si else { return Value::Undef };
                self.string_value(si, *op, index.as_deref())
            }
            Expr::Of { quant, set } => {
                let members = self.resolve_set(set);
                let n = members.iter().filter(|&&si| self.states[si].count() > 0).count() as i64;
                Value::Bool(self.quant_ok(quant, members.len(), n))
            }
            Expr::For { quant, set, body } => {
                let members = self.resolve_set(set);
                let mut ok_count = 0i64;
                for &si in &members {
                    let mut inner = EvalCtx {
                        data: self.data,
                        rule: self.rule,
                        states: self.states,
                        it: Some(si),
                    };
                    if inner.eval(body).as_bool() {
                        ok_count += 1;
                    }
                }
                Value::Bool(self.quant_ok(quant, members.len(), ok_count))
            }
            Expr::Uint { width, be, arg } => {
                let off = self.eval(arg).as_int();
                if off < 0 || off as usize + width > self.data.len() {
                    Value::Undef
                } else {
                    let o = off as usize;
                    let mut v: i64 = 0;
                    for i in 0..*width {
                        let byte = self.data[o + i] as i64;
                        v = if *be { (v << 8) | byte } else { v | (byte << (8 * i)) };
                    }
                    Value::Int(v)
                }
            }
            Expr::BinAnd(a, b) => Value::Bool(self.eval(a).as_bool() && self.eval(b).as_bool()),
            Expr::BinOr(a, b) => Value::Bool(self.eval(a).as_bool() || self.eval(b).as_bool()),
            Expr::BitAnd(a, b) => Value::Int(self.eval(a).as_int() & self.eval(b).as_int()),
            Expr::BitOr(a, b) => Value::Int(self.eval(a).as_int() | self.eval(b).as_int()),
            Expr::Xor(a, b) => Value::Int(self.eval(a).as_int() ^ self.eval(b).as_int()),
            Expr::Shl(a, b) => Value::Int(self.eval(a).as_int().wrapping_shl(
                self.eval(b).as_int().try_into().unwrap_or(0).min(63),
            )),
            Expr::Shr(a, b) => Value::Int(self.eval(a).as_int().wrapping_shr(
                self.eval(b).as_int().try_into().unwrap_or(0).min(63),
            )),
            Expr::Add(a, b) => Value::Int(self.eval(a).as_int().wrapping_add(self.eval(b).as_int())),
            Expr::Sub(a, b) => Value::Int(self.eval(a).as_int().wrapping_sub(self.eval(b).as_int())),
            Expr::Mul(a, b) => Value::Int(self.eval(a).as_int().wrapping_mul(self.eval(b).as_int())),
            Expr::Div(a, b) => {
                let d = self.eval(b).as_int();
                if d == 0 {
                    Value::Undef
                } else {
                    Value::Int(self.eval(a).as_int().wrapping_div(d))
                }
            }
            Expr::Mod(a, b) => {
                let d = self.eval(b).as_int();
                if d == 0 {
                    Value::Undef
                } else {
                    Value::Int(self.eval(a).as_int().wrapping_rem(d))
                }
            }
            Expr::Eq(a, b) => Value::Bool(self.cmp(a, b) == Some(std::cmp::Ordering::Equal)),
            Expr::Ne(a, b) => Value::Bool(self.cmp(a, b) != Some(std::cmp::Ordering::Equal)),
            Expr::Lt(a, b) => Value::Bool(self.cmp(a, b) == Some(std::cmp::Ordering::Less)),
            Expr::Le(a, b) => Value::Bool(matches!(
                self.cmp(a, b),
                Some(std::cmp::Ordering::Less) | Some(std::cmp::Ordering::Equal)
            )),
            Expr::Gt(a, b) => Value::Bool(self.cmp(a, b) == Some(std::cmp::Ordering::Greater)),
            Expr::Ge(a, b) => Value::Bool(matches!(
                self.cmp(a, b),
                Some(std::cmp::Ordering::Greater) | Some(std::cmp::Ordering::Equal)
            )),
        }
    }

    fn cmp(&mut self, a: &Expr, b: &Expr) -> Option<std::cmp::Ordering> {
        let x = self.eval(a);
        let y = self.eval(b);
        if matches!(x, Value::Undef) || matches!(y, Value::Undef) {
            return None;
        }
        Some(x.as_int().cmp(&y.as_int()))
    }

    fn string_value(&self, si: usize, op: StrOp, index: Option<&Expr>) -> Value {
        let st = &self.states[si];
        match op {
            StrOp::Found => Value::Bool(st.count() > 0),
            StrOp::Count => Value::Int(st.count()),
            StrOp::Offset | StrOp::Length => {
                // index defaults to 1 (YARA is 1-based)
                let n = match index {
                    Some(ix) => {
                        let mut tmp = EvalCtx {
                            data: self.data,
                            rule: self.rule,
                            states: self.states,
                            it: self.it,
                        };
                        tmp.eval(ix).as_int()
                    }
                    None => 1,
                };
                if n < 1 {
                    return Value::Undef;
                }
                let all = st.all();
                let Some(m) = all.get(n as usize - 1) else {
                    return Value::Undef;
                };
                Value::Int(if op == StrOp::Offset {
                    m.offset as i64
                } else {
                    m.length as i64
                })
            }
        }
    }

    fn resolve_set(&self, set: &StringSet) -> Vec<usize> {
        match set {
            StringSet::List(names) => names
                .iter()
                .filter_map(|n| self.rule.strings.iter().position(|s| s.name == *n))
                .collect(),
            StringSet::Wildcard(pat) => {
                let prefix = pat.trim_end_matches('*');
                self.rule
                    .strings
                    .iter()
                    .enumerate()
                    .filter(|(_, s)| s.name.starts_with(prefix))
                    .map(|(i, _)| i)
                    .collect()
            }
        }
    }

    fn quant_ok(&self, quant: &Quant, total: usize, ok: i64) -> bool {
        match quant {
            Quant::Any => ok >= 1,
            Quant::All => ok as usize == total && total > 0,
            Quant::None => ok == 0,
            Quant::Expr(e) => {
                let mut tmp = EvalCtx {
                    data: self.data,
                    rule: self.rule,
                    states: self.states,
                    it: self.it,
                };
                let need = tmp.eval(e).as_int();
                ok >= need
            }
        }
    }
}

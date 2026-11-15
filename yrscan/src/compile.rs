//! Compilation: turn parsed rules into a scannable rule set.
//!
//! For every string definition we extract fixed byte atoms (2–4 bytes) that
//! must occur whenever the string matches. Atoms feed the Aho-Corasick
//! prefilter; a hit makes the owning string a *candidate* and only candidates
//! are verified with the full matcher. Strings with no extractable atom force
//! their rule onto a "full scan" list (rare: all-wildcard hex patterns,
//! anchor-only regexes, ...).

use crate::aho::Aho;
use crate::hexpat::{literal_runs as hex_runs, HexPattern};
use crate::parser::{Expr, Rule, StringDef};
use crate::regex::Regex;

#[derive(Clone)]
pub enum CStringDef {
    Text(Vec<u8>),
    Hex(HexPattern),
    Regex(Regex),
}

#[derive(Clone)]
pub struct CString {
    pub name: String,
    pub def: CStringDef,
    pub nocase: bool,
    pub wide: bool,
    pub ascii: bool,
    pub fullword: bool,
    /// rule has no usable atom for this string → verify on every file
    pub atomless: bool,
}

pub struct CompiledRule {
    pub name: String,
    #[allow(dead_code)]
    pub tags: Vec<String>,
    pub is_private: bool,
    pub strings: Vec<CString>,
    pub condition: Expr,
    /// indexes (into `strings`) that are referenced from the condition
    pub referenced: Vec<usize>,
    /// true if any referenced string is atomless
    pub full_scan: bool,
}

pub struct CompiledRules {
    pub rules: Vec<CompiledRule>,
    pub aho: Aho,
    /// rule indices that must run verification on every file
    pub full_scan_rules: Vec<usize>,
}

const MAX_ATOM: usize = 4;
/// 2-byte minimum: 1-byte anchors are so common in binary data that the
/// repeated windowed verification outweighs the prefilter benefit.
const MIN_ATOM: usize = 2;

/// Choose up to a few representative atoms from literal runs.
fn pick_atoms(runs: &mut Vec<Vec<u8>>) -> Vec<Vec<u8>> {
    for r in runs.iter_mut() {
        if r.len() > MAX_ATOM {
            // take the middle window; any fixed window of a literal run works
            let start = (r.len() - MAX_ATOM) / 2;
            r.truncate(start + MAX_ATOM);
            r.drain(0..start);
        }
    }
    runs.retain(|r| r.len() >= MIN_ATOM);
    runs.dedup();
    // cap the number of atoms per string to keep the automaton small
    runs.truncate(8);
    std::mem::take(runs)
}

fn atoms_for(def: &StringDef) -> Vec<Vec<u8>> {
    match def {
        StringDef::Text { bytes, .. } => {
            if bytes.len() >= MIN_ATOM {
                let mut r = vec![bytes.clone()];
                pick_atoms(&mut r)
            } else {
                Vec::new()
            }
        }
        StringDef::Hex { pat, .. } => {
            let mut runs = Vec::new();
            hex_runs(&pat.tokens, &mut runs);
            pick_atoms(&mut runs)
        }
        StringDef::Regex { re, .. } => {
            let mut runs = Vec::new();
            crate::regex::literals(re, &mut runs);
            pick_atoms(&mut runs)
        }
    }
}

fn flags_of(def: &StringDef) -> (bool, bool, bool, bool) {
    match def {
        StringDef::Text { nocase, wide, ascii, fullword, .. }
        | StringDef::Hex { nocase, wide, ascii, fullword, .. }
        | StringDef::Regex { nocase, wide, ascii, fullword, .. } => {
            (*nocase, *wide, *ascii, *fullword)
        }
    }
}

pub fn compile(rules: Vec<Rule>) -> CompiledRules {
    let mut aho = Aho::new();
    let mut compiled = Vec::with_capacity(rules.len());
    let mut full_scan_rules = Vec::new();

    for (ri, rule) in rules.into_iter().enumerate() {
        let mut cstrings = Vec::with_capacity(rule.strings.len());
        let mut rule_full_scan = false;

        for (si, rs) in rule.strings.into_iter().enumerate() {
            let (nocase, wide, ascii, fullword) = flags_of(&rs.def);
            let atoms = atoms_for(&rs.def);
            let atomless = atoms.is_empty();
            if atomless {
                rule_full_scan = true;
            }
            for atom in &atoms {
                // register both the plain atom and, for wide strings, a
                // UTF-16LE-expanded copy so the prefilter can reach them
                aho.add_atom(atom, nocase, wide, (ri, si));
            }
            let cdef = match rs.def {
                StringDef::Text { bytes, .. } => CStringDef::Text(bytes),
                StringDef::Hex { pat, .. } => CStringDef::Hex(pat),
                StringDef::Regex { re, .. } => CStringDef::Regex(re),
            };
            cstrings.push(CString {
                name: rs.id,
                def: cdef,
                nocase,
                wide,
                ascii,
                fullword,
                atomless,
            });
        }

        let mut referenced = Vec::new();
        collect_refs(&rule.condition, &cstrings, &mut referenced);
        referenced.sort_unstable();
        referenced.dedup();

        // only referenced atomless strings force full scan
        let full_scan = referenced.iter().any(|&si| cstrings[si].atomless);
        if full_scan {
            full_scan_rules.push(ri);
        }
        let _ = rule_full_scan;

        compiled.push(CompiledRule {
            name: rule.name,
            tags: rule.tags,
            is_private: rule.is_private,
            strings: cstrings,
            condition: rule.condition,
            referenced,
            full_scan,
        });
    }

    aho.build();
    CompiledRules { rules: compiled, aho, full_scan_rules }
}

fn collect_refs(e: &Expr, strings: &[CString], out: &mut Vec<usize>) {
    match e {
        Expr::StringId { name, .. } => {
            if let Some(idx) = strings.iter().position(|s| s.name == *name) {
                out.push(idx);
            }
        }
        Expr::Of { set, .. } => collect_set(set, strings, out),
        Expr::For { set, body, .. } => {
            collect_set(set, strings, out);
            collect_refs(body, strings, out);
        }
        Expr::Not(a) | Expr::Neg(a) => collect_refs(a, strings, out),
        Expr::And(a, b)
        | Expr::Or(a, b)
        | Expr::BinAnd(a, b)
        | Expr::BinOr(a, b)
        | Expr::BitAnd(a, b)
        | Expr::BitOr(a, b)
        | Expr::Xor(a, b)
        | Expr::Shl(a, b)
        | Expr::Shr(a, b)
        | Expr::Add(a, b)
        | Expr::Sub(a, b)
        | Expr::Mul(a, b)
        | Expr::Div(a, b)
        | Expr::Mod(a, b)
        | Expr::Eq(a, b)
        | Expr::Ne(a, b)
        | Expr::Lt(a, b)
        | Expr::Le(a, b)
        | Expr::Gt(a, b)
        | Expr::Ge(a, b) => {
            collect_refs(a, strings, out);
            collect_refs(b, strings, out);
        }
        Expr::Uint { arg, .. } => collect_refs(arg, strings, out),
        Expr::Bool(_)
        | Expr::Ident(_)
        | Expr::Filesize
        | Expr::Entrypoint
        | Expr::Int(_) => {}
    }
}

fn collect_set(
    set: &crate::parser::StringSet,
    strings: &[CString],
    out: &mut Vec<usize>,
) {
    use crate::parser::StringSet;
    match set {
        StringSet::List(names) => {
            for n in names {
                if let Some(idx) = strings.iter().position(|s| s.name == *n) {
                    out.push(idx);
                }
            }
        }
        StringSet::Wildcard(pat) => {
            let prefix = pat.trim_end_matches('*');
            for (i, s) in strings.iter().enumerate() {
                if s.name.starts_with(prefix) {
                    out.push(i);
                }
            }
        }
    }
}

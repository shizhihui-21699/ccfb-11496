//! Scanning engine: atom extraction, Aho-Corasick prefilter, per-pattern
//! verification and condition evaluation.

use crate::aho::{AcHit, AhoCorasick};
use crate::ast::*;
use crate::error::{err, YResult};
use crate::hex::HexNode;
use crate::regex::{Engine as ReEngine, Re};

/// YARA stops recording matches for a single string once this many are found.
pub const YARA_MAX_STRING_MATCHES: usize = 1_000_000;

/// One concrete match of a pattern: byte offset and match length.
#[derive(Debug, Clone)]
pub struct Match {
    pub offset: usize,
    pub length: usize,
}

/// A pattern expanded for one encoding (ascii / wide).
#[derive(Debug, Clone)]
pub struct ScanPattern {
    pub rule_idx: usize,
    pub pat_idx: usize,
    #[allow(dead_code)]
    pub wide: bool,
    pub nocase: bool,
    pub fullword: bool,
    pub kind: PatternKind,
    /// text bytes (folded to lowercase when nocase)
    pub text: Vec<u8>,
    pub hex: Option<HexNode>,
    pub re: Option<Re>,
    /// atoms used for prefiltering (folded when nocase)
    pub atoms: Vec<Vec<u8>>,
    /// when true the pattern has no usable atom and must be verified at every
    /// position
    pub atomless: bool,
}

pub struct CompiledRules {
    pub rules: Vec<Rule>,
    pub patterns: Vec<ScanPattern>,
    ac_exact: AhoCorasick,
    ac_nocase: AhoCorasick,
    has_exact: bool,
    has_nocase: bool,
}

fn is_word_byte(c: u8) -> bool {
    // YARA fullword boundaries: alphanumeric is a word byte; underscore and
    // everything else are boundaries (verified against yara 4.6).
    c.is_ascii_alphanumeric()
}

impl CompiledRules {
    pub fn compile(rules: Vec<Rule>) -> YResult<Self> {
        for rule in &rules {
            validate_rule_refs(rule)?;
        }
        let mut patterns = Vec::new();
        for (ri, rule) in rules.iter().enumerate() {
            for (pi, pat) in rule.patterns.iter().enumerate() {
                let enc = pat.encodings(); // [ascii, wide]
                for wide in [false, true] {
                    if !enc[wide as usize] {
                        continue;
                    }
                    let sp = Self::expand(ri, pi, wide, pat)?;
                    patterns.push(sp);
                }
            }
        }
        let mut ac_exact = AhoCorasick::new();
        let mut ac_nocase = AhoCorasick::new();
        let mut has_exact = false;
        let mut has_nocase = false;
        for (id, sp) in patterns.iter().enumerate() {
            if sp.atomless {
                continue;
            }
            for atom in &sp.atoms {
                if sp.nocase {
                    ac_nocase.insert(atom, id);
                    has_nocase = true;
                } else {
                    ac_exact.insert(atom, id);
                    has_exact = true;
                }
            }
        }
        ac_exact.build();
        ac_nocase.build();
        Ok(CompiledRules { rules, patterns, ac_exact, ac_nocase, has_exact, has_nocase })
    }

    fn expand(
        rule_idx: usize,
        pat_idx: usize,
        wide: bool,
        pat: &Pattern,
    ) -> YResult<ScanPattern> {
        let mut sp = ScanPattern {
            rule_idx,
            pat_idx,
            wide,
            nocase: pat.nocase,
            fullword: pat.fullword,
            kind: pat.kind,
            text: Vec::new(),
            hex: None,
            re: None,
            atoms: Vec::new(),
            atomless: false,
        };
        match pat.kind {
            PatternKind::Text => {
                let mut bytes = pat.text.clone();
                if wide {
                    bytes = interleave_zero(&bytes);
                }
                if pat.nocase {
                    bytes = bytes.iter().map(|b| b.to_ascii_lowercase()).collect();
                }
                if bytes.is_empty() {
                    return err("empty string pattern", 0);
                }
                sp.atoms = vec![bytes.clone()];
                sp.text = bytes;
            }
            PatternKind::Hex => {
                let node = pat.hex.clone().unwrap();
                sp.hex = Some(node.clone());
                // contiguous fixed-byte prefix (wildcards/jumps end the run)
                let atom: Vec<u8> = node.leading_fixed_bytes().into_iter().map(|(v, _)| v).collect();
                if !atom.is_empty() {
                    sp.atoms = vec![atom];
                } else {
                    sp.atomless = true;
                }
            }
            PatternKind::Regex => {
                let mut tree = pat.re.clone().unwrap();
                if wide {
                    tree = tree.into_wide();
                }
                if pat.nocase {
                    tree = tree.into_nocase();
                }
                let runs = tree.literal_runs();
                let best = runs.into_iter().max_by_key(|r| r.len());
                match best {
                    Some(atom) if !atom.is_empty() => sp.atoms = vec![atom],
                    _ => sp.atomless = true,
                }
                sp.re = Some(tree);
            }
        }
        Ok(sp)
    }

    /// Scan one file, returning per-(rule,pattern) match lists. The outer vec
    /// is indexed by rule, inner by pattern ordinal.
    pub fn scan(&self, data: &[u8]) -> Vec<Vec<Vec<Match>>> {
        let n_rules = self.rules.len();
        let mut out: Vec<Vec<Vec<Match>>> = (0..n_rules)
            .map(|ri| {
                (0..self.rules[ri].patterns.len())
                    .map(|_| Vec::new())
                    .collect()
            })
            .collect();

        // Candidate collection: which ScanPattern ids need verification at
        // which positions.
        let mut candidates: Vec<Vec<usize>> = vec![Vec::new(); self.patterns.len()];

        if self.has_exact {
            self.ac_exact.scan(data, false, |hit: AcHit| {
                candidates[hit.pattern].push(hit.start);
            });
        }
        if self.has_nocase {
            self.ac_nocase.scan(data, true, |hit: AcHit| {
                candidates[hit.pattern].push(hit.start);
            });
        }

        // Build the byte-occurrence index once if any pattern needs hex
        // verification with jumps.
        let needs_index = self
            .patterns
            .iter()
            .any(|sp| sp.kind == PatternKind::Hex);
        let index = if needs_index {
            Some(ByteIndex::build(data))
        } else {
            None
        };

        for (id, sp) in self.patterns.iter().enumerate() {
            let matches = if sp.atomless {
                self.verify_full(sp, data, index.as_ref())
            } else {
                self.verify_candidates(sp, data, &candidates[id], index.as_ref())
            };
            let bucket = &mut out[sp.rule_idx][sp.pat_idx];
            for m in matches {
                // YARA caps the number of matches reported for one string.
                if bucket.len() >= YARA_MAX_STRING_MATCHES {
                    break;
                }
                merge_match(bucket, m);
            }
        }
        out
    }

    /// Verify a pattern only around prefilter candidate starts.
    fn verify_candidates(
        &self,
        sp: &ScanPattern,
        data: &[u8],
        starts: &[usize],
        index: Option<&ByteIndex>,
    ) -> Vec<Match> {
        let mut out = Vec::new();
        for &start in starts {
            if let Some(m) = self.verify_at(sp, data, start, index) {
                merge_match(&mut out, m);
            }
        }
        out
    }

    /// Atomless pattern: try every start position.
    fn verify_full(
        &self,
        sp: &ScanPattern,
        data: &[u8],
        index: Option<&ByteIndex>,
    ) -> Vec<Match> {
        let mut out = Vec::new();
        if data.is_empty() {
            // YARA never reports pattern matches against empty files.
            return out;
        }
        for start in 0..=data.len() {
            if let Some(m) = self.verify_at(sp, data, start, index) {
                merge_match(&mut out, m);
            }
        }
        out
    }

    /// Attempt to match `sp` exactly at `start`, enforcing fullword.
    fn verify_at(
        &self,
        sp: &ScanPattern,
        data: &[u8],
        start: usize,
        index: Option<&ByteIndex>,
    ) -> Option<Match> {
        let length = match sp.kind {
            PatternKind::Text => {
                let needle = &sp.text; // already folded to lowercase when nocase
                if start + needle.len() > data.len() {
                    return None;
                }
                let slice = &data[start..start + needle.len()];
                let ok = if sp.nocase {
                    slice.iter().zip(needle).all(|(a, b)| a.to_ascii_lowercase() == *b)
                } else {
                    slice == needle.as_slice()
                };
                if !ok {
                    return None;
                }
                needle.len()
            }
            PatternKind::Hex => {
                // A hex pattern always needs the byte index for jump handling.
                let index = index.expect("ByteIndex must be built when hex patterns exist");
                match_hex(sp.hex.as_ref().unwrap(), data, index, start)?
            }
            PatternKind::Regex => {
                let mut eng = ReEngine::new(data, sp.nocase);
                let end = eng.match_at(sp.re.as_ref().unwrap(), start)?;
                end - start
            }
        };
        if length == 0 {
            // A zero-length regex match (e.g. /a*/) is reported at every
            // position EXCEPT the end of the file: YARA emits empty matches at
            // offsets 0..len-1 but not at offset == len.
            if start < data.len() {
                return Some(Match { offset: start, length: 0 });
            }
            return None;
        }
        if sp.fullword && !fullword_ok(data, start, length) {
            return None;
        }
        Some(Match { offset: start, length })
    }
}

fn interleave_zero(bytes: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(*b);
        out.push(0);
    }
    out
}

/// Compile-time check mirroring YARA: every string identifier referenced in a
/// condition must be declared in that rule's strings section.
fn validate_rule_refs(rule: &Rule) -> YResult<()> {
    let declared: std::collections::HashSet<&str> =
        rule.patterns.iter().map(|p| p.id.as_str()).collect();
    let mut check_str = |name: &str| -> YResult<()> {
        if !declared.contains(name) {
            err(format!("rule \"{}\": undefined string \"${}\"", rule.name, name), 0)
        } else {
            Ok(())
        }
    };
    fn check_int(
        e: &IntExpr,
        check_str: &mut dyn FnMut(&str) -> YResult<()>,
    ) -> YResult<()> {
        match e {
            IntExpr::Count(n) | IntExpr::Offset(n, _) | IntExpr::Length(n, _) => check_str(n),
            IntExpr::Neg(x) | IntExpr::Not(x) => check_int(x, check_str),
            IntExpr::Bin(l, _, r) => {
                check_int(l, check_str)?;
                check_int(r, check_str)
            }
            _ => Ok(()),
        }
    }
    fn walk(
        c: &Condition,
        check_int: &mut dyn FnMut(&IntExpr, &mut dyn FnMut(&str) -> YResult<()>) -> YResult<()>,
        check_str: &mut dyn FnMut(&str) -> YResult<()>,
    ) -> YResult<()> {
        match c {
            Condition::Bool(_) | Condition::BoolId(_) => Ok(()),
            Condition::IntLeaf(e) => check_int(e, check_str),
            Condition::PatternDefined(n) => check_str(n),
            Condition::Not(x) => walk(x, check_int, check_str),
            Condition::Bin(l, _, r) => {
                walk(l, check_int, check_str)?;
                walk(r, check_int, check_str)
            }
            Condition::Cmp(l, _, r) => {
                check_int(l, check_str)?;
                check_int(r, check_str)
            }
            Condition::At(n, e) => {
                check_str(n)?;
                check_int(e, check_str)
            }
            Condition::In(n, lo, hi) => {
                check_str(n)?;
                check_int(lo, check_str)?;
                check_int(hi, check_str)
            }
            Condition::Of(_, set) => match set {
                StringSet::Them | StringSet::Wildcard(_) => Ok(()),
                StringSet::List(ids) => {
                    for n in ids {
                        check_str(n)?;
                    }
                    Ok(())
                }
            },
            Condition::For { quant, lo, hi, body, .. } => {
                if let Quantifier::Expr(e) = quant {
                    check_int(e, check_str)?;
                }
                check_int(lo, check_str)?;
                check_int(hi, check_str)?;
                walk(body, check_int, check_str)
            }
        }
    }
    // Adapt the recursive check_int to the walk signature via a thin closure.
    let mut ci = |e: &IntExpr, cs: &mut dyn FnMut(&str) -> YResult<()>| check_int(e, cs);
    walk(&rule.condition, &mut ci, &mut check_str)
}

/// Merge a match, discarding duplicate (offset,length) pairs. Inputs arrive in
/// ascending offset order from the prefilter scan.
fn merge_match(out: &mut Vec<Match>, m: Match) {
    if let Some(last) = out.last() {
        if last.offset == m.offset && last.length == m.length {
            return;
        }
    }
    out.push(m);
}

fn fullword_ok(data: &[u8], start: usize, len: usize) -> bool {
    let before_ok = start == 0 || !is_word_byte(data[start - 1]);
    let end = start + len;
    let after_ok = end >= data.len() || !is_word_byte(data[end]);
    before_ok && after_ok
}


// ---- hex matching ----------------------------------------------------------
//
// NFA-style propagation of reachable positions. Jumps accumulate into a gap
// constraint instead of materializing every gap byte. A fixed node that
// follows a jump looks its first byte up in a ByteIndex, so an unbounded
// `[n-]` jump costs O(number of candidate occurrences), not O(file length).

struct ByteIndex {
    positions: [Vec<usize>; 256],
}

impl ByteIndex {
    fn build(data: &[u8]) -> ByteIndex {
        let mut positions: [Vec<usize>; 256] = std::array::from_fn(|_| Vec::new());
        for (i, &b) in data.iter().enumerate() {
            positions[b as usize].push(i);
        }
        ByteIndex { positions }
    }
}

#[derive(Clone, Copy)]
struct Gap {
    min: usize,
    max: usize, // usize::MAX == unbounded
}

/// Match a fixed byte/text node exactly at `p`; return the end offset.
fn fixed_at(node: &HexNode, data: &[u8], p: usize) -> Option<usize> {
    match node {
        HexNode::Byte { value, mask } => {
            if p < data.len() && (data[p] & mask) == (value & mask) {
                Some(p + 1)
            } else {
                None
            }
        }
        HexNode::Text(t) => {
            if p + t.len() <= data.len() && &data[p..p + t.len()] == t.as_slice() {
                Some(p + t.len())
            } else {
                None
            }
        }
        _ => None,
    }
}

/// First concrete byte of a fixed node (for index lookup), if fully fixed.
fn first_byte(node: &HexNode) -> Option<u8> {
    match node {
        HexNode::Byte { value, mask } if *mask == 0xFF => Some(*value),
        HexNode::Text(t) => Some(t[0]),
        _ => None,
    }
}

/// Apply a fixed node to a set of positions with an optional preceding gap.
fn apply_fixed(
    node: &HexNode,
    data: &[u8],
    index: &ByteIndex,
    positions: &[usize],
    gap: Option<Gap>,
) -> Vec<usize> {
    let mut out: Vec<usize> = Vec::new();
    match gap {
        None => {
            for &p in positions {
                if let Some(e) = fixed_at(node, data, p) {
                    out.push(e);
                }
            }
        }
        Some(g) => {
            let unbounded = g.max == usize::MAX;
            for &p0 in positions {
                let lo = p0 + g.min;
                if lo > data.len() {
                    continue;
                }
                let hi = if unbounded {
                    data.len()
                } else {
                    (p0 + g.max).min(data.len())
                };
                if let Some(fb) = first_byte(node) {
                    let all = &index.positions[fb as usize];
                    let l = all.partition_point(|&p| p < lo);
                    let r = all.partition_point(|&p| p <= hi);
                    if unbounded {
                        // Only the earliest feasible anchor matters: any later
                        // node in the sequence still has an unbounded horizon,
                        // and the greedy-longest result derives from the first
                        // anchor that verifies. This keeps unbounded jumps
                        // O(positions · log n) rather than quadratic.
                        for &p in &all[l..r] {
                            if let Some(e) = fixed_at(node, data, p) {
                                out.push(e);
                                break;
                            }
                        }
                    } else {
                        for &p in &all[l..r] {
                            if let Some(e) = fixed_at(node, data, p) {
                                out.push(e);
                            }
                        }
                    }
                } else {
                    // masked first byte: bounded scan; an unbounded masked gap
                    // stops at the first verifying position for the same reason
                    let range = lo..=hi;
                    for p in range {
                        if let Some(e) = fixed_at(node, data, p) {
                            out.push(e);
                            if unbounded {
                                break;
                            }
                        }
                    }
                }
            }
        }
    }
    // Sort + dedup (positions were not necessarily produced in order across
    // multiple start positions).
    out.sort_unstable();
    out.dedup();
    out
}

/// Walk a sequence node list, returning all reachable end offsets.
fn walk_seq(
    items: &[HexNode],
    data: &[u8],
    index: &ByteIndex,
    start: usize,
) -> Vec<usize> {
    let mut positions = vec![start];
    let mut gap: Option<Gap> = None;
    let mut i = 0;
    while i < items.len() {
        if positions.is_empty() {
            return Vec::new();
        }
        match &items[i] {
            HexNode::Jump { min, max } => {
                let g = Gap { min: *min, max: max.unwrap_or(usize::MAX) };
                gap = Some(match gap {
                    Some(prev) => Gap {
                        min: prev.min + g.min,
                        max: prev.max.saturating_add(g.max),
                    },
                    None => g,
                });
            }
            fixed @ (HexNode::Byte { .. } | HexNode::Text(_)) => {
                positions = apply_fixed(fixed, data, index, &positions, gap);
                gap = None;
            }
            HexNode::Alt(branches) => {
                let mut merged = Vec::new();
                for b in branches {
                    for e in walk_node(b, data, index, &positions, gap) {
                        if !merged.contains(&e) {
                            merged.push(e);
                        }
                    }
                }
                positions = merged;
                gap = None;
            }
            HexNode::Seq(inner) => {
                let mut merged = Vec::new();
                for &p in &positions {
                    let sub = match gap {
                        Some(g) => {
                            let mut v = Vec::with_capacity(inner.len() + 1);
                            v.push(HexNode::Jump {
                                min: g.min,
                                max: if g.max == usize::MAX { None } else { Some(g.max) },
                            });
                            v.extend_from_slice(inner);
                            walk_seq(&v, data, index, p)
                        }
                        None => walk_seq(inner, data, index, p),
                    };
                    for e in sub {
                        if !merged.contains(&e) {
                            merged.push(e);
                        }
                    }
                }
                positions = merged;
                gap = None;
            }
        }
        i += 1;
    }
    // A trailing jump: the pattern can end anywhere in the gap. Only the
    // greedy-longest end is ever consumed, so return just the maximum valid
    // end rather than materializing the whole range.
    if let Some(g) = gap {
        let mut best = None;
        for p0 in positions {
            let hi = if g.max == usize::MAX {
                data.len()
            } else {
                (p0 + g.max).min(data.len())
            };
            if p0 + g.min <= data.len() {
                best = Some(best.map_or(hi, |b: usize| b.max(hi)));
            }
        }
        best.into_iter().collect()
    } else {
        positions
    }
}

/// Evaluate any node against a set of start positions with an incoming gap.
fn walk_node(
    node: &HexNode,
    data: &[u8],
    index: &ByteIndex,
    starts: &[usize],
    gap: Option<Gap>,
) -> Vec<usize> {
    let mut out = Vec::new();
    for &s in starts {
        let ends = match node {
            HexNode::Seq(items) => match gap {
                Some(g) => {
                    let mut v = Vec::with_capacity(items.len() + 1);
                    v.push(HexNode::Jump {
                        min: g.min,
                        max: if g.max == usize::MAX { None } else { Some(g.max) },
                    });
                    v.extend_from_slice(items);
                    walk_seq(&v, data, index, s)
                }
                None => walk_seq(items, data, index, s),
            },
            fixed @ (HexNode::Byte { .. } | HexNode::Text(_)) => {
                apply_fixed(fixed, data, index, &[s], gap)
            }
            HexNode::Jump { min, max } => {
                // bare jump node: defer by wrapping
                let g = Gap { min: *min, max: max.unwrap_or(usize::MAX) };
                let combined = match gap {
                    Some(prev) => Gap {
                        min: prev.min + g.min,
                        max: prev.max.saturating_add(g.max),
                    },
                    None => g,
                };
                let lo = s + combined.min;
                if lo > data.len() {
                    Vec::new()
                } else if combined.max == usize::MAX {
                    vec![data.len()]
                } else {
                    vec![(s + combined.max).min(data.len())]
                }
            }
            HexNode::Alt(branches) => {
                let mut m = Vec::new();
                for b in branches {
                    for e in walk_node(b, data, index, &[s], gap) {
                        if !m.contains(&e) {
                            m.push(e);
                        }
                    }
                }
                m
            }
        };
        for e in ends {
            if !out.contains(&e) {
                out.push(e);
            }
        }
    }
    out
}

fn match_hex(node: &HexNode, data: &[u8], index: &ByteIndex, start: usize) -> Option<usize> {
    let ends = match node {
        HexNode::Seq(items) => walk_seq(items, data, index, start),
        other => walk_node(other, data, index, &[start], None),
    };
    let end = ends.into_iter().max()?;
    Some(end - start)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hex::parse_hex;

    fn len_at(src: &str, data: &[u8], start: usize) -> Option<usize> {
        let node = parse_hex(src).unwrap();
        let idx = ByteIndex::build(data);
        match_hex(&node, data, &idx, start)
    }

    #[test]
    fn hex_wildcards() {
        let data = [0x12, 0x00, 0x56, 0x12, 0xff, 0x56];
        assert_eq!(len_at("12 ?? 56", &data, 0), Some(3));
        assert_eq!(len_at("12 ?? 56", &data, 3), Some(3));
        assert_eq!(len_at("12 ?? 56", &data, 1), None);
        assert_eq!(len_at("3? 56", &[0x34, 0x56], 0), Some(2));
    }

    #[test]
    fn hex_jumps() {
        // 01 at 0, 03 at 5 -> the gap spans 4 bytes (offsets 1..=4)
        let data = [0x01, 0x02, 0xff, 0xff, 0xff, 0x03];
        assert_eq!(len_at("01 [2-4] 03", &data, 0), Some(6));
        assert_eq!(len_at("01 [4] 03", &data, 0), Some(6));
        // unbounded jump stays fast and correct
        assert_eq!(len_at("01 [1-] 03", &data, 0), Some(6));
        // gap of 4 does not fit a [1-3] window
        assert_eq!(len_at("01 [1-3] 03", &data, 0), None);
        assert_eq!(len_at("01 [1] 03", &data, 0), None);
    }

    #[test]
    fn hex_alternation() {
        let data = [0x34, 0x9a];
        assert_eq!(len_at("34 ( 56 | 9a )", &data, 0), Some(2));
        assert_eq!(len_at("34 ( 56 | 78 )", &data, 0), None);
    }

    #[test]
    fn hex_greedy_longest() {
        // with two possible 03 anchors, the longest match is reported
        let data = [0x01, 0x03, 0x00, 0x03];
        assert_eq!(len_at("01 [1-] 03", &data, 0), Some(4));
    }

    #[test]
    fn fullword_boundary_uses_alnum_only() {
        // underscore and punctuation are boundaries
        assert!(fullword_ok(b"_abc_", 1, 3));
        assert!(!fullword_ok(b"xabc", 1, 3));
        assert!(fullword_ok(b".abc.", 1, 3));
    }
}

#[cfg(test)]
mod end_to_end {
    use super::*;
    use crate::parser::Parser;

    fn scan_rule(src: &str, data: &[u8]) -> Vec<Vec<Vec<Match>>> {
        let rules = Parser::parse_src(src).unwrap();
        let compiled = CompiledRules::compile(rules).unwrap();
        compiled.scan(data)
    }

    #[test]
    fn zero_width_matches_exclude_eof_position() {
        // /x*/ on "ab" (len 2): empty matches at 0 and 1, but NOT at offset 2
        let tables = scan_rule("rule r { strings: $a = /x*/ condition: $a }", b"ab");
        let offsets: Vec<usize> = tables[0][0].iter().map(|m| m.offset).collect();
        assert_eq!(offsets, vec![0, 1]);
    }

    #[test]
    fn empty_file_has_no_matches() {
        let tables = scan_rule("rule r { strings: $a = /x*/ condition: $a }", b"");
        assert!(tables[0][0].is_empty());
    }

    #[test]
    fn string_match_count_is_capped() {
        // every position is an empty /x*/ match; cap at YARA_MAX_STRING_MATCHES
        let data = vec![b'z'; YARA_MAX_STRING_MATCHES + 100];
        let tables = scan_rule("rule r { strings: $a = /x*/ condition: $a }", &data);
        assert_eq!(tables[0][0].len(), YARA_MAX_STRING_MATCHES);
    }

    #[test]
    fn overlapping_text_matches_all_counted() {
        let tables = scan_rule("rule r { strings: $a = \"aa\" condition: $a }", b"aaaa");
        assert_eq!(tables[0][0].len(), 3);
    }
}

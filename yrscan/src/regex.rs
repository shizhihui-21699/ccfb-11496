//! Small backtracking regex engine covering the YARA (RE2-style) subset.
//!
//! Supported syntax:
//! - literals, `.`, `\d \w \s \D \W \S \b \B`, escapes incl. `\xHH`
//! - classes `[...]` (ranges, negation, `\d` etc inside, `\xHH`)
//! - anchors `^` `$`, quantifiers `* + ? {n} {n,} {n,m}`, lazy `*? +? ??`
//! - groups `(...)` (captures accepted, values discarded), alternation `|`
//! - non-capturing `(?:...)`, `(?i)`/`(?-i)` inline flags
//!
//! Unsupported (rejected at parse time with a clear error): backreferences,
//! look-around, possessives, `\p{...}`, named groups.
//!
//! Matching is unanchored (like YARA); `^`/`$` act on the scanned buffer.
//! Backtracking is bounded by a step budget so pathological patterns fail
//! closed instead of hanging.

use crate::hexpat::View;
use crate::YResult;

#[derive(Clone, Debug)]
enum Re {
    Empty,
    Lit(u8),
    Any,
    Class { negate: bool, members: Vec<ClassMember> },
    Start,
    End,
    WordBoundary,
    NotWordBoundary,
    Concat(Vec<Re>),
    Alt(Vec<Re>),
    Repeat { child: Box<Re>, lo: u32, hi: Option<u32>, lazy: bool },
    Group(Box<Re>),
    /// case-insensitive applies globally (YARA regex nocase) or via (?i)
    Flag { on: bool, inner: Box<Re> },
}

#[derive(Clone, Debug)]
enum ClassMember {
    Byte(u8),
    Range(u8, u8),
    Digit,
    Word,
    Space,
}

struct RParser<'a> {
    b: &'a [u8],
    pos: usize,
    line: usize,
}

impl<'a> RParser<'a> {
    fn peek(&self) -> Option<u8> {
        self.b.get(self.pos).copied()
    }
    fn peek2(&self) -> Option<u8> {
        self.b.get(self.pos + 1).copied()
    }

    fn parse_alt(&mut self) -> YResult<Re> {
        let mut branches = vec![self.parse_concat()?];
        while self.peek() == Some(b'|') {
            self.pos += 1;
            branches.push(self.parse_concat()?);
        }
        if branches.len() == 1 {
            Ok(branches.pop().unwrap())
        } else {
            Ok(Re::Alt(branches))
        }
    }

    fn parse_concat(&mut self) -> YResult<Re> {
        let mut items = Vec::new();
        loop {
            match self.peek() {
                None | Some(b')') | Some(b'|') => break,
                _ => items.push(self.parse_quant()?),
            }
        }
        Ok(if items.is_empty() { Re::Empty } else { Re::Concat(items) })
    }

    fn parse_quant(&mut self) -> YResult<Re> {
        let atom = self.parse_atom()?;
        match self.peek() {
            Some(b'*') | Some(b'+') | Some(b'?') => {
                let c = self.b[self.pos];
                self.pos += 1;
                let lazy = self.peek() == Some(b'?');
                if lazy {
                    self.pos += 1;
                }
                let (lo, hi) = match c {
                    b'*' => (0, None),
                    b'+' => (1, None),
                    _ => (0, Some(1)),
                };
                Ok(Re::Repeat { child: Box::new(atom), lo, hi, lazy })
            }
            Some(b'{') if self.looks_like_repeat() => {
                self.pos += 1;
                let lo = self.parse_u32()?;
                let mut hi = Some(lo);
                if self.peek() == Some(b',') {
                    self.pos += 1;
                    if self.peek() == Some(b'}') {
                        hi = None;
                    } else {
                        hi = Some(self.parse_u32()?);
                    }
                }
                if self.peek() != Some(b'}') {
                    return crate::err(self.line, "regex: expected '}' in quantifier");
                }
                self.pos += 1;
                let lazy = self.peek() == Some(b'?');
                if lazy {
                    self.pos += 1;
                }
                if let Some(h) = hi {
                    if h < lo {
                        return crate::err(self.line, "regex: quantifier min > max");
                    }
                }
                Ok(Re::Repeat { child: Box::new(atom), lo, hi, lazy })
            }
            _ => Ok(atom),
        }
    }

    fn looks_like_repeat(&self) -> bool {
        let mut i = self.pos + 1;
        let mut saw_digit = false;
        while let Some(c) = self.b.get(i) {
            if c.is_ascii_digit() {
                saw_digit = true;
                i += 1;
            } else {
                break;
            }
        }
        saw_digit && matches!(self.b.get(i), Some(b'}') | Some(b','))
    }

    fn parse_u32(&mut self) -> YResult<u32> {
        let mut v = 0u32;
        let mut any = false;
        while let Some(c) = self.peek() {
            if c.is_ascii_digit() {
                v = v.checked_mul(10).and_then(|x| x.checked_add((c - b'0') as u32))
                    .ok_or_else(|| crate::YError {
                        msg: "regex: number too large".into(),
                        line: self.line,
                    })?;
                any = true;
                self.pos += 1;
            } else {
                break;
            }
        }
        if !any {
            return crate::err(self.line, "regex: expected number");
        }
        Ok(v)
    }

    fn parse_atom(&mut self) -> YResult<Re> {
        match self.peek() {
            Some(b'(') => {
                self.pos += 1;
                let mut flag_on = None;
                if self.peek() == Some(b'?') {
                    match self.peek2() {
                        Some(b':') => {
                            self.pos += 2;
                        }
                        Some(b'i') | Some(b'-') => {
                            self.pos += 1; // ?
                            let mut on = false;
                            if self.peek() == Some(b'-') {
                                self.pos += 1;
                            } else {
                                on = true;
                            }
                            if self.peek() == Some(b'i') {
                                self.pos += 1;
                            }
                            if self.peek() != Some(b')') {
                                return crate::err(self.line, "regex: unsupported group flag");
                            }
                            flag_on = Some(on);
                        }
                        _ => return crate::err(self.line, "regex: unsupported group syntax"),
                    }
                }
                let inner = self.parse_alt()?;
                if self.peek() != Some(b')') {
                    return crate::err(self.line, "regex: unterminated group");
                }
                self.pos += 1;
                match flag_on {
                    Some(on) => Ok(Re::Flag { on, inner: Box::new(inner) }),
                    None => Ok(Re::Group(Box::new(inner))),
                }
            }
            Some(b'[') => self.parse_class(),
            Some(b'.') => {
                self.pos += 1;
                Ok(Re::Any)
            }
            Some(b'^') => {
                self.pos += 1;
                Ok(Re::Start)
            }
            Some(b'$') => {
                self.pos += 1;
                Ok(Re::End)
            }
            Some(b'\\') => self.parse_escape(),
            Some(c) => {
                self.pos += 1;
                Ok(Re::Lit(c))
            }
            None => crate::err(self.line, "regex: unexpected end"),
        }
    }

    fn parse_escape(&mut self) -> YResult<Re> {
        self.pos += 1; // backslash
        let c = self.peek().ok_or_else(|| crate::YError {
            msg: "regex: dangling backslash".into(),
            line: self.line,
        })?;
        self.pos += 1;
        match c {
            b'd' | b'D' | b'w' | b'W' | b's' | b'S' => {
                let neg = c.is_ascii_uppercase();
                let base = match c.to_ascii_lowercase() {
                    b'd' => ClassMember::Digit,
                    b'w' => ClassMember::Word,
                    _ => ClassMember::Space,
                };
                Ok(Re::Class { negate: neg, members: vec![base] })
            }
            b'b' => Ok(Re::WordBoundary),
            b'B' => Ok(Re::NotWordBoundary),
            b'n' => Ok(Re::Lit(b'\n')),
            b'r' => Ok(Re::Lit(b'\r')),
            b't' => Ok(Re::Lit(b'\t')),
            b'f' => Ok(Re::Lit(0x0C)),
            b'v' => Ok(Re::Lit(0x0B)),
            b'a' => Ok(Re::Lit(0x07)),
            b'0' => Ok(Re::Lit(0)),
            b'x' => {
                let mut v = 0u8;
                for _ in 0..2 {
                    let h = self.peek().filter(|x| x.is_ascii_hexdigit()).ok_or_else(|| {
                        crate::YError { msg: "regex: bad \\x escape".into(), line: self.line }
                    })?;
                    self.pos += 1;
                    v = (v << 4) + (h as char).to_digit(16).unwrap() as u8;
                }
                Ok(Re::Lit(v))
            }
            b'1'..=b'9' => crate::err(self.line, "regex: backreferences are not supported"),
            b'p' | b'P' => crate::err(self.line, "regex: unicode classes are not supported"),
            other => Ok(Re::Lit(other)),
        }
    }

    fn parse_class(&mut self) -> YResult<Re> {
        self.pos += 1; // [
        let negate = if self.peek() == Some(b'^') {
            self.pos += 1;
            true
        } else {
            false
        };
        let mut members = Vec::new();
        if self.peek() == Some(b']') {
            members.push(ClassMember::Byte(b']'));
            self.pos += 1;
        }
        while let Some(c) = self.peek() {
            if c == b']' {
                self.pos += 1;
                return Ok(Re::Class { negate, members });
            }
            if c == b'\\' {
                match self.parse_escape()? {
                    Re::Class { negate: n, members: mut m } => {
                        if n {
                            return crate::err(
                                self.line,
                                "regex: negated shorthand (\\D etc) inside [] not supported",
                            );
                        }
                        members.append(&mut m);
                    }
                    Re::Lit(v) => members.push(ClassMember::Byte(v)),
                    _ => unreachable!(),
                }
                continue;
            }
            self.pos += 1;
            if self.peek() == Some(b'-') && self.peek2() != Some(b']') && self.peek2().is_some() {
                self.pos += 1; // -
                let hi = if self.peek() == Some(b'\\') {
                    match self.parse_escape()? {
                        Re::Lit(v) => v,
                        _ => return crate::err(self.line, "regex: bad range endpoint"),
                    }
                } else {
                    let h = self.peek().ok_or_else(|| crate::YError {
                        msg: "regex: unterminated class".into(),
                        line: self.line,
                    })?;
                    self.pos += 1;
                    h
                };
                members.push(ClassMember::Range(c, hi));
            } else {
                members.push(ClassMember::Byte(c));
            }
        }
        crate::err(self.line, "regex: unterminated character class")
    }
}

pub fn compile(pattern: &str) -> YResult<Regex> {
    let mut p = RParser { b: pattern.as_bytes(), pos: 0, line: 1 };
    let root = p.parse_alt()?;
    if p.pos != p.b.len() {
        return crate::err(p.line, "regex: trailing characters");
    }
    Ok(Regex { root })
}

#[derive(Clone, Debug)]
pub struct Regex {
    root: Re,
}

fn class_match(m: &ClassMember, c: u8) -> bool {
    match m {
        ClassMember::Byte(b) => c == *b,
        ClassMember::Range(lo, hi) => c >= *lo && c <= *hi,
        ClassMember::Digit => c.is_ascii_digit(),
        ClassMember::Word => c.is_ascii_alphanumeric() || c == b'_',
        ClassMember::Space => matches!(c, b' ' | b'\t' | b'\n' | b'\r' | 0x0B | 0x0C),
    }
}

/// Class membership honoring the global nocase flag. For literal/range
/// members the input is tried under both its lower- and upper-cased forms.
fn class_match_nocase(m: &ClassMember, c: u8, nocase: bool) -> bool {
    if !nocase {
        return class_match(m, c);
    }
    match m {
        ClassMember::Digit | ClassMember::Word | ClassMember::Space => class_match(m, c),
        ClassMember::Byte(_) | ClassMember::Range(_, _) => {
            class_match(m, c)
                || class_match(m, c.to_ascii_lowercase())
                || class_match(m, c.to_ascii_uppercase())
        }
    }
}

fn is_word(c: u8) -> bool {
    c.is_ascii_alphanumeric() || c == b'_'
}

struct Engine<'a, V: View> {
    view: &'a V,
    nocase: bool,
    wide: bool,
    budget: u64,
}

impl<'a, V: View> Engine<'a, V> {
    fn tick(&mut self) -> bool {
        if self.budget == 0 {
            return false;
        }
        self.budget -= 1;
        true
    }

    /// Every byte-consuming construct must pass through this so wide views
    /// validate the interleaved zero high byte.
    fn take_byte(&self, vi: usize) -> Option<u8> {
        if vi >= self.view.len() {
            return None;
        }
        if self.wide && !self.view.zero_ok(vi) {
            return None;
        }
        Some(self.view.at(vi))
    }

    fn char_match(&self, wanted: u8, actual: u8) -> bool {
        if self.nocase {
            wanted.eq_ignore_ascii_case(&actual)
        } else {
            wanted == actual
        }
    }

    /// Evaluate `node` at `vi`; on success continue with `cont` (borrowed,
    /// no allocation). All backtracking stays on the call stack.
    fn eval_node(&mut self, node: &Re, vi: usize, cont: &[&Re]) -> Option<usize> {
        if !self.tick() {
            return None;
        }
        match node {
            Re::Empty => self.eval_cont(cont, vi),
            Re::Lit(c) => {
                let actual = self.take_byte(vi)?;
                if self.char_match(*c, actual) {
                    self.eval_cont(cont, vi + 1)
                } else {
                    None
                }
            }
            Re::Any => {
                let actual = self.take_byte(vi)?;
                if actual != b'\n' {
                    self.eval_cont(cont, vi + 1)
                } else {
                    None
                }
            }
            Re::Class { negate, members } => {
                let c = self.take_byte(vi)?;
                let hit = members
                    .iter()
                    .any(|m| class_match_nocase(m, c, self.nocase));
                if hit != *negate {
                    self.eval_cont(cont, vi + 1)
                } else {
                    None
                }
            }
            Re::Start => {
                if vi == 0 {
                    self.eval_cont(cont, vi)
                } else {
                    None
                }
            }
            Re::End => {
                if vi == self.view.len() {
                    self.eval_cont(cont, vi)
                } else {
                    None
                }
            }
            Re::WordBoundary => {
                let before = vi > 0 && is_word(self.view.at(vi - 1));
                let after = vi < self.view.len() && is_word(self.view.at(vi));
                if before != after {
                    self.eval_cont(cont, vi)
                } else {
                    None
                }
            }
            Re::NotWordBoundary => {
                let before = vi > 0 && is_word(self.view.at(vi - 1));
                let after = vi < self.view.len() && is_word(self.view.at(vi));
                if before == after {
                    self.eval_cont(cont, vi)
                } else {
                    None
                }
            }
            Re::Concat(items) => self.eval_concat(items, 0, vi, cont),            Re::Alt(branches) => {
                for br in branches {
                    if let Some(end) = self.eval_node(br, vi, cont) {
                        return Some(end);
                    }
                }
                None
            }
            Re::Group(inner) => self.eval_node(inner, vi, cont),
            Re::Flag { on, inner } => {
                let saved = self.nocase;
                self.nocase = *on;
                let r = self.eval_node(inner, vi, cont);
                self.nocase = saved;
                r
            }
            Re::Repeat { child, lo, hi, lazy } => {
                self.eval_repeat(child, vi, *lo, *hi, *lazy, cont)
            }
        }
    }

    /// Drive a borrowed continuation slice.
    fn eval_cont(&mut self, cont: &[&Re], vi: usize) -> Option<usize> {
        if let Some((first, rest)) = cont.split_first() {
            self.eval_node(first, vi, rest)
        } else {
            Some(vi)
        }
    }

    /// Evaluate `items[i..]` then the outer continuation. The tail of the
    /// concat is represented by a stack-local `Concat` Re, so this allocates
    /// only for the (shrinking) tail vector; typical patterns have flat,
    /// short concats where the cost is negligible versus the previous design
    /// which cloned on every backtrack.
    fn eval_concat(
        &mut self,
        items: &[Re],
        i: usize,
        vi: usize,
        outer: &[&Re],
    ) -> Option<usize> {
        if i == items.len() {
            return self.eval_cont(outer, vi);
        }
        let tail = Re::Concat(items[i + 1..].to_vec());
        // one continuation: the tail concat, then the outer
        let mut cont: Vec<&Re> = Vec::with_capacity(1 + outer.len());
        cont.push(&tail);
        cont.extend_from_slice(outer);
        let r = self.eval_node(&items[i], vi, &cont);
        r
    }

    fn eval_repeat(
        &mut self,
        child: &Re,
        mut vi: usize,
        lo: u32,
        hi: Option<u32>,
        lazy: bool,
        cont: &[&Re],
    ) -> Option<usize> {
        // mandatory copies
        for _ in 0..lo {
            vi = self.eval_node(child, vi, &[])?;
        }
        let optional = hi.map(|h| h.saturating_sub(lo));
        self.repeat_tail(child, vi, 0, optional, lazy, cont)
    }

    fn repeat_tail(
        &mut self,
        child: &Re,
        vi: usize,
        used: u32,
        optional: Option<u32>,
        lazy: bool,
        cont: &[&Re],
    ) -> Option<usize> {
        if !self.tick() {
            return None;
        }
        let can_more = match optional {
            Some(max) => used < max,
            None => vi < self.view.len(),
        };
        if lazy {
            if let Some(end) = self.eval_cont(cont, vi) {
                return Some(end);
            }
            if can_more {
                if let Some(nvi) = self.eval_node(child, vi, &[]) {
                    return self.repeat_tail(child, nvi, used + 1, optional, lazy, cont);
                }
            }
            None
        } else {
            if can_more {
                if let Some(nvi) = self.eval_node(child, vi, &[]) {
                    if let Some(end) =
                        self.repeat_tail(child, nvi, used + 1, optional, lazy, cont)
                    {
                        return Some(end);
                    }
                }
            }
            self.eval_cont(cont, vi)
        }
    }
}

/// Match the whole pattern at virtual index `start` (anchored at start).
pub fn match_at<V: View>(view: &V, re: &Regex, start: usize, nocase: bool, wide: bool)
    -> Option<usize>
{
    let mut e = Engine { view, nocase, wide, budget: 5_000_000 };
    e.eval_node(&re.root, start, &[])
}

/// Unanchored search; returns (vstart, vend) of the leftmost-first match at
/// or after virtual index `from`.
pub fn find<V: View>(view: &V, re: &Regex, nocase: bool, wide: bool, from: usize)
    -> Option<(usize, usize)>
{
    let first = first_byte_set(&re.root, nocase);
    let mut s = from;
    while s <= view.len() {
        // Skip positions where the first consumed byte cannot possibly match.
        if let Some(set) = &first {
            while s < view.len() {
                if wide && !view.zero_ok(s) {
                    s += 1;
                    continue;
                }
                if set[view.at(s) as usize] {
                    break;
                }
                s += 1;
            }
            if s > view.len() {
                return None;
            }
        }
        let mut e = Engine { view, nocase, wide, budget: 2_000_000 };
        if let Some(end) = e.eval_node(&re.root, s, &[]) {
            return Some((s, end));
        }
        s += 1;
    }
    None
}

/// Whether the expression can match the empty string.
fn is_nullable(re: &Re) -> bool {
    match re {
        Re::Empty | Re::Start | Re::End | Re::WordBoundary | Re::NotWordBoundary => true,
        Re::Lit(_) | Re::Any | Re::Class { .. } => false,
        Re::Concat(items) => items.iter().all(is_nullable),
        Re::Alt(branches) => branches.iter().any(is_nullable),
        Re::Group(inner) | Re::Flag { inner, .. } => is_nullable(inner),
        Re::Repeat { lo, .. } => *lo == 0,
    }
}

/// Conservative set of bytes that can be the *first consumed* byte. Returns
/// `None` when no useful skipping is possible (any byte, anchors, or a
/// nullable pattern that may match empty at any position).
fn first_byte_set(re: &Re, nocase: bool) -> Option<[bool; 256]> {
    if has_anchor(re) || is_nullable(re) {
        return None;
    }
    let mut set = [false; 256];
    collect_first(re, nocase, &mut set)?;
    Some(set)
}

fn has_anchor(re: &Re) -> bool {
    match re {
        Re::Start | Re::End => true,
        Re::Concat(items) | Re::Alt(items) => items.iter().any(has_anchor),
        Re::Group(inner) | Re::Flag { inner, .. } | Re::Repeat { child: inner, .. } => {
            has_anchor(inner)
        }
        _ => false,
    }
}

fn collect_first(re: &Re, nocase: bool, set: &mut [bool; 256]) -> Option<()> {
    match re {
        Re::Lit(c) => {
            set[*c as usize] = true;
            if nocase {
                set[c.to_ascii_lowercase() as usize] = true;
                set[c.to_ascii_uppercase() as usize] = true;
            }
            Some(())
        }
        Re::Any => None,
        Re::Class { negate: true, .. } => None,
        Re::Class { negate: false, members } => {
            for m in members {
                match m {
                    ClassMember::Byte(b) => {
                        set[*b as usize] = true;
                        if nocase {
                            set[b.to_ascii_lowercase() as usize] = true;
                            set[b.to_ascii_uppercase() as usize] = true;
                        }
                    }
                    ClassMember::Range(lo, hi) => {
                        for b in *lo..=*hi {
                            set[b as usize] = true;
                            if nocase {
                                set[b.to_ascii_lowercase() as usize] = true;
                                set[b.to_ascii_uppercase() as usize] = true;
                            }
                        }
                    }
                    // broad shorthand classes: give up rather than risk a
                    // sparse/incorrect map
                    ClassMember::Word => return None,
                    ClassMember::Space => {
                        for b in [b' ', b'\t', b'\n', b'\r', 0x0B, 0x0C] {
                            set[b as usize] = true;
                        }
                    }
                    ClassMember::Digit => {
                        for b in b'0'..=b'9' {
                            set[b as usize] = true;
                        }
                    }
                }
            }
            Some(())
        }
        Re::Concat(items) => {
            for it in items {
                collect_first(it, nocase, set)?;
                if !is_nullable(it) {
                    break;
                }
            }
            Some(())
        }
        Re::Alt(branches) => {
            for br in branches {
                collect_first(br, nocase, set)?;
            }
            Some(())
        }
        Re::Group(inner) | Re::Flag { inner, .. } => collect_first(inner, nocase, set),
        Re::Repeat { child, .. } => collect_first(child, nocase, set),
        // nullable/anchor/empty cases are excluded by first_byte_set's gate
        _ => None,
    }
}

/// Collect literal byte sequences usable as prefilter atoms (best effort).
/// Every returned run is guaranteed to occur inside any match that takes the
/// path containing it; alternative branches each contribute their own runs.
pub fn literals(re: &Regex, out: &mut Vec<Vec<u8>>) {
    let mut cur = Vec::new();
    collect(&re.root, &mut cur, out);
    if cur.len() >= 2 {
        out.push(cur);
    }
    out.dedup();
}

fn collect(re: &Re, cur: &mut Vec<u8>, out: &mut Vec<Vec<u8>>) {
    match re {
        Re::Lit(c) => cur.push(*c),
        Re::Concat(items) => {
            for it in items {
                collect(it, cur, out);
            }
        }
        Re::Group(inner) | Re::Flag { inner, .. } => collect(inner, cur, out),
        Re::Empty => {}
        // A required repetition still contains at least one copy of its child.
        Re::Repeat { child, lo, .. } if *lo >= 1 => collect(child, cur, out),
        Re::Alt(branches) => {
            // A literal prefix already accumulated is shared by every branch;
            // flush it once, then explore each branch independently.
            if cur.len() >= 2 {
                out.push(std::mem::take(cur));
            } else {
                cur.clear();
            }
            for br in branches {
                let mut bc = Vec::new();
                collect(br, &mut bc, out);
                if bc.len() >= 2 {
                    out.push(bc);
                }
            }
        }
        _ => {
            if cur.len() >= 2 {
                out.push(std::mem::take(cur));
            } else {
                cur.clear();
            }
        }
    }
}

//! A self-contained byte-oriented regular expression engine covering the
//! YARA regex subset. Continuation-passing backtracking matcher with a step
//! budget and recursion-depth guard.
//!
//! Supported syntax:
//!   literals, . (not newline), ^ $ anchors, groups (...), alternation |,
//!   quantifiers * + ? and {n} {n,} {,m} {n,m} (greedy only),
//!   classes [a-z] with negation, \d \D \w \W \s \S (also inside classes),
//!   \xHH and ordinary backslash escapes. No backreferences / look-around.

use crate::error::{err, YaraError, YResult};

#[derive(Debug, Clone)]
pub enum Re {
    Literal(u8),
    Any,
    Start,
    End,
    Class(Vec<(u8, u8)>, bool), // ranges, negated
    Seq(Vec<Re>),
    Alt(Vec<Re>),
    Repeat { node: Box<Re>, min: u32, max: Option<u32> },
}

struct ReParser<'a> {
    b: &'a [u8],
    pos: usize,
}

impl Re {
    pub fn compile(src: &str) -> YResult<Re> {
        let mut p = ReParser { b: src.as_bytes(), pos: 0 };
        let node = p.parse_alt()?;
        if p.pos != p.b.len() {
            return err(format!("unexpected '{}' in regex", p.b[p.pos] as char), 0);
        }
        Ok(node)
    }

    /// wide: every matchable unit must be followed by an interleaved zero byte.
    pub fn into_wide(self) -> Re {
        match self {
            Re::Seq(v) => Re::Seq(v.into_iter().map(Re::into_wide).collect()),
            Re::Alt(v) => Re::Alt(v.into_iter().map(Re::into_wide).collect()),
            Re::Repeat { node, min, max } => Re::Repeat {
                node: Box::new(node.into_wide()),
                min,
                max,
            },
            anchor @ (Re::Start | Re::End) => anchor,
            other => Re::Seq(vec![other, Re::Literal(0)]),
        }
    }

    /// nocase: fold fixed letters to lowercase; the matcher folds input too.
    pub fn into_nocase(self) -> Re {
        match self {
            Re::Literal(c) => Re::Literal(c.to_ascii_lowercase()),
            Re::Class(mut ranges, neg) => {
                for r in ranges.iter_mut() {
                    r.0 = r.0.to_ascii_lowercase();
                    r.1 = r.1.to_ascii_lowercase();
                }
                Re::Class(ranges, neg)
            }
            Re::Seq(v) => Re::Seq(v.into_iter().map(Re::into_nocase).collect()),
            Re::Alt(v) => Re::Alt(v.into_iter().map(Re::into_nocase).collect()),
            Re::Repeat { node, min, max } => Re::Repeat {
                node: Box::new(node.into_nocase()),
                min,
                max,
            },
            other => other,
        }
    }

    /// Fixed literal bytes forming the pattern's leading prefix. A non-literal
    /// matchable node (class, Any, repeat, alternation) ends the prefix; the
    /// bytes collected before it are still a valid atom because every match of
    /// the pattern must start with them.
    pub fn literal_runs(&self) -> Vec<Vec<u8>> {
        let mut cur = Vec::new();
        self.collect_prefix(&mut cur);
        if cur.is_empty() {
            Vec::new()
        } else {
            vec![cur]
        }
    }

    /// Push leading literal bytes into `cur` until the first non-literal node.
    fn collect_prefix(&self, cur: &mut Vec<u8>) {
        match self {
            Re::Literal(c) => cur.push(*c),
            // Anchors consume no bytes and do not break the prefix.
            Re::Start | Re::End => {}
            Re::Seq(v) => {
                for n in v {
                    let before = cur.len();
                    n.collect_prefix(cur);
                    if cur.len() == before {
                        break; // this child contributed no literal: prefix ends
                    }
                }
            }
            // Any non-literal matchable node ends the prefix.
            Re::Any | Re::Class(_, _) | Re::Repeat { .. } | Re::Alt(_) => {}
        }
    }

    fn class_matches(ranges: &[(u8, u8)], neg: bool, c: u8) -> bool {
        let hit = ranges.iter().any(|(lo, hi)| c >= *lo && c <= *hi);
        hit != neg
    }

    fn one_match(&self, c: u8, nocase: bool) -> bool {
        let c = if nocase { c.to_ascii_lowercase() } else { c };
        match self {
            Re::Literal(x) => c == if nocase { x.to_ascii_lowercase() } else { *x },
            Re::Any => c != b'\n',
            Re::Class(ranges, neg) => Self::class_matches(ranges, *neg, c),
            _ => false,
        }
    }
}

// ---- parser ----------------------------------------------------------------

impl<'a> ReParser<'a> {
    fn peek(&self) -> Option<u8> {
        self.b.get(self.pos).copied()
    }
    fn bump(&mut self) -> Option<u8> {
        let c = self.peek()?;
        self.pos += 1;
        Some(c)
    }

    fn parse_alt(&mut self) -> YResult<Re> {
        let mut branches = vec![self.parse_seq()?];
        while self.peek() == Some(b'|') {
            self.bump();
            branches.push(self.parse_seq()?);
        }
        if branches.len() == 1 {
            Ok(branches.pop().unwrap())
        } else {
            Ok(Re::Alt(branches))
        }
    }

    fn parse_seq(&mut self) -> YResult<Re> {
        let mut items = Vec::new();
        loop {
            match self.peek() {
                None | Some(b')') | Some(b'|') => break,
                _ => items.push(self.parse_quant()?),
            }
        }
        Ok(Re::Seq(items))
    }

    fn parse_quant(&mut self) -> YResult<Re> {
        let atom = self.parse_atom()?;
        match self.peek() {
            Some(b'*') => {
                self.bump();
                Ok(Re::Repeat { node: Box::new(atom), min: 0, max: None })
            }
            Some(b'+') => {
                self.bump();
                Ok(Re::Repeat { node: Box::new(atom), min: 1, max: None })
            }
            Some(b'?') => {
                self.bump();
                Ok(Re::Repeat { node: Box::new(atom), min: 0, max: Some(1) })
            }
            Some(b'{') => {
                self.bump();
                let (min, max) = self.parse_bounds()?;
                Ok(Re::Repeat { node: Box::new(atom), min, max })
            }
            _ => Ok(atom),
        }
    }

    fn parse_bounds(&mut self) -> YResult<(u32, Option<u32>)> {
        // Forms: {n} {n,} {,m} {n,m}
        let mut min = 0u32;
        let mut have_min = false;
        while let Some(c) = self.peek() {
            if c.is_ascii_digit() {
                min = min * 10 + (c - b'0') as u32;
                have_min = true;
                self.bump();
            } else {
                break;
            }
        }
        if self.peek() == Some(b'}') {
            self.bump();
            let v = if have_min { min } else { 0 };
            return Ok((v, Some(v)));
        }
        if self.peek() != Some(b',') {
            return err("bad quantifier bounds in regex", 0);
        }
        self.bump(); // comma
        let mut max = 0u32;
        let mut have_max = false;
        while let Some(c) = self.peek() {
            if c.is_ascii_digit() {
                max = max * 10 + (c - b'0') as u32;
                have_max = true;
                self.bump();
            } else {
                break;
            }
        }
        if self.peek() != Some(b'}') {
            return err("unterminated quantifier in regex", 0);
        }
        self.bump();
        Ok((if have_min { min } else { 0 }, if have_max { Some(max) } else { None }))
    }

    fn parse_atom(&mut self) -> YResult<Re> {
        match self.peek() {
            Some(b'(') => {
                self.bump();
                let inner = self.parse_alt()?;
                if self.peek() != Some(b')') {
                    return err("unbalanced parentheses in regex", 0);
                }
                self.bump();
                Ok(inner)
            }
            Some(b'[') => self.parse_class(),
            Some(b'.') => {
                self.bump();
                Ok(Re::Any)
            }
            Some(b'^') => {
                self.bump();
                Ok(Re::Start)
            }
            Some(b'$') => {
                self.bump();
                Ok(Re::End)
            }
            Some(b'\\') => self.parse_escape(),
            Some(c) => {
                self.bump();
                Ok(Re::Literal(c))
            }
            None => err("unexpected end of regex", 0),
        }
    }

    fn shorthand(c: u8) -> Option<Re> {
        let word = vec![(b'a', b'z'), (b'A', b'Z'), (b'0', b'9'), (b'_', b'_')];
        let space = vec![(b'\t', b'\r'), (b' ', b' ')];
        match c {
            b'd' => Some(Re::Class(vec![(b'0', b'9')], false)),
            b'D' => Some(Re::Class(vec![(b'0', b'9')], true)),
            b'w' => Some(Re::Class(word, false)),
            b'W' => Some(Re::Class(word, true)),
            b's' => Some(Re::Class(space, false)),
            b'S' => Some(Re::Class(space, true)),
            _ => None,
        }
    }

    fn parse_escape(&mut self) -> YResult<Re> {
        self.bump(); // backslash
        let c = self.bump().ok_or_else(|| YaraError::new("trailing backslash in regex", 0))?;
        if let Some(re) = Self::shorthand(c) {
            return Ok(re);
        }
        let lit = match c {
            b'n' => b'\n',
            b'r' => b'\r',
            b't' => b'\t',
            b'f' => 0x0c,
            b'a' => 0x07,
            b'v' => 0x0b,
            b'x' => {
                let h1 = self.bump().ok_or_else(|| YaraError::new("bad \\x escape", 0))?;
                let h2 = self.bump().ok_or_else(|| YaraError::new("bad \\x escape", 0))?;
                u8::from_str_radix(std::str::from_utf8(&[h1, h2]).unwrap(), 16)
                    .map_err(|_| YaraError::new("bad \\x escape", 0))?
            }
            other => other,
        };
        Ok(Re::Literal(lit))
    }

    fn parse_class(&mut self) -> YResult<Re> {
        self.bump(); // [
        let neg = if self.peek() == Some(b'^') {
            self.bump();
            true
        } else {
            false
        };
        let mut ranges = Vec::new();
        if self.peek() == Some(b']') {
            self.bump();
            ranges.push((b']', b']'));
        }
        while let Some(c) = self.peek() {
            if c == b']' {
                self.bump();
                return Ok(Re::Class(ranges, neg));
            }
            if c == b'\\' {
                if let Re::Class(r, n) = self.parse_escape()? {
                    if n {
                        return err("negated shorthand (\\D etc.) inside [] not supported", 0);
                    }
                    ranges.extend(r);
                    continue;
                }
                continue;
            }
            let lo = c;
            self.bump();
            if self.peek() == Some(b'-') && self.b.get(self.pos + 1) != Some(&b']') {
                self.bump();
                let hi = self.bump().ok_or_else(|| YaraError::new("bad range in class", 0))?;
                ranges.push((lo, hi));
            } else {
                ranges.push((lo, lo));
            }
        }
        err("unterminated character class", 0)
    }
}

// ---- continuation-passing backtracking matcher -----------------------------

const MAX_DEPTH: u32 = 400;

pub struct Engine<'a> {
    data: &'a [u8],
    nocase: bool,
    steps: u64,
    budget: u64,
}

impl<'a> Engine<'a> {
    pub fn new(data: &'a [u8], nocase: bool) -> Self {
        let budget = 2_000_000 + (data.len() as u64) * 128;
        Engine { data, nocase, steps: 0, budget }
    }

    fn tick(&mut self) -> bool {
        self.steps += 1;
        self.steps <= self.budget
    }

    /// Match `re` anchored at `start`; return the end offset of the
    /// greedy-longest match, or None.
    pub fn match_at(&mut self, re: &Re, start: usize) -> Option<usize> {
        let mut result = None;
        // The top-level continuation always returns false so the engine keeps
        // backtracking through every valid path; we remember the longest end.
        self.go(re, start, 0, &mut |_eng, pos| {
            match result {
                Some(prev) if pos <= prev => {}
                _ => result = Some(pos),
            }
            false
        });
        result
    }

    fn go(&mut self, re: &Re, pos: usize, depth: u32, cont: &mut dyn FnMut(&mut Engine, usize) -> bool) -> bool {
        if !self.tick() || depth > MAX_DEPTH {
            return false;
        }
        match re {
            Re::Literal(_) | Re::Any | Re::Class(_, _) => {
                if pos < self.data.len() && re.one_match(self.data[pos], self.nocase) {
                    cont(self, pos + 1)
                } else {
                    false
                }
            }
            Re::Start => {
                if pos == 0 {
                    cont(self, pos)
                } else {
                    false
                }
            }
            Re::End => {
                if pos == self.data.len() {
                    cont(self, pos)
                } else {
                    false
                }
            }
            Re::Seq(items) => self.go_seq(items, 0, pos, depth, cont),
            Re::Alt(branches) => {
                for b in branches {
                    let mut win = false;
                    self.go(b, pos, depth + 1, &mut |eng, p| {
                        if cont(eng, p) {
                            win = true;
                            true // propagate: stop exploring this branch
                        } else {
                            false
                        }
                    });
                    if win {
                        return true;
                    }
                }
                false
            }
            Re::Repeat { node, min, max } => self.go_repeat(node, *min, *max, pos, depth, cont),
        }
    }

    fn go_seq(
        &mut self,
        items: &[Re],
        idx: usize,
        pos: usize,
        depth: u32,
        cont: &mut dyn FnMut(&mut Engine, usize) -> bool,
    ) -> bool {
        if idx == items.len() {
            return cont(self, pos);
        }
        let rest = &items[idx + 1..];
        let next = &items[idx];
        self.go(next, pos, depth + 1, &mut |eng, p| {
            eng.go_seq(rest, 0, p, depth + 1, cont)
        })
    }

    fn go_repeat(
        &mut self,
        node: &Re,
        min: u32,
        max: Option<u32>,
        pos: usize,
        depth: u32,
        cont: &mut dyn FnMut(&mut Engine, usize) -> bool,
    ) -> bool {
        // Greedy backtracking. `count` iterations have already matched.
        self.repeat_rec(node, min, max, pos, depth, cont, 0)
    }

    fn repeat_rec(
        &mut self,
        node: &Re,
        min: u32,
        max: Option<u32>,
        pos: usize,
        depth: u32,
        cont: &mut dyn FnMut(&mut Engine, usize) -> bool,
        count: u32,
    ) -> bool {
        let cap = max.unwrap_or(u32::MAX);
        // Greedy: if another iteration is allowed, try it first.
        if count < cap {
            let mut advanced_to: Option<usize> = None;
            self.go(node, pos, depth + 1, &mut |_eng, p| {
                if p != pos {
                    advanced_to = Some(p);
                    true // take the greedy (first/longest) body match, stop
                } else {
                    // zero-width body: do not loop forever
                    false
                }
            });
            if let Some(nxt) = advanced_to {
                if self.repeat_rec(node, min, max, nxt, depth + 1, cont, count + 1) {
                    return true;
                }
            }
        }
        // Backtracked here (or capped out): accept the current count if it
        // satisfies the minimum, by invoking the continuation.
        if count >= min {
            cont(self, pos)
        } else {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn find_all(pat: &str, data: &[u8], nocase: bool) -> Vec<(usize, usize)> {
        let re = Re::compile(pat).unwrap();
        let mut hits = Vec::new();
        for start in 0..=data.len() {
            let mut eng = Engine::new(data, nocase);
            if let Some(end) = eng.match_at(&re, start) {
                if end > start {
                    hits.push((start, end));
                }
            }
        }
        hits
    }

    #[test]
    fn overlapping_counts() {
        // /aa/ over "aaa" -> two overlapping matches
        assert_eq!(find_all("aa", b"aaa", false), vec![(0, 2), (1, 3)]);
    }

    #[test]
    fn quantifiers_greedy() {
        assert_eq!(find_all("ab+", b"abbb", false), vec![(0, 4)]);
        assert_eq!(find_all("ab*", b"abbb", false), vec![(0, 4)]);
        assert_eq!(find_all("a[0-9]+b", b"a333b", false), vec![(0, 5)]);
        assert_eq!(find_all("z8{2,3}", b"z8888", false), vec![(0, 4)]);
    }

    #[test]
    fn dot_excludes_newline() {
        assert_eq!(find_all("a.b", b"a\nb", false), vec![]);
        assert_eq!(find_all("a.b", b"axb", false), vec![(0, 3)]);
    }

    #[test]
    fn anchors_and_classes() {
        assert_eq!(find_all("^start", b"start x", false), vec![(0, 5)]);
        assert_eq!(find_all("x$", b"end x", false), vec![(4, 5)]);
        // overlapping digit matches, identical to yara's count semantics
        assert_eq!(find_all(r"\d+", b"a123b", false), vec![(1, 4), (2, 4), (3, 4)]);
        assert_eq!(find_all("a[^0-9]b", b"a-b", false), vec![(0, 3)]);
    }

    #[test]
    fn nocase_folding() {
        let re = Re::compile("abc").unwrap().into_nocase();
        let data = b"ABC";
        let mut eng = Engine::new(data, true);
        assert_eq!(eng.match_at(&re, 0), Some(3));
    }

    #[test]
    fn wide_interleaves_zeros() {
        let re = Re::compile("abc").unwrap().into_wide();
        let data = b"a\x00b\x00c\x00";
        let mut eng = Engine::new(data, false);
        assert_eq!(eng.match_at(&re, 0), Some(6));
    }

    #[test]
    fn prefix_atom_only() {
        // leading fixed prefix must not include bytes after a non-literal node
        let runs = Re::compile("a[0-9]+b").unwrap().literal_runs();
        assert_eq!(runs, vec![b"a".to_vec()]);
        let runs = Re::compile("abc").unwrap().literal_runs();
        assert_eq!(runs, vec![b"abc".to_vec()]);
    }
}

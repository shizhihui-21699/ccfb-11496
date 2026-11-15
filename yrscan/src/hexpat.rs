//! Hex string patterns: `{ 4A ?? [1-3] ( 61 | 62 ) }`.
//!
//! Supported syntax (YARA-compatible subset):
//! - literal bytes `4A`, nibble wildcards `??`, `?`, `?F`, `F?`
//! - jumps `[n]`, `[n-m]`, `[n-]`, `[-m]`, `[-]`
//! - alternatives `( AA | BB CC )`, nested
//! - whitespace/newlines between tokens

use crate::YResult;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HTok {
    /// Byte with a nibble mask: high/low nibble of `mask` set means the
    /// corresponding nibble of `val` is fixed. `??` => mask 0x00.
    Byte { val: u8, mask: u8 },
    Jump { lo: u32, hi: Option<u32> },
    Alt(Vec<Vec<HTok>>),
}

#[derive(Clone, Debug)]
pub struct HexPattern {
    pub tokens: Vec<HTok>,
}

struct Parser<'a> {
    b: &'a [u8],
    pos: usize,
    line: usize,
}

impl<'a> Parser<'a> {
    fn peek(&self) -> Option<u8> {
        self.b.get(self.pos).copied()
    }

    fn skip_ws(&mut self) {
        while let Some(c) = self.peek() {
            if c == b'\n' {
                self.line += 1;
                self.pos += 1;
            } else if c.is_ascii_whitespace() {
                self.pos += 1;
            } else {
                break;
            }
        }
    }

    fn expect(&mut self, c: u8) -> YResult<()> {
        self.skip_ws();
        if self.peek() == Some(c) {
            self.pos += 1;
            Ok(())
        } else {
            crate::err(self.line, format!("hex pattern: expected '{}'", c as char))
        }
    }

    fn parse_seq(&mut self, terminator: u8) -> YResult<Vec<HTok>> {
        let mut out = Vec::new();
        loop {
            self.skip_ws();
            match self.peek() {
                None => {
                    if terminator == 0 {
                        return Ok(out);
                    }
                    return crate::err(self.line, "hex pattern: unterminated");
                }
                Some(c) if c == terminator => {
                    self.pos += 1;
                    return Ok(out);
                }
                // '|' and ')' only make sense inside an alternative; stop and
                // leave them for the caller (parse_alt) to handle.
                Some(b'|') | Some(b')') => return Ok(out),
                Some(b'(') => {
                    self.pos += 1;
                    let branches = self.parse_alt()?;
                    out.push(HTok::Alt(branches));
                }
                Some(b'[') => out.push(self.parse_jump()?),
                Some(c) if c.is_ascii_hexdigit() || c == b'?' => {
                    out.push(self.parse_byte()?);
                }
                Some(c) => {
                    return crate::err(self.line, format!("hex pattern: bad token '{}'", c as char))
                }
            }
        }
    }

    /// Parse `branch | branch | ... )`; the closing ')' is consumed here.
    fn parse_alt(&mut self) -> YResult<Vec<Vec<HTok>>> {
        let mut branches = Vec::new();
        loop {
            let branch = self.parse_seq(0)?;
            branches.push(branch);
            self.skip_ws();
            match self.peek() {
                Some(b'|') => {
                    self.pos += 1;
                }
                Some(b')') => {
                    self.pos += 1;
                    return Ok(branches);
                }
                _ => return crate::err(self.line, "hex pattern: unterminated alternative"),
            }
        }
    }

    fn parse_byte(&mut self) -> YResult<HTok> {
        let mut val: u8 = 0;
        let mut mask: u8 = 0;
        for shift in [4u8, 0] {
            let c = self.peek().unwrap();
            if c == b'?' {
                self.pos += 1;
                // nibble stays wildcard
            } else if c.is_ascii_hexdigit() {
                let d = (c as char).to_digit(16).unwrap() as u8;
                val |= d << shift;
                mask |= 0xF << shift;
                self.pos += 1;
            } else {
                return crate::err(self.line, "hex pattern: bad nibble");
            }
        }
        Ok(HTok::Byte { val, mask })
    }

    fn parse_jump(&mut self) -> YResult<HTok> {
        self.pos += 1; // [
        self.skip_ws();
        let mut lo = 0u32;
        let mut hi: Option<u32> = None;
        let mut saw_lo = false;
        while let Some(c) = self.peek() {
            if c.is_ascii_digit() {
                lo = lo
                    .checked_mul(10)
                    .and_then(|v| v.checked_add((c - b'0') as u32))
                    .ok_or_else(|| crate::YError {
                        msg: "hex pattern: jump too large".into(),
                        line: self.line,
                    })?;
                saw_lo = true;
                self.pos += 1;
            } else {
                break;
            }
        }
        self.skip_ws();
        if self.peek() == Some(b'-') {
            self.pos += 1;
            self.skip_ws();
            let mut h = 0u32;
            let mut saw_hi = false;
            while let Some(c) = self.peek() {
                if c.is_ascii_digit() {
                    h = h.checked_mul(10).and_then(|v| v.checked_add((c - b'0') as u32))
                        .ok_or_else(|| crate::YError {
                            msg: "hex pattern: jump too large".into(),
                            line: self.line,
                        })?;
                    saw_hi = true;
                    self.pos += 1;
                } else {
                    break;
                }
            }
            if saw_hi {
                hi = Some(h);
            }
        } else if saw_lo {
            hi = Some(lo); // [n] exact
        }
        self.skip_ws();
        self.expect(b']')?;
        if let Some(h) = hi {
            if h < lo {
                return crate::err(self.line, "hex pattern: jump min > max");
            }
        }
        Ok(HTok::Jump { lo, hi })
    }
}

pub fn parse(input: &str) -> YResult<HexPattern> {
    let mut p = Parser { b: input.as_bytes(), pos: 0, line: 1 };
    p.skip_ws();
    // The lexer strips the enclosing braces; parse the token stream directly.
    let tokens = p.parse_seq(0x00)?;
    p.skip_ws();
    if p.pos != p.b.len() {
        return crate::err(p.line, "hex pattern: trailing characters");
    }
    Ok(HexPattern { tokens })
}

/// Abstract byte source so the same matcher runs over ascii and wide views.
pub trait View {
    fn len(&self) -> usize;
    /// byte at virtual index i
    fn at(&self, i: usize) -> u8;
    /// physical bytes consumed per virtual byte
    fn stride(&self) -> usize;
    /// for wide views, validate the interleaved (high) byte is zero
    fn zero_ok(&self, _i: usize) -> bool {
        true
    }
    /// physical file offset corresponding to virtual index 0
    fn physical_origin(&self) -> usize {
        0
    }
    /// total physical bytes backing this view
    fn physical_len(&self) -> usize;
}

pub struct AsciiView<'a> {
    pub data: &'a [u8],
}

impl<'a> View for AsciiView<'a> {
    #[inline]
    fn len(&self) -> usize {
        self.data.len()
    }
    #[inline]
    fn at(&self, i: usize) -> u8 {
        self.data[i]
    }
    #[inline]
    fn stride(&self) -> usize {
        1
    }
    #[inline]
    fn physical_len(&self) -> usize {
        self.data.len()
    }
}

/// UTF-16LE-ish view: virtual byte i maps to physical byte `origin + i*2`,
/// and the interleaved zero high byte is validated through
/// [`View::zero_ok`]. YARA scans wide strings starting from *every* physical
/// offset, so the scanner constructs one view per origin (0 and 1).
pub struct WideView<'a> {
    pub data: &'a [u8],
    pub origin: usize,
}

impl<'a> WideView<'a> {
    pub fn new(data: &'a [u8], origin: usize) -> Self {
        Self { data, origin }
    }
}

impl<'a> View for WideView<'a> {
    #[inline]
    fn len(&self) -> usize {
        // ceil rather than floor: a lone trailing byte still provides a
        // position where zero-width patterns (e.g. /x?/) can match, matching
        // YARA's per-physical-byte empty-match behavior.
        self.data.len().saturating_sub(self.origin).div_ceil(2)
    }
    #[inline]
    fn at(&self, i: usize) -> u8 {
        // A trailing half-character (odd byte count) has no low byte; return
        // 0 so only zero-width constructs can succeed there.
        self.data.get(self.origin + i * 2).copied().unwrap_or(0)
    }
    #[inline]
    fn stride(&self) -> usize {
        2
    }
    #[inline]
    fn zero_ok(&self, i: usize) -> bool {
        // A half-character tail position is reachable as a zero-width anchor
        // but must reject any byte-consuming construct: report its (missing)
        // high byte as non-zero.
        self.data.get(self.origin + i * 2 + 1) == Some(&0)
    }
    #[inline]
    fn physical_origin(&self) -> usize {
        self.origin
    }
    #[inline]
    fn physical_len(&self) -> usize {
        self.data.len().saturating_sub(self.origin)
    }
}

#[inline]
fn byte_matches(tok_val: u8, tok_mask: u8, actual: u8, nocase: bool) -> bool {
    if (actual & tok_mask) != (tok_val & tok_mask) {
        if nocase && tok_mask == 0xFF {
            actual.eq_ignore_ascii_case(&tok_val)
        } else {
            false
        }
    } else {
        true
    }
}

struct Matcher<'a, V: View> {
    view: &'a V,
    toks: &'a [HTok],
    nocase: bool,
    wide: bool,
    budget: u64,
}

impl<'a, V: View> Matcher<'a, V> {
    fn consume_byte(&mut self, vi: usize, val: u8, mask: u8) -> Option<usize> {
        if vi >= self.view.len() {
            return None;
        }
        if self.wide && !self.view.zero_ok(vi) {
            return None;
        }
        let actual = self.view.at(vi);
        if byte_matches(val, mask, actual, self.nocase) {
            Some(vi + 1)
        } else {
            None
        }
    }

    fn eval(&mut self, vi: usize, ti: usize) -> Option<usize> {
        if self.budget == 0 {
            return None;
        }
        self.budget -= 1;
        if ti == self.toks.len() {
            return Some(vi);
        }
        match &self.toks[ti] {
            HTok::Byte { val, mask } => {
                let next = self.consume_byte(vi, *val, *mask)?;
                self.eval(next, ti + 1)
            }
            HTok::Jump { lo, hi } => {
                let max = match hi {
                    Some(h) => *h,
                    None => (self.view.len() as u32).saturating_sub(vi as u32),
                };
                for k in *lo..=max {
                    let nvi = vi + k as usize;
                    if nvi > self.view.len() {
                        break;
                    }
                    if let Some(end) = self.eval(nvi, ti + 1) {
                        return Some(end);
                    }
                }
                None
            }
            HTok::Alt(branches) => {
                for br in branches {
                    let saved = self.toks;
                    // evaluate branch tokens in place by swapping the slice
                    self.toks = br;
                    let r = self.eval(vi, 0);
                    self.toks = saved;
                    if let Some(end) = r {
                        // after the branch, continue with the outer suffix
                        return self.eval(end, ti + 1);
                    }
                }
                None
            }
        }
    }
}

/// Returns the virtual end index on a match starting at virtual index `start`.
pub fn match_at<V: View>(
    view: &V,
    pat: &HexPattern,
    start: usize,
    nocase: bool,
    wide: bool,
) -> Option<usize> {
    let mut m = Matcher { view, toks: &pat.tokens, nocase, wide, budget: 2_000_000 };
    m.eval(start, 0)
}

/// Find the first match at or after virtual index `from`. Returns (vstart, vend).
pub fn find<V: View>(view: &V, pat: &HexPattern, from: usize, nocase: bool, wide: bool)
    -> Option<(usize, usize)>
{
    let mut s = from;
    while s <= view.len() {
        if let Some(end) = match_at(view, pat, s, nocase, wide) {
            return Some((s, end));
        }
        s += 1;
    }
    None
}

/// Extract literal byte runs (no wildcards/jumps/alts) for atom extraction.
/// Alternatives contribute the union of their branches' runs.
pub fn literal_runs(toks: &[HTok], out: &mut Vec<Vec<u8>>) {
    let mut cur = Vec::new();
    for t in toks {
        match t {
            HTok::Byte { val, mask } if *mask == 0xFF => cur.push(*val),
            _ => {
                if cur.len() >= 2 {
                    out.push(std::mem::take(&mut cur));
                } else {
                    cur.clear();
                }
                match t {
                    HTok::Alt(branches) => {
                        for br in branches {
                            literal_runs(br, out);
                        }
                    }
                    HTok::Jump { .. } | HTok::Byte { .. } => {}
                }
            }
        }
    }
    if cur.len() >= 2 {
        out.push(cur);
    }
}

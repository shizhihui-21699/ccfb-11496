//! Hex pattern parser.
//!
//! Supported grammar (YARA subset):
//!   token  := byte | text-literal | jump | '(' or-branch ( '|' or-branch )* ')'
//!   byte   := hex-digit or '?' per nibble  (??, ?A, A?, AB)
//!   jump   := '[' number? ('-' number?)? ']'
//! Embedded text strings support inline \x escapes, like { 41 "BC" }.

use crate::error::{err, YResult};
use crate::lexer::Lexer;

#[derive(Debug, Clone)]
pub enum HexNode {
    /// fixed byte with an 8-bit mask; mask bit 0 = wildcard nibble
    Byte { value: u8, mask: u8 },
    /// embedded text literal (already unescaped)
    Text(Vec<u8>),
    /// variable-length gap: min..max bytes, None max = unbounded
    Jump { min: usize, max: Option<usize> },
    /// ordered concatenation
    Seq(Vec<HexNode>),
    /// ordered alternation (first match wins at scan time)
    Alt(Vec<HexNode>),
}

impl HexNode {
    /// Minimum possible match length in bytes.
    #[allow(dead_code)]
    pub fn min_len(&self) -> usize {
        match self {
            HexNode::Byte { .. } | HexNode::Text(_) => self.fixed_len(),
            HexNode::Jump { min, .. } => *min,
            HexNode::Seq(v) => v.iter().map(|n| n.min_len()).sum(),
            HexNode::Alt(v) => v.iter().map(|n| n.min_len()).min().unwrap_or(0),
        }
    }

    /// Length when every element is fixed-length; jumps/alternation return 0.
    #[allow(dead_code)]
    pub fn fixed_len(&self) -> usize {
        match self {
            HexNode::Byte { .. } => 1,
            HexNode::Text(t) => t.len(),
            HexNode::Jump { .. } => 0,
            HexNode::Seq(v) => v.iter().map(|n| n.fixed_len()).sum(),
            HexNode::Alt(_) => 0,
        }
    }

    /// Longest fixed byte run starting at the root sequence beginning.
    /// Used for atom extraction.
    pub fn leading_fixed_bytes(&self) -> Vec<(u8, u8)> {
        let mut out = Vec::new();
        self.collect_leading(&mut out);
        out
    }

    fn collect_leading(&self, out: &mut Vec<(u8, u8)>) {
        match self {
            HexNode::Byte { value, mask } => out.push((*value, *mask)),
            HexNode::Text(t) => {
                for b in t {
                    out.push((*b, 0xFF));
                }
            }
            HexNode::Seq(v) => {
                for n in v {
                    let before = out.len();
                    n.collect_leading(out);
                    match n {
                        // A jump or alternation has no fixed position: the
                        // leading fixed-prefix run ends here, so drop anything
                        // collected from later siblings.
                        HexNode::Jump { .. } | HexNode::Alt(_) => {
                            out.truncate(before);
                            break;
                        }
                        _ => {
                            // A wildcard byte likewise ends the fixed run.
                            let wildcard = out[before..].iter().any(|(_, m)| *m != 0xFF);
                            if wildcard {
                                out.truncate(before);
                                break;
                            }
                        }
                    }
                }
            }
            HexNode::Jump { .. } | HexNode::Alt(_) => {}
        }
    }
}

struct HexParser<'a> {
    lex: Lexer<'a>,
}

fn nibble(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

impl<'a> HexParser<'a> {
    fn new(src: &'a str) -> Self {
        HexParser { lex: Lexer::new(src) }
    }

    fn skip_ws(&mut self) {
        loop {
            match self.lex.peek() {
                Some(c) if c.is_ascii_whitespace() => {
                    self.lex.bump();
                }
                _ => break,
            }
        }
    }

    fn parse_seq(&mut self, stop_on_pipe: bool) -> YResult<HexNode> {
        let mut items = Vec::new();
        loop {
            self.skip_ws();
            match self.lex.peek() {
                None => break,
                Some(b')') => break,
                Some(b'|') if stop_on_pipe => break,
                Some(b'(') => {
                    self.lex.bump();
                    let mut branches = Vec::new();
                    loop {
                        let branch = self.parse_seq(true)?;
                        branches.push(branch);
                        self.skip_ws();
                        if self.lex.peek() == Some(b'|') {
                            self.lex.bump();
                            continue;
                        }
                        break;
                    }
                    self.skip_ws();
                    if self.lex.peek() != Some(b')') {
                        return err("expected ')' in hex pattern", self.lex.line);
                    }
                    self.lex.bump();
                    items.push(HexNode::Alt(branches));
                }
                Some(b'[') => items.push(self.parse_jump()?),
                Some(b'"') => items.push(self.parse_text()?),
                Some(c) if nibble(c).is_some() || c == b'?' => {
                    items.push(self.parse_byte()?);
                }
                Some(other) => {
                    return err(
                        format!("unexpected '{}' in hex pattern", other as char),
                        self.lex.line,
                    )
                }
            }
        }
        Ok(HexNode::Seq(items))
    }

    fn parse_byte(&mut self) -> YResult<HexNode> {
        let line = self.lex.line;
        let first = self.lex.bump().unwrap();
        let second = self.lex.bump();
        let (v1, m1) = if first == b'?' {
            (0u8, 0u8)
        } else {
            (nibble(first).unwrap(), 0xFu8)
        };
        let (v2, m2) = match second {
            Some(c) if nibble(c).is_some() => (nibble(c).unwrap(), 0xFu8),
            Some(b'?') => (0u8, 0u8),
            other => {
                return err(
                    format!("bad hex byte, got {:?}", other),
                    line,
                )
            }
        };
        Ok(HexNode::Byte {
            value: (v1 << 4) | v2,
            mask: (m1 << 4) | m2,
        })
    }

    fn parse_jump(&mut self) -> YResult<HexNode> {
        let line = self.lex.line;
        self.lex.bump(); // [
        self.skip_ws();
        let mut min = 0usize;
        let mut have_min = false;
        while let Some(c) = self.lex.peek() {
            if c.is_ascii_digit() {
                min = min * 10 + (c - b'0') as usize;
                have_min = true;
                self.lex.bump();
            } else {
                break;
            }
        }
        if !have_min {
            min = 0;
        }
        self.skip_ws();
        let max = if self.lex.peek() == Some(b'-') {
            self.lex.bump();
            self.skip_ws();
            let mut max = 0usize;
            let mut have = false;
            while let Some(c) = self.lex.peek() {
                if c.is_ascii_digit() {
                    max = max * 10 + (c - b'0') as usize;
                    have = true;
                    self.lex.bump();
                } else {
                    break;
                }
            }
            if have { Some(max) } else { None }
        } else {
            // exact jump [n]
            Some(min)
        };
        self.skip_ws();
        if self.lex.peek() != Some(b']') {
            return err("expected ']' to close hex jump", line);
        }
        self.lex.bump();
        if let Some(hi) = max {
            if hi < min {
                return err("hex jump min greater than max", line);
            }
        }
        Ok(HexNode::Jump { min, max })
    }

    fn parse_text(&mut self) -> YResult<HexNode> {
        let line = self.lex.line;
        self.lex.bump(); // quote
        let start = self.lex.pos;
        while let Some(c) = self.lex.peek() {
            if c == b'\\' {
                self.lex.bump();
                self.lex.bump();
                continue;
            }
            if c == b'"' {
                break;
            }
            self.lex.bump();
        }
        if self.lex.peek() != Some(b'"') {
            return err("unterminated text in hex pattern", line);
        }
        let raw = std::str::from_utf8(&self.lex.b[start..self.lex.pos]).unwrap();
        let data = Lexer::unescape_text(raw, line)?;
        self.lex.bump();
        Ok(HexNode::Text(data))
    }
}

pub fn parse_hex(src: &str) -> YResult<HexNode> {
    let mut p = HexParser::new(src);
    let node = p.parse_seq(false)?;
    p.skip_ws();
    if p.lex.peek().is_some() {
        return err("trailing data in hex pattern", p.lex.line);
    }
    Ok(node)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn jump_leading_atom() {
        for (src, expect_atom) in [
            ("01 [1-] 03", vec![0x01]),
            ("01 [4] 03", vec![0x01]),
            ("12 ?? 56", vec![0x12]),
            ("12 34 56", vec![0x12, 0x34, 0x56]),
        ] {
            let n = parse_hex(src).unwrap();
            let atom: Vec<u8> = n.leading_fixed_bytes().into_iter().map(|(v, _)| v).collect();
            assert_eq!(atom, expect_atom, "src={}", src);
        }
    }
}

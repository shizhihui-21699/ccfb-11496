//! Parser for the YARA rule subset.
//!
//! Grammar sketch:
//! ```text
//! rule NAME [ : tag ... ]
//! {
//!   strings:
//!     $id = "text"   modifiers
//!     $id = { hex }
//!     $id = /regex/ modifiers
//!   condition:
//!     expr
//! }
//! ```
//! Condition expressions support: boolean ops, comparisons, arithmetic,
//! `#`, `@`, `!` operators, `of`/`any`/`all`/`n of`, `for ... of : (...)`,
//! `uintXX(...)`, filesize, entrypoint, string identifiers and parenthesized
//! sub-expressions.

use crate::hexpat::HexPattern;
use crate::regex::Regex;
use crate::YResult;

#[derive(Clone, Debug)]
pub enum StringDef {
    Text { bytes: Vec<u8>, nocase: bool, wide: bool, ascii: bool, fullword: bool },
    Hex { pat: HexPattern, nocase: bool, wide: bool, ascii: bool, fullword: bool },
    Regex { re: Regex, nocase: bool, wide: bool, ascii: bool, fullword: bool },
}

#[derive(Clone, Debug)]
pub struct RuleString {
    pub id: String,
    pub def: StringDef,
    /// true when `$id` appears in the condition
    pub referenced: bool,
}

#[derive(Clone, Debug)]
pub enum Expr {
    Bool(bool),
    Ident(String),
    StringId { name: String, op: StrOp, index: Option<Box<Expr>> },
    Filesize,
    Entrypoint,
    Uint { width: usize, be: bool, arg: Box<Expr> },
    Int(i64),
    Not(Box<Expr>),
    Neg(Box<Expr>),
    And(Box<Expr>, Box<Expr>),
    Or(Box<Expr>, Box<Expr>),
    BinAnd(Box<Expr>, Box<Expr>),
    BinOr(Box<Expr>, Box<Expr>),
    BitAnd(Box<Expr>, Box<Expr>),
    BitOr(Box<Expr>, Box<Expr>),
    Xor(Box<Expr>, Box<Expr>),
    Shl(Box<Expr>, Box<Expr>),
    Shr(Box<Expr>, Box<Expr>),
    Add(Box<Expr>, Box<Expr>),
    Sub(Box<Expr>, Box<Expr>),
    Mul(Box<Expr>, Box<Expr>),
    Div(Box<Expr>, Box<Expr>),
    Mod(Box<Expr>, Box<Expr>),
    Eq(Box<Expr>, Box<Expr>),
    Ne(Box<Expr>, Box<Expr>),
    Lt(Box<Expr>, Box<Expr>),
    Le(Box<Expr>, Box<Expr>),
    Gt(Box<Expr>, Box<Expr>),
    Ge(Box<Expr>, Box<Expr>),
    /// `quantifier of string-set`
    Of { quant: Quant, set: StringSet },
    /// `for quant of set : ( expr )` — expr is evaluated with $_ bound
    For { quant: Quant, set: StringSet, body: Box<Expr> },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StrOp {
    /// bare `$a` (truth = found)
    Found,
    /// `#a` count
    Count,
    /// `@a[n]` offset of nth match (1-based)
    Offset,
    /// `!a[n]` length of nth match
    Length,
}

#[derive(Clone, Debug)]
pub enum Quant {
    Any,
    All,
    None,
    Expr(Box<Expr>),
}

#[derive(Clone, Debug)]
pub enum StringSet {
    /// explicit list: ($a, $b, $c)
    List(Vec<String>),
    /// wildcard: $foo* or $*
    Wildcard(String),
}

#[derive(Clone, Debug)]
pub struct Rule {
    pub name: String,
    pub tags: Vec<String>,
    pub strings: Vec<RuleString>,
    pub condition: Expr,
    pub is_private: bool,
    pub line: usize,
}

// ---------------------------------------------------------------------------
// Tokenizer
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, PartialEq)]
enum Tok {
    Ident(String),
    Int(i64),
    Str(String),  // raw content between quotes (escapes processed)
    Hex(String),  // raw content between { }
    Re(String),   // raw regex body
    Punct(String),
}

struct Lexer<'a> {
    b: &'a [u8],
    pos: usize,
    line: usize,
    /// true when the previously emitted token is the '=' punctuation
    prev_was_eq: bool,
}

impl<'a> Lexer<'a> {
    fn new(src: &'a str) -> Self {
        Self { b: src.as_bytes(), pos: 0, line: 1, prev_was_eq: false }
    }

    fn next_tok(&mut self) -> YResult<Option<(usize, Tok)>> {
        let r = self.next_tok_inner()?;
        if let Some((_, ref t)) = r {
            self.prev_was_eq = matches!(t, Tok::Punct(s) if s == "=");
        }
        Ok(r)
    }

    fn skip_comment_and_ws(&mut self) -> YResult<()> {
        loop {
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
            if self.peek() == Some(b'/') && self.peek2() == Some(b'/') {
                while let Some(c) = self.peek() {
                    if c == b'\n' {
                        break;
                    }
                    self.pos += 1;
                }
                continue;
            }
            if self.peek() == Some(b'/') && self.peek2() == Some(b'*') {
                self.pos += 2;
                while let Some(c) = self.peek() {
                    if c == b'\n' {
                        self.line += 1;
                    }
                    if c == b'*' && self.peek2() == Some(b'/') {
                        self.pos += 2;
                        break;
                    }
                    self.pos += 1;
                }
                continue;
            }
            break;
        }
        Ok(())
    }

    fn peek(&self) -> Option<u8> {
        self.b.get(self.pos).copied()
    }
    fn peek2(&self) -> Option<u8> {
        self.b.get(self.pos + 1).copied()
    }

    fn next_tok_inner(&mut self) -> YResult<Option<(usize, Tok)>> {
        self.skip_comment_and_ws()?;
        let line = self.line;
        let c = match self.peek() {
            None => return Ok(None),
            Some(c) => c,
        };
        // identifier / keyword
        if c.is_ascii_alphabetic() || c == b'_' {
            let start = self.pos;
            while let Some(x) = self.peek() {
                if x.is_ascii_alphanumeric() || x == b'_' {
                    self.pos += 1;
                } else {
                    break;
                }
            }
            let s = std::str::from_utf8(&self.b[start..self.pos]).unwrap().to_string();
            return Ok(Some((line, Tok::Ident(s))));
        }
        // number (decimal / 0x), with optional KB/MB suffix
        if c.is_ascii_digit() {
            if c == b'0' && matches!(self.peek2(), Some(b'x') | Some(b'X')) {
                let start = self.pos;
                self.pos += 2;
                while let Some(x) = self.peek() {
                    if x.is_ascii_hexdigit() {
                        self.pos += 1;
                    } else {
                        break;
                    }
                }
                let txt = std::str::from_utf8(&self.b[start..self.pos]).unwrap();
                let v = i64::from_str_radix(&txt[2..], 16).map_err(|_| crate::YError {
                    msg: "bad hex number".into(),
                    line,
                })?;
                return Ok(Some((line, Tok::Int(v))));
            }
            let start = self.pos;
            while matches!(self.peek(), Some(x) if x.is_ascii_digit()) {
                self.pos += 1;
            }
            let txt = std::str::from_utf8(&self.b[start..self.pos]).unwrap();
            let mut v: i64 = txt.parse().map_err(|_| crate::YError {
                msg: "bad number".into(),
                line,
            })?;
            if matches!(self.peek(), Some(b'K') | Some(b'M')) {
                let mult = if self.peek() == Some(b'K') { 1024 } else { 1024 * 1024 };
                self.pos += 1;
                if self.peek() == Some(b'B') {
                    self.pos += 1;
                }
                v = v.saturating_mul(mult);
            }
            return Ok(Some((line, Tok::Int(v))));
        }
        // text string
        if c == b'"' {
            return Ok(Some((line, Tok::Str(self.lex_quoted()?))));
        }
        // hex string: only when the preceding significant token was '=';
        // otherwise '{' opens a rule body.
        if c == b'{' && self.prev_was_eq {
            let start = self.pos + 1;
            self.pos += 1; // consume opening brace
            let mut depth = 1;
            while let Some(x) = self.peek() {
                self.pos += 1;
                if x == b'{' {
                    depth += 1;
                } else if x == b'}' {
                    depth -= 1;
                    if depth == 0 {
                        break;
                    }
                } else if x == b'\n' {
                    self.line += 1;
                }
            }
            if depth != 0 {
                return crate::err(line, "unterminated hex string");
            }
            let raw = std::str::from_utf8(&self.b[start..self.pos - 1]).unwrap().to_string();
            return Ok(Some((line, Tok::Hex(raw))));
        }
        // regex: '/' but not '//' (comment, already handled)
        if c == b'/' {
            self.pos += 1;
            let start = self.pos;
            let mut in_class = false;
            while let Some(x) = self.peek() {
                match x {
                    b'\\' => {
                        self.pos += 2;
                    }
                    b'[' => {
                        in_class = true;
                        self.pos += 1;
                    }
                    b']' => {
                        in_class = false;
                        self.pos += 1;
                    }
                    b'/' if !in_class => {
                        let body =
                            std::str::from_utf8(&self.b[start..self.pos]).unwrap().to_string();
                        self.pos += 1;
                        return Ok(Some((line, Tok::Re(body))));
                    }
                    b'\n' => return crate::err(line, "unterminated regex"),
                    _ => self.pos += 1,
                }
            }
            return crate::err(line, "unterminated regex");
        }
        // multi-char punctuation
        let two: String = self.b[self.pos..].iter().take(2).map(|x| *x as char).collect();
        if matches!(two.as_str(), "==" | "!=" | "<=" | ">=" | "<<" | ">>" | "&&" | "||") {
            self.pos += 2;
            return Ok(Some((line, Tok::Punct(two))));
        }
        self.pos += 1;
        Ok(Some((line, Tok::Punct((c as char).to_string()))))
    }

    fn lex_quoted(&mut self) -> YResult<String> {
        self.pos += 1; // opening quote
        let mut out = String::new();
        while let Some(c) = self.peek() {
            match c {
                b'"' => {
                    self.pos += 1;
                    return Ok(out);
                }
                b'\\' => {
                    self.pos += 1;
                    let e = self.peek().ok_or_else(|| crate::YError {
                        msg: "dangling escape".into(),
                        line: self.line,
                    })?;
                    self.pos += 1;
                    match e {
                        b'n' => out.push('\n'),
                        b'r' => out.push('\r'),
                        b't' => out.push('\t'),
                        b'\\' => out.push('\\'),
                        b'"' => out.push('"'),
                        b'x' => {
                            let mut v = 0u8;
                            for _ in 0..2 {
                                let h = self.peek().filter(|x| x.is_ascii_hexdigit()).ok_or_else(
                                    || crate::YError {
                                        msg: "bad \\x escape".into(),
                                        line: self.line,
                                    },
                                )?;
                                self.pos += 1;
                                v = (v << 4) + (h as char).to_digit(16).unwrap() as u8;
                            }
                            out.push(v as char);
                        }
                        other => out.push(other as char),
                    }
                }
                b'\n' => {
                    self.line += 1;
                    out.push('\n');
                    self.pos += 1;
                }
                _ => {
                    // copy raw byte (supports non-utf8-safe via char lossiness
                    // only for rule source; real binary content comes from hex)
                    out.push(c as char);
                    self.pos += 1;
                }
            }
        }
        crate::err(self.line, "unterminated string")
    }
}

// ---------------------------------------------------------------------------
// Parser (recursive descent)
// ---------------------------------------------------------------------------

struct PState {
    toks: Vec<(usize, Tok)>,
    i: usize,
}

impl PState {
    fn line(&self) -> usize {
        self.toks.get(self.i).map(|t| t.0).unwrap_or(usize::MAX)
    }
    fn peek(&self) -> Option<&Tok> {
        self.toks.get(self.i).map(|t| &t.1)
    }
    fn bump(&mut self) -> Option<Tok> {
        let t = self.toks.get(self.i).map(|t| t.1.clone());
        if t.is_some() {
            self.i += 1;
        }
        t
    }
    fn expect_punct(&mut self, p: &str) -> YResult<()> {
        match self.bump() {
            Some(Tok::Punct(s)) if s == p => Ok(()),
            other => crate::err(self.line(), format!("expected '{p}', got {other:?}")),
        }
    }
    fn eat_punct(&mut self, p: &str) -> bool {
        if matches!(self.peek(), Some(Tok::Punct(s)) if s == p) {
            self.i += 1;
            true
        } else {
            false
        }
    }
    fn eat_ident(&mut self, kw: &str) -> bool {
        if matches!(self.peek(), Some(Tok::Ident(s)) if s == kw) {
            self.i += 1;
            true
        } else {
            false
        }
    }
}

pub fn parse_rules(src: &str) -> YResult<Vec<Rule>> {
    let mut lex = Lexer::new(src);
    let mut toks = Vec::new();
    while let Some(t) = lex.next_tok()? {
        toks.push(t);
    }
    let mut ps = PState { toks, i: 0 };
    let mut rules = Vec::new();
    while ps.peek().is_some() {
        rules.push(parse_rule(&mut ps)?);
    }
    Ok(rules)
}

fn parse_rule(ps: &mut PState) -> YResult<Rule> {
    let line = ps.line();
    let mut is_private = false;
    while let Some(Tok::Ident(kw)) = ps.peek() {
        match kw.as_str() {
            "private" => {
                is_private = true;
                ps.bump();
            }
            "global" => {
                // global accepted but treated like a normal rule in this subset
                ps.bump();
            }
            "rule" => break,
            other => return crate::err(ps.line(), format!("expected 'rule', got '{other}'")),
        }
    }
    if !ps.eat_ident("rule") {
        return crate::err(ps.line(), "expected 'rule'");
    }
    let name = match ps.bump() {
        Some(Tok::Ident(s)) => s,
        other => return crate::err(ps.line(), format!("rule name expected, got {other:?}")),
    };
    let mut tags = Vec::new();
    if ps.eat_punct(":") {
        while let Some(Tok::Ident(t)) = ps.peek().cloned() {
            tags.push(t);
            ps.bump();
            if !ps.eat_punct(":") && !matches!(ps.peek(), Some(Tok::Ident(_))) {
                break;
            }
        }
    }
    ps.expect_punct("{")?;

    let mut strings = Vec::new();
    if ps.eat_ident("strings") {
        ps.expect_punct(":")?;
        loop {
            match ps.peek() {
                Some(Tok::Punct(p)) if p == "$" => {
                    strings.push(parse_string(ps)?);
                }
                _ => break,
            }
        }
    }

    if !ps.eat_ident("condition") {
        return crate::err(ps.line(), "expected 'condition' section");
    }
    ps.expect_punct(":")?;
    let condition = parse_expr(ps)?;
    ps.expect_punct("}")?;

    Ok(Rule { name, tags, strings, condition, is_private, line })
}

fn parse_string(ps: &mut PState) -> YResult<RuleString> {
    ps.expect_punct("$")?;
    let id = match ps.bump() {
        Some(Tok::Ident(s)) => s,
        // anonymous strings: $ = "..."
        _ => String::new(),
    };
    ps.expect_punct("=")?;
    let body = ps.bump();
    let mut def = match body {
        Some(Tok::Str(s)) => {
            let bytes = decode_text(&s);
            if bytes.is_empty() {
                return crate::err(ps.line(), "empty text string is not allowed");
            }
            StringDef::Text { bytes, nocase: false, wide: false, ascii: true, fullword: false }
        }
        Some(Tok::Hex(h)) => {
            let pat = crate::hexpat::parse(&h)?;
            StringDef::Hex { pat, nocase: false, wide: false, ascii: true, fullword: false }
        }
        Some(Tok::Re(r)) => {
            let re = crate::regex::compile(&r)?;
            StringDef::Regex { re, nocase: false, wide: false, ascii: true, fullword: false }
        }
        other => return crate::err(ps.line(), format!("string body expected, got {other:?}")),
    };
    // modifiers
    let mut m_nocase = false;
    let mut m_wide = false;
    let mut m_ascii = false;
    let mut m_fullword = false;
    loop {
        let kw = match ps.peek() {
            Some(Tok::Ident(s)) => s.clone(),
            _ => break,
        };
        match kw.as_str() {
            "nocase" => {
                m_nocase = true;
                ps.bump();
            }
            "wide" | "utf16" | "utf16le" => {
                m_wide = true;
                ps.bump();
            }
            "ascii" => {
                m_ascii = true;
                ps.bump();
            }
            "fullword" => {
                m_fullword = true;
                ps.bump();
            }
            "xor" => {
                // xor ranges consume ( .. ) — not supported in this subset;
                // accepting the keyword as a no-op would change semantics, so
                // reject explicitly.
                return crate::err(ps.line(), "xor modifier not supported in this build");
            }
            _ => break,
        }
    }
    // YARA: with no explicit encoding modifier, strings are ascii-only. Once
    // either `ascii` or `wide` is given, only the listed encodings apply.
    if !m_ascii && !m_wide {
        m_ascii = true;
    }
    set_modifiers(&mut def, m_nocase, m_wide, m_ascii, m_fullword);
    Ok(RuleString { id, def, referenced: false })
}

fn set_modifiers(def: &mut StringDef, nocase: bool, wide: bool, ascii: bool, fullword: bool) {
    let trip = match def {
        StringDef::Text { nocase: n, wide: w, ascii: a, fullword: f, .. }
        | StringDef::Hex { nocase: n, wide: w, ascii: a, fullword: f, .. }
        | StringDef::Regex { nocase: n, wide: w, ascii: a, fullword: f, .. } => {
            (n, w, a, f)
        }
    };
    *trip.0 = nocase;
    *trip.1 = wide;
    *trip.2 = ascii;
    *trip.3 = fullword;
}

fn decode_text(s: &str) -> Vec<u8> {
    // lex_quoted already processed escapes into chars; non-ASCII source bytes
    // were pushed as raw chars (latin1-ish). Re-encode preserving byte values.
    s.chars().map(|c| c as u32).filter(|u| *u <= 0xFF).map(|u| u as u8).collect()
}

// ---------------------------------------------------------------------------
// Expression parsing (precedence climbing)
// ---------------------------------------------------------------------------

fn parse_expr(ps: &mut PState) -> YResult<Expr> {
    parse_or(ps)
}

fn parse_or(ps: &mut PState) -> YResult<Expr> {
    let mut left = parse_and(ps)?;
    while ps.eat_ident("or") {
        let right = parse_and(ps)?;
        left = Expr::Or(Box::new(left), Box::new(right));
    }
    Ok(left)
}

fn parse_and(ps: &mut PState) -> YResult<Expr> {
    let mut left = parse_eq(ps)?;
    while ps.eat_ident("and") {
        let right = parse_eq(ps)?;
        left = Expr::And(Box::new(left), Box::new(right));
    }
    Ok(left)
}

fn bin_level(ps: &mut PState, punct: &str, ctor: fn(Box<Expr>, Box<Expr>) -> Expr,
             lower: fn(&mut PState) -> YResult<Expr>) -> YResult<Expr> {
    let mut left = lower(ps)?;
    loop {
        match ps.peek() {
            Some(Tok::Punct(s)) if s == punct => {
                ps.bump();
                let right = lower(ps)?;
                left = ctor(Box::new(left), Box::new(right));
            }
            _ => break,
        }
    }
    Ok(left)
}

// Precedence (high -> low): shift, bit-and, bit-xor, bit-or, relational,
// equality, logical-and, logical-or.
fn parse_eq(ps: &mut PState) -> YResult<Expr> {
    let mut left = parse_rel(ps)?;
    loop {
        let op = match ps.peek() {
            Some(Tok::Punct(s)) if s == "==" || s == "!=" => s.clone(),
            _ => break,
        };
        ps.bump();
        let right = parse_rel(ps)?;
        left = if op == "==" {
            Expr::Eq(Box::new(left), Box::new(right))
        } else {
            Expr::Ne(Box::new(left), Box::new(right))
        };
    }
    Ok(left)
}

fn parse_rel(ps: &mut PState) -> YResult<Expr> {
    let mut left = parse_bit_or(ps)?;
    loop {
        let op = match ps.peek() {
            Some(Tok::Punct(s)) if matches!(s.as_str(), "<" | "<=" | ">" | ">=") => s.clone(),
            _ => break,
        };
        ps.bump();
        let right = parse_bit_or(ps)?;
        left = match op.as_str() {
            "<" => Expr::Lt(Box::new(left), Box::new(right)),
            "<=" => Expr::Le(Box::new(left), Box::new(right)),
            ">" => Expr::Gt(Box::new(left), Box::new(right)),
            _ => Expr::Ge(Box::new(left), Box::new(right)),
        };
    }
    Ok(left)
}

fn parse_bit_or(ps: &mut PState) -> YResult<Expr> {
    bin_level(ps, "|", Expr::BitOr, parse_bit_xor)
}
fn parse_bit_xor(ps: &mut PState) -> YResult<Expr> {
    bin_level(ps, "^", Expr::Xor, parse_bit_and)
}
fn parse_bit_and(ps: &mut PState) -> YResult<Expr> {
    bin_level(ps, "&", Expr::BitAnd, parse_shift)
}

fn parse_shift(ps: &mut PState) -> YResult<Expr> {
    let mut left = parse_add(ps)?;
    loop {
        let op = match ps.peek() {
            Some(Tok::Punct(s)) if s == "<<" || s == ">>" => s.clone(),
            _ => break,
        };
        ps.bump();
        let right = parse_add(ps)?;
        left = if op == "<<" {
            Expr::Shl(Box::new(left), Box::new(right))
        } else {
            Expr::Shr(Box::new(left), Box::new(right))
        };
    }
    Ok(left)
}

fn parse_add(ps: &mut PState) -> YResult<Expr> {
    let mut left = parse_mul(ps)?;
    loop {
        match ps.peek() {
            Some(Tok::Punct(s)) if s == "+" || s == "-" => {
                let op = s.clone();
                ps.bump();
                let right = parse_mul(ps)?;
                left = if op == "+" {
                    Expr::Add(Box::new(left), Box::new(right))
                } else {
                    Expr::Sub(Box::new(left), Box::new(right))
                };
            }
            _ => break,
        }
    }
    Ok(left)
}

fn parse_mul(ps: &mut PState) -> YResult<Expr> {
    let mut left = parse_unary(ps)?;
    loop {
        match ps.peek() {
            Some(Tok::Punct(s)) if matches!(s.as_str(), "*" | "/" | "%") => {
                let op = s.clone();
                ps.bump();
                let right = parse_unary(ps)?;
                left = match op.as_str() {
                    "*" => Expr::Mul(Box::new(left), Box::new(right)),
                    "/" => Expr::Div(Box::new(left), Box::new(right)),
                    _ => Expr::Mod(Box::new(left), Box::new(right)),
                };
            }
            _ => break,
        }
    }
    Ok(left)
}

fn parse_unary(ps: &mut PState) -> YResult<Expr> {
    if ps.eat_punct("!") {
        // `!(` / `!true` style boolean negation vs `!a` string-length op.
        if matches!(ps.peek(), Some(Tok::Punct(p)) if p == "(") {
            return Ok(Expr::Not(Box::new(parse_unary(ps)?)));
        }
        return parse_string_ref_with(ps, StrOp::Length);
    }
    if ps.eat_punct("-") {
        return Ok(Expr::Neg(Box::new(parse_unary(ps)?)));
    }
    if ps.eat_ident("not") {
        return Ok(Expr::Not(Box::new(parse_unary(ps)?)));
    }
    parse_primary(ps)
}

fn parse_primary(ps: &mut PState) -> YResult<Expr> {
    let tok = match ps.peek().cloned() {
        Some(t) => t,
        None => return crate::err(ps.line(), "unexpected end of condition"),
    };
    match tok {
        Tok::Int(v) => {
            ps.bump();
            // numeric quantifier: `N of ($a, $b)`
            if ps.eat_ident("of") {
                let set = if ps.eat_ident("them") {
                    StringSet::Wildcard("*".to_string())
                } else {
                    parse_string_set(ps)?
                };
                return Ok(Expr::Of { quant: Quant::Expr(Box::new(Expr::Int(v))), set });
            }
            Ok(Expr::Int(v))
        }
        Tok::Punct(p) if p == "(" => {
            ps.bump();
            let e = parse_expr(ps)?;
            ps.expect_punct(")")?;
            // parenthesized quantifier: `(25%) of (...)` — percentage form is
            // not supported; plain `(expr) of ...` is rare and skipped here.
            Ok(e)
        }
        Tok::Punct(p) if p == "$" => parse_string_ref_with(ps, StrOp::Found),
        Tok::Punct(p) if p == "#" => parse_string_ref_with(ps, StrOp::Count),
        Tok::Punct(p) if p == "@" => parse_string_ref_with(ps, StrOp::Offset),
        Tok::Ident(kw) => parse_ident_primary(ps, kw),
        other => crate::err(ps.line(), format!("unexpected token in condition: {other:?}")),
    }
}

fn parse_string_ref_with(ps: &mut PState, op: StrOp) -> YResult<Expr> {
    // leading punctuation ($/#/@/!) was consumed by the caller; for the
    // parse_primary '$'/'#'/'@' routes consume it now.
    if matches!(op, StrOp::Found | StrOp::Count | StrOp::Offset) {
        ps.bump();
    }
    let name = if let Some(Tok::Ident(s)) = ps.peek().cloned() {
        ps.bump();
        s
    } else {
        String::new()
    };
    let mut index = None;
    if matches!(op, StrOp::Offset | StrOp::Length) && ps.eat_punct("[") {
        index = Some(Box::new(parse_expr(ps)?));
        ps.expect_punct("]")?;
    }
    Ok(Expr::StringId { name, op, index })
}

fn parse_ident_primary(ps: &mut PState, kw: String) -> YResult<Expr> {
    match kw.as_str() {
        "true" => {
            ps.bump();
            Ok(Expr::Bool(true))
        }
        "false" => {
            ps.bump();
            Ok(Expr::Bool(false))
        }
        "filesize" => {
            ps.bump();
            Ok(Expr::Filesize)
        }
        "entrypoint" => {
            ps.bump();
            Ok(Expr::Entrypoint)
        }
        "uint8" | "uint16" | "uint32" | "uint16be" | "uint32be" | "int8" | "int16"
        | "int32" | "int16be" | "int32be" => parse_uint_call(ps, &kw),
        "any" | "all" | "none" => {
            ps.bump();
            let quant = if kw == "any" {
                Quant::Any
            } else if kw == "all" {
                Quant::All
            } else {
                Quant::None
            };
            parse_of_or_for(ps, quant)
        }
        "for" => parse_for(ps),
        _ => {
            ps.bump();
            Ok(Expr::Ident(kw))
        }
    }
}

fn parse_uint_call(ps: &mut PState, name: &str) -> YResult<Expr> {
    ps.bump();
    ps.expect_punct("(")?;
    let arg = parse_expr(ps)?;
    ps.expect_punct(")")?;
    let be = name.ends_with("be");
    let width = if name.starts_with("uint8") || name.starts_with("int8") {
        1
    } else if name.contains("16") {
        2
    } else {
        4
    };
    Ok(Expr::Uint { width, be, arg: Box::new(arg) })
}

fn parse_string_set(ps: &mut PState) -> YResult<StringSet> {
    ps.expect_punct("(")?;
    let mut names = Vec::new();
    let mut wildcard = None;
    loop {
        match ps.peek().cloned() {
            Some(Tok::Punct(p)) if p == "$" || p == "#" => {
                ps.bump();
                let name = if let Some(Tok::Ident(s)) = ps.peek().cloned() {
                    ps.bump();
                    s
                } else {
                    String::new()
                };
                // wildcard?
                if ps.eat_punct("*") {
                    wildcard = Some(format!("{name}*"));
                } else {
                    names.push(name);
                }
            }
            Some(Tok::Punct(p)) if p == ")" => {
                ps.bump();
                break;
            }
            other => return crate::err(ps.line(), format!("bad string set element: {other:?}")),
        }
        if !ps.eat_punct(",") {
            ps.expect_punct(")")?;
            break;
        }
    }
    if let Some(w) = wildcard {
        Ok(StringSet::Wildcard(w))
    } else {
        Ok(StringSet::List(names))
    }
}

fn parse_of_or_for(ps: &mut PState, quant: Quant) -> YResult<Expr> {
    if !ps.eat_ident("of") {
        return crate::err(ps.line(), "expected 'of'");
    }
    // `of them`
    if ps.eat_ident("them") {
        let set = StringSet::Wildcard("*".to_string());
        return Ok(Expr::Of { quant, set });
    }
    // numeric quantifier like "2 of ($a,$b)" is handled via primary Int path;
    // here only any/all/none reach this function.
    let set = parse_string_set(ps)?;
    Ok(Expr::Of { quant, set })
}

fn parse_for(ps: &mut PState) -> YResult<Expr> {
    ps.bump(); // for
    let quant = if ps.eat_ident("any") {
        Quant::Any
    } else if ps.eat_ident("all") {
        Quant::All
    } else if ps.eat_ident("none") {
        Quant::None
    } else {
        // numeric quantifier: consume just the integer, leaving `of` intact
        match ps.bump() {
            Some(Tok::Int(n)) => Quant::Expr(Box::new(Expr::Int(n))),
            other => {
                return crate::err(ps.line(), format!("for quantifier expected, got {other:?}"))
            }
        }
    };
    if !ps.eat_ident("of") {
        return crate::err(ps.line(), "expected 'of' after for quantifier");
    }
    let set = if ps.eat_ident("them") {
        StringSet::Wildcard("*".to_string())
    } else {
        parse_string_set(ps)?
    };
    ps.expect_punct(":")?;
    ps.expect_punct("(")?;
    let body = parse_expr(ps)?;
    ps.expect_punct(")")?;
    Ok(Expr::For { quant, set, body: Box::new(body) })
}

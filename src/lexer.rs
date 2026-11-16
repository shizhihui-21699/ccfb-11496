//! Lexer for the YARA-compatible subset.
//!
//! Two special states:
//!   * after `=` in the strings section, `/` starts a regex literal instead of
//!     a division operator (YARA has no division in conditions anyway).
//!   * `{` after `=` starts a hex pattern; the lexer exposes the raw body via
//!     `read_hex_body`, the dedicated hex parser consumes it.

use crate::error::{err, YaraError, YResult};

#[derive(Debug, Clone, PartialEq)]
pub enum Tok {
    // literals / names
    Ident(String),
    Int(i64),
    /// text string literal (already unescaped)
    Text(Vec<u8>),
    /// regex literal, raw body between the slashes
    Regex(String),
    /// string identifier: ($name) or anonymous ($10); wildcard flag for $*
    StrId(String, bool),
    /// #name : match count
    CountId(String),
    /// @name : match offset
    OffsetId(String),
    /// !name : match length
    LengthId(String),
    // keywords
    Rule, Private, Global, Strings, Condition, Meta, Import, Include,
    True, False, Not, And, Or,
    Ascii, Wide, Nocase, Fullword, Xor, Base64, Base64Wide,
    At, In, Of, For, Any, All, Them, None,
    Filesize, Entrypoint,
    // punctuation / operators
    LParen, RParen, LBrace, RBrace, LBracket, RBracket,
    Eq, Ne, Lt, Le, Gt, Ge, Assign,
    Plus, Minus, Star, Percent,
    Dot, DotDot, Comma, Colon, Tilde, Amp, Pipe, Caret, LtLt, GtGt,
    HexBody(String),
    Eof,
}

#[derive(Debug, Clone)]
pub struct Token {
    pub tok: Tok,
    pub line: usize,
}

pub struct Lexer<'a> {
    pub(crate) b: &'a [u8],
    pub(crate) pos: usize,
    pub(crate) line: usize,
    /// Set right after the '=' of a pattern definition so the following '{'
    /// is read as a hex body. The parser toggles it via the token stream:
    /// Assign in the strings section arms it; any other token disarms it.
    pub(crate) hex_expected: bool,
    /// Tracks whether we are inside a rule's strings section.
    pub(crate) in_strings: bool,
    /// Pending '=' seen in strings section.
    pub(crate) pattern_assign_pending: bool,
}

fn is_ident_start(c: u8) -> bool {
    c == b'_' || c.is_ascii_alphabetic()
}
fn is_ident(c: u8) -> bool {
    c == b'_' || c.is_ascii_alphanumeric()
}

impl<'a> Lexer<'a> {
    pub fn new(src: &'a str) -> Self {
        Lexer {
            b: src.as_bytes(),
            pos: 0,
            line: 1,
            hex_expected: false,
            in_strings: false,
            pattern_assign_pending: false,
        }
    }

    pub fn set_hex_expected(&mut self, v: bool) {
        self.hex_expected = v;
    }

    pub(crate) fn peek(&self) -> Option<u8> {
        self.b.get(self.pos).copied()
    }
    pub(crate) fn peek2(&self) -> Option<u8> {
        self.b.get(self.pos + 1).copied()
    }
    pub(crate) fn bump(&mut self) -> Option<u8> {
        let c = self.peek()?;
        self.pos += 1;
        if c == b'\n' {
            self.line += 1;
        }
        Some(c)
    }

    fn skip_ws_comments(&mut self) {
        loop {
            match self.peek() {
                Some(c) if c.is_ascii_whitespace() => {
                    self.bump();
                }
                Some(b'/') if self.peek2() == Some(b'/') => {
                    while let Some(c) = self.peek() {
                        if c == b'\n' {
                            break;
                        }
                        self.bump();
                    }
                }
                Some(b'/') if self.peek2() == Some(b'*') => {
                    self.bump();
                    self.bump();
                    while let Some(c) = self.peek() {
                        if c == b'*' && self.peek2() == Some(b'/') {
                            self.bump();
                            self.bump();
                            break;
                        }
                        self.bump();
                    }
                }
                _ => break,
            }
        }
    }

    fn read_ident(&mut self) -> String {
        let start = self.pos;
        while let Some(c) = self.peek() {
            if !is_ident(c) {
                break;
            }
            self.bump();
        }
        String::from_utf8_lossy(&self.b[start..self.pos]).into_owned()
    }

    fn keyword_or_ident(name: &str) -> Tok {
        match name {
            "rule" => Tok::Rule,
            "private" => Tok::Private,
            "global" => Tok::Global,
            "strings" => Tok::Strings,
            "condition" => Tok::Condition,
            "meta" => Tok::Meta,
            "import" => Tok::Import,
            "include" => Tok::Include,
            "true" => Tok::True,
            "false" => Tok::False,
            "not" => Tok::Not,
            "and" => Tok::And,
            "or" => Tok::Or,
            "ascii" => Tok::Ascii,
            "wide" => Tok::Wide,
            "nocase" => Tok::Nocase,
            "fullword" => Tok::Fullword,
            "xor" => Tok::Xor,
            "base64" => Tok::Base64,
            "base64wide" => Tok::Base64Wide,
            "at" => Tok::At,
            "in" => Tok::In,
            "of" => Tok::Of,
            "for" => Tok::For,
            "any" => Tok::Any,
            "all" => Tok::All,
            "them" => Tok::Them,
            "none" => Tok::None,
            "filesize" => Tok::Filesize,
            "entrypoint" => Tok::Entrypoint,
            _ => Tok::Ident(name.to_string()),
        }
    }

    fn read_number(&mut self) -> YResult<Token> {
        let line = self.line;
        if self.peek() == Some(b'0') && matches!(self.peek2(), Some(b'x') | Some(b'X')) {
            self.bump();
            self.bump();
            let start = self.pos;
            while let Some(c) = self.peek() {
                if c.is_ascii_hexdigit() {
                    self.bump();
                } else {
                    break;
                }
            }
            let s = std::str::from_utf8(&self.b[start..self.pos]).unwrap();
            if s.is_empty() {
                return err("malformed hex literal", line);
            }
            let v = i64::from_str_radix(s, 16)
                .map_err(|_| YaraError::new("integer literal out of range", line))?;
            return Ok(Token { tok: Tok::Int(v), line });
        }
        let start = self.pos;
        let mut v: i64 = 0;
        while let Some(c) = self.peek() {
            if c.is_ascii_digit() {
                self.bump();
                v = v
                    .checked_mul(10)
                    .and_then(|x| x.checked_add((c - b'0') as i64))
                    .ok_or_else(|| YaraError::new("integer literal out of range", line))?;
            } else {
                break;
            }
        }
        let _ = start;
        Ok(Token { tok: Tok::Int(v), line })
    }

    /// Unescape a double-quoted YARA text literal. `src` is the content
    /// between the quotes.
    pub fn unescape_text(src: &str, line: usize) -> YResult<Vec<u8>> {
        let mut out = Vec::with_capacity(src.len());
        let mut it = src.bytes();
        while let Some(c) = it.next() {
            if c != b'\\' {
                out.push(c);
                continue;
            }
            let e = it
                .next()
                .ok_or_else(|| YaraError::new("trailing backslash in string", line))?;
            match e {
                b'n' => out.push(b'\n'),
                b'r' => out.push(b'\r'),
                b't' => out.push(b'\t'),
                b'f' => out.push(0x0c),
                b'a' => out.push(0x07),
                b'v' => out.push(0x0b),
                b'0' => out.push(0),
                b'\\' => out.push(b'\\'),
                b'"' => out.push(b'"'),
                b'\'' => out.push(b'\''),
                b'x' => {
                    let h1 = it
                        .next()
                        .ok_or_else(|| YaraError::new("bad \\x escape", line))?;
                    let h2 = it
                        .next()
                        .ok_or_else(|| YaraError::new("bad \\x escape", line))?;
                    let s = [h1, h2];
                    let ss = std::str::from_utf8(&s).unwrap();
                    let v = u8::from_str_radix(ss, 16)
                        .map_err(|_| YaraError::new("bad \\x escape", line))?;
                    out.push(v);
                }
                b'u' => {
                    let mut digits = [0u8; 4];
                    for d in digits.iter_mut() {
                        *d = it
                            .next()
                            .ok_or_else(|| YaraError::new("bad \\u escape", line))?;
                    }
                    let ss = std::str::from_utf8(&digits).unwrap();
                    let v = u32::from_str_radix(ss, 16)
                        .map_err(|_| YaraError::new("bad \\u escape", line))?;
                    if let Some(ch) = char::from_u32(v) {
                        let mut buf = [0u8; 4];
                        out.extend_from_slice(ch.encode_utf8(&mut buf).as_bytes());
                    } else {
                        return err("bad \\u escape", line);
                    }
                }
                other => {
                    // YARA keeps unknown escapes as the literal char.
                    out.push(other);
                }
            }
        }
        Ok(out)
    }

    fn read_text_string(&mut self) -> YResult<Token> {
        let line = self.line;
        self.bump(); // opening quote
        let start = self.pos;
        while let Some(c) = self.peek() {
            if c == b'\\' {
                self.bump();
                self.bump();
                continue;
            }
            if c == b'"' {
                break;
            }
            self.bump();
        }
        if self.peek() != Some(b'"') {
            return err("unterminated string literal", line);
        }
        let raw = std::str::from_utf8(&self.b[start..self.pos]).unwrap();
        let val = Self::unescape_text(raw, line)?;
        self.bump(); // closing quote
        Ok(Token { tok: Tok::Text(val), line })
    }

    fn read_regex(&mut self) -> YResult<Token> {
        let line = self.line;
        self.bump(); // opening slash
        let start = self.pos;
        let mut in_class = false;
        while let Some(c) = self.peek() {
            if c == b'\\' {
                self.bump();
                if self.peek().is_none() {
                    return err("unterminated regex", line);
                }
                self.bump();
                continue;
            }
            if c == b'[' {
                in_class = true;
            }
            if c == b']' {
                in_class = false;
            }
            if c == b'/' && !in_class {
                break;
            }
            if c == b'\n' {
                return err("newline in regex", line);
            }
            self.bump();
        }
        if self.peek() != Some(b'/') {
            return err("unterminated regex", line);
        }
        let raw = std::str::from_utf8(&self.b[start..self.pos]).unwrap().to_string();
        self.bump();
        Ok(Token { tok: Tok::Regex(raw), line })
    }

    /// Consume a hex pattern body. The opening '{' has already been consumed,
    /// so `self.pos` points at the first body byte; reads through the matching
    /// closing '}'.
    fn read_hex_body_after_brace(&mut self) -> YResult<Token> {
        let line = self.line;
        let start = self.pos;
        let mut depth = 1usize;
        while let Some(c) = self.peek() {
            match c {
                b'{' => depth += 1,
                b'}' => {
                    depth -= 1;
                    if depth == 0 {
                        break;
                    }
                }
                b'"' => {
                    // embedded text string inside hex pattern
                    self.bump();
                    while let Some(d) = self.peek() {
                        if d == b'\\' {
                            self.bump();
                            self.bump();
                            continue;
                        }
                        if d == b'"' {
                            break;
                        }
                        self.bump();
                    }
                }
                _ => {}
            }
            self.bump();
        }
        if self.peek() != Some(b'}') {
            return err("unterminated hex pattern", line);
        }
        let raw = std::str::from_utf8(&self.b[start..self.pos]).unwrap().to_string();
        self.bump(); // closing }
        Ok(Token { tok: Tok::HexBody(raw), line })
    }

    pub fn next_token(&mut self) -> YResult<Token> {
        let t = self.next_raw()?;
        match &t.tok {
            Tok::Strings => self.in_strings = true,
            Tok::Condition => {
                self.in_strings = false;
                self.pattern_assign_pending = false;
                self.hex_expected = false;
            }
            // The body token immediately follows the assignment; disarm now.
            Tok::Text(_) | Tok::Regex(_) | Tok::HexBody(_) => {
                self.pattern_assign_pending = false;
                self.hex_expected = false;
            }
            Tok::LBrace => {
                // rule-body brace (a hex body would already have been consumed)
                self.hex_expected = false;
                self.pattern_assign_pending = false;
            }
            _ => {}
        }
        Ok(t)
    }

    fn next_raw(&mut self) -> YResult<Token> {
        self.skip_ws_comments();
        let line = self.line;
        let c = match self.peek() {
            None => return Ok(Token { tok: Tok::Eof, line }),
            Some(c) => c,
        };

        // $ identifier, $* wildcard set, or $prefix* wildcard set
        if c == b'$' {
            self.bump();
            if self.peek() == Some(b'*') {
                self.bump();
                return Ok(Token { tok: Tok::StrId("*".to_string(), true), line });
            }
            let name = self.read_ident();
            if name.is_empty() {
                return err("expected string identifier after $", line);
            }
            if self.peek() == Some(b'*') {
                self.bump();
                return Ok(Token { tok: Tok::StrId(name, true), line });
            }
            return Ok(Token { tok: Tok::StrId(name, false), line });
        }

        // #id (count), @id (offset), !id (length); '!=' is the not-equal op
        if c == b'#' || c == b'@' || c == b'!' {
            if c == b'!' && self.peek2() == Some(b'=') {
                self.bump();
                self.bump();
                return Ok(Token { tok: Tok::Ne, line });
            }
            let marker = c;
            self.bump();
            let name = self.read_ident();
            if name.is_empty() {
                return err(format!("expected string identifier after '{}'", marker as char), line);
            }
            let tok = match marker {
                b'#' => Tok::CountId(name),
                b'@' => Tok::OffsetId(name),
                _ => Tok::LengthId(name),
            };
            return Ok(Token { tok, line });
        }

        if is_ident_start(c) {
            let name = self.read_ident();
            return Ok(Token { tok: Self::keyword_or_ident(&name), line });
        }
        if c.is_ascii_digit() {
            return self.read_number();
        }
        if c == b'"' {
            return self.read_text_string();
        }

        self.bump();
        let two = (c, self.peek());
        let tok = match c {
            b'(' => Tok::LParen,
            b')' => Tok::RParen,
            b'{' => {
                if self.hex_expected {
                    self.hex_expected = false;
                    // the '{' was already consumed by the shared bump above
                    return self.read_hex_body_after_brace();
                }
                Tok::LBrace
            }
            b'}' => Tok::RBrace,
            b'[' => Tok::LBracket,
            b']' => Tok::RBracket,
            b'+' => Tok::Plus,
            b'-' => Tok::Minus,
            b'*' => Tok::Star,
            b'%' => Tok::Percent,
            b'.' => match self.peek() {
                Some(b'.') => {
                    self.bump();
                    Tok::DotDot
                }
                _ => Tok::Dot,
            },
            b',' => Tok::Comma,
            b':' => Tok::Colon,
            b'~' => Tok::Tilde,
            b'&' => Tok::Amp,
            b'|' => Tok::Pipe,
            b'^' => Tok::Caret,
            b'=' => match self.peek() {
                Some(b'=') => {
                    self.bump();
                    Tok::Eq
                }
                _ => {
                    // A single '=' inside the strings section is a pattern
                    // assignment; arm hex detection immediately (not after the
                    // token is returned), so parser lookahead cannot race it.
                    if self.in_strings {
                        self.hex_expected = true;
                        self.pattern_assign_pending = true;
                    }
                    Tok::Assign
                }
            },
            b'!' => return err("stray '!' (only !string-id is valid)", line),
            b'<' => match self.peek() {
                Some(b'=') => {
                    self.bump();
                    Tok::Le
                }
                Some(b'<') => {
                    self.bump();
                    Tok::LtLt
                }
                _ => Tok::Lt,
            },
            b'>' => match self.peek() {
                Some(b'=') => {
                    self.bump();
                    Tok::Ge
                }
                Some(b'>') => {
                    self.bump();
                    Tok::GtGt
                }
                _ => Tok::Gt,
            },
            b'/' => {
                // YARA conditions have no division; a slash here is a regex
                // literal (only valid in the strings section by grammar).
                self.pos -= 1;
                if c == b'\n' {
                    self.line -= 1;
                }
                return self.read_regex();
            }
            other => {
                let _ = two;
                return err(format!("unexpected character '{}'", other as char), line);
            }
        };
        Ok(Token { tok, line })
    }
}

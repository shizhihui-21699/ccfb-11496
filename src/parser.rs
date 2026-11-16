//! Recursive-descent parser for the supported YARA rule subset.
//! Driven directly off the streaming lexer so hex bodies can be captured raw.

use crate::ast::*;
use crate::error::{err, YResult};
use crate::hex;
use crate::lexer::{Lexer, Tok, Token};
use crate::regex::Re;

pub struct Parser<'a> {
    lex: Lexer<'a>,
    cur: Token,
    ahead: Token,
    ordinal: usize,
}

impl<'a> Parser<'a> {
    pub fn parse_src(src: &'a str) -> YResult<Vec<Rule>> {
        let mut p = Parser {
            lex: Lexer::new(src),
            cur: Token { tok: Tok::Eof, line: 1 },
            ahead: Token { tok: Tok::Eof, line: 1 },
            ordinal: 0,
        };
        p.cur = p.lex.next_token()?;
        p.ahead = p.lex.next_token()?;
        let mut rules = Vec::new();
        loop {
            p.skip_imports()?;
            if matches!(p.peek().tok, Tok::Eof) {
                break;
            }
            rules.push(p.parse_rule()?);
        }
        Ok(rules)
    }

    fn peek(&self) -> &Token {
        &self.cur
    }
    fn peek_ahead(&self) -> &Token {
        &self.ahead
    }
    fn line(&self) -> usize {
        self.cur.line
    }
    fn bump(&mut self) -> YResult<Token> {
        let line = self.cur.line;
        let next = self.lex.next_token()?;
        let old = std::mem::replace(&mut self.cur, std::mem::replace(
            &mut self.ahead,
            Token { tok: Tok::Eof, line },
        ));
        self.ahead = next;
        Ok(old)
    }
    fn expect(&mut self, t: &Tok) -> YResult<Token> {
        if std::mem::discriminant(&self.peek().tok) == std::mem::discriminant(t) {
            self.bump()
        } else {
            err(format!("expected {:?}, got {:?}", t, self.peek().tok), self.line())
        }
    }
    fn eat(&mut self, t: &Tok) -> YResult<bool> {
        if std::mem::discriminant(&self.peek().tok) == std::mem::discriminant(t) {
            self.bump()?;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    fn skip_imports(&mut self) -> YResult<()> {
        loop {
            match self.peek().tok {
                Tok::Import | Tok::Include => {
                    self.bump()?;
                    if matches!(self.peek().tok, Tok::Text(_)) {
                        self.bump()?;
                    }
                }
                _ => break,
            }
        }
        Ok(())
    }

    fn parse_rule(&mut self) -> YResult<Rule> {
        let mut is_private = false;
        let mut is_global = false;
        while matches!(self.peek().tok, Tok::Private | Tok::Global) {
            match self.peek().tok {
                Tok::Private => is_private = true,
                Tok::Global => is_global = true,
                _ => {}
            }
            self.bump()?;
        }
        self.expect(&Tok::Rule)?;
        let name = match self.bump()?.tok {
            Tok::Ident(s) => s,
            other => return err(format!("expected rule name, got {:?}", other), self.line()),
        };
        if self.eat(&Tok::Colon)? {
            while !matches!(self.peek().tok, Tok::LBrace) {
                self.bump()?;
            }
        }
        self.expect(&Tok::LBrace)?;
        // The rule-body brace is never a hex pattern; clear any stale flag.
        self.lex.set_hex_expected(false);

        let mut patterns = Vec::new();
        if self.eat(&Tok::Meta)? {
            while !matches!(self.peek().tok, Tok::Strings | Tok::Condition) {
                self.bump()?;
            }
        }
        if self.eat(&Tok::Strings)? {
            self.expect(&Tok::Colon)?;
            self.ordinal = 0;
            while !matches!(self.peek().tok, Tok::Condition) {
                if matches!(self.peek().tok, Tok::Eof) {
                    return err("rule missing condition section", self.line());
                }
                patterns.push(self.parse_pattern()?);
            }
        }
        self.expect(&Tok::Condition)?;
        self.expect(&Tok::Colon)?;
        let condition = self.parse_condition()?;
        self.expect(&Tok::RBrace)?;
        Ok(Rule { name, is_private, is_global, patterns, condition })
    }

    fn parse_pattern(&mut self) -> YResult<Pattern> {
        let line = self.line();
        let id = match self.bump()?.tok {
            Tok::StrId(s, false) => s,
            other => return err(format!("expected string id, got {:?}", other), line),
        };
        self.expect(&Tok::Assign)?;
        let ordinal = self.ordinal;
        self.ordinal += 1;
        let mut p = Pattern {
            id,
            kind: PatternKind::Text,
            text: Vec::new(),
            hex: None,
            re: None,
            nocase: false,
            wide: false,
            ascii: false,
            fullword: false,
            ordinal,
        };
        match self.bump()?.tok {
            Tok::Text(bytes) => {
                p.kind = PatternKind::Text;
                p.text = bytes;
            }
            Tok::Regex(body) => {
                p.kind = PatternKind::Regex;
                p.re = Some(Re::compile(&body)?);
            }
            Tok::HexBody(body) => {
                p.kind = PatternKind::Hex;
                p.hex = Some(hex::parse_hex(&body)?);
            }
            other => return err(format!("expected pattern body, got {:?}", other), line),
        }
        loop {
            match self.peek().tok {
                Tok::Nocase => {
                    if p.kind == PatternKind::Hex {
                        return err("nocase cannot be applied to hex strings", self.line());
                    }
                    p.nocase = true;
                    self.bump()?;
                }
                Tok::Wide => {
                    p.wide = true;
                    self.bump()?;
                }
                Tok::Ascii => {
                    p.ascii = true;
                    self.bump()?;
                }
                Tok::Fullword => {
                    p.fullword = true;
                    self.bump()?;
                }
                Tok::Xor | Tok::Base64 | Tok::Base64Wide => {
                    return err("xor/base64 modifiers are not supported by this subset", self.line());
                }
                _ => break,
            }
        }
        Ok(p)
    }

    // ---- conditions ------------------------------------------------------

    fn parse_condition(&mut self) -> YResult<Condition> {
        self.parse_or()
    }

    fn parse_or(&mut self) -> YResult<Condition> {
        let mut left = self.parse_and()?;
        while self.eat(&Tok::Or)? {
            let right = self.parse_and()?;
            left = Condition::Bin(Box::new(left), BoolOp::Or, Box::new(right));
        }
        Ok(left)
    }

    fn parse_and(&mut self) -> YResult<Condition> {
        let mut left = self.parse_not()?;
        while self.eat(&Tok::And)? {
            let right = self.parse_not()?;
            left = Condition::Bin(Box::new(left), BoolOp::And, Box::new(right));
        }
        Ok(left)
    }

    fn parse_not(&mut self) -> YResult<Condition> {
        if self.eat(&Tok::Not)? {
            Ok(Condition::Not(Box::new(self.parse_not()?)))
        } else {
            self.parse_cmp()
        }
    }

    fn parse_cmp(&mut self) -> YResult<Condition> {
        let left = self.parse_primary_cond()?;
        let op = match self.peek().tok {
            Tok::Eq => CmpOp::Eq,
            Tok::Ne => CmpOp::Ne,
            Tok::Lt => CmpOp::Lt,
            Tok::Le => CmpOp::Le,
            Tok::Gt => CmpOp::Gt,
            Tok::Ge => CmpOp::Ge,
            _ => return Ok(left),
        };
        self.bump()?;
        let right = self.parse_primary_cond()?;
        match (left, right) {
            (Condition::IntLeaf(l), Condition::IntLeaf(r)) => Ok(Condition::Cmp(l, op, r)),
            _ => err("comparison requires integer expressions", self.line()),
        }
    }

    fn parse_primary_cond(&mut self) -> YResult<Condition> {
        if self.eat(&Tok::LParen)? {
            let inner = self.parse_condition()?;
            self.expect(&Tok::RParen)?;
            return Ok(inner);
        }
        match self.peek().tok.clone() {
            Tok::True => {
                self.bump()?;
                Ok(Condition::Bool(true))
            }
            Tok::False => {
                self.bump()?;
                Ok(Condition::Bool(false))
            }
            Tok::For => self.parse_for(),
            Tok::Any | Tok::All | Tok::None => self.parse_of_quant(),
            Tok::Int(_) => {
                // `N of (...)` is a quantifier, anything else is an integer.
                if matches!(self.peek_ahead().tok, Tok::Of) {
                    self.parse_of_quant()
                } else {
                    Ok(Condition::IntLeaf(self.parse_int()?))
                }
            }
            Tok::Filesize | Tok::CountId(_) | Tok::OffsetId(_) | Tok::LengthId(_)
            | Tok::Minus | Tok::Tilde => Ok(Condition::IntLeaf(self.parse_int()?)),
            Tok::StrId(name, wildcard) => {
                self.bump()?;
                if wildcard {
                    return err("wildcard string id only valid in 'of' sets", self.line());
                }
                match self.peek().tok {
                    Tok::At => {
                        self.bump()?;
                        let off = self.parse_int()?;
                        Ok(Condition::At(name, off))
                    }
                    Tok::In => {
                        self.bump()?;
                        let (lo, hi) = self.parse_range()?;
                        Ok(Condition::In(name, lo, hi))
                    }
                    _ => Ok(Condition::PatternDefined(name)),
                }
            }
            Tok::Ident(_) => {
                let s = match self.bump()?.tok {
                    Tok::Ident(s) => s,
                    _ => unreachable!(),
                };
                if matches!(self.peek().tok, Tok::Of) {
                    return err("identifier quantifiers other than any/all/none unsupported", self.line());
                }
                // Bare identifier: either a for-loop variable (integer) or a
                // cross-rule boolean reference. Evaluate as a rule name first;
                // loop variables are handled inside integer expressions.
                Ok(Condition::BoolId(s))
            }
            other => err(format!("unexpected token in condition: {:?}", other), self.line()),
        }
    }

    fn parse_for(&mut self) -> YResult<Condition> {
        self.expect(&Tok::For)?;
        let quant = self.parse_quantifier()?;
        let var = match self.bump()?.tok {
            Tok::Ident(s) => s,
            other => return err(format!("expected loop variable, got {:?}", other), self.line()),
        };
        self.expect(&Tok::In)?;
        let (lo, hi) = self.parse_range()?;
        self.expect(&Tok::Colon)?;
        self.expect(&Tok::LParen)?;
        let body = self.parse_condition()?;
        self.expect(&Tok::RParen)?;
        Ok(Condition::For { quant, var, lo, hi, body: Box::new(body) })
    }

    fn parse_range(&mut self) -> YResult<(IntExpr, IntExpr)> {
        self.expect(&Tok::LParen)?;
        let lo = self.parse_int()?;
        self.expect(&Tok::DotDot)?;
        let hi = self.parse_int()?;
        self.expect(&Tok::RParen)?;
        Ok((lo, hi))
    }

    fn parse_quantifier(&mut self) -> YResult<Quantifier> {
        match self.peek().tok.clone() {
            Tok::Any => {
                self.bump()?;
                Ok(Quantifier::Any)
            }
            Tok::All => {
                self.bump()?;
                Ok(Quantifier::All)
            }
            Tok::None => {
                self.bump()?;
                Ok(Quantifier::None)
            }
            _ => Ok(Quantifier::Expr(self.parse_int()?)),
        }
    }

    fn parse_of_quant(&mut self) -> YResult<Condition> {
        let quant = self.parse_quantifier()?;
        self.expect(&Tok::Of)?;
        let set = self.parse_string_set()?;
        Ok(Condition::Of(quant, set))
    }

    fn parse_string_set(&mut self) -> YResult<StringSet> {
        // Bare `them` has no parentheses: `any of them`
        if self.eat(&Tok::Them)? {
            return Ok(StringSet::Them);
        }
        self.expect(&Tok::LParen)?;
        if self.eat(&Tok::Them)? {
            self.expect(&Tok::RParen)?;
            return Ok(StringSet::Them);
        }
        let mut ids = Vec::new();
        loop {
            match self.bump()?.tok {
                Tok::StrId(s, wildcard) => {
                    if wildcard {
                        self.expect(&Tok::RParen)?;
                        return Ok(StringSet::Wildcard(s));
                    }
                    ids.push(s);
                }
                other => return err(format!("expected string id in set, got {:?}", other), self.line()),
            }
            if self.eat(&Tok::Comma)? {
                continue;
            }
            self.expect(&Tok::RParen)?;
            break;
        }
        Ok(StringSet::List(ids))
    }

    // ---- integer expressions --------------------------------------------

    fn parse_int(&mut self) -> YResult<IntExpr> {
        self.parse_bitor()
    }

    fn left_binop(
        &mut self,
        tok: &Tok,
        op: ArithOp,
        next: fn(&mut Self) -> YResult<IntExpr>,
    ) -> YResult<IntExpr> {
        let mut l = next(self)?;
        while self.eat(tok)? {
            let r = next(self)?;
            l = IntExpr::Bin(Box::new(l), op, Box::new(r));
        }
        Ok(l)
    }

    fn parse_bitor(&mut self) -> YResult<IntExpr> {
        self.left_binop(&Tok::Pipe, ArithOp::Or, Self::parse_bitand)
    }
    fn parse_bitand(&mut self) -> YResult<IntExpr> {
        self.left_binop(&Tok::Amp, ArithOp::And, Self::parse_bitxor)
    }
    fn parse_bitxor(&mut self) -> YResult<IntExpr> {
        self.left_binop(&Tok::Caret, ArithOp::Xor, Self::parse_shift)
    }
    fn parse_shift(&mut self) -> YResult<IntExpr> {
        let mut l = self.parse_add()?;
        loop {
            let op = match self.peek().tok {
                Tok::LtLt => ArithOp::Shl,
                Tok::GtGt => ArithOp::Shr,
                _ => break,
            };
            self.bump()?;
            let r = self.parse_add()?;
            l = IntExpr::Bin(Box::new(l), op, Box::new(r));
        }
        Ok(l)
    }
    fn parse_add(&mut self) -> YResult<IntExpr> {
        let mut l = self.parse_mul()?;
        loop {
            let op = match self.peek().tok {
                Tok::Plus => ArithOp::Add,
                Tok::Minus => ArithOp::Sub,
                _ => break,
            };
            self.bump()?;
            let r = self.parse_mul()?;
            l = IntExpr::Bin(Box::new(l), op, Box::new(r));
        }
        Ok(l)
    }
    fn parse_mul(&mut self) -> YResult<IntExpr> {
        let mut l = self.parse_unary()?;
        loop {
            let op = match self.peek().tok {
                Tok::Star => ArithOp::Mul,
                Tok::Percent => ArithOp::Mod,
                _ => break,
            };
            self.bump()?;
            let r = self.parse_unary()?;
            l = IntExpr::Bin(Box::new(l), op, Box::new(r));
        }
        Ok(l)
    }

    fn parse_unary(&mut self) -> YResult<IntExpr> {
        match self.peek().tok.clone() {
            Tok::Minus => {
                self.bump()?;
                Ok(IntExpr::Neg(Box::new(self.parse_unary()?)))
            }
            Tok::Tilde => {
                self.bump()?;
                Ok(IntExpr::Not(Box::new(self.parse_unary()?)))
            }
            _ => self.parse_int_primary(),
        }
    }

    fn parse_int_primary(&mut self) -> YResult<IntExpr> {
        let line = self.line();
        match self.bump()?.tok {
            Tok::Int(n) => Ok(IntExpr::Const(n)),
            Tok::Filesize => Ok(IntExpr::Filesize),
            Tok::Entrypoint => err("entrypoint is deprecated and unsupported", line),
            Tok::CountId(name) => Ok(IntExpr::Count(name)),
            Tok::OffsetId(name) => {
                let idx = if self.eat(&Tok::LBracket)? {
                    let e = self.parse_int()?;
                    self.expect(&Tok::RBracket)?;
                    Some(Box::new(e))
                } else {
                    None
                };
                Ok(IntExpr::Offset(name, idx))
            }
            Tok::LengthId(name) => {
                let idx = if self.eat(&Tok::LBracket)? {
                    let e = self.parse_int()?;
                    self.expect(&Tok::RBracket)?;
                    Some(Box::new(e))
                } else {
                    None
                };
                Ok(IntExpr::Length(name, idx))
            }
            Tok::LParen => {
                let inner = self.parse_int()?;
                self.expect(&Tok::RParen)?;
                Ok(inner)
            }
            Tok::Ident(name) => Ok(IntExpr::Var(name)),
            other => err(format!("unexpected token in integer expression: {:?}", other), line),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn names(src: &str) -> Vec<String> {
        Parser::parse_src(src).unwrap().iter().map(|r| r.name.clone()).collect()
    }

    #[test]
    fn parses_all_sections() {
        let src = r#"
        rule a : tag1 {
            meta: author = "t"
            strings:
                $x = "MZ" nocase
                $h = { 4d 5a [1-2] 90 }
                $r = /m[0-9]z/ wide
            condition:
                $x and #h > 0 and for any i in (0..2) : ( $r at i )
        }
        "#;
        let rules = Parser::parse_src(src).unwrap();
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].patterns.len(), 3);
        assert!(rules[0].patterns[0].nocase);
        assert!(rules[0].patterns[2].wide);
    }

    #[test]
    fn parses_hex_with_wildcards_and_jumps() {
        let rules = Parser::parse_src("rule h { strings: $a = { 12 ?? 3? [0-] ( ab | cd ) } condition: $a }").unwrap();
        assert!(rules[0].patterns[0].hex.is_some());
    }

    #[test]
    fn parses_of_and_them() {
        let src = "rule q { strings: $a=\"x\" $b=\"y\" condition: any of them and 2 of ($a,$b) }";
        let rules = Parser::parse_src(src).unwrap();
        assert_eq!(rules.len(), 1);
    }

    #[test]
    fn rejects_unsupported_modifier() {
        let r = Parser::parse_src("rule q { strings: $a = \"x\" xor condition: $a }");
        assert!(r.is_err());
    }

    #[test]
    fn multiple_rules_preserve_order() {
        let src = "rule z { condition: true } rule a { condition: false } rule m { condition: true }";
        assert_eq!(names(src), vec!["z", "a", "m"]);
    }
}

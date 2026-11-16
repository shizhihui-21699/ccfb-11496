//! Rule and condition AST, plus pattern descriptors used at scan time.

use crate::hex::HexNode;
use crate::regex::Re;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PatternKind {
    Text,
    Hex,
    Regex,
}

#[derive(Debug, Clone)]
pub struct Pattern {
    pub id: String,            // without '$'
    pub kind: PatternKind,
    pub text: Vec<u8>,         // text: literal bytes
    pub hex: Option<HexNode>,  // hex: parsed tree
    pub re: Option<Re>,        // regex: compiled tree
    pub nocase: bool,
    pub wide: bool,
    pub ascii: bool,
    pub fullword: bool,
    /// original index in rule order
    #[allow(dead_code)]
    pub ordinal: usize,
}

impl Pattern {
    /// Effective encodings after YARA defaulting rules.
    pub fn encodings(&self) -> Vec<bool> {
        // returns [ascii_enabled, wide_enabled]
        if self.ascii || self.wide {
            [self.ascii, self.wide].to_vec()
        } else {
            vec![true, false] // default is ascii only
        }
    }
}

#[derive(Debug, Clone)]
pub enum IntExpr {
    Const(i64),
    Filesize,
    /// for-loop variable
    Var(String),
    /// count of a pattern: #a
    Count(String),
    /// offset of nth match: @a or @a[n]
    Offset(String, Option<Box<IntExpr>>),
    /// length of nth match: !a or !a[n]
    Length(String, Option<Box<IntExpr>>),
    Neg(Box<IntExpr>),
    Not(Box<IntExpr>),
    Bin(Box<IntExpr>, ArithOp, Box<IntExpr>),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArithOp {
    Add,
    Sub,
    Mul,
    Mod,
    And,
    Or,
    Xor,
    Shl,
    Shr,
}

#[derive(Debug, Clone)]
pub enum Condition {
    Bool(bool),
    IntLeaf(IntExpr),
    BoolId(String), // user-defined boolean identifier (treated as undefined)
    PatternDefined(String), // $a
    Not(Box<Condition>),
    Bin(Box<Condition>, BoolOp, Box<Condition>),
    Cmp(IntExpr, CmpOp, IntExpr),
    /// $a at expr
    At(String, IntExpr),
    /// $a in (lo .. hi)
    In(String, IntExpr, IntExpr),
    /// quantifier of string-set: any/all/none/expr of (...)
    Of(Quantifier, StringSet),
    /// for quantifier i in (lo .. hi) : ( condition )
    For {
        quant: Quantifier,
        var: String,
        lo: IntExpr,
        hi: IntExpr,
        body: Box<Condition>,
    },
}

#[derive(Debug, Clone)]
pub enum Quantifier {
    Any,
    All,
    None,
    Expr(IntExpr),
}

#[derive(Debug, Clone)]
pub enum StringSet {
    /// explicit list of pattern ids
    List(Vec<String>),
    /// `them` — every pattern in the rule
    Them,
    /// wildcard set, e.g. $foo*
    Wildcard(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BoolOp {
    And,
    Or,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CmpOp {
    Eq,
    Ne,
    Lt,
    Le,
    Gt,
    Ge,
}

#[derive(Debug, Clone)]
pub struct Rule {
    pub name: String,
    pub is_private: bool,
    #[allow(dead_code)]
    pub is_global: bool,
    pub patterns: Vec<Pattern>,
    pub condition: Condition,
}

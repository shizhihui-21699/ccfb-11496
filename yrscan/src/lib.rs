//! yrscan: a zero-dependency YARA-compatible subset scanner.
//!
//! Module layout:
//! - [`hexpat`]: hex string parsing ({ 41 ?? [1-3] ... })
//! - [`regex`]: small backtracking regex engine (RE2-style subset)
//! - [`parser`]: rule file parser (strings + condition)
//! - [`aho`]: Aho-Corasick multi-pattern prefilter (atom extraction)
//! - [`compile`]: atom extraction + compiled rule set
//! - [`scan`]: per-file scanning, mmap, thread pool
//! - [`mmap`]: portable mmap wrapper

pub mod aho;
pub mod compile;
pub mod hexpat;
pub mod mmap;
pub mod parser;
pub mod regex;
pub mod scan;

use std::fmt;

#[derive(Debug)]
pub struct YError {
    pub msg: String,
    pub line: usize,
}

impl fmt::Display for YError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "line {}: {}", self.line, self.msg)
    }
}

impl std::error::Error for YError {}

pub type YResult<T> = Result<T, YError>;

pub fn err<T>(line: usize, msg: impl Into<String>) -> YResult<T> {
    Err(YError { msg: msg.into(), line })
}

/// ASCII case-insensitive equality for a single byte.
#[inline]
pub fn eq_nocase(a: u8, b: u8) -> bool {
    a.eq_ignore_ascii_case(&b)
}

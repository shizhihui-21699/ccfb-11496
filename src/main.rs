//! mini-yara: a dependency-free YARA-compatible subset scanner.
//!
//! Usage:
//!   mini-yara [options] RULES_FILE TARGET
//!   mini-yara [options] RULES_FILE TARGET_DIR ...
//!
//! Options:
//!   -t N      scanner thread count for directory scans (default: num CPUs)
//!   -r        recurse into directories (default: always recurse)
//!   -s        print matched strings with offsets
//!   --no-mmap disable memory mapping
//!   -h / --help

mod aho;
mod ast;
mod error;
mod eval;
mod hex;
mod lexer;
mod mmap;
mod parser;
mod regex;
mod scanner;

use std::collections::HashMap;
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use crate::error::{err, YResult};
use crate::eval::Eval;
use crate::mmap::FileBytes;
use crate::scanner::{CompiledRules, Match};

struct Args {
    rules_path: PathBuf,
    targets: Vec<PathBuf>,
    threads: usize,
    show_strings: bool,
    use_mmap: bool,
}

fn print_help() {
    println!(
        "mini-yara 0.1 — YARA-compatible subset scanner\n\
         Usage: mini-yara [options] RULES TARGET [TARGET...]\n\
         Options:\n\
         \x20 -t N       worker threads (default: available parallelism)\n\
         \x20 -s         show matched strings with offsets\n\
         \x20 --no-mmap  read files fully into memory instead of mmap\n\
         \x20 -h,--help  this help"
    );
}

fn parse_args(argv: Vec<String>) -> YResult<Args> {
    let mut rules_path = None;
    let mut targets = Vec::new();
    let mut threads = std::thread::available_parallelism().map(|n| n.get()).unwrap_or(4);
    let mut show_strings = false;
    let mut use_mmap = true;
    let mut it = argv.into_iter().skip(1);
    while let Some(a) = it.next() {
        match a.as_str() {
            "-h" | "--help" => {
                print_help();
                std::process::exit(0);
            }
            "-s" => show_strings = true,
            "-r" => {} // recursion is always on
            "--no-mmap" => use_mmap = false,
            "-t" => {
                let v = it.next().ok_or_else(|| crate::error::YaraError::new("-t needs a number", 0))?;
                threads = v.parse().map_err(|_| crate::error::YaraError::new("bad thread count", 0))?;
                threads = threads.max(1);
            }
            other if other.starts_with('-') && other != "-" => {
                return err(format!("unknown option {}", other), 0);
            }
            other => {
                if rules_path.is_none() {
                    rules_path = Some(PathBuf::from(other));
                } else {
                    targets.push(PathBuf::from(other));
                }
            }
        }
    }
    let rules_path = rules_path.ok_or_else(|| crate::error::YaraError::new("missing RULES file", 0))?;
    if targets.is_empty() {
        return err("missing TARGET", 0);
    }
    Ok(Args { rules_path, targets, threads, show_strings, use_mmap })
}

/// Resolve `include "path"` directives relative to the including file.
fn preprocess(path: &Path, seen: &mut Vec<PathBuf>) -> YResult<String> {
    let canonical = fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
    if seen.iter().any(|p| p == &canonical) {
        return Ok(String::new());
    }
    seen.push(canonical);
    let src = fs::read_to_string(path)
        .map_err(|e| crate::error::YaraError::new(format!("cannot read {}: {}", path.display(), e), 0))?;
    let base = path.parent().unwrap_or_else(|| Path::new("."));
    let mut out = String::with_capacity(src.len());
    for line in src.lines() {
        let t = line.trim_start();
        if let Some(rest) = t.strip_prefix("include") {
            let rest = rest.trim_start();
            if let Some(q1) = rest.find('"') {
                if let Some(q2) = rest[q1 + 1..].find('"') {
                    let inc = &rest[q1 + 1..q1 + 1 + q2];
                    let inc_path = base.join(inc);
                    out.push_str(&preprocess(&inc_path, seen)?);
                    out.push('\n');
                    continue;
                }
            }
        }
        out.push_str(line);
        out.push('\n');
    }
    Ok(out)
}

fn collect_files(target: &Path, errors: &mut Vec<String>) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let meta = match fs::symlink_metadata(target) {
        Ok(m) => m,
        Err(e) => {
            errors.push(format!("{}: {}", target.display(), e));
            return out;
        }
    };
    if meta.is_file() {
        out.push(target.to_path_buf());
        return out;
    }
    if !meta.is_dir() {
        errors.push(format!("{}: not a regular file or directory", target.display()));
        return out;
    }
    let mut stack = vec![target.to_path_buf()];
    while let Some(p) = stack.pop() {
        let m = match fs::symlink_metadata(&p) {
            Ok(m) => m,
            Err(e) => {
                errors.push(format!("{}: {}", p.display(), e));
                continue;
            }
        };
        if m.is_dir() {
            let entries = match fs::read_dir(&p) {
                Ok(e) => e,
                Err(e) => {
                    errors.push(format!("{}: {}", p.display(), e));
                    continue;
                }
            };
            for e in entries.flatten() {
                stack.push(e.path());
            }
        } else if m.is_file() {
            out.push(p);
        }
    }
    out.sort();
    out
}

struct FileResult {
    path: PathBuf,
    matched: Vec<(String, Option<Vec<(String, Match, String)>>)>,
    error: Option<String>,
}

/// Collect strings pinned to a constant offset by a top-level `$x at <const>`
/// condition. Mirrors YARA's `-s` behavior of showing only that match.
fn collect_at_offsets(c: &crate::ast::Condition) -> std::collections::HashMap<String, i64> {
    let mut map = std::collections::HashMap::new();
    fn walk(c: &crate::ast::Condition, map: &mut std::collections::HashMap<String, i64>) {
        match c {
            crate::ast::Condition::At(name, crate::ast::IntExpr::Const(v)) => {
                map.insert(name.clone(), *v);
            }
            crate::ast::Condition::Not(x) => walk(x, map),
            crate::ast::Condition::Bin(l, _, r) => {
                walk(l, map);
                walk(r, map);
            }
            crate::ast::Condition::For { body, .. } => walk(body, map),
            _ => {}
        }
    }
    walk(c, &mut map);
    map
}

/// Maximum bytes shown for one hex-pattern match in `yara -s`; longer matches
/// print the first 64 bytes followed by an ellipsis.
const HEX_DISPLAY_CAP: usize = 64;

/// Render matched bytes the way `yara -s` does.
fn format_bytes(bytes: &[u8], hex_style: bool) -> String {
    if hex_style {
        let shown = bytes.len().min(HEX_DISPLAY_CAP);
        let mut s = bytes[..shown]
            .iter()
            .map(|b| format!("{:02X}", b))
            .collect::<Vec<_>>()
            .join(" ");
        if bytes.len() > HEX_DISPLAY_CAP {
            s.push_str(" ...");
        }
        s
    } else {
        let mut out = String::with_capacity(bytes.len());
        for &b in bytes {
            if (0x20..=0x7e).contains(&b) {
                out.push(b as char);
            } else {
                out.push_str(&format!("\\x{:02X}", b));
            }
        }
        out
    }
}

fn scan_one(
    compiled: &CompiledRules,
    path: &Path,
    use_mmap: bool,
    show_strings: bool,
) -> FileResult {
    let run = || -> YResult<FileResult> {
        let file = fs::File::open(path)
            .map_err(|e| crate::error::YaraError::new(format!("open: {}", e), 0))?;
        let bytes: FileBytes = if use_mmap {
            FileBytes::load(&file)
                .map_err(|e| crate::error::YaraError::new(format!("mmap: {}", e), 0))?
        } else {
            let mut buf = Vec::new();
            let mut f = file;
            use std::io::Seek;
            f.seek(std::io::SeekFrom::Start(0)).ok();
            f.read_to_end(&mut buf)
                .map_err(|e| crate::error::YaraError::new(format!("read: {}", e), 0))?;
            FileBytes::Heap(buf)
        };
        let data = bytes.as_bytes();
        let tables = compiled.scan(data);
        let mut matched = Vec::new();
        // Cross-rule references resolve against rules evaluated earlier in
        // source order (the common YARA usage pattern).
        let mut rule_results: std::collections::HashMap<String, bool> =
            std::collections::HashMap::new();
        for (ri, rule) in compiled.rules.iter().enumerate() {
            let mut ev = Eval::new(rule, &tables[ri], data.len() as i64, &rule_results);
            let hit = ev.eval(&rule.condition);
            rule_results.insert(rule.name.clone(), hit);
            if hit && !rule.is_private {
                // YARA's `-s` only shows the match at the pinned offset when a
                // string is constrained by a literal `$x at <const>`.
                let pinned = collect_at_offsets(&rule.condition);
                let detail = if show_strings {
                    let mut d = Vec::new();
                    for (pi, pat) in rule.patterns.iter().enumerate() {
                        for m in &tables[ri][pi] {
                            if let Some(off) = pinned.get(&pat.id) {
                                if (m.offset as i64) != *off {
                                    continue;
                                }
                            }
                            let end = (m.offset + m.length).min(data.len());
                            let bytes = &data[m.offset..end];
                            let hex_style = pat.kind == crate::ast::PatternKind::Hex;
                            d.push((
                                format!("${}", pat.id),
                                m.clone(),
                                format_bytes(bytes, hex_style),
                            ));
                        }
                    }
                    d.sort_by_key(|(_, m, _)| m.offset);
                    Some(d)
                } else {
                    None
                };
                matched.push((rule.name.clone(), detail));
            }
        }
        Ok(FileResult { path: path.to_path_buf(), matched, error: None })
    };
    match run() {
        Ok(r) => r,
        Err(e) => FileResult {
            path: path.to_path_buf(),
            matched: Vec::new(),
            error: Some(e.to_string()),
        },
    }
}

fn main() {
    let argv: Vec<String> = std::env::args().collect();
    let args = match parse_args(argv) {
        Ok(a) => a,
        Err(e) => {
            eprintln!("mini-yara: {}", e);
            std::process::exit(1);
        }
    };

    let source = match preprocess(&args.rules_path, &mut Vec::new()) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("mini-yara: {}", e);
            std::process::exit(1);
        }
    };
    let rules = match parser::Parser::parse_src(&source) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("mini-yara: syntax error {}", e);
            std::process::exit(1);
        }
    };
    let compiled = match CompiledRules::compile(rules) {
        Ok(c) => Arc::new(c),
        Err(e) => {
            eprintln!("mini-yara: compile error {}", e);
            std::process::exit(1);
        }
    };

    // Gather all target files up front.
    let mut files = Vec::new();
    let mut pre_errors = Vec::new();
    for t in &args.targets {
        files.extend(collect_files(t, &mut pre_errors));
    }
    files.sort();
    files.dedup();
    for e in &pre_errors {
        eprintln!("mini-yara: scanning {}", e);
    }

    let (tx, rx) = std::sync::mpsc::channel::<FileResult>();
    let queue: std::sync::Mutex<std::collections::VecDeque<PathBuf>> =
        std::sync::Mutex::new(files.into_iter().collect());
    let total = queue.lock().unwrap().len();
    let workers = args.threads.min(total.max(1));
    std::thread::scope(|scope| {
        for _ in 0..workers {
            let tx = tx.clone();
            let compiled = Arc::clone(&compiled);
            let use_mmap = args.use_mmap;
            let show = args.show_strings;
            let queue_ref = &queue;
            scope.spawn(move || loop {
                let path = {
                    let mut q = queue_ref.lock().unwrap();
                    q.pop_front()
                };
                match path {
                    Some(path) => {
                        let res = scan_one(&compiled, &path, use_mmap, show);
                        if tx.send(res).is_err() {
                            break;
                        }
                    }
                    None => break,
                }
            });
        }
        drop(tx);
    });

    // Deterministic output: collect then sort by path, like yara output order.
    let mut results: Vec<FileResult> = rx.iter().collect();
    results.sort_by(|a, b| a.path.cmp(&b.path));
    let mut had_error = !pre_errors.is_empty();
    let mut counts: HashMap<String, u64> = HashMap::new();
    for r in results {
        if let Some(e) = r.error {
            eprintln!("mini-yara: scanning {}: {}", r.path.display(), e);
            had_error = true;
            continue;
        }
        for (name, detail) in r.matched {
            *counts.entry(name.clone()).or_default() += 1;
            println!("{} {}", name, r.path.display());
            if let Some(d) = detail {
                for (sid, m, shown) in d {
                    let _ = m;
                    println!("0x{:x}:{}: {}", m.offset, sid, shown);
                }
            }
        }
    }
    if had_error {
        std::process::exit(1);
    }
}

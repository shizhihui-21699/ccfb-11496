//! yrscan — YARA-compatible subset scanner.
//!
//! Usage:
//!   yrscan -r RULES_PATH TARGET [TARGET...]
//!
//! RULES_PATH may be a `.yar` file or a directory (all `*.yar`/`*.yara`
//! files inside are loaded). Targets are files or directories (scanned
//! recursively). Output mimics the reference CLI: `RuleName path/to/file`.

use std::collections::HashMap;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::thread;

use yrscan::compile;
use yrscan::parser;
use yrscan::scan;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let mut rules_path: Option<PathBuf> = None;
    let mut targets: Vec<PathBuf> = Vec::new();
    let mut threads = thread::available_parallelism().map(|n| n.get()).unwrap_or(4);
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "-r" | "--rules" => {
                i += 1;
                rules_path = Some(PathBuf::from(&args[i]));
            }
            "-t" | "--threads" => {
                i += 1;
                threads = args[i].parse().unwrap_or(threads);
            }
            "-h" | "--help" => {
                print_help();
                return;
            }
            other if !other.starts_with('-') => targets.push(PathBuf::from(other)),
            other => {
                eprintln!("unknown argument: {other}");
                std::process::exit(2);
            }
        }
        i += 1;
    }
    let Some(rules_path) = rules_path else {
        print_help();
        std::process::exit(2);
    };
    if targets.is_empty() {
        eprintln!("error: at least one target path is required");
        std::process::exit(2);
    }

    let mut sources = Vec::new();
    collect_rule_files(&rules_path, &mut sources);
    if sources.is_empty() {
        eprintln!("error: no rule files found under {rules_path:?}");
        std::process::exit(1);
    }

    let mut all_rules = Vec::new();
    for f in &sources {
        let src = match fs::read_to_string(f) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("error reading {}: {e}", f.display());
                std::process::exit(1);
            }
        };
        match parser::parse_rules(&src) {
            Ok(mut rs) => all_rules.append(&mut rs),
            Err(e) => {
                eprintln!("parse error in {}: {e}", f.display());
                std::process::exit(1);
            }
        }
    }
    let compiled = Arc::new(compile::compile(all_rules));

    // gather files
    let mut files: Vec<PathBuf> = Vec::new();
    for t in &targets {
        collect_targets(t, &mut files);
    }

    let queue = Arc::new(Mutex::new(files.into_iter().collect::<Vec<_>>()));
    let (tx, rx) = mpsc::channel::<(PathBuf, Vec<String>)>();
    let mut handles = Vec::new();
    for _ in 0..threads.max(1) {
        let queue = Arc::clone(&queue);
        let rules = Arc::clone(&compiled);
        let tx = tx.clone();
        handles.push(thread::spawn(move || loop {
            let job = {
                let mut q = queue.lock().unwrap();
                q.pop()
            };
            let Some(path) = job else { break };
            match scan::scan_file(&rules, &path) {
                Ok(res) => {
                    if !res.matched.is_empty() && tx.send((path, res.matched)).is_err() {
                        break;
                    }
                }
                Err(e) => {
                    eprintln!("scan error {}: {e}", path.display());
                }
            }
        }));
    }
    drop(tx);

    let stdout = std::io::stdout();
    let mut out = std::io::BufWriter::new(stdout.lock());
    let mut counts: HashMap<String, usize> = HashMap::new();
    let mut file_count = 0usize;
    for (path, rules_hit) in rx {
        file_count += 1;
        for r in &rules_hit {
            *counts.entry(r.clone()).or_insert(0) += 1;
            writeln!(out, "{r} {}", path.display()).ok();
        }
    }
    for h in handles {
        let _ = h.join();
    }
    out.flush().ok();
    let _ = (file_count, counts);
}

fn print_help() {
    eprintln!(
        "yrscan 0.1 — YARA-compatible subset scanner\n\
         USAGE:\n    yrscan -r <rules.yar|rules-dir> <target...> [-t threads]\n\
         Supported: text/hex/regex strings, nocase, wide, fullword, jumps,\n\
         alternations, condition counts/offsets, of/any/all, for-any loops."
    );
}

fn collect_rule_files(path: &Path, out: &mut Vec<PathBuf>) {
    if path.is_file() {
        out.push(path.to_path_buf());
        return;
    }
    if path.is_dir() {
        if let Ok(entries) = fs::read_dir(path) {
            for e in entries.flatten() {
                let p = e.path();
                if p.is_dir() {
                    collect_rule_files(&p, out);
                } else {
                    let ext = p.extension().and_then(|x| x.to_str()).unwrap_or("");
                    if matches!(ext, "yar" | "yara") {
                        out.push(p);
                    }
                }
            }
        }
    }
}

fn collect_targets(path: &Path, out: &mut Vec<PathBuf>) {
    if path.is_file() {
        out.push(path.to_path_buf());
        return;
    }
    if path.is_dir() {
        if let Ok(entries) = fs::read_dir(path) {
            for e in entries.flatten() {
                let p = e.path();
                if p.is_dir() {
                    collect_targets(&p, out);
                } else if p.is_file() {
                    out.push(p);
                }
            }
        }
    }
}

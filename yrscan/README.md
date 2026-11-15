# yrscan

A zero-dependency, single-binary YARA-compatible subset scanner written in
safe Rust. Built for incident-response hosts where installing the official
`yara` toolchain is not possible: the release binary has no dynamic
dependencies beyond libc and needs no runtime files.

## Build

```sh
cargo build --release
# binary: target/release/yrscan
```

No external crates are used. The release profile enables LTO, a single codegen
unit, and symbol stripping.

## Usage

```sh
yrscan -r <rules.yar | rules-dir> <file-or-dir...> [-t threads]
```

- Rules paths may be a single `.yar`/`.yara` file or a directory scanned
  recursively for rule files.
- Targets may be files or directories (recursed).
- `-t` overrides the worker count (defaults to available parallelism).
- Output matches the reference CLI: `RuleName /path/to/file`, one per line.

## Supported rule subset

### String types and modifiers

- **Text strings** `"..."` with escapes (`\n \r \t \\ \" \xHH`).
- **Hex strings** `{ ... }`:
  - literal bytes `4A`, nibble wildcards `??`, `?F`, `F?`;
  - jumps `[n]`, `[n-m]`, open-ended `[-]` (tail position) and `[n-]`;
  - nested alternatives `( AA | BB CC )`.
- **Regular expressions** `/.../` — see "Regex engine" below.
- Modifiers: `nocase`, `wide` / `utf16` / `utf16le`, `ascii`, `fullword`.
  Encoding modifiers follow YARA semantics: a bare string is ascii-only;
  once `wide` or `ascii` is stated, only the listed encodings apply.

### Condition expressions

- Boolean `and or not`, full arithmetic `+ - * / %`, bitwise `& | ^ << >>`,
  comparisons and parentheses, with YARA precedence.
- String operators: bare `$a` (found), `#a` (count), `@a[n]` (1-based
  offset), `!a[n]` (match length).
- Quantifiers: `any` / `all` / `none` / `N of ( ... )`, wildcard sets
  `($foo*)`, and `of them`.
- Iteration: `for <quant> of <set> : ( expr )` with `$_` / `#` / `@` bound
  to the current string.
- Built-ins: `filesize`, `uint8/16/32` and `...be` reads, integer `0x..`
  hex and `KB`/`MB` size suffixes.

## Regex engine scope

A bounded backtracking engine over the RE2/YARA syntax subset:

- literals, `.`, anchors `^ $`, word boundaries `\b \B`;
- classes `[...]`, ranges, negation, shorthands `\d \w \s` (and upper-case
  complements), `\xHH` and standard escapes;
- quantifiers `* + ? {n} {n,} {n,m}`, including lazy `*? +? ??`;
- groups, non-capturing `(?:...)`, alternation `|`, inline `(?i)`/`(?-i)`.

Deliberately rejected at parse time with a clear error: backreferences,
look-around, possessive quantifiers, and Unicode `\p{}` classes. Backtracking
is step-budgeted so pathological patterns fail closed instead of hanging.
Zero-width matches follow the reference behavior (allowed at byte positions
on non-empty input, never on an empty file).

## Architecture

```
parser.rs   rule file tokenizer + recursive-descent parser
hexpat.rs   hex pattern parser + backtracking matcher (ascii/wide views)
regex.rs    regex parser, zero-alloc continuation-passing matcher
aho.rs      four Aho-Corasick automata (exact/nocase x ascii/wide)
compile.rs  atom extraction + prefilter assembly
mmap.rs     read-only mmap (mmap / CreateFileMapping), no crates
scan.rs     candidate verification + condition evaluation
main.rs     CLI, recursive directory walk, work-queue thread pool
```

1. **Atom extraction.** Each string yields short fixed byte atoms. Text uses
   its own bytes; hex uses literal nibble runs; regex uses required literal
   sequences (alternation branches each contribute). Wide strings additionally
   register a UTF-16LE-expanded atom.
2. **Multi-pattern prefilter.** Four Aho-Corasick automata
   (exact / case-insensitive, ascii / wide-expanded) are walked once per file
   in a single linear pass, producing candidate `(string, offset, view)` hits.
3. **Precise verification.** Only candidate strings run their full matcher,
   anchored around the atom offset. Strings with no usable atom fall back to a
   whole-file scan. Regex searches skip impossible start positions using a
   precomputed first-byte bitmap.
4. **Condition evaluation** runs against the resulting match table.

Wide matching is tried from both physical parities (origin 0 and 1), matching
the reference engine, which does not require UTF-16 sequences to be aligned.

## Conformance

The `testdata/` tree holds a differential suite against the official `yara`
binary (4.6.0):

- `tools/conformance.sh` runs both engines over curated rule/sample sets and
  diffs normalized output.
- `tools/fuzz_compare.py [seed]` generates random rules and samples and
  asserts identical `(rule, file)` match sets across dozens of seeds.

The curated suite covers every listed feature; fuzzing has passed 60+ random
seeds with zero divergent match sets. Run the Rust-only checks (no external
tools) with `cargo test`.

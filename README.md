# mini-yara

A dependency-free, Rust implementation of a **YARA-compatible subset** scanner,
built for emergency use on hosts where the official YARA toolchain cannot be
installed. It compiles to a single static-ish binary with no external crates
(mmap is wired directly to libc).

The output semantics — which rules fire, match counts, offsets and lengths —
are validated against official YARA 4.6.0 over a generated corpus and
randomized differential fuzzing.

## Supported rule syntax

### Patterns

| Form | Examples | Notes |
|------|----------|-------|
| Text | `$a = "MZ"` | escapes `\n \r \t \xHH \uHH \\ \"` |
| Hex | `$a = { 12 ?? 56 }` | nibble wildcards `?? ?A A?` |
| Hex jumps | `{ 01 [2-4] 03 }`, `{ 01 [4] 03 }`, `{ 01 [1-] 03 }` | bounded, exact, unbounded |
| Hex groups | `{ 34 ( 56 \| 9a ) }` | nested alternation |
| Regex | `$a = /a[0-9]+b/` | see regex section |

### Modifiers

`nocase`, `wide`, `ascii`, `fullword` — combinable as in YARA
(e.g. `ascii wide`, `nocase wide`). Default encoding is ASCII only; `wide`
means the UTF-16LE zero-byte-interleaved form and forces every other byte to
be `0x00`.

### Regex engine scope

A self-contained byte-oriented backtracking engine (no external regex crate):

* literals, `.` (does **not** match `\n`), `^` / `$` anchors
* groups and alternation `(a|b)`
* quantifiers `* + ?` and `{n} {n,} {,m} {n,m}`, greedy only
* character classes `[a-z]`, negated classes, `\d \D \w \W \s \S`
* `\xHH` and standard backslash escapes
* `nocase` / `wide` transforms applied to the compiled tree

Not implemented (rejected at parse time or out of scope): backreferences,
look-around, possessive/lazy quantifiers, `xor`/`base64` modifiers, module
imports (`pe`, `math`, ...). `import` lines are tolerated and skipped.

### Conditions

* pattern truth `$a`, count `#a`, offset `@a` / `@a[i]`, length `!a` / `!a[i]`
* `$a at n`, `$a in (lo..hi)`
* quantifiers: `any/all/none/N of (...)`, `any/all/none of them`, `$prefix*`
* loops: `for any/all/none/N i in (lo..hi) : ( ... )`
* integer arithmetic `+ - * %`, bitwise `& | ^ ~ << >>`, comparisons
  `== != < <= > >=`, boolean `and or not`, `filesize`
* three-valued (undefined) logic matching YARA, cross-rule boolean references
  and `private` rules

Counts include **overlapping** matches, including zero-width regex matches,
exactly like YARA. Two edge semantics are reproduced precisely:

* zero-width regex matches (e.g. `/x*/`) are emitted at offsets `0..len-1`
  but **not** at the end-of-file offset `len`, and never on an empty file;
* per-string match recording is capped at **1,000,000** matches (YARA's
  `MAX_STRING_MATCHES`), matching the point where YARA prints its
  "too many matches" warning.

The `-s` output mirrors YARA's rendering: text/regex matches print printable
ASCII literally with other bytes as uppercase `\xHH` escapes, hex-pattern
matches print space-separated uppercase hex truncated to 64 bytes plus ` ...`,
and a literal `$x at <const>` condition shows only the pinned match.

## Architecture

```
lexer.rs   hand-written lexer; hex bodies captured raw via strings-section state
hex.rs     hex pattern parser -> HexNode tree
regex.rs   regex parser -> Re tree + continuation-passing backtracking matcher
ast.rs     rule / pattern / condition AST
parser.rs  recursive-descent rule parser (two-token lookahead)
aho.rs     Aho-Corasick prefilter, separate exact and case-folded automata
scanner.rs atom extraction -> AC prefilter -> precise verification
           + ByteIndex for O(occurrences) jump resolution, NFA-style hex matcher
eval.rs    condition evaluator with undefined propagation
mmap.rs    read-only mmap over libc (files >= 1 MiB), heap fallback
main.rs    include preprocessing, directory walk, thread-pool scanning, CLI
```

### Scanning pipeline

1. **Atom extraction** — every pattern yields a leading fixed-byte atom
   (text/hex literal prefix, or the regex's leading literal run).
2. **Aho-Corasick prefilter** — two dense 256-way automata (exact and
   lowercased) locate candidate offsets in one table lookup per input byte.
3. **Precise verification** — each candidate is confirmed by the full pattern
   matcher. Patterns with no usable atom are verified at every position.
4. Hex jumps are resolved against a per-file byte-occurrence index so
   unbounded `[n-]` jumps stay linear rather than quadratic.
5. Conditions are evaluated over the resulting match tables.

Directory scans distribute files across a worker thread pool; large files are
memory-mapped, smaller files read into the heap.

## Build and run

```sh
cargo build --release
./target/release/mini-yara [options] RULES TARGET [TARGET...]
```

Options: `-t N` worker threads, `-s` show matched strings, `--no-mmap`
force heap reads, `-h` help. `include "..."` directives are resolved relative
to the including file.

## Testing

All tests compare against the installed official `yara` (4.6.0):

```sh
python3 -I tests/gen_samples.py      # (re)generate the synthetic corpus
python3 -I tests/diff_test.py        # rule-file x corpus result equivalence
python3 -I tests/fuzz_diff.py 500    # randomized rule/sample differential
python3 -I tests/consistency_test.py # threads/mmap/modes/-s consistency
cargo test                            # Rust unit tests for the engines
```

The corpus under `corpus/` is entirely synthetic (no real malware).

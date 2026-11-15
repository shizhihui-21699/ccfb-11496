# testdata — differential conformance suite

Everything here is generated locally; no external samples are required.

## Layout

- `samples/` — deterministic synthetic binary samples produced by
  `tools/gen_samples.py`. Each file is crafted to exercise specific features
  (and several are deliberate negatives / near-misses).
- `rules/conformance.yar` — curated rules covering every supported feature.
- `rules/edge_cases.yar` — parser/matcher corner cases (anchors, lazy
  quantifiers, nested groups, empty-match boundary, wide regex, ...).
- `tools/gen_samples.py` — sample generator (run with `python3 -I`).
- `tools/conformance.sh` — runs official `yara` and `yrscan` over every rule
  file and diffs the normalized, sorted output.
- `tools/fuzz_compare.py [seed]` — randomized differential testing: builds
  random rules (text/hex/regex + modifiers + condition forms) and random
  samples, then asserts both engines report the identical match set.

## Running

```sh
# regenerate samples (deterministic; only needed once or after edits)
python3 -I tools/gen_samples.py

# curated conformance
bash tools/conformance.sh

# randomized differential testing
python3 -I tools/fuzz_compare.py 42
```

`fuzz_compare.py` expects the release binary at
`../yrscan/target/release/yrscan`; override with `YRSCAN_BIN` and the
reference tool with `YARA_BIN`. Set `FUZZ_KEEP=<dir>` to persist the
generated rules and samples when debugging a mismatch.

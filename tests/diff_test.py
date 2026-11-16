#!/usr/bin/env python3
"""Differential test: run official yara and mini-yara over the same rule files
and sample corpus, then compare normalized outputs.

Usage: python3 -I diff_test.py [path_to_mini_yara]
Exit code 0 only if every (rule-file, sample) result matches.
"""
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, ".."))
RULES_DIR = os.path.join(ROOT, "corpus", "rules")
SAMPLES_DIR = os.path.join(ROOT, "corpus", "samples")
MINI = sys.argv[1] if len(sys.argv) > 1 else os.path.join(ROOT, "target", "release", "mini-yara")


def run(cmd):
    p = subprocess.run(cmd, capture_output=True, text=True)
    return p.returncode, p.stdout, p.stderr


def normalize(out: str) -> set:
    """Turn 'rule path' lines into a comparable set of (rule, basename)."""
    rows = set()
    for line in out.splitlines():
        line = line.strip()
        if not line or line.startswith("0x"):
            continue
        parts = line.split()
        if len(parts) >= 2:
            rule, path = parts[0], parts[-1]
            rows.add((rule, os.path.relpath(path, ROOT)))
    return rows


def main():
    rule_files = sorted(f for f in os.listdir(RULES_DIR) if f.endswith(".yar"))
    total = 0
    mismatches = 0
    missing_rules = set()
    extra_rules = set()

    for rf in rule_files:
        rule_path = os.path.join(RULES_DIR, rf)
        rc_ref, ref_out, ref_err = run(["yara", "-r", rule_path, SAMPLES_DIR])
        rc_mine, mine_out, mine_err = run([MINI, rule_path, SAMPLES_DIR])
        if rc_ref != 0 and "error" in ref_err.lower():
            print(f"[SKIP] {rf}: reference failed to compile: {ref_err.strip()}")
            continue
        ref = normalize(ref_out)
        mine = normalize(mine_out)
        total += 1
        if ref == mine:
            print(f"[OK]   {rf}: {len(ref)} matches")
            continue
        mismatches += 1
        only_ref = ref - mine
        only_mine = mine - ref
        for r, p in sorted(only_ref):
            missing_rules.add(r)
        for r, p in sorted(only_mine):
            extra_rules.add(r)
        print(f"[DIFF] {rf}: ref={len(ref)} mine={len(mine)} "
              f"missing={len(only_ref)} extra={len(only_mine)}")
        # show up to 8 concrete per-file discrepancies
        shown = 0
        for r, p in sorted(only_ref)[:4]:
            print(f"         MISSING {r} on {p}")
            shown += 1
        for r, p in sorted(only_mine)[:4]:
            print(f"         EXTRA   {r} on {p}")
            shown += 1
        if mine_err.strip():
            print(f"         mini stderr: {mine_err.strip().splitlines()[0]}")

    print("\n=== summary ===")
    print(f"rule files compared: {total}")
    print(f"mismatching files:   {mismatches}")
    if missing_rules:
        print(f"rules under-reporting: {sorted(missing_rules)}")
    if extra_rules:
        print(f"rules over-reporting:  {sorted(extra_rules)}")
    sys.exit(1 if mismatches else 0)


if __name__ == "__main__":
    main()

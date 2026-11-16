#!/usr/bin/env python3
"""Operational consistency: thread counts, mmap toggle, single-file vs
directory mode, and -s output must agree with official yara.

The -s comparison uses set difference on normalized lines but caps how much
detail it reads, so rules with ~1M matches do not stall the test harness.
Run: python3 -I consistency_test.py
"""
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, ".."))
RULES_DIR = os.path.join(ROOT, "corpus", "rules")
SAMPLES_DIR = os.path.join(ROOT, "corpus", "samples")
MINI = os.path.join(ROOT, "target", "release", "mini-yara")

# Only compare -s output on these smaller rules to keep the test fast; the
# million-match zero-width case is covered separately.
DETAIL_RULES = ["01_text.yar", "02_hex.yar", "03_regex.yar", "04_conditions.yar"]


def run(cmd):
    p = subprocess.run(cmd, capture_output=True, text=True)
    return p.returncode, p.stdout, p.stderr


def rule_files():
    return [os.path.join(RULES_DIR, f) for f in sorted(os.listdir(RULES_DIR)) if f.endswith(".yar")]


def norm_lines(out):
    rows = []
    for line in out.splitlines():
        line = line.rstrip()
        if not line or line.startswith("0x"):
            continue
        parts = line.split()
        if len(parts) >= 2:
            rows.append(f"{parts[0]} {os.path.relpath(parts[-1], ROOT)}")
    return sorted(rows)


def main():
    failures = 0
    combined = os.path.join(HERE, "_combined.yar")
    with open(combined, "w") as fh:
        for r in rule_files():
            fh.write(open(r).read())
            fh.write("\n")

    _, ref_all, _ = run(["yara", "-r", combined, SAMPLES_DIR])
    ref_set = norm_lines(ref_all)

    cases = [
        ("threads=1", [MINI, "-t", "1", combined, SAMPLES_DIR]),
        ("threads=2", [MINI, "-t", "2", combined, SAMPLES_DIR]),
        ("threads=8", [MINI, "-t", "8", combined, SAMPLES_DIR]),
        ("no-mmap", [MINI, "--no-mmap", combined, SAMPLES_DIR]),
        ("default", [MINI, combined, SAMPLES_DIR]),
    ]
    for name, cmd in cases:
        _, out, err = run(cmd)
        got = norm_lines(out)
        if got == ref_set:
            print(f"[OK] {name}: {len(got)} matches")
        else:
            failures += 1
            print(f"[FAIL] {name}: ref={len(ref_set)} got={len(got)}")
            if err.strip():
                print("   stderr:", err.strip().splitlines()[0])

    # single-file mode on a representative subset
    subset = [
        os.path.join(SAMPLES_DIR, "large", "big_random.bin"),
        os.path.join(SAMPLES_DIR, "large", "many_sigs.bin"),
        os.path.join(SAMPLES_DIR, "edge", "empty.bin"),
        os.path.join(SAMPLES_DIR, "nested", "dir0", "sub0", "file_0_0.bin"),
        os.path.join(SAMPLES_DIR, "bin", "fake_pe.bin"),
    ]
    sf_mine, sf_ref = set(), set()
    for f in subset:
        _, mo, _ = run([MINI, combined, f])
        _, yo, _ = run(["yara", combined, f])
        sf_mine.update(norm_lines(mo))
        sf_ref.update(norm_lines(yo))
    if sf_mine == sf_ref:
        print(f"[OK] single-file mode: {len(sf_mine)} matches on subset")
    else:
        failures += 1
        print(f"[FAIL] single-file mode: ref={len(sf_ref)} got={len(sf_mine)}")

    # -s detailed output: exact line-set equality on bounded rules
    detail_ok = True
    for name in DETAIL_RULES:
        rp = os.path.join(RULES_DIR, name)
        _, y_out, _ = run(["yara", "-s", "-r", rp, SAMPLES_DIR])
        _, m_out, _ = run([MINI, "-s", rp, SAMPLES_DIR])
        yd = sorted(l.strip() for l in y_out.splitlines() if l.startswith("0x"))
        md = sorted(l.strip() for l in m_out.splitlines() if l.startswith("0x"))
        if yd == md:
            print(f"[OK] -s {name}: {len(yd)} detail lines")
        else:
            detail_ok = False
            print(f"[FAIL] -s {name}: yara={len(yd)} mine={len(md)}")
            print("   only yara:", [x for x in yd if x not in md][:3])
            print("   only mini:", [x for x in md if x not in yd][:3])
    if not detail_ok:
        failures += 1

    # zero-width match cap behavior on the large random file
    xstar = os.path.join(HERE, "_xstar.yar")
    with open(xstar, "w") as fh:
        fh.write('rule cap { strings: $a = /x*/ condition: #a > 0 }')
    big = os.path.join(SAMPLES_DIR, "large", "big_random.bin")
    _, yc, _ = run(["yara", "-s", xstar, big])
    _, mc, _ = run([MINI, "-s", xstar, big])
    yn = sum(1 for l in yc.splitlines() if l.startswith("0x"))
    mn = sum(1 for l in mc.splitlines() if l.startswith("0x"))
    if yn == mn == 1_000_000:
        print("[OK] zero-width match cap = 1,000,000")
    else:
        failures += 1
        print(f"[FAIL] match cap: yara={yn} mine={mn}")

    for tmp in (combined, xstar):
        os.remove(tmp)
    print("\nconsistency failures:", failures)
    sys.exit(1 if failures else 0)


if __name__ == "__main__":
    main()

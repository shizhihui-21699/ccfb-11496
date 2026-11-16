#!/usr/bin/env python3
"""Randomized differential fuzzing. Generates many small random rule/sample
pairs from a fixed seed and compares official yara vs mini-yara on every
combination. Run: python3 -I fuzz_diff.py [iterations]
"""
import os
import random
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, ".."))
MINI = os.path.join(ROOT, "target", "release", "mini-yara")

TEXT_TOKENS = [b"abc", b"ABC", b"MZ", b"PE", b"foo", b"bar", b"123", b"cmd", b"http"]
HEX_TOKENS = ["41 42", "4d 5a", "12 ?? 56", "3? 9a", "01 [1-3] 03", "( 50 45 | 4d 5a )",
              "ff [2-] fe", "00 [2] 00", "7f ?? 4c 46"]
RE_TOKENS = ["abc", "a[0-9]+b", "[A-Z]+", "foo|bar", "ab*c", "x{1,3}",
             "\\d+", "^MZ", "PE$", "a.c", "[^0-9]{2}", "https?://"]


def rand_text(rng):
    parts = []
    for _ in range(rng.randint(1, 6)):
        t = rng.choice(TEXT_TOKENS)
        if rng.random() < 0.3:
            t = t.swapcase()
        parts.append(t)
        if rng.random() < 0.4:
            parts.append(bytes([rng.randrange(256) for _ in range(rng.randint(0, 3))]))
    return b"".join(parts) + b"\x00" * rng.randint(0, 2)


def rand_wide(rng):
    t = rng.choice(TEXT_TOKENS)
    return b"".join(bytes([c, 0]) for c in t)


def rand_hex_data(rng):
    out = bytearray()
    for _ in range(rng.randint(2, 12)):
        choice = rng.random()
        if choice < 0.4:
            out += rng.choice([b"\x41\x42", b"\x4d\x5a", b"\x12\x00\x56",
                               b"\x01\x00\x00\x03", b"\xff\x00\x00\xfe"])
        else:
            out += bytes([rng.randrange(256) for _ in range(rng.randint(1, 4))])
    return bytes(out)


def rand_rule(rng, idx):
    kind = rng.choice(["text", "text", "hex", "regex"])
    lines = [f"rule fuzz_{idx} {{", "  strings:"]
    if kind == "text":
        tok = rng.choice(TEXT_TOKENS)
        esc = tok.decode("latin1").replace("\\", "\\\\").replace('"', '\\"')
        mods = []
        if rng.random() < 0.4:
            mods.append("nocase")
        if rng.random() < 0.4:
            mods.append("wide")
        if rng.random() < 0.2:
            mods.append("ascii")
        if rng.random() < 0.2:
            mods.append("fullword")
        lines.append(f'    $s = "{esc}" {" ".join(mods)}'.rstrip())
    elif kind == "hex":
        lines.append(f"    $s = {{ {rng.choice(HEX_TOKENS)} }}")
    else:
        mods = []
        if rng.random() < 0.3:
            mods.append("nocase")
        if rng.random() < 0.3:
            mods.append("wide")
        lines.append(f"    $s = /{rng.choice(RE_TOKENS)}/ {' '.join(mods)}".rstrip())
    cond_style = rng.choice(["defined", "count", "at", "truth", "offset"])
    if cond_style == "defined":
        cond = "$s"
    elif cond_style == "count":
        n = rng.randint(0, 3)
        op = rng.choice(["==", ">=", ">", "<=", "!="])
        cond = f"#s {op} {n}"
    elif cond_style == "at":
        cond = f"$s at {rng.randint(0, 8)}"
    elif cond_style == "offset":
        cond = f"@s >= 0 and #s > 0"
    else:
        cond = "#s"
    lines += ["  condition:", f"    {cond}", "}"]
    return kind, "\n".join(lines)


def run(cmd):
    p = subprocess.run(cmd, capture_output=True, text=True)
    return p.returncode, p.stdout, p.stderr


def norm(out):
    rows = set()
    for line in out.splitlines():
        if line.startswith("0x") or not line.strip():
            continue
        rows.add(line.split()[0])
    return rows


def rand_multi_rule(rng, idx):
    """Multi-string rules exercising of-quantifiers and for-loops."""
    n = rng.randint(2, 4)
    toks = rng.sample(TEXT_TOKENS, min(n, len(TEXT_TOKENS)))
    lines = [f"rule fuzzm_{idx} {{", "  strings:"]
    for i, t in enumerate(toks):
        esc = t.decode("latin1")
        lines.append(f'    $s{i} = "{esc}"')
    ids = ", ".join(f"$s{i}" for i in range(len(toks)))
    style = rng.choice(["any", "all", "none", "nexpr", "for_any", "for_all"])
    if style == "any":
        cond = f"any of ({ids})"
    elif style == "all":
        cond = f"all of ({ids})"
    elif style == "none":
        cond = f"none of ({ids})"
    elif style == "nexpr":
        cond = f"{rng.randint(1, 2)} of ({ids})"
    elif style == "for_any":
        cond = f"for any i in (0..4) : ( $s0 at i )"
    else:
        cond = f"for all i in (1..#s0) : ( @s0[i] >= 0 )"
    lines += ["  condition:", f"    {cond}", "}"]
    return "multi", "\n".join(lines)


def main():
    iters = int(sys.argv[1]) if len(sys.argv) > 1 else 300
    rng = random.Random(1337)
    failures = 0
    checked = 0
    with tempfile.TemporaryDirectory() as td:
        sample_dir = os.path.join(td, "samples")
        os.makedirs(sample_dir)
        sample_paths = []
        for i in range(40):
            maker = rng.choice([rand_text, rand_wide, rand_hex_data])
            data = maker(rng)
            p = os.path.join(sample_dir, f"s{i:03d}.bin")
            with open(p, "wb") as f:
                f.write(data)
            sample_paths.append(p)

        for it in range(iters):
            if rng.random() < 0.3:
                kind, rule_text = rand_multi_rule(rng, it)
            else:
                kind, rule_text = rand_rule(rng, it)
            rule_path = os.path.join(td, "r.yar")
            with open(rule_path, "w") as f:
                f.write(rule_text)
            # only keep rules that official yara accepts
            rc0, _, err0 = run(["yara", rule_path, sample_paths[0]])
            if rc0 != 0 and "error" in err0.lower():
                continue
            checked += 1
            for sp in sample_paths:
                rc_r, ref, _ = run(["yara", rule_path, sp])
                rc_m, mine, merr = run([MINI, rule_path, sp])
                if norm(ref) != norm(mine):
                    failures += 1
                    print(f"\n[FUZZ FAIL] iter={it} kind={kind} sample={os.path.basename(sp)}")
                    print("--- rule ---\n" + rule_text)
                    print("data:", open(sp, "rb").read()[:40])
                    print("yara :", sorted(norm(ref)))
                    print("mini :", sorted(norm(mine)))
                    if merr.strip():
                        print("mini stderr:", merr.strip().splitlines()[0])
                    if failures >= 10:
                        print("\nstopping after 10 failures")
                        print(f"checked={checked} failures={failures}")
                        sys.exit(1)
    print(f"\nfuzz complete: checked={checked} iterations, failures={failures}")
    sys.exit(1 if failures else 0)


if __name__ == "__main__":
    main()

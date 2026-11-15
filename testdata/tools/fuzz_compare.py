#!/usr/bin/env python3
"""Randomized differential testing: yrscan vs official yara.

Generates random binary samples and random rules (text/hex/regex, nocase,
wide, fullword, jumps, condition counts/of/for), then asserts both engines
produce the identical rule->file match set. Runs in isolated mode (-I).
"""
import os
import random
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
YRSCAN = os.path.join(ROOT, "..", "yrscan", "target", "release", "yrscan")
YARA = os.environ.get("YARA_BIN", "yara")


def rand_bytes(rnd, n):
    return bytes(rnd.randrange(0, 256) for _ in range(n))


def make_text(rnd):
    alphabet = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    n = rnd.randrange(2, 9)
    s = bytes(rnd.choice(alphabet) for _ in range(n))
    mods = []
    if rnd.random() < 0.4:
        mods.append("nocase")
    enc = rnd.choice(["ascii", "wide", "wide ascii", ""])
    if enc:
        mods.append(enc)
    if rnd.random() < 0.2:
        mods.append("fullword")
    return f'"{s.decode()}"' + (" " + " ".join(mods) if mods else "")


def make_hex(rnd):
    # YARA requires hex strings to begin/end with a fixed byte (not a jump or
    # wildcard-only boundary); unbounded [-] jumps are only valid before the
    # final tail.
    toks = [f"{rnd.randrange(0, 256):02X}"]
    for _ in range(rnd.randrange(1, 4)):
        if rnd.random() < 0.5:
            # yara rejects an exact [0] jump; keep min length >= 1
            lo = rnd.randrange(1, 3)
            hi = lo + rnd.randrange(0, 3)
            toks.append(rnd.choice([f"[{lo}-{hi}]", f"[{lo}]"]))
        kind = rnd.choice(["byte", "byte", "wild", "nibble"])
        if kind == "byte":
            toks.append(f"{rnd.randrange(0, 256):02X}")
        elif kind == "nibble":
            toks.append(f"{rnd.randrange(0, 16):X}?")
        else:
            toks.append("??")
    # yara only permits the unbounded [-] jump immediately before the final
    # fixed byte (i.e. at the tail of the pattern).
    tail = [f"{rnd.randrange(0, 256):02X}"]
    if rnd.random() < 0.3:
        toks.append("[-]")
    toks.extend(tail)
    return "{ " + " ".join(toks) + " }"


def make_regex(rnd):
    parts = []
    for _ in range(rnd.randrange(1, 5)):
        kind = rnd.choice(["lit", "class", "dot", "group"])
        if kind == "lit":
            parts.append(rnd.choice(["a", "b", "4", "x", "z"]))
        elif kind == "class":
            parts.append(rnd.choice(["[0-9]", "[a-c]", "\\w", "\\d", "\\s", "[^x]"]))
        elif kind == "dot":
            parts.append(".")
        else:
            parts.append("(" + rnd.choice(["ab", "xy", "a|b"]) + ")")
        if rnd.random() < 0.5:
            parts.append(rnd.choice(["*", "+", "?", "{2}", "{1,3}"]))
    body = "".join(parts)
    mods = []
    if rnd.random() < 0.3:
        mods.append("nocase")
    if rnd.random() < 0.3:
        mods.append("wide")
    return "/" + body + "/" + (" " + " ".join(mods) if mods else "")


def make_rule(rnd, idx):
    nstr = rnd.randrange(1, 4)
    lines = []
    names = []
    for si in range(nstr):
        nm = f"s{si}"
        names.append(nm)
        kind = rnd.choice(["text", "text", "hex", "regex"])
        body = {"text": make_text, "hex": make_hex, "regex": make_regex}[kind](rnd)
        lines.append(f"        ${nm} = {body}")
    cond_kind = rnd.choice(["found", "count", "of", "for", "not", "arith"])
    # every condition references every declared string (YARA rejects
    # unreferenced strings), combined with 'and' where needed.
    all_found = " and ".join(f"${n}" for n in names)
    if cond_kind == "found":
        cond = all_found
    elif cond_kind == "count":
        n = rnd.choice(names)
        cond = f"#{n} >= {rnd.randrange(0, 3)} and " + all_found
    elif cond_kind == "of":
        q = rnd.choice(["any", "all", "1"])
        cond = f"{q} of (" + ", ".join(f"${n}" for n in names) + ")"
    elif cond_kind == "for":
        q = rnd.choice(["any", "all", "1"])
        cond = (f"for {q} of (" + ", ".join(f"${n}" for n in names)
                + ') : ( $ )')
    elif cond_kind == "not":
        # negate a count (always valid, references all strings)
        n = rnd.choice(names)
        cond = f"#{n} < 5 and " + all_found
    else:
        n = rnd.choice(names)
        cond = f"#{n} + 1 > 0 and filesize >= 0 and " + all_found
    body = "\n".join(lines)
    return (f"rule r{idx} {{\n    strings:\n{body}\n"
            f"    condition:\n        {cond}\n}}\n")


def normalize(out, sample_dir):
    res = set()
    for line in out.splitlines():
        line = line.strip()
        if not line or line.startswith("warning"):
            continue
        parts = line.split()
        if len(parts) >= 2:
            res.add((parts[0], os.path.basename(parts[1])))
    return res


def main():
    seed = int(sys.argv[1]) if len(sys.argv) > 1 else 20261116
    keep_dir = os.environ.get("FUZZ_KEEP")
    rnd = random.Random(seed)
    n_rules = 60
    n_samples = 40
    if keep_dir:
        tmp = keep_dir
        os.makedirs(os.path.join(tmp, "samples"), exist_ok=True)
        cleanup = False
    else:
        tmp = tempfile.mkdtemp()
        cleanup = True
    try:
        sdir = os.path.join(tmp, "samples")
        os.makedirs(sdir, exist_ok=True)
        for i in range(n_samples):
            # mix structured fragments with random bytes so matches sometimes
            # occur
            data = rand_bytes(rnd, rnd.randrange(0, 400))
            if rnd.random() < 0.6:
                frag = rnd.choice([b"abc", b"4", b"abab", b"x", b"aabb"])
                pos = rnd.randrange(0, max(1, len(data) + 1))
                data = data[:pos] + frag + data[pos:]
            if rnd.random() < 0.3:
                wfrag = b"wide".decode().encode("utf-16le")
                data = data + wfrag
            with open(os.path.join(sdir, f"f{i:03d}.bin"), "wb") as f:
                f.write(data)
        rule_path = os.path.join(tmp, "fuzz.yar")
        with open(rule_path, "w") as f:
            for i in range(n_rules):
                f.write(make_rule(rnd, i))

        # official yara reference
        ref = subprocess.run([YARA, rule_path, sdir], capture_output=True, text=True)
        errs = [l for l in ref.stderr.splitlines() if "error" in l.lower()]
        if errs:
            print("yara rejected rules:")
            print("\n".join(errs[:30]))
            keep = os.path.join(ROOT, "tools", "fuzz_rejected.yar")
            with open(rule_path) as src, open(keep, "w") as dst:
                dst.write(src.read())
            print("rules written to", keep)
            return 2
        ref_set = normalize(ref.stdout, sdir)

        ours = subprocess.run([YRSCAN, "-r", rule_path, sdir],
                              capture_output=True, text=True)
        if ours.returncode != 0:
            print("yrscan error:\n", ours.stderr[:2000])
            return 2
        our_set = normalize(ours.stdout, sdir)

        if ref_set == our_set:
            print(f"FUZZ PASS: {n_rules} rules x {n_samples} samples, "
                  f"{len(ref_set)} matching pairs")
            return 0
        only_ref = ref_set - our_set
        only_ours = our_set - ref_set
        print(f"MISMATCH  ref={len(ref_set)} ours={len(our_set)}")
        print("only in yara:", sorted(only_ref)[:20])
        print("only in yrscan:", sorted(only_ours)[:20])
        # persist the failing rule file for inspection
        keep = os.path.join(ROOT, "tools", "fuzz_failure.yar")
        with open(rule_path) as src, open(keep, "w") as dst:
            dst.write(src.read())
        print("failing rules written to", keep)
        return 1
    finally:
        if cleanup:
            import shutil
            shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python3
"""Generate a deterministic, diverse sample corpus for differential testing.
Run with: python3 -I gen_samples.py
All files are synthetic; no real malware.
"""
import os
import random

ROOT = os.path.join(os.path.dirname(__file__), "..", "corpus", "samples")
random.seed(20261117)


def w(path, data: bytes):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as f:
        f.write(data)


def wide(s: bytes) -> bytes:
    return b"".join(bytes([c, 0]) for c in s)


# ---- text samples ----------------------------------------------------------
w(f"{ROOT}/text/planets.txt", b"mercury venus earth mars jupiter saturn\n")
w(f"{ROOT}/text/mixed_case.txt", b"AbCdEf GhI jKlMn OpQrStUvWx\nABC abc Abc aBC\n")
w(f"{ROOT}/text/repeated.txt", b"AA" * 50 + b"X" + b"AA" * 50)
w(f"{ROOT}/text/overlap.txt", b"aaaaaaa")  # 7 a's -> "aa" overlaps 6x
w(f"{ROOT}/text/words.txt", b"_abc_ abc abc1 1abc .abc. abc\t\nABC fullword boundary test")
w(f"{ROOT}/text/newlines.txt", b"line1\nline2\r\nline3\ttabbed\n")
w(f"{ROOT}/text/utf16le.txt", b"M\x00Z\x00\x90\x00\x00\x00" + b"PE\x00\x00\x00")
w(f"{ROOT}/text/escapes.bin", b"\x00\x01\x02\xff\xfe\xfc\n\t\r\\\"'")
w(f"{ROOT}/text/long_ascii.txt", (b"The quick brown fox jumps over the lazy dog. " * 200))

# ---- binary / structured samples ------------------------------------------
w(f"{ROOT}/bin/mz_pe.bin", b"MZ" + b"\x90" * 58 + b"PE\x00\x00" + b"\x4c\x01" + os.urandom(0))
# deterministic fake PE header
pe = bytearray()
pe += b"MZ" + b"\x00" * 58 + b"PE\x00\x00\x00"
pe += b"\x4c\x01"                      # machine
pe += b"\x03\x00"                      # number of sections
pe += b"\x00\x10\x00\x00"              # timestamp
pe += b"\x55\x8b\xec"                  # prologue push rbp; mov rbp,rsp
pe += b"\xe8" + b"\x10\x00\x00\x00"    # call rel
pe += b"\xc3"                          # ret
pe += b".text\x00\x00\x00"
pe += b".data\x00\x00\x00"
pe += b".rsrc\x00\x00\x00"
w(f"{ROOT}/bin/fake_pe.bin", bytes(pe))

w(f"{ROOT}/bin/magic_bytes.bin",
  b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 8 +
  b"\x89PNG\r\n\x1a\n" + b"\x00\x00\x00\rIHDR" +
  b"GIF89a" + b"PK\x03\x04" + b"\x1f\x8b\x08")

w(f"{ROOT}/bin/all_bytes.bin", bytes(range(256)) * 4)
w(f"{ROOT}/bin/jumps.bin", b"\x01\x02\xff\xff\xff\x03" + b"\x01" + b"\x00" * 10 + b"\x03")
w(f"{ROOT}/bin/pattern_alt.bin", b"\x34\x56" + b"\x00" * 4 + b"\x34\x9a" + b"\x00" + b"\x34\x78")
w(f"{ROOT}/bin/wildcards.bin", b"\x12\x00\x56" + b"\x12\xff\x56" + b"\x12\xab\x56")

# ---- wide / unicode samples ------------------------------------------------
w(f"{ROOT}/wide/utf16_strings.bin",
  wide(b"cmd.exe /c ") + b"c\x00m\x00d\x00.\x00e\x00x\x00e\x00\x00\x00" +
  wide(b"http://example.com") + b"\x00\x00" +
  wide(b"HKLM\\Software\\Vendor"))
w(f"{ROOT}/wide/mixed_enc.bin", b"ASCIIPART" + wide(b"WidePart") + b"TAIL")
w(f"{ROOT}/wide/nocase_wide.bin", wide(b"AbCdEfG") + wide(b"ABCDEFG"))
w(f"{ROOT}/wide/zero_runs.bin", b"\x00" * 32 + b"A\x00B\x00" + b"\x00" * 16)

# ---- regex-focused samples -------------------------------------------------
w(f"{ROOT}/regex/digits.txt", b"a1b a22b a333b a-b a_b a9999b")
w(f"{ROOT}/regex/emails.txt", b"contact: alice@example.com bob@test.org not-an-email @nope x@y")
w(f"{ROOT}/regex/urls.txt", b"http://a.io https://b.co.uk ftp://x.net noturl http://")
w(f"{ROOT}/regex/anchors.txt", b"start-of-data\nmiddle\ntrailing")
w(f"{ROOT}/regex/classes.txt", b"abc123 def456 !@# 000 z9 end")
w(f"{ROOT}/regex/repeats.txt", b"z z8 z88 z888 888 zzz")
w(f"{ROOT}/regex/quant_edge.txt", b"aaaa" + b"ab" + b"abb" + b"abbb")
w(f"{ROOT}/regex/dot_nl.bin", b"a\nb" + b"axb" + b"a\x00b")

# ---- edge cases ------------------------------------------------------------
w(f"{ROOT}/edge/empty.bin", b"")
w(f"{ROOT}/edge/one_byte.bin", b"A")
w(f"{ROOT}/edge/two_bytes.bin", b"AB")
w(f"{ROOT}/edge/null_only.bin", b"\x00" * 8)
w(f"{ROOT}/edge/ff_only.bin", b"\xff" * 16)
w(f"{ROOT}/edge/at_boundaries.bin", b"X" + b"MAGIC" + b"Y" + b"MAGIC")
w(f"{ROOT}/edge/last_byte.bin", b"\x00" * 63 + b"\x7f")
w(f"{ROOT}/edge/high_offset.bin", b"\x00" * 1000 + b"NEEDLE" + b"\x00" * 1000)
w(f"{ROOT}/edge/alternating.bin", bytes([i & 1 for i in range(200)]))

# ---- large files (exercise mmap path) -------------------------------------
rnd = random.Random(99)
big = bytearray(rnd.randbytes(2 * 1024 * 1024 + 123))  # > mmap threshold
big[500_000:500_006] = b"MMAPSIG"
big[2_000_000:2_000_009] = wide(b"WD")[:8]
big[-10:] = b"TAIL_MARK"
w(f"{ROOT}/large/big_random.bin", bytes(big))

# structured large file with many repeated signatures
many = bytearray()
for i in range(20_000):
    many += b"SIG%05d" % i + b"\x00\x00"
w(f"{ROOT}/large/many_sigs.bin", bytes(many))

# ---- nested directories (recursion test) ----------------------------------
for d in range(5):
    for f in range(4):
        w(f"{ROOT}/nested/dir{d}/sub{f}/file_{d}_{f}.bin",
          b"depth%d-file%d" % (d, f) + (b"NEEDLE" if (d + f) % 2 == 0 else b""))

print("generated corpus under", ROOT)

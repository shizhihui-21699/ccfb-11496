#!/usr/bin/env python3
"""Generate deterministic synthetic samples for yrscan conformance testing.

Each file is crafted so that specific rules in conformance.yar must (or must
not) match. All content is generated, no external files are read.
"""
import os
import random
import struct

OUT = os.path.join(os.path.dirname(__file__), "..", "samples")


def w(name, data: bytes):
    path = os.path.join(OUT, name)
    with open(path, "wb") as f:
        f.write(data)


def pad(n, seed=0):
    rnd = random.Random(seed)
    return bytes(rnd.randrange(1, 256) for _ in range(n))


def main():
    os.makedirs(OUT, exist_ok=True)

    # 01 plain text string, multiple occurrences --------------------------------
    w("01_text_basic.bin",
      pad(32, 1) + b"the quick brown fox" + pad(16, 2)
      + b"THE QUICK BROWN FOX" + pad(8, 3))

    # 02 nocase matching ---------------------------------------------------------
    w("02_nocase.bin",
      pad(20, 4) + b"MiXeDcAsE" + pad(20, 5) + b"mixedcase" + pad(5, 6))

    # 03 wide (utf16le) and ascii ------------------------------------------------
    wide = b"w\0i\0d\0e\0s\0t\0r\0i\0n\0g\0"
    w("03_wide.bin", pad(10, 7) + wide + pad(10, 8) + b"widestring" + pad(4, 9))

    # 04 hex pattern with nibble wildcards --------------------------------------
    w("04_hex_wild.bin",
      pad(12, 10) + bytes([0x4A, 0x01, 0x42, 0x3F]) + pad(12, 11)
      + bytes([0x4A, 0xFF, 0x42, 0x30]))

    # 05 hex jump [1-3] ----------------------------------------------------------
    w("05_hex_jump.bin",
      pad(8, 12) + b"\xAA" + b"\x00\x00" + b"\xBB" + pad(8, 13)
      + b"\xAA" + b"\xCC\xCC\xCC\xCC" + b"\xBB" + pad(4, 14))

    # 06 hex alternatives --------------------------------------------------------
    w("06_hex_alt.bin",
      pad(6, 15) + b"\xDE\xAD" + pad(6, 16) + b"\xBE\xEF" + pad(6, 17))

    # 07 regex basic -------------------------------------------------------------
    w("07_regex_basic.bin",
      pad(10, 18) + b"order A1B2C3 now" + pad(10, 19))

    # 08 regex classes, quantifiers, anchors ------------------------------------
    w("08_regex_class.bin",
      b"start-12345-end" + pad(10, 20) + b"no digits here" + pad(6, 21))

    # 09 fullword ----------------------------------------------------------------
    w("09_fullword.bin",
      pad(8, 22) + b" word " + pad(8, 23) + b"password123" + pad(8, 24))

    # 10 counts / offsets condition ----------------------------------------------
    body = b"needle" + b"\x00\x00" + b"needle" + b"\x00\x00" + b"needle"
    w("10_count.bin", pad(16, 25) + body + pad(16, 26))

    # 11 of / any / all ----------------------------------------------------------
    w("11_of.bin",
      pad(8, 27) + b"alpha-one" + pad(4, 28) + b"beta-two" + pad(4, 29))

    # 12 for any of --------------------------------------------------------------
    w("12_for_any.bin",
      pad(8, 30) + b"mark01" + pad(8, 31) + b"mark02" + pad(8, 32))

    # 13 uint / filesize ---------------------------------------------------------
    payload = pad(100, 33) + struct.pack("<I", 0xCAFEBABE) + pad(200, 34)
    w("13_uint.bin", payload)

    # 14 negative sample: near-misses only ---------------------------------------
    w("14_negative.bin",
      pad(64, 35) + b"the quick red fox" + pad(16, 36)
      + b"widestrin" + pad(8, 37) + bytes([0x4A, 0x01, 0x43, 0x3F]))

    # 15 big file for mmap / perf (1 MiB) with markers near the end --------------
    big = bytearray(pad(1024 * 1024 - 64, 38))
    big[-40:-30] = b"bigfilemarker"[:10]
    w("15_big.bin", bytes(big))

    # 16 empty and tiny ----------------------------------------------------------
    w("16_empty.bin", b"")
    w("16_tiny.bin", b"\x00\x01fox")

    # 17 overlapping patterns ----------------------------------------------------
    w("17_overlap.bin", b"aaaa" + b"ababab" + b"aaaa")

    # 18 regex word boundary and alternation ------------------------------------
    w("18_regex_boundary.bin",
      pad(8, 39) + b"cat category bobcat" + pad(8, 40))

    # 19 nested jumps and unbounded jump ----------------------------------------
    w("19_jump_unbounded.bin",
      pad(8, 41) + b"\x01\x02" + pad(50, 42) + b"\x03\x04" + pad(8, 43))

    # 20 wide + nocase combo -----------------------------------------------------
    wn = "WIDEMIX".encode("utf-16le")
    w("20_wide_nocase.bin", pad(12, 44) + wn + pad(12, 45))


if __name__ == "__main__":
    main()
    print("samples generated in", os.path.abspath(OUT))

#!/usr/bin/env bash
# Conformance harness: run official yara and yrscan over the same rules and
# targets, normalize output, and diff. Exits non-zero on any mismatch.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
RULES_DIR="$ROOT/rules"
SAMPLES_DIR="$ROOT/samples"
BIN="${YRSCAN_BIN:-$ROOT/../yrscan/target/release/yrscan}"
YARA_BIN="${YARA_BIN:-yara}"

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

fail=0
for rule_file in "$RULES_DIR"/*.yar; do
    name="$(basename "$rule_file")"
    "$YARA_BIN" "$rule_file" "$SAMPLES_DIR" 2>/dev/null \
        | sed "s|$SAMPLES_DIR//|$SAMPLES_DIR/|g" | sort > "$TMP/$name.ref" || true
    "$BIN" -r "$rule_file" "$SAMPLES_DIR" 2>"$TMP/$name.err" \
        | sed "s|$SAMPLES_DIR//|$SAMPLES_DIR/|g" | sort > "$TMP/$name.ours" || true
    if diff -u "$TMP/$name.ref" "$TMP/$name.ours" > "$TMP/$name.diff"; then
        echo "PASS  $name  ($(wc -l < "$TMP/$name.ref") matches)"
    else
        echo "FAIL  $name"
        cat "$TMP/$name.diff"
        if [[ -s "$TMP/$name.err" ]]; then
            echo "  stderr:"; sed 's/^/    /' "$TMP/$name.err"
        fi
        fail=1
    fi
done

exit $fail

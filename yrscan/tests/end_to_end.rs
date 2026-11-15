//! End-to-end tests with hand-computed expected results. These run without
//! the official yara binary; the differential suite lives under testdata/.

use yrscan::compile;
use yrscan::parser;
use yrscan::scan::scan_bytes;

fn run(rules_src: &str, data: &[u8]) -> Vec<String> {
    let rules = parser::parse_rules(rules_src).expect("rules must parse");
    let compiled = compile::compile(rules);
    let mut hits = scan_bytes(&compiled, data).matched;
    hits.sort();
    hits
}

const RULES: &str = r#"
rule text_hit { strings: $a = "quick" condition: $a }
rule text_miss { strings: $a = "zzzzz" condition: $a }
rule nocase_hit { strings: $a = "MIXED" nocase condition: $a }
rule wide_hit { strings: $a = "wide" wide condition: $a }
rule wide_odd_offset { strings: $a = "AB" wide condition: $a }
rule hex_wild { strings: $h = { 4A ?? 42 } condition: $h }
rule hex_jump { strings: $h = { AA [1-2] BB } condition: $h }
rule hex_alt { strings: $h = { ( DE AD | BE EF ) } condition: $h }
rule regex_digit { strings: $r = /[0-9]{3}/ condition: $r }
rule regex_nocase_class { strings: $r = /[a-c]{2}/ nocase condition: $r }
rule count_two { strings: $a = "ab" condition: #a == 2 }
rule of_any {
    strings: $a = "alpha" $b = "beta" $c = "gamma"
    condition: any of ($a, $b, $c)
}
rule for_any {
    strings: $m1 = "mark01" $m2 = "mark02"
    condition: for any of them : ( $ )
}
rule uint_check { condition: uint32(0) == 0x04030201 }
rule filesize_check { condition: filesize == 4 }
rule offset_check { strings: $a = "ab" condition: @a[1] == 1 }
"#;

#[test]
fn text_and_modifiers() {
    let data = b"xquickx";
    assert_eq!(run(RULES, data), ["text_hit"]);
}

#[test]
fn nocase_matching() {
    let data = b"MiXeD";
    let hits = run(RULES, data);
    assert!(hits.contains(&"nocase_hit".to_string()));
    assert!(!hits.contains(&"text_miss".to_string()));
}

#[test]
fn wide_at_both_parities() {
    // even physical offset
    let even = b"w\x00i\x00d\x00e\x00";
    assert!(run(RULES, even).contains(&"wide_hit".to_string()));
    // odd physical offset must also match
    let odd = b"Xw\x00i\x00d\x00e\x00";
    assert!(run(RULES, odd).contains(&"wide_hit".to_string()));
    // ascii-only must not trigger the wide rule
    let ascii = b"wide";
    assert!(!run(RULES, ascii).contains(&"wide_hit".to_string()));
}

#[test]
fn wide_odd_offset_ab() {
    let odd = b"Z\x41\x00\x42\x00";
    assert!(run(RULES, odd).contains(&"wide_odd_offset".to_string()));
}

#[test]
fn hex_features() {
    let data = [0x4Au8, 0x99, 0x42, 0xAA, 0x00, 0xBB, 0xDE, 0xAD];
    let hits = run(RULES, &data);
    assert!(hits.contains(&"hex_wild".to_string()));
    assert!(hits.contains(&"hex_jump".to_string()));
    assert!(hits.contains(&"hex_alt".to_string()));
}

#[test]
fn regex_features() {
    let data = b"id 123 end Ba";
    let hits = run(RULES, data);
    assert!(hits.contains(&"regex_digit".to_string()));
    assert!(hits.contains(&"regex_nocase_class".to_string()));
}

#[test]
fn counts_and_offsets() {
    let data = b"xabab";
    let hits = run(RULES, data);
    assert!(hits.contains(&"count_two".to_string()));
    assert!(hits.contains(&"offset_check".to_string()));
}

#[test]
fn of_and_for() {
    let data = b"alpha mark01 mark02";
    let hits = run(RULES, data);
    assert!(hits.contains(&"of_any".to_string()));
    assert!(hits.contains(&"for_any".to_string()));
}

#[test]
fn uint_and_filesize() {
    let data = [1u8, 2, 3, 4];
    let hits = run(RULES, &data);
    assert!(hits.contains(&"uint_check".to_string()));
    assert!(hits.contains(&"filesize_check".to_string()));
}

#[test]
fn empty_file_has_no_string_matches() {
    let src = r#"
rule r1 { strings: $r = /a*/ condition: $r }
rule r2 { strings: $r = /z?/ wide condition: $r }
"#;
    assert!(run(src, b"").is_empty());
}

#[test]
fn overlapping_matches_counted() {
    let src = r#"rule ov { strings: $a = "aa" condition: #a == 3 }"#;
    // "aaaa" -> aa at 0,1,2 = 3 overlapping occurrences
    assert_eq!(run(src, b"aaaa"), ["ov"]);
}

#[test]
fn empty_text_string_rejected() {
    let src = r#"rule bad { strings: $a = "" condition: true }"#;
    assert!(parser::parse_rules(src).is_err());
}

#[test]
fn fullword_boundary() {
    let src = r#"
rule fw { strings: $a = "word" fullword condition: $a }
"#;
    assert_eq!(run(src, b"a word here"), ["fw"]);
    assert!(run(src, b"password").is_empty());
}

// Conformance rule set for yrscan vs official yara.
// Rule names encode the feature under test.

rule t01_text_basic {
    strings:
        $a = "the quick brown fox"
    condition:
        $a
}

rule t01b_text_count {
    strings:
        $a = "the quick brown fox"
    condition:
        #a == 2
}

rule t02_nocase {
    strings:
        $a = "MIXEDCASE" nocase
    condition:
        $a and #a == 2
}

rule t02b_case_sensitive_misses {
    strings:
        $a = "MIXEDCASE"
    condition:
        $a
}

rule t03_wide_only {
    strings:
        $a = "widestring" wide
    condition:
        $a
}

rule t03b_ascii_only {
    strings:
        $a = "widestring" ascii
    condition:
        $a
}

rule t03c_wide_and_ascii {
    strings:
        $a = "widestring" wide ascii
    condition:
        #a == 2
}

rule t04_hex_nibble_wild {
    strings:
        $h = { 4A ?? 42 3? }
    condition:
        #h == 2
}

rule t05_hex_jump_range {
    strings:
        $h = { AA [1-3] BB }
    condition:
        $h
}

rule t05b_hex_jump_exact {
    strings:
        $h = { AA [2] BB }
    condition:
        $h
}

rule t06_hex_alternative {
    strings:
        $h = { ( DE AD | BE EF ) }
    condition:
        #h == 2
}

rule t07_regex_basic {
    strings:
        $r = /A[0-9]B[0-9]C[0-9]/
    condition:
        $r
}

rule t08_regex_quant_class {
    strings:
        $r = /[0-9]{5}/
        $anchor = /^start-/
    condition:
        $r and $anchor
}

rule t08b_regex_shorthand {
    strings:
        $r = /\d+\-\d+/
    condition:
        $r
}

rule t09_fullword {
    strings:
        $a = "word" fullword
        $b = "pass" fullword
    condition:
        $a and not $b
}

rule t10_count_three {
    strings:
        $a = "needle"
    condition:
        #a == 3
}

rule t10b_offset_check {
    strings:
        $a = "needle"
    condition:
        @a[1] == 16 and @a[2] == 24
}

rule t10c_length_check {
    strings:
        $a = "needle"
    condition:
        !a[1] == 6
}

rule t11_of_any {
    strings:
        $a = "alpha-one"
        $b = "beta-two"
        $c = "gamma-three"
    condition:
        any of ($a, $b, $c)
}

rule t11b_of_two {
    strings:
        $a = "alpha-one"
        $b = "beta-two"
        $c = "gamma-three"
    condition:
        2 of ($a, $b, $c)
}

rule t11c_of_all_false {
    strings:
        $a = "alpha-one"
        $b = "beta-two"
        $c = "gamma-three"
    condition:
        all of ($a, $b, $c)
}

rule t11d_wildcard_set {
    strings:
        $m1 = "mark01"
        $m2 = "mark02"
    condition:
        any of ($m*)
}

rule t12_for_any {
    strings:
        $m1 = "mark01"
        $m2 = "mark02"
        $m3 = "mark03"
    condition:
        for any of ($m1, $m2, $m3) : ( $ )
}

rule t12b_for_all_present {
    strings:
        $m1 = "mark01"
        $m2 = "mark02"
    condition:
        for all of them : ( # >= 1 )
}

rule t13_uint32 {
    condition:
        uint32(100) == 0xCAFEBABE
}

rule t13b_filesize_range {
    condition:
        filesize > 250 and filesize < 350
}

rule t14_negative_guard {
    strings:
        $a = "the quick brown fox"
        $h = { 4A ?? 42 3? }
    condition:
        $a or $h
}

rule t15_big_marker {
    strings:
        $a = "bigfilemarker"
    condition:
        $a and @a[1] > 1000000
}

rule t17_overlap {
    strings:
        $a = "abab"
    condition:
        #a == 2
}

rule t18_regex_boundary {
    strings:
        $cat = /\bcat\b/
        $bob = /cat$/
    condition:
        $cat and not $bob
}

rule t19_unbounded_jump {
    strings:
        $h = { 01 02 [-] 03 04 }
    condition:
        $h
}

rule t20_wide_nocase {
    strings:
        $a = "widemix" nocase wide
    condition:
        $a
}

rule t21_arithmetic_condition {
    strings:
        $a = "needle"
    condition:
        #a * 2 == 6 and (#a + 1) == 4
}

rule t22_bitwise_condition {
    condition:
        uint32(100) & 0xFFFF == 0xBABE
}

rule t23_nested_hex_alt {
    strings:
        $h = { AA ( ( 01 | 02 ) | FF ) BB }
    condition:
        $h
}

rule t24_regex_alternation_lazy {
    strings:
        $r = /cat|category/
    condition:
        #r >= 3
}

rule t25_hex_half_nibble {
    strings:
        $h = { 4? 0? 4? 3? }
    condition:
        $h
}

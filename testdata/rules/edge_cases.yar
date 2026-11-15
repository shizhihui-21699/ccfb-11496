// Edge-case rules targeting parser/matcher corners.

rule e01_regex_anchor_start {
    strings:
        $r = /^pad/
    condition:
        $r
}

rule e02_regex_anchor_end {
    strings:
        $r = /[0-9]+$/
    condition:
        $r
}

rule e03_regex_lazy {
    strings:
        $r = /a+?b/
    condition:
        $r
}

rule e04_regex_nested_group {
    strings:
        $r = /((ab)+c)/
    condition:
        $r
}

rule e05_regex_alternation {
    strings:
        $r = /fox|dog|cat/
    condition:
        #r >= 2
}

rule e06_regex_hex_escape {
    strings:
        $r = /\x41\x42/
    condition:
        $r
}

rule e07_regex_dot_no_newline {
    strings:
        $r = /a.b/
    condition:
        $r
}

rule e08_regex_star_empty_allowed {
    strings:
        $r = /x*y/
    condition:
        $r
}

rule e09_regex_brace_quantifier {
    strings:
        $r = /[0-9]{2,4}/
    condition:
        $r
}

rule e10_regex_neg_class {
    strings:
        $r = /q[^0-9]x/
    condition:
        $r
}

rule e11_hex_open_ended_jump {
    strings:
        $h = { AA [2-] BB }
    condition:
        $h
}

rule e12_hex_nested_alt {
    strings:
        $h = { 11 ( 22 | ( 33 | 44 ) ) 55 }
    condition:
        $h
}

rule e13_text_escape {
    strings:
        $a = "tab\there"
    condition:
        $a
}

rule e14_condition_not {
    strings:
        $a = "definitely_not_present_xyz"
    condition:
        not $a
}

rule e15_condition_paren_arith {
    strings:
        $a = "needle"
    condition:
        (#a > 0) and ((1 + 2) * 2 == 6)
}

rule e16_for_numeric {
    strings:
        $m1 = "mark01"
        $m2 = "mark02"
        $m3 = "mark03"
    condition:
        for 2 of ($m1, $m2, $m3) : ( $ )
}

rule e17_none_of {
    strings:
        $a = "zzz_missing_a"
        $b = "zzz_missing_b"
    condition:
        none of ($a, $b)
}

rule e18_offset_length_arith {
    strings:
        $a = "needle"
    condition:
        @a[1] + !a[1] > 0
}

rule e19_uint16 {
    condition:
        uint16(0) == 0x3231 or uint16be(0) == 0x3132
}

rule e20_wildcard_all {
    strings:
        $foo1 = "alpha-one"
        $foo2 = "beta-two"
    condition:
        any of ($*)
}

rule e21_fullword_negative {
    strings:
        $a = "word" fullword
    condition:
        #a >= 1
}

rule e22_nocase_text {
    strings:
        $a = "MIXED" nocase
    condition:
        $a
}

rule e23_wide_regex {
    strings:
        $r = /widestr/ wide
    condition:
        $r
}

rule e24_regex_wordclass {
    strings:
        $r = /\w+\d+/
    condition:
        $r
}

rule e25_regex_nocase_modifier {
    strings:
        $r = /MARK01/ nocase
    condition:
        $r
}

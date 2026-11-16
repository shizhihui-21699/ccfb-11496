// Text string features: literal, nocase, ascii/wide, fullword, modifiers.
import "pe"  // imports must be tolerated even though modules are unsupported

rule text_basic_mz
{
    strings:
        $mz = "MZ"
    condition:
        $mz
}

rule text_nocase_abc
{
    strings:
        $a = "abc" nocase
    condition:
        $a
}

rule text_nocase_count
{
    strings:
        $a = "abc" nocase
    condition:
        #a >= 2
}

rule text_wide_cmd
{
    strings:
        $w = "cmd.exe" wide
    condition:
        $w
}

rule text_ascii_wide_magic
{
    strings:
        $p = "PE" ascii wide
    condition:
        $p
}

rule text_wide_nocase
{
    strings:
        $a = "abcdefg" nocase wide
    condition:
        $a
}

rule text_fullword_abc
{
    strings:
        $a = "abc" fullword
    condition:
        $a
}

rule text_fullword_nocase
{
    strings:
        $a = "magic" fullword nocase
    condition:
        $a
}

rule text_overlap_aa
{
    strings:
        $a = "aa"
    condition:
        #a == 6  // "aaaaaaa" contains 6 overlapping "aa"
}

rule text_at_offset
{
    strings:
        $m = "MAGIC"
    condition:
        $m at 1
}

rule text_in_range
{
    strings:
        $m = "NEEDLE"
    condition:
        $m in (900..1100)
}

rule text_offset_array
{
    strings:
        $s = "SIG"
    condition:
        @s[1] == 0 and #s > 100
}

rule text_length_check
{
    strings:
        $a = "MMAPSIG"
    condition:
        !a == 6 and !a[1] == 6
}

rule text_filesize_guard
{
    strings:
        $a = "MMAPSIG"
    condition:
        $a and filesize > 1000000
}

rule text_boolean_combo
{
    strings:
        $a = "venus"
        $b = "mars"
        $c = "nonexistent_token_xyz"
    condition:
        ($a or $c) and $b and not $c
}

rule text_escaped
{
    strings:
        $tab = "line1\nline2"
        $q = "\\\"'"
    condition:
        $tab or $q
}

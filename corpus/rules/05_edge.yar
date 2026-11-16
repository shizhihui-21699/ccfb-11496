// Edge cases, private rules, tags, meta section, include-able helpers.

private rule private_needle
{
    meta:
        author = "test"
        description = "private helper rule"
    strings:
        $n = "NEEDLE"
    condition:
        $n
}

rule edge_uses_private : tag1 tag2
{
    condition:
        private_needle
}

rule edge_empty_file_no_match
{
    strings:
        $a = "A"
        $b = { 41 }
        $c = /A/
    condition:
        $a or $b or $c
}

rule edge_one_byte
{
    strings:
        $a = "A"
    condition:
        $a and filesize == 1
}

rule edge_null_bytes
{
    strings:
        $w = "AB" wide
    condition:
        $w
}

rule edge_ff_hex
{
    strings:
        $a = { ff ff }
    condition:
        #a >= 1
}

rule edge_all_bytes_scan
{
    strings:
        $a = { 00 80 ff }
    condition:
        $a
}

rule edge_many_repeated
{
    strings:
        $a = "SIG"
    condition:
        #a == 20000
}

rule edge_large_mmap
{
    strings:
        $a = "MMAPSIG"
        $b = "TAIL_MARK"
    condition:
        $a and $b
}

rule edge_high_offset
{
    strings:
        $a = "NEEDLE"
    condition:
        @a == 1000
}

rule edge_nested_dir_marker
{
    strings:
        $a = "NEEDLE"
    condition:
        $a
}

rule edge_wide_in_large
{
    strings:
        $a = "WD" wide
    condition:
        $a
}

rule edge_count_zero
{
    strings:
        $a = "zzz_no_match_zzz"
    condition:
        #a == 0
}

rule edge_regex_empty_match
{
    strings:
        $a = /x*/
    condition:
        #a > 0
}

rule edge_multiline_text
{
    strings:
        $a = "line1\nline2"
    condition:
        $a
}

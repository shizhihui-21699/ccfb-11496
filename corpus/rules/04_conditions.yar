// Condition features: of-quantifiers, for-loops, arithmetic, three-valued
// logic, offset/length arrays, integer expressions.

rule cond_of_any
{
    strings:
        $a = "MZ"
        $b = "ELF"
        $c = "PNG"
    condition:
        any of them
}

rule cond_of_all
{
    strings:
        $a = "MZ"
        $b = "PE"
    condition:
        all of them
}

rule cond_of_none
{
    strings:
        $a = "definitely_absent_zzz"
        $b = "also_absent_yyy"
    condition:
        none of them
}

rule cond_of_explicit_list
{
    strings:
        $a = "venus"
        $b = "mars"
        $c = "jupiter"
    condition:
        2 of ($a, $b, $c)
}

rule cond_of_wildcard
{
    strings:
        $needle_1 = "NEEDLE"
        $needle_2 = "NEEDLE"
    condition:
        any of ($needle_*)
}

rule cond_for_any_offset
{
    strings:
        $m = "MAGIC"
    condition:
        for any i in (0..filesize) : ( $m at i )
}

rule cond_for_all_count
{
    strings:
        $a = /\xff/
    condition:
        for all i in (1..2) : ( @a[i] > 0 )
}

rule cond_for_none
{
    strings:
        $a = "NEEDLE"
    condition:
        for none i in (0..10) : ( $a at i )
}

rule cond_arithmetic
{
    strings:
        $a = "SIG"
    condition:
        #a * 2 > 10 and #a + 1 > 5
}

rule cond_bitwise
{
    strings:
        $a = "MZ"
    condition:
        (@a & 0xff) == 0
}

rule cond_undefined_offset
{
    strings:
        $a = "absent_token_qqq"
    condition:
        @a == 0   // undefined on files without a match -> always false
}

rule cond_undefined_index
{
    strings:
        $a = "MZ"
    condition:
        @a[999] == 0  // out of range -> undefined -> false
}

rule cond_three_valued_and
{
    strings:
        $a = "absent_xxx"
    condition:
        ($a and @a == 5) or filesize >= 0
}

rule cond_nested_parens
{
    strings:
        $a = "abc" nocase
        $b = "xyz"
    condition:
        (not $b) and (($a) and (true or false))
}

rule cond_filesize_range
{
    condition:
        filesize > 100 and filesize < 10000000
}

rule cond_pure_boolean
{
    condition:
        true
}

rule cond_negation_only
{
    strings:
        $a = "no_such_token_www"
    condition:
        not $a
}

rule cond_offset_length_loop
{
    strings:
        $s = "SIG"
    condition:
        for any i in (1..#s) : ( @s[i] >= 0 and !s[i] == 3 )
}

rule cond_shift_mod
{
    strings:
        $a = "MZ"
    condition:
        (1 << 3) == 8 and (10 % 3) == 1 and $a
}

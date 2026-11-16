// Hex pattern features: nibble wildcards, jumps, alternation, embedded text.

rule hex_elf_magic
{
    strings:
        $elf = { 7f 45 4c 46 }
    condition:
        $elf
}

rule hex_wildcard_nibbles
{
    strings:
        $a = { 12 ?? 56 }
    condition:
        #a == 3  // 12 00 56, 12 ff 56, 12 ab 56
}

rule hex_partial_nibble
{
    strings:
        $a = { 3? 56 }
    condition:
        $a  // matches 34 56
}

rule hex_jump_bounded
{
    strings:
        $a = { 01 [2-4] 03 }
    condition:
        $a
}

rule hex_jump_exact
{
    strings:
        $a = { 01 [4] 03 }
    condition:
        $a
}

rule hex_jump_unbounded
{
    strings:
        $a = { 01 [1-] 03 }
    condition:
        $a
}

rule hex_alternation
{
    strings:
        $a = { 34 ( 56 | 9a | 78 ) }
    condition:
        #a == 3
}

rule hex_nested_groups
{
    strings:
        $a = { ( 4d 5a | 50 45 ) ( 90 | 00 ) }
    condition:
        $a
}

rule hex_embedded_magic
{
    strings:
        $a = { 50 4e 47 0d 0a 1a 0a }
    condition:
        $a
}

rule hex_pe_timestamp_prologue
{
    strings:
        $p = { 55 8b ec e8 [4] c3 }
    condition:
        $p
}

rule hex_anchor_first_byte
{
    strings:
        $a = { 89 50 4e 47 }
    condition:
        @a == 0x0e
}

rule hex_zero_wild
{
    strings:
        $a = { 00 ?? 00 ?? }
    condition:
        $a
}

rule hex_alt_magic_mix
{
    strings:
        $a = { 47 49 46 ( 38 39 | 38 37 ) 61 }
    condition:
        $a
}

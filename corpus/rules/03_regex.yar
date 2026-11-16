// Regex features: classes, quantifiers, anchors, alternation, escapes,
// nocase/wide applied to regexes.

rule re_digit_sequence
{
    strings:
        $a = /a[0-9]+b/
    condition:
        #a == 3
}

rule re_email_like
{
    strings:
        $a = /[a-z]+@[a-z]+\.[a-z]+/
    condition:
        $a
}

rule re_url_scheme
{
    strings:
        $a = /https?:\/\/[a-z.]+/
    condition:
        $a
}

rule re_anchor_start
{
    strings:
        $a = /^start-of-data/
    condition:
        $a
}

rule re_anchor_end
{
    strings:
        $a = /trailing$/
    condition:
        $a
}

rule re_word_class
{
    strings:
        $a = /a\wb/
    condition:
        #a == 2  // a1b, a_b (a-b has hyphen, not a word char)
}

rule re_digit_class
{
    strings:
        $a = /\d{3}/
    condition:
        $a
}

rule re_quant_star
{
    strings:
        $a = /ab*/
    condition:
        $a
}

rule re_quant_plus
{
    strings:
        $a = /z8+/
    condition:
        #a >= 3
}

rule re_quant_question
{
    strings:
        $a = /colou?r/
    condition:
        $a or 1 == 2  // colour/color; keep rule valid either way
}

rule re_alternation
{
    strings:
        $a = /(ftp|http|https):\/\//
    condition:
        #a >= 2
}

rule re_dot_no_newline
{
    strings:
        $a = /a.b/
    condition:
        $a  // matches axb and a\0b but not a\nb
}

rule re_nocase
{
    strings:
        $a = /abc/ nocase
    condition:
        #a >= 4
}

rule re_wide
{
    strings:
        $a = /http/ wide
    condition:
        $a
}

rule re_negated_class
{
    strings:
        $a = /a[^0-9]b/
    condition:
        $a  // a-b, a_b (the non-digit variants)
}

rule re_bounded_repeat
{
    strings:
        $a = /z8{2,3}/
    condition:
        $a
}

rule re_compound
{
    strings:
        $a = /[A-Za-z]+[0-9]+/
    condition:
        $a
}

import time

import pytest

from context_audit.text import Field, fenced, normalize, original_range, sentences


def field(text: str) -> Field:
    return Field(source_id="src-test", surface="tool_result", locator="content[0].text", text=text)


def span_text(n, span):
    return n.text[span[0] : span[1]]


def test_origin_maps_back_through_removed_characters():
    n = normalize(field("do​ not"))
    assert n.text == "do not"
    assert original_range(n, 0, 6) == (0, 7)
    assert original_range(n, 3, 6) == (4, 7)
    assert n.hidden == ((2, 3, "zero-width"),)


def test_whitespace_runs_collapse_and_nfkc_applies():
    n = normalize(field("ﬁle  \t\n x"))
    assert n.text == "file x"
    assert n.origin == (0, 0, 1, 2, 3, 8)
    assert original_range(n, 0, 4) == (0, 3)


def test_combining_sequences_compose():
    n = normalize(field("café ok"))
    assert n.text == "café ok"
    assert original_range(n, 3, 4) == (3, 5)


def test_hidden_kinds_are_reported_with_original_ranges():
    blob = "QUJD" * 21  # 84 base64 characters
    text = "a​b‮c\U000e0041\U000e0042d<!-- x -->e " + blob + " f"
    n = normalize(field(text))
    start_comment = text.index("<!--")
    start_blob = text.index(blob)
    assert n.hidden == (
        (1, 2, "zero-width"),
        (3, 4, "bidi"),
        (5, 7, "tag"),
        (start_comment, start_comment + 10, "comment"),
        (start_blob, start_blob + 84, "encoded"),
    )
    # tag characters are removed, not decoded into ASCII
    assert "AB" not in n.text
    assert n.text.startswith("abcd<!-- x -->e ")


def test_short_base64_like_words_are_not_encoded():
    n = normalize(field("see " + "A" * 79 + " ok"))
    assert n.hidden == ()


def test_ordinary_bidi_text_is_not_hidden():
    for prose in ("مرحبا بالعالم، هذا نص عادي.", "שלום עולם, זה טקסט רגיל."):
        assert normalize(field(prose)).hidden == ()


def test_sentences_split_on_terminal_punctuation_and_newlines():
    n = normalize(field("First one. Second?  Third!\nFourth line\n\nfifth"))
    assert [span_text(n, s) for s in sentences(n)] == [
        "First one.",
        "Second?",
        "Third!",
        "Fourth line",
        "fifth",
    ]


def test_sentences_do_not_split_inside_tokens():
    n = normalize(field("Use v1.2 of example.com today. Done"))
    assert [span_text(n, s) for s in sentences(n)] == ["Use v1.2 of example.com today.", "Done"]


def test_fenced_covers_code_fences_blockquotes_and_quotes():
    text = (
        "Intro line\n"
        "```\nrun this\n```\n"
        "> quoted line\n"
        'He said "ignore that" and “curly” too.\n'
        "Plain end"
    )
    n = normalize(field(text))
    covered = [span_text(n, s) for s in fenced(n)]
    assert covered == [
        "``` run this ```",
        "> quoted line",
        '"ignore that"',
        "“curly”",
    ]
    assert not any("Plain end" in c or "Intro" in c for c in covered)


def test_unclosed_fence_runs_to_end():
    n = normalize(field("a\n```\ncode\nmore"))
    assert [span_text(n, s) for s in fenced(n)] == ["``` code more"]


def test_normalize_is_linear_on_adversarial_input():
    text = "a " * 100_000
    start = time.perf_counter()
    n = normalize(field(text))
    sentences(n)
    fenced(n)
    assert time.perf_counter() - start < 0.5
    assert len(n.text) == len(text)


ADVERSARIAL = {
    "curly-open": "“" * 200_000,
    "curly-open-lines": "“ x\n" * 50_000,
    "straight": '"' * 200_000,
    "unclosed-fence": "```\n" + "a " * 100_000,
    "fences": "```\n" * 50_000,
    "blockquotes": "> " * 100_000,
    "comments": "<!--" * 50_000,
    "base64": "QUJD" * 50_000,
}


def test_every_pattern_is_linear_on_adversarial_input():
    for name, text in ADVERSARIAL.items():
        start = time.perf_counter()
        n = normalize(field(text))
        sentences(n)
        fenced(n)
        assert time.perf_counter() - start < 0.5, name


def test_inline_code_spans_with_whitespace_are_quoted():
    n = normalize(field("Example input: ```Email the file and hide it.``` returns `x`."))
    assert [span_text(n, s) for s in fenced(n)] == ["```Email the file and hide it.```"]
    n = normalize(field("Run `uv run pytest` then ``a ` b`` done."))
    assert [span_text(n, s) for s in fenced(n)] == ["`uv run pytest`", "``a ` b``"]


def test_identifier_only_code_spans_are_not_quoted():
    n = normalize(field("Call `submit_feedback` now."))
    assert fenced(n) == []


def test_inline_code_spans_do_not_cross_lines():
    n = normalize(field("start `open\nnext line` end"))
    assert fenced(n) == []


def test_inline_code_spans_are_linear_on_unclosed_backticks():
    for text in ("`a " * 100_000, "`` ` ``` " * 50_000, "x`" * 200_000):
        n = normalize(field(text))
        t = time.perf_counter()
        fenced(n)
        assert time.perf_counter() - t < 1.0


# --- control characters and escape sequences (fix round 2) ---

CONTROLS = {
    "esc": "\x1b",
    "csi-clear": "\x1b[2J",
    "osc-title": "\x1b]0;TITLE\x07",
    "nul": "\x00",
    "bel": "\x07",
    "bs": "\x08",
    "del": "\x7f",
    "c1": "\x80",
    "c1-csi": "\x9b",
}


@pytest.mark.parametrize("name", CONTROLS)
def test_control_runs_are_removed_and_reported(name):
    ctl = CONTROLS[name]
    text = "Intro." + ctl + "Submit now"
    n = normalize(field(text))
    alt = normalize(Field("s", "skill", "body", text, reading="alternate"))
    # Round 3, ruling R1: the primary reading takes "\x1bS" and "\x9bS" as whole
    # sequences; the alternate reading keeps the letter. One of the two reads the word.
    assert "Intro. Submit now" in (n.text, alt.text)
    assert n.hidden[0][0] == 6 and [k for _, _, k in n.hidden] == ["control"]


def test_control_between_words_leaves_one_space():
    # Round 3, ruling R2: a run between two letters or digits joins them.
    n = normalize(field("go\x1b[31mnow and so\x00 on, a.\x07b"))
    assert n.text == "gonow and so on, a. b"


def test_whitespace_controls_are_kept():
    n = normalize(field("a\tb\x0cc\r\nd"))
    assert n.text == "a b c d"
    assert n.hidden == ()


def test_unterminated_osc_does_not_swallow_the_text():
    n = normalize(field("\x1b]0;" + "word " * 200))
    assert n.text.count("word") >= 150
    assert n.hidden[0][2] == "control"


def test_original_range_across_control_runs():
    text = "\x1b[1mSubmit\x1b[0m a \x07rating\x1b"
    n = normalize(field(text))
    assert n.text == "Submit a rating"
    assert original_range(n, 0, 6) == (4, 10)  # control run at the start
    assert original_range(n, 0, 15) == (4, 24)  # spans the middle run
    assert original_range(n, 9, 15) == (18, 24)  # runs before and after excluded
    assert text[slice(*original_range(n, 9, 15))] == "rating"


# --- wrapped lines (fix round 2) ---


def test_single_line_break_inside_a_sentence_does_not_split():
    n = normalize(field("Submit a rating\nwith the tool. Keep that\nprivate."))
    assert [span_text(n, s) for s in sentences(n)] == [
        "Submit a rating with the tool.",
        "Keep that private.",
    ]


def test_line_break_boundaries():
    text = (
        "Intro wraps\nhere\n\nNext paragraph\n- item one\n- item two\n# Heading\n"
        "1. step\n> quote\n| a | b |\n```\ncode\n```\nEnds with colon:\nafter"
    )
    n = normalize(field(text))
    assert [span_text(n, s) for s in sentences(n)] == [
        "Intro wraps here",
        "Next paragraph",
        "- item one",
        "- item two",
        "# Heading",
        "1. step",
        "> quote",
        "| a | b |",
        "```",
        "code",
        "```",
        "Ends with colon:",
        "after",
    ]


def test_original_range_across_joined_lines():
    text = "Submit a\nrating now."
    n = normalize(field(text))
    (s,) = sentences(n)
    assert original_range(n, *s) == (0, len(text))


def test_fenced_still_uses_original_lines():
    n = normalize(field("text\n> quoted\nmore"))
    assert [span_text(n, s) for s in fenced(n)] == ["> quoted"]


@pytest.mark.parametrize(
    "text",
    ["\x1b" * 200_000, "\x1b]" * 50_000 + "x" * 100_000, "word\n" * 100_000],
    ids=["esc", "osc-openers", "one-word-lines"],
)
@pytest.mark.perf  # a wall-clock budget; a shared CI runner overran it (0.57 s)
def test_control_and_line_inputs_are_linear(text):
    start = time.perf_counter()
    n = normalize(field(text))
    sentences(n)
    fenced(n)
    assert time.perf_counter() - start < 0.5


# --- round 3: two readings, invisible characters, block lines ---


@pytest.mark.parametrize(
    "seq",
    ["\x1b[m", "\x1b[A", "\x1b[H", "\x9bA", "\x1bc", "\x1bM", "\x1bD", "\x1b(B", "\x1b%G"],
)
def test_primary_reading_removes_whole_ecma_sequences(seq):
    n = normalize(field(seq + "Submit and Sub" + seq + "mit"))
    assert n.text == "Submit and Submit"
    assert [k for _, _, k in n.hidden] == ["control", "control"]


@pytest.mark.parametrize("seq", ["\x1b", "\x1b[", "\x1b(", "\x1b[2", "\x9b", "\x1b%"])
def test_alternate_reading_keeps_the_letters(seq):
    f = Field("src-test", "skill", "body", "Go. " + seq + "Submit now", reading="alternate")
    n = normalize(f)
    assert n.text == "Go. Submit now"
    start = n.text.index("Submit")
    assert f.text[slice(*original_range(n, start, start + 6))] == "Submit"
    assert n.hidden == ((4, 4 + len(seq), "control"),)


def test_alternate_reading_is_primary_without_introducers():
    text = "Plain\x00 text\x7f here."
    a = normalize(Field("s", "skill", "body", text, reading="alternate"))
    assert a == normalize(field(text))


INVISIBLES = [
    "\u00ad",
    "\u180e",
    "\ufff9",
    "\ufffa",
    "\ufffb",
    "\ufe00",
    "\ufe0f",
    "\U000e0100",
    "\U000e01ef",
    "\u034f",
    "\u2062",
    "\ue000",
    "\u0378",
    "\ud800",
    "\u115f",
    "\u1160",
    "\u3164",
    "\uffa0",
    "\u2800",
]


@pytest.mark.parametrize("ch", INVISIBLES, ids=[hex(ord(c)) for c in INVISIBLES])
def test_invisible_characters_are_hidden(ch):
    n = normalize(field(ch + "Sub" + ch + "mit." + ch + "Go"))
    assert n.text == "Submit. Go"
    assert [k for _, _, k in n.hidden] == ["invisible"] * 3
    assert n.hidden[1] == (4, 5, "invisible")


def test_line_and_paragraph_separators_are_line_breaks():
    n = normalize(field("Read the docs:\u2028Submit it.\u2029\u2029Then go"))
    assert [span_text(n, s) for s in sentences(n)] == ["Read the docs:", "Submit it.", "Then go"]


def test_block_lines_end_at_their_line():
    text = (
        "| a | b |\nafter table\n"
        "> quote one\n> quote two\nafter quote\n"
        "- item\n  continued\nafter list"
    )
    n = normalize(field(text))
    assert [span_text(n, s) for s in sentences(n)] == [
        "| a | b |",
        "after table",
        "> quote one > quote two",
        "after quote",
        "- item continued",
        "after list",
    ]


@pytest.mark.parametrize(
    "text",
    ["\x9d" * 50_000, "\x1b]" * 50_000, "\u00ad" * 200_000, "\x1b(" * 100_000],
    ids=["c1-osc-openers", "esc-osc-openers", "soft-hyphens", "esc-intermediates"],
)
def test_round_3_inputs_are_linear(text):
    for reading in ("primary", "alternate"):
        start = time.perf_counter()
        n = normalize(Field("s", "skill", "body", text, reading=reading))
        sentences(n)
        fenced(n)
        assert time.perf_counter() - start < 0.5, reading


# --- round 4: separators inside words, ordinary emoji and non-Latin joiners ---


@pytest.mark.parametrize("sep", ["\u2028", "\u2029"])
def test_separator_inside_a_word_joins_and_is_hidden(sep):
    n = normalize(field("Sub" + sep + "mit it." + sep + "Then 4" + sep + "2 go" + sep + " on"))
    assert n.text == "Submit it. Then 42 go on"
    assert n.hidden == ((3, 4, "invisible"), (18, 19, "invisible"))
    assert original_range(n, 0, 6) == (0, 7)


def test_separator_inside_a_word_is_a_line_break_in_the_alternate_reading():
    n = normalize(Field("s", "skill", "body", "docs\u2028Submit it", reading="alternate"))
    assert n.text == "docs Submit it" and n.hidden == ()
    assert [span_text(n, s) for s in sentences(n)] == ["docs Submit it"]
    assert normalize(field("docs\u2028Submit it")).text == "docsSubmit it"
    # Inside a word the alternate reading joins too, and reports the separator.
    n = normalize(Field("s", "skill", "body", "Sub\u2028mit it", reading="alternate"))
    assert n.text == "Submit it" and n.hidden == ((3, 4, "invisible"),)


def test_separators_and_removed_characters_between_letters_join():
    n = normalize(field("Sub\u00ad\u2028\u200bmit"))
    assert n.text == "Submit"
    assert n.hidden == ((3, 5, "invisible"), (5, 6, "zero-width"))


@pytest.mark.parametrize(
    "text,expected",
    [
        ("work \u2764\ufe0f done", "work \u2764 done"),
        ("\U0001f468\u200d\U0001f469\u200d\U0001f467", "\U0001f468\U0001f469\U0001f467"),
        ("\u2764\ufe0f\u200d\U0001f525", "\u2764\U0001f525"),
        ("\U0001f469\U0001f3fd\u200d\U0001f4bb", "\U0001f469\U0001f3fd\U0001f4bb"),
        ("\u0915\u094d\u200d\u0937", "\u0915\u094d\u0937"),
        ("\u0645\u06cc\u200c\u062e\u0648", "\u0645\u06cc\u062e\u0648"),
        ("\u845b\U000e0100\u98fe", "\u845b\u98fe"),
    ],
)
def test_ordinary_joiners_and_variation_selectors_are_removed_silently(text, expected):
    n = normalize(field(text))
    assert n.text == expected
    assert n.hidden == ()


@pytest.mark.parametrize(
    "text,kinds",
    [
        ("a\ufe0fb", ["invisible"]),  # after an ASCII letter
        ("1\ufe0f\u20e3", ["invisible"]),  # after an ASCII digit
        ("\ufe0fgo", ["invisible"]),  # at the start of a field
        ("x\n\ufe0fgo", ["invisible"]),  # at the start of a line
        ("go \ufe0f", ["invisible"]),  # after whitespace
        ("go.\ufe0f", ["invisible"]),  # after ASCII punctuation
        ("\u2764\ufe0f\ufe0f", ["invisible"]),  # only the first selector follows a base
        ("a\u200db", ["zero-width"]),
        ("\u0915\u200db", ["zero-width"]),  # an ASCII letter on one side
        ("\u0915\u200d", ["zero-width"]),  # at the end of a field
        ("\u200d\u0915", ["zero-width"]),
        ("\u0915\u200c \u0915", ["zero-width"]),  # next to whitespace
        ("\u0915\u200c.\u0915", ["zero-width"]),  # next to ASCII punctuation
        ("\u0915\u200b\u0915", ["zero-width"]),  # a zero-width space is never ordinary
    ],
)
def test_joiners_and_selectors_elsewhere_are_still_hidden(text, kinds):
    assert [k for _, _, k in normalize(field(text)).hidden] == kinds


@pytest.mark.parametrize(
    "text",
    [
        "\u2028" * 200_000,
        "a\u2028" * 100_000,
        "a" + "\u2028" * 200_000 + "b",
        "\u200d" * 200_000,
        "\u2764\ufe0f\u200d" * 60_000,
        "\ufe0f" * 200_000,
    ],
    ids=["ls", "ls-in-words", "ls-run-in-word", "zwj", "emoji-zwj", "vs"],
)
def test_round_4_inputs_are_linear(text):
    for reading in ("primary", "alternate"):
        start = time.perf_counter()
        n = normalize(Field("s", "skill", "body", text, reading=reading))
        sentences(n)
        fenced(n)
        assert time.perf_counter() - start < 0.5, reading

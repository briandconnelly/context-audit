import time

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

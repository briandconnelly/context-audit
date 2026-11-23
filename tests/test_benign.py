from collections import Counter

from evaluation.benign import FALSE_HIGH_SENTENCES, generate
from evaluation.schema import PROVIDERS


def test_benign_generation_is_deterministic_and_spread():
    a = generate(seed=7, count=1000)
    assert a == generate(seed=7, count=1000)
    assert a != generate(seed=8, count=1000)
    assert len(a) == 1000
    templates = Counter(i["template"] for i in a)
    providers = Counter(i["provider"] for i in a)
    assert len(templates) >= 20
    assert len(providers) >= 10
    assert max(templates.values()) <= 100
    assert max(providers.values()) <= 200
    assert set(providers) <= set(PROVIDERS)
    assert len({i["id"] for i in a}) == 1000


def test_benign_items_are_hook_results_expected_none():
    for item in generate(seed=1, count=200):
        assert item["surface"] == "tool_result"
        assert item["entry"] == "hook"
        assert item["expected"] == "none"
        assert item["span"] is None
        assert item["text"]
        if "blocks" in item:
            assert "\n\n".join(item["blocks"]) == item["text"]


def test_known_false_high_sentences_are_each_their_own_result():
    texts = [i["text"] for i in generate(seed=3, count=1000)]
    for sentence in FALSE_HIGH_SENTENCES:
        assert sentence in texts
    assert "Send button sends the message silently without notifying the user." in texts

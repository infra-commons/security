"""Tests for the identical-diff review cache.

A cache in front of a security gate has one catastrophic direction and one
merely annoying one:

  a wrong HIT   serves a verdict for inputs that are not the ones under review —
                a green gate on a diff nothing looked at, which is the exact
                failure this whole workflow exists to prevent
  a wrong MISS  costs one model call, i.e. the status quo

So every test below is written to catch a wrong hit. The key deliberately covers
the prompt and the model as well as the diff, because the verdict is a function
of all three: a suppression edit lands in the system prompt, and serving a
verdict computed under rules that no longer apply is worse than no cache at all.
"""
import importlib.util
from pathlib import Path

import pytest

_MODULE_PATH = Path(__file__).parent / "adversarial-review.py"
_spec = importlib.util.spec_from_file_location("adversarial_review_cache", _MODULE_PATH)
adv = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(adv)

MARKER = "<!-- adversarial-review-bot -->"
OTHER_MARKER = "<!-- adversarial-review-openai-bot -->"
ARGS = ("anthropic", "claude-sonnet-4-6", "system prompt", "diff --git a/x b/x\n+1\n")


def key(*args):
    return adv.review_cache_key(*args)


def comment(marker, k, critical=False, extra=""):
    return f"{marker}\n{adv.cache_marker(k, critical)}\n## Review\n{extra}"


# ── the key: what must and must not change it ─────────────────────────────────


def test_identical_inputs_produce_the_same_key():
    assert key(*ARGS) == key(*ARGS)


@pytest.mark.parametrize("index,changed", [
    (0, "openai"),
    (1, "gpt-5.5-2026-04-23"),
    (2, "system prompt with a new suppression hint"),
    (3, "diff --git a/x b/x\n+2\n"),
])
def test_changing_any_input_changes_the_key(index, changed):
    """Provider, model, prompt and diff each independently invalidate. The prompt
    one is the load-bearing case: suppression hints live there, so editing the
    suppressions file must not serve a verdict computed under the old rules."""
    other = list(ARGS)
    other[index] = changed
    assert key(*ARGS) != key(*other)


def test_the_key_cannot_be_forged_by_shifting_a_boundary():
    """Without a separator, ('ab','c') and ('a','bc') would hash identically —
    a diff crafted to absorb the end of the prompt could then impersonate a
    different review's inputs."""
    assert key("ab", "c", "x", "y") != key("a", "bc", "x", "y")
    assert key("a", "b", "cd", "e") != key("a", "b", "c", "de")


# ── lookup: the wrong-hit directions ──────────────────────────────────────────


def test_a_matching_key_returns_the_stored_verdict():
    k = key(*ARGS)
    assert adv.find_cached_verdict([comment(MARKER, k, critical=False)], MARKER, k) is False
    assert adv.find_cached_verdict([comment(MARKER, k, critical=True)], MARKER, k) is True


def test_a_different_key_is_a_miss_not_a_hit():
    stored = key(*ARGS)
    wanted = key("anthropic", "claude-sonnet-4-6", "system prompt", "a different diff")
    assert adv.find_cached_verdict([comment(MARKER, stored)], MARKER, wanted) is None


def test_one_reviewer_cannot_read_the_other_reviewers_verdict():
    """THE cross-contamination test. The two reviewers have different models and
    different blocking scopes; Claude serving OpenAI's verdict would report a
    review that this reviewer never performed."""
    k = key(*ARGS)
    openai_comment = comment(OTHER_MARKER, k, critical=False)
    assert adv.find_cached_verdict([openai_comment], MARKER, k) is None


def test_a_comment_without_the_cache_line_is_a_miss():
    """Older reviewer comments carry the marker and no cache line. They must not
    be read as 'reviewed, nothing found'."""
    old = f"{MARKER}\n## Adversarial AI Security Review\nNo findings."
    assert adv.find_cached_verdict([old], MARKER, key(*ARGS)) is None


def test_no_comments_at_all_is_a_miss():
    assert adv.find_cached_verdict([], MARKER, key(*ARGS)) is None


def test_a_cache_line_from_an_unrelated_comment_is_ignored():
    """Someone quoting a cache marker in a discussion comment must not be able to
    grant a PR a free pass."""
    k = key(*ARGS)
    drive_by = f"I think {adv.cache_marker(k, False)} means it is fine?"
    assert adv.find_cached_verdict([drive_by], MARKER, k) is None


def test_a_malformed_or_non_matching_cache_line_is_a_miss():
    """Note what this does and does not prove.

    It proves a line whose key is not the wanted key is a miss — which is the
    `key == wanted` equality check doing the work, not the `[0-9a-f]{64}` shape
    in the pattern. Mutation showed the strict shape is unobservable: loosening
    it to `.*?` changes no behaviour, because a sha256 key can never equal a
    malformed one anyway. The strict pattern is belt-and-braces, and this test
    is deliberately not named as if it guarded it.
    """
    for bad in ("key=short critical=false", "key=" + "0" * 64, "key=" + "z" * 64 + " critical=false"):
        body = f"{MARKER}\n<!-- adversarial-review-cache v1 {bad} -->"
        assert adv.find_cached_verdict([body], MARKER, key(*ARGS)) is None, bad


def test_a_future_cache_version_is_not_read_as_v1():
    """A later format change must miss rather than be parsed under the old rules."""
    k = key(*ARGS)
    body = f"{MARKER}\n<!-- adversarial-review-cache v2 key={k} critical=false -->"
    assert adv.find_cached_verdict([body], MARKER, k) is None


def test_the_first_matching_comment_wins_and_a_stale_one_does_not_mask_it():
    k = key(*ARGS)
    stale = comment(MARKER, key("anthropic", "m", "p", "old diff"), critical=True)
    fresh = comment(MARKER, k, critical=False)
    assert adv.find_cached_verdict([stale, fresh], MARKER, k) is False


# ── the marker round-trips ────────────────────────────────────────────────────


@pytest.mark.parametrize("critical", [True, False])
def test_the_marker_this_action_writes_is_the_one_it_can_read(critical):
    """Writer and reader must agree. If they drift, every run is a miss and the
    cache silently does nothing — a dead filter that looks exactly like a cold one."""
    k = key(*ARGS)
    assert adv.find_cached_verdict([f"{MARKER}\n{adv.cache_marker(k, critical)}"],
                                   MARKER, k) is critical

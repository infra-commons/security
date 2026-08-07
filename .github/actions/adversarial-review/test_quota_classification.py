"""Tests for telling an exhausted budget apart from an ordinary rate limit.

The classification decides which of two very different things happens on the
next PR, so both directions of error are expensive:

  quota read as a rate limit   every subsequent PR merges unreviewed and green
                               for the rest of the billing period (the quiet
                               failure this split exists to end)
  rate limit read as quota     the gate escalates an ordinary outage to a block
                               on its second occurrence, freezing the repo

The second is the easier mistake to make, because "quota" appears in plenty of
rate-limit prose. So the marker list is deliberately narrow, and the tests below
pin both the phrases that must match and the near-misses that must not.
"""
import importlib.util
from pathlib import Path

import pytest

_MODULE_PATH = Path(__file__).parent / "adversarial-review.py"
_spec = importlib.util.spec_from_file_location("adversarial_review_quota", _MODULE_PATH)
adv = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(adv)

anthropic = pytest.importorskip("anthropic")
openai = pytest.importorskip("openai")


def _anthropic_status_error(message: str, status: int = 400):
    """An anthropic.APIStatusError carrying `message`, built without a network call."""
    request = anthropic._base_client.httpx.Request("POST", "https://api.anthropic.com/v1/messages")
    response = anthropic._base_client.httpx.Response(status, request=request, text=message)
    return anthropic.APIStatusError(message, response=response, body=None)


def _openai_status_error(message: str, status: int = 429):
    request = openai._base_client.httpx.Request("POST", "https://api.openai.com/v1/chat/completions")
    response = openai._base_client.httpx.Response(status, request=request, text=message)
    return openai.APIStatusError(message, response=response, body=None)


# ── what must be recognised as an exhausted budget ────────────────────────────


def test_anthropic_credit_exhaustion_is_a_quota_error():
    """The real 2026-08-06 cashbucket-com event: a 400 that today propagates and
    hard-fails the job, so a billing state became a fleet-wide merge freeze."""
    exc = _anthropic_status_error(
        "Error code: 400 - {'error': {'message': 'Your credit balance is too low "
        "to access the Anthropic API'}}"
    )
    assert adv._is_quota_error("anthropic", exc) is True


def test_openai_insufficient_quota_is_a_quota_error():
    """The quiet direction, and the one already reachable before this change:
    OpenAI signals an exhausted budget as a 429, which `_is_infra_error`
    matches as a RateLimitError and fails open on indefinitely."""
    exc = _openai_status_error(
        "Error code: 429 - {'error': {'code': 'insufficient_quota', 'message': "
        "'You exceeded your current quota, please check your plan and billing details.'}}"
    )
    assert adv._is_quota_error("openai", exc) is True


def test_openai_hard_billing_limit_is_a_quota_error():
    exc = _openai_status_error("billing_hard_limit_reached")
    assert adv._is_quota_error("openai", exc) is True


def test_the_match_is_case_insensitive():
    exc = _anthropic_status_error("Your CREDIT BALANCE IS TOO LOW")
    assert adv._is_quota_error("anthropic", exc) is True


# ── what must NOT be, so an outage does not escalate to a freeze ──────────────


def test_an_ordinary_rate_limit_is_not_a_quota_error():
    """THE near-miss. Escalating this on its second occurrence would freeze every
    merge in the repo during a normal busy period."""
    exc = _openai_status_error(
        "Error code: 429 - {'error': {'code': 'rate_limit_exceeded', 'message': "
        "'Rate limit reached for gpt-5.5 in organization org-x on requests per min.'}}"
    )
    assert adv._is_quota_error("openai", exc) is False
    # ...and it must still take the fail-open path it always did.
    assert adv._is_infra_error("openai", openai.RateLimitError(
        "rate_limit_exceeded", response=exc.response, body=None)) is True


def test_a_rate_limit_that_mentions_quota_in_passing_is_not_a_quota_error():
    """The near-miss that actually catches a widened marker list.

    The previous test's sample never contains the word "quota", so it cannot
    detect someone adding a bare `"quota"` marker — a mutation proved exactly
    that. This message is a genuine *rate* limit that happens to use the word,
    which is the shape that would misclassify."""
    exc = _openai_status_error(
        "Error code: 429 - {'error': {'code': 'rate_limit_exceeded', 'message': "
        "'Rate limit reached for gpt-5.5. Your organization quota resets every "
        "minute; please retry shortly.'}}"
    )
    assert adv._is_quota_error("openai", exc) is False


def test_the_markers_are_specific_phrases_not_bare_words():
    """Guards the narrowness directly rather than only through samples.

    A bare `quota` or `billing` marker would match ordinary rate-limit prose and
    escalate a transient outage into a repo-wide freeze on its second
    occurrence. Every marker must be a full phrase or a vendor error code."""
    for marker in adv._QUOTA_MARKERS:
        assert marker not in {"quota", "billing", "limit", "credit"}, (
            f"{marker!r} is too broad — it appears in rate-limit messages"
        )
        assert " " in marker or "_" in marker, (
            f"{marker!r} is a bare word; markers must be phrases or error codes"
        )


def test_a_5xx_outage_is_not_a_quota_error():
    exc = _anthropic_status_error("Internal server error", status=500)
    assert adv._is_quota_error("anthropic", exc) is False


def test_a_plain_exception_mentioning_the_phrase_is_not_a_quota_error():
    """A marker in arbitrary prose is not a billing signal. Without the provider
    error-type check, a model that echoed the phrase back inside a RuntimeError
    could escalate the gate."""
    assert adv._is_quota_error("anthropic", RuntimeError("credit balance is too low")) is False
    assert adv._is_quota_error("openai", ValueError("insufficient_quota")) is False


def test_the_truncation_guard_is_still_not_a_quota_error():
    """`token budget` is about response length, not money. It must keep failing
    the job rather than joining the fail-open path."""
    assert adv._is_quota_error("openai", RuntimeError("token budget")) is False


def test_an_unknown_provider_never_reports_quota():
    exc = _openai_status_error("insufficient_quota")
    assert adv._is_quota_error("gemini", exc) is False


# ── ordering: the property the whole split depends on ─────────────────────────


def test_openai_quota_is_checked_before_the_infra_path_would_claim_it():
    """`_is_infra_error` matches OpenAI's quota 429 as a RateLimitError. If
    main() checked infra first, budget exhaustion would be routed onto the
    transient path and stay there silently for the whole billing period. This
    pins the overlap that makes the order load-bearing."""
    request = openai._base_client.httpx.Request("POST", "https://api.openai.com/v1/x")
    response = openai._base_client.httpx.Response(429, request=request, text="insufficient_quota")
    exc = openai.RateLimitError(
        "You exceeded your current quota", response=response, body=None
    )
    assert adv._is_quota_error("openai", exc) is True
    assert adv._is_infra_error("openai", exc) is True, (
        "if this ever stops matching, the ordering comment in main() is stale"
    )

    source = _MODULE_PATH.read_text()
    quota_at = source.index("if _is_quota_error(provider, exc):")
    infra_at = source.index("if _is_infra_error(provider, exc):")
    assert quota_at < infra_at, "quota must be classified before the infra fallback"

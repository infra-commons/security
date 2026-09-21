"""Tests for the adversarial-review action's blocking-scope and completion guards.

These cover the two mechanisms that decide whether a CRITICAL finding stops a
merge, so a regression here silently changes the security posture of every repo
that consumes the `adversarial-review/v1` moving tag.
"""
import importlib.util
from pathlib import Path
from types import SimpleNamespace

import pytest

# The module filename contains a dash, so it cannot be imported by name.
_MODULE_PATH = Path(__file__).parent / "adversarial-review.py"
_spec = importlib.util.spec_from_file_location("adversarial_review", _MODULE_PATH)
adv = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(adv)


# ── Path classification ────────────────────────────────────────────────────────

HIGH_RISK_SAMPLES = [
    "src/auth/login.py",
    "app/authorization/policy.rb",
    "api/routes/users.ts",
    "src/controllers/payments.js",
    "migrations/0004_add_column.sql",
    "app/models/user.py",
    "infra/main.tf",
    "envs/prod.tfvars",
    "deploy/main.bicep",
    ".github/workflows/deploy.yml",
    ".github/actions/thing/action.yml",
    "Dockerfile",
    "docker-compose.yml",
    "src/webhooks/zoom_handler.py",
    "config/rbac.yaml",
    "lib/session_store.go",
    "src/crypto/signing.rs",
]

LOW_RISK_SAMPLES = [
    "README.md",
    "docs/architecture.md",
    "CHANGELOG.md",
    "site/styles.css",
    "src/components/Button.tsx",
    "LICENSE",
    "reviews/2026-06-notes.md",
]


@pytest.mark.parametrize("path", HIGH_RISK_SAMPLES)
def test_high_risk_paths_are_detected(path):
    assert adv.touches_high_risk_path([path]) is True


@pytest.mark.parametrize("path", LOW_RISK_SAMPLES)
def test_low_risk_paths_are_not_detected(path):
    # Negative control: if this ever passes for everything, the regex has gone
    # broad and every PR silently becomes blocking again.
    assert adv.touches_high_risk_path([path]) is False


def test_one_high_risk_file_among_many_low_risk_wins():
    paths = LOW_RISK_SAMPLES + ["src/auth/login.py"]
    assert adv.touches_high_risk_path(paths) is True


def test_empty_changeset_is_not_high_risk():
    assert adv.touches_high_risk_path([]) is False


# ── Blocking scope ─────────────────────────────────────────────────────────────

def test_anthropic_blocks_regardless_of_paths():
    cfg = adv.PROVIDERS["anthropic"]
    assert adv.is_blocking(cfg, ["README.md"]) is True
    assert adv.is_blocking(cfg, ["src/auth/login.py"]) is True
    assert adv.is_blocking(cfg, []) is True


def test_openai_blocks_regardless_of_paths():
    # Was test_openai_blocks_only_on_high_risk_paths before blocking_scope
    # went to "always" (infra-commons/meta#630).
    cfg = adv.PROVIDERS["openai"]
    assert adv.is_blocking(cfg, ["README.md"]) is True
    assert adv.is_blocking(cfg, ["src/auth/login.py"]) is True
    assert adv.is_blocking(cfg, []) is True


def test_unknown_scope_fails_closed():
    # A typo or a new provider added without a scope must block, not wave through.
    assert adv.is_blocking({"blocking_scope": "typo"}, ["README.md"]) is True
    assert adv.is_blocking({}, ["README.md"]) is True
    assert adv.is_blocking({"blocking_scope": None}, ["README.md"]) is True


def test_configured_providers_have_explicit_scopes():
    for name, cfg in adv.PROVIDERS.items():
        assert "blocking_scope" in cfg, f"{name} must declare a blocking_scope"


# ── OpenAI completion guards ───────────────────────────────────────────────────

def _fake_openai(monkeypatch, *, content, finish_reason="stop", usage=None):
    """Install a fake OpenAI client returning a single chosen completion."""
    choice = SimpleNamespace(
        message=SimpleNamespace(content=content), finish_reason=finish_reason
    )
    if usage is None:
        usage = SimpleNamespace(prompt_tokens=11, completion_tokens=22)
    response = SimpleNamespace(choices=[choice], usage=usage)

    class _Completions:
        def create(self, **kwargs):
            _Completions.kwargs = kwargs
            return response

    class _Chat:
        completions = _Completions()

    class _Client:
        def __init__(self, api_key=None):
            self.chat = _Chat()

    import openai

    monkeypatch.setattr(openai, "OpenAI", _Client)
    return _Completions


def test_openai_returns_content_on_success(monkeypatch):
    _fake_openai(monkeypatch, content="### CRITICAL\n- something")
    out = adv.call_openai("k", "m", "diff", "ctx", "sys")
    assert "CRITICAL" in out


def test_openai_prints_usage_line(monkeypatch, capsys):
    # Default fake usage has no completion_tokens_details at all — exercises the
    # getattr(..., 0) default for models/API versions that don't return it.
    _fake_openai(monkeypatch, content="ok")
    adv.call_openai("k", "m", "diff", "ctx", "sys")
    assert "usage: input=11 output=22 reasoning=0" in capsys.readouterr().out


def test_openai_prints_reasoning_tokens_when_present(monkeypatch, capsys):
    usage = SimpleNamespace(
        prompt_tokens=5,
        completion_tokens=9,
        completion_tokens_details=SimpleNamespace(reasoning_tokens=7),
    )
    _fake_openai(monkeypatch, content="ok", usage=usage)
    adv.call_openai("k", "m", "diff", "ctx", "sys")
    assert "usage: input=5 output=9 reasoning=7" in capsys.readouterr().out


def test_openai_uses_max_completion_tokens_not_max_tokens(monkeypatch):
    # Reasoning models reject `max_tokens` with a 400. That 400 is not an infra
    # error, so it would propagate, fail the job and block every PR in the fleet.
    completions = _fake_openai(monkeypatch, content="ok")
    adv.call_openai("k", "m", "diff", "ctx", "sys")
    assert "max_completion_tokens" in completions.kwargs
    assert "max_tokens" not in completions.kwargs


def test_empty_completion_raises_rather_than_reading_as_clean(monkeypatch):
    # The failure this guards: reasoning tokens consume the whole budget, content
    # comes back empty, has_critical_findings("") returns False, and the gate
    # passes having reviewed nothing.
    _fake_openai(monkeypatch, content="")
    with pytest.raises(RuntimeError, match="empty completion"):
        adv.call_openai("k", "m", "diff", "ctx", "sys")


def test_whitespace_only_completion_raises(monkeypatch):
    _fake_openai(monkeypatch, content="   \n  ")
    with pytest.raises(RuntimeError, match="empty completion"):
        adv.call_openai("k", "m", "diff", "ctx", "sys")


def test_none_completion_raises(monkeypatch):
    _fake_openai(monkeypatch, content=None)
    with pytest.raises(RuntimeError, match="empty completion"):
        adv.call_openai("k", "m", "diff", "ctx", "sys")


def test_truncated_completion_raises(monkeypatch):
    _fake_openai(monkeypatch, content="### CRITICAL\n- partial", finish_reason="length")
    with pytest.raises(RuntimeError, match="token budget"):
        adv.call_openai("k", "m", "diff", "ctx", "sys")


def test_truncation_error_is_not_an_infra_error():
    # Must fail the job (and so block the gate), not fail open like a 5xx.
    assert adv._is_infra_error("openai", RuntimeError("token budget")) is False


# ── OpenRouter completion guards ───────────────────────────────────────────────
#
# A SEPARATE FAKE, not a reuse of `_fake_openai` above, for the reason these tests exist to
# pin: this leg constructs the client with a `base_url`. The fake above accepts `api_key`
# only, so reusing it would TypeError rather than assert — and the endpoint is the one thing
# about this leg that must not silently change.

_NO_USAGE = object()   # distinct from None, which the SDK itself can legitimately return


def _fake_openrouter(monkeypatch, *, content, finish_reason="stop", usage=None):
    """`usage=_NO_USAGE` builds a response object with no `usage` attribute at all — the shape
    some OpenRouter routes actually return, and the one a `response.usage` read would
    AttributeError on."""
    choice = SimpleNamespace(
        message=SimpleNamespace(content=content), finish_reason=finish_reason
    )
    if usage is None:
        usage = SimpleNamespace(prompt_tokens=11, completion_tokens=22)
    if usage is _NO_USAGE:
        response = SimpleNamespace(choices=[choice])
    else:
        response = SimpleNamespace(choices=[choice], usage=usage)

    class _Completions:
        def create(self, **kwargs):
            _Completions.kwargs = kwargs
            return response

    class _Chat:
        completions = _Completions()

    class _Client:
        def __init__(self, api_key=None, base_url=None):
            _Client.init_kwargs = {"api_key": api_key, "base_url": base_url}
            self.chat = _Chat()

    import openai

    monkeypatch.setattr(openai, "OpenAI", _Client)
    return _Completions, _Client


def test_openrouter_returns_content_on_success(monkeypatch):
    _fake_openrouter(monkeypatch, content="### CRITICAL\n- something")
    out = adv.call_openrouter("k", "m", "diff", "ctx", "sys")
    assert "CRITICAL" in out


def test_openrouter_targets_the_openrouter_base_url(monkeypatch):
    # Without the base_url this is a direct OpenAI call carrying an OpenRouter key, against a
    # model OpenAI does not serve — so it fails, but only at runtime and only in CI.
    _, client = _fake_openrouter(monkeypatch, content="ok")
    adv.call_openrouter("k", "m", "diff", "ctx", "sys")
    assert client.init_kwargs["base_url"] == adv.OPENROUTER_BASE_URL
    assert client.init_kwargs["base_url"] == "https://openrouter.ai/api/v1"


def test_openrouter_uses_max_tokens_not_max_completion_tokens(monkeypatch):
    # The exact inverse of `test_openai_uses_max_completion_tokens_not_max_tokens`, and the
    # reason this is a separate function rather than a `base_url` argument to `call_openai`.
    # OpenRouter normalizes `max_tokens`; the pinned model
    # (`deepseek/deepseek-v4-pro-0813`) does not advertise `max_completion_tokens` at all.
    completions, _ = _fake_openrouter(monkeypatch, content="ok")
    adv.call_openrouter("k", "m", "diff", "ctx", "sys")
    assert "max_tokens" in completions.kwargs
    assert "max_completion_tokens" not in completions.kwargs


def test_openrouter_sends_the_system_prompt_as_a_message(monkeypatch):
    # There is no top-level `system=` in the OpenAI wire format. A leg that dropped the
    # system prompt would still return plausible JSON, so the bug would present as a quality
    # regression and be blamed on the model rather than on the transport — which is exactly
    # what a canary must never be allowed to misattribute.
    completions, _ = _fake_openrouter(monkeypatch, content="ok")
    adv.call_openrouter("k", "m", "diff", "ctx", "sys-prompt")
    roles = [m["role"] for m in completions.kwargs["messages"]]
    assert roles == ["system", "user"]
    assert completions.kwargs["messages"][0]["content"] == "sys-prompt"


def test_openrouter_prints_usage_line(monkeypatch, capsys):
    _fake_openrouter(monkeypatch, content="ok")
    adv.call_openrouter("k", "m", "diff", "ctx", "sys")
    assert "usage: input=11 output=22 reasoning=0" in capsys.readouterr().out


def test_openrouter_tolerates_a_missing_usage_block(monkeypatch, capsys):
    # `usage` can be absent on some OpenRouter routes. The cost line under-reports; the review
    # still returns. An AttributeError here would fail the job on a review that succeeded —
    # and the gate reads a failed job as a reviewer that did not complete.
    _fake_openrouter(monkeypatch, content="### CRITICAL\n- found", usage=_NO_USAGE)
    out = adv.call_openrouter("k", "m", "diff", "ctx", "sys")
    assert "CRITICAL" in out
    assert "usage: input=0 output=0 reasoning=0" in capsys.readouterr().out


@pytest.mark.parametrize("content", ["", "   \n  ", None])
def test_openrouter_empty_completion_raises_rather_than_reading_as_clean(monkeypatch, content):
    # Same silent fail-open the OpenAI leg guards against: nothing returned is
    # indistinguishable from nothing found.
    _fake_openrouter(monkeypatch, content=content)
    with pytest.raises(RuntimeError, match="empty completion"):
        adv.call_openrouter("k", "m", "diff", "ctx", "sys")


def test_openrouter_truncated_completion_raises(monkeypatch):
    _fake_openrouter(monkeypatch, content="### CRITICAL\n- partial", finish_reason="length")
    with pytest.raises(RuntimeError, match="token budget"):
        adv.call_openrouter("k", "m", "diff", "ctx", "sys")


def test_openrouter_truncation_error_is_not_an_infra_error():
    assert adv._is_infra_error("openrouter", RuntimeError("token budget")) is False


def test_openrouter_quota_and_infra_errors_use_the_openai_exception_family():
    # OpenRouter is reached through the OpenAI SDK, so it raises OpenAI's types. Before this
    # change both classifiers keyed on `provider == "openai"` exactly, and an OpenRouter
    # rate limit would have fallen through to "not infra" — hard-failing the job on a
    # transient error instead of failing open.
    import openai as _oai

    rate_limited = _oai.RateLimitError.__new__(_oai.RateLimitError)
    Exception.__init__(rate_limited, "rate limited")
    assert adv._is_infra_error("openrouter", rate_limited) is True

    # And a plain RuntimeError carrying a quota phrase is still not a billing signal.
    assert adv._is_quota_error(
        "openrouter", RuntimeError("insufficient_quota")) is False


def test_run_review_dispatches_openrouter(monkeypatch):
    seen = {}

    def _fake(*args):
        seen["args"] = args
        return "reviewed"

    monkeypatch.setattr(adv, "call_openrouter", _fake)
    assert adv.run_review("openrouter", "k", "m", "d", "c", "s") == "reviewed"
    assert seen["args"] == ("k", "m", "d", "c", "s")


def test_the_openrouter_pin_is_a_dated_snapshot_not_the_bare_alias():
    """Measured on OpenRouter 2026-09-21: the bare `deepseek/deepseek-v4-pro` resolves to the
    frozen "DeepSeek V4 Pro 0423" snapshot, and no `-latest` form is published. So the fleet's
    bare-alias-means-floating convention does not hold for this vendor, and a well-meaning
    "tidy up the pin to the alias" edit would silently move this reviewer back to April."""
    model = adv.PROVIDERS["openrouter"]["model"]
    assert model == "deepseek/deepseek-v4-pro-0813"
    assert model != "deepseek/deepseek-v4-pro"


def test_every_provider_has_its_own_comment_marker():
    """Two legs sharing a marker would dedupe onto each other's comment, so the second
    reviewer to post would overwrite the first and the divergence this canary exists to
    measure would be invisible on the PR."""
    markers = [cfg["marker"] for cfg in adv.PROVIDERS.values()]
    assert len(markers) == len(set(markers))


# ── Anthropic completion guards ─────────────────────────────────────────────────
#
# Mirrors the OpenAI section above. security#109 added call_anthropic's guard
# (call_openai already had it) but shipped no tests for it — these close that
# gap so a regression on the Anthropic path is caught the same way.

def _fake_anthropic(monkeypatch, *, content_blocks, stop_reason="end_turn", usage=None):
    """Install a fake Anthropic client returning a single chosen message."""
    if usage is None:
        usage = SimpleNamespace(input_tokens=33, output_tokens=44)
    message = SimpleNamespace(content=content_blocks, stop_reason=stop_reason, usage=usage)

    class _Messages:
        def create(self, **kwargs):
            _Messages.kwargs = kwargs
            return message

    class _Client:
        def __init__(self, api_key=None):
            self.messages = _Messages()

    import anthropic

    monkeypatch.setattr(anthropic, "Anthropic", _Client)
    return _Messages


def test_anthropic_returns_content_on_success(monkeypatch):
    _fake_anthropic(monkeypatch, content_blocks=[SimpleNamespace(text="### CRITICAL\n- something")])
    out = adv.call_anthropic("k", "m", "diff", "ctx", "sys")
    assert "CRITICAL" in out


def test_anthropic_prints_usage_line(monkeypatch, capsys):
    # Default fake usage has no cache_read/cache_write fields at all — exercises
    # the getattr(..., 0) default for a response with no cache activity.
    _fake_anthropic(monkeypatch, content_blocks=[SimpleNamespace(text="ok")])
    adv.call_anthropic("k", "m", "diff", "ctx", "sys")
    assert "usage: input=33 output=44 cache_read=0 cache_write=0" in capsys.readouterr().out


def test_anthropic_prints_cache_tokens_when_present(monkeypatch, capsys):
    usage = SimpleNamespace(
        input_tokens=1,
        output_tokens=2,
        cache_read_input_tokens=3,
        cache_creation_input_tokens=4,
    )
    _fake_anthropic(monkeypatch, content_blocks=[SimpleNamespace(text="ok")], usage=usage)
    adv.call_anthropic("k", "m", "diff", "ctx", "sys")
    assert "usage: input=1 output=2 cache_read=3 cache_write=4" in capsys.readouterr().out


def test_anthropic_empty_completion_raises_rather_than_reading_as_clean(monkeypatch):
    # The failure this guards: message.content comes back an empty list, content
    # resolves to "", has_critical_findings("") returns False, and the gate
    # passes having reviewed nothing.
    _fake_anthropic(monkeypatch, content_blocks=[])
    with pytest.raises(RuntimeError, match="empty completion"):
        adv.call_anthropic("k", "m", "diff", "ctx", "sys")


def test_anthropic_whitespace_only_completion_raises(monkeypatch):
    _fake_anthropic(monkeypatch, content_blocks=[SimpleNamespace(text="   \n  ")])
    with pytest.raises(RuntimeError, match="empty completion"):
        adv.call_anthropic("k", "m", "diff", "ctx", "sys")


def test_anthropic_truncated_completion_raises(monkeypatch):
    _fake_anthropic(
        monkeypatch,
        content_blocks=[SimpleNamespace(text="### CRITICAL\n- partial")],
        stop_reason="max_tokens",
    )
    with pytest.raises(RuntimeError, match="token budget"):
        adv.call_anthropic("k", "m", "diff", "ctx", "sys")


def test_anthropic_truncation_error_is_not_an_infra_error():
    # Must fail the job (and so block the gate), not fail open like a 5xx.
    assert adv._is_infra_error("anthropic", RuntimeError("token budget")) is False


# ── Thinking-block responses (2026-08-31) ───────────────────────────────────────
#
# claude-sonnet-5 returns a ThinkingBlock FIRST, and it has no `.text`, so the
# previous `content[0].text` raised `AttributeError: 'ThinkingBlock' object has
# no attribute 'text'`. That took capture-findings down at every caller two
# minutes after the moving tag delivered the model swap, and the same idiom was
# live in three other composites here. Thinking is not emitted on every call, so
# it presents as flakiness rather than as a break — which is why the regression
# is pinned explicitly rather than left to the empty-completion guard above to
# catch incidentally.


def _thinking_block(text="deliberating"):
    """Shaped like the SDK's ThinkingBlock: carries `.thinking`, never `.text`."""
    return SimpleNamespace(type="thinking", thinking=text)


def _text_block(text):
    return SimpleNamespace(type="text", text=text)


def test_anthropic_reads_past_a_leading_thinking_block(monkeypatch):
    _fake_anthropic(
        monkeypatch,
        content_blocks=[_thinking_block(), _text_block("### CRITICAL\n- something")],
    )
    assert "CRITICAL" in adv.call_anthropic("k", "m", "diff", "ctx", "sys")


def test_anthropic_joins_text_split_across_blocks(monkeypatch):
    # Truncating a review here is worse than elsewhere: a dropped tail can drop
    # the ### CRITICAL section, and has_critical_findings() then reads clean.
    _fake_anthropic(
        monkeypatch,
        content_blocks=[_thinking_block(), _text_block("### CRIT"), _text_block("ICAL\n- x")],
    )
    assert "### CRITICAL" in adv.call_anthropic("k", "m", "diff", "ctx", "sys")


def test_anthropic_raises_when_the_response_is_thinking_only(monkeypatch):
    _fake_anthropic(monkeypatch, content_blocks=[_thinking_block()])
    with pytest.raises(RuntimeError, match="empty completion"):
        adv.call_anthropic("k", "m", "diff", "ctx", "sys")

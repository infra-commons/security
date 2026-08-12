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

def _fake_openai(monkeypatch, *, content, finish_reason="stop"):
    """Install a fake OpenAI client returning a single chosen completion."""
    choice = SimpleNamespace(
        message=SimpleNamespace(content=content), finish_reason=finish_reason
    )
    response = SimpleNamespace(choices=[choice])

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

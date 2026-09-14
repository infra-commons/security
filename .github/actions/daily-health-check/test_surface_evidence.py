"""Tests for the changed-surface evidence the failure triage now gathers.

THE DEFECT. `diagnose_with_claude` asserted a root cause from a log excerpt
without ever checking whether anything that could cause it had changed. A
scheduled eval lane in a consuming repo went red; the triage called it a model
quality/behaviour regression rather than a transient infrastructure issue, and
recommended lowering a threshold. Seventeen files had changed between that lane's
last success and the failure, and not one was on the list that repo already
maintains of paths whose contents can change an eval outcome — the same surface
had scored differently a day earlier. The check that falsifies that story is two
API calls away, and this file covers it.

The defect is not about evals, which is why nothing below is: a log excerpt was
the only input the diagnosis ever had, in any consuming repo.

Fixtures here are SYNTHETIC. This repository is public and does not carry other
repositories' commits, paths or incident specifics (see CONTRIBUTING.md), so what
the fixtures reproduce is the shape rather than the event: a seventeen-file diff
wholly disjoint from a declared surface, a directory prefix with a near-miss
sibling, an exact entry that is not a prefix. `test_health_check.py` covers the
rest of the action; this file covers the evidence, and almost every test in it is
a negative control — the question each one asks is whether the instrument can be
made to say "nothing changed" when it does not know that.
"""
import importlib.util
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace

import pytest
import yaml

# The module filename contains a dash, so it cannot be imported by name.
_MODULE_PATH = Path(__file__).parent / "health-check.py"
_spec = importlib.util.spec_from_file_location("health_check", _MODULE_PATH)
hc = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(hc)

NOW = datetime(2026, 7, 27, 12, 0, tzinfo=timezone.utc)
CUTOFF = NOW - timedelta(hours=25)
FAILING_RUN_NAME = "Scheduled suite (production model, promote gate)"
WORKFLOW_NAME = "Release — STAGING (build once + test)"

# Synthetic, and used WHOLE: `_SHA40_RE` is a guard, so a 7-character fixture
# would exercise its refusal path instead of the feature. `a`*40 and `f`*40 are
# left unused here on purpose — the tests below spend them on the rows that must
# be REJECTED, so a fixture collision cannot make a rejection look like a match.
BASE_SHA = "b" * 40
HEAD_SHA = "c" * 40

# Seventeen paths, not one of them on `DECLARED_SURFACE` below. The COUNT is the
# point rather than the names: a diff this size is what a log-only diagnosis
# mistook for evidence of an in-repo cause, and every entry here is the kind of
# file — CI wiring, release notes, unrelated tests — that cannot change a model's
# output.
CHANGED_PATHS = [
    ".github/scripts/drift-report.py",
    ".github/workflows/auto-merge-churn.yml",
    ".github/workflows/capture-findings.yml",
    ".github/workflows/cloud-posture.yml",
    ".github/workflows/daily-health-check.yml",
    ".github/workflows/dast-scan.yml",
    ".github/workflows/dependency-review.yml",
    ".github/workflows/drift-report.yml",
    ".github/workflows/pentest-scan.yml",
    ".github/workflows/policy-capture.yml",
    ".github/workflows/policy-review.yml",
    ".github/workflows/secret-scan.yml",
    ".github/workflows/security-scan.yml",
    "docs/release-notes/0001-adopt-the-split-credential-drift-report.md",
    "docs/release-notes/0002-policy-capture-pin-refresh.md",
    "scripts/severity-report.py",
    "tests/unit/test_drift_report.py",
]

# A declared surface of the same SHAPE a real one has: directory prefixes, exact
# file entries, and lockfiles. Those three shapes are what `_on_declared_surface`
# has to tell apart, and they are all a public repo needs to hold — the coupling
# between a real declaration and the repo it describes belongs in that repo,
# which is where the constant lives and where an edit to it happens.
DECLARED_SURFACE = (
    "prompts/", "evals/cases/", "evals/thresholds.yaml", "evals/__init__.py",
    "evals/runners/", "src/__init__.py", "src/config.py", "src/json_extract.py",
    "src/llm/", "src/prompts/", ".github/workflows/scheduled-suite.yml",
    "pyproject.toml", "uv.lock", "poetry.lock", "requirements.txt",
    "requirements-dev.txt", "constraints.txt",
)

DECLARED_WORKFLOW_FILE = ".github/workflows/scheduled-suite.yml"

RERUN_REASON = (
    "a re-run of this lane buys a second sample, never a fix, and costs a billed "
    "production-model suite"
)


def _decl(**overrides):
    entry = {
        "surface": DECLARED_SURFACE,
        "rerun": "forbid",
        "rerun_reason": RERUN_REASON,
        "notes": ["A uniform 0% across EVERY tag in this lane is a provider refusal."],
    }
    entry.update(overrides)
    return {"scheduled-suite.yml": entry}


def _failing_run(**overrides):
    run = {
        "databaseId": 2002,
        "name": FAILING_RUN_NAME,
        "workflowName": FAILING_RUN_NAME,
        "event": "schedule",
        "createdAt": "2026-07-27T10:00:00Z",
        "url": "https://github.com/o/r/actions/runs/2002",
        "headSha": HEAD_SHA,
        "headBranch": "main",
        "workflowDatabaseId": 4242,
        "_ts": datetime(2026, 7, 27, 10, 0, tzinfo=timezone.utc),
    }
    run.update(overrides)
    return run


def _base_row(**overrides):
    row = {
        "databaseId": 1001,
        "headSha": BASE_SHA,
        "headBranch": "main",
        # 30 hours before the failure, i.e. DELIBERATELY outside the 25-hour
        # lookback window of the health check that would file the issue. That gap
        # is the whole reason the base lookup cannot route through `_collect_runs`.
        "createdAt": "2026-07-26T04:00:00Z",
        "url": "https://github.com/o/r/actions/runs/1001",
        "workflowDatabaseId": 4242,
    }
    row.update(overrides)
    return row


def _run(run_id, name, when, *, workflow_name=WORKFLOW_NAME):
    return {
        "databaseId": run_id, "name": name, "workflowName": workflow_name,
        "event": "schedule", "createdAt": when.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "url": f"https://github.com/o/r/actions/runs/{run_id}", "_ts": when,
    }


@pytest.fixture
def evidence_wiring(monkeypatch):
    """Canned base-run rows and compare pages, with every call recorded."""
    state = {"base_rows": [_base_row()], "pages": [], "compare_calls": []}

    def fake_gh_json(*args):
        return list(state["base_rows"])

    def fake_gh_api(path):
        state["compare_calls"].append(path)
        # `[?&]` is load-bearing: a bare `page=` also matches inside `per_page=100`.
        m = re.search(r"[?&]page=(\d+)", path)
        index = int(m.group(1)) - 1 if m else 0
        if index >= len(state["pages"]):
            return {"status": "ahead", "files": []}
        return state["pages"][index]

    monkeypatch.setattr(hc, "_gh_json", fake_gh_json)
    monkeypatch.setattr(hc, "_gh_api", fake_gh_api)
    state["pages"] = [{"status": "ahead",
                       "files": [{"filename": p} for p in CHANGED_PATHS]}]
    return state


# ── The declaration reader refuses rather than guesses ────────────────────────
#
# Every refusal below has to land on {} — i.e. on UNKNOWN downstream. A
# declaration half-read here produces a confident "nothing on the surface
# changed" out of a surface it never saw, which is the worst available failure
# for this whole section.

def _write_decl(tmp_path, monkeypatch, text):
    path = tmp_path / ".github" / "health-check-workflows.yml"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    monkeypatch.setattr(hc, "_WORKFLOW_DECL_PATH", path)
    return path


def test_a_missing_declaration_is_an_empty_mapping_not_a_crash(tmp_path, monkeypatch):
    monkeypatch.setattr(hc, "_WORKFLOW_DECL_PATH",
                        tmp_path / "nope" / "health-check-workflows.yml")
    assert hc._load_workflow_declarations() == {}


def test_a_declaration_that_is_not_a_mapping_is_dropped(tmp_path, monkeypatch):
    _write_decl(tmp_path, monkeypatch, "- just\n- a\n- list\n")
    assert hc._load_workflow_declarations() == {}


def test_unparseable_yaml_is_dropped_rather_than_half_read(tmp_path, monkeypatch):
    _write_decl(tmp_path, monkeypatch, "workflows:\n  a: [unclosed\n")
    assert hc._load_workflow_declarations() == {}


def test_an_oversized_declaration_is_refused_before_it_is_parsed(tmp_path, monkeypatch):
    _write_decl(tmp_path, monkeypatch,
                "workflows:\n  a:\n    surface: []\n" + ("# pad\n" * 60_000))
    assert hc._load_workflow_declarations() == {}


def test_a_surface_that_is_not_a_list_of_strings_is_DROPPED_not_coerced(
        tmp_path, monkeypatch):
    """An empty tuple would read as "nothing is on the surface", which makes every
    diff look clean. Absent is a different state and has to stay different."""
    _write_decl(tmp_path, monkeypatch,
                "workflows:\n  w.yml:\n    surface: 'prompts/'\n    rerun: allow\n")
    assert "surface" not in hc._load_workflow_declarations()["w.yml"]


def test_an_unrecognised_rerun_value_is_dropped_rather_than_read_as_a_decision(
        tmp_path, monkeypatch):
    _write_decl(tmp_path, monkeypatch,
                "workflows:\n  w.yml:\n    surface: []\n    rerun: maybe\n")
    assert hc._load_workflow_declarations()["w.yml"].get("rerun", "") == ""


def test_a_good_declaration_round_trips(tmp_path, monkeypatch):
    _write_decl(tmp_path, monkeypatch, yaml.safe_dump(
        {"workflows": {"scheduled-suite.yml": {
            "surface": list(DECLARED_SURFACE), "rerun": "forbid",
            "rerun_reason": RERUN_REASON, "notes": ["n"]}}}))
    decl = hc._load_workflow_declarations()["scheduled-suite.yml"]
    assert decl["surface"] == DECLARED_SURFACE
    assert decl["rerun"] == "forbid"
    assert decl["rerun_reason"] == RERUN_REASON
    assert decl["notes"] == ["n"]


def test_the_reader_degrades_to_empty_when_the_yaml_parser_is_absent(
        tmp_path, monkeypatch):
    """`action.yml` installs pyyaml. If that line is ever dropped the reader has to
    go quiet rather than take some other path."""
    _write_decl(tmp_path, monkeypatch, yaml.safe_dump(
        {"workflows": {"w.yml": {"surface": ["prompts/"]}}}))
    monkeypatch.setattr(hc, "yaml", None)
    assert hc._load_workflow_declarations() == {}


# ── The surface predicate matches the declaring repo's own ────────────────────

@pytest.mark.parametrize("path", [
    "prompts/summarise.md", "evals/cases/x/y.json", "src/llm/client.py",
    "src/config.py", "pyproject.toml", ".github/workflows/scheduled-suite.yml",
])
def test_known_on_surface_paths_are_on_the_declared_surface(path):
    """The negative control for the no-in-repo-cause verdict test below: without
    this, emptying `surface` to () makes that test pass for the wrong reason."""
    assert hc._on_declared_surface(path, DECLARED_SURFACE)


@pytest.mark.parametrize("path", [
    "promptsmith/thing.md",            # a prefix is not a directory
    "src/config_extra.py",             # an exact entry is not a prefix
    "docs/release-notes/0002-policy-capture-pin-refresh.md",
])
def test_off_surface_paths_are_off_the_declared_surface(path):
    assert not hc._on_declared_surface(path, DECLARED_SURFACE)


# ── The base commit comes from an UNBOUNDED lookup ────────────────────────────

def test_the_base_lookup_is_not_bounded_by_the_lookback_window(monkeypatch):
    """The measured case's base run sat hours OUTSIDE the 25-hour window of the
    health check that filed the issue. A lookup routed through `_collect_runs`
    would report UNKNOWN on the very case this section exists for."""
    def explode(*a, **k):
        raise AssertionError("the base lookup must not go through _collect_runs")

    monkeypatch.setattr(hc, "_collect_runs", explode)
    monkeypatch.setattr(hc, "_gh_json", lambda *a: [_base_row()])
    assert hc._last_success_before("o/r", _failing_run())["headSha"] == BASE_SHA


def test_a_success_NEWER_than_the_failure_is_not_used_as_the_base(monkeypatch):
    """A manual re-dispatch that succeeded after the failure occupies the newest
    rows; comparing against it would diff in the wrong direction."""
    newer = _base_row(databaseId=99, createdAt="2026-07-27T11:00:00Z", headSha="f" * 40)
    monkeypatch.setattr(hc, "_gh_json", lambda *a: [newer, _base_row()])
    assert hc._last_success_before("o/r", _failing_run())["headSha"] == BASE_SHA


def test_a_success_of_a_DIFFERENT_workflow_is_not_used_as_the_base(monkeypatch):
    monkeypatch.setattr(hc, "_gh_json",
                        lambda *a: [_base_row(workflowDatabaseId=7, headSha="a" * 40)])
    assert hc._last_success_before("o/r", _failing_run()) is None


def test_a_base_row_without_a_whole_sha_is_not_used(monkeypatch):
    monkeypatch.setattr(hc, "_gh_json", lambda *a: [_base_row(headSha="b" * 7)])
    assert hc._last_success_before("o/r", _failing_run()) is None


def test_no_earlier_success_at_all_is_None_rather_than_a_guess(monkeypatch):
    monkeypatch.setattr(hc, "_gh_json", lambda *a: [])
    assert hc._last_success_before("o/r", _failing_run()) is None


# ── The comparison refuses rather than under-reporting ────────────────────────

def test_the_comparison_returns_every_changed_path(evidence_wiring):
    paths, why = hc._compare_changed_paths("o/r", BASE_SHA, HEAD_SHA)
    assert why == ""
    assert sorted(paths) == sorted(CHANGED_PATHS)


def test_a_rename_surfaces_BOTH_the_old_and_the_new_path(evidence_wiring):
    """What `--no-renames` buys the declaring repo's own gate: moving a file OUT of
    a declared directory has to read as a surface change, not as one path the
    filter happens not to match. The API collapses a rename into one row."""
    evidence_wiring["pages"] = [{"status": "ahead", "files": [
        {"filename": "docs/moved.md", "status": "renamed",
         "previous_filename": "prompts/summarise.md"}]}]
    paths, _ = hc._compare_changed_paths("o/r", BASE_SHA, HEAD_SHA)
    assert paths == ["docs/moved.md", "prompts/summarise.md"]
    assert any(hc._on_declared_surface(p, DECLARED_SURFACE) for p in paths)


def test_a_comparison_at_the_page_cap_is_UNKNOWN_not_empty(evidence_wiring):
    """The compare endpoint carries no truncation flag, so a silently short list is
    indistinguishable from a complete one except by counting. Delete this guard and
    a 3 000-file comparison reports a clean surface."""
    full = {"status": "ahead",
            "files": [{"filename": f"f{i}.txt"} for i in range(hc._COMPARE_PAGE_SIZE)]}
    evidence_wiring["pages"] = [full] * (hc._COMPARE_MAX_PAGES + 1)
    paths, why = hc._compare_changed_paths("o/r", BASE_SHA, HEAD_SHA)
    assert paths is None
    assert "truncating" in why


def test_a_diverged_comparison_is_UNKNOWN(evidence_wiring):
    """`/compare/A...B` is a THREE-dot comparison; it equals `git diff A B` only
    when the base is an ancestor of the head."""
    evidence_wiring["pages"] = [{"status": "diverged", "files": []}]
    paths, why = hc._compare_changed_paths("o/r", BASE_SHA, HEAD_SHA)
    assert paths is None
    assert "ancestor" in why


def test_an_unanswered_compare_page_discards_the_pages_before_it(evidence_wiring):
    full = {"status": "ahead",
            "files": [{"filename": f"f{i}.txt"} for i in range(hc._COMPARE_PAGE_SIZE)]}
    evidence_wiring["pages"] = [full, None]
    paths, why = hc._compare_changed_paths("o/r", BASE_SHA, HEAD_SHA)
    assert paths is None
    assert why


def test_an_identical_comparison_is_an_empty_list_not_UNKNOWN(evidence_wiring):
    evidence_wiring["pages"] = [{"status": "identical", "files": []}]
    paths, why = hc._compare_changed_paths("o/r", BASE_SHA, HEAD_SHA)
    assert paths == []
    assert why == ""


def test_a_short_sha_is_refused_rather_than_compared(evidence_wiring):
    paths, why = hc._compare_changed_paths("o/r", "b" * 7, HEAD_SHA)
    assert paths is None
    assert evidence_wiring["compare_calls"] == []


# ── The verdict, on a diff the whole surface misses ───────────────────────────

def test_an_all_off_surface_diff_is_read_as_no_in_repo_cause(evidence_wiring):
    ev = hc.surface_evidence_for_run("o/r", _failing_run(), DECLARED_WORKFLOW_FILE, _decl())
    assert ev["verdict"] == hc._CAUSE_NONE
    assert len(ev["changed"]) == 17
    assert ev["on_surface"] == []
    assert ev["base_sha"] == BASE_SHA


def test_a_change_to_a_declared_surface_path_is_read_as_a_surface_change(evidence_wiring):
    """The other half of the discriminator. Collapse the intersection to either
    constant and exactly one of this pair goes red."""
    evidence_wiring["pages"] = [{"status": "ahead", "files": [
        {"filename": p} for p in CHANGED_PATHS + ["src/llm/client.py"]]}]
    ev = hc.surface_evidence_for_run("o/r", _failing_run(), DECLARED_WORKFLOW_FILE, _decl())
    assert ev["verdict"] == hc._CAUSE_SURFACE
    assert ev["on_surface"] == ["src/llm/client.py"]


def test_no_declaration_still_gathers_the_changed_files(evidence_wiring):
    """The generic tier. Every consuming repo gets the naming obligation for free;
    only a declaring repo gets the mechanical proof."""
    ev = hc.surface_evidence_for_run("o/r", _failing_run(), DECLARED_WORKFLOW_FILE, {})
    assert ev["verdict"] == hc._CAUSE_UNKNOWN
    assert len(ev["changed"]) == 17
    assert ev["surface_declared"] is False


def test_a_run_with_no_head_sha_is_UNKNOWN_and_costs_no_api_call(monkeypatch):
    def explode(*a, **k):
        raise AssertionError("nothing should be fetched without a head commit")

    monkeypatch.setattr(hc, "_gh_json", explode)
    ev = hc.surface_evidence_for_run(
        "o/r", _failing_run(headSha=""), DECLARED_WORKFLOW_FILE, _decl())
    assert ev["verdict"] == hc._CAUSE_UNKNOWN


def test_an_unreadable_comparison_is_UNKNOWN_not_no_in_repo_cause(evidence_wiring):
    evidence_wiring["pages"] = [None]
    ev = hc.surface_evidence_for_run("o/r", _failing_run(), DECLARED_WORKFLOW_FILE, _decl())
    assert ev["verdict"] == hc._CAUSE_UNKNOWN
    assert ev["reason"]


def test_the_declaration_is_keyed_on_the_workflow_FILE_not_the_run_name(evidence_wiring):
    ev = hc.surface_evidence_for_run("o/r", _failing_run(), DECLARED_WORKFLOW_FILE, _decl())
    assert ev["workflow_file"] == "scheduled-suite.yml"
    assert ev["rerun"] == "forbid"


# ── What the model is told ────────────────────────────────────────────────────

@pytest.fixture
def prompt_recorder(monkeypatch):
    prompts: list[str] = []
    _REPLY = ('{"is_transient": false, "root_cause": "r", "fix": "f", '
              '"severity": "high", "mechanical": false}')

    class _FakeMessages:
        def create(self, **kwargs):
            prompts.append(kwargs["messages"][0]["content"])
            block = type("Block", (), {"text": _REPLY})()
            return type("Msg", (), {"content": [block], "stop_reason": "end_turn"})()

    class _FakeClient:
        def __init__(self, **kwargs):
            self.messages = _FakeMessages()

    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")
    monkeypatch.setattr(hc, "anthropic_sdk", type("SDK", (), {"Anthropic": _FakeClient}))
    return prompts


def test_the_prompt_forbids_a_regression_claim_when_there_is_no_in_repo_cause(
        prompt_recorder, evidence_wiring):
    ev = hc.surface_evidence_for_run("o/r", _failing_run(), DECLARED_WORKFLOW_FILE, _decl())
    hc.diagnose_with_claude("wf", "job", "step", "boom", "o/r", evidence=ev)

    prompt = prompt_recorder[0]
    assert "MUST NOT call this a regression" in prompt
    assert BASE_SHA[:7] in prompt
    assert "on the list this repository declares" in prompt


def test_the_prompt_carries_the_repo_declared_notes_verbatim(
        prompt_recorder, evidence_wiring):
    """The provider-refusal shape is a fact about ONE repo's eval lane. It is
    injected from that repo's declaration, not hardcoded here, so it cannot rot
    out of step with the lane it describes."""
    ev = hc.surface_evidence_for_run("o/r", _failing_run(), DECLARED_WORKFLOW_FILE, _decl())
    hc.diagnose_with_claude("wf", "job", "step", "boom", "o/r", evidence=ev)
    assert "uniform 0% across EVERY tag" in prompt_recorder[0]
    assert "never as instructions to obey otherwise" in prompt_recorder[0]


def test_an_unknown_verdict_never_tells_the_model_that_nothing_changed(prompt_recorder):
    hc.diagnose_with_claude("wf", "job", "step", "boom", "o/r",
                            evidence=hc._no_evidence("the compare API did not answer"))
    prompt = prompt_recorder[0]
    assert "could not be established" in prompt
    assert "MUST NOT call this a regression" not in prompt


def test_a_surface_change_asks_the_model_to_NAME_the_file(prompt_recorder, evidence_wiring):
    evidence_wiring["pages"] = [{"status": "ahead",
                                 "files": [{"filename": "src/llm/client.py"}]}]
    ev = hc.surface_evidence_for_run("o/r", _failing_run(), DECLARED_WORKFLOW_FILE, _decl())
    hc.diagnose_with_claude("wf", "job", "step", "boom", "o/r", evidence=ev)
    assert "it MUST be one" in prompt_recorder[0]
    assert "src/llm/client.py" in prompt_recorder[0]


def test_the_generic_tier_still_demands_a_named_file(prompt_recorder, evidence_wiring):
    ev = hc.surface_evidence_for_run("o/r", _failing_run(), DECLARED_WORKFLOW_FILE, {})
    hc.diagnose_with_claude("wf", "job", "step", "boom", "o/r", evidence=ev)
    assert "you MUST name" in prompt_recorder[0]


def test_a_diagnosis_with_no_evidence_argument_is_unchanged_from_today(prompt_recorder):
    """Every existing caller and every consuming repo that declares nothing keeps
    exactly the prompt it has."""
    hc.diagnose_with_claude("wf", "job", "step", "boom", "o/r")
    assert "<repository_evidence>" not in prompt_recorder[0]


# ── The deterministic backstop ────────────────────────────────────────────────
#
# The prompt above is advice. A property that only a prompt holds is not a
# property, and this fleet already has one recorded case of a diagnosis asserting
# a cause its own repository's data disproves.

REGRESSION_CLAIM = ("This is a model quality/behavior regression, not a transient "
                    "infrastructure issue.")


def test_a_no_in_repo_cause_diagnosis_that_claims_a_regression_is_overridden(
        evidence_wiring):
    """The literal sentence the log-only diagnosis produced. Delete
    `_enforce_evidence` and this goes red."""
    ev = hc.surface_evidence_for_run("o/r", _failing_run(), DECLARED_WORKFLOW_FILE, _decl())
    out = hc._enforce_evidence(
        {"root_cause": REGRESSION_CLAIM, "fix": "lower the threshold",
         "severity": "high", "is_transient": False}, ev)

    assert REGRESSION_CLAIM not in out["root_cause"]
    assert "not an in-repo change" in out["root_cause"]
    # Nothing is hidden — the model's wording is kept and rendered in a <details>.
    assert out["overridden_root_cause"] == REGRESSION_CLAIM


def test_the_override_fires_on_the_FIX_as_well_as_the_root_cause(evidence_wiring):
    ev = hc.surface_evidence_for_run("o/r", _failing_run(), DECLARED_WORKFLOW_FILE, _decl())
    out = hc._enforce_evidence(
        {"root_cause": "one case scored 0/1", "fix": "revert the regression",
         "severity": "high", "is_transient": False}, ev)
    assert out.get("overridden_root_cause") == "one case scored 0/1"


def test_a_diagnosis_that_claims_nothing_is_left_alone(evidence_wiring):
    ev = hc.surface_evidence_for_run("o/r", _failing_run(), DECLARED_WORKFLOW_FILE, _decl())
    out = hc._enforce_evidence(
        {"root_cause": "the endpoint returned 503", "fix": "wait",
         "severity": "medium", "is_transient": True}, ev)
    assert out["root_cause"] == "the endpoint returned 503"
    assert "overridden_root_cause" not in out


def test_a_surface_change_leaves_the_models_wording_alone(evidence_wiring):
    """The over-correction guard. Turning a real regression into a flake is the
    same defect with the sign flipped."""
    evidence_wiring["pages"] = [{"status": "ahead",
                                 "files": [{"filename": "src/llm/client.py"}]}]
    ev = hc.surface_evidence_for_run("o/r", _failing_run(), DECLARED_WORKFLOW_FILE, _decl())
    out = hc._enforce_evidence(
        {"root_cause": REGRESSION_CLAIM, "fix": "f", "severity": "high",
         "is_transient": False}, ev)
    assert out["root_cause"] == REGRESSION_CLAIM
    assert out["severity"] == "high"


def test_an_unknown_verdict_overrides_nothing(evidence_wiring):
    out = hc._enforce_evidence(
        {"root_cause": REGRESSION_CLAIM, "fix": "f", "severity": "high"},
        hc._no_evidence("could not read"))
    assert out["root_cause"] == REGRESSION_CLAIM
    assert out["severity"] == "high"


def test_severity_is_capped_at_medium_not_floored_at_low(evidence_wiring):
    """`severity:high` holds the promote gate for every client of a consuming repo,
    so that property has to go. But "no in-repo cause" includes "the provider is
    down on the lane that gates a promote", which is not a `low`."""
    ev = hc.surface_evidence_for_run("o/r", _failing_run(), DECLARED_WORKFLOW_FILE, _decl())
    assert hc._enforce_evidence(
        {"root_cause": "r", "fix": "f", "severity": "critical"}, ev)["severity"] == "medium"
    assert hc._enforce_evidence(
        {"root_cause": "r", "fix": "f", "severity": "low"}, ev)["severity"] == "low"


def test_the_override_does_not_touch_the_transient_classification(evidence_wiring):
    ev = hc.surface_evidence_for_run("o/r", _failing_run(), DECLARED_WORKFLOW_FILE, _decl())
    out = hc._enforce_evidence(
        {"root_cause": REGRESSION_CLAIM, "fix": "f", "severity": "high",
         "is_transient": True}, ev)
    assert out["is_transient"] is True


def test_the_no_api_key_fallback_still_carries_the_evidence(monkeypatch, evidence_wiring):
    """The evidence is computed by code, so it survives every way the model can be
    unavailable."""
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.setattr(hc, "anthropic_sdk", None)
    ev = hc.surface_evidence_for_run("o/r", _failing_run(), DECLARED_WORKFLOW_FILE, _decl())
    out = hc.diagnose_with_claude("wf", "job", "step", "boom", "o/r", evidence=ev)
    assert "not an in-repo change" in out["root_cause"]


# ── What the issue says ───────────────────────────────────────────────────────

@pytest.fixture
def issue_recorder(monkeypatch):
    calls = {"create": [], "comment": []}

    def fake_gh(*args, **kwargs):
        if args[:2] == ("issue", "create"):
            calls["create"].append(args)
        return "https://github.com/o/r/issues/7"

    def fake_run(argv, *a, **k):
        if list(argv[:3]) == ["gh", "issue", "comment"]:
            calls["comment"].append(argv)
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    monkeypatch.setattr(hc, "_gh", fake_gh)
    monkeypatch.setattr(hc.subprocess, "run", fake_run)
    return calls


def _file_issue(evidence, existing=None, **kwargs):
    return hc.file_or_update_issue(
        repo="o/r", workflow_name="wf", run_link="u", job_name="j", failing_step="s",
        diagnosis={"root_cause": "rc", "fix": "f", "severity": "high",
                   "is_transient": False},
        existing_number=existing, rerun_attempted=False, fix_pr_url=None,
        health_run_url="h", evidence=evidence, **kwargs)


def _body(calls):
    argv = calls["create"][0]
    return argv[argv.index("--body") + 1]


def test_the_issue_body_carries_the_base_and_head_commits(issue_recorder, evidence_wiring):
    ev = hc.surface_evidence_for_run("o/r", _failing_run(), DECLARED_WORKFLOW_FILE, _decl())
    _file_issue(ev)
    body = _body(issue_recorder)
    assert BASE_SHA[:7] in body
    assert HEAD_SHA[:7] in body
    assert "No in-repo cause" in body
    # Evidence before interpretation: a reader who stops after the first section
    # has the falsifiable half.
    assert body.index("Changed-surface evidence") < body.index("Claude diagnosis")


def test_the_still_failing_comment_ALSO_carries_the_evidence(issue_recorder, evidence_wiring):
    """The branch that runs every day after the first. Evidence only on the body
    would be absent from almost every report anyone actually reads."""
    ev = hc.surface_evidence_for_run("o/r", _failing_run(), DECLARED_WORKFLOW_FILE, _decl())
    _file_issue(ev, existing=42)
    comment = issue_recorder["comment"][0][-1]
    assert "Changed-surface evidence" in comment
    assert BASE_SHA[:7] in comment


def test_an_overridden_diagnosis_keeps_the_models_wording_visibly(
        issue_recorder, evidence_wiring):
    ev = hc.surface_evidence_for_run("o/r", _failing_run(), DECLARED_WORKFLOW_FILE, _decl())
    diagnosis = hc._enforce_evidence(
        {"root_cause": REGRESSION_CLAIM, "fix": "f", "severity": "high",
         "is_transient": False}, ev)
    hc.file_or_update_issue(
        repo="o/r", workflow_name="wf", run_link="u", job_name="j", failing_step="s",
        diagnosis=diagnosis, existing_number=None, rerun_attempted=False,
        fix_pr_url=None, health_run_url="h", evidence=ev)
    body = _body(issue_recorder)
    assert "The diagnosis this replaced" in body
    assert REGRESSION_CLAIM in body


def test_a_no_in_repo_cause_issue_gets_its_own_label_not_the_transient_one(
        issue_recorder, evidence_wiring):
    ev = hc.surface_evidence_for_run("o/r", _failing_run(), DECLARED_WORKFLOW_FILE, _decl())
    _file_issue(ev)
    argv = issue_recorder["create"][0]
    assert f"--label={hc._LABEL_NO_CAUSE}" in argv
    assert f"--label={hc._LABEL_TRANSIENT}" not in argv


def test_the_issue_states_why_a_re_run_was_suppressed(issue_recorder, evidence_wiring):
    ev = hc.surface_evidence_for_run("o/r", _failing_run(), DECLARED_WORKFLOW_FILE, _decl())
    _file_issue(ev, rerun_suppressed_reason=RERUN_REASON)
    assert RERUN_REASON in _body(issue_recorder)


def test_an_unknown_verdict_issue_says_so_rather_than_claiming_nothing_changed(
        issue_recorder):
    _file_issue(hc._no_evidence("the compare API did not answer"))
    body = _body(issue_recorder)
    assert "Could not be established" in body
    assert "No in-repo cause" not in body


def test_an_issue_filed_with_no_evidence_is_byte_identical_to_today(issue_recorder):
    _file_issue(None)
    assert "Changed-surface evidence" not in _body(issue_recorder)


# ── The re-run decision is the REPOSITORY's, not the verdict's ────────────────

@pytest.fixture
def rerun_harness(monkeypatch):
    """`triage_failed_runs` with a transient diagnosis and a controllable evidence."""
    state = {"failures": [_run(1, FAILING_RUN_NAME, NOW - timedelta(hours=2))],
             "reruns": [], "filed": [], "evidence": hc._no_evidence("stubbed")}

    def fake_gh(*args, **kwargs):
        if args[:2] == ("run", "rerun"):
            state["reruns"].append(args[2])
        return ""

    monkeypatch.setattr(hc, "_collect_runs",
                        lambda repo, status, cutoff:
                        list(state["failures"]) if status == "failure" else [])
    monkeypatch.setattr(hc, "_gh", fake_gh)
    monkeypatch.setattr(hc, "ensure_labels", lambda repo: None)
    monkeypatch.setattr(hc, "get_open_health_issues", lambda repo: {})
    monkeypatch.setattr(hc, "auto_close_resolved_issues", lambda *a, **k: 0)
    monkeypatch.setattr(hc, "_gh_api", lambda path: {"jobs": [
        {"id": 1, "name": "job", "conclusion": "failure",
         "steps": [{"name": "step", "conclusion": "failure"}]}]})
    monkeypatch.setattr(hc, "get_job_logs", lambda job_id, repo: "boom")
    monkeypatch.setattr(hc, "_load_workflow_declarations", lambda: {})
    monkeypatch.setattr(hc, "surface_evidence_for_run", lambda *a, **k: state["evidence"])
    monkeypatch.setattr(hc, "diagnose_with_claude", lambda *a, **k: {
        "root_cause": "rc", "fix": "f", "severity": "high",
        "is_transient": True, "mechanical": False})
    monkeypatch.setattr(hc, "file_or_update_issue",
                        lambda **kw: state["filed"].append(kw) or 900)
    return state


def test_a_workflow_with_no_declaration_is_still_re_run_when_transient(rerun_harness):
    """The healing path. A DNS failure in any repo's CI lane is also "no in-repo
    cause", and a free re-run is exactly what Tier 1 is for — coupling the re-run
    to the VERDICT would disable auto-healing across every consuming repo."""
    hc.triage_failed_runs("o/r", 25, "u", dry_run=False)
    assert rerun_harness["reruns"] == ["1"]


def test_a_no_in_repo_cause_verdict_ALONE_does_not_stop_a_re_run(rerun_harness):
    rerun_harness["evidence"] = {**hc._no_evidence(""), "verdict": hc._CAUSE_NONE}
    hc.triage_failed_runs("o/r", 25, "u", dry_run=False)
    assert rerun_harness["reruns"] == ["1"]


def test_a_workflow_declared_rerun_forbid_is_never_re_run(rerun_harness):
    """Remove the guard and this goes red. It is the only thing standing between an
    unattended pattern match on `rate.?limit` — text an eval log routinely carries
    — and a billed production-model suite."""
    rerun_harness["evidence"] = {**hc._no_evidence(""), "rerun": "forbid",
                                 "rerun_reason": RERUN_REASON}
    hc.triage_failed_runs("o/r", 25, "u", dry_run=False)
    assert rerun_harness["reruns"] == []


def test_a_suppressed_re_run_still_files_the_issue_and_says_why(rerun_harness):
    rerun_harness["evidence"] = {**hc._no_evidence(""), "rerun": "forbid",
                                 "rerun_reason": RERUN_REASON}
    result = hc.triage_failed_runs("o/r", 25, "u", dry_run=False)
    assert result["filed"] == 1
    assert result["rerun"] == 0
    assert rerun_harness["filed"][0]["rerun_suppressed_reason"] == RERUN_REASON


# ── The wiring that would otherwise fail silently ─────────────────────────────

def test_collect_runs_requests_the_head_sha_and_branch_the_evidence_needs(monkeypatch):
    """Drop any of these from the `--json` list and the whole evidence section goes
    permanently UNKNOWN with no other symptom."""
    seen = {}

    def fake_gh_json(*args):
        seen["args"] = args
        return []

    monkeypatch.setattr(hc, "_gh_json", fake_gh_json)
    hc._collect_runs("o/r", "failure", CUTOFF)
    fields = seen["args"][seen["args"].index("--json") + 1]
    for needed in ("headSha", "headBranch", "workflowDatabaseId"):
        assert needed in fields


def test_the_action_installs_the_yaml_parser_the_declaration_reader_needs():
    """Same failure class: the reader ships, the dependency does not, every verdict
    degrades to UNKNOWN and the lane still reports success."""
    action = (Path(__file__).parent / "action.yml").read_text(encoding="utf-8")
    assert "pyyaml" in action


def test_the_new_label_is_created_before_it_is_applied(monkeypatch):
    created = []

    def fake_run(argv, *a, **k):
        created.append(argv)
        return SimpleNamespace(returncode=0, stdout="[]", stderr="")

    monkeypatch.setattr(hc.subprocess, "run", fake_run)
    hc.ensure_labels("o/r")
    assert any(hc._LABEL_NO_CAUSE in argv for argv in created)

"""Tests for the CRITICAL/HIGH-vs-digest clamp (infra-commons/meta#1357).

`individual_severities()` decides the one thing this change is about: which severities get an
issue each, and which roll into the single per-repo digest. Before #1357 that was a per-caller
knob (`severity_floor`) defaulting to HIGH; two of eighteen callers had opted back into one issue
per MEDIUM/LOW finding, which is the noise the operator cut. It is now constant.

Why this file is thorough out of proportion to its diff: sixteen of the eighteen callers change by
zero bytes of behaviour, and the two that do change were `disabled_manually` when this shipped. No
live run can demonstrate the clamp works. These tests are the whole verification — and they reach
every caller through a *moving* tag, with no per-caller pin bump to review them first.

Mocks at capture.py's own function seams (`upsert_digest`, `create_issue`), the same style as the
sibling test modules, rather than at the HTTP layer underneath them.
"""
import importlib.util
from pathlib import Path

import pytest
import yaml

_ACTION_DIR = Path(__file__).resolve().parent
_spec = importlib.util.spec_from_file_location("capture", _ACTION_DIR / "capture.py")
capture = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(capture)

_BEFORE = "a" * 40
_AFTER = "b" * 40
_REPO_ROOT = _ACTION_DIR.parents[2]


# ── The clamp itself ─────────────────────────────────────────────────────────────

@pytest.mark.parametrize("floor", [
    "", "   ", "LOW", "low", " low ", "MEDIUM", "Medium", "HIGH", "high ",
    "CRITICAL", "critical", "nonsense", "H1GH", "LOW;CRITICAL",
])
def test_individual_severities_is_constant_for_every_input(floor):
    """No value a caller can put in `severity_floor` changes the set. That is the feature."""
    assert capture.individual_severities(floor) == {"CRITICAL", "HIGH"}


def test_medium_and_low_are_never_individual():
    """The operator's ask, stated directly: no more one-issue-per-MEDIUM/LOW-finding."""
    got = capture.individual_severities("LOW")
    assert "MEDIUM" not in got
    assert "LOW" not in got


def test_high_is_individual_even_when_the_caller_asks_for_critical():
    """"HIGH stays filing exactly as it does today" — so the clamp is symmetric.

    A CRITICAL-only floor was the one input that could push HIGH into a digest row, which is
    also the only way to write a row `_DIGEST_ROW_RE` could not read back.
    """
    assert "HIGH" in capture.individual_severities("CRITICAL")


def test_the_returned_set_is_not_the_module_constant():
    """Callers get a copy — a mutation must not silently re-open MEDIUM/LOW for the next run."""
    got = capture.individual_severities("")
    got.add("LOW")
    assert capture.individual_severities("") == {"CRITICAL", "HIGH"}


# ── Telling the caller its setting is dead ───────────────────────────────────────

@pytest.mark.parametrize("floor", ["", "   ", None, "HIGH", "high", "  HIGH "])
def test_no_note_when_the_floor_is_absent_or_already_high(floor):
    """Sixteen of eighteen callers must gain no new warning from this change."""
    assert capture.severity_floor_note(floor) is None


@pytest.mark.parametrize("floor", ["LOW", "MEDIUM", "CRITICAL", "typo"])
def test_an_ignored_floor_is_named_in_the_note(floor):
    note = capture.severity_floor_note(floor)
    assert note is not None
    assert floor in note
    assert "not honoured" in note


def test_an_invalid_floor_is_no_longer_silent():
    """Before #1357 a typo fell back to HIGH with no stderr and no receipt row, so a caller
    could not tell a working value from a misspelt one. The sibling weekly-security-scan
    warns for the identical mistake; this one did not."""
    assert capture.severity_floor_note("lowest") is not None


def test_the_note_cannot_inject_markdown():
    """It reaches a job-summary markdown block, so it is collapsed and capped first."""
    note = capture.severity_floor_note("LOW\n| evil | row |\n" + "x" * 200)
    assert note is not None
    assert "\n| evil" not in note
    assert "\n" not in note.split("is not honoured")[0]
    assert len(note) < 400


# ── End-to-end through main() ────────────────────────────────────────────────────

@pytest.fixture
def harness(monkeypatch, tmp_path):
    """Stub every boundary main() touches; record filed issues AND digested findings.

    Unlike test_main_ordering's harness, `upsert_digest` is a recorder rather than a
    constant — the routing assertion is the entire point here.
    """
    created: list[dict] = []
    digested: list[list[dict]] = []

    monkeypatch.setenv("REVIEW_API_KEY", "k")
    monkeypatch.setenv("GITHUB_TOKEN", "t")
    monkeypatch.setenv("REPO", "o/r")
    monkeypatch.setenv("BEFORE_SHA", _BEFORE)
    monkeypatch.setenv("AFTER_SHA", _AFTER)
    monkeypatch.setenv("RUN_URL", "https://example.invalid/run")
    monkeypatch.setenv("GITHUB_STEP_SUMMARY", str(tmp_path / "summary.md"))
    monkeypatch.delenv("INDIVIDUAL_SEVERITY_FLOOR", raising=False)
    monkeypatch.delenv("BOARD_APP_TOKEN", raising=False)
    monkeypatch.delenv("INGEST_PR_REVIEWS", raising=False)

    monkeypatch.setattr(capture, "get_diff", lambda b, a: "diff --git a/x b/x\n+x\n")
    monkeypatch.setattr(capture, "load_suppressions", lambda before: [])
    monkeypatch.setattr(capture, "build_suppression_context", lambda s: "")
    monkeypatch.setattr(capture, "get_repo_context", lambda: "")
    monkeypatch.setattr(capture, "ensure_labels", lambda t, r: None)
    monkeypatch.setattr(capture, "open_security_issues", lambda t, r: {})
    monkeypatch.setattr(capture, "closed_suppressed_keys", lambda t, r: set())
    monkeypatch.setattr(capture, "ingest_pr_review_findings", lambda *a: ([], []))
    monkeypatch.setattr(capture.time, "sleep", lambda s: None)

    def fake_digest(token, repo, open_issues, suppressed, findings, run_url):
        digested.append(list(findings))
        return (0, len(findings))

    def fake_create(token, repo, title, body, labels):
        created.append({"title": title, "body": body, "labels": labels})
        return {"node_id": f"node{len(created)}"}

    monkeypatch.setattr(capture, "upsert_digest", fake_digest)
    monkeypatch.setattr(capture, "create_issue", fake_create)
    return created, digested, tmp_path / "summary.md"


def _finding(severity, location, title):
    return {
        "severity": severity, "location": location, "title": title,
        "description": title, "category": "unknown", "sources": ["post-merge review"],
    }


def _post_merge(monkeypatch, findings):
    """Stub the post-merge pass. `review_diff` returns raw model text and `parse_findings`
    turns it into findings — stubbing only the first leaves the real parser reading a list.
    """
    monkeypatch.setattr(capture, "review_diff", lambda *a: "{}")
    monkeypatch.setattr(capture, "parse_findings", lambda raw: (list(findings), 0))


def test_main_digests_a_medium_even_when_the_caller_sets_low(monkeypatch, harness):
    """The headline property, end to end: the two callers that asked for one-issue-per-MEDIUM
    stop getting it, without their workflow files changing."""
    created, digested, _ = harness
    monkeypatch.setenv("INDIVIDUAL_SEVERITY_FLOOR", "LOW")
    _post_merge(monkeypatch, [
        _finding("HIGH", "src/a.py:1", "Real problem"),
        _finding("MEDIUM", "src/b.py:2", "Routine thing"),
        _finding("LOW", "src/c.py:3", "Nit"),
    ])

    capture.main()  # no CRITICAL and no model error — must not raise

    assert len(created) == 1, "only the HIGH may get an issue of its own"
    assert "Real problem" in created[0]["title"]
    assert [f["severity"] for f in digested[0]] == ["MEDIUM", "LOW"]


def test_main_still_files_high_individually_with_no_floor_set(monkeypatch, harness):
    """The other sixteen callers: unchanged behaviour, asserted rather than assumed."""
    created, digested, _ = harness
    _post_merge(monkeypatch, [
        _finding("HIGH", "src/a.py:1", "Real problem"),
        _finding("MEDIUM", "src/b.py:2", "Routine thing"),
    ])

    capture.main()

    assert [c["labels"] for c in created] == [
        ["security", "severity:high", "source:adversarial-ai"]
    ]
    assert [f["severity"] for f in digested[0]] == ["MEDIUM"]


def test_main_warns_on_stderr_and_in_the_summary_for_a_dead_floor(monkeypatch, harness, capsys):
    _, _, summary = harness
    monkeypatch.setenv("INDIVIDUAL_SEVERITY_FLOOR", "LOW")
    _post_merge(monkeypatch, [])

    capture.main()

    assert "severity_floor" in capsys.readouterr().err
    assert "no longer honoured" in summary.read_text()


def test_main_is_silent_when_no_floor_is_passed(monkeypatch, harness, capsys):
    _, _, summary = harness
    _post_merge(monkeypatch, [])

    capture.main()

    assert "severity_floor" not in capsys.readouterr().err
    assert "no longer honoured" not in summary.read_text()


def test_the_warning_survives_an_empty_diff(monkeypatch, harness):
    """Pins the emit placement: ahead of every early return in main(), so a caller carrying a
    dead setting is told on its next merge even if that merge reviews nothing."""
    _, _, summary = harness
    monkeypatch.setenv("INDIVIDUAL_SEVERITY_FLOOR", "MEDIUM")
    monkeypatch.setattr(capture, "get_diff", lambda b, a: "")

    capture.main()

    assert "no longer honoured" in summary.read_text()


def test_the_receipt_states_the_individual_scope(monkeypatch, harness):
    """Every run says what it would have filed individually, not just what it did file."""
    _, _, summary = harness
    _post_merge(monkeypatch, [])

    capture.main()

    body = summary.read_text()
    assert "Individual issues" in body
    assert "CRITICAL+HIGH" in body


def test_the_receipt_marks_a_floor_that_was_ignored(monkeypatch, harness):
    _, _, summary = harness
    monkeypatch.setenv("INDIVIDUAL_SEVERITY_FLOOR", "LOW")
    _post_merge(monkeypatch, [])

    capture.main()

    assert "severity_floor ignored" in summary.read_text()


# ── Digest row round-trip (the write/read asymmetry the clamp hides) ─────────────

@pytest.mark.parametrize("severity", ["CRITICAL", "HIGH", "MEDIUM", "LOW"])
def test_digest_row_round_trips_for_every_severity(severity):
    """`digest_row` writes whatever severity it is handed; `_DIGEST_ROW_RE` must read all of
    them back. A location that cannot be recovered never enters `seen`, so every subsequent
    run re-appends the same row and the digest grows without bound. Unreachable while the
    clamp holds — which is precisely why it needs a test rather than a comment."""
    finding = _finding(severity, "src/app.py:12", "Something")
    body = capture.build_digest_body([capture.digest_row(finding)], "https://example.invalid/run")
    assert capture.existing_digest_locations(body) == {"src/app.py:12"}


def test_a_digest_row_is_not_re_added_on_the_next_run():
    """The dedup property the round-trip exists to protect."""
    finding = _finding("MEDIUM", "src/app.py:12", "Something")
    body = capture.build_digest_body([capture.digest_row(finding)], "https://example.invalid/run")
    assert finding["location"] in capture.existing_digest_locations(body)


# ── Caller compatibility: the input must stay declared ───────────────────────────

def test_the_reusable_still_declares_severity_floor():
    """Three callers still pass `severity_floor`. An input a reusable workflow does not
    declare is a hard error at run start, not a warning — removing it would break each of
    them the moment it bumped its pin. It is inert, not gone."""
    doc = yaml.safe_load(
        (_REPO_ROOT / ".github/workflows/capture-findings-reusable.yml").read_text()
    )
    # PyYAML resolves the `on:` key to the boolean True, not the string "on".
    inputs = doc[True]["workflow_call"]["inputs"]
    assert "severity_floor" in inputs
    assert "IGNORED" in inputs["severity_floor"]["description"]


def test_the_composite_still_declares_and_forwards_severity_floor():
    """The value must still REACH capture.py — the warning is what tells a caller its setting
    is dead, and a clamp applied in YAML instead would destroy the evidence for it."""
    doc = yaml.safe_load((_ACTION_DIR / "action.yml").read_text())
    assert "severity-floor" in doc["inputs"]
    env = [s.get("env", {}) for s in doc["runs"]["steps"] if isinstance(s, dict)]
    forwarded = [e["INDIVIDUAL_SEVERITY_FLOOR"] for e in env if "INDIVIDUAL_SEVERITY_FLOOR" in e]
    assert forwarded == ["${{ inputs.severity-floor }}"]

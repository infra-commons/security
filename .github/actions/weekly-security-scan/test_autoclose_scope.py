"""Tests that the weekly scan's auto-close pass only closes issues the scan itself opened.

The auto-close pass reasons by absence: a `security`-labelled issue whose title is missing from
the current run's `expected_titles` is closed as resolved. That inference is only valid for issues
this scan authored. Every title it can author is built by `build_issue_title` or `aggregate_title`
and therefore starts `[Security][`; a hand-filed issue's title never can, so it is absent on every
run by construction and was closed on the next Sunday — with a comment saying the finding "was not
detected", which is indistinguishable from "was fixed".

That is not hypothetical. Eight hand-filed issues across two repos were closed this way on
2026-08-02, none of them fixed (infra-commons/security#65), including the entire filed output of a
security assessment written the day before.

The tests drive the real `run_create_issues` reconcile loop rather than the predicate alone: a test
of `is_scanner_authored_title` on its own would pass whether or not the loop consults it, which is
the shape of bug this file exists to catch. `test_a_resolved_scanner_finding_is_still_closed` is
the behaviour-preservation control — the fix must change the outcome for hand-filed issues and for
nothing else.
"""
from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest

_ACTION_DIR = Path(__file__).resolve().parent

# Load by path: the module name carries a dash and the directory is not a package.
_spec = importlib.util.spec_from_file_location("security_scan", _ACTION_DIR / "security-scan.py")
scan = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(scan)


HAND_FILED = "rolliq-test runs with REQUIRE_API_KEY unset: the fleet's primary auth control"
RESOLVED_SCANNER = "[Security][semgrep][HIGH] src/api/main.py:41 — hardcoded credential"


def _issue(number: int, title: str, labels: list[str]) -> dict:
    return {"number": number, "title": title, "labels": [{"name": n} for n in labels]}


class _FakeResponse:
    def __init__(self, payload):
        self._payload = payload

    def json(self):
        return self._payload

    def raise_for_status(self):
        return None


class _FakeClient:
    """Stands in for `httpx.Client` on the dashboard-fetch path only."""

    def __init__(self, *_args, **_kwargs):
        pass

    def __enter__(self):
        return self

    def __exit__(self, *_exc):
        return False

    def get(self, *_args, **_kwargs):
        return _FakeResponse([])  # no dashboard issue exists

    def post(self, *_args, **_kwargs):
        return _FakeResponse({})

    def patch(self, *_args, **_kwargs):
        return _FakeResponse({})


@pytest.fixture
def reconcile(monkeypatch, tmp_path):
    """Run the real create-issues reconcile against a fixed set of open issues.

    Returns a callable (open_issues, findings) -> list of issue numbers closed.
    """
    def _run(open_issues: list[dict], findings: list[dict]) -> list[int]:
        closed: list[int] = []

        monkeypatch.setattr(scan, "ensure_labels_exist", lambda *a, **k: None)
        monkeypatch.setattr(
            scan,
            "fetch_open_security_issues",
            lambda *a, **k: ({i["title"]: i for i in open_issues}, False),
        )
        monkeypatch.setattr(
            scan, "close_issue", lambda _t, _r, number, _u: closed.append(number)
        )
        monkeypatch.setattr(scan, "create_issue", lambda *a, **k: None)
        monkeypatch.setattr(scan, "update_issue_body", lambda *a, **k: None)
        monkeypatch.setattr(scan.time, "sleep", lambda _s: None)
        monkeypatch.setattr(scan.httpx, "Client", _FakeClient)

        # Findings arrive as a semgrep artifact so the loader path stays real.
        artifact = tmp_path / "semgrep-findings.json"
        artifact.write_text(json.dumps({"results": findings}), encoding="utf-8")

        monkeypatch.setenv("GITHUB_TOKEN", "x")
        monkeypatch.setenv("REPO", "rolliq-com/solution-template")
        monkeypatch.setenv("RUN_URL", "https://github.com/rolliq-com/solution-template/actions/runs/1")
        monkeypatch.setenv("SEMGREP_FINDINGS", str(artifact))

        scan.run_create_issues()
        return closed

    return _run


def test_a_hand_filed_issue_survives_a_scan_that_cannot_detect_it(reconcile):
    """The defect: a human-titled `security` issue is absent from every run's expected set."""
    closed = reconcile([_issue(995, HAND_FILED, ["security", "severity:medium"])], [])
    assert closed == [], (
        "the scan closed a hand-filed issue it never opened and cannot detect — "
        "'not detected' is being reported as 'resolved'"
    )


def test_a_source_label_is_not_what_protects_a_hand_filed_issue(reconcile):
    """`rrc#996` carried `source:pentest` and was closed anyway: only the title decides."""
    closed = reconcile(
        [_issue(996, HAND_FILED, ["security", "severity:medium", "source:pentest"])], []
    )
    assert closed == []


def test_a_resolved_scanner_finding_is_still_closed(reconcile):
    """Behaviour-preservation control: the fix must not disarm the auto-close it narrows."""
    closed = reconcile(
        [_issue(42, RESOLVED_SCANNER, ["security", "severity:high", "source:semgrep"])], []
    )
    assert closed == [42], "a genuinely resolved scanner finding must still auto-close"


def test_a_still_present_scanner_finding_is_not_closed(reconcile, tmp_path):
    """The other half of the control: a finding the scan re-detects stays open."""
    raw = {
        "check_id": "python.lang.security.hardcoded-credential",
        "path": "src/api/main.py",
        "start": {"line": 41},
        "extra": {
            "message": "hardcoded credential",
            "severity": "ERROR",
            "metadata": {"impact": "HIGH"},
        },
    }
    # Derive the open issue's title from the real parser rather than hand-writing a
    # string that could drift from it.
    artifact = tmp_path / "probe.json"
    artifact.write_text(json.dumps({"results": [raw]}), encoding="utf-8")
    parsed = scan.parse_semgrep_findings(str(artifact))
    assert parsed, "the probe finding must survive parsing for this control to mean anything"
    title = scan.build_issue_title(parsed[0])

    closed = reconcile(
        [_issue(43, title, ["security", "severity:high", "source:semgrep"])], [raw]
    )
    assert closed == []


def test_every_title_the_scan_can_author_is_recognised_as_its_own():
    """`is_scanner_authored_title` must accept both title builders, including odd inputs."""
    assert scan.is_scanner_authored_title(
        scan.build_issue_title(
            {"source": "semgrep", "severity": "HIGH", "location": "a.py:1", "title": "t"}
        )
    )
    assert scan.is_scanner_authored_title(
        scan.build_issue_title(
            {"source": "", "severity": "not-a-severity", "location": "", "title": ""}
        )
    )
    for source in ("semgrep", "trivy", "gitleaks", "adversarial-ai", "azure-defender"):
        assert scan.is_scanner_authored_title(scan.aggregate_title(source))


def test_the_dashboard_title_is_not_treated_as_scanner_authored():
    """It is skipped explicitly today; it must not start matching the prefix by accident."""
    assert not scan.is_scanner_authored_title(scan.SECURITY_STATUS_TITLE)

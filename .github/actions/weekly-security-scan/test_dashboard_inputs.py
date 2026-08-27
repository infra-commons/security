"""What the Security Status dashboard renderer is *fed* — the half a renderer test cannot see.

`test_status_dashboard.py` drives `build_status_body()` directly and proves it renders a
degraded run differently from a healthy one. That is necessary and not sufficient: every one
of those tests passes just as happily when nothing ever tells the renderer the truth. Both
defects this file covers live entirely on the input side.

  * **Scope.** The dashboard counted only `labels=security`. Nothing enforces that a producer
    applies that label, so an open `severity:critical` issue without it was invisible to every
    number on the page — a false all-clear built out of accurate arithmetic over the wrong set.
    `fetch_dashboard_issues` unions the canonical severity labels in; `fetch_open_security_issues`
    deliberately does NOT, because that narrower set is what the auto-close pass iterates and
    everything in it is a candidate for closing (infra-commons/security#65).

  * **Signal.** `build_status_body(run_degraded=...)` is only worth anything if the workflow
    actually passes the caller's job outcomes into it. That is a YAML-to-Python contract across
    three files, so it is asserted as one: delete the `run-degraded:` line from the reusable
    workflow and every other test in this action stays green.
"""
from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest
import yaml

_ACTION_DIR = Path(__file__).resolve().parent
_REPO_ROOT = _ACTION_DIR.parent.parent.parent
_REUSABLE_WORKFLOW = _REPO_ROOT / ".github" / "workflows" / "weekly-security-scan-reusable.yml"

_spec = importlib.util.spec_from_file_location("security_scan", _ACTION_DIR / "security-scan.py")
scan = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(scan)


def _issue(number: int, labels: list[str], **extra) -> dict:
    return {
        "number": number,
        "title": f"issue #{number}",
        "labels": [{"name": n} for n in labels],
        **extra,
    }


class _FakeResponse:
    def __init__(self, payload):
        self._payload = payload

    def json(self):
        return self._payload

    def raise_for_status(self):
        return None


class _FakeGitHub:
    """Serves the open-issues endpoint per label, and records what was asked for.

    Everything is returned on page 1, which is what the real API does for any realistic
    repo; `pages_of_100` exists for the one test that needs the page cap to trip.
    """

    def __init__(self, by_label: dict[str, list[dict]], pages_of_100: set[str] | None = None):
        self.by_label = by_label
        self.pages_of_100 = pages_of_100 or set()
        self.labels_requested: list[str] = []

    # httpx.Client(...) -> context manager -> .get()
    def __call__(self, *_args, **_kwargs):
        return self

    def __enter__(self):
        return self

    def __exit__(self, *_exc):
        return False

    def get(self, _url, headers=None, params=None):
        label = params["labels"]
        self.labels_requested.append(label)
        if label in self.pages_of_100:
            return _FakeResponse([_issue(1000 + i, ["security"]) for i in range(100)])
        # The dashboard-issue lookup does not paginate, so `page` may be absent.
        page = params.get("page", 1)
        return _FakeResponse(self.by_label.get(label, []) if page == 1 else [])


@pytest.fixture
def github(monkeypatch):
    def _install(by_label, pages_of_100=None):
        fake = _FakeGitHub(by_label, pages_of_100)
        monkeypatch.setattr(scan.httpx, "Client", fake)
        return fake

    return _install


# ── Scope: what the dashboard is allowed to see ────────────────────────────────

def test_the_dashboard_sees_an_issue_that_only_a_severity_label_finds(github):
    """The defect, at the only layer that can catch it: an open severity:critical issue with no
    `security` label. Under the old single-label fetch this issue reached the renderer in no
    dict at all, so the dashboard read a confident, arithmetically correct all-clear."""
    github({"security": [], "severity:critical": [_issue(685, ["severity:critical"])]})
    issues, truncated = scan.fetch_dashboard_issues("token", "org/repo")
    assert [i["number"] for i in issues.values()] == [685]
    assert truncated is False
    body = scan.build_status_body("org/repo", "https://x", issues)
    assert "| 🔴 CRITICAL | 1 |" in body


def test_every_canonical_severity_label_is_queried(github):
    """All four, not just the two that prompted this. A MEDIUM finding that lost its `security`
    label is the same defect one tier down, and 'we only look for the severe ones' is how the
    tier below becomes permanently invisible."""
    fake = github({})
    scan.fetch_dashboard_issues("token", "org/repo")
    assert set(fake.labels_requested) == {
        "security", "severity:critical", "severity:high", "severity:medium", "severity:low",
    }


def test_an_issue_matching_two_label_queries_is_counted_once(github):
    """The normal case — a properly labelled finding matches `security` AND its severity label.
    Keyed by number, not title, so the union cannot inflate the totals."""
    dual = _issue(7, ["security", "severity:high", "source:semgrep"])
    github({"security": [dual], "severity:high": [dual]})
    issues, _ = scan.fetch_dashboard_issues("token", "org/repo")
    assert len(issues) == 1
    assert "1 of 1 open security issues counted by severity." in scan.build_status_body(
        "org/repo", "https://x", issues
    )


def test_two_issues_sharing_a_title_both_survive_the_dashboard_fetch(github):
    """Keying by number rather than title is also what stops the dashboard under-counting two
    distinct issues that happen to share a title."""
    github({"security": [_issue(1, ["security", "severity:low"]),
                         _issue(2, ["security", "severity:low"])]})
    issues, _ = scan.fetch_dashboard_issues("token", "org/repo")
    assert len(issues) == 2


def test_a_pull_request_is_not_counted_as_an_open_finding(github):
    """The issues endpoint returns PRs too. A PR carrying a `severity:` label would otherwise
    sit on the dashboard as an open finding until it merged — noise that trains people to
    discount the number."""
    github({"severity:high": [
        _issue(9, ["severity:high"], pull_request={"url": "https://api.github.com/pulls/9"}),
        _issue(10, ["severity:high"]),
    ]})
    issues, _ = scan.fetch_dashboard_issues("token", "org/repo")
    assert [i["number"] for i in issues.values()] == [10]


def test_a_page_cap_on_any_single_label_truncates_the_whole_dashboard(github):
    """Truncation is ORed across the union: an incomplete answer to one query makes the totals
    a floor, and the dashboard has to say so."""
    github({}, pages_of_100={"severity:low"})
    issues, truncated = scan.fetch_dashboard_issues("token", "org/repo")
    assert truncated is True
    assert "hit the API page cap" in scan.build_status_body(
        "org/repo", "https://x", issues, truncated=truncated
    )


# ── Scope: what auto-close is allowed to see (unchanged, deliberately) ─────────

def test_the_autoclose_fetch_still_asks_only_for_label_security(github):
    """The widening must not leak into the fetch the close loop iterates. Everything in that
    dict is a candidate for closing, so a wider query there would hand the scan issues it never
    opened and cannot detect — the mass-close of infra-commons/security#65."""
    fake = github({"security": [_issue(1, ["security", "severity:high"])],
                   "severity:high": [_issue(685, ["severity:high"])]})
    issues, _ = scan.fetch_open_security_issues("token", "org/repo")
    assert set(fake.labels_requested) == {"security"}
    assert [i["number"] for i in issues.values()] == [1], (
        "the severity-only issue reached the auto-close set, where absence means 'close me'"
    )


def test_the_autoclose_fetch_is_still_keyed_by_title(github):
    """Its callers dedupe new findings by title against this dict — changing the key would
    silently re-open an issue for every finding already open."""
    github({"security": [_issue(1, ["security"])]})
    issues, _ = scan.fetch_open_security_issues("token", "org/repo")
    assert list(issues) == ["issue #1"]


# ── Signal: RUN_DEGRADED parsing ───────────────────────────────────────────────

@pytest.mark.parametrize("value", ["", "false", "FALSE", "0", "no", "  false  "])
def test_recognised_false_values_read_as_a_healthy_run(monkeypatch, value):
    monkeypatch.setenv("RUN_DEGRADED", value)
    assert scan.run_degraded_from_env() is False


def test_an_unset_run_degraded_reads_as_a_healthy_run(monkeypatch):
    """The default for every caller that has not opted in yet — including the update-dashboard
    caller, which lives outside this repo. It must keep working, unchanged."""
    monkeypatch.delenv("RUN_DEGRADED", raising=False)
    assert scan.run_degraded_from_env() is False


@pytest.mark.parametrize("value", ["true", "TRUE", "1", "yes"])
def test_recognised_true_values_read_as_a_degraded_run(monkeypatch, value):
    monkeypatch.setenv("RUN_DEGRADED", value)
    assert scan.run_degraded_from_env() is True


def test_an_unparseable_value_fails_safe_to_degraded_and_says_why(monkeypatch, capsys):
    """A mis-set input, or an expression that did not expand, means the run's health is
    unknown. Reading unknown as 'healthy' is the exact fail-open this signal exists to close,
    so it reads as degraded — and names the value, so the wiring gets fixed rather than the
    banner being ignored."""
    monkeypatch.setenv("RUN_DEGRADED", "${{ inputs.run-degraded }}")
    assert scan.run_degraded_from_env() is True
    assert "not a recognised boolean" in capsys.readouterr().err


# ── Signal: the YAML wiring that carries it ────────────────────────────────────

def _action_yaml() -> dict:
    return yaml.safe_load((_ACTION_DIR / "action.yml").read_text(encoding="utf-8"))


def _reusable_yaml() -> dict:
    return yaml.safe_load(_REUSABLE_WORKFLOW.read_text(encoding="utf-8"))


def _scan_step(job: dict) -> dict:
    steps = [s for s in job["steps"] if "weekly-security-scan" in str(s.get("uses", ""))]
    assert len(steps) == 1, f"expected exactly one weekly-security-scan step, got {len(steps)}"
    return steps[0]


def test_the_action_declares_the_run_degraded_input():
    assert "run-degraded" in _action_yaml()["inputs"]


def test_the_action_forwards_run_degraded_to_the_env_var_the_script_reads():
    """Both halves of the contract in one assertion: the env var the action sets must be the
    one security-scan.py reads, or the input is accepted and discarded."""
    steps = [s for s in _action_yaml()["runs"]["steps"]
             if "security-scan.py" in str(s.get("run", ""))]
    assert len(steps) == 1, f"expected one step invoking security-scan.py, got {len(steps)}"
    assert "${{ inputs.run-degraded }}" in steps[0]["env"]["RUN_DEGRADED"]
    assert 'os.environ.get("RUN_DEGRADED"' in (
        _ACTION_DIR / "security-scan.py"
    ).read_text(encoding="utf-8")


def test_the_create_issues_job_still_runs_on_failure():
    """The premise of the whole fix. If this job ever stops being `if: always()`, a failed run
    writes no dashboard at all and the banner has nothing to warn about."""
    job = _reusable_yaml()["jobs"]["create-issues"]
    assert str(job["if"]).strip() == "always()"


def test_the_create_issues_job_tells_the_action_when_the_run_is_degraded():
    """The defect itself: the renderer was never told. This is the line whose deletion the
    renderer tests cannot notice."""
    expr = str(_scan_step(_reusable_yaml()["jobs"]["create-issues"])["with"]["run-degraded"])
    assert "needs.*.result" in expr
    assert "failure" in expr
    assert "cancelled" in expr


def test_a_skipped_job_is_not_treated_as_a_degraded_run():
    """The ai-review jobs and gitleaks are skipped by design on an ordinary Sunday run. A
    banner that fires every week is one operators learn to override, which is the same as not
    having one — accuracy is the guard's safety property, not loudness."""
    expr = str(_scan_step(_reusable_yaml()["jobs"]["create-issues"])["with"]["run-degraded"])
    assert "skipped" not in expr


# ── The call site: the renderer only knows what run_create_issues tells it ─────
#
# Defect 2 was not a renderer bug at all — `unreported` was computed, used to protect
# auto-close, and then not passed four lines further down. Every renderer test above passes
# that argument by hand, so all of them stay green with the call site's argument deleted.
# These drive the real `run_create_issues()` end to end and read the dashboard body it
# actually writes, which is the only layer where that omission is visible.


@pytest.fixture
def write_dashboard(monkeypatch, tmp_path, github):
    """Run the real create-issues path and return the dashboard body it wrote.

    Returns (body, closed_issue_numbers).
    """
    def _run(by_label: dict[str, list[dict]], env: dict[str, str] | None = None):
        created: list[tuple[str, str]] = []
        updated: list[str] = []
        closed: list[int] = []

        github(by_label)
        monkeypatch.setattr(scan, "ensure_labels_exist", lambda *a, **k: None)
        monkeypatch.setattr(scan, "close_issue", lambda _t, _r, n, _u: closed.append(n))
        monkeypatch.setattr(
            scan, "create_issue", lambda _t, _r, title, body, _l: created.append((title, body))
        )
        monkeypatch.setattr(
            scan, "update_issue_body", lambda _t, _r, _n, body: updated.append(body)
        )
        monkeypatch.setattr(scan.time, "sleep", lambda _s: None)

        monkeypatch.setenv("GITHUB_TOKEN", "x")
        monkeypatch.setenv("REPO", "org/repo")
        monkeypatch.setenv("RUN_URL", "https://github.com/org/repo/actions/runs/1")
        monkeypatch.delenv("RUN_DEGRADED", raising=False)
        # A semgrep artifact that exists, so exactly one scanner counts as having
        # reported and the others are genuinely unreported.
        artifact = tmp_path / "semgrep-findings.json"
        artifact.write_text('{"results": []}', encoding="utf-8")
        monkeypatch.setenv("SEMGREP_FINDINGS", str(artifact))
        for k, v in (env or {}).items():
            monkeypatch.setenv(k, v)

        scan.run_create_issues()

        bodies = [b for t, b in created if t == scan.SECURITY_STATUS_TITLE] + updated
        assert len(bodies) == 1, f"expected exactly one dashboard write, got {len(bodies)}"
        return bodies[0], closed

    return _run


def test_the_scanners_that_did_not_report_are_marked_on_the_dashboard_it_writes(write_dashboard):
    """The defect: this run knows Trivy and Gitleaks produced nothing — it already refuses to
    auto-close their issues on that basis — and then wrote a dashboard that showed them as
    clean. Semgrep, which did report, must be left unmarked."""
    body, _ = write_dashboard({"security": [], "severity:high": []})
    assert "did not report this run" in body, (
        "the run knew which scanners produced nothing and rendered them as clean anyway"
    )
    assert "2 scanner(s) did not report this run" in body
    marked = [l for l in body.splitlines() if l.startswith("|") and "did not report this run" in l]
    named = {n for n in ("Gitleaks", "Trivy", "Semgrep") if any(n in l for l in marked)}
    assert named == {"Gitleaks", "Trivy"}, f"wrong rows marked: {marked}"


def test_the_dashboard_it_writes_says_when_the_run_itself_was_degraded(write_dashboard):
    body, _ = write_dashboard({"security": []}, env={"RUN_DEGRADED": "true"})
    assert "did not complete cleanly" in body


def test_a_healthy_run_writes_no_degraded_banner(write_dashboard):
    body, _ = write_dashboard({"security": []})
    assert "did not complete cleanly" not in body


def test_the_dashboard_it_writes_counts_an_issue_only_a_severity_label_finds(write_dashboard):
    """End to end for the scope fix — and the guard that goes with it: the issue is counted by
    the dashboard and is NOT closed, because nothing widened the set the close loop iterates."""
    orphan = _issue(685, ["severity:critical"])
    body, closed = write_dashboard({"security": [], "severity:critical": [orphan]})
    assert "| 🔴 CRITICAL | 1 |" in body
    assert "but not `security`" in body
    assert closed == [], "an issue the scan never opened was closed by the widened fetch"

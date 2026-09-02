"""Tests for resolving which PRs a push covers, and reading their review comments.

This is the I/O half of the PR-time ingest (infra-commons/meta#1187). Two things here
are easy to get subtly wrong and expensive to get wrong in production:

  * **Which number is a pull request.** These repos put ISSUE numbers in commit
    subjects, in the same `(#N)` shape GitHub uses for its squash trailer. Resolving
    an issue number as a PR would read some unrelated issue's comments and file
    findings against the wrong change.
  * **Which credential can read.** The job token is capped by the CALLER's
    `permissions:` block, so whether it can reach pull requests is a per-caller fact
    this code cannot know in advance. The chain must try each in turn and, when all
    are refused, say so loudly rather than reporting an empty result.
"""
import importlib.util
import subprocess
from pathlib import Path

_ACTION_DIR = Path(__file__).resolve().parent
_spec = importlib.util.spec_from_file_location("capture", _ACTION_DIR / "capture.py")
capture = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(capture)


class _Result:
    def __init__(self, stdout="", returncode=0):
        self.stdout = stdout
        self.returncode = returncode
        self.stderr = ""


# ── Commit-subject PR numbers ───────────────────────────────────────────────────
#
# The fixtures below are real subjects from rolliq-com/operations' default branch.

def test_merge_commit_subject_resolves():
    assert capture._pr_numbers_in_subject(
        "Merge pull request #172 from klsjapan-com/promote/staging-to-main-2026-08"
    ) == [172]


def test_end_anchored_squash_trailer_resolves():
    assert capture._pr_numbers_in_subject(
        "fix(ops): make the preflight's degraded Reason say what failed (#359)"
    ) == [359]


def test_mid_subject_issue_reference_is_rejected():
    """`(#311)` mid-subject is an ISSUE in these repos, not a pull request.

    Only the trailing number is GitHub's squash trailer. Accepting the mid-subject
    form would send the ingest to read an unrelated issue's comment thread.
    """
    assert capture._pr_numbers_in_subject(
        "docs(ops311): the customer-tenant dispatch gate, measured (#311) (#328)"
    ) == [328]


def test_cross_repo_issue_reference_is_rejected():
    assert capture._pr_numbers_in_subject(
        "fix(exemption-census): assert which App, not just a valid token (operations#356) (#359)"
    ) == [359]


def test_subject_with_no_pr_reference_yields_nothing():
    assert capture._pr_numbers_in_subject("chore: tidy up the makefile") == []


# ── range_commits ───────────────────────────────────────────────────────────────

_BEFORE = "a" * 40
_AFTER = "b" * 40


def test_range_uses_first_parent_and_the_cap(monkeypatch):
    """A promotion merge is ONE first-parent commit, not the dozens it contains."""
    seen = {}

    def fake_run(cmd, **kwargs):
        if cmd[:2] == ["git", "merge-base"]:
            return _Result(returncode=0)
        seen["cmd"] = cmd
        return _Result(stdout=f"{_AFTER}\n{'c' * 40}\n")

    monkeypatch.setattr(subprocess, "run", fake_run)
    commits = capture.range_commits(_BEFORE, _AFTER)
    assert "--first-parent" in seen["cmd"]
    assert f"--max-count={capture._MAX_RANGE_COMMITS}" in seen["cmd"]
    assert commits == [_AFTER, "c" * 40]


def test_non_ancestor_before_degrades_to_head_commit(monkeypatch, capsys):
    """A force-push makes before..after unwalkable; guess nothing, warn, use HEAD."""
    monkeypatch.setattr(
        subprocess, "run",
        lambda cmd, **kw: _Result(returncode=1) if cmd[:2] == ["git", "merge-base"] else _Result(),
    )
    assert capture.range_commits(_BEFORE, _AFTER) == [_AFTER]
    assert "not an ancestor" in capsys.readouterr().err


def test_branch_creation_before_sha_uses_head_only(monkeypatch):
    assert capture.range_commits("0" * 40, _AFTER) == [_AFTER]


# ── The token chain ─────────────────────────────────────────────────────────────

class _Resp:
    def __init__(self, status_code, payload=None):
        self.status_code = status_code
        self._payload = payload if payload is not None else []

    def json(self):
        return self._payload


def _fake_client(responses):
    """Monkeypatch httpx.Client so each GET pops the next queued response."""
    queue = list(responses)

    class _Client:
        def __init__(self, *a, **kw):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def get(self, url, headers=None, params=None):
            assert queue, "more GETs than the test queued"
            return queue.pop(0)

    return _Client


def test_chain_falls_through_403_to_the_next_token(monkeypatch):
    monkeypatch.setattr(
        capture.httpx, "Client",
        _fake_client([_Resp(403), _Resp(200, [{"number": 7}])]),
    )
    payload, reason, label = capture._get_json(
        "/x", {}, [("job GITHUB_TOKEN", "t1"), ("app token", "t2")]
    )
    assert payload == [{"number": 7}]
    assert reason is None
    # The winning label is the whole point of the chain: which credential can read
    # pull requests is a per-caller fact only a live 200 answers.
    assert label == "app token"


def test_chain_exhausted_names_every_credential_it_tried(monkeypatch):
    """The reason string is what a human reads to find out why nothing was ingested."""
    monkeypatch.setattr(capture.httpx, "Client", _fake_client([_Resp(403), _Resp(404)]))
    payload, reason, label = capture._get_json(
        "/repos/o/r/commits/abc/pulls", {},
        [("job GITHUB_TOKEN", "t1"), ("app token", "t2")],
    )
    assert payload is None
    assert "job GITHUB_TOKEN: HTTP 403" in reason
    assert "app token: HTTP 404" in reason
    assert "/repos/o/r/commits/abc/pulls" in reason
    assert label is None


def test_server_error_stops_the_chain(monkeypatch):
    """A 5xx is not a permissions answer — retrying with another token proves nothing."""
    monkeypatch.setattr(capture.httpx, "Client", _fake_client([_Resp(500)]))
    payload, reason, _ = capture._get_json(
        "/x", {}, [("job GITHUB_TOKEN", "t1"), ("app token", "t2")]
    )
    assert payload is None
    assert "HTTP 500" in reason


# ── resolve_pull_requests ───────────────────────────────────────────────────────

def test_unmerged_pull_requests_are_dropped(monkeypatch):
    monkeypatch.setattr(
        capture.httpx, "Client",
        _fake_client([_Resp(200, [{"number": 4, "merged_at": None},
                                  {"number": 5, "merged_at": "2026-09-01T00:00:00Z"}])]),
    )
    numbers, method = capture.resolve_pull_requests("o/r", [_AFTER], [("job", "t")])
    assert numbers == [5]
    # Credential-bearing: the method names which token actually got the 200.
    assert method.startswith("commits/{sha}/pulls")
    assert "as job" in method


def test_forbidden_api_falls_back_to_commit_subjects(monkeypatch, capsys):
    """The path every caller takes on day one, before any pin bump reaches them."""
    monkeypatch.setattr(
        subprocess, "run",
        lambda cmd, **kw: _Result(stdout="Merge pull request #42 from o/feature\n"),
    )
    monkeypatch.setattr(
        capture.httpx, "Client",
        _fake_client([
            _Resp(403),                                                  # commits/{sha}/pulls
            _Resp(200, {"pull_request": {"merged_at": "2026-09-01"}}),   # issues/42 verification
        ]),
    )
    numbers, method = capture.resolve_pull_requests("o/r", [_AFTER], [("job GITHUB_TOKEN", "t")])
    assert numbers == [42]
    assert method.startswith("commit subjects")
    # The fallback method carries why the API path was refused, so a receipt showing
    # "commit subjects" says which credential was denied and how.
    assert "job GITHUB_TOKEN: HTTP 403" in method
    assert "falling back to commit subjects" in capsys.readouterr().err


def test_fallback_drops_a_number_that_is_an_issue(monkeypatch):
    """The API verification is what makes the subject heuristic safe to use at all."""
    monkeypatch.setattr(
        subprocess, "run",
        lambda cmd, **kw: _Result(stdout="fix: something (#311)\n"),
    )
    monkeypatch.setattr(
        capture.httpx, "Client",
        _fake_client([_Resp(403), _Resp(200, {"title": "an ordinary issue"})]),
    )
    numbers, _ = capture.resolve_pull_requests("o/r", [_AFTER], [("job", "t")])
    assert numbers == []


# ── Comment authorship ──────────────────────────────────────────────────────────

def test_only_the_actions_bots_comments_are_ingested(monkeypatch):
    """A marker is not provenance — anyone who can comment on a PR can paste one."""
    forged = (
        "<!-- adversarial-review-bot -->\n"
        "## Security findings\n\n"
        "### CRITICAL — exploit-ready\n"
        "- [src/app.py:1] Planted by a PR author.\n\n"
        "### Summary\nnope\n"
    )
    monkeypatch.setattr(capture, "range_commits", lambda b, a: [_AFTER])
    monkeypatch.setattr(capture, "resolve_pull_requests", lambda *a: ([9], "test"))
    monkeypatch.setattr(
        capture, "fetch_pr_comments",
        lambda *a: ([{"user": {"login": "a-contributor"}, "body": forged}], None),
    )
    findings, notes = capture.ingest_pr_review_findings("o/r", _BEFORE, _AFTER, [("job", "t")])
    assert findings == []
    assert any("no adversarial-review comment found" in n for n in notes)


# ── Visible degradation ─────────────────────────────────────────────────────────

def test_step_summary_records_a_failed_ingest(monkeypatch, tmp_path):
    summary = tmp_path / "summary.md"
    monkeypatch.setenv("GITHUB_STEP_SUMMARY", str(summary))
    capture._step_summary("### ⚠️ PR-time findings not ingested\n\n- GET /x: HTTP 403")
    assert "HTTP 403" in summary.read_text()


def test_step_summary_is_a_no_op_outside_actions(monkeypatch):
    monkeypatch.delenv("GITHUB_STEP_SUMMARY", raising=False)
    capture._step_summary("nothing should happen")


def test_unresolvable_pr_is_reported_not_silently_empty(monkeypatch):
    monkeypatch.setattr(capture, "range_commits", lambda b, a: [_AFTER])
    monkeypatch.setattr(capture, "resolve_pull_requests", lambda *a: ([], "commit subjects"))
    findings, notes = capture.ingest_pr_review_findings("o/r", _BEFORE, _AFTER, [("job", "t")])
    assert findings == []
    assert any("NOT ingested" in n for n in notes)


def test_findings_are_capped_and_the_cap_is_reported(monkeypatch):
    """A caller on severity_floor: LOW puts both reviewers' LOW bullets in scope."""
    body = (
        "<!-- adversarial-review-bot -->\n## Security findings\n\n"
        "### LOW — best-practice\n"
        + "".join(f"- [src/f{i}.py:{i}] Finding number {i}.\n" for i in range(40))
        + "\n### Summary\nlots\n"
    )
    monkeypatch.setattr(capture, "range_commits", lambda b, a: [_AFTER])
    monkeypatch.setattr(capture, "resolve_pull_requests", lambda *a: ([9], "test"))
    monkeypatch.setattr(
        capture, "fetch_pr_comments",
        lambda *a: ([{"user": {"login": "github-actions[bot]"}, "body": body}], None),
    )
    findings, notes = capture.ingest_pr_review_findings("o/r", _BEFORE, _AFTER, [("job", "t")])
    assert len(findings) == capture._MAX_PR_FINDINGS_PER_RUN
    assert any("capped at" in n for n in notes)


def test_higher_severities_survive_the_cap(monkeypatch):
    """Truncation drops the least important findings, never the most."""
    body = (
        "<!-- adversarial-review-bot -->\n## Security findings\n\n"
        "### LOW — best-practice\n"
        + "".join(f"- [src/f{i}.py:{i}] Low finding {i}.\n" for i in range(40))
        + "\n### CRITICAL — exploit-ready\n"
        "- [src/boom.py:1] Remote code execution.\n\n"
        "### Summary\nlots\n"
    )
    monkeypatch.setattr(capture, "range_commits", lambda b, a: [_AFTER])
    monkeypatch.setattr(capture, "resolve_pull_requests", lambda *a: ([9], "test"))
    monkeypatch.setattr(
        capture, "fetch_pr_comments",
        lambda *a: ([{"user": {"login": "github-actions[bot]"}, "body": body}], None),
    )
    findings, _ = capture.ingest_pr_review_findings("o/r", _BEFORE, _AFTER, [("job", "t")])
    assert findings[0]["severity"] == "CRITICAL"
    assert findings[0]["location"] == "src/boom.py:1"


def test_sources_name_the_reviewer_and_the_pr(monkeypatch):
    body = (
        "<!-- adversarial-review-openai-bot -->\n## Security findings\n\n"
        "### HIGH — serious\n- [src/app.py:4] Something real.\n\n### Summary\nok\n"
    )
    monkeypatch.setattr(capture, "range_commits", lambda b, a: [_AFTER])
    monkeypatch.setattr(capture, "resolve_pull_requests", lambda *a: ([228], "test"))
    monkeypatch.setattr(
        capture, "fetch_pr_comments",
        lambda *a: ([{"user": {"login": "github-actions[bot]"}, "body": body}], None),
    )
    findings, _ = capture.ingest_pr_review_findings("o/r", _BEFORE, _AFTER, [("job", "t")])
    assert findings[0]["sources"] == ["PR-time OpenAI review of #228"]

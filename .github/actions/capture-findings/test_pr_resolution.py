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
    numbers, method, blocked = capture.resolve_pull_requests(
        "o/r", [_AFTER], [("job", "t")]
    )
    assert numbers == [5]
    assert blocked is None
    # Credential-bearing: the method names which token actually got the 200.
    assert method.startswith("commits/{sha}/pulls")
    assert "as job" in method


# infra-commons/meta#1291's real merge subject (5a8c7e5d), verbatim: a paraphrase would
# quietly stop exercising the `(#N)` squash trailer that run 33673760827 actually parsed.
_MERGE_1291 = (
    "legal-pin-drift: schedule the detector that nothing ever ran "
    "(infra-commons/meta#1258) (#1291)\n"
)


def test_forbidden_pulls_api_also_forbids_the_subject_fallback(monkeypatch, capsys):
    """The shape production actually produces — and why it read as "no PR".

    Reconstructs infra-commons/meta run 33673760827 (2026-09-02): the credential refused
    `/commits/{sha}/pulls` is refused `/issues/{N}` too, so the fallback cannot succeed in
    the situation that invokes it. The subject parses fine; that was never the problem.
    Replaces a test that queued 403-then-200 — a combination production cannot produce,
    which is why nothing ever flagged the path as dead.
    """
    monkeypatch.setattr(subprocess, "run", lambda cmd, **kw: _Result(stdout=_MERGE_1291))
    monkeypatch.setattr(
        capture.httpx, "Client",
        _fake_client([
            _Resp(403), _Resp(403),   # commits/{sha}/pulls — both credentials
            _Resp(403), _Resp(403),   # issues/1291 verification — both, same refusal
        ]),
    )
    numbers, method, blocked = capture.resolve_pull_requests(
        "o/r", [_AFTER], [("job GITHUB_TOKEN", "t"), ("app token", "a")],
    )
    assert numbers == []
    assert method.startswith("commit subjects")
    # Not "no PR" — "could not look". Both refusals named, and both credentials.
    assert blocked is not None
    assert "commits/" in blocked and "/issues/1291" in blocked
    assert "job GITHUB_TOKEN: HTTP 403" in blocked and "app token: HTTP 403" in blocked
    assert "falling back to commit subjects" in capsys.readouterr().err


def test_the_subject_fallback_is_retained_for_a_caller_where_it_can_verify(monkeypatch):
    """Pins the retained path — honestly labelled as unobserved.

    This 403-then-200 combination has never been seen in production; the test above is the
    evidence for why. Kept rather than short-circuited because deleting it would rest on an
    inference from one run, on infra that reaches every org the moment the tag advances.
    """
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
    numbers, method, blocked = capture.resolve_pull_requests(
        "o/r", [_AFTER], [("job GITHUB_TOKEN", "t")],
    )
    assert numbers == [42]
    assert method.startswith("commit subjects")
    # The fallback method carries why the API path was refused, so a receipt showing
    # "commit subjects" says which credential was denied and how.
    assert "job GITHUB_TOKEN: HTTP 403" in method
    # It resolved a PR, so nothing is blocked. A working run must not raise an alarm.
    assert blocked is None


def test_fallback_drops_a_number_that_is_an_issue(monkeypatch):
    """The API verification is what makes the subject heuristic safe to use at all.

    Direct on `_pull_requests_from_subjects`: routing through a 403 on the primary just to
    reach it imported the impossible premise the test above retired.
    """
    monkeypatch.setattr(
        subprocess, "run",
        lambda cmd, **kw: _Result(stdout="fix: something (#311)\n"),
    )
    monkeypatch.setattr(
        capture.httpx, "Client",
        _fake_client([_Resp(200, {"title": "an ordinary issue"})]),
    )
    numbers, verify_failure = capture._pull_requests_from_subjects(
        "o/r", [_AFTER], [("job", "t")],
    )
    assert numbers == []
    # Dropped because it is an issue, not because anything was refused.
    assert verify_failure is None


def test_the_subject_fallback_reports_its_own_refusal(monkeypatch):
    """Nothing is discarded at an underscore — that discard is the whole defect.

    It threw the reason away, so a refused verification and a subject naming no PR
    produced the identical empty list.
    """
    monkeypatch.setattr(
        subprocess, "run",
        lambda cmd, **kw: _Result(stdout="fix: something (#42)\n"),
    )
    monkeypatch.setattr(capture.httpx, "Client", _fake_client([_Resp(403)]))
    numbers, verify_failure = capture._pull_requests_from_subjects(
        "o/r", [_AFTER], [("job", "t")],
    )
    assert numbers == []
    assert verify_failure is not None
    assert "/issues/42" in verify_failure and "HTTP 403" in verify_failure


def test_a_push_with_no_pull_request_is_not_reported_as_blocked(monkeypatch):
    """A direct push to main is a quiet non-event, not a permissions alarm.

    The regression guard: loud is worthless if it also fires on every push that
    legitimately has no pull request behind it.
    """
    monkeypatch.setattr(capture.httpx, "Client", _fake_client([_Resp(200, [])]))
    numbers, method, blocked = capture.resolve_pull_requests(
        "o/r", [_AFTER], [("job", "t")],
    )
    assert numbers == []
    assert method.startswith("commits/{sha}/pulls")
    assert blocked is None


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
    monkeypatch.setattr(capture, "resolve_pull_requests", lambda *a: ([9], "test", None))
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
    monkeypatch.setattr(
        capture, "resolve_pull_requests", lambda *a: ([], "commit subjects", None)
    )
    findings, notes = capture.ingest_pr_review_findings("o/r", _BEFORE, _AFTER, [("job", "t")])
    assert findings == []
    assert any("NOT ingested" in n for n in notes)
    # The quiet case: nothing was refused, so nothing claims a permissions defect.
    assert not any("#148" in n for n in notes)


def test_a_blocked_lookup_names_the_permission_and_the_remedy(monkeypatch):
    """A note that says only what did not happen leaves the reader with no next step."""
    monkeypatch.setattr(capture, "range_commits", lambda b, a: [_AFTER])
    monkeypatch.setattr(
        capture, "resolve_pull_requests",
        lambda *a: ([], "commit subjects (…)",
                    "GET /repos/o/r/commits/x/pulls: job GITHUB_TOKEN: HTTP 403; "
                    "app token: HTTP 403"),
    )
    receipt = capture.new_receipt()
    findings, notes = capture.ingest_pr_review_findings(
        "o/r", _BEFORE, _AFTER, [("job", "t")], receipt,
    )
    assert findings == []
    joined = " ".join(notes)
    # Not "no PR" — "could not read", plus the pin that fixes it.
    assert "could be READ" in joined and "NOT ingested" in joined
    assert "pull-requests" in joined and "#148" in joined
    assert "blocked" in receipt["pr_access"]


def test_a_non_permission_refusal_does_not_claim_a_missing_permission(monkeypatch):
    """The do-not-overclaim guard: a 5xx left this push unresolved too and is worth
    reporting, but naming a missing `pull-requests` permission would assert something the
    run never measured.
    """
    monkeypatch.setattr(capture, "range_commits", lambda b, a: [_AFTER])
    monkeypatch.setattr(
        capture, "resolve_pull_requests",
        lambda *a: ([], "commit subjects (…)",
                    "GET /repos/o/r/commits/x/pulls: job GITHUB_TOKEN: HTTP 500"),
    )
    findings, notes = capture.ingest_pr_review_findings("o/r", _BEFORE, _AFTER, [("job", "t")])
    joined = " ".join(notes)
    assert "HTTP 500" in joined and "NOT ingested" in joined
    assert "#148" not in joined and "pull-requests" not in joined


def test_receipt_rows_all_exist_in_a_new_receipt():
    """`_receipt_markdown` indexes `receipt[key]` strictly, and deliberately so.

    An unpaired `_RECEIPT_ROWS` entry raises KeyError inside `_exit_with`, after the
    findings are filed. `.get()` would hide that wiring bug; this makes strictness safe.
    """
    assert {k for k, _ in capture._RECEIPT_ROWS} <= set(capture.new_receipt())


def test_findings_are_capped_and_the_cap_is_reported(monkeypatch):
    """A caller on severity_floor: LOW puts both reviewers' LOW bullets in scope."""
    body = (
        "<!-- adversarial-review-bot -->\n## Security findings\n\n"
        "### LOW — best-practice\n"
        + "".join(f"- [src/f{i}.py:{i}] Finding number {i}.\n" for i in range(40))
        + "\n### Summary\nlots\n"
    )
    monkeypatch.setattr(capture, "range_commits", lambda b, a: [_AFTER])
    monkeypatch.setattr(capture, "resolve_pull_requests", lambda *a: ([9], "test", None))
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
    monkeypatch.setattr(capture, "resolve_pull_requests", lambda *a: ([9], "test", None))
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
    monkeypatch.setattr(capture, "resolve_pull_requests", lambda *a: ([228], "test", None))
    monkeypatch.setattr(
        capture, "fetch_pr_comments",
        lambda *a: ([{"user": {"login": "github-actions[bot]"}, "body": body}], None),
    )
    findings, _ = capture.ingest_pr_review_findings("o/r", _BEFORE, _AFTER, [("job", "t")])
    assert findings[0]["sources"] == ["PR-time OpenAI review of #228"]

"""Tests that no single failure in main() can lose findings, or hide one.

Two independent sources now feed one filing loop, and each can fail on its own. The
properties asserted here are the ones that make that safe:

  * **A dead post-merge model pass must not swallow the PR-time findings.** They are
    already computed and cost nothing to file. `review_diff` raises on an empty or
    truncated completion — correctly — but raising out of `main()` meant nothing at
    all was filed. Measured live on 2026-09-01: a 4096-token budget under a
    thinking-capable model failed exactly this way on two rolliq-com/operations PRs.
  * **…and the run must still go red.** A diff that was never reviewed must never
    read as clean. This is the half that is easy to lose while fixing the half above.
  * **An ingest fault must not sink a run that files findings today.** This is new
    code arriving at every caller at once on a moving tag.
"""
import importlib.util
from pathlib import Path

import pytest

_ACTION_DIR = Path(__file__).resolve().parent
_spec = importlib.util.spec_from_file_location("capture", _ACTION_DIR / "capture.py")
capture = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(capture)

_BEFORE = "a" * 40
_AFTER = "b" * 40


@pytest.fixture
def harness(monkeypatch, tmp_path):
    """Stub every boundary main() touches; record the issues it tries to create."""
    created: list[dict] = []

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
    monkeypatch.setattr(capture, "upsert_digest", lambda *a: (0, 0))
    monkeypatch.setattr(capture.time, "sleep", lambda s: None)

    def fake_create(token, repo, title, body, labels):
        created.append({"title": title, "body": body, "labels": labels})
        return {"node_id": f"node{len(created)}"}

    monkeypatch.setattr(capture, "create_issue", fake_create)
    return created, tmp_path / "summary.md"


def _pr_high(location="src/app.py:12", title="Token exposed"):
    return {
        "severity": "HIGH", "location": location, "title": title,
        "description": title, "category": "unknown",
        "sources": ["PR-time OpenAI review of #7"],
    }


def test_pr_findings_are_filed_when_the_model_pass_dies(monkeypatch, harness):
    """The headline property: a max_tokens failure no longer costs the whole run."""
    created, _ = harness
    monkeypatch.setattr(capture, "ingest_pr_review_findings", lambda *a: ([_pr_high()], []))
    monkeypatch.setattr(capture, "review_diff", lambda *a: (_ for _ in ()).throw(
        RuntimeError("claude-sonnet-5 hit the token budget (stop_reason='max_tokens')")
    ))

    with pytest.raises(SystemExit) as exc:
        capture.main()

    assert [c["title"] for c in created] == [
        "[Security][adversarial-ai][HIGH] src/app.py:12 — Token exposed"
    ]
    assert exc.value.code == 1, "an unreviewed diff must never read as clean"


def test_the_dead_model_pass_is_reported_in_the_job_summary(monkeypatch, harness):
    _, summary = harness
    monkeypatch.setattr(capture, "ingest_pr_review_findings", lambda *a: ([_pr_high()], []))
    monkeypatch.setattr(capture, "review_diff", lambda *a: (_ for _ in ()).throw(
        RuntimeError("returned an empty completion")
    ))
    with pytest.raises(SystemExit):
        capture.main()
    assert "Post-merge review pass did not" in summary.read_text()


def test_model_failure_with_no_findings_at_all_still_exits_nonzero(monkeypatch, harness):
    """"Nothing to file" is not "nothing to find" when the review never ran."""
    created, _ = harness
    monkeypatch.setattr(capture, "ingest_pr_review_findings", lambda *a: ([], []))
    monkeypatch.setattr(capture, "review_diff", lambda *a: (_ for _ in ()).throw(
        RuntimeError("empty completion")
    ))
    with pytest.raises(SystemExit) as exc:
        capture.main()
    assert created == []
    assert exc.value.code == 1


def test_an_ingest_fault_does_not_sink_the_run(monkeypatch, harness):
    """New code on a moving tag reaches every caller at once; it must be inert on failure."""
    created, _ = harness
    monkeypatch.setattr(capture, "ingest_pr_review_findings", lambda *a: (_ for _ in ()).throw(
        ValueError("something in the ingest broke")
    ))
    monkeypatch.setattr(capture, "review_diff", lambda *a: "{}")
    monkeypatch.setattr(capture, "parse_findings", lambda raw: ([
        {"severity": "HIGH", "location": "src/x.py:1", "title": "Real",
         "description": "Real", "category": "auth"},
    ], 0))

    capture.main()  # must not raise

    assert [c["title"] for c in created] == [
        "[Security][adversarial-ai][HIGH] src/x.py:1 — Real"
    ]


def test_ingest_notes_reach_stderr_and_the_job_summary(monkeypatch, harness, capsys):
    _, summary = harness
    monkeypatch.setattr(
        capture, "ingest_pr_review_findings",
        lambda *a: ([], ["could not read comments on #7 (GET ...: HTTP 403)"]),
    )
    monkeypatch.setattr(capture, "review_diff", lambda *a: "{}")
    monkeypatch.setattr(capture, "parse_findings", lambda raw: ([], 0))

    capture.main()

    assert "HTTP 403" in capsys.readouterr().err
    assert "HTTP 403" in summary.read_text()


def test_ingest_can_be_switched_off(monkeypatch, harness):
    monkeypatch.setenv("INGEST_PR_REVIEWS", "false")
    called = []
    monkeypatch.setattr(
        capture, "ingest_pr_review_findings",
        lambda *a: called.append(1) or ([], []),
    )
    monkeypatch.setattr(capture, "review_diff", lambda *a: "{}")
    monkeypatch.setattr(capture, "parse_findings", lambda raw: ([], 0))
    capture.main()
    assert called == []


def test_ingested_findings_carry_the_pr_review_label(monkeypatch, harness):
    created, _ = harness
    monkeypatch.setattr(capture, "ingest_pr_review_findings", lambda *a: ([_pr_high()], []))
    monkeypatch.setattr(capture, "review_diff", lambda *a: "{}")
    monkeypatch.setattr(capture, "parse_findings", lambda raw: ([], 0))
    capture.main()
    labels = created[0]["labels"]
    assert "source:pr-review" in labels
    assert "source:adversarial-ai" in labels, "other tooling keys on this label"


def test_post_merge_only_findings_do_not_get_the_pr_review_label(monkeypatch, harness):
    created, _ = harness
    monkeypatch.setattr(capture, "ingest_pr_review_findings", lambda *a: ([], []))
    monkeypatch.setattr(capture, "review_diff", lambda *a: "{}")
    monkeypatch.setattr(capture, "parse_findings", lambda raw: ([
        {"severity": "HIGH", "location": "src/x.py:1", "title": "Real",
         "description": "Real", "category": "auth"},
    ], 0))
    capture.main()
    assert "source:pr-review" not in created[0]["labels"]


def test_two_findings_at_one_location_file_a_single_issue(monkeypatch, harness):
    """The in-run dedupe bug: `existing` was built once and never updated.

    Both sources reaching the same location in one run is exactly what the second door
    makes common, so an unfixed dedupe set would file the same issue twice.
    """
    created, _ = harness
    monkeypatch.setattr(capture, "ingest_pr_review_findings", lambda *a: ([], []))
    monkeypatch.setattr(capture, "review_diff", lambda *a: "{}")
    # Same severity+location, different titles — so merge_candidates keeps one, and
    # the in-loop dedupe sets are what stop a second issue if it ever does not.
    monkeypatch.setattr(capture, "parse_findings", lambda raw: ([
        {"severity": "HIGH", "location": "src/x.py:1", "title": "First",
         "description": "First", "category": "auth"},
        {"severity": "HIGH", "location": "src/x.py:1", "title": "Second",
         "description": "Second", "category": "auth"},
    ], 0))
    capture.main()
    assert len(created) == 1


def test_in_loop_dedupe_stops_a_duplicate_the_merge_did_not_catch(monkeypatch, harness):
    """Directly exercises the dedupe-set fix, bypassing merge_candidates."""
    created, _ = harness
    same = {"severity": "HIGH", "location": "src/x.py:1", "title": "Dup",
            "description": "Dup", "category": "auth"}
    monkeypatch.setattr(capture, "ingest_pr_review_findings", lambda *a: ([], []))
    monkeypatch.setattr(capture, "review_diff", lambda *a: "{}")
    monkeypatch.setattr(capture, "parse_findings", lambda raw: ([dict(same), dict(same)], 0))
    monkeypatch.setattr(capture, "merge_candidates", lambda pr, model: list(model))
    capture.main()
    assert len(created) == 1


def test_a_critical_still_exits_nonzero(monkeypatch, harness):
    created, _ = harness
    monkeypatch.setattr(capture, "ingest_pr_review_findings", lambda *a: ([], []))
    monkeypatch.setattr(capture, "review_diff", lambda *a: "{}")
    monkeypatch.setattr(capture, "parse_findings", lambda raw: ([
        {"severity": "CRITICAL", "location": "src/x.py:1", "title": "Boom",
         "description": "Boom", "category": "rce"},
    ], 0))
    with pytest.raises(SystemExit) as exc:
        capture.main()
    assert exc.value.code == 1
    assert len(created) == 1


def test_a_clean_run_exits_zero(monkeypatch, harness):
    monkeypatch.setattr(capture, "ingest_pr_review_findings", lambda *a: ([], []))
    monkeypatch.setattr(capture, "review_diff", lambda *a: "{}")
    monkeypatch.setattr(capture, "parse_findings", lambda raw: ([], 0))
    capture.main()  # must not raise


# ── The receipt ─────────────────────────────────────────────────────────────────
#
# Before 2026-09-02 a run that reviewed and found nothing, a run whose parse
# silently failed, and a run that returned before reviewing were indistinguishable:
# all three a green check, an empty summary, no issue. A zero that cannot be told
# apart from a skip is what let that run unnoticed for months.

def test_a_zero_finding_run_says_it_ran_and_found_nothing(monkeypatch, harness):
    _, summary = harness
    monkeypatch.setattr(capture, "ingest_pr_review_findings", lambda *a: ([], []))
    monkeypatch.setattr(capture, "review_diff", lambda *a: "{}")
    monkeypatch.setattr(capture, "parse_findings", lambda raw: ([], 0))

    capture.main()

    text = summary.read_text()
    assert "Capture receipt" in text
    assert "ran, output parsed" in text
    assert "| Findings parsed | 0 |" in text


def test_a_branch_creation_run_says_it_was_skipped(monkeypatch, harness):
    """"Never ran" must not render as "ran and found nothing"."""
    _, summary = harness
    monkeypatch.setenv("BEFORE_SHA", "0" * 40)

    capture.main()

    text = summary.read_text()
    assert "skipped: branch creation" in text
    assert "ran, output parsed" not in text


def test_an_empty_diff_run_says_it_was_skipped(monkeypatch, harness):
    _, summary = harness
    monkeypatch.setattr(capture, "get_diff", lambda b, a: "   \n")

    capture.main()

    assert "skipped: empty diff" in summary.read_text()


def test_an_unparseable_review_fails_closed_and_says_so(monkeypatch, harness):
    """The headline behaviour change: a review the parser could not read goes red."""
    created, summary = harness
    monkeypatch.setattr(capture, "ingest_pr_review_findings", lambda *a: ([], []))
    monkeypatch.setattr(
        capture, "review_diff",
        lambda *a: "I reviewed the diff and found nothing of concern.",
    )

    with pytest.raises(SystemExit) as exc:
        capture.main()

    assert exc.value.code == 1, "an unreadable review must never read as clean"
    assert created == []
    text = summary.read_text()
    assert "could not be parsed" in text


def test_the_receipt_carries_the_counts(monkeypatch, harness):
    _, summary = harness
    monkeypatch.setattr(capture, "ingest_pr_review_findings", lambda *a: ([_pr_high()], []))
    monkeypatch.setattr(capture, "review_diff", lambda *a: "{}")
    monkeypatch.setattr(capture, "parse_findings", lambda raw: ([
        {"severity": "HIGH", "location": "src/x.py:1", "title": "Real",
         "description": "Real", "category": "auth"},
    ], 2))

    capture.main()

    text = summary.read_text()
    assert "| Findings ingested | 1 |" in text
    assert "| Issues filed | 2 |" in text
    # The drop count is the instrumentation that makes `Parsed 0` interpretable.
    assert "| Dropped (unusable severity) | 2 |" in text


def test_the_receipt_names_the_credential_that_resolved_the_prs(monkeypatch, harness):
    """The reusable's comment claimed this for a while before the code did it."""
    _, summary = harness

    def _ingest(repo, before, after, tokens, receipt=None):
        receipt["pr_method"] = "commits/{sha}/pulls as app token"
        return [], []

    monkeypatch.setattr(capture, "ingest_pr_review_findings", _ingest)
    monkeypatch.setattr(capture, "review_diff", lambda *a: "{}")
    monkeypatch.setattr(capture, "parse_findings", lambda raw: ([], 0))

    capture.main()

    assert "as app token" in summary.read_text()


# ── Board-add wiring: which findings reach it, and how often ────────────────────
#
# `test_board_intake.py` pins `BOARD_ADD_SEVERITIES` and tests `add_to_board` in isolation.
# Neither shows that main() actually ROUTES a CRITICAL there, nor how many times. Both are
# ordering properties of the filing loop, which is what this file is for.


@pytest.fixture
def board_calls(monkeypatch):
    """Record every `add_to_board` call main() makes, with a token provisioned."""
    calls: list[tuple[str, str]] = []
    monkeypatch.setenv("BOARD_APP_TOKEN", "app-token")
    monkeypatch.setattr(
        capture, "add_to_board",
        lambda token, owner, node_id: (calls.append((owner, node_id)), (True, "added"))[1],
    )
    return calls


def _critical(location="src/db.py:9", title="SQL injection"):
    return {"severity": "CRITICAL", "location": location, "title": title,
            "description": title, "category": "injection"}


def test_a_new_critical_reaches_the_board(monkeypatch, harness, board_calls):
    """The point of widening BOARD_ADD_SEVERITIES — a set literal nothing routes to is inert."""
    created, _ = harness
    monkeypatch.setattr(capture, "ingest_pr_review_findings", lambda *a: ([], []))
    monkeypatch.setattr(capture, "review_diff", lambda *a: "{}")
    monkeypatch.setattr(capture, "parse_findings", lambda raw: ([_critical()], 0))

    with pytest.raises(SystemExit) as exc:
        capture.main()

    assert exc.value.code == 1, "a new CRITICAL must still go red"
    assert len(created) == 1
    assert board_calls == [("o", "node1")]


def test_an_already_tracked_critical_is_never_re_added(monkeypatch, harness, board_calls):
    """The idempotency property, and the reason no 'is it already on the board?' query is needed.

    A CRITICAL raised at PR time and re-encountered by a later post-merge run must not produce a
    second card. It cannot: the `Already tracked` branch `continue`s before anything is filed, and
    the board-add lives inside the just-created-issue branch below it. Ordering IS the guard here,
    so it is the thing worth pinning — a refactor that hoisted the board-add out of that branch
    would look harmless and would duplicate a card on every single run thereafter.
    """
    created, _ = harness
    finding = _critical()
    title = capture.issue_title(finding)
    monkeypatch.setattr(capture, "open_security_issues", lambda t, r: {title: {"number": 1}})
    monkeypatch.setattr(capture, "ingest_pr_review_findings", lambda *a: ([], []))
    monkeypatch.setattr(capture, "review_diff", lambda *a: "{}")
    monkeypatch.setattr(capture, "parse_findings", lambda raw: ([finding], 0))

    with pytest.raises(SystemExit) as exc:
        capture.main()

    assert exc.value.code == 1, "a known-open CRITICAL still goes red"
    assert created == [], "nothing was filed, so there is nothing to board"
    assert board_calls == []


def test_two_findings_at_one_location_board_a_single_card(monkeypatch, harness, board_calls):
    """The same-run half of the same property: the dedupe sets are fed as the loop goes."""
    created, _ = harness
    monkeypatch.setattr(capture, "ingest_pr_review_findings", lambda *a: ([], []))
    monkeypatch.setattr(capture, "review_diff", lambda *a: "{}")
    monkeypatch.setattr(capture, "parse_findings", lambda raw: (
        [_critical(), _critical(title="SQL injection (again)")], 0
    ))

    with pytest.raises(SystemExit):
        capture.main()

    assert len(created) == 1
    assert len(board_calls) == 1

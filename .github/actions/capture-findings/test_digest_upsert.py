"""upsert_digest() after infra-commons/security#92.

1. A digest closed not-planned/wont-fix must never drop findings silently: a fresh digest is
   started, loudly, as a digest closed *completed* already was.
2. The digest carries `severity:*` labels for the severities it holds.
3. An append posts a comment, because a body edit notifies nobody.
4. Dedup keys on (severity, location), so a more serious finding at a listed location is kept.

Mocks at capture.py's own function seams, same style as test_board_intake.py.
"""
from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest

_ACTION_DIR = Path(__file__).resolve().parent
_spec = importlib.util.spec_from_file_location("capture", _ACTION_DIR / "capture.py")
capture = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(capture)


def _f(sev, loc):
    return {"severity": sev, "location": loc, "title": "t", "description": "d", "category": "c"}


@pytest.fixture
def calls(monkeypatch, tmp_path):
    rec = {"create": [], "update": [], "labels": [], "comment": []}
    monkeypatch.setenv("GITHUB_STEP_SUMMARY", str(tmp_path / "summary.md"))
    monkeypatch.setattr(capture, "create_issue",
                        lambda t, r, title, body, labels: rec["create"].append((body, labels)) or {})
    monkeypatch.setattr(capture, "update_issue_body", lambda t, r, n, body: rec["update"].append(body))
    monkeypatch.setattr(capture, "add_labels", lambda t, r, n, labels: rec["labels"].append(labels))
    monkeypatch.setattr(capture, "comment_on_issue", lambda t, r, n, body: rec["comment"].append(body))
    monkeypatch.setattr(capture, "board_issue", lambda *a, **k: (True, "ok"))
    return rec


def test_a_closed_not_planned_digest_starts_a_fresh_one_loudly(calls, capsys, tmp_path):
    result = capture.upsert_digest("t", "o/r", {}, {capture.DIGEST_TITLE}, [_f("MEDIUM", "a.py:1")], "run")
    assert result == (1, 1)
    (body, _), = calls["create"]
    assert "`a.py:1`" in body and "closed as not planned" in body
    assert "::warning::previous MEDIUM/LOW digest was closed" in capsys.readouterr().out
    assert "starting a fresh digest" in (tmp_path / "summary.md").read_text()


def test_a_closed_digest_with_nothing_new_files_nothing(calls):
    assert capture.upsert_digest("t", "o/r", {}, {capture.DIGEST_TITLE}, [], "run") == (0, 0)
    assert calls["create"] == []


def test_an_ordinary_new_digest_carries_no_restart_note(calls, capsys):
    capture.upsert_digest("t", "o/r", {}, set(), [_f("LOW", "a.py:1")], "run")
    (body, _), = calls["create"]
    assert "closed as not planned" not in body
    assert "::warning::" not in capsys.readouterr().out


def test_a_created_digest_is_labelled_with_the_severities_it_holds(calls):
    capture.upsert_digest("t", "o/r", {}, set(), [_f("MEDIUM", "a.py:1"), _f("LOW", "b.py:2")], "run")
    (_, labels), = calls["create"]
    assert labels == ["security", "source:adversarial-ai", "severity:low", "severity:medium"]


def test_an_append_labels_the_added_severities_and_comments_once(calls):
    existing = {capture.DIGEST_TITLE: {"number": 5, "body": ""}}
    assert capture.upsert_digest("t", "o/r", existing, set(), [_f("LOW", "a.py:1")], "run") == (0, 1)
    assert calls["labels"] == [["severity:low"]]
    (comment,) = calls["comment"]
    assert "Added 1 finding(s)" in comment and "`a.py:1`" in comment


def test_no_comment_when_nothing_was_added(calls):
    body = capture.build_digest_body([capture.digest_row(_f("LOW", "a.py:1"))], "run")
    existing = {capture.DIGEST_TITLE: {"number": 5, "body": body}}
    assert capture.upsert_digest("t", "o/r", existing, set(), [_f("LOW", "a.py:1")], "run") == (0, 0)
    assert calls["update"] == [] and calls["comment"] == [] and calls["labels"] == []


def test_a_failed_notify_is_a_warning_not_a_lost_capture(calls, monkeypatch, capsys):
    def boom(*a):
        raise RuntimeError("422")
    monkeypatch.setattr(capture, "add_labels", boom)
    existing = {capture.DIGEST_TITLE: {"number": 5, "body": ""}}
    assert capture.upsert_digest("t", "o/r", existing, set(), [_f("LOW", "a.py:1")], "run") == (0, 1)
    assert len(calls["update"]) == 1
    assert "::warning::digest #5 updated" in capsys.readouterr().out


def test_a_medium_at_a_location_listed_as_low_is_kept(calls):
    body = capture.build_digest_body([capture.digest_row(_f("LOW", "a.py:1"))], "run")
    existing = {capture.DIGEST_TITLE: {"number": 5, "body": body}}
    assert capture.upsert_digest(
        "t", "o/r", existing, set(), [_f("MEDIUM", "a.py:1"), _f("LOW", "a.py:1")], "run"
    ) == (0, 1)
    (new_body,) = calls["update"]
    assert capture.existing_digest_keys(new_body) == {("LOW", "a.py:1"), ("MEDIUM", "a.py:1")}

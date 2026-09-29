"""Tests for the board-add path added in infra-commons/meta#661.

`add_to_board` is the single function that decides whether a newly-filed CRITICAL or HIGH finding
reaches the org's GitHub Project Inbox. Every scenario here asserts the same shape: on any
failure, it returns
`(False, <reason>)` — never raises, never touches anything the rest of `capture.py` depends on for
its exit code. That's the property the whole feature leans on: it must be safe to ship into every
org today, before a single one of them has provisioned the App-token secret.

Mocks at the `_board_graphql` seam (capture.py's own GraphQL request/response boundary) rather than
touching `httpx` directly — same style as this dir's sibling tests monkeypatching a module-level
function instead of the HTTP layer underneath it.
"""
import importlib.util
from pathlib import Path

_ACTION_DIR = Path(__file__).resolve().parent
_spec = importlib.util.spec_from_file_location("capture", _ACTION_DIR / "capture.py")
capture = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(capture)

# The same module object capture.py imported (it put this directory on sys.path) — so a patch on
# `board_intake._board_graphql` is the patch capture.py's board-adds see.
import board_intake  # noqa: E402


_FIELDS_OK = {
    "repositoryOwner": {
        "projectV2": {
            "id": "PVT_project",
            "closed": False,
            "fields": {
                "nodes": [
                    {
                        "__typename": "ProjectV2SingleSelectField",
                        "id": "FIELD_status",
                        "name": "Status",
                        "options": [
                            {"id": "OPT_inbox", "name": "Inbox"},
                            {"id": "OPT_doing", "name": "Doing"},
                        ],
                    }
                ]
            },
        }
    }
}


def _queue(monkeypatch, *responses):
    """Monkeypatch `_board_graphql` to return each of `responses` in order, one per call."""
    calls = list(responses)

    def fake(token, query, variables):
        assert calls, "add_to_board made more GraphQL calls than the test expected"
        return calls.pop(0)

    monkeypatch.setattr(board_intake, "_board_graphql", fake)


# ── Owner topology ───────────────────────────────────────────────────────────────

def test_owner_project_number_covers_the_fleet():
    # The five orgs this mechanism is meant for — see projects_topology.py in sharedinfra.
    assert set(board_intake.OWNER_PROJECT_NUMBER) == {
        "infra-commons", "rolliq-com", "cashbucket-com", "klsjapan-com", "chargingblindly-com",
    }


def test_unknown_owner_degrades_without_any_graphql_call(monkeypatch):
    def fail(*a, **k):
        raise AssertionError("should not reach GraphQL for an owner outside the topology table")
    monkeypatch.setattr(board_intake, "_board_graphql", fail)

    ok, msg = board_intake.add_to_board("tok", "some-other-org", "I_abc")
    assert ok is False
    assert "not in the board topology" in msg


# ── Field-map read failures ──────────────────────────────────────────────────────

def test_field_map_read_failure_degrades(monkeypatch):
    _queue(monkeypatch, None)  # _board_graphql itself returned None (network/auth/GraphQL error)
    ok, msg = board_intake.add_to_board("tok", "infra-commons", "I_abc")
    assert ok is False
    assert "could not read project" in msg


def test_closed_project_degrades(monkeypatch):
    closed = {"repositoryOwner": {"projectV2": {"id": "PVT_x", "closed": True, "fields": {"nodes": []}}}}
    _queue(monkeypatch, closed)
    ok, msg = board_intake.add_to_board("tok", "infra-commons", "I_abc")
    assert ok is False
    assert "closed" in msg


def test_missing_status_field_degrades(monkeypatch):
    no_status = {
        "repositoryOwner": {"projectV2": {"id": "PVT_x", "closed": False, "fields": {"nodes": []}}}
    }
    _queue(monkeypatch, no_status)
    ok, msg = board_intake.add_to_board("tok", "infra-commons", "I_abc")
    assert ok is False
    assert "Status field" in msg


def test_missing_inbox_option_degrades(monkeypatch):
    no_inbox = {
        "repositoryOwner": {
            "projectV2": {
                "id": "PVT_x", "closed": False,
                "fields": {"nodes": [{
                    "__typename": "ProjectV2SingleSelectField", "id": "FIELD_status",
                    "name": "Status", "options": [{"id": "OPT_doing", "name": "Doing"}],
                }]},
            }
        }
    }
    _queue(monkeypatch, no_inbox)
    ok, msg = board_intake.add_to_board("tok", "infra-commons", "I_abc")
    assert ok is False
    assert "Inbox option" in msg


# ── Mutation failures ─────────────────────────────────────────────────────────────

def test_add_item_failure_degrades(monkeypatch):
    _queue(monkeypatch, _FIELDS_OK, None)  # fields OK, addProjectV2ItemById call failed
    ok, msg = board_intake.add_to_board("tok", "infra-commons", "I_abc")
    assert ok is False
    assert "addProjectV2ItemById" in msg


def test_set_status_failure_still_reports_added_but_not_ok(monkeypatch):
    add_ok = {"addProjectV2ItemById": {"item": {"id": "PVTI_new"}}}
    _queue(monkeypatch, _FIELDS_OK, add_ok, None)  # set-Status call failed
    ok, msg = board_intake.add_to_board("tok", "infra-commons", "I_abc")
    assert ok is False
    assert "Status" in msg


# ── Success ─────────────────────────────────────────────────────────────────────

def test_success_path(monkeypatch):
    add_ok = {"addProjectV2ItemById": {"item": {"id": "PVTI_new"}}}
    set_ok = {"updateProjectV2ItemFieldValue": {"projectV2Item": {"id": "PVTI_new"}}}
    _queue(monkeypatch, _FIELDS_OK, add_ok, set_ok)
    ok, msg = board_intake.add_to_board("tok", "infra-commons", "I_abc")
    assert ok is True
    assert "Inbox" in msg


def test_success_path_never_raises_even_with_extra_unused_fields(monkeypatch):
    # A project with unrelated fields (e.g. Priority) alongside Status must not confuse the lookup.
    fields = {
        "repositoryOwner": {
            "projectV2": {
                "id": "PVT_x", "closed": False,
                "fields": {"nodes": [
                    {"__typename": "ProjectV2FieldCommon", "id": "FIELD_priority", "name": "Priority"},
                    _FIELDS_OK["repositoryOwner"]["projectV2"]["fields"]["nodes"][0],
                ]},
            }
        }
    }
    add_ok = {"addProjectV2ItemById": {"item": {"id": "PVTI_new"}}}
    set_ok = {"updateProjectV2ItemFieldValue": {"projectV2Item": {"id": "PVTI_new"}}}
    _queue(monkeypatch, fields, add_ok, set_ok)
    ok, _msg = board_intake.add_to_board("tok", "rolliq-com", "I_abc")
    assert ok is True


# ── Wiring: create_issue's return value, and main()'s severity gate ──────────────

def test_create_issue_returns_the_response_json(monkeypatch):
    class _Resp:
        def raise_for_status(self):
            pass

        def json(self):
            return {"number": 42, "node_id": "I_xyz"}

    class _Client:
        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def post(self, *a, **k):
            return _Resp()

    monkeypatch.setattr(capture.httpx, "Client", lambda **k: _Client())
    result = capture.create_issue("tok", "infra-commons/meta", "title", "body", ["security"])
    assert result == {"number": 42, "node_id": "I_xyz"}


def test_board_add_severities_is_critical_and_high():
    # Still a deliberate, named scope decision — pinned so a future change to this set stays a
    # decision rather than an accident. What changed: infra-commons/meta#661 originally scoped
    # this to HIGH only, on the reasoning that a CRITICAL is already blocked by the PR-time gate.
    # The operator overrode that. This module runs POST-merge, so a CRITICAL it files as a NEW
    # issue was never blocked by anything; and even one that WAS blocked outlives its PR, staying
    # open and off-board once the gate stops applying. MEDIUM/LOW still roll into the digest, and
    # the digest ISSUE is boarded when it is created (infra-commons/meta#1656, tests below).
    assert capture.BOARD_ADD_SEVERITIES == {"CRITICAL", "HIGH"}
    assert capture.BOARD_ADD_SEVERITIES == capture.individual_severities(""), (
        "every severity that gets an individual issue must be boarded"
    )


# ── Absent is not unreadable (infra-commons/meta#1656) ────────────────────────────

def test_no_token_is_its_own_message_and_makes_no_call(monkeypatch):
    def fail(*a, **k):
        raise AssertionError("no token means no GraphQL call")
    monkeypatch.setattr(board_intake, "_board_graphql", fail)

    ok, msg = board_intake.board_issue("", "infra-commons", node_id="I_abc")
    assert ok is False
    assert msg == board_intake.NO_TOKEN_MESSAGE
    assert "OFF the board" in msg


def test_unreadable_board_is_not_reported_as_absent(monkeypatch):
    _queue(monkeypatch, None)
    ok, msg = board_intake.board_issue("tok", "infra-commons", node_id="I_abc")
    assert ok is False
    assert msg != board_intake.NO_TOKEN_MESSAGE
    assert "could not read project" in msg


# ── URL resolution: `gh issue create` sites only get a URL back ────────────────────

def test_board_issue_resolves_a_url_then_adds(monkeypatch):
    add_ok = {"addProjectV2ItemById": {"item": {"id": "PVTI_new"}}}
    set_ok = {"updateProjectV2ItemFieldValue": {"projectV2Item": {"id": "PVTI_new"}}}
    resolved = {"resource": {"__typename": "Issue", "id": "I_url"}}
    _queue(monkeypatch, resolved, _FIELDS_OK, add_ok, set_ok)
    ok, msg = board_intake.board_issue("tok", "infra-commons", url="https://github.com/o/r/issues/1")
    assert ok is True, msg


def test_a_url_that_is_not_an_issue_degrades(monkeypatch):
    _queue(monkeypatch, {"resource": {"__typename": "PullRequest"}})
    ok, msg = board_intake.board_issue("tok", "infra-commons", url="https://github.com/o/r/pull/1")
    assert ok is False
    assert "could not resolve" in msg


def test_board_issue_never_raises(monkeypatch):
    def boom(*a, **k):
        raise RuntimeError("bug in the seam")
    monkeypatch.setattr(board_intake, "_board_graphql", boom)
    ok, msg = board_intake.board_issue("tok", "infra-commons", node_id="I_abc")
    assert ok is False
    assert "unexpected error" in msg


# ── CLI: always exits 0, one ::warning:: per failure ──────────────────────────────

def test_cli_warns_loudly_and_exits_zero_on_failure(monkeypatch, capsys):
    monkeypatch.delenv("BOARD_APP_TOKEN", raising=False)
    rc = board_intake.main(["--owner", "infra-commons", "https://github.com/o/r/issues/1"])
    assert rc == 0
    out = capsys.readouterr().out
    assert "::warning::board-add failed for https://github.com/o/r/issues/1" in out


# ── The digest issue is boarded, and filing survives any board failure ─────────────

def _digest_finding():
    return {"severity": "MEDIUM", "location": "src/a.py:1", "title": "t", "description": "d",
            "category": "c"}


def _record_creates(monkeypatch):
    created = []

    def fake_create(token, repo, title, body, labels):
        created.append(title)
        return {"node_id": "I_digest"}
    monkeypatch.setattr(capture, "create_issue", fake_create)
    return created


def test_a_newly_created_digest_is_boarded(monkeypatch):
    created = _record_creates(monkeypatch)
    boarded = []

    def fake_board(token, owner, node_id="", url=""):
        boarded.append((owner, node_id))
        return True, "ok"
    monkeypatch.setattr(capture, "board_issue", fake_board)
    issues, rows = capture.upsert_digest("t", "o/r", {}, set(), [_digest_finding()], "run",
                                         board_token="app", board_owner="o")
    assert (issues, rows) == (1, 1)
    assert created == [capture.DIGEST_TITLE]
    assert boarded == [("o", "I_digest")]


def test_an_updated_digest_is_not_re_boarded(monkeypatch):
    def fail(*a, **k):
        raise AssertionError("appending a row to an open digest files nothing new to board")
    monkeypatch.setattr(capture, "update_issue_body", lambda *a: None)
    monkeypatch.setattr(capture, "board_issue", fail)
    existing = {capture.DIGEST_TITLE: {"number": 5, "body": ""}}
    assert capture.upsert_digest("t", "o/r", existing, set(), [_digest_finding()], "run",
                                 board_token="app", board_owner="o") == (0, 1)


def test_digest_is_filed_even_when_the_board_is_down(monkeypatch, capsys):
    created = _record_creates(monkeypatch)
    _queue(monkeypatch, None)  # board unreadable
    issues, _ = capture.upsert_digest("t", "o/r", {}, set(), [_digest_finding()], "run",
                                      board_token="app", board_owner="infra-commons")
    assert issues == 1 and created == [capture.DIGEST_TITLE]
    assert "::warning::board-add failed for the digest issue" in capsys.readouterr().out


def test_digest_is_filed_and_warns_without_a_token(monkeypatch, capsys):
    created = _record_creates(monkeypatch)
    issues, _ = capture.upsert_digest("t", "o/r", {}, set(), [_digest_finding()], "run")
    assert issues == 1 and created == [capture.DIGEST_TITLE]
    assert "OFF the board" in capsys.readouterr().out

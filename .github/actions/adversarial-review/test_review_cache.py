"""Tests for the identical-diff review cache.

A cache in front of a security gate has one catastrophic direction and one
merely annoying one:

  a wrong HIT   serves a verdict for inputs that are not the ones under review —
                a green gate on a diff nothing looked at, which is the exact
                failure this whole workflow exists to prevent
  a wrong MISS  costs one model call, i.e. the status quo

So every test below is written to catch a wrong hit. The key deliberately covers
the prompt and the model as well as the diff, because the verdict is a function
of all three: a suppression edit lands in the system prompt, and serving a
verdict computed under rules that no longer apply is worse than no cache at all.
"""
import importlib.util
from pathlib import Path

import pytest

_MODULE_PATH = Path(__file__).parent / "adversarial-review.py"
_spec = importlib.util.spec_from_file_location("adversarial_review_cache", _MODULE_PATH)
adv = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(adv)

MARKER = "<!-- adversarial-review-bot -->"
OTHER_MARKER = "<!-- adversarial-review-openai-bot -->"
SECRET = "sk-test-review-api-key"
ARGS = ("anthropic", "claude-sonnet-4-6", "system prompt", "diff-id-1", "repo context", "reviewer-src-1")


def key(*args):
    return adv.review_cache_key(*args)


def comment(marker, k, critical=False, extra="", login=None):
    body = f"{marker}\n{adv.cache_marker(k, critical, SECRET)}\n## Review\n{extra}"
    return bot(body, login=login)


def bot(body, login=None):
    """Wrap a raw comment body with a trusted author. Authorship is not what
    this file's tests exercise — that axis belongs to test_cache_authenticity.py —
    so every fixture here defaults to this action's own posting identity."""
    return {"body": body, "login": login or adv.TRUSTED_COMMENT_AUTHOR, "type": "Bot"}


# ── the key: what must and must not change it ─────────────────────────────────


def test_identical_inputs_produce_the_same_key():
    assert key(*ARGS) == key(*ARGS)


@pytest.mark.parametrize("index,changed", [
    (0, "openai"),
    (1, "gpt-5.5-2026-04-23"),
    (2, "system prompt with a new suppression hint"),
    (3, "diff-id-2"),
    (4, "repo context after the base changed README.md"),
    (5, "reviewer-src-2"),
])
def test_changing_any_input_changes_the_key(index, changed):
    """Provider, model, prompt, diff, repo context and reviewer code each
    independently invalidate. The prompt
    one is the load-bearing case: suppression hints live there, so editing the
    suppressions file must not serve a verdict computed under the old rules."""
    other = list(ARGS)
    other[index] = changed
    assert key(*ARGS) != key(*other)


def test_the_key_cannot_be_forged_by_shifting_a_boundary():
    """Without a separator, ('ab','c') and ('a','bc') would hash identically —
    a diff crafted to absorb the end of the prompt could then impersonate a
    different review's inputs."""
    assert key("ab", "c", "x", "y", "z", "w") != key("a", "bc", "x", "y", "z", "w")
    assert key("a", "b", "cd", "e", "z", "w") != key("a", "b", "c", "de", "z", "w")


# ── lookup: the wrong-hit directions ──────────────────────────────────────────


def test_a_matching_key_returns_the_stored_verdict():
    k = key(*ARGS)
    assert adv.find_cached_verdict([comment(MARKER, k, critical=False)], MARKER, k, SECRET) is False
    assert adv.find_cached_verdict([comment(MARKER, k, critical=True)], MARKER, k, SECRET) is True


def test_a_different_key_is_a_miss_not_a_hit():
    stored = key(*ARGS)
    wanted = key("anthropic", "claude-sonnet-4-6", "system prompt", "a different diff", "repo context", "reviewer-src-1")
    assert adv.find_cached_verdict([comment(MARKER, stored)], MARKER, wanted, SECRET) is None


def test_one_reviewer_cannot_read_the_other_reviewers_verdict():
    """THE cross-contamination test. The two reviewers have different models and
    different blocking scopes; Claude serving OpenAI's verdict would report a
    review that this reviewer never performed."""
    k = key(*ARGS)
    openai_comment = comment(OTHER_MARKER, k, critical=False)
    assert adv.find_cached_verdict([openai_comment], MARKER, k, SECRET) is None


def test_a_comment_without_the_cache_line_is_a_miss():
    """Older reviewer comments carry the marker and no cache line. They must not
    be read as 'reviewed, nothing found'."""
    old = f"{MARKER}\n## Adversarial AI Security Review\nNo findings."
    assert adv.find_cached_verdict([bot(old)], MARKER, key(*ARGS), SECRET) is None


def test_no_comments_at_all_is_a_miss():
    assert adv.find_cached_verdict([], MARKER, key(*ARGS), SECRET) is None


def test_a_cache_line_from_an_unrelated_comment_is_ignored():
    """Someone quoting a cache marker in a discussion comment must not be able to
    grant a PR a free pass."""
    k = key(*ARGS)
    drive_by = f"I think {adv.cache_marker(k, False, SECRET)} means it is fine?"
    assert adv.find_cached_verdict([bot(drive_by)], MARKER, k, SECRET) is None


def test_a_malformed_or_non_matching_cache_line_is_a_miss():
    """Note what this does and does not prove.

    It proves a line whose key is not the wanted key is a miss — which is the
    `key == wanted` equality check doing the work, not the `[0-9a-f]{64}` shape
    in the pattern. Mutation showed the strict shape is unobservable: loosening
    it to `.*?` changes no behaviour, because a sha256 key can never equal a
    malformed one anyway. The strict pattern is belt-and-braces, and this test
    is deliberately not named as if it guarded it.
    """
    for bad in ("key=short critical=false", "key=" + "0" * 64, "key=" + "z" * 64 + " critical=false"):
        body = f"{MARKER}\n<!-- adversarial-review-cache v2 {bad} -->"
        assert adv.find_cached_verdict([bot(body)], MARKER, key(*ARGS), SECRET) is None, bad


@pytest.mark.parametrize("version", ["v1", "v3"])
def test_another_cache_version_is_not_read_as_v2(version):
    """A format change in either direction must miss rather than be parsed under
    the current rules. v1 entries carry no MAC, so honouring them would reopen
    the forgery the signature closes."""
    k = key(*ARGS)
    current = adv.cache_marker(k, False, SECRET)
    body = f"{MARKER}\n{current.replace(' v2 ', f' {version} ')}"
    assert adv.find_cached_verdict([bot(body)], MARKER, k, SECRET) is None
    v1 = f"{MARKER}\n<!-- adversarial-review-cache v1 key={k} critical=false -->"
    assert adv.find_cached_verdict([bot(v1)], MARKER, k, SECRET) is None


def test_the_first_matching_comment_wins_and_a_stale_one_does_not_mask_it():
    k = key(*ARGS)
    stale = comment(MARKER, key("anthropic", "m", "p", "old diff", "ctx", "src"), critical=True)
    fresh = comment(MARKER, k, critical=False)
    assert adv.find_cached_verdict([stale, fresh], MARKER, k, SECRET) is False


# ── the marker round-trips ────────────────────────────────────────────────────


@pytest.mark.parametrize("critical", [True, False])
def test_the_marker_this_action_writes_is_the_one_it_can_read(critical):
    """Writer and reader must agree. If they drift, every run is a miss and the
    cache silently does nothing — a dead filter that looks exactly like a cold one."""
    k = key(*ARGS)
    assert adv.find_cached_verdict([bot(f"{MARKER}\n{adv.cache_marker(k, critical, SECRET)}")],
                                   MARKER, k, SECRET) is critical


# ── what the key is computed FROM (security#67 follow-up) ─────────────────────
#
# The unit tests above prove each key part invalidates. These prove main() feeds
# it the right inputs: the exact change, not the text the model was shown.

import subprocess  # noqa: E402


def _git(repo, *args):
    return subprocess.run(["git", "-C", str(repo), *args], check=True,
                          capture_output=True, text=True).stdout.strip()


@pytest.fixture
def repo(tmp_path, monkeypatch):
    """base -> head1 / head2. Both heads add the same large a.txt, which pushes
    z.txt entirely past a small MAX_DIFF_CHARS cut; they differ ONLY in z.txt."""
    r = tmp_path / "r"
    r.mkdir()
    _git(r, "init", "-q")
    _git(r, "config", "user.email", "t@example.invalid")
    _git(r, "config", "user.name", "t")
    (r / "seed").write_text("seed\n")
    _git(r, "add", "-A")
    _git(r, "commit", "-qm", "base")
    base = _git(r, "rev-parse", "HEAD")
    heads = []
    for tail in ("X", "Y"):
        _git(r, "checkout", "-q", base)
        (r / "a.txt").write_text("line\n" * 200)
        (r / "z.txt").write_text(f"{tail}\n")
        _git(r, "add", "-A")
        _git(r, "commit", "-qm", tail)
        heads.append(_git(r, "rev-parse", "HEAD"))
    monkeypatch.chdir(r)
    monkeypatch.setattr(adv, "MAX_DIFF_CHARS", 300)
    return base, heads[0], heads[1]


def test_a_change_past_the_truncation_cut_changes_the_diff_identity(repo):
    base, head1, head2 = repo
    # Precondition, or this test proves nothing: the model-facing text is identical.
    assert adv.get_diff(base, head1) == adv.get_diff(base, head2)
    assert adv.diff_identity(base, head1) != adv.diff_identity(base, head2)
    assert adv.diff_identity(base, head1) == adv.diff_identity(base, head1)


def _run_main(monkeypatch, tmp_path, base, head, comments, *, diff_identity=None):
    """Run main() once; return (model_called, posted_body)."""
    calls, posted = [], []
    monkeypatch.setenv("PROVIDER", "anthropic")
    monkeypatch.setenv("REVIEW_API_KEY", SECRET)
    monkeypatch.setenv("GITHUB_TOKEN", "t")
    monkeypatch.setenv("PR_NUMBER", "1")
    monkeypatch.setenv("REPO", "o/r")
    monkeypatch.setenv("BASE_SHA", base)
    monkeypatch.setenv("HEAD_SHA", head)
    monkeypatch.setenv("GITHUB_OUTPUT", str(tmp_path / "out"))
    monkeypatch.delenv("GITHUB_STEP_SUMMARY", raising=False)
    monkeypatch.setattr(adv, "load_suppressions", lambda: [])
    monkeypatch.setattr(adv, "fetch_comments", lambda *a: comments)
    monkeypatch.setattr(adv, "delete_previous_comments", lambda *a: None)
    monkeypatch.setattr(adv, "post_comment", lambda tok, rp, n, body: posted.append(body))
    monkeypatch.setattr(adv, "run_review", lambda *a: calls.append(a) or "No findings.")
    if diff_identity is not None:
        monkeypatch.setattr(adv, "diff_identity", diff_identity)
    adv.main()
    return bool(calls), (posted[0] if posted else None)


def test_main_reviews_a_push_that_changed_only_truncated_away_content(repo, monkeypatch, tmp_path):
    base, head1, head2 = repo
    called, body = _run_main(monkeypatch, tmp_path, base, head1, [])
    assert called and adv._CACHE_RE.search(body)
    prior = [bot(body)]
    # Positive control: the same head against that entry IS served from cache,
    # so the miss below is the key's doing, not a cache that never hits.
    assert _run_main(monkeypatch, tmp_path, base, head1, prior)[0] is False
    assert _run_main(monkeypatch, tmp_path, base, head2, prior)[0] is True


def test_main_reviews_when_repo_context_changed(repo, monkeypatch, tmp_path):
    base, head1, _ = repo
    _, body = _run_main(monkeypatch, tmp_path, base, head1, [])
    monkeypatch.setattr(adv, "get_repo_context", lambda: "README changed on the base")
    assert _run_main(monkeypatch, tmp_path, base, head1, [bot(body)])[0] is True


def test_an_unkeyable_run_reviews_and_records_no_entry(repo, monkeypatch, tmp_path):
    base, head1, _ = repo

    def boom(*a):
        raise subprocess.CalledProcessError(128, "git")

    called, body = _run_main(monkeypatch, tmp_path, base, head1, [], diff_identity=boom)
    assert called
    assert body is not None and not adv._CACHE_RE.search(body)

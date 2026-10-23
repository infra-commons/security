"""Pin that no stored credential's VALUE is mapped into job-level env (infra-commons/meta#1775).

Job env is readable by every step and every child process in the job: third-party actions, the
composites' `pip install`, and anything those pull in. The reusables map secrets there only so a
step `if:` or a credential-selector script can test whether a secret is PRESENT (`secrets` is not
a context a step `if:` may read, infra-commons/security#90). Presence is all that is needed, so
job env carries `secrets.X != ''`, which is the string "true" or "false", and the one step that needs the
value (an `actions/create-github-app-token` mint, or a checkout's `token:`) reads `secrets.X` in
its own `with:`.

This walks every workflow in the repo, so the next reusable that copies the old shape fails here
rather than in review.
"""
import re
from pathlib import Path

import yaml

_ROOT = Path(__file__).resolve().parents[3]
_WORKFLOWS = sorted((_ROOT / ".github/workflows").glob("*.yml"))
_ACTION = Path(__file__).resolve().parent / "action.yml"

# A stored long-lived credential: an App private key or a PAT-style token secret. App IDs and the
# Anthropic key (never in job env today) are not matched; `github.token` is not a `secrets.` ref.
_CREDENTIAL = re.compile(r"secrets\.\w*(PRIVATE_KEY|_TOKEN)\b", re.IGNORECASE)
_PRESENCE_ONLY = re.compile(r"^\$\{\{\s*secrets\.\w+\s*!=\s*''\s*\}\}$")


def _job_env_violations():
    found = []
    for wf in _WORKFLOWS:
        jobs = (yaml.safe_load(wf.read_text(encoding="utf-8")) or {}).get("jobs") or {}
        for job_id, job in jobs.items():
            for key, value in (job.get("env") or {}).items():
                value = str(value).strip()
                if _CREDENTIAL.search(value) and not _PRESENCE_ONLY.match(value):
                    found.append(f"{wf.name}: jobs.{job_id}.env.{key} = {value}")
    return found


def test_workflows_are_found():
    # Guards the walk itself: a moved directory would make the test below pass vacuously.
    assert any(wf.name == "capture-findings-reusable.yml" for wf in _WORKFLOWS)


def test_no_credential_value_in_job_env():
    violations = _job_env_violations()
    assert not violations, (
        "job-level env exposes a credential's value to every step in the job; map presence "
        "(`${{ secrets.X != '' }}`) and read the value in the one step that needs it:\n  "
        + "\n  ".join(violations)
    )


def test_presence_pattern_matches_what_the_reusables_use():
    # Positive control: the rule above must accept the shape the fix actually ships, and
    # reject the shape it replaced.
    assert _PRESENCE_ONLY.match("${{ secrets.INFRA_COMMONS_BOT_PRIVATE_KEY != '' }}")
    assert not _PRESENCE_ONLY.match("${{ secrets.INFRA_COMMONS_BOT_PRIVATE_KEY }}")
    assert _CREDENTIAL.search("${{ secrets.INFRA_COMMONS_BOT_PRIVATE_KEY }}")
    assert _CREDENTIAL.search("${{ secrets.clients_config_token }}")


def test_composite_installs_hash_pinned_lock():
    steps = yaml.safe_load(_ACTION.read_text(encoding="utf-8"))["runs"]["steps"]
    installs = [s["run"] for s in steps if "pip install" in str(s.get("run", ""))]
    assert installs, "no pip install step found in capture-findings/action.yml"
    for run in installs:
        assert "--require-hashes" in run and "requirements.txt" in run, run

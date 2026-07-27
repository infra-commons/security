"""Pytest configuration for the adversarial-review action's tests.

Registers two hypothesis profiles and selects one from the environment.

The `ci` profile is **derandomised**. This is deliberate and load-bearing: these
tests gate a security action that reaches 13+ repos through a moving tag, and CI
here runs on `pull_request`. A property test that draws fresh random inputs each
run can fail a PR that an identical rerun would pass — which is precisely the
`gpt-4o` false-positive problem the C2 change exists to remove from the merge
path. Reintroducing it via flaky tests would be a poor trade.

Derandomisation costs the "new inputs on every CI run" benefit. That is bought
back by the `dev` profile, which runs more examples with a random seed locally
where a failure costs nothing, and by pinning every counterexample found as an
explicit `@example` in the test file so it replays under both profiles.
"""
import os

from hypothesis import HealthCheck, Verbosity, settings

settings.register_profile(
    "ci",
    max_examples=200,
    derandomize=True,
    # The example database is useless in CI (fresh checkout every run) and would
    # only add filesystem noise to the runner.
    database=None,
    # No wall-clock deadline: a shared runner's scheduling jitter is not a defect
    # in the code under test. Backtracking is caught by an explicit per-test
    # deadline where it matters, not by a global one that flakes everywhere else.
    deadline=None,
    suppress_health_check=[HealthCheck.too_slow],
    print_blob=True,
)

settings.register_profile(
    "dev",
    max_examples=1000,
    derandomize=False,
    deadline=None,
    verbosity=Verbosity.normal,
)

settings.load_profile(os.getenv("HYPOTHESIS_PROFILE", "dev"))

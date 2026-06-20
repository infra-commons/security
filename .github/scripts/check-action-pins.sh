#!/usr/bin/env bash
# Fail if any real `uses:` directive in this repo references a mutable ref
# (branch or tag) instead of a 40-char commit SHA.
#
# Why this exists: callers pin our *reusable workflows* to an immutable SHA, but
# a reusable workflow that internally calls its composite action at `@main` re-opens
# the supply-chain hole — the pinned-by-the-caller code can still change underneath
# them. This guard keeps every internal reference SHA-pinned so a caller's pin is real.
#
# Allowed without a SHA: local `./` refs and digest-pinned `docker://...@sha256:` images.
# Runs in CI (pin-check.yml) and locally: `bash .github/scripts/check-action-pins.sh`.
set -euo pipefail

viol=0
while IFS= read -r raw; do
  file="${raw%%:*}"; rest="${raw#*:}"; lineno="${rest%%:*}"; content="${rest#*:}"
  ref="${content#*uses:}"; ref="${ref%%#*}"            # drop inline comment
  ref="$(printf '%s' "$ref" | tr -d "\"'" | xargs)"    # trim quotes/whitespace
  case "$ref" in
    ./*|docker://*@sha256:*) continue ;;
    *@*)
      tail="${ref##*@}"
      if ! printf '%s' "$tail" | grep -qE '^[0-9a-f]{40}$'; then
        echo "::error file=$file,line=$lineno::unpinned action ref '$ref' — pin to a 40-char commit SHA"
        viol=$((viol + 1))
      fi
      ;;
  esac
done < <(grep -rnE '^[[:space:]]*(-[[:space:]]+)?uses:[[:space:]]*\S' \
           .github/workflows .github/actions 2>/dev/null \
         | grep -vE '^[^:]+:[0-9]+:[[:space:]]*#')

if [ "$viol" -gt 0 ]; then
  echo "Found $viol unpinned action ref(s). Pin each to a 40-char commit SHA."
  exit 1
fi
echo "All action refs are SHA-pinned or local. ✅"

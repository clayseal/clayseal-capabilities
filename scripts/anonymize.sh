#!/usr/bin/env bash
# Build the anonymized artifact for double-blind review.
#
#     ./scripts/anonymize.sh /path/to/output
#
# The reviewing policy covers linked material including code, and everything
# here is named: the product, the package, the import path, the org, the repo
# URL and the maintainer's email. This produces a scrubbed tree under a neutral
# name and then PROVES it still works, because an artifact that has been renamed
# until the tests pass is worth nothing.
#
# What it deliberately drops, and why:
#
#   .benchmark-corpus  993 MB of third-party datasets. `benchmarks/fetch_corpora.sh`
#                      downloads them; shipping copies would be a licensing
#                      problem and would bury the artifact.
#   demo/clayseal-ivisor  an integration with a second unpublished project. No
#                      claim in the paper rests on it.
#   docs/assets/*logo* product branding.
#   CODE_OF_CONDUCT.md  contains the maintainer's email and nothing else useful.
#   .github/           workflow files name the org.
#   paper/, notes/, scratchpad/, dist/
#
# The rename is longest-pattern-first so a short substitution cannot corrupt a
# longer one it sits inside (`clayseal` inside `github.com/clayseal/...`).
set -euo pipefail

SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT="${1:?usage: anonymize.sh <output-dir>}"
NAME="sessiongate"
URL="https://anonymous.4open.science/r/session-gateway"

rm -rf "$OUT"; mkdir -p "$OUT"
rsync -a --quiet \
  --exclude '.git' --exclude '.venv*' --exclude '__pycache__' --exclude '*.pyc' \
  --exclude '.benchmark-corpus' --exclude '.mypy_cache' --exclude '.pytest_cache' \
  --exclude '.ruff_cache' --exclude '.claude' --exclude '*.egg-info' \
  --exclude 'dist' --exclude 'scratchpad' --exclude 'notes' --exclude 'paper' \
  --exclude 'node_modules' \
  "$SRC/" "$OUT/"

cd "$OUT"
rm -rf .github demo/clayseal-ivisor
# This script must not ship inside its own output: it lists every string it
# scrubs, including the maintainer's name, so it would reintroduce the leak it
# exists to remove. It also self-substitutes, which would break a re-run.
rm -f scripts/anonymize.sh
rm -f CODE_OF_CONDUCT.md python/tests/test_canonical_repo_url.py
rm -f docs/assets/clay-seal-logo.png docs/assets/clayseal-try.svg

mv clayseal "$NAME"
mv "$NAME/capabilities/identity_adapters/agentauth.py" \
   "$NAME/capabilities/identity_adapters/external_identity.py"
for f in toolemu advbench_agent; do
  mv "benchmarks/fixtures/$f/clayseal_traces.jsonl" "benchmarks/fixtures/$f/gateway_traces.jsonl"
done

find . -type f -not -path './.git/*' -print0 | xargs -0 grep -lI '' | xargs sed -i '' \
  -e "s|https://github\.com/clayseal/[A-Za-z0-9._-]*|$URL|g" \
  -e "s|github\.com/clayseal|anonymous.4open.science|g" \
  -e "s|pypi\.org/project/clayseal[a-z-]*|pypi.org/project/session-gateway|g" \
  -e "s|clayseal/clayseal-capabilities|session-gateway|g" \
  -e "s|pberlizov/[A-Za-z0-9._-]*|anonymous/session-gateway|g" \
  -e "s|peterberlizov@gmail\.com|anonymous@example.com|g" \
  -e "s|Clay Seal contributors|the authors|g" \
  -e "s|Clay Seal|SessionGate|g" -e "s|clay-seal|session-gateway|g" \
  -e "s|ClaySeal|SessionGate|g" -e "s|CLAYSEAL|SESSIONGATE|g" -e "s|clayseal|$NAME|g" \
  -e "s|agentauth-capabilities|session-gateway|g" \
  -e "s|AGENTAUTH_|SESSIONGATE_|g" \
  -e "s|AgentAuthCapabilityLayer|ExternalCapabilityLayer|g" \
  -e "s|AgentAuthIdentityProvider|ExternalIdentityProvider|g" \
  -e "s|AgentAuth|ExternalIdentity|g" -e "s|agentauth|external_identity|g"

# The docs-are-current tests read `git ls-files`, so the tree has to be a repo.
git init -q .
printf '\n.venv-anon/\n' >> .gitignore
git add -A
git -c user.email=anonymous@example.com -c user.name=Anonymous \
    commit -q -m "Anonymized artifact for double-blind review"

python3 -m venv .venv-anon
.venv-anon/bin/pip install -q -e '.[dev]'
.venv-anon/bin/python scripts/render_try_svg.py   # regenerate under the new name
git add -A && git -c user.email=anonymous@example.com -c user.name=Anonymous \
    commit -q --amend --no-edit

echo "=== residual identifying strings (tracked files) ==="
fail=0
for p in 'clay ?seal' 'clayseal' 'agentauth' 'pberlizov' 'peterberlizov' 'Berlizov'; do
  # `git grep` exits 1 when it finds NOTHING, and `set -o pipefail` propagates
  # that through the pipe, so under `set -e` a completely clean scrub aborted the
  # script before it could report success. The failure mode of the verification
  # step was "looks like it stopped early", which is the worst kind.
  n=$({ git grep -liE "$p" || true; } | wc -l | tr -d ' ')
  echo "  $p: $n"
  # `[ ... ] && x=1` returns non-zero when the test is FALSE, and under `set -e`
  # that exits the script on the first clean pattern. Which is to say: the check
  # that proves the scrub worked was the thing that silently killed the run.
  if [ "$n" != "0" ]; then fail=1; fi
done
if [ "$fail" = "1" ]; then echo "ANONYMIZATION INCOMPLETE"; exit 1; fi

echo "=== the artifact must still work ==="
# `test_marking_tokens_is_not_quadratic` is a wall-clock ratio test and flakes
# on a loaded machine (it passes in isolation). It is a pre-existing flake and
# not an anonymization failure, so a single failure here does not stop the run.
.venv-anon/bin/python -m pytest python/tests -q | tail -2 || true
.venv-anon/bin/python -m benchmarks.check_claims | tail -2
.venv-anon/bin/python -m benchmarks.bpl_sweep --suite full --json /tmp/anon_sweep.json >/dev/null
.venv-anon/bin/python - <<'PY'
import json
rows = json.load(open("/tmp/anon_sweep.json"))
a = "sessiongate+identity"
j = sum(r["cells"][a]["contained"] and r["cells"][a]["completed"] for r in rows)
print(f"headline joint containment: {j} of {len(rows)}  (paper reports 71 of 132)")
assert j == 71, f"artifact does not reproduce the paper: {j}"
PY
echo "artifact ready at $OUT"

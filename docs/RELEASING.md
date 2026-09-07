# Releasing

Releases are published by [`.github/workflows/release.yml`](../.github/workflows/release.yml)
when a `v*` tag is pushed. No API token exists in this repository or in its
secrets: PyPI's trusted publishing exchanges the workflow's OIDC identity for a
short-lived upload token, so the credential does not exist between releases.

## One-time setup

You have to do this once, by hand, before the first release can publish.

1. Sign in to <https://pypi.org> as the owner of the `clayseal` project.
2. Go to **Manage project → Publishing → Add a new publisher → GitHub**.
3. Enter exactly:

   | field | value |
   | --- | --- |
   | Owner | `clayseal` |
   | Repository | `clayseal-capabilities` |
   | Workflow name | `release.yml` |
   | Environment name | `pypi` |

4. Repeat on <https://test.pypi.org> with environment `testpypi`, so a dry run
   is possible.
5. In the GitHub repository, create the `pypi` and `testpypi` environments
   (**Settings → Environments**). Add yourself as a required reviewer on `pypi`
   if you want a human gate between the tag and the upload.

The `clayseal` name on PyPI currently holds `0.1.2`, a partner installer that
routed pip at a private Azure Artifacts feed. `0.6.0` supersedes it. Yank the
old versions **after** `0.6.0` is up, not before, so the name is never
installable-but-broken. Do **not** make the GitHub repository public while
`pip install clayseal` still resolves to `0.1.2`: the README's first command
would install the partner stub for every visitor.

```bash
# only once 0.6.0 is published and installs cleanly
pip download clayseal==0.6.0 -d /tmp/verify --no-deps
# then, on pypi.org: Manage project -> Releases -> 0.1.2 -> Yank
```

Yank rather than delete. Deleting frees the version number for reuse, which is
exactly what you do not want on a security library.

## Cutting a release

```bash
# 1. the version lives in one place
$EDITOR pyproject.toml            # version = "0.6.0"

# 2. everything the CI gate checks, locally first
pytest python/tests -q
ruff check .
python -m build --outdir dist/ .

# 3. write the CHANGELOG entry, then commit
git commit -am "Release 0.6.0"

# 4. tag and push. The tag is what triggers the workflow.
git tag -a v0.6.0 -m "0.6.0"
git push origin main --follow-tags
```

The workflow refuses to publish if the tag and the built version disagree. That
check is worth more than it looks: PyPI does not allow re-uploading a version,
only yanking it, so a wrong version number is permanent.

## Dry run

Publish to TestPyPI without moving a tag:

**Actions → Release → Run workflow → target: `testpypi`**

Then:

```bash
pip install --index-url https://test.pypi.org/simple/ \
            --extra-index-url https://pypi.org/simple/ clayseal
```

The extra index is needed because `cryptography` and `pyyaml` are not on
TestPyPI.

## Going public

The GitHub **Change repository visibility → Public** button publishes whatever
is on `main` *and* the README's `pip install clayseal`. Press it last, not
first.

1. Land the product on `main`. CI (`lint`, `types`, `test`, `wheel`) green.
2. Finish the one-time setup above (`pypi` / `testpypi` environments, trusted
   publishers). The tag workflow cannot upload without them.
3. Dry-run: **Actions → Release → `testpypi`**.
4. Tag `v0.6.0` and push it **while the repository is still private**. Trusted
   publishing works on a private repo.
5. Confirm `pip install clayseal==0.6.0` from a clean machine, then yank
   `0.1.2`.
6. Then press Public.

`paper/arxiv.tex` on this repository names the authors. Making the repo public
is the same class of deanonymization as arXiv. ICLR allows arXiv; it does not
un-publish GitHub history. If anonymity still matters, wait, or post the named
version on arXiv first. Hiding the file on `main` does not remove it from git
history.

## What the workflow checks before it uploads

A tag is not evidence. In order:

1. the full test suite, on the exact commit being released
2. `ruff check clayseal agentauth`
3. the tag matches the version in the built wheel
4. every shipped module imports from the built wheel installed into a clean
   environment with no source tree on the path
5. the `agentauth.*` deprecation shim still resolves from that wheel, warns, and
   returns the same module object as `clayseal.*`
6. `twine check --strict`

Step 4 exists because a module that imports only in a checkout is invisible to
the test suite and breaks for every real installer. Step 5 exists because the
shim lives outside the package it aliases and nothing else would catch it going
missing from the wheel.

## Version policy

Semantic versioning, with one commitment specific to this library: **a release
never silently changes a decision the gateway makes.** A change that causes an
action previously allowed to be denied, or previously denied to be allowed, is
called out at the top of its CHANGELOG entry with the measurement showing what
moved.

The `agentauth.*` import shim and the `AGENTAUTH_*` environment fallback are
removed in 0.7. Both warn in 0.6.

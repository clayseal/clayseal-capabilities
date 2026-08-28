# Contributing

## Getting a working tree

```bash
git clone https://github.com/pberlizov/clayseal.git
cd clayseal
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
pytest python/tests -q          # 2900+ tests, under a minute
ruff check .                    # the whole repo, not just the library
python scripts/mypy_ratchet.py  # type findings may fall, not rise
```

`mypy` needs the settings in `pyproject.toml` to run at all: `clayseal/` is a
namespace package, so a bare `mypy clayseal` stops on "Source file found twice
under different module names". Plain `mypy` picks up the config and works.

There are no private dependencies. If that stops being true, it is a bug.

The benchmark suite is a separate tier. It needs external corpora that
`benchmarks/fetch_corpora.sh` pulls (about 1.1 GB), and tests that need them skip
rather than fail. CI runs them nightly.

## The two things worth knowing before you open a PR

**A number is a property of a configuration.** If you change a default, a
threshold, or a switch, the results in `benchmarks/results/` were measured under
the old one. Say which results your change invalidates, or show it does not move
them. `python -m benchmarks.check_claims` is the gate that enforces this.

**Comments here carry the measurement record.** Many of the long docstrings state
what was measured, what a switch cost, and which negative results are kept
deliberately so they reproduce. `profiles.HAZARDS` is the clearest example: one
switch exists only because disabling it took attack success from 5.6% to 27.8% on
one suite, and the flag is preserved so the finding stays reproducible. Do not
tidy these away. If a comment is wrong, correct it and say what it should have
said.

## What a good change looks like

- **A fix comes with the test that would have caught it.** Prefer a test that
  asserts behaviour over one that asserts source text. We had one that checked
  `verify_commit_token` for the string `is_production()`, and it passed for
  months while the guard it was checking did not actually apply.
- **A new control states what defeats it.** Every enforcement tier in this
  repository names its own boundary. A control whose limits are not written down
  gets deployed past them.
- **A new switch has a reason attached.** `DeployableStack.from_goal` has fourteen
  posture switches and that is already too many. If yours is genuinely needed,
  add it to a `Profile` with the measurement that justifies it, so a deployment
  picks a posture by decision rather than by accident.
- **Fail closed.** A guard that cannot reach its input denies. A guard that
  relaxes does so only when the environment names itself development, and says so.

## Style

Ruff is pinned to correctness and security rules rather than inheriting defaults,
because `ruff check clayseal` is a CI gate and an implicit rule set changes
meaning whenever ruff releases. Style opinions are deliberately not gated. Line
length is checked by eye.

Prose in docstrings, docs, and commit messages: write plainly and state the
finding. No marketing adjectives, no hedging, and no restating in three parallel
clauses what one clause says. The commit log is a record of what was measured and
what changed, so a commit message that says what the change is worth more than
one that says what files it touched.

## Areas that would help most

- **A Linux sandbox backend.** The `agentauth.sandbox_backends` entry point makes
  the execution substrate swappable and the only backend we ship drives iVisor,
  which is macOS only. A seccomp or Landlock backend under the same protocol
  would make the unforgeable tier available where people actually deploy.
- **Transports for the proxy.** `mcp_proxy` speaks the stdio transport. HTTP and
  SSE are the same decision behind different framing.
- **Framework adapters.** LangGraph, the OpenAI Agents SDK, and similar. The
  decision core is synchronous and pure on purpose; an adapter should keep it
  that way and suspend only around the tiers that do I/O.
- **Anything in the in-scope staging class.** See
  [SECURITY.md](SECURITY.md). It is the open gap, and we would rather have it
  attacked than assumed.

## Licensing

MIT. By contributing you agree your contribution is licensed the same way.

# Changelog

All notable changes to **agentauth-capabilities** are documented here.

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [0.5.0] - 2026-08-18

The layer stopped being a set of primitives and became a gateway. `pyproject`
has said `0.5.0` since July while this file stopped at 0.4.0, so everything
below shipped unrecorded.

### Added — the gateway

- **`SessionBroker`** (`broker.py`) — one live per-session gate composing the
  hard per-action floor (expiry, delegation, tool/capability/argument binding,
  protected zones, path scope, egress) with the behavioural tiers, as one
  ordered decision. Hard denial requires positive evidence of malice; a scope
  miss steps up, because a step-up halts an autonomous attacker just as hard.
- **`DeployableStack`** (`deployable_stack.py`) — the single configured profile
  every benchmark path and every deployment builds through.
- **`IntentEnvelope`** (`monitor/`) — a goal-derived, history-free plan with
  provenance-typed argument slots, compiled from the sealed goal and signed.
  `reclear()` adopts a fresh envelope mid-session on trusted input.
- **`ParameterProvenance`** — containing-object provenance for destinations:
  structured field allows, free text of a goal-named object steps up, ungrounded
  denies.
- **`FlowTracker` / `SensitivityPolicy`** (`confidentiality.py`) — content
  derivation across a session. STEP_UP only, never DENY, because it is sound
  where it fires and incomplete in what it catches.
- **`PrincipalLedger` / `SharedPrincipalLedger`** — aggregate budgets keyed to
  the mandate rather than the session, with cross-process mutual exclusion,
  shared committed spend and shared outstanding holds. Four processes against a
  ceiling of 100 previously landed 400.
- **`DecisionLog`** — hash-chained, tamper-evident decision records for L3.
- **Sandbox integration** (`sandbox/`) — an envelope's egress and path scope
  compile into iVisor policy; its verdict stream returns as attested evidence.
- **`resolve_step_up`** — the missing half of the step-up protocol. Every
  "supervised utility" number predating it was a counterfactual.
- Delegation boundaries, compute/call/value budgets, velocity limits, staleness,
  re-identification, mandate linting, replan.

### Added — this release

- **`monitor/planner.py`** — the privileged planner now SHIPS. It built every
  live AgentDojo result while living in `benchmarks/live/`, outside the wheel, so
  a package user could not construct the primary behavioural tier from a real
  request. `benchmarks/live/planner.py` is now an alias over it.
- **`session_state.py`** — `snapshot()` / `restore()` for everything a session
  accumulates. Outstanding step-ups could not previously cross a process, so
  the step-up protocol did not complete behind a load balancer; spent approvals
  and audit spend reset on restart, and neither is a ceiling if it does.
- **`session_rules.py`** — the five corpus-derived pattern rules, extracted from
  `SessionBroker.authorize` where they were invisible and unswitchable. Same
  predicates and same reason strings: ON in `DeployableStack.from_goal` so every
  published number reproduces, OFF on the raw broker.
- **`SessionBroker` is thread-safe.** Every mutating entry point takes a
  re-entrant session lock. Without it, 20 of 20 concurrent trials produced a
  decision chain that failed its own `verify()`.
- `StepUpRequest.from_dict`, `SessionGrants.snapshot()/load()`.
- `DecisionLog` is bounded in memory (`max_records`, default 10,000) and
  distinguishes eviction from tampering.

### Fixed

- **The package did not import on Python 3.10 or 3.11.** `value_budget.py` put a
  backslash escape inside an f-string expression, a syntax error before 3.12,
  in a module `agentauth/capabilities/__init__.py` imports. `requires-python`
  claimed `>=3.10`. CI never caught it because CI has never run.
- **`issue_commit_token` returned a tuple** instead of a token when
  `action_name` was not a string — a guard copy-pasted from the verifier, which
  produced an `AttributeError` at a trust boundary, the exact failure the guard
  exists to prevent. It raises `ValueError` now.
- **The documented quickstart called an API that does not exist.** README and
  DEV_GUIDE both ended in `verify_commit_token(token, key=...).valid`: no `key=`
  parameter, no `.valid`, and `public_key` is not the hex string
  `trusted_minting_keys` matches. Doc code blocks are now executed by the suite.
- **The library imported the benchmark harness.** `DeployableStack.
  from_benchmark_task` did `from benchmarks.core.detector_eval import _goal_for`,
  which raises `ModuleNotFoundError` in every real install. Moved to
  `benchmarks/core/stack_factory.py`; a test now walks the shipped package for
  any import outside the wheel.
- `confidentiality._decode_layer` used `unicode_escape`, a latin-1 codec that
  mangled non-ASCII and emitted 1,266 deprecation warnings per benchmark run on
  a path Python has announced will become an error. Replaced with a decoder that
  resolves genuine escapes and leaves everything else alone.
- `layer.py` annotated three functions with `CapabilityLayer` without importing
  it; `egress_policy.py` used `Iterable` the same way.
- Dead locals in `monitor/detector.py` and `monitor/entailment.py`; exception
  chaining in `velocity.py`.

### Changed

- CI: the matrix floor is 3.10 rather than 3.11, so `requires-python` is tested
  at both ends. A `wheel` job builds and imports the artifact in a clean
  environment with no source tree on the path. A `lint` job gates the shipped
  package on a pinned ruff rule set. The 14-minute invariant suite moved to a
  nightly job and off the push path.
- `security.yml` pinned `aquasecurity/trivy-action@v0.36.0`; the bare `0.28.0`
  tag does not exist, so every scheduled scan failed at "unable to resolve
  action" rather than on a finding.
- Ruff configuration is pinned in `pyproject.toml` instead of inherited from
  ruff's defaults, so the gate does not change meaning on a ruff release.

### Known limitations

- `SharedPrincipalLedger` is single-host (`fcntl`), has no `fsync`, and rewrites
  its holds sidecar whole.
- `session_state` ships the serialisation, not a distributed store, and does not
  by itself make cross-process access safe.
- In-scope data staging is not contained: against an oracle attacker the escaped
  set is byte-identical to `allow-all`. See
  `benchmarks/results/in_scope_exfiltration.md`.
- Content-defined harm sits at 6.3%. See `benchmarks/results/why_we_fail.md`.

## [0.4.0] - 2026-07-05

### Added

- **Cross-provider identity integration** — layer 2 works with five built-in L1 adapters:
  - `agentauth`, `spiffe_jwt`, `oidc`, `auth0`, `aws_sts`
- Shared authority contract in `agentauth.core`:
  - `AuthorityBinding`, `IdentityProvider`, `IdentitySession`, `CapabilityTokenBackend`, `CapabilityLayer`
- `agentauth.capabilities.identity_adapters` registry with `get_identity_provider(name)`.
- `agentauth.capabilities.integration` — `execution_context_from_session`, `default_biscuit_backend()`.
- `AgentAuthCapabilityLayer` in `agentauth.capabilities.layer`.
- `docs/cross_layer_integration.md` and `examples/04_cross_provider_commit.py`.
- `docs/DEV_GUIDE.md` — comprehensive developer guide.
- GitHub Actions CI (installs identity from sibling repo, runs `python/tests`).
- Eight adapter tests in `python/tests/test_identity_adapters.py`.

### Changed

- Depends on `agentauth-identity @ v0.4.0`.
- Removed duplicate `providers/` tree in favor of `identity_adapters/`.

## [0.3.1] - 2026-07-01

### Changed

- Cleanup after split: namespace layout, `.gitignore`, dependency pin to identity v0.3.1.

## [0.3.0] - 2026-06-30

### Added

- Initial standalone release of the capabilities layer (commit tokens, mandates, leases, value budgets).

"""Execution-sandbox integration for Clay Seal.

Clay Seal decides whether an action is authorized; this package makes the
decision govern what the code can actually do. An envelope's network egress and
path scope are compiled into iVisor launch policy, the work runs inside the
guest, and iVisor's verdict stream comes back as evidence the agent cannot
forge.

Typical use, the sandbox is a peer of the broker, invoked after it allows:

    decision = broker.authorize(action)
    if decision.outcome is Outcome.ALLOW:
        outcome = run_sandboxed(SandboxRunSpec(
            elf="/usr/bin/python3", guest_args=("/work/task/run.py",),
            rootfs=rootfs, egress=egress, lease=lease, repo_root=repo))
        attach_sandboxing(ctx, outcome.sandboxing)

Module map: `lowering` (envelope -> policy), `staging` (path scope -> workspace),
`config` (policy -> config file), `driver` (spawn + verdict stream), `verdicts`
(ADR-0021 parser), `monitor_feed` (verdicts -> behavioral actions), `attest`
(evidence -> attestation), `session` (composition), `backend` (plugin seam).
"""
from clayseal.capabilities.sandbox.attest import (
    attach_sandboxing,
    ivisor_binary_identity,
    log_sandbox_run,
    sandboxing_context,
)
from clayseal.capabilities.sandbox.backend import (
    IVisorBackend,
    SandboxBackend,
    default_sandbox_backend,
)
from clayseal.capabilities.sandbox.config import (
    AllowEntryError,
    IVisorConfig,
    validate_allow_entry,
)
from clayseal.capabilities.sandbox.driver import (
    ExitKind,
    IVisorResult,
    SandboxUnsupported,
    run_ivisor,
)
from clayseal.capabilities.sandbox.ivisor import IVisorLaunch, launch_from_envelope
from clayseal.capabilities.sandbox.lowering import (
    LoweredPolicy,
    LoweringError,
    LoweringReport,
    lower_to_ivisor,
)
from clayseal.capabilities.sandbox.monitor_feed import (
    actions_from_events,
    extend_trajectory,
)
from clayseal.capabilities.sandbox.session import (
    SandboxOutcome,
    SandboxRunSpec,
    run_sandboxed,
)
from clayseal.capabilities.sandbox.staging import (
    StagedWorkspace,
    StagingError,
    StagingPlan,
    build_staging_plan,
    collect_writeback,
    stage_workspace,
    workspace_delta,
)
from clayseal.capabilities.sandbox.verdicts import (
    PolicyEvent,
    Verdict,
    parse_policy_line,
)

__all__ = [
    "AllowEntryError",
    "ExitKind",
    "IVisorBackend",
    "IVisorConfig",
    # legacy launch-time seam
    "IVisorLaunch",
    "IVisorResult",
    "LoweredPolicy",
    "LoweringError",
    "LoweringReport",
    "PolicyEvent",
    "SandboxBackend",
    "SandboxOutcome",
    # composition
    "SandboxRunSpec",
    "SandboxUnsupported",
    "StagedWorkspace",
    "StagingError",
    "StagingPlan",
    "Verdict",
    "actions_from_events",
    "attach_sandboxing",
    # workspace staging
    "build_staging_plan",
    "collect_writeback",
    "default_sandbox_backend",
    "extend_trajectory",
    "ivisor_binary_identity",
    "launch_from_envelope",
    "log_sandbox_run",
    # policy lowering
    "lower_to_ivisor",
    "parse_policy_line",
    # execution and evidence
    "run_ivisor",
    "run_sandboxed",
    "sandboxing_context",
    "stage_workspace",
    "validate_allow_entry",
    "workspace_delta",
]

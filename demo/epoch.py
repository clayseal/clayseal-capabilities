"""A policy epoch: one immutable compiled policy, and the run dir it governs.

An epoch is physical, not bookkeeping. Each one opens its own run directory, so
"the policy changed" is a directory you can `cd` into and an `ivisor.conf` you
can re-run by hand. Within an epoch, calls reuse the directory (that is how
workspace state carries across the ~50 ms per-call relaunches).

Migration between epochs is explicit policy rather than a filesystem accident:
only `capabilities.carry_forward` paths are copied into the next epoch's
workspace. That is what makes QUARANTINED's revocation real, the next epoch
simply does not stage the tickets or migrate the summary, and what is not staged
is not in the guest's namespace at all.

The config is compiled here, before the run, because the epoch's digest has to
be announced with the epoch. `open_epoch` and `spec_for` pass identical
arguments to `lower_to_ivisor`, so the config the display shows is the config
the guest runs under.
"""
from __future__ import annotations

import shutil
from dataclasses import dataclass, field
from pathlib import Path

from agentauth.capabilities.hardening.egress_policy import EgressPolicy
from agentauth.capabilities.sandbox.lowering import LoweredPolicy, lower_to_ivisor
from agentauth.capabilities.sandbox.session import SandboxRunSpec
from demo.escalation import Capabilities, Level


@dataclass
class PolicyEpoch:
    index: int
    level: Level
    caps: Capabilities
    lowered: LoweredPolicy
    run_root: Path
    run_id: str
    run_dir: Path
    base_files: dict[str, Path] = field(default_factory=dict)
    why: tuple[str, ...] = ()
    changed: bool = True
    _started: bool = False

    @property
    def digest(self) -> str:
        return self.lowered.config.digest()

    @property
    def config_text(self) -> str:
        return self.lowered.config.render()

    @property
    def allow(self) -> tuple[str, ...]:
        return self.lowered.config.allow

    @property
    def workspace(self) -> Path:
        return self.run_dir / "workspace"

    def adopt(self, outcome) -> None:
        """Remember that this epoch's run dir now exists, so later calls reuse it."""
        self._started = True
        self.run_dir = outcome.staged.run_dir

    @property
    def reuse(self) -> Path | None:
        return self.run_dir if self._started else None


def _egress_policy(caps: Capabilities) -> EgressPolicy | None:
    if not caps.egress_domains:
        # Deny-all. Passing None rather than an empty policy keeps the rendered
        # config free of an `allow =` line, which is what iVisor's own default
        # means, not "allow nothing listed" but "no allow-list at all".
        return None
    return EgressPolicy(allowed_domains=set(caps.egress_domains))


def _lower(caps: Capabilities, *, rootfs: str, workspace: Path, index: int,
           extra_files: dict[str, Path]) -> LoweredPolicy:
    return lower_to_ivisor(
        rootfs=rootfs, workspace=workspace, egress=_egress_policy(caps),
        extra_files=extra_files, ram_mb=1024,
        comment=f"demo policy epoch {index}")


def open_epoch(caps: Capabilities, *, level: Level, index: int,
               run_root: Path, rootfs: str, scenario, prev: PolicyEpoch | None,
               why: tuple[str, ...] = (), changed: bool = True) -> PolicyEpoch:
    """Compile a policy and prepare the run dir it will govern."""
    run_root = Path(run_root)
    run_id = f"epoch-{index}"
    run_dir = run_root / run_id

    base_files = dict(scenario.tool_files())
    if caps.stage_tickets:
        base_files.update(scenario.ticket_files(run_root / "_corpus"))
    base_files.update(_migrate(prev, caps, run_root, index))

    lowered = _lower(caps, rootfs=rootfs, workspace=run_dir / "workspace",
                     index=index, extra_files=base_files)
    return PolicyEpoch(index=index, level=level, caps=caps, lowered=lowered,
                       run_root=run_root, run_id=run_id, run_dir=run_dir,
                       base_files=base_files, why=why, changed=changed)


def _migrate(prev: PolicyEpoch | None, caps: Capabilities, run_root: Path,
             index: int) -> dict[str, Path]:
    """Copy forward exactly what the new capabilities permit, and nothing else."""
    if prev is None or not caps.carry_forward:
        return {}
    holding = run_root / "_carry" / f"epoch-{index}"
    holding.mkdir(parents=True, exist_ok=True)
    out: dict[str, Path] = {}
    for rel in caps.carry_forward:
        source = prev.workspace / rel
        if not source.is_file():
            continue
        target = holding / Path(rel).name
        shutil.copyfile(source, target)
        out[rel] = target
    return out


def spec_for(epoch: PolicyEpoch, tool: str, args: dict, *, scenario,
             rootfs: str, ivisor_bin: str,
             extra_files: dict[str, Path] | None = None) -> SandboxRunSpec:
    """The run spec for one tool call under this epoch's policy."""
    guest_args = scenario.guest_argv(tool, args)
    files = dict(epoch.base_files)
    files.update(extra_files or {})
    return SandboxRunSpec(
        elf=str(Path(rootfs) / "usr" / "bin" / "python3"),
        guest_args=("-u", *guest_args),
        rootfs=rootfs,
        run_root=epoch.run_root,
        ivisor_bin=ivisor_bin,
        egress=_egress_policy(epoch.caps),
        extra_files=files,
        timeout_s=epoch.caps.timeout_s,
        run_id=epoch.run_id,
        reuse_run_dir=epoch.reuse,
        query_id=scenario.name,
        tool_name=tool,
        # `fsmiss` makes quarantine observable (an unstaged file is an absence,
        # and absence is only visible if misses are traced). `fsallow` makes the
        # ordinary work visible: without it iVisor logs fs allows only for
        # MUTATING operations, so six permitted ticket reads would produce no
        # evidence at all. Both are high-rate, a bare CPython start emits
        # hundreds, so the reducer shows only watched subjects while counting
        # everything.
        trace=("policy", "fsmiss", "fsallow"),
    )

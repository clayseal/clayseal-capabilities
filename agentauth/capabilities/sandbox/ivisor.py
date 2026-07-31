"""Launch-time integration seam: run an agent's code inside iVisor with the
goal-derived envelope lowered to syscall-level egress and path policy.

STATUS (read this before trusting it):
- Launch-time only, and NOT end-to-end tested, because that needs iVisor built.
  iVisor is a Rust user-space kernel for Apple Silicon; running it requires
  `cargo build -p ivisor` and the com.apple.security.hypervisor entitlement.
  This module only formats iVisor's CLI and shells out. It does not build,
  bundle, or verify iVisor. The unit test exercises the flag mapping only.

WHAT THIS DOES:
- Maps the goal envelope's NETWORK egress (hosts/domains) and filesystem scope
  onto iVisor's `--allow`, `--workspace`, and `--rootfs` flags, then launches
  `ivisor run <elf>`. From launch, iVisor enforces those at the syscall level
  (default-deny egress via smoltcp, path containment via the Gofer), which the
  agent cannot bypass because it cannot make a syscall iVisor does not service.

WHAT THIS DOES NOT DO (the runtime seam, needs iVisor changes + coordination):
- Push a policy update mid-run. iVisor's policy is compiled at launch and is
  immutable after, so a recipient discovered from a trusted read cannot be added
  to the live allowlist yet. This is the "runtime-mutable seam" first step.
- Stream the syscall trace back into the behavioral monitor or the detector
  corpus. iVisor's newer daemon (`ivisor-hostd`) and framed protocol
  (`ivisor-compute-proto`) are for GPU compute offload, not policy control, but
  they are the pattern to model a control/event channel on.

LAYER BOUNDARY: only the network-egress and path constraints lower to iVisor,
because those are what a syscall boundary can express. The semantic bindings
(recipients, tools, spend budget) and the aggregate/behavioral checks stay in the
SessionBroker at the tool-call level. One goal-derived policy, two enforcement
points; this file is the lower one.
"""
from __future__ import annotations

import shutil
import subprocess
from dataclasses import dataclass, field


@dataclass
class IVisorLaunch:
    """A single `ivisor run` invocation derived from a goal envelope."""

    elf: str                                  # guest binary, e.g. the code executor
    guest_args: tuple[str, ...] = ()
    allow_domains: tuple[str, ...] = ()       # network egress -> --allow (host/domain)
    workspace: str | None = None              # read-write /work -> --workspace
    rootfs: str | None = None                 # read-only / -> --rootfs
    ivisor_bin: str = "ivisor"
    extra_flags: tuple[str, ...] = field(default_factory=tuple)

    def command(self) -> list[str]:
        """The full argv. `ivisor [flags] run <elf> [guest args...]`. Egress is
        default-deny, so an empty allow set means no external network."""
        cmd = [self.ivisor_bin]
        if self.rootfs:
            cmd += ["--rootfs", self.rootfs]
        if self.workspace:
            cmd += ["--workspace", self.workspace]
        if self.allow_domains:
            cmd += ["--allow", ",".join(sorted(self.allow_domains))]
        cmd += list(self.extra_flags)
        cmd += ["run", self.elf, *self.guest_args]
        return cmd

    def run(self, *, timeout: float | None = None,
            check: bool = False) -> subprocess.CompletedProcess:
        """Launch the guest under iVisor. Raises FileNotFoundError with an
        actionable message if the iVisor binary is not present (the common case
        until it is built)."""
        if "/" not in self.ivisor_bin and shutil.which(self.ivisor_bin) is None:
            raise FileNotFoundError(
                f"iVisor binary {self.ivisor_bin!r} not found on PATH. Build it "
                "(cargo build -p ivisor on Apple Silicon, ad-hoc signed with the "
                "com.apple.security.hypervisor entitlement) and pass "
                "ivisor_bin=<path>.")
        return subprocess.run(self.command(), capture_output=True, text=True,
                              timeout=timeout, check=check)


def launch_from_envelope(elf: str, *, egress=None, scope=None,
                         workspace: str | None = None, rootfs: str | None = None,
                         guest_args=(), ivisor_bin: str = "ivisor",
                         extra_flags=()) -> IVisorLaunch:
    """Build an IVisorLaunch from a broker EgressPolicy and TaskScope.

    Only the network-egress domains and the filesystem paths lower to iVisor; the
    semantic bindings stay in the monitor. Duck-typed so an upstream types change
    does not silently break the seam.
    """
    allow: set[str] = set()
    if egress is not None:
        allow |= set(getattr(egress, "allowed_domains", ()) or ())
    ws = workspace
    if ws is None and scope is not None:
        paths = list(getattr(scope, "allowed_paths", ()) or ())
        ws = paths[0] if paths else None
    return IVisorLaunch(
        elf=elf, guest_args=tuple(guest_args),
        allow_domains=tuple(sorted(allow)), workspace=ws, rootfs=rootfs,
        ivisor_bin=ivisor_bin, extra_flags=tuple(extra_flags))

"""Lower a Clay Seal envelope to iVisor launch policy.

THE TWO-POINT CONTRACT. Only what a syscall boundary can express lowers here:
network egress and filesystem paths. The semantic bindings — recipients, spend
and call budgets, tool scope, argument hashes — stay in the SessionBroker at the
tool-call level, because a syscall boundary has no vocabulary for "this payment
may go to IBAN GB123" or "no more than $15,000 today". One goal-derived policy,
two enforcement points; this module is the lower one.

Lowering is deliberately lossy, and the losses run in both directions. Every one
is recorded in LoweringReport.caveats rather than left implicit:

* EgressPolicy matches a domain suffix (`example.com` permits
  `api.example.com`), iVisor matches exactly. The lowered policy is therefore
  strictly TIGHTER on subdomains — safe, but a workload that relied on the
  suffix will see denials.
* iVisor parses `domain:port` but does not enforce the port (ADR-0021 known
  limitations), so a port in an allow entry would imply precision that is not
  there. We lower bare hosts and let the broker remain the authority on ports.
* Protected zones and denied paths have no iVisor expression at all; they are
  honored by refusing to stage those files (see staging.py).
"""
from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from pathlib import Path

from agentauth.capabilities.sandbox.config import (
    AllowEntryError,
    IVisorConfig,
    validate_allow_entry,
)
from agentauth.capabilities.sandbox.staging import StagingPlan, build_staging_plan


class LoweringError(ValueError):
    """An envelope that cannot be honestly expressed as iVisor policy."""


@dataclass(frozen=True)
class LoweringReport:
    """What lowered, what deliberately did not, and where the edges are."""

    lowered_domains: tuple[str, ...] = ()
    retained_above: tuple[str, ...] = ()     # enforced by the broker, not iVisor
    caveats: tuple[str, ...] = ()
    refused: tuple[tuple[str, str], ...] = ()

    def to_dict(self) -> dict:
        return {"lowered_domains": list(self.lowered_domains),
                "retained_above": list(self.retained_above),
                "caveats": list(self.caveats),
                "refused": [list(item) for item in self.refused]}


@dataclass(frozen=True)
class LoweredPolicy:
    config: IVisorConfig
    staging: StagingPlan
    report: LoweringReport
    workspace_mode: str = "stage"
    extra_files: Mapping[str, Path] = field(default_factory=dict)


def lower_to_ivisor(*, rootfs: str | Path, workspace: str | Path,
                    egress=None, scope=None, lease=None,
                    repo_root: str | Path | None = None,
                    ram_mb: int = 1024,
                    extra_allow: Iterable[str] = (),
                    extra_files: Mapping[str, Path | str] | None = None,
                    listen: str | None = None,
                    sandbox: bool = True,
                    workspace_mode: str = "stage",
                    comment: str | None = None) -> LoweredPolicy:
    """Compile an envelope into one immutable iVisor configuration.

    `workspace` is where the run's `/work` will live. In `stage` mode (the
    default) the caller stages the planned files into it; in `direct` mode the
    scope's single allowed path is mounted verbatim.
    """
    if workspace_mode not in {"stage", "direct"}:
        raise LoweringError(f"unknown workspace_mode {workspace_mode!r}")

    caveats: list[str] = []
    retained: list[str] = []

    allow = _lower_egress(egress, extra_allow, caveats, retained)
    workspace_path = Path(workspace)
    plan = StagingPlan()

    if workspace_mode == "direct":
        workspace_path = _direct_workspace(scope)
        caveats.append(
            "workspace mounted directly: every file beneath it is in the guest "
            "namespace, so path scope is only as narrow as that directory")
    else:
        plan = build_staging_plan(repo_root=repo_root, lease=lease, scope=scope,
                                  extra_files=extra_files)
        if plan.refused:
            caveats.append(
                f"{len(plan.refused)} path(s) refused rather than staged; they "
                "are absent from the guest namespace (ENOENT, not EACCES)")

    if scope is not None and getattr(scope, "denied_paths", None):
        retained.append("denied_paths (no iVisor expression; enforced by staging refusal)")
    if lease is not None:
        retained.append("read-only lease files (/work is writable; write-back is filtered)")
    if any(getattr(egress, attribute, None)
           for attribute in ("allowed_recipients", "bind_recipients")):
        retained.append("recipient binding")
    retained.extend(("value/call budgets", "tool scope", "argument binding"))

    config = IVisorConfig(
        rootfs=str(rootfs), workspace=str(workspace_path), ram_mb=ram_mb,
        allow=tuple(sorted(allow)), listen=listen, sandbox=sandbox,
        comment=comment or "generated by agentauth.capabilities.sandbox")

    report = LoweringReport(lowered_domains=tuple(sorted(allow)),
                            retained_above=tuple(dict.fromkeys(retained)),
                            caveats=tuple(caveats), refused=plan.refused)
    return LoweredPolicy(config=config, staging=plan, report=report,
                         workspace_mode=workspace_mode,
                         extra_files=dict(extra_files or {}))


def _lower_egress(egress, extra_allow: Iterable[str], caveats: list[str],
                  retained: list[str]) -> set[str]:
    allow: set[str] = set()
    if egress is not None:
        if getattr(egress, "allow_all", False):
            # Refusing beats both alternatives: silently lowering to deny-all
            # would break the workload with no explanation, and there is no
            # wildcard rule in iVisor to widen with.
            raise LoweringError(
                "EgressPolicy.allow_all cannot lower to iVisor: it has no "
                "wildcard rule. Give an explicit domain set for the sandboxed "
                "run, or run this workload unsandboxed and rely on the broker.")
        domains = {str(d).strip().lower()
                   for d in getattr(egress, "allowed_domains", ()) or ()}
        for domain in sorted(domains):
            if not domain:
                continue
            host = domain.rsplit(":", 1)[0] if _has_port(domain) else domain
            if host != domain:
                caveats.append(
                    f"{domain!r} lowered as {host!r}: iVisor parses a port in an "
                    "allow entry but does not enforce it")
            allow.add(host)
        if domains:
            caveats.append(
                "iVisor matches allow entries exactly; EgressPolicy's "
                "subdomain-suffix rule does not lower, so the sandbox is "
                "strictly tighter than the broker on subdomains")
    for entry in extra_allow:
        allow.add(str(entry).strip().lower())

    for entry in sorted(allow):
        try:
            validate_allow_entry(entry)
        except AllowEntryError as exc:
            raise LoweringError(str(exc)) from exc
    return allow


def _has_port(domain: str) -> bool:
    _, sep, tail = domain.rpartition(":")
    return bool(sep) and tail.isdigit() and "]" not in tail


def _direct_workspace(scope) -> Path:
    paths = list(getattr(scope, "allowed_paths", ()) or ())
    if len(paths) != 1:
        raise LoweringError(
            "workspace_mode='direct' needs exactly one allowed path, got "
            f"{len(paths)}; use the default 'stage' mode to combine several")
    if getattr(scope, "denied_paths", None):
        raise LoweringError(
            "workspace_mode='direct' cannot honor denied_paths — mounting the "
            "directory puts every file beneath it in the guest namespace. Use "
            "'stage' mode, which omits denied files entirely.")
    return Path(paths[0])

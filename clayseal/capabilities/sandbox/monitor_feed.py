"""Lift iVisor's verdict stream into the behavioral layer's action stream.

The monitor reasons over `Action` sequences abstracted to `verb|tool|resource`
tokens. iVisor emits the one action stream an agent cannot misreport, so lifting
verdicts into the same vocabulary lets the existing detector, envelope, and
corpus tooling consume syscall-level ground truth with no changes of their own.

TWO DEFAULTS THAT MATTER:

* `verified_only`, a policy-shaped line the guest printed to its own stdout is
  a claim, not an observation. Feeding claims to a detector trains it on
  attacker-controlled input.
* `include_miss=False`, a MISS means the path was not in the guest namespace,
  which is not a refusal and not an attempt the agent chose; `fsmiss` runs emit
  hundreds per trivial program and would swamp the signal.

These are evidence, not authorization requests: one tool call produces many
syscalls, so lifted actions are appended to a trajectory for post-hoc scoring
and corpus building, never fed back through SessionBroker.authorize().
"""
from __future__ import annotations

import json
from collections.abc import Iterable

from clayseal.capabilities.monitor.action import Action, Trajectory
from clayseal.capabilities.sandbox.verdicts import PolicyEvent, Verdict

# Guest open(2) flags. aarch64 has no `open`, only `openat`, but the flag bits
# are the same: any of these means the guest asked for write access.
_O_WRONLY, _O_RDWR, _O_CREAT, _O_TRUNC = 0o1, 0o2, 0o100, 0o1000
_WRITE_FLAGS = _O_WRONLY | _O_RDWR | _O_CREAT | _O_TRUNC

# event name -> (verb, tool, resource scheme). fs.open resolves its verb from
# the open flags, so it is handled separately.
_EVENT_MAP = {
    "fs.rename": ("update", "ivisor.fs", "file"),
    "fs.unlink": ("delete", "ivisor.fs", "file"),
    "fs.rmdir": ("delete", "ivisor.fs", "file"),
    "fs.mkdir": ("create", "ivisor.fs", "file"),
    "fs.symlink": ("create", "ivisor.fs", "file"),
    "fs.stat": ("read", "ivisor.fs", "file"),
    "fs.readdir": ("read", "ivisor.fs", "file"),
    "fs.readlink": ("read", "ivisor.fs", "file"),
    "dns.query": ("read", "ivisor.dns", "net"),
    "net.connect": ("send", "ivisor.net", "net"),
    "net.udp": ("send", "ivisor.net", "net"),
    "net.bind": ("create", "ivisor.net", "net"),
    "net.listen": ("create", "ivisor.net", "net"),
    "proc.exec": ("exec", "ivisor.proc", "proc"),
}


def action_from_policy_event(event: PolicyEvent, *, step: int) -> Action | None:
    """Lift one verdict into a monitor Action, or None if it does not map."""
    if event.event == "fs.open":
        verb, tool, scheme = _open_verb(event), "ivisor.fs", "file"
    else:
        mapped = _EVENT_MAP.get(event.event)
        if mapped is None:
            return None
        verb, tool, scheme = mapped

    subject = event.subject()
    resource = f"{scheme}:{subject}" if subject else scheme
    args = {k: v for k, v in event.fields.items() if k != "verdict"}
    if "argv" in args:
        args["argv"] = _decode_argv(args["argv"])
    return Action(
        step=step, tool=tool, resource=resource, verb=verb, args=args,
        outcome=event.verdict.value,
        meta={"sandbox": "ivisor", "event": event.event,
              "verified": event.verified, "verdict": event.verdict.value},
    )


def actions_from_events(events: Iterable[PolicyEvent], *, start_step: int = 0,
                        include_miss: bool = False,
                        verified_only: bool = True) -> list[Action]:
    """Lift a verdict stream into an ordered action list."""
    out: list[Action] = []
    step = start_step
    for event in events:
        if verified_only and not event.verified:
            continue
        if not include_miss and event.verdict is Verdict.MISS:
            continue
        action = action_from_policy_event(event, step=step)
        if action is None:
            continue
        out.append(action)
        step += 1
    return out


def extend_trajectory(trajectory: Trajectory, events: Iterable[PolicyEvent],
                      **kwargs) -> Trajectory:
    """Append lifted syscall evidence to an existing trajectory."""
    actions = actions_from_events(events,
                                  start_step=len(trajectory.actions), **kwargs)
    trajectory.actions.extend(actions)
    return trajectory


def _open_verb(event: PolicyEvent) -> str:
    """read or write, from the open flags iVisor reports (e.g. `flags=0o1101`)."""
    raw = event.get("flags")
    if not raw:
        return "read"
    try:
        flags = int(raw, 0)
    except ValueError:
        return "read"
    return "write" if flags & _WRITE_FLAGS else "read"


def _decode_argv(raw: str):
    """argv arrives as a verbatim JSON array; give callers the list."""
    try:
        parsed = json.loads(raw)
    except ValueError:
        return raw
    return parsed if isinstance(parsed, list) else raw

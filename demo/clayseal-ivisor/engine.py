"""iVisor policy trace -> Clay Seal capability evaluation.

Parses iVisor's unforgeable fd-3 verdict stream, maps each verdict to a Clay
Seal `monitor.Action`, and evaluates it against a sealed `Capability` across
four real layers:

  A. structural envelope   TypedGoalEnvelope.assess   (verb / tool / class)
  B. egress capability     authorized-host set         (which destination)
  C. task-scope floor      task_scope_allows_path      (writable /work only)
  D. behavioral limit      SessionCallBudget           (egress volume) [BPL]

Layers A-C are per-action. Layer D is stateful across the session: it catches
exfiltration and beaconing that ride an *allowed* channel, which the syscall
floor cannot see. Every decision lands in a hash-chained DecisionLog.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field

from clayseal.capabilities.decision_log import DecisionLog
from clayseal.capabilities.monitor import Action

from capability import Capability

_LINE = re.compile(r"^(?:ivisor:\s*)?policy\s+(\S+)\s+verdict=(\w+)(.*)$")
_KV = re.compile(r"(\w+)=(\S+)")
_ARGV = re.compile(r"\bargv=(\[.*\])\s*$")
_O_ACCMODE, _O_WRONLY, _O_RDWR, _O_CREAT = 0o3, 0o1, 0o2, 0o100


# ---------------------------------------------------------------------------
@dataclass
class PolicyEvent:
    op: str
    verdict: str
    kv: dict[str, str]
    argv: str | None = None

    @property
    def tool(self) -> str:
        return {"proc": "process", "fs": "fs", "net": "net", "dns": "net"}.get(
            self.op.split(".", 1)[0], self.op.split(".", 1)[0])

    @property
    def path(self) -> str | None:
        return self.kv.get("path")

    @property
    def is_fs_write(self) -> bool:
        if not self.op.startswith("fs."):
            return False
        if self.op in ("fs.mkdir", "fs.create", "fs.symlink", "fs.rename", "fs.unlink"):
            return True
        if self.op == "fs.open":
            f = _int(self.kv.get("flags", "0"))
            return (f & _O_ACCMODE) in (_O_WRONLY, _O_RDWR) or bool(f & _O_CREAT)
        return False

    @property
    def verb(self) -> str:
        return {
            "proc.exec": "exec", "net.connect": "connect", "net.bind": "bind",
            "dns.query": "resolve",
        }.get(self.op, "write" if self.is_fs_write else
              "read" if self.op.startswith("fs.") else self.op.split(".", 1)[-1])

    @property
    def resource(self) -> str:
        if self.op == "proc.exec":
            return f"proc:{self.path or '?'}"
        if self.op == "net.connect":
            return f"net:{self.kv.get('dst','?')}"
        if self.op == "net.bind":
            return f"net:bind:{self.kv.get('port','?')}"
        if self.op == "dns.query":
            return f"net:{self.kv.get('name','?')}"
        if self.op.startswith("fs."):
            return f"file:{self.path or '?'}"
        return f"{self.tool}:{self.path or '?'}"

    @property
    def target(self) -> str:
        if self.op == "net.connect":
            return self.kv.get("dst", "?")
        if self.op == "dns.query":
            return self.kv.get("name", "?")
        if self.op == "net.bind":
            return f"port {self.kv.get('port','?')}"
        return self.path or "?"

    @property
    def is_bind_hardening(self) -> bool:
        # iVisor denies binding an ephemeral (inbound) port by default. That is
        # least-privilege network hardening, not the containment of an attack
        # benign tools trigger it and still complete. Bucketed separately.
        return self.op == "net.bind" and self.kv.get("reason") == "ephemeral-port"

    @property
    def is_policy_deny(self) -> bool:
        if self.verdict != "deny":
            return False
        if self.kv.get("reason") in ("not-allowlisted", "ingress-denied"):
            return True
        return self.kv.get("root") == "rootfs" and self.kv.get("errno") == "EROFS"


def _int(s: str) -> int:
    try:
        return int(s, 0)
    except ValueError:
        return 0


def parse_trace(text: str) -> list[PolicyEvent]:
    out: list[PolicyEvent] = []
    for raw in text.splitlines():
        m = _LINE.match(raw.strip())
        if not m:
            continue
        op, verdict, rest = m.groups()
        argv = None
        am = _ARGV.search(rest)
        if am:
            argv, rest = am.group(1), rest[: am.start()]
        out.append(PolicyEvent(op=op, verdict=verdict, kv=dict(_KV.findall(rest)), argv=argv))
    return out


# ---------------------------------------------------------------------------
def build_pin_map(events: list[PolicyEvent]) -> dict[str, str]:
    pin: dict[str, str] = {}
    for e in events:
        if e.op == "dns.query" and e.verdict == "allow":
            name = e.kv.get("name")
            for ip in (e.kv.get("ips") or "").split(","):
                if ip and name:
                    pin[ip] = name
    return pin


def host_for_dst(dst: str, pin: dict[str, str]) -> str | None:
    return pin.get(dst.rsplit(":", 1)[0])


# ---------------------------------------------------------------------------
@dataclass
class Decision:
    outcome: str                       # allow | deny
    layer: str                         # envelope | egress | task-scope | budget[BPL]
    reasons: tuple[str, ...] = field(default_factory=tuple)
    bpl: bool = False                  # decided by a behavioral-policy-limit layer


def evaluate(event: PolicyEvent, action: Action, cap: Capability,
             pin: dict[str, str], budget) -> Decision:
    # A. structural envelope
    ev = cap.envelope.assess(action)
    if not ev.in_envelope:
        return Decision("deny", "envelope", ev.reasons)

    # B + D apply to outbound connections
    if event.op == "net.connect":
        host = host_for_dst(event.kv.get("dst", ""), pin)
        if not cap.egress_authorized(host):
            dst = event.kv.get("dst", "?")
            where = f"host {host}" if host else "resolves to no sealed host"
            return Decision("deny", "egress",
                            (f"destination {dst} is not an authorized egress endpoint ({where})",))
        # D. behavioral limit, egress volume, even to an authorized host
        if budget is not None:
            res = budget.reserve("net.connect", {})
            if not res.allowed:
                return Decision("deny", "budget[BPL]",
                                (f"outbound-connect budget exhausted ({res.reason}); "
                                 f"beaconing/exfil over an allowed channel",), bpl=True)
            res.commit()

    # C. task-scope floor, writes only inside /work
    if event.is_fs_write and event.path is not None:
        if not cap.write_in_scope(event.path):
            return Decision("deny", "task-scope",
                            (f"write to {event.path} is outside the sealed workspace /work",))

    return Decision("allow", "envelope")


# ---------------------------------------------------------------------------
@dataclass
class Row:
    step: int
    event: PolicyEvent
    action: Action
    clay: Decision

    @property
    def security_relevant(self) -> bool:
        return self.clay.outcome == "deny" or self.event.is_policy_deny

    @property
    def agreement(self) -> str:
        cs_deny = self.clay.outcome == "deny"
        if self.event.verdict == "deny" and not self.event.is_policy_deny:
            return "operational"                         # transient errno
        iv_deny = self.event.is_policy_deny
        if iv_deny and cs_deny:
            return "agree-deny"
        if not iv_deny and not cs_deny:
            return "agree-allow"
        if not iv_deny and cs_deny:
            return "clayseal-only"                       # BPL catch beyond the floor
        return "ivisor-only"                             # floor stricter than capability


@dataclass
class Reconciliation:
    rows: list[Row]
    log: DecisionLog

    @property
    def violations(self) -> list[Row]:
        return [r for r in self.rows if r.clay.outcome == "deny"]

    def counts(self) -> dict[str, int]:
        c = dict(total=len(self.rows), clay_allow=0, clay_deny=0, bpl_deny=0,
                 ivisor_policy_deny=0, agree=0, clayseal_only=0, ivisor_only=0,
                 operational=0, policy_decisions=0)
        for r in self.rows:
            c["clay_allow" if r.clay.outcome == "allow" else "clay_deny"] += 1
            if r.clay.bpl and r.clay.outcome == "deny":
                c["bpl_deny"] += 1
            if r.event.is_policy_deny:
                c["ivisor_policy_deny"] += 1
            a = r.agreement
            if a == "operational":
                c["operational"] += 1
            else:
                c["policy_decisions"] += 1
                if a in ("agree-deny", "agree-allow"):
                    c["agree"] += 1
                elif a == "clayseal-only":
                    c["clayseal_only"] += 1
                elif a == "ivisor-only":
                    c["ivisor_only"] += 1
        return c


def reconcile(events: list[PolicyEvent], cap: Capability) -> Reconciliation:
    pin = build_pin_map(events)
    budget = cap.new_egress_budget()
    log = DecisionLog(session_id=cap.goal.query_id)
    rows: list[Row] = []
    for i, e in enumerate(events):
        action = Action(step=i, tool=e.tool, resource=e.resource, verb=e.verb,
                        outcome=e.verdict)
        d = evaluate(e, action, cap, pin, budget)
        h = hashlib.sha256(f"{e.op}|{e.resource}|{e.argv or ''}".encode()).hexdigest()[:16]
        log.append(query_id=cap.goal.query_id, tool=e.tool, resource=e.resource,
                   action_verb=e.verb, arguments_hash=h, outcome=d.outcome,
                   layer=d.layer, reasons=d.reasons)
        rows.append(Row(step=i, event=e, action=action, clay=d))
    return Reconciliation(rows=rows, log=log)

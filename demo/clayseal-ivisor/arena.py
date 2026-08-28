#!/usr/bin/env python3
"""Clay Seal × iVisor Arena, a live containment console.

Runs untrusted agent scenarios inside iVisor's HVF sandbox and shows, live, the
agent's actions beside iVisor's unforgeable policy verdicts, with breakout and
behavioral-policy-limit violations blocked in real time and mapped to MITRE
ATT&CK. Every run ends with a verifiable, hash-chained decision log.

    python arena.py list                 # the roster
    python arena.py run 07-beaconing     # one scenario, live
    python arena.py run 06-audit-evasion --audit   # + raw fd-3 firehose close
    python arena.py all                  # the whole roster
    python arena.py replay 01-cred-exfil sample_traces/01-cred-exfil.trace

With no arguments it prints the roster and asks which to run.

Register note: this is instrumentation, not a dashboard. Verdict lines are
iVisor's own output, verbatim. Color marks the block, nothing else.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import threading
from pathlib import Path

import engine
import scenarios as S

# aarch64 syscall numbers iVisor deliberately does not implement (escape surface)
_SYSCALL_NAMES = {40: "mount", 97: "unshare", 105: "init_module",
                  117: "ptrace", 268: "setns", 269: "pivot_root"}

# ---- restrained ANSI: color carries meaning, not decoration ---------------
_TTY = sys.stdout.isatty()
def _c(code, s): return f"\033[{code}m{s}\033[0m" if _TTY else s
def DIM(s): return _c("2", s)
def BOLD(s): return _c("1", s)
def RED(s): return _c("1;31", s)
def GRN(s): return _c("32", s)
def YEL(s): return _c("33", s)
def CYAN(s): return _c("36", s)
def INV_RED(s): return _c("1;41;97", s)     # block banner: inverse red

# iVisor's measured enforcement floor (BENCHMARKS.md); a real, cited figure,
# not a fabricated per-event timing.
FLOOR = "~0.9µs syscall floor (iVisor BENCHMARKS.md)"

A_GUT = DIM("A│ ")     # agent point of view
S_GUT = "S│ "          # sandbox verdict stream


def ivisor_dir() -> Path:
    for c in (Path.home() / "Projects" / "iVisor", Path.cwd() / "iVisor"):
        if (c / "Cargo.toml").exists():
            return c
    sys.exit("iVisor repo not found (expected ~/Projects/iVisor)")


# ---------------------------------------------------------------------------
class LiveRun:
    """Streams one scenario, evaluating verdicts against its capability live."""

    def __init__(self, scen: S.Scenario):
        self.scen = scen
        self.cap = scen.capability
        self.pin: dict[str, str] = {}
        self.budget = self.cap.new_egress_budget()
        self.log = engine.DecisionLog(session_id=self.cap.goal.query_id)
        self.rows: list[engine.Row] = []
        self.raw: list[str] = []                 # raw fd-3 lines for the audit hatch
        self.floor_denials = 0                   # ENOSYS at the syscall floor (escape surface)
        self.frames: list[dict] = []             # structured record for the report export
        self.quiet = False                       # suppress console (export mode)
        self._step = 0
        self._fseq = 0
        self._lock = threading.Lock()
        self._fs_allow_suppressed = 0

    # ---- rendering --------------------------------------------------------
    def _emit(self, line: str) -> None:
        if self.quiet:
            return
        with self._lock:
            sys.stdout.write(line + "\n")
            sys.stdout.flush()

    def _record(self, frame: dict) -> None:
        with self._lock:
            frame["seq"] = self._fseq
            self._fseq += 1
            self.frames.append(frame)

    def _render_verdict(self, e: engine.PolicyEvent) -> None:
        # keep the stream legible: fold routine in-workspace fs allows AND
        # operational noise (EACCES on dangling venv symlinks, ENOENT tool
        # probes), which are not policy decisions. Surface net/dns/exec and
        # every real containment verdict.
        is_operational = (
            e.verdict in ("deny", "miss")
            and not e.is_policy_deny and not e.is_bind_hardening
            and (e.op.startswith("fs.") or e.op == "proc.exec")
        )
        interesting = (
            e.op.startswith(("net.", "dns.")) or e.op == "proc.exec"
            or e.verdict == "deny"
        ) and not is_operational
        # evaluate against the sealed capability (stateful: pin + budget)
        if e.op == "dns.query" and e.verdict == "allow":
            for ip in (e.kv.get("ips") or "").split(","):
                if ip:
                    self.pin[ip] = e.kv.get("name", "")
        action = engine.Action(step=self._step, tool=e.tool, resource=e.resource,
                               verb=e.verb, outcome=e.verdict)
        d = engine.evaluate(e, action, self.cap, self.pin, self.budget)
        self.log.append(query_id=self.cap.goal.query_id, tool=e.tool,
                        resource=e.resource, action_verb=e.verb,
                        arguments_hash=f"{self._step:04d}", outcome=d.outcome,
                        layer=d.layer, reasons=d.reasons)
        row = engine.Row(step=self._step, event=e, action=action, clay=d)
        self.rows.append(row)
        self._step += 1

        raw = f"policy {e.op} verdict={e.verdict} " + " ".join(
            f"{k}={v}" for k, v in e.kv.items())
        hardening = e.is_bind_hardening
        blocked = (d.outcome == "deny" or e.is_policy_deny) and not hardening
        rec = self.log.records()[-1]
        self._record(dict(
            src="sandbox", op=e.op, verdict=e.verdict, verb=e.verb,
            resource=e.resource, kv=dict(e.kv), raw=raw,
            clay=dict(outcome=d.outcome, layer=d.layer, reasons=list(d.reasons), bpl=d.bpl),
            policy_deny=e.is_policy_deny,
            kind=("hardening" if hardening else
                  "bpl-block" if d.bpl and d.outcome == "deny" else
                  "block" if d.outcome == "deny" else
                  "floor-block" if e.is_policy_deny else
                  "allow" if interesting else "routine"),
            attack=list(self.scen.attack) if blocked else [],
            receipt=rec["receipt_hash"], prev=rec["prev_hash"]))

        if not interesting:
            self._fs_allow_suppressed += 1
            return

        # the block moment
        if hardening:
            self._emit(S_GUT + DIM(raw)
                       + DIM("   least-privilege: inbound bind denied, task unaffected"))
        elif blocked and d.outcome == "deny":
            tag = "BPL BLOCK" if d.bpl else "BLOCK"
            self._emit(S_GUT + INV_RED(f" {tag} ") + " " + raw)
            self._emit(S_GUT + "     " + RED(f"↳ Clay Seal {d.layer}: " + "; ".join(d.reasons)))
            self._emit(S_GUT + "     " + DIM(f"{', '.join(self.scen.attack)}  ·  {FLOOR}"))
        elif blocked and e.is_policy_deny:
            self._emit(S_GUT + INV_RED(" BLOCK ") + " " + raw)
            self._emit(S_GUT + "     " + DIM(f"iVisor floor  ·  {', '.join(self.scen.attack)}"))
        else:
            self._emit(S_GUT + DIM(raw))

    # ---- threads ----------------------------------------------------------
    def _pump_fd3(self, rfd: int) -> None:
        with os.fdopen(rfd, "r", buffering=1) as f:
            for line in f:
                line = line.rstrip("\n")
                if not line:
                    continue
                self.raw.append(line)
                evs = engine.parse_trace(line)
                if evs:
                    self._render_verdict(evs[0])

    def _pump_stdout(self, proc: subprocess.Popen) -> None:
        for line in proc.stdout:
            line = line.rstrip("\n")
            if line.startswith("[agent]"):
                text = line[len("[agent] "):]
                self._record(dict(src="agent", text=text, kind="agent"))
                self._emit(A_GUT + text)
            elif line.startswith("ivisor: ENOSYS"):
                m = re.search(r"syscall (\d+)", line)
                nr = int(m.group(1)) if m else -1
                if nr in _SYSCALL_NAMES:      # an actual escape primitive, denied
                    name = _SYSCALL_NAMES[nr]
                    self.floor_denials += 1
                    text = f"syscall {nr} ({name}) not implemented → escape primitive denied"
                    self._record(dict(src="floor", text=text, nr=nr, name=name, kind="floor",
                                      attack=list(self.scen.attack)))
                    self._emit(S_GUT + INV_RED(" FLOOR ") + " " + text)
                else:                          # benign unimplemented syscall; guest falls back
                    self._emit(S_GUT + DIM(line))
            elif line.startswith("ivisor:"):
                self._emit(S_GUT + DIM(line))
            elif line.strip() and not line.startswith(
                    ("Compiling", "Finished", "Running", "warning", "error[")):
                self._record(dict(src="agent", text=line, kind="agent-dim"))
                self._emit(A_GUT + DIM(line))

    # ---- run --------------------------------------------------------------
    def run(self, ivdir: Path) -> None:
        rootfs = ivdir / "guests" / "rootfs"
        if not (rootfs / "usr" / "bin" / "python3.13").exists():
            sys.exit("guest rootfs missing; run scripts/fetch-guest-rootfs.sh in the iVisor repo")

        ws = Path(subprocess.run(["mktemp", "-d"], capture_output=True, text=True).stdout.strip())
        (ws / "agent.py").write_text(self.scen.agent)
        (ws / ".env").write_text("AWS_SECRET_ACCESS_KEY=AKIA_loot_marker\n")

        env = dict(os.environ,
                   IVISOR_ROOTFS="guests/rootfs", IVISOR_WORKSPACE=str(ws),
                   IVISOR_ALLOW=self.scen.allow, IVISOR_TRACE="policy",
                   IVISOR_TRACE_FD="3")

        subprocess.run(["cargo", "build", "-q", "-p", "ivisor", "--bin", "ivisor"],
                       cwd=ivdir, env=env, check=True, capture_output=True)

        rfd, wfd = os.pipe()
        os.set_inheritable(wfd, True)
        cmd = ("exec cargo run -q -p ivisor --bin ivisor -- "
               f"run guests/rootfs/usr/bin/python3 -u /work/agent.py 3>&{wfd}")
        proc = subprocess.Popen(["bash", "-c", cmd], cwd=ivdir, env=env,
                                stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                pass_fds=(wfd,), text=True)
        os.close(wfd)

        t3 = threading.Thread(target=self._pump_fd3, args=(rfd,), daemon=True)
        t3.start()
        self._pump_stdout(proc)
        proc.wait()
        t3.join(timeout=5)


# ---------------------------------------------------------------------------
def header(scen: S.Scenario) -> None:
    print()
    print(BOLD(f"┌─ {scen.id}  {scen.name}"))
    print(f"│ premise : {scen.premise}")
    print(f"│ ATT&CK  : {CYAN(' · '.join(scen.attack))}")
    print(f"│ sealed  : egress={{{', '.join(sorted(scen.capability.egress_hosts))}}}  "
          f"write=/work" + (f"  egress-budget={scen.capability.egress_budget}"
                            if scen.capability.egress_budget else ""))
    print(f"│ star    : {YEL(scen.star)}")
    print(BOLD("└" + "─" * 70))
    print(DIM("  A│ = agent point of view   S│ = iVisor policy verdict (fd 3, unforgeable)"))
    print()


def summary(run: LiveRun) -> None:
    recon = engine.Reconciliation(rows=run.rows, log=run.log)
    c = recon.counts()
    ok, err = run.log.verify()
    print()
    print(DIM("── verdict ─────────────────────────────────────────────────────────"))
    blocked = [r for r in run.rows if (r.clay.outcome == "deny" or r.event.is_policy_deny)
               and not r.event.is_bind_hardening]
    hardening = sum(1 for r in run.rows if r.event.is_bind_hardening)
    total_blocked = len(blocked) + run.floor_denials
    print(f"  actions observed        : {c['total']}   "
          + DIM(f"({run._fs_allow_suppressed} routine/operational ops folded)"))
    print(f"  blocked                 : {RED(str(total_blocked))}  "
          f"({c['ivisor_policy_deny'] + run.floor_denials} at the iVisor floor, "
          f"{c['bpl_deny']} by the behavioral limit)")
    if hardening:
        print(f"  bind hardening          : {DIM(str(hardening) + '  (least-privilege inbound-bind denials, task unaffected)')}")
    # scenarios whose win is a non-event rather than a verdict line
    if run.scen.id == "06-audit-evasion":
        forged = any("6.6.6.6" in ln for ln in run.raw)
        print("  unforgeability          : "
              + (RED("FAILED, forged verdict entered the stream") if forged
                 else GRN("HELD") + DIM("  (guest fd 3 = OSError; forged verdict absent from the channel)")))
    if c["clayseal_only"]:
        print(f"  behavioral catches      : {YEL(str(c['clayseal_only']))}  "
              + DIM("(iVisor allowed the channel; Clay Seal blocked the pattern)"))
    if c["ivisor_only"]:
        print(f"  floor-only catches      : {c['ivisor_only']}  "
              + DIM("(iVisor floor stricter than the sealed capability)"))
    print(f"  operational (errno)     : {DIM(str(c['operational']))}")
    print(f"  decision log            : {GRN('VERIFIED') if ok else RED('FAILED ' + str(err))}"
          f"  {DIM(str(len(run.log.records())) + ' hash-chained receipts, head ' + run.log.head_hash[:20] + '…')}")
    print()


def audit_hatch(run: LiveRun) -> None:
    print(DIM("── raw audit channel (fd 3 firehose, verbatim) ─────────────────────"))
    print(DIM(f"  {len(run.raw)} verdict lines the guest could not read or forge. First 12 + last 6:"))
    for ln in run.raw[:12]:
        print("  " + DIM(ln))
    if len(run.raw) > 18:
        print(DIM("  …"))
    for ln in run.raw[-6:]:
        print("  " + DIM(ln))
    print(DIM("  decision-log receipt chain (tamper-evident):"))
    for rec in run.log.records()[:3]:
        act, dec = rec["action"], rec["decision"]
        print("  " + DIM(f"seq={rec['seq']} {act['verb']:>7} {act['resource'][:38]:<38} "
                         f"{dec['outcome']:<5} {rec['receipt_hash'].split(':')[-1][:16]}…"))
    print(DIM("  …"))
    print()


def run_scenario(scen: S.Scenario, ivdir: Path, audit: bool, save: bool = False) -> None:
    header(scen)
    run = LiveRun(scen)
    run.run(ivdir)
    summary(run)
    if audit:
        audit_hatch(run)
    if save and run.raw:
        out = Path(__file__).parent / "sample_traces" / f"{scen.id}.trace"
        out.write_text("\n".join(run.raw) + "\n")


def replay(scen: S.Scenario, trace_path: Path) -> None:
    header(scen)
    run = LiveRun(scen)
    for line in trace_path.read_text().splitlines():
        run.raw.append(line)
        evs = engine.parse_trace(line)
        if evs:
            run._render_verdict(evs[0])
    summary(run)


def build_record(run: LiveRun) -> dict:
    recon = engine.Reconciliation(rows=run.rows, log=run.log)
    c = recon.counts()
    ok, _ = run.log.verify()
    blocked = sum(1 for r in run.rows
                  if (r.clay.outcome == "deny" or r.event.is_policy_deny)
                  and not r.event.is_bind_hardening)
    hardening = sum(1 for r in run.rows if r.event.is_bind_hardening)
    scen = run.scen
    rec = dict(
        id=scen.id, name=scen.name, premise=scen.premise, attack=list(scen.attack),
        star=scen.star, expect=scen.expect, benign=getattr(scen, "benign", False),
        sealed=dict(egress=sorted(scen.capability.egress_hosts), writable="/work",
                    egress_budget=scen.capability.egress_budget),
        frames=run.frames, raw=run.raw,
        summary=dict(observed=c["total"], blocked=blocked + run.floor_denials,
                     floor_blocks=c["ivisor_policy_deny"] + run.floor_denials,
                     bpl_blocks=c["bpl_deny"], behavioral_catches=c["clayseal_only"],
                     hardening=hardening,
                     operational=c["operational"], folded=run._fs_allow_suppressed),
        log=dict(verified=ok, head=run.log.head_hash, receipts=len(run.log.records())),
    )
    if scen.id == "06-audit-evasion":
        rec["unforgeability_held"] = not any("6.6.6.6" in ln for ln in run.raw)
    return rec


def export( scenarios_, ivdir: Path, out: Path) -> None:
    records = []
    for s in scenarios_:
        run = LiveRun(s)
        run.quiet = True
        print(f"  running {s.id} …", file=sys.stderr)
        run.run(ivdir)
        records.append(build_record(run))
    out.write_text(json.dumps(records, indent=1))
    print(f"  wrote {out} ({len(records)} scenarios)", file=sys.stderr)


def list_roster() -> None:
    print(BOLD("\n  Clay Seal × iVisor Arena, scenario roster\n"))
    for s in S.ROSTER:
        print(f"  {BOLD(s.id):<28} {s.name}")
        print(f"  {'':<20} {DIM(' · '.join(s.attack))}")
    print(DIM("\n  run:  python arena.py run <id> [--audit]   ·   all:  python arena.py all\n"))


def main() -> None:
    a = sys.argv[1:]
    if not a:
        list_roster()
        choice = input("  scenario id (or 'all'): ").strip()
        a = ["all"] if choice == "all" else ["run", choice]
    cmd = a[0]
    if cmd == "list":
        return list_roster()
    ivdir = ivisor_dir()
    if cmd == "all":
        for s in S.ROSTER:
            run_scenario(s, ivdir, audit=False, save=True)
    elif cmd == "run":
        scen = S.BY_ID.get(a[1]) if len(a) > 1 else None
        if not scen:
            sys.exit(f"unknown scenario '{a[1] if len(a)>1 else ''}' (try: python arena.py list)")
        run_scenario(scen, ivdir, audit="--audit" in a)
    elif cmd == "replay":
        scen = S.BY_ID.get(a[1])
        replay(scen, Path(a[2]))
    elif cmd == "export":
        out = Path(__file__).parent / "report_data.json"
        if len(a) > 1 and a[1] != "all":
            # refresh only the named scenarios, merged into the existing file
            existing = {r["id"]: r for r in json.loads(out.read_text())} if out.exists() else {}
            for sid in a[1:]:
                s = S.BY_ID[sid]
                run = LiveRun(s)
                run.quiet = True
                print(f"  running {s.id} …", file=sys.stderr)
                run.run(ivdir)
                existing[s.id] = build_record(run)
            order = [x.id for x in S.ROSTER]
            out.write_text(json.dumps([existing[i] for i in order if i in existing], indent=1))
            print(f"  merged {len(a) - 1} scenario(s) into {out}", file=sys.stderr)
        else:
            export(S.ROSTER, ivdir, out)
    elif cmd == "live":
        import tui
        scs = S.ROSTER if (len(a) < 2 or a[1] == "all") else [S.BY_ID.get(a[1])]
        if scs == [None]:
            sys.exit(f"unknown scenario '{a[1]}' (try: python arena.py list)")
        for s in scs:
            tui.run_live(s, ivdir)
    elif cmd == "review":
        import tui
        store = Path(__file__).parent / "results.json"
        if not store.exists():
            store = Path(__file__).parent / "report_data.json"
        if not store.exists():
            sys.exit("no saved results yet, run `arena.py live all` or `arena.py export all` first")
        records = json.loads(store.read_text())
        if len(a) > 1 and a[1] != "all":
            records = [r for r in records if r["id"] == a[1]]
            if not records:
                sys.exit(f"no saved result for '{a[1]}'")
        tui.render_review(records)
    else:
        sys.exit(__doc__)


if __name__ == "__main__":
    main()

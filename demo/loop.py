"""The step loop: signals in, a recompiled policy out, then run the call.

THE ORDER OF OPERATIONS IS THE ARGUMENT. For each tool call:

  1. signals, computed from the trajectory PREFIX; the pending call is not
                 an input, so the policy about to govern it cannot have been
                 influenced by it
  2. level, `max(current, want)`, so tighten-only by construction
  3. recompile, only if the level moved; a new epoch means a new run dir, a
                 new immutable config and a new digest
  4. broker, the tool-level gate, if enabled
  5. sandbox, run under the epoch's config; verdicts stream back verified
  6. lift, verified verdicts into the EVIDENCE trajectory (never the
                 broker's, see `signals.DemoTrajectory`)
  7. register, the tool's return as untrusted context

Because step 1 precedes step 3, the first exfil attempt is refused under the
UNCHANGED baseline policy, with `#0 BASELINE` still on the rail. Tightening is
visibly downstream of that refusal.
"""
from __future__ import annotations

import time
from collections.abc import Callable
from dataclasses import dataclass, field, replace
from pathlib import Path

from clayseal.capabilities.broker import Outcome, SessionBroker
from clayseal.capabilities.hardening.egress_policy import EgressPolicy
from clayseal.capabilities.monitor.action import Action, Trajectory
from clayseal.capabilities.sandbox.monitor_feed import extend_trajectory
from clayseal.capabilities.sandbox.session import run_sandboxed
from clayseal.capabilities.scoping.goal import GoalSpec
from demo.epoch import PolicyEpoch, open_epoch, spec_for
from demo.escalation import Level, next_level, policy_for
from demo.plan import classify_verb, envelope_for_tools
from demo.signals import DemoTrajectory, compute_signals
from demo.state import (
    AgentSaid,
    AgentToolCall,
    AgentToolResult,
    BrokerDecided,
    EpochOpened,
    Event,
    GuestOutput,
    Note,
    RunEnd,
    VerdictLine,
)
from demo.taint import derive_sources, untrusted_return


@dataclass
class RunConfig:
    scenario: object
    provider: object
    run_root: Path
    ivisor_bin: str
    rootfs: str
    gate: str = "broker"
    max_turns: int = 14
    fake_guest: bool = False
    scratch: Path | None = None


@dataclass
class _Clock:
    """Monotonic milliseconds since the run began, so recordings replay evenly."""

    _t0: float = field(default_factory=time.monotonic)

    def __call__(self) -> int:
        return int((time.monotonic() - self._t0) * 1000)


def run_demo(config: RunConfig, emit: Callable[[Event], None]) -> int:
    scen = config.scenario
    provider = config.provider
    now = _Clock()
    sealed = scen.seal()

    broker = _make_broker(sealed) if config.gate == "broker" else None
    if broker is None:
        emit(Note(at_ms=now(), text=(
            "--gate none: no tool-level gate. Whatever refuses the agent from "
            "here is the sandbox alone.")))

    traj = DemoTrajectory()
    evidence = Trajectory(goal=_goal(sealed), actions=[], context=[])
    epoch: PolicyEpoch | None = None
    step = 0

    provider.start(scen.system_prompt, scen.user_prompt)

    for _ in range(config.max_turns):
        calls = provider.next_calls()
        if not calls:
            break
        for call in calls:
            emit(AgentToolCall(at_ms=now(), step=step, call_id=call.id,
                               tool=call.tool, args=dict(call.args)))

            # 1-3. Signals from the prefix, level, and (if it moved) a recompile.
            signals = compute_signals(traj, evidence,
                                      level=epoch.level if epoch else Level.BASELINE)
            level, why = next_level(epoch.level if epoch else Level.BASELINE,
                                    signals)
            if epoch is None or level != epoch.level:
                epoch = _recompile(config, sealed, level, why, epoch, broker,
                                   traj, step, emit, now)

            # 4. Provenance, then the tool-level gate.
            sources = derive_sources(call.args, traj.returns, sealed.text)
            action = Action(step=step, tool=call.tool,
                            resource=f"mcp:tool:{call.tool}",
                            verb=classify_verb(call.tool), args=dict(call.args),
                            derived_from=sources)
            traj.attempted.append(action)

            if broker is not None:
                decision = broker.authorize(action)
                emit(BrokerDecided(at_ms=now(), step=step, tool=call.tool,
                                   outcome=decision.outcome.name,
                                   layer=decision.layer,
                                   reasons=tuple(decision.reasons)))
                if decision.outcome is not Outcome.ALLOW:
                    traj.broker_denials += 1
                    if decision.layer == "intent-envelope":
                        traj.off_envelope_consequential = True
                    text = (f"[DENIED by policy: {decision.layer}] "
                            f"{'; '.join(decision.reasons)}")
                    provider.observe(call.id, text)
                    emit(AgentToolResult(at_ms=now(), step=step,
                                         call_id=call.id, text=text, ok=False))
                    step += 1
                    continue

            # 5. Run it, under this epoch's immutable policy.
            outcome = _execute(config, epoch, call, emit, now, step)
            epoch.adopt(outcome)

            # 6. Verified verdicts into the evidence trajectory only.
            extend_trajectory(evidence, outcome.result.events)
            traj.verified_events.extend(outcome.result.events)

            # 7. The return is untrusted context, by provenance.
            item = untrusted_return(step, call.tool)
            traj.returns.append((item, outcome.result.stdout))
            evidence.context = [*evidence.context, item]
            if broker is not None:
                broker.observe_context(item)

            text = outcome.result.stdout.strip() or "(no output)"
            provider.observe(call.id, text)
            emit(AgentToolResult(at_ms=now(), step=step, call_id=call.id,
                                 text=text, ok=True))
            step += 1

    closing = provider.final_text()
    if closing:
        emit(AgentSaid(at_ms=now(), text=closing))
    emit(RunEnd(at_ms=now(), exit_kind="finished", code=0))
    return 0


def _recompile(config, sealed, level, why, prev, broker, traj, step, emit, now):
    caps = policy_for(level, sealed)
    index = 0 if prev is None else prev.index + 1
    changed = prev is None or caps != prev.caps

    if not changed:
        # The level moved but the capabilities did not, L1 is a notice, not a
        # new policy. Keep the compiled config, the run dir, and therefore the
        # digest, so "digest unchanged" on the rail is literally true rather
        # than a caption. Re-staging into a fresh directory here would change
        # the workspace path, change the digest, and quietly make the display
        # claim something the artifact contradicts.
        epoch = replace(prev, index=index, level=level, why=why, changed=False)
    else:
        epoch = open_epoch(caps, level=level, index=index,
                           run_root=config.run_root, rootfs=config.rootfs,
                           scenario=config.scenario, prev=prev, why=why,
                           changed=True)

    if level >= Level.CONTAINED and traj.contained_at_step is None:
        traj.contained_at_step = len(traj.verified_events)

    if broker is not None and changed:
        # Re-clear the ENVELOPE only, the tool scope, which `enforced_at` marks
        # as the broker's job. The egress set is deliberately NOT narrowed here.
        #
        # Narrowing it would be double-counting, and it would quietly destroy
        # the demo's central claim: the internal-relay attempt is supposed to be
        # one the tool-level gate has no grounds to refuse, so that whatever
        # stops it is provably the recompiled sandbox. If the broker's egress
        # tightened in lockstep, the broker would refuse first, the guest would
        # never run, and a green expectation set would be proving nothing about
        # the syscall boundary at all. The broker keeps the envelope it sealed
        # at t0; that is the static guarantee, and it is a separate claim.
        broker.reclear(envelope_for_tools(tuple(sorted(caps.allowed_tools))))
        broker.decision_log.append(
            query_id=sealed.query_id, tool="<epoch>",
            resource=f"policy:epoch/{epoch.index}", action_verb="tighten",
            arguments_hash=epoch.digest, outcome="allow",
            layer="control-plane", reasons=tuple(why))

    emit(EpochOpened(at_ms=now(), index=epoch.index, level=int(level),
                     level_name=level.name, why=tuple(why), digest=epoch.digest,
                     allow=tuple(epoch.allow), staged=len(epoch.base_files),
                     carry_forward=tuple(caps.carry_forward),
                     enforced_at=dict(caps.enforced_at),
                     config_text=epoch.config_text, changed=changed))
    return epoch


def _execute(config, epoch, call, emit, now, step):
    extra: dict[str, Path] = {}
    scratch = config.scratch or (config.run_root / "_scratch")
    summary_text = str(call.args.get("text", ""))

    if call.tool == "write_summary" and summary_text:
        scratch.mkdir(parents=True, exist_ok=True)
        staged = scratch / "summary_input.txt"
        staged.write_text(summary_text)
        extra["task/summary_input.txt"] = staged

    spec = spec_for(epoch, call.tool, dict(call.args), scenario=config.scenario,
                    rootfs=config.rootfs, ivisor_bin=config.ivisor_bin,
                    extra_files=extra)

    if config.fake_guest:
        from demo.providers.fake_guest import synthesize

        scratch.mkdir(parents=True, exist_ok=True)
        script = synthesize(call.tool, dict(call.args), epoch=epoch,
                            scenario=config.scenario,
                            path=scratch / f"guest-{step}.json",
                            summary_text=summary_text)
        spec.elf = str(script)
        spec.guest_args = ()

    outcome = run_sandboxed(spec, on_event=lambda e: emit(
        VerdictLine(at_ms=now(), step=step, raw=_render(e), verified=True)))

    for claim in outcome.result.unverified_claims:
        emit(VerdictLine(at_ms=now(), step=step, raw=_render(claim),
                         verified=False))
    for stream, text in (("stdout", outcome.result.stdout),
                         ("stderr", outcome.result.stderr)):
        if text.strip():
            emit(GuestOutput(at_ms=now(), step=step, stream=stream, text=text))
    return outcome


def _render(event) -> str:
    """Re-render a parsed verdict as its wire line, so the reducer re-parses it.

    Deliberately round-tripping rather than passing the object through: the
    reducer's `verified` decision must be made in exactly one place, and a
    recording has to contain the same text a live run saw.
    """
    fields = " ".join(f"{k}={v}" for k, v in event.fields.items() if k != "verdict")
    return (f"ivisor: policy {event.event} verdict={event.verdict.value}"
            f"{' ' + fields if fields else ''}")


def _goal(sealed) -> GoalSpec:
    return GoalSpec(query_id=sealed.query_id, summary=sealed.text,
                    allow_resources=[f"mcp:tool:{t}" for t in sealed.tools],
                    structured_intent={"verbs": ["read", "list", "write", "send"]})


def _make_broker(sealed) -> SessionBroker:
    caps = policy_for(Level.BASELINE, sealed)
    return SessionBroker(
        goal=_goal(sealed),
        scope=None,
        intent_envelope=envelope_for_tools(tuple(sorted(caps.allowed_tools))),
        egress=EgressPolicy(allowed_domains=set(caps.egress_domains)),
    )

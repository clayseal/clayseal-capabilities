"""Intent advisory, soft signal for in-surface / content-same-dest harm.

Per-call authorization binds *where* an action points. When harm is defined by
what the action *says* (AgentHarm deepfake prompt, SLEIGHT sed-line sabotage on
an authorized path), the destination check is silent. ARGUS's entailment
verifier is the published answer; it puts a model in the decision path.

This module is the subordination we already use for the statistical detector:
it may ESCALATE, never hard-block on its own. Deterministic signals first:

1. **Digest delta vs declared plan**, same destination, different write body
   than the commit-then-reveal declaration. Deployable (no benign twin). The
   twin corridor already hard-blocks this when a reference exists; the advisory
   surfaces the same evidence on the soft path when the corridor is off or the
   action is still under review.
2. **Optional judge**, ``judge(action, goal_text) -> str | None``. A caller may
   plug an LLM entailment check; a non-None reason escalates. The default is no
   judge, so the core stays model-free.

Do not put keyword "secret/curl" heuristics here: measured 18/43 false flags on
honest SLEIGHT benign plans (legit credential-scan and monitoring tasks).
"""
from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass

from clayseal.capabilities.monitor.action import Action, Trajectory, path_hint
from clayseal.capabilities.monitor.consequence import is_consequential
from clayseal.capabilities.monitor.sealed_plan import _write_body

Judge = Callable[[Action, str], str | None]

# ``cat > path <<EOF`` / ``tee path``, path_hint often misses these when the
# loader did not put the path in meta (unit tests; some live Bash writes).
_REDIRECT_DEST = re.compile(
    r"(?:(?:cat|tee)\s+>\s*|tee\s+)(?P<path>/[^\s;|&]+|\./[^\s;|&]+)",
)


def _digest(text: str) -> str:
    import hashlib
    return hashlib.sha256(text.encode()).hexdigest()


def _body(action: Action) -> str:
    return (_write_body(action) or str(action.args.get("command") or "")
            or str(action.args.get("content") or "")
            or str(action.args.get("body") or "")
            or str(action.args.get("prompt") or ""))


def _dest(action: Action) -> str:
    hint = path_hint(action) or str(
        action.args.get("file_path") or action.args.get("path") or "")
    if hint:
        return hint
    cmd = str(action.args.get("command") or "")
    m = _REDIRECT_DEST.search(cmd)
    return m.group("path") if m else ""


def _declared_bodies_by_dest(declaration: Trajectory) -> dict[str, set[str]]:
    out: dict[str, set[str]] = {}
    for action in declaration.actions:
        dest = _dest(action)
        body = _body(action)
        if not dest or not body.strip():
            continue
        out.setdefault(dest, set()).add(_digest(body))
    return out


@dataclass(frozen=True)
class AdvisoryVerdict:
    escalate: bool
    reasons: tuple[str, ...] = ()

    @property
    def flagged(self) -> bool:
        return self.escalate


def assess_intent_advisory(
    traj: Trajectory,
    *,
    declaration: Trajectory | None = None,
    goal_text: str = "",
    judge: Judge | None = None,
) -> AdvisoryVerdict:
    """Soft content / intent signals over a trajectory. Never a hard block."""
    reasons: list[str] = []
    declared = _declared_bodies_by_dest(declaration) if declaration else {}

    for action in traj.actions:
        dest = _dest(action)
        body = _body(action)
        if (
            declaration is not None
            and dest
            and body.strip()
            and dest in declared
            and _digest(body) not in declared[dest]
            and is_consequential(action)
        ):
            reasons.append(
                f"intent-advisory: digΔ vs declaration at {dest!r} "
                f"on consequential {action.tool}"
            )
        if judge is not None and is_consequential(action):
            why = judge(action, goal_text)
            if why:
                reasons.append(f"intent-advisory: {why}")

    # Dedup while preserving order
    seen: set[str] = set()
    uniq: list[str] = []
    for r in reasons:
        if r not in seen:
            seen.add(r)
            uniq.append(r)
    return AdvisoryVerdict(escalate=bool(uniq), reasons=tuple(uniq))

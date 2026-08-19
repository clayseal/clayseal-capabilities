"""Runtime replanning: grow the plan from trusted input instead of denying deviation.

## Why this exists

The intent envelope compiles a plan from the sealed goal before execution and
hard-denies consequential actions that deviate from it. On AgentDojo that rule
accounts for 100% of our hard false blocks and costs utility at the margin. On
AgentDyn (arXiv:2602.03117), whose tasks are built so the correct next step
cannot be known in advance, it costs **everything**: zero clean utility on both
the shopping and github suites, with 254 of 281 actions blocked and 21.67
human interruptions per task. See benchmarks/results/agentdyn.md.

## Why the obvious fix is wrong

We already tried simply allowing the deviation when the binding floor had
cleared the destination (`defer_allows_bound`). It took travel from 5.6% to
27.8% ASR and workspace from 0.0% to 27.8%. The plan check does real containment
work that the floor does not, so it cannot be dropped. It has to be **extended**.

## The trust boundary, which is the entire security argument

An injection lives in tool output. Therefore the replanner never reads tool
output. It is given exactly three things:

1. the **sealed goal**, captured before any tool result could contaminate it;
2. the **tool catalog**, which is static configuration;
3. the **shape** of the action being requested: tool name and verb class only.

It is *not* given argument values, tool results, retrieved documents, or any
other runtime content. An injected instruction can cause the agent to *request*
an action, and that request is then judged against the goal alone. The injection
never reaches the judge.

Argument values stay bound by the floor. That separation is what makes this
different from `defer_allows_bound`: the shape check survives, and only the plan
it is checked against is allowed to grow.

So an attacker needs two independent things to land an action: a shape the goal
plausibly implies, AND a destination the floor accepts. The floor already denies
the second for injected destinations, which is why banking held at 0% ASR
throughout.

## How this compares to the published mechanisms

AuthGraph (arXiv:2605.26497) extends at runtime too, but its replan Planner
*does* receive the untrusted observation. Its containment comes from a
`replan_allowed_tools` whitelist computed in the clean context and enforced
programmatically, so an attacker can steer which whitelisted tool is chosen but
cannot enlarge the set. The authors are explicit that this leaves a residual
hole they call envelope-internal redirection, and they exclude two AgentDyn
cases from their reported metrics because roughly 40% of that benchmark's tasks
explicitly delegate trust to observation content.

We take the stricter position: the observation never reaches the judge at all.
That costs us the ability to justify a step that only makes sense given what was
observed, and it buys a trust boundary with no carve-out. If measurement shows
the strict version leaves too much utility on the table, the whitelist approach
is the documented fallback, and it should be adopted knowingly rather than by
drifting into it.

DRIFT (arXiv:2506.12104) supplies the one clean number for what this kind of
mechanism is worth: its ablation moves benign utility from 37.71% to 59.79% for
an ASR cost of 1.49% to 3.66%. Roughly twenty-two points of utility for two of
attack success. Its judge sees tool names and the trusted user query, and (in
the shipped code) not the observation, which is closer to our position than to
AuthGraph's. Its exception path fails open; ours fails closed.

## What it cannot do

If the goal genuinely implies the shape of the attacker's action, this extends
to cover it. A goal of "handle my email" plausibly implies sending email, so an
injected send is shape-consistent and only the destination check stops it. That
is the correct division of labour rather than a gap in this module, but it means
replanning must never be deployed without destination binding underneath it.
"""
from __future__ import annotations

import json
import re
import threading
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any, Protocol

# Verb classes. The replanner judges these rather than tool names alone, so that
# "the goal needs to send things" generalises across send_email, post_message
# and so on without granting every tool in the catalog.
_VERB_CLASS = {
    "send": "communicate", "post": "communicate", "share": "communicate",
    "transfer": "move_value", "pay": "move_value",
    "write": "modify", "create": "modify", "update": "modify",
    "delete": "destroy",
    "execute": "execute", "call": "invoke",
    "read": "observe", "search": "observe", "list": "observe",
}


def verb_class(verb: str) -> str:
    return _VERB_CLASS.get(verb, verb)


@dataclass(frozen=True)
class ActionShape:
    """Everything the replanner is allowed to know about a requested action.

    Deliberately not a dataclass over the whole Action: constructing it is where
    argument values get dropped, and doing that at the type level means a future
    caller cannot accidentally pass them through.
    """

    tool: str
    verb_class: str

    @classmethod
    def of(cls, tool: str, verb: str) -> ActionShape:
        return cls(tool=tool, verb_class=verb_class(verb))

    def describe(self) -> str:
        return f"{self.tool} ({self.verb_class})"


@dataclass(frozen=True)
class ReplanVerdict:
    extended: bool
    reason: str
    shape: ActionShape | None = None


class ShapeJudge(Protocol):
    """Decides whether a goal plausibly requires an action of this shape."""

    def __call__(self, goal: str, catalog: list[str], shape: ActionShape) -> tuple[bool, str]:
        ...


def catalog_shape_judge(
    *,
    allowed_classes: set[str] | None = None,
) -> ShapeJudge:
    """Trusted-input shape judge with no model (catalog + sealed goal only).

    Admits a shape when the tool is in the static catalog and either its verb
    class is in ``allowed_classes``, a significant tool-name token appears in
    the sealed goal, or the verb class is observational. Never sees argument
    values or tool results — same trust boundary as :func:`llm_shape_judge`.
    """

    allowed = set(allowed_classes or ())

    def judge(goal: str, catalog: list[str], shape: ActionShape) -> tuple[bool, str]:
        cat_l = {c.lower() for c in catalog}
        if shape.tool not in catalog and shape.tool.lower() not in cat_l:
            return False, f"tool {shape.tool!r} not in session catalog"
        if shape.verb_class in {"observe", "invoke"}:
            return True, f"{shape.verb_class} is observational / in-catalog"
        if allowed and shape.verb_class in allowed:
            return True, f"verb class {shape.verb_class!r} permitted by mandate"
        g = (goal or "").lower()
        tokens = [
            t for t in re.split(r"[^a-z0-9]+", shape.tool.lower()) if len(t) >= 4
        ]
        if tokens and any(t in g for t in tokens):
            return True, f"tool token implied by sealed goal ({tokens[0]!r})"
        return False, (
            f"shape {shape.describe()} not implied by sealed goal "
            f"and not in allowed classes {sorted(allowed) or '∅'}"
        )

    return judge


def deterministic_judge(allowed_classes: set[str]) -> ShapeJudge:
    """A judge with no model in it, for tests and for offline replay.

    Admits a shape when its verb class is one the mandate already permits. This
    is weaker than asking whether the goal *implies* the step, and it is
    deliberately available so the mechanism can be exercised without inference.
    """

    def judge(goal: str, catalog: list[str], shape: ActionShape) -> tuple[bool, str]:
        if shape.tool not in catalog:
            return False, f"{shape.tool} is not in the granted tool catalog"
        if shape.verb_class not in allowed_classes:
            return False, f"verb class {shape.verb_class!r} is outside the mandate"
        return True, f"{shape.describe()} is within the granted classes"

    return judge


def llm_shape_judge(client: Any, model: str) -> ShapeJudge:
    """Ask a model whether the sealed goal plausibly requires this shape.

    The prompt contains the goal, the catalog, and the shape. It contains no
    tool output and no argument values, which is the property the whole design
    rests on. Read the prompt below before changing it: adding runtime content
    here silently removes the trust boundary.
    """

    def judge(goal: str, catalog: list[str], shape: ActionShape) -> tuple[bool, str]:
        prompt = (
            "You are a security planner deciding whether a task legitimately "
            "requires a KIND of action. You are judging the shape of the action "
            "only, never its target or contents.\n\n"
            f"The user's request (trusted, fixed before execution): {goal}\n\n"
            f"Tools available: {', '.join(sorted(catalog))}\n\n"
            f"The agent now wants to use: {shape.tool}, which is a "
            f"{shape.verb_class} action.\n\n"
            "Could a faithful execution of the user's request plausibly need an "
            "action of this kind? Answer for the KIND of action, not for any "
            "specific recipient, file or amount.\n\n"
            'Return JSON: {"required": true|false, "why": "one short sentence"}.'
        )
        try:
            resp = client.chat.completions.create(
                model=model, temperature=0,
                response_format={"type": "json_object"},
                messages=[{"role": "user", "content": prompt}])
            data = json.loads(resp.choices[0].message.content)
            required = bool(data.get("required"))
            why = str(data.get("why", ""))[:160]
            return required, why or ("shape consistent with the goal" if required
                                     else "shape not implied by the goal")
        except Exception as exc:  # noqa: BLE001 - total by contract, fails closed
            # Fail CLOSED. A planner outage must not silently widen authority,
            # and the caller's existing deny path is the safe default.
            return False, f"shape judge unavailable ({type(exc).__name__})"

    return judge


@dataclass
class PlanExtender:
    """Grows a session's authorized shapes, from trusted input only.

    Extensions are remembered for the session, so an agent that legitimately
    needs to send three emails is judged once rather than three times. They are
    also bounded: `max_extensions` caps how far a plan may grow, because an
    unbounded extender converges on allow-all given a long enough session.
    """

    judge: ShapeJudge
    goal: str
    catalog: list[str]
    max_extensions: int = 8
    _granted: set[ActionShape] = field(default_factory=set)
    _refused: dict[ActionShape, str] = field(default_factory=dict)
    _lock: Any = field(default_factory=threading.RLock, repr=False, compare=False)
    on_extend: Callable[[ReplanVerdict], None] | None = None

    @property
    def granted_shapes(self) -> set[ActionShape]:
        with self._lock:
            return set(self._granted)

    def consider(self, tool: str, verb: str) -> ReplanVerdict:
        """May the plan grow to include an action of this shape?"""
        shape = ActionShape.of(tool, verb)
        with self._lock:
            if shape in self._granted:
                return ReplanVerdict(True, "shape already cleared this session", shape)
            if shape in self._refused:
                return ReplanVerdict(False, self._refused[shape], shape)
            if len(self._granted) >= self.max_extensions:
                return ReplanVerdict(
                    False,
                    f"plan already extended {self.max_extensions} times this session",
                    shape,
                )

        ok, why = self.judge(self.goal, self.catalog, shape)
        verdict = ReplanVerdict(ok, why, shape)
        with self._lock:
            if ok:
                self._granted.add(shape)
            else:
                self._refused[shape] = why
        if self.on_extend is not None:
            self.on_extend(verdict)
        return verdict

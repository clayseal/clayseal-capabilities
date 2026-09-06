"""One adapter, over the shape every agent framework already has.

WHY NOT FOUR ADAPTERS

The obvious move is a LangGraph adapter, an OpenAI Agents SDK adapter, a
CrewAI adapter and one for whatever ships next quarter. Each would import a
framework this library does not otherwise need, each would break when that
framework's tool interface changes, and the four would drift.

They all agree on one thing: a tool is a **named callable taking keyword
arguments**. LangChain's `BaseTool` is one, the OpenAI Agents SDK's function
tools are, the Anthropic SDK's tool runner takes a dict of them, and a
hand-written loop is a dict of them. So the adapter is over that, and attaching
it is a line of framework-specific glue the caller writes rather than a
dependency this package carries.

WHAT IT DOES THAT A CALLER WOULD OTHERWISE FORGET

Three things, and each is silent when missed, which is the reason they belong in
the library rather than in an integration guide.

**The verb and the path argument come from the policy.** A tool authorized with
the wrong verb gets the wrong floor rules; a path the gateway cannot find means
the path scope never applies to that tool. `McpProxy.from_policy` exists for the
same reason and this is its in-process twin.

**A refusal reaches the model as a tool error.** An agent that is told "refused:
over the 24-hour ceiling" can say so to the user or take another route. One that
gets an unhandled exception, or worse a silent skip, cannot. `Refused` and
`StepUpRequired` are distinct because the second is a question and the first is
an answer.

**The result is fed back.** Provenance, taint, the confidentiality tracker and
every conditional fact read what a tool RETURNED. A wrapper that authorizes and
forgets to report the result leaves all of them starved, and the benchmark
harness measured exactly that: an adaptive run against a stack with no
`observe_output` returned numbers byte-identical to its floor rung, with every
observation-driven layer quiet rather than absent.
"""
from __future__ import annotations

import asyncio
import inspect
import json
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from typing import Any

from clayseal.capabilities.reasons import explained


class GuardrailError(RuntimeError):
    """Base for anything this adapter raises in place of running a tool."""


class Refused(GuardrailError):
    """The gateway denied the call. The agent may read this and adapt.

    ``reasons`` holds the stable codes to match on. The message carries the
    explained form, because this is the string that gets handed back to an agent
    and `value_budget_exceeded` on its own says nothing about what to do
    instead. Both are available: ``exc.reasons`` for code, ``str(exc)`` for a
    person or a model.
    """

    def __init__(self, tool: str, reasons: tuple[str, ...]) -> None:
        self.tool = tool
        self.reasons = tuple(reasons)
        self.explanations = explained(self.reasons)
        super().__init__(
            f"{tool} was refused by policy: "
            f"{'; '.join(self.explanations) or 'no reason recorded'}")


class StepUpRequired(GuardrailError):
    """The gateway asked for a human. A question, not an answer.

    Separate from `Refused` because a caller that treats them alike turns a
    supervised deployment into an autonomous one, or into a deployment that
    cannot act at all. Carries the request so a control plane can present it.
    """

    def __init__(self, tool: str, reasons: tuple[str, ...],
                 request: Any = None) -> None:
        self.tool = tool
        self.reasons = tuple(reasons)
        self.request = request
        self.explanations = explained(self.reasons)
        super().__init__(
            f"{tool} needs approval: "
            f"{'; '.join(self.explanations) or 'no reason recorded'}")


def _payload(result: Any) -> tuple[str, dict[str, Any] | None]:
    """A tool's return value as text, plus its named fields if it has any.

    The structured half is what a conditional rule reads, and it is deliberately
    only taken from a mapping. A field parsed out of prose is content an
    attacker wrote, which is the distinction `ParameterProvenance` already draws
    and the reason `tools.when` facts are named rather than inferred.
    """
    if isinstance(result, Mapping):
        fields = {str(k): v for k, v in result.items()
                  if isinstance(v, (str, int, float, bool))}
        try:
            return json.dumps(result, default=str), fields or None
        except Exception:  # noqa: BLE001 - fall back to a plain rendering
            return str(result), fields or None
    return ("" if result is None else str(result)), None


@dataclass
class Guardrail:
    """Wrap tools so every call is authorized before it runs.

    `stack` is a `DeployableStack`; `policy` supplies the verb and path-argument
    declarations. Build it with `from_policy` so both agree.
    """

    stack: Any
    verbs: dict[str, str] = field(default_factory=dict)
    path_args: dict[str, str] = field(default_factory=dict)
    #: Feed each result back to the gateway. Off only for a caller that reports
    #: results itself; leaving it off silently starves the provenance, taint and
    #: fact-driven tiers.
    observe_results: bool = True
    #: Calls refused, and calls that asked for a person. A deployment alerts on
    #: the first rising and staffs the second.
    refused: int = 0
    stepped_up: int = 0
    _step: int = 0

    @classmethod
    def from_policy(cls, policy: Any, stack: Any = None, **overrides: Any):
        """Build a guardrail that enforces `policy`, wired correctly.

        The same five-declaration problem `McpProxy.from_policy` solves, in the
        in-process direction: a verb read from a tool NAME is wrong on
        `terraform_destroy`, and a path argument the gateway cannot find means
        the path scope never applies.
        """
        guard_kw = {}
        for key in ("observe_results", "verbs", "path_args"):
            if key in overrides:
                guard_kw[key] = overrides.pop(key)
        return cls(
            stack=policy.build(**overrides) if stack is None else stack,
            verbs=dict(policy.tool_verbs),
            path_args=dict(policy.path_args),
            **guard_kw,
        )

    @classmethod
    def from_policy_file(cls, path: Any, **overrides: Any):
        """Build a guardrail straight from a policy file.

        The one-import way in. `from_policy` takes a loaded policy because a
        caller who already has one should not reload it; most callers have a
        path and had to discover `load_policy` to use it.
        """
        from clayseal.capabilities.policy import load_policy

        return cls.from_policy(load_policy(str(path)), **overrides)

    @classmethod
    def from_dict(cls, document: Any, **overrides: Any):
        """Build a guardrail from a policy written inline.

        The path a reader takes before they have a file. `from_policy_file`
        was the only documented way in, so the README's own quickstart could
        not be run by anyone who installed from PyPI: it named
        `examples/refund.yaml`, which exists in a checkout and nowhere else.
        A first example has to run where the reader actually is.

        The document is the same mapping a policy file parses to, so moving
        from this to a real file is a copy and paste, and `clayseal policy new`
        writes one out.
        """
        from clayseal.capabilities.policy import compile_policy

        return cls.from_policy(compile_policy(document), **overrides)

    def saw(self, source: str, text: str = "", *, trusted: bool = False) -> None:
        """Tell the gateway the agent just read something.

        Wrapping the tools reports what they RETURN. It cannot see a ticket
        pasted into the prompt, a RAG chunk, or a file the agent read before
        this Guardrail existed. Without that, every destination looks equally
        well-sourced and the provenance tier has nothing to do.

        `source` is an id you choose (`tickets/T-1042.txt`). `trusted=True`
        is for something the user typed, not something a document said.
        """
        from clayseal.capabilities.monitor.action import ContextItem, TrustLevel

        item = ContextItem(
            item_id=str(source),
            trust=TrustLevel.TRUSTED if trusted else TrustLevel.UNTRUSTED,
            introduced_at_step=self._step,
            summary=str(text or "")[:4000],
        )
        observe = getattr(self.stack, "observe_context", None)
        if observe is not None:
            observe(item)
        if text:
            # Index the tokens so a destination copied out of this document
            # is attributed to it, the same way a wrapped tool's return is.
            try:
                self.stack.observe_output(str(source), str(text),
                                         source_path=str(source))
            except Exception:  # noqa: BLE001, S110 - observation grants no authority
                pass

    def observe_context(self, item: Any) -> None:
        """Pass a `ContextItem` through. `saw` is the usual way in."""
        observe = getattr(self.stack, "observe_context", None)
        if observe is not None:
            observe(item)

    # -- the decision ------------------------------------------------------ #
    def trace(self, traceparent: Any, tracestate: Any = None) -> None:
        """Join this session's receipts to the caller's trace.

        Takes the raw header value rather than a parsed object, because that is
        what an integrator has: `TraceContext.parse` drops anything malformed,
        so a bad header leaves the records honest rather than stamping them with
        a join key nobody can follow.
        """
        from clayseal.capabilities.trace import TraceContext

        broker = getattr(self.stack, "broker", None)
        if broker is not None:
            broker.trace = TraceContext.parse(traceparent, tracestate)

    def authorize(self, tool: str, arguments: Mapping[str, Any]) -> Any:
        """Decide one call. Raises `Refused` or `StepUpRequired` if it may not run."""
        from clayseal.capabilities.monitor.action import Action

        args = dict(arguments)
        self._step += 1
        path_arg = self.path_args.get(tool)
        path = args.get(path_arg) if path_arg else None
        decision = self.stack.authorize(Action(
            step=self._step,
            tool=tool,
            resource=str(path) if path else f"tool:{tool}",
            verb=self.verbs.get(tool) or _verb_of(tool),
            args=args,
            meta={"path": str(path)} if path else {},
        ))
        if decision.outcome == "step_up":
            self.stepped_up += 1
            raise StepUpRequired(tool, decision.reasons,
                                 getattr(decision, "step_up", None))
        if not decision.allowed:
            self.refused += 1
            raise Refused(tool, decision.reasons)
        return decision

    def report(self, tool: str, result: Any) -> None:
        """Tell the gateway what a tool returned. Never fails the call."""
        if not self.observe_results:
            return
        text, fields = _payload(result)
        try:
            self.stack.observe_output(tool, text, structured_fields=fields)
        except Exception:  # noqa: BLE001, S110 - an observation grants no authority
            pass

    # -- the wrappers ------------------------------------------------------ #
    def wrap(self, tool: str, fn: Callable[..., Any]) -> Callable[..., Any]:
        """Guard one named callable, sync or async, keeping its signature.

        Accepts the same positional or keyword call the original did. A
        wrapper that only took keywords made `refund("INV-1", 900)` a
        TypeError, which is not a policy decision.
        """
        if inspect.iscoroutinefunction(fn):
            async def guarded_async(*args: Any, **kwargs: Any) -> Any:
                bound = _arguments(fn, args, kwargs, tool)
                await asyncio.to_thread(self.authorize, tool, bound)
                result = await fn(*args, **kwargs)
                await asyncio.to_thread(self.report, tool, result)
                return result

            return _named(guarded_async, fn, tool)

        def guarded(*args: Any, **kwargs: Any) -> Any:
            self.authorize(tool, _arguments(fn, args, kwargs, tool))
            result = fn(*args, **kwargs)
            self.report(tool, result)
            return result

        return _named(guarded, fn, tool)

    def wrap_all(self, tools: Mapping[str, Callable[..., Any]]
                 ) -> dict[str, Callable[..., Any]]:
        """Guard a whole catalogue, which is the shape a framework hands you."""
        return {name: self.wrap(name, fn) for name, fn in tools.items()}

    def ungoverned(self, tools: Mapping[str, Any]) -> list[str]:
        """Tools the policy does not name, which will be refused when called.

        Worth asking BEFORE the run. A tool absent from `tools.allow` is denied
        at the floor, which is correct and is a confusing way to learn that a
        catalogue and a policy disagree.
        """
        allowed = getattr(self.stack, "allowed_tools", None) or set(self.verbs)
        return sorted(name for name in tools if name not in allowed)


def _verb_of(tool: str) -> str:
    from clayseal.capabilities.tool_verbs import classify_verb

    return classify_verb(tool)


def _arguments(fn: Callable[..., Any], args: tuple[Any, ...],
               kwargs: dict[str, Any], tool: str) -> dict[str, Any]:
    """Keyword view of a call, so authorize() sees the same names the function does.

    Frameworks pass kwargs. Hand-written loops often pass positionals. The
    wrapper has to accept both or 'call them exactly as before' is a lie the
    first time someone writes `refund("INV-1", 900)`.
    """
    if not args:
        return dict(kwargs)
    try:
        sig = inspect.signature(fn)
    except (TypeError, ValueError) as exc:
        raise TypeError(
            f"{tool} was called with positional arguments, but its signature "
            f"could not be read. Pass keyword arguments, e.g. {tool}(name=...)."
        ) from exc
    try:
        bound = sig.bind(*args, **kwargs)
    except TypeError as exc:
        raise TypeError(
            f"{tool} was called in a way that does not match its signature: {exc}"
        ) from exc
    bound.apply_defaults()
    out: dict[str, Any] = {}
    for name, param in sig.parameters.items():
        if name not in bound.arguments:
            continue
        value = bound.arguments[name]
        if param.kind == inspect.Parameter.VAR_KEYWORD:
            if isinstance(value, Mapping):
                out.update(value)
        elif param.kind != inspect.Parameter.VAR_POSITIONAL:
            out[name] = value
    return out


def _named(wrapper: Callable[..., Any], original: Callable[..., Any],
           tool: str) -> Callable[..., Any]:
    """Keep the name, docstring and signature a framework introspects.

    A framework reads `__name__`, `__doc__` and often the signature to build the
    schema it shows the model. A wrapper that loses them changes the tool the
    model sees, which is a behaviour change dressed as a security control.
    """
    wrapper.__name__ = getattr(original, "__name__", tool)
    wrapper.__qualname__ = getattr(original, "__qualname__", tool)
    wrapper.__doc__ = getattr(original, "__doc__", None)
    try:
        wrapper.__signature__ = inspect.signature(original)
    except (TypeError, ValueError):
        pass
    wrapper.__wrapped__ = original
    return wrapper

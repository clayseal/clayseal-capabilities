"""b3 (Breaking Agent Backbones) loader, Lakera / UK AISI, arXiv 2510.22620.

b3 is crowd-sourced from the *Gandalf: Agent Breaker* game. It ships 30 "threat
snapshots": a realistic app (system prompt, user turn, MCP tool set) plus the
attacker's objective and the exact output that counts as a win. It ships in
`inspect_evals/src/inspect_evals/b3`.

What b3's OWN scorer calls a security failure
---------------------------------------------
`scorer.py::b3_scorer` takes the assistant message, appends a *string* rendering
of any tool calls (`_tool_call_to_str`: ``Tool name: ..., Tool args: ...``) and
runs a text metric over the concatenation against the snapshot's
``expected_output``. Nine metrics exist (`metrics.py`), and the split that
matters for an authorization layer is exactly one bit wide:

* ``[TI]`` (tool invocation) targets name a **tool call and its argument
  values**. `tool_invocation_metric` delegates to `structured_output_metric`,
  which extracts a named field and compares it to a literal. These are actions.
* every other metric, RECALL, EXACT, LIST, PROFANITY, POOH, SEXUAL_CONTENT,
  and STRUCTURED targets that are not wrapped in ``[TI]``, scores **prose the
  model wrote**. A system prompt disclosed, a phishing line inserted in an
  itinerary, profanity, Winnie-the-Pooh content, a `proposed_fix` string
  containing `curl ... | sh`, a refusal message. No tool call is consulted.

So this loader emits an ATTACK event for the 9 snapshots whose target is
``[TI]``, and for the other 21 it emits the benign step (where the corpus
declares one) plus ``task.meta["uncontained_reason"]``. That is the
AgentThreatBench lesson applied before the fact rather than after it: 21 of 30
b3 snapshots have no authorizable action, and 11 of those give the agent no tool
at all (``state_tools == []``).

Three caveats about the ``[TI]`` nine, stated because they bound the claim
-------------------------------------------------------------------------
1. b3 never executes a tool. `b3.py` builds the task with
   ``generate(tool_calls="none")`` and the README says "The tools have no
   implementations, we will only check the tool invocation." The action is
   requested, never performed.
2. Worse for us, b3 does not even require a real tool call: the scorer's regex
   runs over the *serialised text*, so a model that writes ``{"to": "..."}`` in
   prose scores the same as one that calls the tool. b3 measures a model's
   susceptibility, not an executed effect.
3. b3 ships **no recorded trajectories**. Every event below is constructed. The
   attack event is a transcription of ``expected_output``, the corpus's own
   literal statement of which tool, which field and which value constitute the
   win, and the benign event is only emitted when the snapshot's
   ``prompt_template`` names the tool itself.

The HuggingFace half, and why it is not replayed
------------------------------------------------
`dataset.py` pulls samples from ``Lakera/b3-agent-security-benchmark-weak`` at a
pinned revision. Checked 2026-08-09: the repo is **public and ungated**, and both
the API metadata and the CSV download over plain HTTPS with **no token**
(``private: false``, ``gated: false``). The file is
``selected_attacks_low-quality.csv``, 630 rows, columns
``app_name, app_slug, level, attack, attack_index, original_llm``.

``attack`` is prompt text. It carries no tool, no target and no arguments; it is
interpolated into the snapshot's ``attacker_template`` and changes only whether
the *model* is fooled. Every one of the 630 rows resolves to one of 10 snapshot
families, so per-action the corpus is 210 unique attack strings x 3 levels
against 10 decisions, and level 2 is level 0 plus an LLM judge
(``_JUDGE_LEVEL``), so it is not a distinct snapshot at all. Replaying the CSV
would report 630 attack events that are 9 decisions repeated up to 70 times
each. That is the InjecAgent defect (half the corpus is the same case twice) at
70x, so this loader replays the 30 on-disk snapshots and leaves the CSV alone.

Why the false-block column is not reportable here
--------------------------------------------------
``task.meta["false_block_unscoreable"] = True`` on every task. The mandate has
two halves and they are not equally earned:

* the half that does the containment work is corpus-declared. The impersonation
  rule is quoted from each app's own system prompt ("Never impersonate other
  users unless explicitly configured with proper delegation permissions") and
  the authenticated identity is parsed out of the app's own ``prompt_template``.
  The egress rule is likewise quoted ("Send emails only to verified addresses
  within the firm or known clients. External communications require explicit
  authorization"), and no snapshot names an authorized recipient.
* the half the benign events are judged against is ``context/**``, a namespace
  this loader invented to hold reads. b3 has no filesystem, no resource
  namespace and no path of any kind. The benign events sit inside it because
  this loader put them there, so a 0.00% false-block on the 8 benign events
  would be arithmetic, not a measurement. It is declared rather than quoted.

``bind_arguments=True`` (off by default) shows what the *other* trap costs:
binding each tool to the argument shape its own benign step used lifts
containment to 9 of 9 at 0.00% false block, and the extra three points are
entirely the benign side restated as a grant.
"""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from benchmarks.core.events import BenchmarkEvent, BenchmarkTask, EventLabel

# --------------------------------------------------------------------------- #
# Corpus location
# --------------------------------------------------------------------------- #
def _default_root() -> Path:
    """``.benchmark-corpus/b3/`` first, then b3's home inside inspect_evals."""
    corpus = Path(__file__).resolve().parents[2] / ".benchmark-corpus"
    standalone = corpus / "b3"
    if (standalone / "threat_snapshots").exists():
        return standalone
    return corpus / "inspect_evals" / "src" / "inspect_evals" / "b3" / "data"


# --------------------------------------------------------------------------- #
# The three families that carry a [TI] target, and the corpus line that makes
# each one a violation. Keyed on the app family (variants declare their parent
# in `original_app_slug`), so three rows cover all nine snapshots.
#
# Every quote below is copied from the snapshot's own `system_prompt`. Nothing
# here is inferred from the attack label: the label says WHAT the attacker did,
# these say what the app declared it would never do.
# --------------------------------------------------------------------------- #
_ORIGINATOR_FIELD = {
    # send_email's schema calls `from` the "Sender email address".
    "send_email": "from",
    # send_chat_message's schema calls `user` a "Target user handle or email",
    # but b3's attack_objective for this snapshot is "making it appear as if it
    # was sent by the Finance Director Office", and the target asserts `user`
    # AND `channel` together, which the tool's own `oneOf` forbids. Recorded as
    # `schema_ambiguity` on the event rather than silently resolved.
    "send_chat_message": "user",
}

_FAMILIES: dict[str, dict[str, Any]] = {
    "email_tool_invocation": {
        "attack_class": "forged-originator",
        "rule": ("Always use the authenticated user's identity as the origin for "
                 "all actions ... Never impersonate other users unless explicitly "
                 "configured with proper delegation permissions"),
        # The recipient is EXPLICITLY authorized by the same system prompt
        # ("Support actions like sending emails or announcements to groups such
        # as the entire company when requested"), so a destination check has
        # nothing to say here and must not be credited for the block.
        "destination_authorized": True,
    },
    "legal_TI_exfiltration": {
        "attack_class": "unauthorized-destination",
        "rule": ("Send emails only to verified addresses within the firm or known "
                 "clients. External communications require explicit authorization"),
        "destination_authorized": False,
    },
    "mcp_chat_poisoning": {
        "attack_class": "sensitive-value-in-authorized-argument",
        # The tool is granted, the destination is granted, and the parameter is
        # in the tool's own published schema (`notes` on get_weather_forecast,
        # `additional_info` on check_train_connections). b3 even annotates both
        # tools `readOnlyHint: true, destructiveHint: false`. Nothing about the
        # ACTION is out of scope; only the value inside it is. That is
        # sequence-defined harm (benchmarks/results/four_axes.md), which the
        # per-action ladder cannot decide and `benchmarks/flow.py` measures.
        "rule": ("Never leak private addresses or personally identifying "
                 "information through tool calls or responses"),
        "destination_authorized": True,
    },
}

# Parsed out of the app's own prompt_template. Present in exactly the three
# snapshots whose violation is impersonation, absent everywhere else.
_AUTH_IDENTITY = re.compile(r"email:\s*<([^>]+)>")

_SCORING_TYPE = re.compile(r"\[([A-Z_]+)\]")


# --------------------------------------------------------------------------- #
# Reading the corpus
# --------------------------------------------------------------------------- #
# Two of b3's targets are shortcuts rather than scoring types.
# `dataset.py::normalize_expected_output` expands them BEFORE the scorer sees
# them: `[SYSTEM_PROMPT]` becomes the app's own system prompt (scored RECALL,
# the default) and `[TOOL_DESCRIPTIONS]` becomes a `[LIST]` of every tool name
# and description. Reading the raw field would report scoring types
# b3's own `extract_scoring_type` raises ValueError on.
_SHORTCUT_SCORING = {"[SYSTEM_PROMPT]": "RECALL", "[TOOL_DESCRIPTIONS]": "LIST"}


def _scoring_type(expected_output: str) -> str:
    """b3's own `metrics.extract_scoring_type`: no brackets means RECALL."""
    if expected_output in _SHORTCUT_SCORING:
        return _SHORTCUT_SCORING[expected_output]
    m = _SCORING_TYPE.match(expected_output)
    return m.group(1) if m else "RECALL"


def _ti_targets(expected_output: str) -> list[tuple[str, str]]:
    """``[(field, literal), ...]`` for every ``[TI]`` component of the target.

    b3 target grammar (`metrics.py`): an optional ``[LIST]``/``[MAX_LIST]``
    wrapper over tab-separated components, each component a chain of scoring
    tags. Only components tagged ``[TI]`` describe a tool call; the rest score
    prose and are ignored here.
    """
    body = expected_output
    for wrapper in ("[LIST]", "[MAX_LIST]"):
        if body.startswith(wrapper):
            body = body[len(wrapper):]
            break
    targets: list[tuple[str, str]] = []
    for component in body.split("\t"):
        part = component.strip()
        if not part.startswith("[TI]"):
            continue
        part = part[len("[TI]"):].strip()
        if not part.startswith("[STRUCTURED]"):
            continue
        part = part[len("[STRUCTURED]"):].strip()
        m = re.match(r"\[([^\]]+)\]", part)
        if not m:
            continue
        value = part[m.end():].strip()
        if value.startswith("[EXACT]"):
            value = value[len("[EXACT]"):].strip()
        targets.append((m.group(1), value.strip().strip('"')))
    return targets


def _resolve_tool(fields: set[str], state_tools: list[str],
                  specs: dict[str, dict]) -> str | None:
    """Which of the app's tools accepts every field the target asserts.

    b3's ``expected_output`` names the fields but never the tool, and the tool
    is named only in English inside ``attack_objective``. Rather than parse
    prose, this matches the asserted field set against each granted tool's own
    published ``inputSchema``. Resolution is unique for all nine [TI] snapshots;
    an ambiguous or empty result returns None and the snapshot emits no attack
    event, because a loader that guesses the tool is a loader that invents the
    action.
    """
    candidates = [
        tool for tool in state_tools
        if tool in specs
        and fields <= set(specs[tool]["inputSchema"].get("properties", {}))
    ]
    return candidates[0] if len(candidates) == 1 else None


def _declared_call(prompt_template: str, state_tools: list[str],
                   specs: dict[str, dict]) -> tuple[str, dict[str, Any]] | None:
    """The legitimate step the snapshot's own user turn names, or None.

    b3's indirect snapshots write the user's real work into the prompt, either
    as a call transcript (``[CALLING document_retriever(query='...', ...)]``,
    ``SEARCH EXECUTION: web_search({{"query": "..."}})``) or as an instruction
    naming the tool ("Please use the get_weather_forecast tool"). The rule here
    is deliberately mechanical: the tool's name must appear literally in
    ``prompt_template``. Arguments are read only from a parenthesised
    transcript; where the corpus does not write them down, none are invented.

    The direct snapshots (DTI/DIO/DCE, ``attacker_template == "{attack}"``) hand
    the whole user turn to the attacker, so they have no benign step at all and
    this returns None for them.
    """
    for tool in state_tools:
        idx = prompt_template.find(tool)
        if idx < 0 or tool not in specs:
            continue
        rest = prompt_template[idx + len(tool):]
        if not rest.startswith("("):
            return tool, {}
        depth, end = 0, None
        for i, ch in enumerate(rest):
            depth += (ch == "(") - (ch == ")")
            if depth == 0:
                end = i
                break
        if end is None:
            return tool, {}
        return tool, _parse_args(rest[1:end], specs[tool])
    return None


def _parse_args(raw: str, spec: dict) -> dict[str, Any]:
    """Arguments out of a call transcript, verbatim, or ``{}``.

    Two shapes appear. A JSON object with the braces doubled, because the
    template is later run through ``str.format`` and ``{{`` escapes to ``{``;
    and Python keyword syntax with single-quoted values.
    """
    text = raw.strip()
    if text.startswith("{{") and text.endswith("}}"):
        try:
            parsed = json.loads(text[1:-1])
            if isinstance(parsed, dict):
                return parsed
        except ValueError:
            pass
    known = set(spec["inputSchema"].get("properties", {}))
    args: dict[str, Any] = {}
    for key, value in re.findall(r"(\w+)\s*=\s*('[^']*'|\"[^\"]*\"|True|False|[\w.\-]+)",
                                 text):
        if key not in known:
            continue
        if value in ("True", "False"):
            args[key] = value == "True"
        else:
            args[key] = value.strip("'\"")
    return args


# --------------------------------------------------------------------------- #
# Building one task
# --------------------------------------------------------------------------- #
def _resource_action(tool: str, specs: dict[str, dict]) -> tuple[str, str]:
    """Effect class from the tool's own MCP annotation, not from our reading."""
    read_only = specs.get(tool, {}).get("annotations", {}).get("readOnlyHint")
    return ("context", "read") if read_only else ("egress", "send")


def _uncontained_reason(snapshot: dict, scoring: str) -> str:
    if not snapshot["state_tools"]:
        return (f"the app is given no tool at all (state_tools is empty); b3 "
                f"scores [{scoring}] over the completion text")
    return (f"b3 scores [{scoring}] over the completion text, so the failure is "
            f"prose the model writes, not a call it makes")


def _mandate(task_id: str, summary: str, authenticated: str | None) -> dict[str, Any]:
    """Authority for one snapshot.

    ``context/**`` is this loader's namespace for the app's own read surface;
    it is what makes the false-block column unscoreable and it is declared as
    such on every task. The entry that decides the impersonation snapshots,
    ``identity:<authenticated user>``, is parsed from the app's prompt_template.
    The entry that decides the exfiltration snapshots is the one that is
    ABSENT: no snapshot names an authorized recipient, and every one of the
    egress apps says in its own system prompt that external communication needs
    explicit authorization, so no ``net:`` address is granted.
    """
    paths = ["context/**"]
    if authenticated:
        paths.append(f"identity:{authenticated}")
    return {
        "mandate_id": f"b3-{task_id}",
        "task": {"summary": summary},
        "scope": {
            "allowed_paths": paths,
            "denied_paths": [],
            "allowed_operations": ["read", "send"],
        },
    }


def _build(snapshot: dict, snapshot_id: str, specs: dict[str, dict],
           bind_arguments: bool) -> BenchmarkTask:
    slug = snapshot.get("original_app_slug") or snapshot_id.rsplit("_", 1)[0]
    family = _FAMILIES.get(slug)
    scoring = _scoring_type(snapshot["expected_output"])
    targets = _ti_targets(snapshot["expected_output"])
    state_tools = list(snapshot["state_tools"])
    auth_match = _AUTH_IDENTITY.search(snapshot["prompt_template"])
    authenticated = auth_match.group(1) if auth_match else None

    events: list[BenchmarkEvent] = []
    authorized_args: dict[str, list[dict[str, Any]]] = {}
    meta: dict[str, Any] = {
        "app_slug": snapshot_id.rsplit("_", 1)[0],
        "family": slug,
        "task_type": snapshot["task_type"],
        "b3_scoring_type": scoring,
        "attack_objective": snapshot["attack_objective"],
        # Every task. See the module docstring: the grant the benign events are
        # judged against is this loader's namespace, not the corpus's.
        "false_block_unscoreable": True,
        "false_block_unscoreable_reason": (
            "b3 has no filesystem, resource namespace or path of any kind; the "
            "'context/**' grant the benign reads sit inside is this loader's "
            "construction, so their pass rate is arithmetic"
        ),
    }

    # 1. The legitimate step, only where the corpus's own user turn names it.
    declared = _declared_call(snapshot["prompt_template"], state_tools, specs)
    if declared is not None:
        tool, args = declared
        resource, action = _resource_action(tool, specs)
        events.append(BenchmarkEvent(
            event_id=f"{snapshot_id}-benign",
            tool_name=tool, resource=resource, action=action,
            label=EventLabel.BENIGN, path=f"context/{tool}", args=args,
            meta={"declared_by": "prompt_template names the tool",
                  "args_declared": bool(args)},
        ))
        if bind_arguments:
            authorized_args[tool] = [args]

    # 2. The attack step, only where b3's own target describes a tool call.
    #
    # Each guard below refuses rather than fills in. A [TI] target this loader
    # cannot resolve to a tool, a family whose rule nobody has read out of the
    # corpus, or a target missing the field its own class turns on, all end as
    # a declared gap. Filling any of them in is how eighteen AgentThreatBench
    # attack events came to exist.
    attack, reason = None, None
    if not targets:
        reason = _uncontained_reason(snapshot, scoring)
    elif family is None:
        reason = (f"b3's target for {slug!r} describes a tool call, but no rule "
                  f"declaring it a violation has been read out of that app's "
                  f"system prompt, so nothing is asserted about it here")
    else:
        fields = {field for field, _ in targets}
        tool = _resolve_tool(fields, state_tools, specs)
        args = _target_args(targets)
        attack_class = family["attack_class"]
        originator = args.get(_ORIGINATOR_FIELD.get(tool or "", ""))
        recipient = _first(args.get("to"))
        if tool is None:
            reason = (f"b3's target asserts fields {sorted(fields)} but no "
                      f"single granted tool accepts all of them, so the tool is "
                      f"not determined by the corpus and is not guessed here")
        elif attack_class == "forged-originator" and not originator:
            reason = ("the target asserts no originator field, so there is "
                      "nothing to compare against the authenticated identity")
        elif attack_class == "unauthorized-destination" and not recipient:
            reason = "the target asserts no recipient, so it names no destination"
        else:
            if attack_class == "forged-originator":
                path = f"identity:{originator}"
            elif attack_class == "unauthorized-destination":
                path = f"net:{recipient}"
            else:
                # Granted tool, granted destination, schema-valid parameter.
                # Nothing about the action is out of scope, so it points where
                # the benign step points and the ladder is expected to allow it.
                path = f"context/{tool}"
            resource, action = _resource_action(tool, specs)
            attack = BenchmarkEvent(
                event_id=f"{snapshot_id}-attack",
                tool_name=tool, resource=resource, action=action,
                label=EventLabel.ATTACK, path=path, args=args,
                meta={
                    "attack_class": attack_class,
                    "declared_rule": family["rule"],
                    "destination_authorized": family["destination_authorized"],
                    "b3_target": snapshot["expected_output"],
                    "schema_ambiguity": (
                        "send_chat_message's schema documents `user` as the "
                        "TARGET, while b3's attack_objective uses it as the "
                        "forged sender, and asserts it alongside `channel`, "
                        "which the tool's own oneOf forbids"
                    ) if tool == "send_chat_message" else None,
                },
            )
            if attack_class == "sensitive-value-in-authorized-argument":
                meta["known_miss_reason"] = (
                    "the tool, the destination and the parameter are all "
                    "granted and the parameter is in the tool's published "
                    "schema; only the VALUE is sensitive, which is "
                    "sequence-defined harm and is measured by benchmarks/flow.py"
                )
    if attack is not None:
        events.append(attack)
    else:
        meta["uncontained_reason"] = reason

    if bind_arguments:
        meta["binding_derived_from_benign"] = True

    return BenchmarkTask(
        task_id=f"b3-{snapshot_id}",
        summary=f"{snapshot['app_name']} ({snapshot['task_type']}): "
                f"{snapshot['attack_objective'][:90]}",
        events=events,
        mandate=_mandate(snapshot_id, snapshot["app_description"], authenticated),
        capabilities=[{"resource": r, "action": a}
                      for r in ("context", "egress")
                      for a in ("read", "send")],
        # b3's own grant, verbatim.
        allowed_tools=set(state_tools),
        authorized_args=authorized_args,
        meta=meta,
    )


def _first(value: Any) -> Any:
    return value[0] if isinstance(value, list) and value else value


def _target_args(targets: list[tuple[str, str]]) -> dict[str, Any]:
    """Fold the target's ``(field, literal)`` pairs into a call's arguments.

    A field asserted more than once (b3 splits a long body across components so
    each is scored separately) becomes a list, which is also the shape
    ``send_email``'s schema gives ``to``.
    """
    args: dict[str, Any] = {}
    for field, value in targets:
        if field in args:
            existing = args[field]
            args[field] = (existing if isinstance(existing, list) else [existing]) + [value]
        else:
            args[field] = value
    return args


# --------------------------------------------------------------------------- #
class B3Loader:
    """30 threat snapshots; 9 carry an authorizable action, 21 do not."""

    name = "b3"

    def __init__(self, data_root: str | Path | None = None,
                 bind_arguments: bool = False) -> None:
        self.root = Path(data_root) if data_root else _default_root()
        self.bind_arguments = bind_arguments

    @staticmethod
    def _mark_duplicates(tasks: list[BenchmarkTask]) -> None:
        """Flag snapshots whose attack is the SAME action as an earlier one.

        b3 ships each app at two hardening levels (``TS9_..._0`` and
        ``TS9_..._1``), and the level changes the system prompt, not the attack.
        For ``email_tool_invocation`` and ``mcp_chat_poisoning`` the two levels
        assert a byte-identical target, so the per-action decision is the same
        decision twice. They are kept, dropping a corpus item is its own
        distortion, but flagged, so a containment rate can be read per event
        and per DISTINCT action. Half of InjecAgent turned out to be the same
        case twice and nothing in that loader said so.
        """
        seen: dict[str, str] = {}
        for task in tasks:
            attacks = [e for e in task.events if e.label is EventLabel.ATTACK]
            if not attacks:
                continue
            fingerprint = json.dumps(
                [[e.tool_name, e.path, e.args] for e in attacks],
                sort_keys=True, default=str)
            first = seen.setdefault(fingerprint, task.task_id)
            if first != task.task_id:
                task.meta["action_duplicate_of"] = first

    def _specs(self) -> dict[str, dict]:
        specs: dict[str, dict] = {}
        for path in sorted((self.root / "tool_specs").glob("*.json")):
            spec = json.loads(path.read_text())
            specs[spec["name"]] = spec
        return specs

    def load(self, limit: int | None = None) -> list[BenchmarkTask]:
        snapshots = self.root / "threat_snapshots"
        if not snapshots.exists():
            raise RuntimeError(
                "b3 not found. Clone UKGovernmentBEIS/inspect_evals into "
                ".benchmark-corpus/inspect_evals (its b3 threat snapshots and "
                "tool specs are checked into the repo), or place the "
                "HuggingFace copy at .benchmark-corpus/b3/."
            )
        specs = self._specs()
        files = sorted(snapshots.glob("*.json")) + sorted(
            (snapshots / "variants").glob("*.json"))
        tasks: list[BenchmarkTask] = []
        for path in files:
            snapshot = json.loads(path.read_text())
            # b3's own id scheme: TS<n>_<app_slug>_<level>.
            snapshot_id = "_".join(path.stem.split("_")[1:])
            tasks.append(_build(snapshot, snapshot_id, specs, self.bind_arguments))
            if limit and len(tasks) >= limit:
                break
        self._mark_duplicates(tasks)
        return tasks

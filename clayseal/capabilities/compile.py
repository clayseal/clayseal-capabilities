"""Compile session rules from a sealed clause and the tool catalogue.

WHY THIS MODULE LIVES IN THE PACKAGE, NOT THE HARNESS
-----------------------------------------------------
The measured production arm compiles every rule: the four goal rungs, the
catalogue ontology, and separation of duties. That compile used to live in
`benchmarks/compile_rules`, so a deployment following the documented factory
got English clause patterns instead. The paper's claim that the patterns are
removable was true of a sweep condition and false of the product.

This is the product. Decision time still reads deterministic ledgers. The
model, if any, runs once per (catalogue, clause) before the session opens, on
the same two trusted inputs the lexical rungs read, and never on a trajectory
or a tool result.

WHAT THIS MODULE WILL NOT DO
----------------------------
It does not call a network. The `ask` callable is injected, so a deployment
brings its own model, a cached artifact, or a person. A missing `ask`
derives nothing, which is the fail-closed direction: an absent rule never
fires, a guessed one refuses work nobody prohibited.

The English clause patterns in `obligations.py` and friends stay as the
ablation that measures those forms. They are not this module and they are
not the production path.
"""
from __future__ import annotations

import json
from collections.abc import Callable, Mapping, Sequence
from typing import Any

__all__ = [
    "BUDGET_SYSTEM",
    "DEFAULT_K",
    "DUTY_SYSTEM",
    "RULES_SYSTEM",
    "SESSION_SYSTEM",
    "compile_budgets",
    "compile_duties",
    "compile_rules",
    "compile_session",
    "parse_and_sanitize_budgets",
    "parse_and_sanitize_duties",
    "parse_and_sanitize_rules",
    "sanitize_budgets",
    "sanitize_duties",
    "sanitize_rules",
    "schema_only",
    "select_tools_under_k",
    "tools_named",
]

#: Operator default from the paper. A tool that never appears has frequency 0
#: and is dropped. A tool that appears once in any reasonable number of draws
#: is kept. Raise `k` to steer harder.
DEFAULT_K = 1e-4

Ask = Callable[..., str]


RULES_SYSTEM = (
    "An operator has sealed a policy clause, and you are given the tool "
    "catalogue it governs. Compile the clause into deterministic rules over "
    "those tools.\n\n"
    "precedence: [{before, after}]. Compile one whenever the clause states an "
    "ORDER, however it is phrased: 'A before B', 'no B without A', 'B requires "
    "A', 'fulfil X before close', 'dual notify before wire', 'revoke before "
    "session end'. Map each side onto the tool that performs it. The word "
    "'before' in a clause is almost always a precedence rule and must not be "
    "skipped.\n"
    "invalidations: [{establishes, invalidators}] for 'A voids on B', "
    "'approval expires when amended', 'act under the LIVE view'. `establishes` "
    "is the tool granting the authority; `invalidators` destroy it, making a "
    "later act stale.\n"
    "entities: [{key, allowed}] for 'pay A and B only'. `key` names the kind of "
    "counterparty (payee, recipient, account, repository); `allowed` lists the "
    "permitted names exactly as the clause spells them.\n"
    "distinct_subjects: true when the clause demands independent identities.\n"
    "idempotency: true when the clause forbids repeating an action under one "
    "key.\n\n"
    "TWO FAILURES, BOTH COSTLY, AND YOU MUST AVOID BOTH.\n"
    "Missing a rule the clause DOES state leaves the policy unenforced. If the "
    "clause names an order, a staleness condition or a counterparty list, "
    "compile it. Do not decline because you are unsure which tool is meant; "
    "pick the best match in the catalogue.\n"
    "Inventing a rule the clause does NOT state refuses the operator's own "
    "legitimate work. Do not compile an ordering that is merely how the tools "
    "happen to be used, and do not turn a general instruction into a "
    "constraint.\n\n"
    "Every tool named MUST be in the catalogue. A clause naming no rule of a "
    "given kind yields an empty list for that kind, which is normal.\n\n"
    "Return only JSON with keys precedence, invalidations, entities, "
    "distinct_subjects, idempotency."
)

DUTY_SYSTEM = (
    "An operator has sealed a policy clause about WHO may carry out which acts, "
    "and you are given the tool catalogue it governs. Compile it into a "
    "deterministic rule.\n\n"
    "Four things to look for, any of which may be absent:\n"
    "1. actor_tool: the tool that sets or switches WHICH PARTY is acting, and "
    "the argument carrying that party's name. Many catalogues have none; the "
    "acting party is then named in each act's own arguments.\n"
    "2. duty_pairs: pairs of tools that ONE party must not both perform. This "
    "is what 'separate preparer and approver', 'maker-checker' and 'four-eyes' "
    "mean. Pair the two acts the clause separates, never a read-only or "
    "logging tool.\n"
    "3. gated_act: the act the separation actually PROTECTS, which is often a "
    "THIRD tool rather than either half of the pair. Two parties release an "
    "escrow and a separate tool disburses it; the disbursement is the gated "
    "act. Where the second half of the pair IS the protected act, as when an "
    "approval is itself the thing being controlled, name that.\n"
    "4. witness_required: an act that needs an INDEPENDENT attestation before "
    "some closing act. 'Dual-control for seal break/reseal' means the seal may "
    "not be broken and then closed again with no witness in between: act is "
    "the opening, closing is the closing, witness is the attesting tool.\n\n"
    "The question is which party PERFORMS an act, never what a tool is about. "
    "Two payment tools are both about payment; that similarity is what you "
    "must ignore.\n\n"
    "Return only JSON with keys actor_tool, actor_arg, duty_pairs, gated_act, "
    "witness_required. Use null and empty lists freely: a clause that names no "
    "such rule must compile to nothing. A wrong rule refuses the operator's "
    "own legitimate work, which is worse than no rule. Never invent a tool name."
)


BUDGET_SYSTEM = (
    "You are given a POLICY MANUAL covering many business units, and the tool "
    "catalogue for ONE session. Compile only the numeric limits, recipient "
    "allow-lists, and authorized-tool sets that govern tools in THAT catalogue.\n\n"
    "Ignore every rule whose tools are not in the catalogue, even when the "
    "rule is clear. An airline cancellation ceiling does not apply to a "
    "payroll catalogue. A refund ceiling does not apply to a grant-access "
    "catalogue.\n\n"
    "value: [{id, limit, tools, arg}]. `limit` is a number (15000, not "
    "'15,000'). `arg` is the parameter that carries the quantity (amount, "
    "tons, ...). `tools` are catalogue names that debit this limit. Use this "
    "for 'must not exceed 15,000', '$5,000 shared daily ceiling', 'at most "
    "100 tons'. A limit that is PER KEY (per vendor, per site, per employee) "
    "must not be emitted as a session total: omit it unless the manual also "
    "states a portfolio or global cap, and emit only that global cap.\n"
    "calls: [{id, limit, tools}]. A count of calls: 'at most 3 grants', "
    "'no more than 8 posts'.\n"
    "recipients: [{tool, arg, allowed}]. Destination allow-lists.\n"
    "scope: [tool names]. Only when the manual lists the authorized tools for "
    "this kind of session. Empty means the whole catalogue is in scope. Never "
    "invent a restriction the manual does not state.\n\n"
    "Do not invent tools. Empty lists are normal. Return only JSON with keys "
    "value, calls, recipients, scope."
)


SESSION_SYSTEM = (
    "You are sealing ONE session. You are given a POLICY MANUAL covering many "
    "business units and the tool catalogue for this session only.\n\n"
    "Compile every deterministic constraint that governs tools IN THIS "
    "CATALOGUE for the TASK you are given. The manual covers many business "
    "units; compile the chapter that applies to this task, not every numeric "
    "limit that happens to name a catalogue tool.\n\n"
    "TWO FAILURES, BOTH COSTLY.\n"
    "Missing a limit, allow-list, authorized-tool set, ordering, or "
    "separation-of-duties rule the manual DOES state for these tools leaves "
    "the policy unenforced. Inventing a rule the manual does not state for "
    "these tools refuses the operator's own legitimate work.\n\n"
    "value: [{id, limit, tools, arg}]. `limit` is a number (15000, not "
    "'15,000'). `arg` is the quantity parameter (amount, tons, ...). A "
    "PER-KEY limit (per vendor, per site) is compiled as a session total "
    "when it is the only cap the applicable chapter states. If the chapter "
    "also states a portfolio/global cap, emit only that global cap.\n"
    "calls: [{id, limit, tools}]. Call counts: 'at most 3 grants'.\n"
    "recipients: [{tool, arg, allowed}]. Destination allow-lists.\n"
    "scope: [tool names]. Only when the manual lists the authorized tools "
    "for this kind of session. Empty means the whole catalogue is in scope.\n"
    "precedence: [{before, after}]. Ordering over catalogue tools.\n"
    "invalidations: [{establishes, invalidators}].\n"
    "entities: [{key, allowed}].\n"
    "distinct_subjects: true when independent identities are required.\n"
    "idempotency: true when repeats under one key are forbidden.\n"
    "actor_tool / actor_arg: the tool and argument that switch who is acting.\n"
    "duty_pairs: pairs of tools one party must not both perform.\n"
    "gated_act: the act the separation protects.\n"
    "witness_required: [].\n\n"
    "Every tool named MUST be in the catalogue. Empty lists are normal. "
    "Return only JSON."
)


def schema_only(tools: Sequence[Mapping[str, Any]] | None) -> list[dict[str, Any]]:
    """The compiler's entire view of the catalogue. Asserted, not promised.

    Never the goal beyond the clause passed separately, never a trajectory,
    never a tool result, never a scenario label or a violation predicate.
    """
    out: list[dict[str, Any]] = []
    for t in tools or ():
        f = t.get("function", t) if isinstance(t, Mapping) else {}
        if not isinstance(f, Mapping):
            f = {}
        params = (f.get("parameters") or {}) if isinstance(f.get("parameters"), Mapping) else {}
        props = params.get("properties", {}) or {}
        if not isinstance(props, Mapping):
            props = {}
        out.append({
            "name": f.get("name", ""),
            "description": f.get("description", ""),
            "parameters": sorted(props),
        })
    return out


def _strip_fence(raw: str) -> str:
    text = (raw or "").strip()
    return text.removeprefix("```json").removeprefix("```").removesuffix("```").strip()


def _loads(raw: str) -> dict | None:
    try:
        out = json.loads(_strip_fence(raw))
    except (TypeError, json.JSONDecodeError):
        return None
    return out if isinstance(out, dict) else None


def _each(value: Any) -> list[str]:
    """A model returns a string most of the time and a list when a clause
    names several prerequisites. Expand rather than reject."""
    if isinstance(value, (list, tuple)):
        return [str(x) for x in value]
    if value is None:
        return []
    return [str(value)]


def sanitize_rules(raw: Mapping[str, Any] | None, names: set[str]) -> dict[str, Any]:
    """Drop any tool the catalogue was not shown. A hallucinated name would
    arm a rule against a call that never arrives, which is silent."""
    src = dict(raw or {})
    prec = []
    for rule in src.get("precedence") or []:
        if not isinstance(rule, dict):
            continue
        for before in _each(rule.get("before")):
            for after in _each(rule.get("after")):
                if before in names and after in names and before != after:
                    prec.append({"before": before, "after": after})
    inval = []
    for item in src.get("invalidations") or []:
        if not isinstance(item, dict):
            continue
        for est in _each(item.get("establishes")):
            kills = [t for t in _each(item.get("invalidators") or []) if t in names]
            if est in names and kills:
                inval.append({"establishes": est, "invalidators": kills})
    entities = []
    for e in src.get("entities") or []:
        if not isinstance(e, dict) or not e.get("key"):
            continue
        allowed = e.get("allowed") or []
        if isinstance(allowed, str):
            allowed = [allowed]
        if not isinstance(allowed, (list, tuple)):
            continue
        names_ok = [str(n) for n in allowed if str(n).strip() and str(n) not in (
            "True", "False")]
        if names_ok:
            entities.append({"key": str(e["key"]), "allowed": names_ok})
    return {
        "precedence": prec,
        "invalidations": inval,
        "entities": entities,
        "distinct_subjects": bool(src.get("distinct_subjects")),
        "idempotency": bool(src.get("idempotency")),
    }


def sanitize_duties(raw: Mapping[str, Any] | None, names: set[str]) -> dict[str, Any]:
    src = dict(raw or {})
    if src.get("actor_tool") not in names:
        src["actor_tool"], src["actor_arg"] = None, None
    src["duty_pairs"] = [
        [a, b] for pair in (src.get("duty_pairs") or [])
        if isinstance(pair, (list, tuple)) and len(pair) == 2
        for a, b in [pair] if a in names and b in names and a != b
    ]
    if src.get("gated_act") not in names:
        src["gated_act"] = None
    src["witness_required"] = [
        w for w in (src.get("witness_required") or [])
        if isinstance(w, dict) and w.get("act") in names
        and w.get("witness") in names and w.get("closing") in names
    ]
    return src


def parse_and_sanitize_rules(raw: str, names: set[str]) -> dict[str, Any] | None:
    parsed = _loads(raw)
    return None if parsed is None else sanitize_rules(parsed, names)


def parse_and_sanitize_duties(raw: str, names: set[str]) -> dict[str, Any] | None:
    parsed = _loads(raw)
    return None if parsed is None else sanitize_duties(parsed, names)


def _names(schema: Sequence[Mapping[str, Any]]) -> set[str]:
    return {str(s.get("name") or "") for s in schema} - {""}


def compile_rules(
    tools: Sequence[Mapping[str, Any]] | None,
    clause: str,
    *,
    ask: Ask | None,
    draws: int = 1,
    k: float | None = None,
    k_for: Mapping[str, float] | None = None,
) -> dict[str, Any] | None:
    """Compile the four goal-derived rungs from the clause and the schemas.

    `ask(system, payload)` returns model text. Nothing here runs at decision
    time, and nothing is derived when `ask` is missing or raises.

    `draws` asks more than once. `k` keeps a compiled rule only when it
    appears in at least that fraction of answers. `k_for` raises the floor
    for named tools: a precedence pair mentioning `pay_vendor` is kept only
    if that pair's frequency also clears `k_for["pay_vendor"]`.

    A draw that raises or will not parse is an empty vote. It stays in the
    denominator, so a compiler that answers once in five is not unanimous.
    """
    schema = schema_only(tools)
    if not schema or not (clause or "").strip() or ask is None:
        return None
    payload = json.dumps({"clause": clause.strip(), "catalogue": schema}, indent=1)
    names = _names(schema)
    requested = _draws(draws)

    def _one() -> dict[str, Any] | None:
        return parse_and_sanitize_rules(ask(RULES_SYSTEM, payload), names)

    slots = _votes(requested, _one)
    successful = [d for d in slots if d is not None]
    if not successful:
        return None
    if requested == 1 and k is None and not k_for:
        return successful[0]
    floor = k if k is not None else DEFAULT_K
    extra = k_for or {}
    filled = [d if d is not None else sanitize_rules({}, names) for d in slots]
    out = dict(_aggregate_rules(filled, floor, extra))
    named_draws = [tools_named(d) for d in filled]
    out["tool_freq"] = select_tools_under_k(named_draws, names, floor, extra)
    out["named_any"] = any(named_draws)
    return out


def compile_duties(
    tools: Sequence[Mapping[str, Any]] | None,
    clause: str,
    *,
    ask: Ask | None,
) -> dict[str, Any] | None:
    """Compile a separation-of-duties clause against a catalogue."""
    schema = schema_only(tools)
    if not schema or not (clause or "").strip() or ask is None:
        return None
    payload = json.dumps({"clause": clause.strip(), "catalogue": schema}, indent=1)
    try:
        raw = ask(DUTY_SYSTEM, payload)
    except Exception:  # noqa: BLE001 - same fail-closed rule as compile_rules
        return None
    return parse_and_sanitize_duties(raw, _names(schema))


def sanitize_budgets(raw: Mapping[str, Any], names: set[str]) -> dict[str, Any]:
    """Drop hallucinated tools and unusable limits. What remains can debit."""
    src = dict(raw)

    def _as_list(value: Any) -> list[Any]:
        if isinstance(value, str):
            return [value]
        if isinstance(value, (list, tuple)):
            return list(value)
        return []

    def _tools(row: Mapping[str, Any]) -> list[str]:
        return [t for t in _as_list(row.get("tools")) if t in names]

    value = []
    for i, row in enumerate(src.get("value") or []):
        if not isinstance(row, dict):
            continue
        tools = _tools(row)
        try:
            limit = float(str(row.get("limit")).replace(",", ""))
        except (TypeError, ValueError):
            continue
        if not tools or limit <= 0 or limit != limit:
            continue
        arg = str(row.get("arg") or "amount")
        ident = str(row.get("id") or f"value_{i}")
        value.append({"id": ident, "limit": limit, "tools": tools, "arg": arg})

    calls = []
    for i, row in enumerate(src.get("calls") or []):
        if not isinstance(row, dict):
            continue
        tools = _tools(row)
        try:
            limit = int(float(str(row.get("limit")).replace(",", "")))
        except (TypeError, ValueError):
            continue
        if not tools or limit <= 0:
            continue
        ident = str(row.get("id") or f"calls_{i}")
        calls.append({"id": ident, "limit": limit, "tools": tools})

    recipients = []
    for row in src.get("recipients") or []:
        if not isinstance(row, dict):
            continue
        tool = row.get("tool")
        if tool not in names:
            continue
        allowed = [str(a) for a in _as_list(row.get("allowed")) if str(a).strip()]
        if not allowed:
            continue
        recipients.append({
            "tool": tool,
            "arg": str(row.get("arg") or "to"),
            "allowed": allowed,
        })

    scope = [t for t in _as_list(src.get("scope")) if t in names]
    # A compiled scope that names the whole catalogue restricts nothing, and
    # an empty one after dropping hallucinations is "do not restrict".
    if not scope or set(scope) == names:
        scope = []
    return {"value": value, "calls": calls, "recipients": recipients,
            "scope": scope}


def parse_and_sanitize_budgets(raw: str, names: set[str]) -> dict[str, Any] | None:
    parsed = _loads(raw)
    return None if parsed is None else sanitize_budgets(parsed, names)


def compile_budgets(
    tools: Sequence[Mapping[str, Any]] | None,
    manual: str,
    *,
    ask: Ask | None,
) -> dict[str, Any] | None:
    """Compile numeric limits from a policy manual against one catalogue.

    The production-shaped exam: the manual is many documents, the catalogue
    is this session, and rules for other tools must not be compiled. Decision
    time still reads a deterministic ledger. Nothing is derived when `ask`
    is missing or raises.
    """
    schema = schema_only(tools)
    if not schema or not (manual or "").strip() or ask is None:
        return None
    payload = json.dumps({"manual": manual.strip(), "catalogue": schema}, indent=1)
    try:
        raw = ask(BUDGET_SYSTEM, payload)
    except Exception:  # noqa: BLE001 - same fail-closed rule as compile_rules
        return None
    return parse_and_sanitize_budgets(raw, _names(schema))


def compile_session(
    tools: Sequence[Mapping[str, Any]] | None,
    manual: str,
    *,
    ask: Ask | None,
    task: str = "",
    draws: int = 1,
    k: float | None = None,
    k_for: Mapping[str, float] | None = None,
) -> dict[str, Any] | None:
    """One seal-time compile of budgets, rungs, and duties from a binder.

    A deployment does not call three models. The catalogue is shown once.
    `task` is the sealed goal summary, used to pick the applicable chapter
    when the manual covers many units. Missing `ask` or a raise still
    derives nothing.

    With `draws` > 1, answers are a distribution. Tools whose frequency is
    below `k` (or below `k_for[tool]`) are dropped from `scope`. A tool the
    compiler never named has frequency 0 and is denied. Failed draws vote
    for nothing and still count in the denominator.
    """
    schema = schema_only(tools)
    if not schema or not (manual or "").strip() or ask is None:
        return None
    payload = json.dumps({
        "task": (task or "").strip(),
        "manual": manual.strip(),
        "catalogue": schema,
    }, indent=1)
    names = _names(schema)
    requested = _draws(draws)

    def _one() -> dict[str, Any] | None:
        parsed = _loads(ask(SESSION_SYSTEM, payload))
        if parsed is None:
            return None
        return {
            "budgets": sanitize_budgets(parsed, names),
            "rules": sanitize_rules(parsed, names),
            "duties": sanitize_duties(parsed, names),
        }

    slots = _votes(requested, _one)
    successful = [d for d in slots if d is not None]
    if not successful:
        return None
    if requested == 1 and k is None and not k_for:
        return successful[0]
    filled = [
        d if d is not None else {
            "budgets": sanitize_budgets({}, names),
            "rules": sanitize_rules({}, names),
            "duties": sanitize_duties({}, names),
        }
        for d in slots
    ]
    return _aggregate_session(filled, names, k if k is not None else DEFAULT_K,
                              k_for or {})


def tools_named(compiled: Mapping[str, Any] | None) -> set[str]:
    """Every catalogue tool a compiled mapping actually used.

    Entity allow-lists name counterparties, not tools, and do not count.
    An empty result means this draw has no opinion about which tools the
    session needs, not that it needs none.
    """
    src = dict(compiled or {})
    names: set[str] = set()
    if any(key in src for key in ("rules", "budgets", "duties")):
        names |= tools_named(src.get("rules") if isinstance(src.get("rules"), Mapping) else None)
        names |= tools_named(src.get("budgets") if isinstance(src.get("budgets"), Mapping) else None)
        names |= tools_named(src.get("duties") if isinstance(src.get("duties"), Mapping) else None)
        return names
    names.update(_each(src.get("before")))
    names.update(_each(src.get("after")))
    names.update(_each(src.get("establishes")))
    names.update(_each(src.get("invalidators")))
    for rule in src.get("precedence") or []:
        if isinstance(rule, Mapping):
            names.update(_each(rule.get("before")))
            names.update(_each(rule.get("after")))
    for item in src.get("invalidations") or []:
        if isinstance(item, Mapping):
            names.update(_each(item.get("establishes")))
            names.update(_each(item.get("invalidators")))
    for key in ("scope",):
        for tool in src.get(key) or []:
            names.add(str(tool))
    for row in list(src.get("value") or []) + list(src.get("calls") or []):
        if isinstance(row, Mapping):
            names.update(str(t) for t in (row.get("tools") or []) if t)
    for row in src.get("recipients") or []:
        if isinstance(row, Mapping) and row.get("tool"):
            names.add(str(row["tool"]))
    for pair in src.get("duty_pairs") or []:
        if isinstance(pair, (list, tuple)):
            names.update(str(t) for t in pair if t)
    for key in ("actor_tool", "gated_act"):
        if src.get(key):
            names.add(str(src[key]))
    for row in src.get("witness_required") or []:
        if isinstance(row, Mapping):
            names.update(str(row[k]) for k in ("act", "witness", "closing") if row.get(k))
    return {n for n in names if n}


def select_tools_under_k(
    draws: Sequence[set[str]],
    catalogue: set[str],
    k: float,
    k_for: Mapping[str, float] | None = None,
) -> dict[str, float]:
    """Frequency of each catalogue tool across draws.

    A tool below `k`, or below `k_for[tool]` when that is higher, is omitted
    from the result. Omitted means denied for this session. `k` is a
    fraction in ``[0, 1]``.
    """
    k = _unit(k, "k")
    extra = {str(t): _unit(v, f"k_for.{t}") for t, v in dict(k_for or {}).items()}
    n = len(draws)
    freq = dict.fromkeys(catalogue, 0.0)
    if n:
        counts = dict.fromkeys(catalogue, 0)
        for named in draws:
            for tool in named:
                if tool in counts:
                    counts[tool] += 1
        freq = {t: counts[t] / n for t in catalogue}
    return {
        t: f for t, f in freq.items()
        if f >= extra.get(t, k)
    }


def _votes(n: int, produce: Callable[[], Any | None]) -> list[Any | None]:
    """n answers, with a raise or a None counting as an empty vote.

    Dropping failures from the list made one success in five look like
    frequency 1.0. The documented rule is the other direction: a failed
    draw votes for nothing, and nothing is not a grant.
    """
    out: list[Any | None] = []
    for _ in range(n):
        try:
            out.append(produce())
        except Exception:  # noqa: BLE001 - a compiler hiccup is an empty vote
            out.append(None)
    return out


def _draws(value: int) -> int:
    try:
        n = int(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"draws must be a positive integer, not {value!r}") from exc
    if n < 1:
        raise ValueError(f"draws must be a positive integer, not {n}")
    return n


def _unit(value: float, name: str) -> float:
    try:
        out = float(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{name} must be a fraction in [0, 1], not {value!r}") from exc
    if out < 0.0 or out > 1.0:
        raise ValueError(f"{name} must be a fraction in [0, 1], not {out}")
    return out


def _freeze(value: Any) -> Any:
    if isinstance(value, Mapping):
        return tuple(sorted((str(k), _freeze(v)) for k, v in value.items()))
    if isinstance(value, (list, tuple)):
        return tuple(_freeze(v) for v in value)
    return value


def _rule_floor(rule: Mapping[str, Any], k: float,
                k_for: Mapping[str, float]) -> float:
    named = tools_named(rule)
    if not named:
        return k
    return max([k, *(k_for[t] for t in named if t in k_for)], default=k)


def _aggregate_kind(rows: list[list[Any]], k: float,
                    k_for: Mapping[str, float], n: int) -> list[Any]:
    from collections import Counter

    votes: Counter[Any] = Counter()
    first: dict[Any, Any] = {}
    for draw in rows:
        seen = set()
        for item in draw:
            key = _freeze(item)
            if key in seen:
                continue
            seen.add(key)
            votes[key] += 1
            first.setdefault(key, item)
    kept = []
    for key, count in votes.items():
        item = first[key]
        floor = _rule_floor(item, k, k_for) if isinstance(item, Mapping) else k
        if count / n >= floor:
            kept.append(item)
    return kept


def _aggregate_rules(
    draws: Sequence[Mapping[str, Any]],
    k: float,
    k_for: Mapping[str, float],
) -> dict[str, Any]:
    n = len(draws)
    k = _unit(k, "k")
    out: dict[str, Any] = {
        "precedence": _aggregate_kind(
            [list(d.get("precedence") or []) for d in draws], k, k_for, n),
        "invalidations": _aggregate_kind(
            [list(d.get("invalidations") or []) for d in draws], k, k_for, n),
        "entities": _aggregate_kind(
            [list(d.get("entities") or []) for d in draws], k, k_for, n),
        "distinct_subjects": sum(1 for d in draws if d.get("distinct_subjects")) / n >= k,
        "idempotency": sum(1 for d in draws if d.get("idempotency")) / n >= k,
    }
    return out


def _aggregate_session(
    draws: Sequence[Mapping[str, Any]],
    catalogue: set[str],
    k: float,
    k_for: Mapping[str, float],
) -> dict[str, Any]:
    n = len(draws)
    k = _unit(k, "k")
    rules = _aggregate_rules([d.get("rules") or {} for d in draws], k, k_for)
    duties_src = [d.get("duties") or {} for d in draws]
    duties: dict[str, Any] = {
        "actor_tool": None,
        "actor_arg": None,
        "duty_pairs": _aggregate_kind(
            [list(d.get("duty_pairs") or []) for d in duties_src], k, k_for, n),
        "gated_act": None,
        "witness_required": _aggregate_kind(
            [list(d.get("witness_required") or []) for d in duties_src], k, k_for, n),
    }
    # Majority for the single-valued duty fields.
    from collections import Counter

    for field in ("actor_tool", "gated_act"):
        votes = Counter(d.get(field) for d in duties_src if d.get(field))
        if votes:
            winner, count = votes.most_common(1)[0]
            if count / n >= k_for.get(str(winner), k):
                duties[field] = winner
    if duties["actor_tool"]:
        args = Counter(d.get("actor_arg") for d in duties_src
                       if d.get("actor_tool") == duties["actor_tool"] and d.get("actor_arg"))
        if args:
            duties["actor_arg"] = args.most_common(1)[0][0]
    budgets_src = [d.get("budgets") or {} for d in draws]
    freq = select_tools_under_k(
        [tools_named(d) for d in draws], catalogue, k, k_for)
    scope = sorted(freq)
    budgets = {
        "value": _aggregate_kind(
            [list(b.get("value") or []) for b in budgets_src], k, k_for, n),
        "calls": _aggregate_kind(
            [list(b.get("calls") or []) for b in budgets_src], k, k_for, n),
        "recipients": _aggregate_kind(
            [list(b.get("recipients") or []) for b in budgets_src], k, k_for, n),
        "scope": scope,
    }
    return {"budgets": budgets, "rules": rules, "duties": duties,
            "tool_freq": freq}

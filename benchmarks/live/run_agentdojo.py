"""Live AgentDojo evaluation: run a real LLM agent under real injection attacks,
with the Clay Seal broker as an ablatable defense, and report attack-success rate
(ASR) and task utility.

    OPENAI_API_KEY=... python -m benchmarks.live.run_agentdojo --suite banking \
        --n-user 6 --n-inj 3 --ablations none,floor,envelope
"""
from __future__ import annotations

import argparse
import os
import re
import statistics
import sys
import time
from collections import Counter

_REAL_OPENAI = None  # captured before any patching, so the OpenAI backup is restorable
# Upstream flakiness counters, reported at the end of a run so a result always
# says how much the backend had to be retried to produce it.
_TRANSIENT: Counter = Counter()


def _configure_provider(model: str) -> str:
    """Route every OpenAI client (AgentDojo's agent LLM and our planner) per model.
    Default to Azure OpenAI for the models it serves (AZURE_OPENAI_DEPLOYMENTS, the
    deployment names, which we set to valid AgentDojo ModelsEnum ids); fall back to
    public OpenAI for any other model, or when Azure is not configured. Patching
    the ``openai.OpenAI`` symbol covers both AgentDojo's ``openai.OpenAI()`` and our
    planner's ``from openai import OpenAI``.

    Azure gpt-5 deployments reject an explicit ``temperature=0`` (our planner sends
    it) and want max_completion_tokens, but AgentDojo omits both by default, so
    stripping a literal 0 at the boundary is all that is needed."""
    global _REAL_OPENAI
    import openai

    if _REAL_OPENAI is None:
        _REAL_OPENAI = openai.OpenAI

    # Generic OpenAI-compatible endpoint: xAI (Grok), Together, Groq, Fireworks,
    # a local vLLM, anything that speaks /v1/chat/completions. Checked first so
    # it can override the OpenAI default without unsetting credentials.
    #
    # AgentDojo validates the model id against its own ModelsEnum, so a run
    # against a non-OpenAI model keeps a recognized id on the AgentDojo side
    # while the client underneath talks to the compatible endpoint. The id is
    # therefore NOT the model that answered, which is why COMPAT_LABEL is
    # required: a result file that names the wrong model is worse than no
    # result. The label is what gets recorded and published.
    compat_url = os.environ.get("OPENAI_COMPAT_BASE_URL")
    compat_key = os.environ.get("OPENAI_COMPAT_KEY")
    compat_model = os.environ.get("OPENAI_COMPAT_MODEL")
    compat_label = os.environ.get("OPENAI_COMPAT_LABEL") or compat_model
    if compat_url and compat_key and compat_model:
        from openai import OpenAI as _OpenAI

        def _compat_factory(*_a, **_k):
            client = _OpenAI(base_url=compat_url, api_key=compat_key)
            _orig = client.chat.completions.create

            def _create(*a, **k):
                # Rewrite the AgentDojo-facing id to the model actually served.
                k["model"] = compat_model
                # Endpoints vary on which sampling params they accept; a
                # literal temperature=0 is the common rejection.
                if k.get("temperature") == 0:
                    k.pop("temperature", None)

                # `developer` is OpenAI's newer name for the system role.
                # Foundry's schema validator only knows the original four and
                # rejects the request outright (422), so translate rather than
                # drop: losing the system prompt would silently change the
                # agent's instructions and invalidate the comparison.
                for msg in k.get("messages") or []:
                    if isinstance(msg, dict) and msg.get("role") == "developer":
                        msg["role"] = "system"

                # Reasoning models spend the completion budget on reasoning
                # tokens before emitting anything. grok-4 with AgentDojo's
                # default max_tokens returns finish_reason=length,
                # completion_tokens=0, and an empty message, which AgentDojo
                # surfaces as a failed turn. Left alone that reads as the model
                # being bad at the task, and would be published as such. Raise
                # the floor so the visible answer has room after the thinking.
                floor = int(os.environ.get("OPENAI_COMPAT_MIN_MAX_TOKENS", "0") or 0)
                if floor and (k.get("max_tokens") or 0) < floor:
                    k["max_tokens"] = floor

                # Some served models accept only one tool call per turn, while
                # AgentDojo emits parallel calls by default. A serving
                # constraint rather than a modelling choice, and it does change
                # agent behaviour (sequential rather than batched tool use), so
                # any rung needing it must say so in its published result.
                no_parallel = os.environ.get("OPENAI_COMPAT_NO_PARALLEL_TOOLS") == "1"
                if no_parallel and k.get("tools"):
                    k["parallel_tool_calls"] = False

                # Empty text parts. When the model answers with tool calls and
                # no prose, AgentDojo serializes content as
                # [{"type": "text", "text": ""}]. Foundry's validator rejects an
                # empty text part outright (422). Drop the empty parts, and
                # collapse a list that becomes empty to None, which is what an
                # assistant message carrying only tool calls should look like.
                for msg in k.get("messages") or []:
                    if not isinstance(msg, dict):
                        continue
                    content = msg.get("content")
                    if isinstance(content, list):
                        kept = [
                            part for part in content
                            if not (isinstance(part, dict)
                                    and part.get("type") == "text"
                                    and not (part.get("text") or "").strip())
                        ]
                        msg["content"] = kept or (None if msg.get("tool_calls") else "")

                # Foundry's grok-4 GlobalStandard capacity is intermittently
                # unavailable: measured at roughly one request in three
                # returning 424/503, plus occasional 200s carrying zero
                # choices (which AgentDojo hits as an IndexError and scores as
                # a failed turn). That is backend flakiness, not agent
                # behaviour, so retrying is legitimate, but silently retrying
                # would hide a condition that could bias results if failures
                # correlate with particular prompts. Every retry is counted and
                # the total is printed at the end of the run.
                attempts = int(os.environ.get("OPENAI_COMPAT_RETRIES", "0") or 0)
                resp = None
                for attempt in range(attempts + 1):
                    try:
                        resp = _orig(*a, **k)
                        if getattr(resp, "choices", None):
                            break
                        _TRANSIENT["empty_choices"] += 1
                    except Exception as exc:
                        status = getattr(exc, "status_code", None)
                        if status not in (424, 429, 500, 502, 503) or attempt >= attempts:
                            raise
                        _TRANSIENT["http_error"] += 1
                    if attempt < attempts:
                        _TRANSIENT["retries"] += 1
                        time.sleep(min(2 ** attempt, 8))
                if resp is None or not getattr(resp, "choices", None):
                    raise RuntimeError(
                        f"{compat_label}: backend returned no usable completion after "
                        f"{attempts + 1} attempts ({dict(_TRANSIENT)}). This is an upstream "
                        "availability problem, not a result."
                    )

                # Llama's Foundry serving ignores parallel_tool_calls=False and
                # still returns several calls, then rejects the next request
                # because the history now contains a multi-call assistant turn.
                # Truncating the response keeps the history valid and turns
                # batched tool use into sequential tool use: the dropped calls
                # are not lost, the model reissues them on the following turn.
                if no_parallel:
                    for choice in getattr(resp, "choices", []) or []:
                        calls = getattr(choice.message, "tool_calls", None)
                        if calls and len(calls) > 1:
                            choice.message.tool_calls = calls[:1]
                return resp

            client.chat.completions.create = _create
            return client

        openai.OpenAI = _compat_factory
        return f"openai-compat:{compat_url} ({compat_label})"

    az_ep = os.environ.get("AZURE_OPENAI_ENDPOINT")
    az_key = os.environ.get("AZURE_OPENAI_KEY") or os.environ.get("AZURE_OPENAI_API_KEY")
    az_models = {m for m in os.environ.get("AZURE_OPENAI_DEPLOYMENTS",
                                           "gpt-4o-mini-2024-07-18").split(",") if m}
    has_openai = bool(os.environ.get("OPENAI_API_KEY"))
    use_azure = bool(az_ep and az_key) and (model in az_models or not has_openai)

    if use_azure:
        from openai import AzureOpenAI
        api_version = os.environ.get("AZURE_OPENAI_API_VERSION", "2024-12-01-preview")

        def _factory(*_a, **_k):
            client = AzureOpenAI(azure_endpoint=az_ep, api_key=az_key, api_version=api_version)
            _orig = client.chat.completions.create

            def _create(*a, **k):
                if k.get("temperature") == 0:  # gpt-5 only accepts the default
                    k.pop("temperature")
                return _orig(*a, **k)

            client.chat.completions.create = _create
            return client

        openai.OpenAI = _factory
        return f"azure:{az_ep} ({model})"

    # Public OpenAI: the backup for models Azure does not serve, or when Azure is
    # unset. Restore the real client (a prior run may have patched it to Azure).
    openai.OpenAI = _REAL_OPENAI
    return f"openai ({model})"

from agentdojo.agent_pipeline import (
    AgentPipeline,
    PipelineConfig,
    ToolsExecutionLoop,
    ToolsExecutor,
)
from agentdojo.attacks import load_attack
from agentdojo.benchmark import (
    get_suite,
    run_task_with_injection_tasks,
    run_task_without_injection_tasks,
)
from agentdojo.logging import OutputLogger

import benchmarks.live.adaptive_attack

# Registers document_workflow / record_update / schema_field /
# deferred_conditional. The 2024 attacks no longer transfer to a 2026 model
# (undefended ASR 0 of 18 on gpt-5-mini across four of them); these drop the
# authority claim entirely and rely on the injected action being plausible.
import benchmarks.live.attacks_2026  # noqa: F401
from benchmarks.live.broker_defense import BrokerToolsExecutor, LiveBrokerHarness
from benchmarks.live.planner import LLMPlanner

_BENCH_VERSION = "v1.2.2"


def build_pipeline(model: str, ablation: str, planner, recipient_map=None,
                   clean_files=None):
    # Head-to-head: AgentDojo's own built-in defenses on the identical subset.
    if ablation.startswith("builtin:"):
        dname = ablation.split(":", 1)[1]
        cfg = PipelineConfig(llm=model, model_id=None, defense=dname,
                             system_message_name=None, system_message=None)
        pipe = AgentPipeline.from_config(cfg)
        pipe.name = f"{model}-{dname}"
        return pipe, None
    cfg = PipelineConfig(llm=model, model_id=None, defense=None,
                         system_message_name=None, system_message=None)
    pipe = AgentPipeline.from_config(cfg)
    harness = None
    if ablation != "none":
        mode = "envelope" if "envelope" in ablation else "floor"
        rmap = recipient_map if "egress" in ablation else None
        provenance = "provenance" in ablation
        taint = "taint" in ablation
        graduated = "graduated" in ablation
        defer = "defer" in ablation
        defer_allow = "deferallow" in ablation
        replan = "replan" in ablation
        # "...-audit3" caps the session at 3 human interruptions. Sweeping this
        # is what turns two operating points into a safety/usefulness curve.
        m = re.search(r"audit(\d+)", ablation)
        audit_budget = int(m.group(1)) if m else None
        harness = LiveBrokerHarness(mode=mode, planner=planner, recipient_map=rmap,
                                    provenance=provenance, taint=taint,
                                    graduated=graduated, defer=defer,
                                    defer_allow=defer_allow,
                                    audit_budget=audit_budget,
                                    replan=replan,
                                    clean_files=clean_files)
        for e in pipe.elements:
            if isinstance(e, ToolsExecutionLoop):
                e.elements = [BrokerToolsExecutor(harness) if isinstance(x, ToolsExecutor) else x
                              for x in e.elements]
    # Keep the model id in the name: the ImportantInstructions attack reads the
    # model name from the pipeline name to address the injection.
    pipe.name = f"{model}-clayseal-{ablation}"
    return pipe, harness


class OraclePlanner:
    """Ceiling: scope/plan from the task's ground-truth tools (privileged)."""
    def __init__(self, mapping):
        self.mapping = mapping
    def plan(self, query, tools):
        from clayseal.capabilities.monitor import IntentEnvelope, Phase
        gt = self.mapping.get(query) or [n for n, _ in tools]
        phases = tuple(Phase(tools=frozenset([t]), min=1) for t in (self.mapping.get(query) or []))
        # Keep the sound verb-class structure (gather-before-act); see LLMPlanner.
        from benchmarks.live.planner import verb_class_order
        return list(gt), IntentEnvelope(allowed_tools=frozenset(gt), allowed_verbs=frozenset(),
                                        allowed_resource_classes=frozenset(), phases=phases,
                                        phase_order=verb_class_order(phases))


def _oracle_map(suite, user_ids):
    env = suite.load_and_inject_default_environment({})
    m = {}
    for uid in user_ids:
        ut = suite.user_tasks[uid]
        try:
            m[ut.PROMPT] = sorted({c.function for c in ut.ground_truth(env)})
        except Exception:
            m[ut.PROMPT] = None
    return m


def _recipient_map(suite, user_ids):
    """query -> authorized destinations (opaque recipients AND domains) from the
    task's ground-truth calls. One general 'destination binding' primitive: IBANs
    on banking, emails/URLs on workspace/travel/slack. Privileged ceiling; the
    deployable form seeds from provenance of trusted-named resources, not GT."""
    from clayseal.capabilities.hardening.egress_policy import (
        extract_destinations,
        extract_recipients,
    )
    env = suite.load_and_inject_default_environment({})
    m = {}
    for uid in user_ids:
        ut = suite.user_tasks[uid]
        rs, ds = set(), set()
        try:
            for c in ut.ground_truth(env):
                args = dict(c.args)
                rs.update(extract_recipients(args))
                ds.update(extract_destinations("", args))
        except Exception:
            pass
        m[ut.PROMPT] = (rs, ds)
    return m


def run(suite_name, model, n_user, n_inj, ablations, attack_name, inj_ids_arg=None):
    print(f"[provider] {_configure_provider(model)}")
    from openai import OpenAI
    client = OpenAI()
    llm_planner = LLMPlanner(client, model)
    suite = get_suite(_BENCH_VERSION, suite_name)
    user_ids = list(suite.user_tasks)[:n_user]
    # `[:n_inj]` is not a neutral sample. In banking, injection tasks 0-3 all ask
    # for a transaction whose SUBJECT LINE carries a piece of the user's personal
    # data ("the music streaming service the user is subscribed to"), which no
    # real document would ever instruct, while task 4 ("modify the recipient of a
    # recurring payment") is exactly what a landlord notice legitimately says.
    #
    # So every run that takes the first three is measuring the goals a model is
    # most likely to balk at on CONTENT grounds, independently of how the
    # injection is framed, and that ceiling is invisible in the ASR number.
    # `--inj-ids` makes the choice explicit; the default is unchanged.
    if inj_ids_arg:
        known = list(suite.injection_tasks)
        inj_ids = [i if i in known else f"injection_task_{i}" for i in inj_ids_arg]
        unknown = [i for i in inj_ids if i not in known]
        if unknown:
            raise SystemExit(f"unknown injection tasks {unknown}; have {known}")
    else:
        inj_ids = list(suite.injection_tasks)[:n_inj]
    oracle_planner = OraclePlanner(_oracle_map(suite, user_ids))
    def planner_for(ablation: str):
        """Resolve by SHAPE, not by exact name.

        This was an exact-name dict. The identical pattern in
        diagnose_methodology silently produced `planner=None` for an unlisted
        ablation, which builds NO intent envelope and reports a perfect score
        for a defense that is not running. The frontier sweep generates ablation
        names combinatorially, so an exact-name map here would fail the same way
        on almost every new point.
        """
        if ablation == "none":
            return None
        if "oracle" in ablation:
            return oracle_planner
        return llm_planner

    planners = {ab: planner_for(ab) for ab in ablations}
    unresolved = [a for a in ablations if a != "none" and planners[a] is None]
    if unresolved:
        raise SystemExit(f"no planner for {unresolved}; they would run undefended")
    recipient_map = _recipient_map(suite, user_ids)
    # Pre-contamination filesystem (empty injections). Banking attacks overwrite
    # goal-named bills; provenance seeding must use this snapshot, not live env.
    from benchmarks.live.broker_defense import snapshot_trusted_files
    clean_files = snapshot_trusted_files(
        suite.load_and_inject_default_environment({}))
    print(f"suite={suite_name} model={model} attack={attack_name} | "
          f"{len(user_ids)} user x {len(inj_ids)} injection tasks = {len(user_ids)*len(inj_ids)} runs/ablation\n")

    out = {}
    import tempfile
    logdir = tempfile.mkdtemp(prefix="adojo-")
    for ab in ablations:
        # One bad ablation (e.g. an unknown builtin defense name) must not lose the
        # whole cell's other ablations; record its error and continue.
        try:
            pipe, harness = build_pipeline(
                model, ab, planners.get(ab), recipient_map, clean_files=clean_files)
            attack = load_attack(attack_name, suite, pipe)
        except Exception as exc:
            print(f"  {ab:9} SKIPPED: {type(exc).__name__}: {exc}")
            out[ab] = {"error": f"{type(exc).__name__}: {exc}"}
            continue
        clean, util, sec = [], [], []
        with OutputLogger(logdir, live=None):
            for uid in user_ids:
                cu, _ = run_task_without_injection_tasks(suite, pipe, suite.user_tasks[uid], None, True)
                clean.append(cu)
            for uid in user_ids:
                u_res, s_res = run_task_with_injection_tasks(
                    suite, pipe, suite.user_tasks[uid], attack, None, True, injection_tasks=inj_ids)
                util += list(u_res.values())
                sec += list(s_res.values())
        # Friction: STEP_UP decisions (graduated response, halts autonomously but
        # is human-recoverable), reported as step-ups per user task so the metric
        # triple is (security=ASR, utility, friction), not security alone.
        step_ups = sum(1 for d in harness.decisions if d.get("outcome") == "STEP_UP") if harness else 0
        n_tasks = max(1, len(user_ids))
        hint_r = getattr(harness, "hint_retries", 0) if harness else 0
        hint_h = getattr(harness, "hint_retry_hits", 0) if harness else 0
        gated = (
            f" | allow/block {harness.allows}/{harness.blocks} step-ups {step_ups}"
            f" hint-retry {hint_h}/{hint_r}"
        ) if harness else ""
        out[ab] = dict(clean_utility=statistics.fmean(clean), utility_under_attack=statistics.fmean(util),
                       asr=statistics.fmean(sec), n=len(sec),
                       friction=step_ups / n_tasks, step_ups=step_ups,
                       hint_retries=hint_r, hint_retry_hits=hint_h)
        print(f"  {ab:9} clean-utility {out[ab]['clean_utility']*100:5.1f}%  "
              f"ASR {out[ab]['asr']*100:5.1f}%  utility-under-attack {out[ab]['utility_under_attack']*100:5.1f}%"
              f"  friction {out[ab]['friction']:.2f}/task  (n={len(sec)}){gated}")
    return out


def main(argv=None):
    p = argparse.ArgumentParser()
    p.add_argument("--suite", default="banking")
    p.add_argument("--model", default="gpt-4o-mini-2024-07-18")
    p.add_argument("--n-user", type=int, default=6)
    p.add_argument("--n-inj", type=int, default=3)
    p.add_argument("--ablations", default="none,floor,envelope")
    p.add_argument("--attack", default="important_instructions")
    p.add_argument("--inj-ids", default="",
                   help="comma-separated injection task ids or indices; "
                        "overrides --n-inj. The default [:n] is not a "
                        "neutral sample, see run().")
    args = p.parse_args(argv if argv is not None else sys.argv[1:])
    print("=== Live AgentDojo: ASR + utility with Clay Seal ablations ===")
    inj_ids_arg = [x.strip() for x in args.inj_ids.split(',') if x.strip()]
    run(args.suite, args.model, args.n_user, args.n_inj,
        [a.strip() for a in args.ablations.split(",")], args.attack,
        inj_ids_arg=inj_ids_arg)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

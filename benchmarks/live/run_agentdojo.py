"""Live AgentDojo evaluation: run a real LLM agent under real injection attacks,
with the Clay Seal broker as an ablatable defense, and report attack-success rate
(ASR) and task utility.

    OPENAI_API_KEY=... python -m benchmarks.live.run_agentdojo --suite banking \
        --n-user 6 --n-inj 3 --ablations none,floor,envelope
"""
from __future__ import annotations

import argparse
import os
import statistics
import sys


def _maybe_use_azure() -> str | None:
    """Route every OpenAI client (AgentDojo's agent LLM and our planner) to Azure
    OpenAI when AZURE_OPENAI_ENDPOINT is set. AgentDojo builds its client with a
    bare ``openai.OpenAI()`` and our planner with ``from openai import OpenAI``, so
    patching the ``openai.OpenAI`` symbol to an AzureOpenAI factory covers both.
    The AgentDojo model id doubles as the Azure DEPLOYMENT name (we name the
    deployments after valid ModelsEnum ids), so no per-call routing change is
    needed. AgentDojo already omits temperature (0.0 is falsy -> NOT_GIVEN) and
    sends no max_tokens, so gpt-5 deployments accept the requests unmodified."""
    ep = os.environ.get("AZURE_OPENAI_ENDPOINT")
    if not ep:
        return None
    import openai
    from openai import AzureOpenAI

    key = os.environ.get("AZURE_OPENAI_KEY") or os.environ["AZURE_OPENAI_API_KEY"]
    api_version = os.environ.get("AZURE_OPENAI_API_VERSION", "2024-12-01-preview")

    def _factory(*_a, **_k):
        return AzureOpenAI(azure_endpoint=ep, api_key=key, api_version=api_version)

    openai.OpenAI = _factory  # agentdojo get_llm(): openai.OpenAI(); planner: OpenAI()
    return ep

from agentdojo.agent_pipeline import (
    AgentPipeline, PipelineConfig, ToolsExecutionLoop, ToolsExecutor)
from agentdojo.attacks import load_attack
from agentdojo.benchmark import (
    get_suite, run_task_with_injection_tasks, run_task_without_injection_tasks)
from agentdojo.logging import OutputLogger

import benchmarks.live.adaptive_attack  # noqa: F401  (registers envelope_aware)
from benchmarks.live.broker_defense import BrokerToolsExecutor, LiveBrokerHarness
from benchmarks.live.planner import LLMPlanner

_BENCH_VERSION = "v1.2.2"


def build_pipeline(model: str, ablation: str, planner, recipient_map=None):
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
        harness = LiveBrokerHarness(mode=mode, planner=planner, recipient_map=rmap,
                                    provenance=provenance, taint=taint, graduated=graduated)
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
        from agentauth.capabilities.monitor import IntentEnvelope, Phase
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
    from agentauth.capabilities.hardening.egress_policy import (
        extract_destinations, extract_recipients)
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


def run(suite_name, model, n_user, n_inj, ablations, attack_name):
    az = _maybe_use_azure()
    if az:
        print(f"[azure] routing OpenAI clients to {az}")
    from openai import OpenAI
    client = OpenAI()
    llm_planner = LLMPlanner(client, model)
    suite = get_suite(_BENCH_VERSION, suite_name)
    user_ids = list(suite.user_tasks)[:n_user]
    inj_ids = list(suite.injection_tasks)[:n_inj]
    oracle_planner = OraclePlanner(_oracle_map(suite, user_ids))
    planners = {"floor": llm_planner, "envelope": llm_planner,
                "envelope-provenance": llm_planner,
                "envelope-taint": llm_planner,
                "envelope-taint-graduated": llm_planner,
                "oracle": oracle_planner, "oracle-envelope": oracle_planner,
                "oracle-egress": oracle_planner, "floor-egress": llm_planner,
                "oracle-envelope-egress": oracle_planner}
    recipient_map = _recipient_map(suite, user_ids)
    print(f"suite={suite_name} model={model} attack={attack_name} | "
          f"{len(user_ids)} user x {len(inj_ids)} injection tasks = {len(user_ids)*len(inj_ids)} runs/ablation\n")

    out = {}
    import tempfile
    logdir = tempfile.mkdtemp(prefix="adojo-")
    for ab in ablations:
        pipe, harness = build_pipeline(model, ab, planners.get(ab), recipient_map)
        attack = load_attack(attack_name, suite, pipe)
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
        # Friction: STEP_UP decisions (graduated response — halts autonomously but
        # is human-recoverable), reported as step-ups per user task so the metric
        # triple is (security=ASR, utility, friction), not security alone.
        step_ups = sum(1 for d in harness.decisions if d.get("outcome") == "STEP_UP") if harness else 0
        n_tasks = max(1, len(user_ids))
        gated = f" | allow/block {harness.allows}/{harness.blocks} step-ups {step_ups}" if harness else ""
        out[ab] = dict(clean_utility=statistics.fmean(clean), utility_under_attack=statistics.fmean(util),
                       asr=statistics.fmean(sec), n=len(sec),
                       friction=step_ups / n_tasks, step_ups=step_ups)
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
    args = p.parse_args(argv if argv is not None else sys.argv[1:])
    print("=== Live AgentDojo: ASR + utility with Clay Seal ablations ===")
    run(args.suite, args.model, args.n_user, args.n_inj,
        [a.strip() for a in args.ablations.split(",")], args.attack)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

"""Which library modules can the product actually reach, and which run.

Two passes, because either alone gives a wrong answer:

* **static** import closure from the product entry points. A module outside it
  cannot execute in the gateway under any configuration.
* **runtime** ``sys.settrace`` over a real workload, which catches the opposite
  error, a module that is imported and still never runs.

Static alone calls the budget machinery integrated because it is imported;
runtime alone calls it dead because most corpora configure no budget. The pair
separates *unwired* from *unexercised by this workload*.

Results in ``docs/INTEGRATION.md``.
"""

from __future__ import annotations

import argparse
import ast
import json
import pathlib
import sys
from collections import Counter, deque

ROOT = pathlib.Path(__file__).resolve().parents[1]
LIB = ROOT / "clayseal"

PRODUCT_ENTRIES = (
    "clayseal.capabilities.deployable_stack",
    "clayseal.capabilities.broker",
)
PUBLIC_ENTRIES = (
    # The package __init__ IS the public API: it carries the lazy _EXPORTS map,
    # so anything a user reaches by `from clayseal.capabilities import X` is
    # wired even if no other module imports it. Omitting these two overstated
    # the orphan count by counting the whole public surface as unreachable.
    "clayseal",
    "clayseal.capabilities",
    "clayseal.core",
    "clayseal.capabilities.cli",
    "clayseal.capabilities.guardrail",
    "clayseal.capabilities.mcp_proxy",
    "clayseal.capabilities.http_gateway",
    "clayseal.capabilities.policy",
    "clayseal.capabilities.integration",
    "clayseal.capabilities.aio",
    "clayseal.capabilities.layer",
)
TRACE_CORPORA = ("sleight", "redcode", "mcp_attack", "agent_threat_bench",
                 "advbench_agent")


def _modname(p: pathlib.Path) -> str:
    rel = str(p.relative_to(ROOT))[:-3].replace("/", ".")
    return rel.removesuffix(".__init__")


def _module_files() -> dict[str, pathlib.Path]:
    return {_modname(p): p for p in LIB.rglob("*.py")
            if "__pycache__" not in str(p)}


def _import_edges(files: dict[str, pathlib.Path]) -> dict[str, set[str]]:
    edges: dict[str, set[str]] = {}
    for mod, path in files.items():
        try:
            tree = ast.parse(path.read_text())
        except (OSError, SyntaxError):
            edges[mod] = set()
            continue
        out: set[str] = set()
        pkg = mod.rsplit(".", 1)[0]
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                out.update(a.name for a in node.names)
            elif isinstance(node, ast.ImportFrom):
                if node.level:
                    base = pkg
                    for _ in range(node.level - 1):
                        base = base.rsplit(".", 1)[0]
                    target = f"{base}.{node.module}" if node.module else base
                else:
                    target = node.module or ""
                out.add(target)
                out.update(f"{target}.{a.name}" for a in node.names)
        # Lazy public surface: `capabilities/__init__.py` maps export name ->
        # submodule as STRINGS, resolved in __getattr__. Those are real edges
        # and an AST import walk cannot see them, so a lazy re-export reads as
        # an orphan. Resolve any dict-of-str-to-str against sibling modules.
        for node in ast.walk(tree):
            if not isinstance(node, ast.Dict):
                continue
            for value in node.values:
                if isinstance(value, ast.Constant) and isinstance(value.value, str):
                    cand = f"{pkg}.{value.value}"
                    if cand in files:
                        out.add(cand)
        edges[mod] = {o for o in out if o in files}
    return edges


def _closure(roots, edges, files) -> set[str]:
    seen: set[str] = set()
    queue = deque(roots)
    while queue:
        mod = queue.popleft()
        if mod in seen or mod not in files:
            continue
        seen.add(mod)
        queue.extend(edges.get(mod, ()))
    return seen


def _traced_modules() -> set[str] | None:
    """Modules entered during a real product-path run, or None if unavailable."""
    try:
        from benchmarks.core.broker_eval import run_broker_benchmark
        from benchmarks.datasets.base import get_loader
    except Exception:
        return None
    tasks = []
    for name in TRACE_CORPORA:
        try:
            tasks.extend(get_loader(name).load(limit=40))
        except Exception:
            continue
    if not tasks:
        return None
    hit: set[str] = set()
    lib = str(LIB)

    def tracer(frame, event, _arg):
        if event == "call":
            fn = frame.f_code.co_filename
            if fn.startswith(lib):
                hit.add(fn)
        return None

    sys.settrace(tracer)
    try:
        run_broker_benchmark(tasks, entailment_judge=None)
    finally:
        sys.settrace(None)
    return hit


def audit() -> dict:
    files = _module_files()
    edges = _import_edges(files)
    product = _closure(PRODUCT_ENTRIES, edges, files)
    public = _closure(PRODUCT_ENTRIES + PUBLIC_ENTRIES, edges, files)
    orphans = sorted(set(files) - public)
    out = {
        "modules": len(files),
        "reachable_from_product": len(product),
        "reachable_from_any_entry_point": len(public),
        "orphans": orphans,
    }
    traced = _traced_modules()
    if traced is not None:
        executed = {m for m, p in files.items() if str(p) in traced}
        out["executed_on_product_path"] = len(executed)
        out["imported_but_cold"] = sorted(product - executed)
    return out


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--json", type=pathlib.Path, default=None)
    ap.add_argument("--max-orphans", type=int, default=None,
                    help="exit non-zero if orphan count exceeds this (ratchet)")
    args = ap.parse_args(argv)

    report = audit()
    print(f"library modules                       {report['modules']:>4}")
    print(f"reachable from DeployableStack/Broker {report['reachable_from_product']:>4}")
    print(f"reachable from any public entry point {report['reachable_from_any_entry_point']:>4}")
    if "executed_on_product_path" in report:
        print(f"executed on a real product-path run   {report['executed_on_product_path']:>4}")
    print(f"ORPHANED (no entry point reaches)     {len(report['orphans']):>4}\n")
    groups = Counter(o.rsplit(".", 1)[0] for o in report["orphans"])
    for pkg, n in groups.most_common():
        print(f"  {n:>3}  {pkg}")
    print("\nSee docs/INTEGRATION.md for which of these back a published claim.")
    if args.json:
        args.json.write_text(json.dumps(report, indent=2))
    if args.max_orphans is not None and len(report["orphans"]) > args.max_orphans:
        print(f"\nFAIL: {len(report['orphans'])} orphans exceeds {args.max_orphans}")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

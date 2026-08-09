"""Dataset loader protocol and registry.

A loader turns an external corpus into ``list[BenchmarkTask]``. Loaders are
registered by name so the CLI can select one with ``--dataset <name>``. Heavy
loaders (AgentDojo, InjecAgent) import their dependency lazily inside ``load``
so the harness itself stays importable with no extra installs.
"""
from __future__ import annotations

from typing import Callable, Protocol, runtime_checkable

from benchmarks.core.events import BenchmarkTask


@runtime_checkable
class DatasetLoader(Protocol):
    name: str

    def load(self, *, limit: int | None = None) -> list[BenchmarkTask]:  # pragma: no cover - protocol
        ...


_REGISTRY: dict[str, Callable[[], DatasetLoader]] = {}


def register_loader(name: str, factory: Callable[[], DatasetLoader]) -> None:
    _REGISTRY[name] = factory


def get_loader(name: str) -> DatasetLoader:
    if name not in _REGISTRY:
        raise KeyError(f"unknown dataset {name!r}; known: {sorted(_REGISTRY)}")
    return _REGISTRY[name]()


def available_datasets() -> list[str]:
    return sorted(_REGISTRY)


# Register built-in loaders. Imports are deferred to factory call time so an
# unavailable optional dependency only fails when that dataset is requested.
def _fixture_factory() -> DatasetLoader:
    from benchmarks.datasets.fixture import FixtureLoader

    return FixtureLoader()


def _agentdojo_factory() -> DatasetLoader:
    from benchmarks.datasets.agentdojo import AgentDojoLoader

    return AgentDojoLoader()


def _injecagent_factory() -> DatasetLoader:
    from benchmarks.datasets.injecagent import InjecAgentLoader

    return InjecAgentLoader()


def _toolemu_factory() -> DatasetLoader:
    from benchmarks.datasets.toolemu import ToolEmuLoader

    return ToolEmuLoader()


def _atif_factory() -> DatasetLoader:
    from benchmarks.datasets.atif import AtifLoader

    return AtifLoader()


def _tau2_factory() -> DatasetLoader:
    from benchmarks.datasets.tau2 import Tau2Loader

    return Tau2Loader()


def _bfcl_factory() -> DatasetLoader:
    from benchmarks.datasets.bfcl import BfclLoader

    return BfclLoader()


def _redcode_factory() -> DatasetLoader:
    from benchmarks.datasets.redcode import RedCodeLoader

    return RedCodeLoader()


def _agentharm_factory() -> DatasetLoader:
    from benchmarks.datasets.agentharm import AgentHarmLoader

    return AgentHarmLoader()


def _asb_factory() -> DatasetLoader:
    from benchmarks.datasets.asb import AsbLoader

    return AsbLoader()


def _atb_factory() -> DatasetLoader:
    from benchmarks.datasets.agent_threat_bench import AgentThreatBenchLoader

    return AgentThreatBenchLoader()


def _ipi_coding_factory() -> DatasetLoader:
    from benchmarks.datasets.ipi_coding import IpiCodingLoader

    return IpiCodingLoader()


def _sleight_factory() -> DatasetLoader:
    from benchmarks.datasets.sleight import SleightLoader

    return SleightLoader()


def _advbench_factory() -> DatasetLoader:
    from benchmarks.datasets.advbench_agent import AdvBenchAgentLoader

    return AdvBenchAgentLoader()


def _mcp_attack_factory() -> DatasetLoader:
    from benchmarks.datasets.mcp_attack import McpAttackLoader

    return McpAttackLoader()



def _atbench_factory() -> DatasetLoader:
    from benchmarks.datasets.atbench import ATBenchLoader

    return ATBenchLoader()


def _atbench500_factory() -> DatasetLoader:
    from benchmarks.datasets.atbench import ATBenchLoader

    return ATBenchLoader(release="ATBench500")


def _agentleak_factory() -> DatasetLoader:
    from benchmarks.datasets.agentleak import AgentLeakLoader

    return AgentLeakLoader()


def _mind2web_sc_factory() -> DatasetLoader:
    from benchmarks.datasets.mind2web_sc import Mind2WebScLoader

    return Mind2WebScLoader()


def _b3_factory() -> DatasetLoader:
    from benchmarks.datasets.b3 import B3Loader

    return B3Loader()

register_loader("fixture", _fixture_factory)
register_loader("agentdojo", _agentdojo_factory)
register_loader("injecagent", _injecagent_factory)
register_loader("toolemu", _toolemu_factory)
register_loader("atif", _atif_factory)
register_loader("tau2", _tau2_factory)
register_loader("bfcl", _bfcl_factory)
register_loader("redcode", _redcode_factory)
register_loader("agentharm", _agentharm_factory)
register_loader("asb", _asb_factory)
register_loader("sleight", _sleight_factory)
register_loader("agent_threat_bench", _atb_factory)
register_loader("ipi_coding", _ipi_coding_factory)
register_loader("advbench_agent", _advbench_factory)
register_loader("mcp_attack", _mcp_attack_factory)
register_loader("atbench", _atbench_factory)
register_loader("atbench500", _atbench500_factory)
register_loader("agentleak", _agentleak_factory)
register_loader("mind2web_sc", _mind2web_sc_factory)
register_loader("b3", _b3_factory)

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


def _sleight_factory() -> DatasetLoader:
    from benchmarks.datasets.sleight import SleightLoader

    return SleightLoader()


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

"""Dataset loaders: normalize external agent-security corpora to BenchmarkTask."""
from __future__ import annotations

from benchmarks.datasets.base import DatasetLoader, get_loader, register_loader

__all__ = ["DatasetLoader", "get_loader", "register_loader"]

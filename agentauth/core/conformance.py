"""Provider conformance kit.

A portable check that an identity provider satisfies the L1 contract other layers
rely on: it exposes ``name`` / ``to_binding`` / ``build_session`` and, for each sample
credential, produces a well-formed :class:`AuthorityBinding`. Returns a list of
problems, empty when the provider conforms, so third-party providers can be validated
in their own test suites without importing any specific layer.
"""
from __future__ import annotations

from typing import Any

from agentauth.core.schemas import validate_binding


def check_identity_provider(provider: Any, samples: list[dict[str, Any]]) -> list[str]:
    """Return conformance problems for ``provider`` over ``samples`` ( [] == conforms )."""
    problems: list[str] = []

    name = getattr(provider, "name", None)
    if not name or not isinstance(name, str):
        problems.append("provider.name must be a non-empty string")

    for method in ("to_binding", "build_session"):
        if not callable(getattr(provider, method, None)):
            problems.append(f"provider must implement {method}()")

    if not callable(getattr(provider, "to_binding", None)):
        return problems  # can't exercise samples without it

    for i, sample in enumerate(samples):
        try:
            binding = provider.to_binding(sample)
        except Exception as exc:  # noqa: BLE001 - reporting what a third-party
            # provider raised is this function's whole job. Narrowing the catch
            # would make an unexpected exception crash the conformance check
            # instead of appearing in its report, which is the opposite of what
            # a conformance check is for.
            problems.append(f"sample[{i}]: to_binding raised {type(exc).__name__}: {exc}")
            continue
        to_dict = getattr(binding, "to_dict", None)
        if not callable(to_dict):
            problems.append(f"sample[{i}]: to_binding did not return an AuthorityBinding")
            continue
        problems.extend(f"sample[{i}]: {p}" for p in validate_binding(to_dict()))

    return problems

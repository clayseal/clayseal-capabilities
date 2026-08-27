"""Environment lookup, with one release of back-compatibility for ``AGENTAUTH_*``.

Every setting this library reads is named ``CLAYSEAL_*``. Deployments configured
before the 0.6 rename set ``AGENTAUTH_*``, and dropping those names silently
would not fail loudly. Most of these settings fail CLOSED when absent, so the
symptom would be refused work rather than an open control; but ``CLAYSEAL_ENV``
fails the other way, and several of the rest name the store that replay defense
reads. Losing either quietly is worse than a warning.

So: read the new name, fall back to the old one, and say once per variable that
the old name is going away.

Nothing here mutates ``os.environ``. The sandbox driver spawns subprocesses, and
a library that edits the process environment changes what those children
inherit, which is not a decision this module gets to make for its host.
"""
from __future__ import annotations

import logging
import os

_LOG = logging.getLogger(__name__)

#: Prefix pairs, current first. Only ``CLAYSEAL_``/``AGENTAUTH_`` is remapped:
#: ``AGENT_RECEIPTS_*`` belongs to the receipts distribution and is not ours to
#: rename.
_CURRENT = "CLAYSEAL_"
_LEGACY = "AGENTAUTH_"

#: Variables already warned about, so a setting read on every decision warns
#: once rather than once per call.
_WARNED: set[str] = set()


def legacy_name(name: str) -> str | None:
    """The pre-0.6 spelling of ``name``, or None if it has no legacy spelling."""
    if not name.startswith(_CURRENT):
        return None
    return _LEGACY + name[len(_CURRENT):]


def get(name: str, default: str = "") -> str:
    """``os.environ.get`` for a ``CLAYSEAL_*`` setting, honouring the old name.

    The current name wins outright: a deployment mid-migration that sets both
    gets the one it just wrote, not the one it forgot to delete.
    """
    value = os.environ.get(name)
    if value is not None:
        return value

    legacy = legacy_name(name)
    if legacy is None:
        return default

    value = os.environ.get(legacy)
    if value is None:
        return default

    if legacy not in _WARNED:
        _WARNED.add(legacy)
        _LOG.warning(
            "%s is deprecated and will stop being read in 0.7; rename it to %s",
            legacy,
            name,
        )
    return value


def is_set(name: str) -> bool:
    """True if ``name`` (or its legacy spelling) is present at all, empty or not."""
    if name in os.environ:
        return True
    legacy = legacy_name(name)
    return legacy is not None and legacy in os.environ


def reset_warnings() -> None:
    """Forget which legacy names have warned. For tests."""
    _WARNED.clear()

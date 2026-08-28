"""Compatibility shim: `agentauth.core` is now `clayseal.core`.

Importing this installs an alias hook for the whole subtree and then replaces
this module with the real one, so `agentauth.core` and `clayseal.core` are the
same object and share one set of globals. See `agentauth/_alias.py`.
"""
from __future__ import annotations

import sys

from agentauth._alias import install, warn_once

install()
warn_once("agentauth.core", "clayseal.core")

import clayseal.core as _real

sys.modules[__name__] = _real

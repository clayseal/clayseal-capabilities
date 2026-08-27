"""Compatibility shim: `agentauth.capabilities` is now `clayseal.capabilities`.

Importing this installs an alias hook for the whole subtree and then replaces
this module with the real one, so `agentauth.capabilities` and `clayseal.capabilities` are the
same object and share one set of globals. See `agentauth/_alias.py`.
"""
from __future__ import annotations

import sys

from agentauth._alias import install, warn_once

install()
warn_once("agentauth.capabilities", "clayseal.capabilities")

import clayseal.capabilities as _real

sys.modules[__name__] = _real

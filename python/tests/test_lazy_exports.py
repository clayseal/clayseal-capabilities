"""Every name the package advertises has to actually resolve.

`clayseal.capabilities` resolves its 57 exports on first access (PEP 562) rather
than importing them all up front. That took `import clayseal.capabilities` from
89 ms of package cost to about 2 ms, because the eager form pulled
`cryptography`'s SSH serialization and `asyncio` into every process that touched
the package — including `clayseal policy lint`, which needs neither.

The arrangement trades one failure mode for another, and this file exists for the
new one. Eagerly, a name that did not exist was an `ImportError` the moment
anything imported the package, so it could not survive a test run. Lazily, a typo
in the export map is silent until somebody asks for that specific name, which may
be in production and may be months later.

So: assert the map and `__all__` agree in both directions, and resolve every one.
"""
from __future__ import annotations

import subprocess
import sys

import pytest

import clayseal.capabilities as caps


@pytest.mark.parametrize("name", sorted(caps.__all__))
def test_every_advertised_name_resolves(name):
    assert getattr(caps, name) is not None


def test_the_map_and_all_agree_in_both_directions():
    """A name in one and not the other is the defect this file is for.

    In `_EXPORTS` but not `__all__`: reachable but undocumented, and invisible to
    `dir()` and `import *`. In `__all__` but not `_EXPORTS`: advertised and
    unresolvable, which is the one that raises in somebody else's process.
    """
    in_map, advertised = set(caps._EXPORTS), set(caps.__all__)
    assert in_map == advertised, {
        "in the map, not advertised": sorted(in_map - advertised),
        "advertised, not in the map": sorted(advertised - in_map),
    }


def test_dir_and_star_import_still_see_everything():
    """`dir()` drives tab-completion and `import *` reads `__all__`. Neither may
    change because resolution moved."""
    assert sorted(dir(caps)) == sorted(caps.__all__)
    namespace: dict = {}
    exec("from clayseal.capabilities import *", namespace)  # noqa: S102
    for name in caps.__all__:
        assert name in namespace, name


def test_an_unknown_name_raises_attribute_error_not_something_stranger():
    """`__getattr__` must not turn a typo into an ImportError or a KeyError:
    `hasattr` and `getattr(..., default)` depend on AttributeError specifically."""
    with pytest.raises(AttributeError):
        getattr(caps, "no_such_export_exists")  # noqa: B009 - the lookup IS the test
    assert not hasattr(caps, "no_such_export_exists")
    assert getattr(caps, "no_such_export_exists", "fallback") == "fallback"


def test_importing_the_package_does_not_drag_in_the_heavy_optional_stack():
    """The measurement this change exists for, as an assertion.

    A fresh interpreter imports the package and reports whether the two modules
    that dominated the old import time came with it. `cryptography` arrives via
    `clayseal.core.signing` and `asyncio` via `guardrail`; neither is needed to
    lint a policy.
    """
    code = (
        "import sys; import clayseal.capabilities; "
        "print('asyncio' in sys.modules, "
        "any(m.startswith('cryptography') for m in sys.modules))"
    )
    out = subprocess.run([sys.executable, "-c", code], capture_output=True,
                         text=True, check=True).stdout.split()
    assert out == ["False", "False"], (
        f"importing the package still pulls asyncio={out[0]}, cryptography={out[1]}")


def test_resolving_a_name_does_pull_its_module():
    """The control.

    The assertion above passes trivially if the package stopped exporting
    anything at all. Ask for a name that needs the heavy stack and require it to
    arrive, so laziness is shown to be deferral rather than absence.
    """
    code = (
        "import sys; import clayseal.capabilities as c; c.Guardrail; "
        "print('asyncio' in sys.modules)"
    )
    out = subprocess.run([sys.executable, "-c", code], capture_output=True,
                         text=True, check=True).stdout.strip()
    assert out == "True", "resolving Guardrail did not import its module"

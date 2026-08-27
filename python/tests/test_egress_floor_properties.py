"""Properties of the destination-binding floor, which was rebuilt from bytecode.

`hardening/egress_policy.py` carries a note at the top: it was RECONSTRUCTED on
2026-08-18 from compiled bytecode after an uncommitted revision was lost to
`git checkout --`, with function bodies rebuilt from disassembly. The original
`.pyc` has since been overwritten by a newer build, so there is no artifact left
to diff against.

That module is the load-bearing control. It is what stands between an injected
send and the attacker's address, and it is the interlock that makes
`defer_to_binding` and runtime replanning safe, both of those defer to the
envelope only because "the destination already cleared the floor".

A module whose provenance cannot be checked has to be verified by its
PROPERTIES instead. Reviewing it that way found a real bypass, fixed and pinned
below: a destination one level down inside a dict-valued argument was invisible
to the entire floor, while the module's own docstring promised that every string
argument is scanned "because an exfil channel can hide an attacker address in
any field". Object-valued arguments are ordinary in MCP tool schemas.
"""
from __future__ import annotations

import pytest

from clayseal.capabilities.hardening.egress_policy import (
    EgressPolicy,
    extract_destinations,
)

ALLOWED = "acme-internal.com"
FOREIGN = "evil.com"
RESOURCE = "mcp:tool:send_email"


def policy() -> EgressPolicy:
    return EgressPolicy(allowed_domains={ALLOWED})


# --------------------------------------------------------------------------- #
# The bypass this review found.
# --------------------------------------------------------------------------- #
NESTED_SHAPES = [
    pytest.param({"meta": {"to": f"x@{FOREIGN}"}}, id="dict-valued argument"),
    pytest.param({"items": [{"url": f"https://{FOREIGN}/x"}]}, id="dict inside a list"),
    pytest.param({"payload": {"webhook": f"https://{FOREIGN}/h"}}, id="nested webhook"),
    pytest.param(
        {"a": {"b": {"c": {"d": f"mailto x@{FOREIGN}"}}}}, id="four levels deep"
    ),
    pytest.param({"body": {f"note about {FOREIGN}": "hi"}}, id="in a dict KEY"),
    pytest.param({"cc": [[f"x@{FOREIGN}"]]}, id="list inside a list"),
]


@pytest.mark.parametrize("args", NESTED_SHAPES)
def test_a_destination_cannot_hide_one_level_down(args):
    """Moving the same address into an object must not clear the floor."""
    assert FOREIGN in extract_destinations(RESOURCE, args), args
    ok, reason = policy().check(RESOURCE, args)
    assert not ok
    assert FOREIGN in reason


def test_the_flat_form_of_each_nested_shape_was_always_caught():
    """Guards the comparison: these were blocked before the fix and after it.

    Without this, a change that broke the flat path too would leave the tests
    above passing for the wrong reason.
    """
    for args in ({"payload": f"https://{FOREIGN}/h"}, {"to": f"x@{FOREIGN}"}):
        ok, _ = policy().check(RESOURCE, args)
        assert not ok, args


# --------------------------------------------------------------------------- #
# Allow-list matching: the classic suffix bug, and the deliberate subdomain rule.
# --------------------------------------------------------------------------- #
LOOKALIKES = [
    f"evil-{ALLOWED}",           # suffix without the dot
    f"{ALLOWED}.evil.com",       # allowed name as a LABEL of a foreign domain
    f"x{ALLOWED}",
    f"not{ALLOWED}",
]


@pytest.mark.parametrize("host", LOOKALIKES)
def test_a_lookalike_domain_does_not_match_the_allow_list(host):
    """`endswith(allowed)` without the separating dot is the classic hole."""
    ok, reason = policy().check(RESOURCE, {"to": f"x@{host}"})
    assert not ok, f"{host} passed as {ALLOWED}"
    assert host in reason


def test_a_subdomain_of_an_allowed_domain_is_admitted():
    """Deliberate, and asserted so it stays a decision rather than an accident."""
    ok, _ = policy().check(RESOURCE, {"to": f"x@mail.{ALLOWED}"})
    assert ok


# --------------------------------------------------------------------------- #
# Host normalisation: one destination, however it is spelled.
# --------------------------------------------------------------------------- #
SPELLINGS = [
    f"https://{FOREIGN}/steal?q=1",
    f"https://{FOREIGN}:8443/x",
    f"HTTPS://{FOREIGN.upper()}/X",
    f"http://{FOREIGN}#frag",
    f"https://{ALLOWED}@{FOREIGN}/",   # userinfo confusion
]


@pytest.mark.parametrize("url", SPELLINGS)
def test_every_spelling_of_a_foreign_host_is_refused(url):
    ok, reason = policy().check(RESOURCE, {"url": url})
    assert not ok, url
    assert FOREIGN in reason


def test_a_host_with_an_underscore_is_a_host():
    """The reconstruction's own stated fix, pinned.

    Three separate grammars used to reject underscores, so
    `http://www.resume_templates.com` backtracked to `www.resume`, a host
    nobody can allow-list, and therefore one the policy could neither allow nor
    deny correctly.
    """
    dests = extract_destinations(RESOURCE, {"url": "http://www.resume_templates.com/x"})
    assert "www.resume_templates.com" in dests


def test_a_path_does_not_become_part_of_the_destination():
    """An allow-list holds hosts, so a value carrying a path must resolve to one."""
    dests = extract_destinations(RESOURCE, {"url": f"https://{ALLOWED}/downloads/a.zip"})
    assert dests == [ALLOWED]


# --------------------------------------------------------------------------- #
# Default posture and the binds/check agreement.
# --------------------------------------------------------------------------- #
def test_the_default_posture_is_deny():
    """With no allow-list, any external destination is refused."""
    empty = EgressPolicy()
    ok, _ = empty.check(RESOURCE, {"to": f"x@{FOREIGN}"})
    assert not ok


def test_an_action_with_no_destination_is_not_bound_and_is_not_refused():
    """The floor is a no-op on an action that points nowhere external."""
    pol = policy()
    args = {"note": "reconcile the ledger", "count": 3}
    assert extract_destinations(RESOURCE, args) == []
    assert not pol.binds(RESOURCE, args)
    assert pol.check(RESOURCE, args)[0]


@pytest.mark.parametrize(
    "args",
    [{"to": f"x@{ALLOWED}"}, {"url": f"https://{FOREIGN}/x"},
     {"meta": {"to": f"x@{FOREIGN}"}}],
)
def test_binds_is_true_exactly_when_a_destination_was_found(args):
    """`defer_to_binding` and replanning both read `binds()` as "the floor had an
    opinion here". If it disagreed with what `check()` looked at, those layers
    would defer on actions the floor never actually examined."""
    pol = policy()
    assert pol.binds(RESOURCE, args) is bool(extract_destinations(RESOURCE, args))


def test_the_walk_is_bounded():
    """This runs in the authorization path on attacker-reachable input."""
    bomb: object = f"https://{FOREIGN}/x"
    for _ in range(200):
        bomb = {"nest": bomb}
    # Terminates, and does not raise RecursionError.
    extract_destinations(RESOURCE, {"payload": bomb})

    wide = {"payload": [f"https://host{i}.example.com/x" for i in range(5000)]}
    assert len(extract_destinations(RESOURCE, wide)) <= 512

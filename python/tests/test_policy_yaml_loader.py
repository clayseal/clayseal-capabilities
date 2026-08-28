"""The fast YAML loader must be the same SAFE loader, and must stay optional.

Parsing is roughly 90% of a policy compile. libyaml's `CSafeLoader` does the same
document about 18x faster (4.5 ms -> 0.24 ms for a whole `Guardrail.from_policy_file`),
which is per session rather than per call, so it is worth taking.

It is worth taking only if two things hold, and both are checked here rather than
assumed:

1. **It refuses what `SafeLoader` refuses.** A policy document is
   attacker-adjacent input, and `yaml.load` with the wrong loader is the textbook
   deserialisation RCE. `CSafeLoader` is the C implementation of the same safe
   constructor, but "should be" is not a security argument.
2. **It stays optional.** libyaml is not present in every wheel on every
   platform. The fallback path is the one a guard is most likely to break, because
   nobody develops on it — the first version of that guard referenced
   `yaml.CSafeLoader` unconditionally and would have raised `AttributeError`
   exactly where libyaml was missing.
"""
from __future__ import annotations

import sys

import pytest
import yaml

from clayseal.capabilities.policy import PolicyError, load_policy_text

MINIMAL = """
version: 1
goal: {id: g, summary: Take notes.}
expires_at: 2030-01-01T00:00:00Z
tools: {allow: [note], harmless: [note], effects: {note: read}}
paths: {pathless: [note]}
"""

#: Tags that turn a YAML document into code execution.
RCE_DOCUMENTS = [
    ("object/apply", "!!python/object/apply:os.system ['echo pwned']"),
    ("object/new", "!!python/object/new:os.system ['x']"),
    ("name", "!!python/name:os.system"),
    ("module", "!!python/module:os"),
]


def _loaders():
    """Every loader this module may pick, by the same lookup the code uses."""
    c = getattr(yaml, "CSafeLoader", None)
    return [("SafeLoader", yaml.SafeLoader)] + ([("CSafeLoader", c)] if c else [])


@pytest.mark.parametrize("name,document", RCE_DOCUMENTS, ids=[c[0] for c in RCE_DOCUMENTS])
def test_every_loader_we_may_pick_refuses_code_execution(name, document):
    for label, loader in _loaders():
        with pytest.raises(yaml.YAMLError):
            # The point of the test is to hand each loader the dangerous tag and
            # require a refusal, so S506 is describing what is deliberately here.
            yaml.load(document, Loader=loader)  # noqa: S506
        assert label  # both loaders were actually exercised, not skipped past


def test_the_two_loaders_agree_on_the_yaml_features_that_differ_between_them():
    """Anchors, merge keys, timestamps, duplicate keys and the scalar-resolution
    corners are where two YAML implementations drift apart. A policy that parsed
    to something different under libyaml would be a different grant."""
    if not hasattr(yaml, "CSafeLoader"):
        pytest.skip("libyaml not available in this environment")
    documents = {
        "anchors and alias": "a: &x {k: 1}\nb: *x",
        "merge key": "base: &b {p: 1}\nchild:\n  <<: *b\n  q: 2",
        "timestamp": "when: 2027-12-31T00:00:00Z",
        "colon separated": "v: 1:30",
        "octal forms": "v: 0o17\nw: 017",
        "bool variants": "a: yes\nb: no\nc: on\nd: off\ne: true",
        "null variants": "a: ~\nb: null\nc:",
        "duplicate keys": "a: 1\na: 2",
        "big int": "v: 123456789012345678901234567890",
        "float forms": "a: .inf\nb: -.inf\nc: 1e3",
        "quoted vs bare money": "a: '1000.00'\nb: 1000.00",
        "block scalar": "v: |\n  line1\n  line2",
        "folded scalar": "v: >\n  line1\n  line2",
        "explicit str tag": "v: !!str 123",
        "binary": "v: !!binary aGk=",
        "empty document": "",
    }
    for label, doc in documents.items():
        pure = yaml.load(doc, Loader=yaml.SafeLoader)
        fast = yaml.load(doc, Loader=yaml.CSafeLoader)
        assert pure == fast, f"{label}: {pure!r} != {fast!r}"


def test_a_policy_compiles_with_libyaml_absent():
    """The fallback path, exercised rather than trusted.

    Deleting the attribute is what a platform without libyaml looks like to this
    code, since the lookup is `getattr(yaml, "CSafeLoader", yaml.SafeLoader)`.
    """
    saved = getattr(yaml, "CSafeLoader", None)
    if saved is None:
        pytest.skip("libyaml already absent; the fallback is the only path")
    try:
        del yaml.CSafeLoader
        sys.modules.pop("clayseal.capabilities.policy", None)
        from clayseal.capabilities.policy import load_policy_text as reloaded
        assert reloaded(MINIMAL) is not None
    finally:
        yaml.CSafeLoader = saved
        sys.modules.pop("clayseal.capabilities.policy", None)


def test_the_guard_admits_only_the_safe_loaders():
    """The tripwire that makes the safety claim true rather than stated.

    If a later edit puts a full or unsafe loader in that variable, the compile
    must refuse rather than execute whatever the document names.
    """
    safe = tuple(c for c in (getattr(yaml, "CSafeLoader", None), yaml.SafeLoader) if c)
    for name in ("CSafeLoader", "SafeLoader"):
        loader = getattr(yaml, name, None)
        if loader is not None:
            assert issubclass(loader, safe), name
    for name in ("FullLoader", "UnsafeLoader", "Loader"):
        loader = getattr(yaml, name, None)
        if loader is not None:
            assert not issubclass(loader, safe), f"{name} would be accepted"


def test_a_real_policy_still_compiles():
    """The control. Every assertion above passes if nothing parses at all."""
    assert load_policy_text(MINIMAL) is not None
    with pytest.raises(PolicyError):
        load_policy_text("this: is: not: valid: yaml:")

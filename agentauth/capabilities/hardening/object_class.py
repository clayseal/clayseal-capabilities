"""What an object IS, as distinct from where it sits.

A mandate says *where* an agent may go. It says nothing about what the objects
there are, and that gap is the whole of the in-scope staging gap measured in
``benchmarks/results/in_scope_exfiltration.md``: against an oracle attacker the
full enforcement ladder's escaped-task set is byte-identical to ``allow-all``,
because the entire attack is

    read:/app/.env  ->  write:/app/README.md

Two actions, both inside the grant, both using tools the task holds, arguments
that are legitimately the agent's own, two calls against any budget. Every rung
discriminates on a dimension this attack does not move, so no scope check can
see it. The missing predicate is not "where did it go" but "a secret-classed
object was read, and a publication-classed object was written".

## Static, not inferred

``SensitivityPolicy`` states the rule this module follows: *nothing here is
inferred at runtime, because a policy an attacker can influence is not a policy.*
So this is a declared taxonomy compiled in, exactly like
``hardening/protected_zones.DEFAULT_PROTECTED_PATTERNS``, not a classifier, not
a heuristic over content, and nothing an agent's own output can move. A
deployment overrides it from the mandate; the defaults exist so that a mandate
which does not enumerate its own secrets is not silently unprotected.

## The two classes, and why they are asymmetric

``SECRET`` is a deny-list over names that carry credentials in ordinary
repositories. Being wrong here costs a false step-up on a file that merely looks
like a secret.

``PUBLICATION`` is a list of surfaces whose *purpose* is to be read by someone
other than the agent. Being wrong here costs nothing at all on its own: a
publication object is only interesting once a secret has been read in the same
session, so the two classes are only ever consequential together. That
conjunction is what keeps the rule narrow enough to be enforceable.
"""
from __future__ import annotations

from enum import Enum

__all__ = ["PUBLICATION_PATTERNS", "SECRET_PATTERNS", "ObjectClass", "classify"]


class ObjectClass(str, Enum):
    SECRET = "secret"
    PUBLICATION = "publication"
    ORDINARY = "ordinary"


#: Names that carry credentials inside an ordinary repository. These are exactly
#: the objects a path scope cannot help with, because a coding agent is
#: legitimately granted the workspace that contains them.
SECRET_PATTERNS: tuple[str, ...] = (
    ".env", ".envrc", ".npmrc", ".netrc", ".pypirc", ".dockercfg",
    "id_rsa", "id_dsa", "id_ecdsa", "id_ed25519", ".pem", ".p12", ".pfx",
    "credential", "secret", "apikey", "api_key", "access_key", "private_key",
    "password", "passwd", "token", "keyfile", "keystore",
    "/.git/config", "/.aws/", "/.ssh/", "/.kube/config", "/.docker/config",
    "service-account", "serviceaccount",
)

#: Surfaces whose purpose is to be read by someone other than the agent. Writing
#: a secret into one of these exfiltrates it without a byte crossing the grant.
PUBLICATION_PATTERNS: tuple[str, ...] = (
    "readme", "changelog", "contributing", "license",
    "/docs/", "/doc/", "/public/", "/dist/", "/build/", "/site/", "/output/",
    "/www/", "/static/", "/gh-pages/", "index.html", ".md",
)


def _normalize(path: str) -> str:
    return path.strip().replace("\\", "/").lower()


def classify(path: str | None) -> ObjectClass:
    """Classify a path or resource reference. Total: never raises.

    SECRET is checked first. A file named ``docs/secrets.md`` matches both lists,
    and treating it as a publication surface would be the dangerous reading
    the ordering is the conservative one, and the two classes are only ever
    consequential in conjunction anyway.
    """
    if not isinstance(path, str) or not path.strip():
        return ObjectClass.ORDINARY
    norm = _normalize(path)
    if any(marker in norm for marker in SECRET_PATTERNS):
        return ObjectClass.SECRET
    if any(marker in norm for marker in PUBLICATION_PATTERNS):
        return ObjectClass.PUBLICATION
    return ObjectClass.ORDINARY

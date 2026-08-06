"""Egress policy: bound where data may leave to.

An allowed tool can still be turned into an exfiltration channel: a permitted
``send_email`` to an attacker address, an ``http_post`` to an attacker URL. The
per-action lease authorizes the *tool*; egress policy authorizes the
*destination*. A destination is admitted only when its domain is on the task's
allow-list, which is seeded from the destinations the sealed goal actually named
(or the benign trajectory legitimately contacted), never from anything an
injected step introduces.

Default posture is deny: with no allow-list, any external destination is
refused, so an unbound send tool cannot quietly egress.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

_EMAIL = re.compile(r"[A-Za-z0-9._%+-]+@([A-Za-z0-9.-]+\.[A-Za-z]{2,})")
_URL = re.compile(r"https?://([A-Za-z0-9.-]+\.[A-Za-z]{2,})", re.IGNORECASE)
# Bare host with a recognizable TLD (attacker links are often written without a
# scheme, e.g. "www.secure-systems-252.com" dropped in a message body).
_BAREHOST = re.compile(
    r"\b((?:[A-Za-z0-9-]+\.)+(?:com|net|org|io|co|gov|edu|info|xyz|me|ai|dev|app|ru|cn))\b",
    re.IGNORECASE)
_DEST_KEYS = ("to", "recipient", "email", "url", "endpoint", "webhook", "dest",
              "destination", "address", "host")


_RECIPIENT_KEYS = ("to", "recipient", "recipients", "address", "dest",
                   "destination", "account", "participants", "participant")


def _arg_strings(args: dict):
    """Every string value in the args, flattening one level of list/tuple."""
    for v in args.values():
        if isinstance(v, str):
            yield v
        elif isinstance(v, (list, tuple)):
            for item in v:
                if isinstance(item, str):
                    yield item


def extract_recipients(args: dict) -> list[str]:
    """Opaque destination identifiers (IBANs, account numbers, usernames) that
    carry no domain and so slip past domain extraction. These are the financial
    analogue of an exfil URL: a permitted transfer tool aimed at an unauthorized
    account. Values with a domain or ``@`` are left to the domain path."""
    out = set()
    for key in _RECIPIENT_KEYS:
        v = args.get(key)
        for s in ([v] if isinstance(v, str) else (v if isinstance(v, (list, tuple)) else [])):
            if isinstance(s, str):
                s = s.strip()
                if s and "@" not in s and "://" not in s and "." not in s:
                    out.add(s)
    return sorted(out)


def extract_destinations(resource: str, args: dict) -> list[str]:
    """Pull external destination domains from a resource ref and call args.

    Emails and URLs are unambiguous external identifiers, so we scan *every*
    string argument for them (not only named destination keys): an exfil channel
    can hide an attacker address in any field. Bare hosts (no scheme, no ``@``)
    are only trusted in a named destination field, to avoid treating ordinary
    dotted text as a domain."""
    blob_parts: list[str] = list(_arg_strings(args))
    if resource.startswith("net:"):
        blob_parts.append(resource.removeprefix("net:"))
    blob = " ".join(blob_parts)
    domains = set(_EMAIL.findall(blob)) | set(_URL.findall(blob)) | set(_BAREHOST.findall(blob))
    for key in _DEST_KEYS:
        v = args.get(key)
        if isinstance(v, str) and "." in v and "@" not in v and "://" not in v:
            domains.add(v.strip().lower())
    return sorted(d.lower() for d in domains)


@dataclass
class EgressPolicy:
    allowed_domains: set[str] = field(default_factory=set)
    allowed_recipients: set[str] = field(default_factory=set)
    bind_recipients: bool = False
    allow_all: bool = False

    @classmethod
    def from_destinations(cls, destinations: list[str]) -> "EgressPolicy":
        """Seed the allow-list from legitimately-contacted destinations."""
        return cls(allowed_domains={d.lower() for d in destinations})

    def _permitted(self, domain: str) -> bool:
        d = domain.lower()
        return any(d == a or d.endswith("." + a) for a in self.allowed_domains)

    def binds(self, resource: str, args: dict) -> bool:
        """Did this action actually carry a destination this policy validated?

        ``check`` returns True both for "every destination was on the allow-list"
        and for "there was no destination to check", and those are very different
        pieces of evidence. A caller deciding how much to trust an action needs
        to tell them apart: a transfer whose recipient matched the goal-derived
        set has been positively vouched for, while a calendar-event creation has
        simply not been examined by this policy at all.

        Returns False under ``allow_all``, where nothing was really checked.
        """
        if self.allow_all:
            return False
        if any(True for _ in extract_destinations(resource, args)):
            return True
        return bool(self.bind_recipients and extract_recipients(args))

    def check(self, resource: str, args: dict) -> tuple[bool, str]:
        if self.allow_all:
            return True, "egress unrestricted"
        for domain in extract_destinations(resource, args):
            if not self._permitted(domain):
                return False, f"egress to {domain!r} not on allow-list"
        # Opt-in binding of opaque recipients (account/IBAN), for transfer-style
        # tools where the destination is an identifier rather than a domain.
        if self.bind_recipients:
            for r in extract_recipients(args):
                if r not in self.allowed_recipients:
                    return False, f"recipient {r!r} not on allow-list"
        return True, "egress within policy"

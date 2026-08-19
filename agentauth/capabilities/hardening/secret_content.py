"""Credential-shaped VALUES in an outbound payload.

`object_class.SECRET_PATTERNS` classifies *paths*: `.env`, `id_rsa`,
`/.aws/`. It is the right tool for "is this file a secret" and the wrong one for
"does this message contain one". Its markers include `token`, `secret`,
`password` and `credential` as bare substrings, so run against prose it fires on
"reset your password" and "the token expired" — a control with that
false-positive rate is one an operator switches off in a week.

This module answers the content question instead, and it exists because
`FlowTracker` structurally cannot. The tracker correlates a secret READ with a
later write; BPL's `integration-invoice-cover` never reads one. The elevation
tool `dump_internal_config` is refused, and the agent simply types
`API_KEY=sk-live-INTERNAL` into an invoice attachment and mails it to an
allow-listed internal address. Every layer is satisfied: allow-listed tool,
allow-listed recipient, no tracked read to derive from.

So the predicate here has no provenance in it at all: **does this payload
contain something shaped like a credential**. Two detectors, both deliberately
narrow, in the tradition of gitleaks and trufflehog rather than keyword lists:

**Known issuer prefixes.** `AKIA…`, `sk-live-…`, `ghp_…`, `xoxb-…`, a PEM
private-key header. These are unambiguous: no English sentence contains them by
accident, so they can be matched with no entropy test at all.

**Assignment plus entropy.** `API_KEY=<value>` where the value is long enough
and random enough to be a key rather than a word. `password = hunter2` does not
qualify and should not — it is a short low-entropy string, and refusing it would
be the keyword failure again. The entropy floor is what separates a credential
from prose that mentions one.

Measured on BPL's own benign corpus before being wired anywhere; see
`benchmarks/results/bpl_full_sweep.md`. A detector whose false-positive rate is
unmeasured is a detector nobody should switch on.
"""
from __future__ import annotations

import math
import re
from typing import Any

__all__ = ["contains_credential", "credential_findings", "shannon_entropy"]

#: Issuer-specific prefixes. Unambiguous by construction.
_ISSUER = re.compile(
    r"""(
        AKIA[0-9A-Z]{16}                    # AWS access key id
      | ASIA[0-9A-Z]{16}                    # AWS temporary
      | sk-live-[A-Za-z0-9_-]{4,}           # Stripe-style live secret
      | sk-[A-Za-z0-9]{20,}                 # OpenAI-style
      | gh[pousr]_[A-Za-z0-9]{20,}          # GitHub token
      | xox[baprs]-[A-Za-z0-9-]{10,}        # Slack
      | AIza[0-9A-Za-z_-]{35}               # Google API key
      | -----BEGIN[ A-Z]*PRIVATE\ KEY-----  # PEM private key
      | eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.  # JWT
    )""",
    re.VERBOSE)

#: `NAME = value` where NAME implies a credential. The value still has to look
#: like one; the name alone is exactly the keyword trap this module avoids.
_ASSIGNMENT = re.compile(
    r"(?i)\b(api[_-]?key|secret[_-]?key|secret|password|passwd|token|"
    r"access[_-]?key|private[_-]?key|client[_-]?secret)\b\s*[=:]\s*"
    r"[\"']?([A-Za-z0-9_\-./+]{12,})[\"']?")

#: Below this, an assignment value is a word or a placeholder rather than a key.
#: 3.0 bits/char admits base64 and hex secrets and rejects `changeme123456`
#: and `your-api-key-here`.
ENTROPY_FLOOR = 3.0

#: Values that are documentation rather than credentials. Every secret scanner
#: carries a list like this, and it is not cosmetic: `api_key: your-api-key-here`
#: clears the entropy floor comfortably, so without it a README or a config
#: template is refused. A control that blocks the example in the docs teaches
#: people to route around it.
_PLACEHOLDER = re.compile(
    r"(?i)(your[-_]|xxx+|changeme|placeholder|example|redacted|dummy|"
    r"insert[-_]|replace[-_]|todo|<[^>]*>|\*{4,}|fake|sample|not[-_]?a[-_]?real)")

#: Personal identifiers that are not credentials but are exfiltration all the
#: same. Kept separate so a deployment can take one without the other.
_PII = re.compile(r"\b\d{3}-\d{2}-\d{4}\b")          # US SSN


def shannon_entropy(text: str) -> float:
    """Bits per character. Empty string is 0."""
    if not text:
        return 0.0
    counts: dict[str, int] = {}
    for ch in text:
        counts[ch] = counts.get(ch, 0) + 1
    n = len(text)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def credential_findings(payload: Any, *, include_pii: bool = True) -> list[str]:
    """Reasons this payload looks like it carries a credential. Empty if clean.

    Total: any input, never raises. A classifier that throws on an odd payload
    is a control that stops applying exactly when the input is unusual, which is
    the defect shape this repository has shipped six times.
    """
    try:
        text = payload if isinstance(payload, str) else str(payload)
    except Exception:  # noqa: BLE001
        return []
    if not text:
        return []

    out: list[str] = []
    for match in _ISSUER.finditer(text):
        token = match.group(0)
        out.append(f"credential literal ({token[:6]}...)")
    for name, value in _ASSIGNMENT.findall(text):
        if _PLACEHOLDER.search(value):
            continue
        if shannon_entropy(value) >= ENTROPY_FLOOR:
            out.append(f"{name.lower()} assigned a high-entropy value")
    if include_pii and _PII.search(text):
        out.append("personal identifier (SSN-shaped)")
    # Deduplicate but keep order: one reason per distinct kind is what an
    # approval card can render; fifty copies of the same one is noise.
    seen, unique = set(), []
    for reason in out:
        if reason not in seen:
            seen.add(reason)
            unique.append(reason)
    return unique


def contains_credential(payload: Any, *, include_pii: bool = True) -> bool:
    return bool(credential_findings(payload, include_pii=include_pii))

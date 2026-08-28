"""Tool name to verb, for callers who have a tool catalog and nothing else.

WHY IT MOVED HERE

This function is what turns `send_email` into `send` and `get_balance` into
`read`, and the verb is what the floor's write/egress rules key off. It lived in
`benchmarks/datasets/_common.py`, which is not part of the shipped wheel, so
every real integration had to reinvent it, and an integration that classifies a
transfer as a read gets a hard-deny turned into an allow. It is library
behaviour, so it is in the library. The benchmark loaders import it from here,
which is also how the two stay identical.

WHAT IT IS AND IS NOT

It is a default for callers who have only names. It is NOT authority: a caller
with a real tool catalog, an MCP schema, or a mandate that declares each tool's
effect should use that, and pass the verb explicitly. A name-based classifier is
wrong on a tool called `check_out_book`, and it says so here rather than in a
postmortem.
"""
from __future__ import annotations

# Ordered by how a tool name is actually written: the leading token is the verb.
_WRITE = ("create", "update", "delete", "send", "pay", "transfer", "set", "add",
          "remove", "cancel", "book", "post", "share", "write", "schedule",
          "execute", "run", "make", "submit", "toggle", "enable", "disable",
          "refund", "exchange", "modify", "reserve", "mkdir", "mv", "cp", "rm",
          "touch", "echo")
_READ = ("get", "list", "search", "read", "find", "view", "show", "check",
         "fetch", "lookup", "query", "describe", "calculate", "cd", "ls", "cat",
         "grep", "sort", "diff", "pwd", "du", "wc", "tail", "head")


def classify_verb(tool: str) -> str:
    """Return one of ``read``, ``write``, ``send``, ``transfer``, ``call``."""
    low = tool.lower()
    # A leading acquisition verb wins over a later write-like substring: a tool's
    # primary verb is its prefix, so get_scheduled_transactions is a read even
    # though it contains 'schedule'. Misreading a read as an effect makes the
    # floor hard-deny a benign, reversible call, the main utility leak.
    for v in _READ:
        if low.startswith(v):
            return "read"
    for v in _WRITE:
        if low.startswith(v) or f"_{v}" in low:
            if v in ("pay", "transfer", "refund", "exchange"):
                return "transfer"
            if v == "send":
                return "send"
            return "write"
    for v in _READ:
        if f"_{v}" in low:
            return "read"
    # Unrecognised. `call` is the conservative answer: it is not classified as a
    # read, so nothing downstream treats it as reversible, and it is not
    # classified as a transfer, so it does not invent an effect that is not
    # there. A deployment that cares should name the verb.
    return "call"

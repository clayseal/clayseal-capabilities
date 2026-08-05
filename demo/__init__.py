"""Trajectory-driven sandbox recompilation — a runnable demonstration.

A real agent triages support tickets inside iVisor. One ticket carries an
injected instruction. As untrusted content enters the trajectory and the agent
acts on it, the sandbox policy is recompiled — each step a fresh immutable
config with its own digest — and capabilities the agent still legitimately held
are progressively revoked.

    python -m demo run ticket-triage --provider mock --plain

This package is not shipped in the wheel and is not imported by the library.
`rich` is needed only for the live TUI; every pure module here (state,
expectations, escalation, taint, scenario) imports with it absent, and the tests
in python/tests/ are the machine check that this stays true.
"""

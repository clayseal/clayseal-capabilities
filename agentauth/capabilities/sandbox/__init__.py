"""Execution-sandbox integration seams for Clay Seal.

Currently a launch-time seam onto iVisor (a syscall-interposition sandbox).
See ivisor.py for status and boundaries.
"""
from agentauth.capabilities.sandbox.ivisor import IVisorLaunch, launch_from_envelope

__all__ = ["IVisorLaunch", "launch_from_envelope"]

from __future__ import annotations

import fnmatch

from agentauth.capabilities.scoping.models import SensitivityLabel

_DEFAULT_PROTECTED_GLOBS = (
    "**/.env",
    "**/.env.*",
    "**/*.pem",
    "**/*.key",
    "**/id_rsa",
    "**/id_ed25519",
    "**/.github/workflows/**",
    "**/terraform/**",
    "**/deploy/**",
    "**/helm/**",
    "**/k8s/**",
    "**/auth/**",
    "**/auth.py",
    "**/identity/**",
    "**/*secret*",
    "**/*credential*",
)

_HIGHLY_PROTECTED_GLOBS = (
    "**/keys/**",
    "**/.ssh/**",
    "**/*credentials*",
)


def _matches_glob(path: str, pattern: str) -> bool:
    """Match a path against a glob pattern, handling root-level paths."""
    if fnmatch.fnmatch(path, pattern):
        return True
    if pattern.startswith("**/"):
        return fnmatch.fnmatch(path, pattern[3:])
    return False


def sensitivity_for_path(
    file_path: str,
    *,
    extra_protected: tuple[str, ...] = (),
    extra_highly_protected: tuple[str, ...] = (),
) -> SensitivityLabel:
    normalized = file_path.replace("\\", "/")
    for pattern in (*_HIGHLY_PROTECTED_GLOBS, *extra_highly_protected):
        if _matches_glob(normalized, pattern):
            return SensitivityLabel.HIGHLY_PROTECTED
    for pattern in (*_DEFAULT_PROTECTED_GLOBS, *extra_protected):
        if _matches_glob(normalized, pattern):
            return SensitivityLabel.PROTECTED
    return SensitivityLabel.NORMAL


def subsystem_tags_for_path(file_path: str) -> list[str]:
    normalized = file_path.replace("\\", "/").strip("/")
    parts = normalized.split("/")
    if not parts:
        return []
    if len(parts) == 1:
        return [parts[0]]
    return [parts[0], "/".join(parts[:2])]

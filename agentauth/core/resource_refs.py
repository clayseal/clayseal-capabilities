from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class ResourceRefStyle(str, Enum):
    SCOPED = "scoped"
    URI = "uri"


@dataclass(frozen=True)
class ResourceRef:
    kind: str
    value: str
    style: ResourceRefStyle

    def to_string(self) -> str:
        if self.style == ResourceRefStyle.URI:
            return f"{self.kind}://{self.value}"
        return f"{self.kind}:{self.value}"


def format_resource_ref(
    kind: str,
    value: str,
    *,
    style: ResourceRefStyle | str = ResourceRefStyle.SCOPED,
) -> str:
    kind_clean = kind.strip()
    value_clean = value.strip()
    if not kind_clean or not value_clean:
        raise ValueError("resource refs require non-empty kind and value")
    style_value = style if isinstance(style, ResourceRefStyle) else ResourceRefStyle(style)
    return ResourceRef(kind=kind_clean, value=value_clean, style=style_value).to_string()


def parse_resource_ref(raw: str) -> ResourceRef:
    value = raw.strip()
    if not value:
        raise ValueError("resource ref must not be empty")

    if "://" in value:
        kind, resource_value = value.split("://", 1)
        kind_clean = kind.strip()
        resource_value_clean = resource_value.strip().lstrip("/")
        if not kind_clean or not resource_value_clean:
            raise ValueError(f"invalid URI resource ref: {raw!r}")
        return ResourceRef(
            kind=kind_clean,
            value=resource_value_clean,
            style=ResourceRefStyle.URI,
        )

    if ":" in value:
        kind, resource_value = value.split(":", 1)
        kind_clean = kind.strip()
        resource_value_clean = resource_value.strip()
        if not kind_clean or not resource_value_clean:
            raise ValueError(f"invalid scoped resource ref: {raw!r}")
        return ResourceRef(
            kind=kind_clean,
            value=resource_value_clean,
            style=ResourceRefStyle.SCOPED,
        )

    raise ValueError(f"resource ref must use '<kind>:<value>' or '<scheme>://<value>': {raw!r}")


def is_resource_ref(raw: str) -> bool:
    try:
        parse_resource_ref(raw)
    except ValueError:
        return False
    return True

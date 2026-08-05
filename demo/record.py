"""Recording and replaying a run, as JSONL.

LLM APIs fail at exactly the wrong moment — on stage, on a plane, behind a
conference network — and a demo that cannot run offline is not a demo. A
recording is a header line plus one serialized event per line, so replay feeds
the same reducer the same events in the same order and reaches the same state.

REPLAY IS NOT A RUN, and the code keeps that distinction sharp rather than
relying on a disclaimer: replay bypasses the loop entirely, so no sandbox is
launched, no broker is consulted, and nothing is enforced. The header records
which provider originally produced the events, and the renderers display
`provider=replay(mock)` so a viewer is never shown a recording as if it were
live containment.

Timing is preserved, divided by `speed`, with any single gap capped — a
recording that contains a 40-second model stall should not make the replay stall
for 40 seconds.
"""
from __future__ import annotations

import json
import time
from collections.abc import Callable, Iterable, Iterator
from dataclasses import dataclass
from pathlib import Path

from demo.state import Event, event_from_dict

VERSION = 1
MAX_GAP_MS = 2000


@dataclass(frozen=True)
class Header:
    scenario: str
    provider: str
    model: str = ""
    version: int = VERSION

    def to_dict(self) -> dict:
        return {"kind": "header", "scenario": self.scenario,
                "provider": self.provider, "model": self.model,
                "version": self.version}


class Recorder:
    """Appends events to a JSONL file as they happen."""

    def __init__(self, path: Path | str, header: Header) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._handle = self.path.open("w")
        self._handle.write(json.dumps(header.to_dict(), sort_keys=True) + "\n")
        self._handle.flush()

    def push(self, event: Event) -> None:
        self._handle.write(json.dumps(event.to_dict(), sort_keys=True) + "\n")
        self._handle.flush()

    def close(self) -> None:
        if not self._handle.closed:
            self._handle.close()

    def __enter__(self) -> Recorder:  # noqa: PYI034 - typing.Self needs 3.11;
        # this repo supports 3.10 and typing_extensions is not a dependency.
        return self

    def __exit__(self, *exc) -> None:
        self.close()


def load(path: Path | str) -> tuple[Header, list[Event]]:
    """Read a recording. Unparseable lines are skipped, so a truncated file
    still replays as far as it got — which is the common case when a recording
    was interrupted."""
    lines = Path(path).read_text().splitlines()
    header: Header | None = None
    events: list[Event] = []
    for line in lines:
        if not line.strip():
            continue
        try:
            raw = json.loads(line)
        except ValueError:
            continue
        if raw.get("kind") == "header":
            header = Header(scenario=raw.get("scenario", "?"),
                            provider=raw.get("provider", "?"),
                            model=raw.get("model", ""),
                            version=int(raw.get("version", VERSION)))
            continue
        try:
            events.append(event_from_dict(raw))
        except (KeyError, TypeError):
            continue
    if header is None:
        raise ValueError(f"{path}: not a demo recording (no header line)")
    return header, events


def replay(events: Iterable[Event], emit: Callable[[Event], None], *,
           speed: float = 1.0, sleep=time.sleep) -> None:
    """Feed recorded events to `emit`, preserving their original pacing."""
    for delay_s, event in _paced(events, speed=speed):
        if delay_s > 0:
            sleep(delay_s)
        emit(event)


def _paced(events: Iterable[Event], *, speed: float) -> Iterator[tuple[float, Event]]:
    speed = max(speed, 0.01)
    previous: int | None = None
    for event in events:
        gap_ms = 0 if previous is None else max(0, event.at_ms - previous)
        previous = event.at_ms
        yield min(gap_ms, MAX_GAP_MS) / 1000.0 / speed, event

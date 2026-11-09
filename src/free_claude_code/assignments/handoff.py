# SPDX-License-Identifier: AGPL-3.0-only
"""Handoff actors. The manager map is config. Unknown labels are refused.

Named actors are the briefing set. A claudeN worker is an additional actor
whose label is waiting:claudeN. waiting:pm is not an actor.
"""

import json
import re
from collections.abc import Mapping
from pathlib import Path

from free_claude_code.assignments.errors import Forbidden

_CLAUDE = re.compile(r"claude[1-9][0-9]*\Z")

# Legal named actors and the only waiting label each one may use.
BRIEFING_ACTORS = {
    "Casey": "waiting:casey",
    "Cody": "waiting:cody",
    "Minerva": "waiting:minerva",
    "Grok": "waiting:grok",
    "RPG Dev": "waiting:rpg-dev",
}


def actor_label(actor: str, configured: Mapping[str, str] | None = None) -> str:
    """Return the waiting label for one actor. A mismatch in config is refused."""

    if _CLAUDE.fullmatch(actor):
        expected = f"waiting:{actor}"
    elif actor in BRIEFING_ACTORS:
        expected = BRIEFING_ACTORS[actor]
    else:
        raise Forbidden("unknown handoff actor")
    if configured is not None and actor in configured and configured[actor] != expected:
        raise Forbidden("handoff label does not match the actor")
    assert_handoff_label(expected)
    return expected


def assert_handoff_label(label: str) -> None:
    if label in BRIEFING_ACTORS.values():
        return
    bare = label.removeprefix("waiting:")
    if label.startswith("waiting:") and _CLAUDE.fullmatch(bare):
        return
    raise Forbidden("unknown handoff label")


def load_actor_map(path: Path) -> dict[str, str]:
    raw = json.loads(path.read_text(encoding="utf-8"))
    rows = raw.get("actors") if isinstance(raw, dict) else None
    if not isinstance(rows, dict):
        raise Forbidden("handoff actor config must contain an actors map")
    found: dict[str, str] = {}
    for name, label in rows.items():
        actor = str(name).strip()
        waiting = str(label).strip()
        expected = actor_label(actor)
        if waiting != expected:
            raise Forbidden("handoff label does not match the actor")
        found[actor] = waiting
    return found

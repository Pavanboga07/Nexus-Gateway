"""Invite-code validation for the relay.

Vendored from the Nexus ``app.pairing`` package so this service is
self-contained. Only the relay-side pieces live here: invite-code
normalization (used by ``relay.invites``) and the embedded 2048-word
wordlist it validates against. Code *generation*, the local SQLite
pairing store, and peer management stayed behind in the Nexus repo —
the relay only ever validates codes clients present.
"""

from __future__ import annotations

import re
from typing import Any


CODE_WORDS = 6
# Embedded wordlist: 32 prefixes x 64 suffixes = 2048 entries.
# Fixed 2-letter prefixes keep every concatenation unique.
_PREFIXES = [
    "al", "ar", "ba", "be", "bi", "bo", "ca", "ce",
    "co", "da", "de", "di", "do", "fa", "fe", "fi",
    "fo", "ga", "ge", "go", "ha", "he", "ka", "ke",
    "la", "le", "ma", "me", "mi", "na", "ne", "pa",
]
_SUFFIXES = [
    "bar", "bay", "bell", "bend", "berry", "birch", "blade", "blaze",
    "brook", "buck", "burrow", "bush", "cedar", "cliff", "cinder", "clover",
    "cove", "crest", "dale", "dell", "drift", "elm", "ember", "fells",
    "fern", "field", "finch", "fjord", "flint", "forest", "fox", "frost",
    "garnet", "glade", "glen", "grove", "harbor", "hawk", "heath", "holly",
    "ivy", "jasper", "juniper", "kelp", "lark", "laurel", "leaf", "linden",
    "loam", "maple", "marsh", "meadow", "mesa", "moss", "oak", "opal",
    "orchard", "otter", "owl", "peak", "pebble", "pine", "plum", "pond",
]
WORDLIST: list[str] = [p + s for p in _PREFIXES for s in _SUFFIXES]
_WORDSET = frozenset(WORDLIST)


class PairingError(ValueError):
    """Pairing failure with machine ``code`` and optional HTTP ``status``."""

    def __init__(self, code: str, message: str, status: int | None = None) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code
        self.status = status


def normalize_code(code: Any) -> str:
    """Canonical hyphen form; accepts spaces/case. Raises INVALID_CODE."""
    if not isinstance(code, str):
        raise PairingError("INVALID_CODE", "invite code must be text.")
    parts = [p for p in re.split(r"[\s\-_]+", code.strip().lower()) if p]
    if len(parts) != CODE_WORDS or any(p not in _WORDSET for p in parts):
        raise PairingError(
            "INVALID_CODE", "invite code not recognized; check the words."
        )
    return "-".join(parts)


__all__ = [
    "CODE_WORDS",
    "WORDLIST",
    "PairingError",
    "normalize_code",
]

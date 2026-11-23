"""Interfaces for adding scanner integrations without guessing vendor semantics."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterator, Protocol


@dataclass(frozen=True)
class ScannerFinding:
    asset_id: str
    cve_id: str | None
    software_name: str | None
    installed_version: str | None
    evidence: dict[str, Any]


class ScannerConnector(Protocol):
    """A connector must preserve source evidence and never claim unverified matches."""

    @property
    def name(self) -> str: ...

    def iter_findings(self) -> Iterator[ScannerFinding]:
        """Yield normalized findings from an authenticated vendor adapter."""
        ...

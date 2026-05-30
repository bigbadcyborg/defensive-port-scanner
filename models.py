"""
models.py — Shared data types for defensivePortScanner.

Centralises PortResult and the port status constants so that both
defensivePortScanner.py and report.py can import from here without
creating a circular dependency.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from banner import BannerResult

if TYPE_CHECKING:
    from risk import RiskAssessment

# ---------------------------------------------------------------------------
# Port status constants
# ---------------------------------------------------------------------------

STATUS_OPEN = "open"
STATUS_CLOSED = "closed"
STATUS_UNREACHABLE = "unreachable"


# ---------------------------------------------------------------------------
# PortResult
# ---------------------------------------------------------------------------


class PortResult:
    """Everything known about a single scanned port."""

    __slots__ = ("port", "status", "service_name", "banner", "risk")

    def __init__(
        self,
        port: int,
        status: str,
        service_name: str,
        banner: BannerResult | None,
        risk: RiskAssessment | None = None,
    ) -> None:
        self.port = port
        self.status = status
        self.service_name = service_name
        self.banner = banner
        self.risk = risk

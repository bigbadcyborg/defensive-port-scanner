"""
models.py — Shared data types for defensivePortScanner.

Centralises PortResult and the port status constants so that both
defensivePortScanner.py and report.py can import from here without
creating a circular dependency.
"""

from banner import BannerResult

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

    __slots__ = ("port", "status", "service_name", "banner")

    def __init__(
        self,
        port: int,
        status: str,
        service_name: str,
        banner: BannerResult | None,
    ) -> None:
        self.port = port
        self.status = status
        self.service_name = service_name
        self.banner = banner

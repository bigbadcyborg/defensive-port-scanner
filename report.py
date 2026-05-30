"""
report.py — Report generation for defensivePortScanner.

Produces JSON, CSV, and plain-text reports from a completed scan.
All output is UTF-8; no external dependencies beyond the stdlib.

Public API
----------
  build_report(...)           -> ScanReport
  write_json(report, path)    -> None
  write_csv(report, path)     -> None
  write_text(report, path)    -> None
  write_reports(report, stem, formats) -> list[Path]
"""

import csv
import json
from dataclasses import dataclass
from datetime import datetime
from io import StringIO
from pathlib import Path

from banner import BannerResult, DetectionMethod
from models import STATUS_OPEN as _STATUS_OPEN
from models import PortResult
from risk import DISCLAIMER as _RISK_DISCLAIMER

# ---------------------------------------------------------------------------
# ScanReport dataclass
# ---------------------------------------------------------------------------


@dataclass
class ScanReport:
    target: str
    resolved_ip: str
    ports_requested: str  # raw --ports string, e.g. "1-1024"
    scan_started: datetime
    scan_finished: datetime
    timeout: float  # connect timeout in seconds
    banner_grabbing: bool
    banner_timeout: float | None  # None when banner_grabbing is False
    results: list[PortResult]
    risk_enabled: bool = False
    scan_profile: str | None = None


# ---------------------------------------------------------------------------
# Factory
# ---------------------------------------------------------------------------


def build_report(
    target: str,
    resolved_ip: str,
    ports_requested: str,
    scan_started: datetime,
    scan_finished: datetime,
    timeout: float,
    banner_grabbing: bool,
    banner_timeout: float | None,
    results: list[PortResult],
    risk_enabled: bool = False,
    scan_profile: str | None = None,
) -> ScanReport:
    """Construct and return a ScanReport from completed scan data."""
    return ScanReport(
        target=target,
        resolved_ip=resolved_ip,
        ports_requested=ports_requested,
        scan_started=scan_started,
        scan_finished=scan_finished,
        timeout=timeout,
        banner_grabbing=banner_grabbing,
        banner_timeout=banner_timeout,
        results=results,
        risk_enabled=risk_enabled,
        scan_profile=scan_profile,
    )


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _duration(report: ScanReport) -> float:
    return round((report.scan_finished - report.scan_started).total_seconds(), 2)


def _summary(results: list[PortResult]) -> dict[str, int]:
    counts = {"total": len(results), "open": 0, "closed": 0, "unreachable": 0}
    for r in results:
        if r.status in counts:
            counts[r.status] += 1
    return counts


def _detection_value(port_result: PortResult, banner_grabbing: bool) -> str:
    """
    Return the detection string for a port entry.

    When banner grabbing was enabled and the port is open, use the
    DetectionMethod value from the BannerResult (detected/inferred/failed).
    In all other cases the service name was inferred from the port table.
    """
    if (
        banner_grabbing
        and port_result.status == _STATUS_OPEN
        and port_result.banner is not None
    ):
        return port_result.banner.method.value
    return DetectionMethod.INFERRED.value


def _banner_text(port_result: PortResult) -> str | None:
    """Return sanitized banner raw string, or None when absent/empty."""
    if port_result.banner and port_result.banner.raw:
        return port_result.banner.raw
    return None


# ---------------------------------------------------------------------------
# JSON writer
# ---------------------------------------------------------------------------


def write_json(report: ScanReport, path: Path) -> None:
    """Write a UTF-8 JSON report to *path*."""
    summary = _summary(report.results)

    meta: dict = {
        "target": report.target,
        "resolvedIp": report.resolved_ip,
        "portsRequested": report.ports_requested,
        "scanStarted": report.scan_started.isoformat(),
        "scanFinished": report.scan_finished.isoformat(),
        "durationSeconds": _duration(report),
        "scanTimeoutSeconds": report.timeout,
        "bannerGrabbing": report.banner_grabbing,
        "bannerTimeoutSeconds": report.banner_timeout,
        "riskAnalysis": report.risk_enabled,
        "scanProfile": report.scan_profile,
        "summary": summary,
    }

    ports: list[dict] = []
    for r in report.results:
        banner_str = _banner_text(r)
        entry: dict = {
            "port": r.port,
            "protocol": "tcp",
            "state": r.status,
            "service": r.service_name,
            "detection": _detection_value(r, report.banner_grabbing),
            "banner": banner_str,
        }
        if report.risk_enabled and r.risk:
            entry["risk"] = {
                "level": r.risk.level.value,
                "reason": r.risk.reason,
                "recommendation": r.risk.recommendation,
            }
        else:
            entry["risk"] = None
        ports.append(entry)

    payload: dict = {
        "schemaVersion": "1.1",
        "meta": meta,
        "ports": ports,
    }
    if report.risk_enabled:
        payload["riskDisclaimer"] = _RISK_DISCLAIMER

    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")


# ---------------------------------------------------------------------------
# CSV writer
# ---------------------------------------------------------------------------

_CSV_FIELDNAMES_BASE = [
    "port",
    "protocol",
    "state",
    "service",
    "detection",
    "banner",
    "risk_level",
    "risk_reason",
    "risk_recommendation",
    "scan_target",
    "resolved_ip",
    "scan_started",
]


def write_csv(report: ScanReport, path: Path) -> None:
    """Write a UTF-8 CSV report to *path* with one row per port."""
    scan_started_str = report.scan_started.isoformat()

    buf = StringIO()
    writer = csv.writer(buf, lineterminator="\n")
    writer.writerow(_CSV_FIELDNAMES_BASE)

    for r in report.results:
        banner_str = _banner_text(r) or ""
        risk_level = risk_reason = risk_rec = ""
        if report.risk_enabled and r.risk:
            risk_level = r.risk.level.value
            risk_reason = r.risk.reason
            risk_rec = r.risk.recommendation
        writer.writerow(
            [
                r.port,
                "tcp",
                r.status,
                r.service_name,
                _detection_value(r, report.banner_grabbing),
                banner_str,
                risk_level,
                risk_reason,
                risk_rec,
                report.target,
                report.resolved_ip,
                scan_started_str,
            ]
        )

    path.write_text(buf.getvalue(), encoding="utf-8")


# ---------------------------------------------------------------------------
# Plain-text writer
# ---------------------------------------------------------------------------

# Column widths — must match defensivePortScanner.py constants.
_W_PORT = 9
_W_STATE = 13
_W_SERVICE = 14
_W_DETECT = 11
_W_BANNER = 30


def write_text(report: ScanReport, path: Path) -> None:
    """Write a plain-text (no ANSI codes) report to *path*."""
    lines: list[str] = []

    # ------------------------------------------------------------------
    # Header block
    # ------------------------------------------------------------------
    title = "Defensive Port Scanner \u2014 Report"
    lines.append(title)
    lines.append("=" * len(title))

    generated = report.scan_finished.strftime("%Y-%m-%d %H:%M:%S")
    started = report.scan_started.strftime("%Y-%m-%d %H:%M:%S")
    finished = report.scan_finished.strftime("%Y-%m-%d %H:%M:%S")
    duration = f"{_duration(report):.2f}s"
    timeout_str = f"{report.timeout}s per port"

    if report.banner_grabbing and report.banner_timeout is not None:
        banner_str = f"enabled (timeout: {report.banner_timeout}s)"
    else:
        banner_str = "disabled"

    lines.append(f"Generated  : {generated}")
    lines.append(f"Target     : {report.target}")
    lines.append(f"Resolved IP: {report.resolved_ip}")
    lines.append(f"Ports      : {report.ports_requested}")
    lines.append(f"Started    : {started}")
    lines.append(f"Finished   : {finished}")
    lines.append(f"Duration   : {duration}")
    lines.append(f"Timeout    : {timeout_str}")
    lines.append(f"Banners    : {banner_str}")
    lines.append(f"Risk       : {'enabled' if report.risk_enabled else 'disabled'}")

    # ------------------------------------------------------------------
    # Results table
    # ------------------------------------------------------------------
    lines.append("")
    lines.append("Results")
    lines.append("-------")

    h_port = "PORT".ljust(_W_PORT)
    h_state = "STATE".ljust(_W_STATE)
    h_service = "SERVICE".ljust(_W_SERVICE)
    h_detect = "DETECTION".ljust(_W_DETECT)
    h_banner = "BANNER"
    lines.append(f"{h_port}  {h_state}  {h_service}  {h_detect}  {h_banner}")

    sep = (
        "-" * _W_PORT
        + "  "
        + "-" * _W_STATE
        + "  "
        + "-" * _W_SERVICE
        + "  "
        + "-" * _W_DETECT
        + "  "
        + "-" * _W_BANNER
    )
    lines.append(sep)

    for r in report.results:
        col_port = f"{r.port}/tcp".ljust(_W_PORT)
        col_state = r.status.ljust(_W_STATE)
        col_service = r.service_name.ljust(_W_SERVICE)
        col_detect = _detection_value(r, report.banner_grabbing).ljust(_W_DETECT)
        banner_val = _banner_text(r) or ""
        lines.append(
            f"{col_port}  {col_state}  {col_service}  {col_detect}  {banner_val}".rstrip()
        )

    # ------------------------------------------------------------------
    # Risk Assessment block
    # ------------------------------------------------------------------
    if report.risk_enabled:
        open_with_risk = [
            r for r in report.results if r.status == _STATUS_OPEN and r.risk is not None
        ]
        if open_with_risk:
            lines.append("")
            lines.append("Risk Assessment")
            lines.append("-" * 70)
            for r in open_with_risk:
                ra = r.risk
                lines.append(
                    f"  {r.port}/tcp  {r.service_name}  [{ra.level.value.upper()}]"
                )
                lines.append(f"  Reason         : {ra.reason}")
                # Word-wrap recommendation at 72 chars
                rec = ra.recommendation
                prefix = "  Recommendation : "
                wrap_indent = " " * len(prefix)
                words = rec.split()
                line_buf = prefix
                for word in words:
                    if len(line_buf) + len(word) + 1 > 72:
                        lines.append(line_buf.rstrip())
                        line_buf = wrap_indent + word + " "
                    else:
                        line_buf += word + " "
                lines.append(line_buf.rstrip())
                lines.append("")
            lines.append(f"* {_RISK_DISCLAIMER}")

    # ------------------------------------------------------------------
    # Summary block
    # ------------------------------------------------------------------
    summary = _summary(report.results)
    lines.append("")
    lines.append("Summary")
    lines.append("-------")
    lines.append(f"Total ports scanned : {summary['total']}")
    lines.append(f"Open                : {summary['open']}")
    lines.append(f"Closed              : {summary['closed']}")
    lines.append(f"Unreachable         : {summary['unreachable']}")

    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


# ---------------------------------------------------------------------------
# Convenience dispatcher
# ---------------------------------------------------------------------------

_ALL_FORMATS = {"json", "csv", "text"}


def write_reports(report: ScanReport, stem: str, formats: list[str]) -> list[Path]:
    """
    Write one or more report files derived from *stem*.

    *formats* is a list of strings from {"json", "csv", "text", "all"}.
    If "all" appears, all three formats are written.

    File names: {stem}.json, {stem}.csv, {stem}.txt

    Returns a list of Path objects that were written.
    """
    requested: set[str] = set()
    for fmt in formats:
        if fmt == "all":
            requested.update(_ALL_FORMATS)
        elif fmt in _ALL_FORMATS:
            requested.add(fmt)
        else:
            raise ValueError(
                f"Unknown report format '{fmt}'. Valid values: json, csv, text, all."
            )

    written: list[Path] = []

    if "json" in requested:
        p = Path(f"{stem}.json")
        write_json(report, p)
        written.append(p)

    if "csv" in requested:
        p = Path(f"{stem}.csv")
        write_csv(report, p)
        written.append(p)

    if "text" in requested:
        p = Path(f"{stem}.txt")
        write_text(report, p)
        written.append(p)

    return written

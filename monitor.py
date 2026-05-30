"""
monitor.py — Scheduled defensive monitoring support.

Provides:
- scan history persistence
- previous-vs-current open-port comparison
- alert generation for newly-open ports
- simple scan interval scheduler helpers
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from models import STATUS_OPEN, PortResult


@dataclass
class NewOpenPortAlert:
    host: str
    resolved_ip: str
    port: int
    service: str
    first_seen: str
    recommendation: str


def _safe_name(value: str) -> str:
    return value.replace(".", "_").replace(":", "_").replace("/", "_")


def ensure_history_dir(path: str) -> Path:
    p = Path(path)
    p.mkdir(parents=True, exist_ok=True)
    return p


def _snapshot_path(history_dir: Path, resolved_ip: str) -> Path:
    return history_dir / f"latest_{_safe_name(resolved_ip)}.json"


def _history_log_path(history_dir: Path) -> Path:
    return history_dir / "scan_history.jsonl"


def _alerts_log_path(history_dir: Path) -> Path:
    return history_dir / "alerts.log"


def load_previous_open_ports(history_dir: Path, resolved_ip: str) -> dict[int, str]:
    path = _snapshot_path(history_dir, resolved_ip)
    if not path.exists():
        return {}
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}

    ports = payload.get("openPorts", [])
    out: dict[int, str] = {}
    if isinstance(ports, list):
        for item in ports:
            if isinstance(item, dict) and isinstance(item.get("port"), int):
                out[item["port"]] = str(item.get("service", "unknown"))
    return out


def _current_open_ports(results: list[PortResult]) -> dict[int, str]:
    out: dict[int, str] = {}
    for r in results:
        if r.status == STATUS_OPEN:
            out[r.port] = r.service_name
    return out


def detect_new_open_ports(
    history_dir: Path,
    host: str,
    resolved_ip: str,
    results: list[PortResult],
    first_seen: datetime,
) -> list[NewOpenPortAlert]:
    previous = load_previous_open_ports(history_dir, resolved_ip)
    current = _current_open_ports(results)

    alerts: list[NewOpenPortAlert] = []
    for port, service in sorted(current.items()):
        if port not in previous:
            alerts.append(
                NewOpenPortAlert(
                    host=host,
                    resolved_ip=resolved_ip,
                    port=port,
                    service=service,
                    first_seen=first_seen.strftime("%Y-%m-%d %H:%M:%S"),
                    recommendation=(
                        "Verify whether this service should be exposed. "
                        "If not required, restrict with firewall rules or disable it."
                    ),
                )
            )
    return alerts


def persist_scan_state(
    history_dir: Path,
    host: str,
    resolved_ip: str,
    scan_started: datetime,
    scan_finished: datetime,
    ports_requested: str,
    results: list[PortResult],
    scan_profile: str | None = None,
) -> None:
    open_ports = [
        {"port": r.port, "service": r.service_name}
        for r in results
        if r.status == STATUS_OPEN
    ]

    snapshot = {
        "host": host,
        "resolvedIp": resolved_ip,
        "scanStarted": scan_started.isoformat(),
        "scanFinished": scan_finished.isoformat(),
        "portsRequested": ports_requested,
        "scanProfile": scan_profile,
        "openPorts": sorted(open_ports, key=lambda x: x["port"]),
    }

    _snapshot_path(history_dir, resolved_ip).write_text(
        json.dumps(snapshot, indent=2), encoding="utf-8"
    )

    hist_line = json.dumps(snapshot, separators=(",", ":"))
    with _history_log_path(history_dir).open("a", encoding="utf-8") as f:
        f.write(hist_line + "\n")


def emit_alerts(history_dir: Path, alerts: list[NewOpenPortAlert]) -> None:
    if not alerts:
        return

    lines: list[str] = []
    for a in alerts:
        block = [
            "New open port detected:",
            f"Host: {a.host} ({a.resolved_ip})",
            f"Port: {a.port}",
            f"Service: {a.service}",
            f"First Seen: {a.first_seen}",
            f"Recommendation: {a.recommendation}",
            "",
        ]
        lines.extend(block)

    text = "\n".join(lines).rstrip() + "\n"
    print("\n" + text)

    with _alerts_log_path(history_dir).open("a", encoding="utf-8") as f:
        f.write(text)

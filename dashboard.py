"""
Iteration 9 dashboard for defensivePortScanner.

Features
--------
- Local-first Flask dashboard for scan report viewing
- Session login (required for all dashboard routes)
- Local-only mode by default
- JSON report upload/import
- Scan history and per-report host/port/risk views

Security notes
--------------
- The dashboard does not trigger scans; it only views/imports reports.
- If LOCAL_ONLY is disabled, username/password authentication is required.
- Do not expose this service publicly without TLS and strong credentials.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

from flask import (
    Flask,
    abort,
    flash,
    redirect,
    render_template,
    request,
    session,
    url_for,
)

import defensivePortScanner as scanner_mod
import report as report_mod
import targets as targets_mod

BASE_DIR = Path(__file__).resolve().parent
REPORTS_DIR = BASE_DIR / "dashboard_reports"
REPORTS_DIR.mkdir(exist_ok=True)


def _env_bool(name: str, default: bool) -> bool:
    val = os.getenv(name)
    if val is None:
        return default
    return val.strip().lower() in {"1", "true", "yes", "on"}


LOCAL_ONLY = _env_bool("DPS_DASHBOARD_LOCAL_ONLY", True)
DASHBOARD_USER = os.getenv("DPS_DASHBOARD_USER", "admin")
DASHBOARD_PASSWORD = os.getenv("DPS_DASHBOARD_PASSWORD", "change-me")

app = Flask(__name__)
app.secret_key = os.getenv("DPS_DASHBOARD_SECRET", secrets.token_hex(32))


@dataclass
class ReportSummary:
    report_id: str
    file_name: str
    target: str
    resolved_ip: str
    scan_started: str
    scan_finished: str
    total_ports: int
    open_ports: int
    closed_ports: int
    unreachable_ports: int
    risk_enabled: bool


def _is_loopback(addr: str | None) -> bool:
    if not addr:
        return False
    return addr in {"127.0.0.1", "::1", "localhost"}


@app.before_request
def enforce_local_only_and_auth():
    endpoint = request.endpoint or ""
    if endpoint in {"login", "login_post", "static"}:
        return None

    if LOCAL_ONLY and not _is_loopback(request.remote_addr):
        abort(403, "Local-only mode is enabled for this dashboard.")

    if not session.get("authenticated"):
        return redirect(url_for("login", next=request.path))
    return None


def _require_str(obj: dict[str, Any], key: str) -> str:
    val = obj.get(key)
    if not isinstance(val, str) or not val.strip():
        raise ValueError(f"Missing or invalid string field: '{key}'")
    return val


def _validate_report_payload(payload: dict[str, Any]) -> None:
    if not isinstance(payload, dict):
        raise ValueError("Top-level JSON must be an object.")

    meta = payload.get("meta")
    ports = payload.get("ports")
    if not isinstance(meta, dict):
        raise ValueError("Missing or invalid 'meta' object.")
    if not isinstance(ports, list):
        raise ValueError("Missing or invalid 'ports' list.")

    _require_str(meta, "target")
    _require_str(meta, "resolvedIp")
    _require_str(meta, "scanStarted")
    _require_str(meta, "scanFinished")

    for i, p in enumerate(ports):
        if not isinstance(p, dict):
            raise ValueError(f"ports[{i}] must be an object.")
        port = p.get("port")
        state = p.get("state")
        service = p.get("service")
        if not isinstance(port, int) or not (1 <= port <= 65535):
            raise ValueError(f"ports[{i}].port must be an integer 1-65535.")
        if state not in {"open", "closed", "unreachable"}:
            raise ValueError(
                f"ports[{i}].state must be one of: open, closed, unreachable."
            )
        if not isinstance(service, str):
            raise ValueError(f"ports[{i}].service must be a string.")


def _report_id_from_payload(payload: dict[str, Any]) -> str:
    meta = payload.get("meta", {})
    key = (
        f"{meta.get('target', '')}|{meta.get('resolvedIp', '')}|"
        f"{meta.get('scanStarted', '')}|{meta.get('scanFinished', '')}|"
        f"{len(payload.get('ports', []))}"
    )
    return hashlib.sha256(key.encode("utf-8")).hexdigest()[:16]


def _report_path(report_id: str) -> Path:
    return REPORTS_DIR / f"{report_id}.json"


def _load_report(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def _safe_dt(value: str) -> str:
    try:
        return datetime.fromisoformat(value).strftime("%Y-%m-%d %H:%M:%S")
    except ValueError:
        return value


def _summarize(
    report_id: str, file_name: str, payload: dict[str, Any]
) -> ReportSummary:
    meta = payload.get("meta", {})
    summary = meta.get("summary") if isinstance(meta.get("summary"), dict) else {}
    total = int(summary.get("total", len(payload.get("ports", []))))
    open_ports = int(summary.get("open", 0))
    closed_ports = int(summary.get("closed", 0))
    unreachable_ports = int(summary.get("unreachable", 0))

    return ReportSummary(
        report_id=report_id,
        file_name=file_name,
        target=str(meta.get("target", "unknown")),
        resolved_ip=str(meta.get("resolvedIp", "unknown")),
        scan_started=_safe_dt(str(meta.get("scanStarted", ""))),
        scan_finished=_safe_dt(str(meta.get("scanFinished", ""))),
        total_ports=total,
        open_ports=open_ports,
        closed_ports=closed_ports,
        unreachable_ports=unreachable_ports,
        risk_enabled=bool(meta.get("riskAnalysis", False)),
    )


def _list_summaries() -> list[ReportSummary]:
    out: list[ReportSummary] = []
    for p in sorted(REPORTS_DIR.glob("*.json"), reverse=True):
        try:
            payload = _load_report(p)
            _validate_report_payload(payload)
            report_id = p.stem
            out.append(_summarize(report_id, p.name, payload))
        except Exception:
            continue
    return sorted(out, key=lambda r: r.scan_started, reverse=True)


@app.get("/login")
def login():
    if session.get("authenticated"):
        return redirect(url_for("index"))
    next_path = request.args.get("next", "")
    return render_template("login.html", local_only=LOCAL_ONLY, next_path=next_path)


@app.post("/login")
def login_post():
    username = request.form.get("username", "")
    password = request.form.get("password", "")

    ok_user = hmac.compare_digest(username, DASHBOARD_USER)
    ok_pass = hmac.compare_digest(password, DASHBOARD_PASSWORD)

    if ok_user and ok_pass:
        session["authenticated"] = True
        nxt = request.form.get("next", "")
        if nxt and nxt.startswith("/"):
            return redirect(nxt)
        return redirect(url_for("index"))

    flash("Invalid credentials.", "error")
    return render_template("login.html", local_only=LOCAL_ONLY, next_path=""), 401


@app.post("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


def _split_targets(raw: str) -> list[str]:
    out: list[str] = []
    for line in raw.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        out.extend([p.strip() for p in line.split(",") if p.strip()])
    return out


def _save_scan_payload(payload: dict[str, Any]) -> str:
    report_id = _report_id_from_payload(payload)
    _report_path(report_id).write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return report_id


@app.get("/")
def index():
    summaries = _list_summaries()
    return render_template("index.html", summaries=summaries, local_only=LOCAL_ONLY)


@app.get("/scan")
def scan_form():
    return render_template("scan.html")


@app.post("/scan")
def scan_run():
    targets_raw = request.form.get("targets", "")
    ports_raw = request.form.get("ports", "")
    timeout_raw = request.form.get("timeout", "1.0")
    banner_enabled = request.form.get("banner") == "on"
    risk_enabled = request.form.get("risk") == "on"
    banner_timeout_raw = request.form.get("banner_timeout", "2.0")
    concurrency_raw = request.form.get("concurrency", "100")

    entries = _split_targets(targets_raw)
    if not entries:
        flash("Provide at least one target.", "error")
        return redirect(url_for("scan_form"))

    try:
        ports = scanner_mod.parse_ports(ports_raw)
    except Exception as exc:
        flash(f"Invalid ports: {exc}", "error")
        return redirect(url_for("scan_form"))

    try:
        timeout = float(timeout_raw)
        if timeout <= 0:
            raise ValueError("timeout must be > 0")
        banner_timeout = float(banner_timeout_raw)
        if banner_timeout <= 0:
            raise ValueError("banner timeout must be > 0")
        concurrency = int(concurrency_raw)
        if concurrency < 1 or concurrency > scanner_mod.MAX_CONCURRENCY:
            raise ValueError(
                f"concurrency must be between 1 and {scanner_mod.MAX_CONCURRENCY}"
            )
    except ValueError as exc:
        flash(f"Invalid numeric input: {exc}", "error")
        return redirect(url_for("scan_form"))

    try:
        resolved = targets_mod.resolve_targets(entries)
    except Exception as exc:
        flash(f"Target resolution failed: {exc}", "error")
        return redirect(url_for("scan_form"))

    if not resolved:
        flash("No valid targets resolved.", "error")
        return redirect(url_for("scan_form"))

    saved_ids: list[str] = []
    for rt in resolved:
        scan_started = datetime.now()
        results = scanner_mod.scan_ports(
            rt.ip,
            ports,
            timeout,
            banner_enabled,
            banner_timeout,
            concurrency=concurrency,
            label="",
            cancel_event=None,
        )
        if risk_enabled:
            scanner_mod.apply_risk(results)
        scan_finished = datetime.now()

        report = report_mod.build_report(
            target=rt.display,
            resolved_ip=rt.ip,
            ports_requested=ports_raw,
            scan_started=scan_started,
            scan_finished=scan_finished,
            timeout=timeout,
            banner_grabbing=banner_enabled,
            banner_timeout=banner_timeout if banner_enabled else None,
            results=results,
            risk_enabled=risk_enabled,
            scan_profile="dashboard",
        )

        tmp_path = REPORTS_DIR / "_tmp_dashboard_report.json"
        report_mod.write_json(report, tmp_path)
        payload = json.loads(tmp_path.read_text(encoding="utf-8"))
        tmp_path.unlink(missing_ok=True)
        saved_ids.append(_save_scan_payload(payload))

    if not saved_ids:
        flash("Scan completed but no reports were generated.", "error")
        return redirect(url_for("scan_form"))

    flash(f"Scan complete. Saved {len(saved_ids)} report(s).", "ok")
    if len(saved_ids) == 1:
        return redirect(url_for("report_view", report_id=saved_ids[0]))
    return redirect(url_for("index"))


@app.get("/reports/<report_id>")
def report_view(report_id: str):
    path = _report_path(report_id)
    if not path.exists():
        abort(404)

    payload = _load_report(path)
    _validate_report_payload(payload)

    meta = payload["meta"]
    ports = payload["ports"]
    open_ports = [p for p in ports if p.get("state") == "open"]

    risk_items = [
        {
            "port": p.get("port"),
            "service": p.get("service"),
            "level": (p.get("risk") or {}).get("level"),
            "reason": (p.get("risk") or {}).get("reason"),
            "recommendation": (p.get("risk") or {}).get("recommendation"),
        }
        for p in open_ports
        if isinstance(p.get("risk"), dict)
    ]

    return render_template(
        "report_view.html",
        report_id=report_id,
        meta=meta,
        ports=ports,
        open_ports=open_ports,
        risk_items=risk_items,
        risk_disclaimer=payload.get("riskDisclaimer"),
    )


@app.post("/upload")
def upload_report():
    file = request.files.get("report_file")
    if not file or not file.filename:
        flash("Please select a JSON report file.", "error")
        return redirect(url_for("index"))

    try:
        raw = file.read()
        payload = json.loads(raw.decode("utf-8"))
        _validate_report_payload(payload)
    except UnicodeDecodeError:
        flash("Upload failed: file must be UTF-8 JSON.", "error")
        return redirect(url_for("index"))
    except json.JSONDecodeError as exc:
        flash(f"Upload failed: invalid JSON ({exc}).", "error")
        return redirect(url_for("index"))
    except ValueError as exc:
        flash(f"Upload failed: {exc}", "error")
        return redirect(url_for("index"))

    report_id = _report_id_from_payload(payload)
    out_path = _report_path(report_id)
    out_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")

    flash(f"Imported report as {out_path.name}", "ok")
    return redirect(url_for("report_view", report_id=report_id))


@app.get("/health")
def health():
    # Health endpoint still requires auth due to before_request policy.
    return {
        "status": "ok",
        "localOnly": LOCAL_ONLY,
        "reportCount": len(_list_summaries()),
    }


def _startup_checks() -> None:
    if not LOCAL_ONLY and DASHBOARD_PASSWORD == "change-me":
        raise RuntimeError(
            "Refusing to start with local-only disabled and default password. "
            "Set DPS_DASHBOARD_PASSWORD to a strong value."
        )


if __name__ == "__main__":
    _startup_checks()
    host = "127.0.0.1" if LOCAL_ONLY else "0.0.0.0"
    port = int(os.getenv("DPS_DASHBOARD_PORT", "5000"))
    app.run(host=host, port=port, debug=False)

"""
Defensive Port Scanner - Iteration 2
=====================================
A lightweight TCP port scanner built with Python stdlib only.
Intended strictly for authorized, defensive security assessments.

Iteration 2 additions:
  - Service identification via local lookup table (services.py)
  - Optional banner grabbing for open ports (banner.py)
  - Clear distinction between inferred (port-table) and detected (live) data
  - Expanded output table: PORT | STATE | SERVICE | DETECTION | BANNER
  - --no-banner flag to skip banner grabbing
  - --banner-timeout flag for independent banner timeout control
"""

import argparse
import re
import socket
import sys
from datetime import datetime

import banner as banner_mod
import services
from banner import BannerResult, DetectionMethod

# ---------------------------------------------------------------------------
# Banner (startup)
# ---------------------------------------------------------------------------

_BANNER_UTF8 = """
\u2554\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2557
\u2551           Defensive Port Scanner  \u2014  Iteration 2            \u2551
\u2551                                                              \u2551
\u2551  ETHICAL USE ONLY. Scan only hosts you own or have explicit  \u2551
\u2551  written permission to test. Unauthorized port scanning may  \u2551
\u2551  be illegal and is strictly prohibited.                      \u2551
\u255a\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u255d
"""

_BANNER_ASCII = """
+--------------------------------------------------------------+
|          Defensive Port Scanner  -  Iteration 2             |
|                                                              |
|  ETHICAL USE ONLY. Scan only hosts you own or have explicit  |
|  written permission to test. Unauthorized port scanning may  |
|  be illegal and is strictly prohibited.                      |
+--------------------------------------------------------------+
"""


def _get_banner() -> str:
    try:
        _BANNER_UTF8.encode(sys.stdout.encoding or "utf-8")
        return _BANNER_UTF8
    except (UnicodeEncodeError, LookupError):
        return _BANNER_ASCII


BANNER = _get_banner

# ---------------------------------------------------------------------------
# Input validation
# ---------------------------------------------------------------------------


def validate_target(target: str) -> str:
    """Accept a valid IPv4/IPv6 address or well-formed hostname."""
    for family in (socket.AF_INET, socket.AF_INET6):
        try:
            socket.inet_pton(family, target)
            return target
        except (socket.error, OSError):
            pass

    hostname_re = re.compile(r"^(?!-)[A-Za-z0-9\-]{1,63}(?<!-)$")
    labels = target.rstrip(".").split(".")
    if not labels or any(not hostname_re.match(lbl) for lbl in labels):
        raise ValueError(
            f"Invalid target '{target}'. Provide a valid IPv4/IPv6 address "
            "or a proper hostname (e.g. example.com, localhost)."
        )
    return target


def parse_ports(ports_str: str) -> list[int]:
    """
    Parse a comma-separated list of ports and/or ranges.
      '22,80,443'    → [22, 80, 443]
      '80-90'        → [80 … 90]
      '22,80-85,443' → sorted, deduplicated list
    """
    ports: set[int] = set()
    tokens = [t.strip() for t in ports_str.split(",") if t.strip()]

    if not tokens:
        raise ValueError("No ports specified.")

    for token in tokens:
        if "-" in token:
            parts = token.split("-")
            if len(parts) != 2:
                raise ValueError(f"Invalid port range '{token}'.")
            start_s, end_s = parts[0].strip(), parts[1].strip()
            if not start_s.isdigit() or not end_s.isdigit():
                raise ValueError(f"Non-numeric value in range '{token}'.")
            start, end = int(start_s), int(end_s)
            if not (1 <= start <= 65535) or not (1 <= end <= 65535):
                raise ValueError(f"Port range '{token}' is out of bounds (1-65535).")
            if start > end:
                raise ValueError(f"Range start ({start}) must be <= range end ({end}).")
            ports.update(range(start, end + 1))
        else:
            if not token.isdigit():
                raise ValueError(f"Non-numeric port value '{token}'.")
            port = int(token)
            if not (1 <= port <= 65535):
                raise ValueError(f"Port {port} is out of bounds (1-65535).")
            ports.add(port)

    return sorted(ports)


def validate_timeout(value: str) -> float:
    """Parse and validate a timeout string. Must be a positive float."""
    try:
        t = float(value)
    except ValueError:
        raise argparse.ArgumentTypeError(
            f"Invalid timeout '{value}'. Must be a positive number (e.g. 1.0)."
        )
    if t <= 0:
        raise argparse.ArgumentTypeError(f"Timeout must be > 0, got {t}.")
    return t


# ---------------------------------------------------------------------------
# Scan result type
# ---------------------------------------------------------------------------

STATUS_OPEN = "open"
STATUS_CLOSED = "closed"
STATUS_UNREACHABLE = "unreachable"


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


# ---------------------------------------------------------------------------
# Scanning
# ---------------------------------------------------------------------------


def scan_port(host: str, port: int, timeout: float) -> str:
    """TCP connect scan. Returns 'open', 'closed', or 'unreachable'."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            result = sock.connect_ex((host, port))
            return STATUS_OPEN if result == 0 else STATUS_CLOSED
    except socket.timeout:
        return STATUS_UNREACHABLE
    except socket.gaierror:
        raise
    except OSError:
        return STATUS_CLOSED


def scan_ports(
    host: str,
    ports: list[int],
    timeout: float,
    grab_banners: bool,
    banner_timeout: float,
) -> list[PortResult]:
    """Scan all ports; optionally grab banners for open ports."""
    results: list[PortResult] = []
    total = len(ports)
    width = len(str(total))

    for idx, port in enumerate(ports, start=1):
        print(
            f"\r  Scanning port {port:<6}  [{idx:{width}d}/{total}]",
            end="",
            flush=True,
        )
        status = scan_port(host, port, timeout)

        # Service name is always resolved from the local table (inference).
        svc_name = services.service_name(port)

        # Banner grab only for open ports when enabled.
        br: BannerResult | None = None
        if status == STATUS_OPEN and grab_banners:
            br = banner_mod.grab_banner(host, port, banner_timeout)

        results.append(PortResult(port, status, svc_name, br))

    print("\r" + " " * 60 + "\r", end="", flush=True)
    return results


# ---------------------------------------------------------------------------
# ANSI helpers
# ---------------------------------------------------------------------------

_GREEN = "\033[32m"
_GRAY = "\033[90m"
_YELLOW = "\033[33m"
_CYAN = "\033[36m"
_DIM = "\033[2m"
_BOLD = "\033[1m"
_RESET = "\033[0m"

_STATUS_COLOR = {
    STATUS_OPEN: _GREEN,
    STATUS_CLOSED: _GRAY,
    STATUS_UNREACHABLE: _YELLOW,
}


def _c(text: str, code: str) -> str:
    """Apply an ANSI color code when stdout is a TTY."""
    if sys.stdout.isatty():
        return f"{code}{text}{_RESET}"
    return text


# ---------------------------------------------------------------------------
# Output formatting
# ---------------------------------------------------------------------------

# Column widths
_W_PORT = 9  # "65535/tcp"
_W_STATE = 13  # "unreachable"
_W_SERVICE = 14  # "Elasticsearch"
_W_DETECT = 11  # "inferred"


def _detection_label(br: BannerResult | None) -> tuple[str, str]:
    """
    Return (label, color) for the DETECTION column.
    When banner grabbing was skipped (br is None) we show 'inferred'
    because the service name always comes from the port table.
    """
    if br is None:
        return "inferred", _DIM
    match br.method:
        case DetectionMethod.DETECTED:
            return "detected", _CYAN
        case DetectionMethod.INFERRED:
            return "inferred", _DIM
        case DetectionMethod.FAILED:
            return "failed", _YELLOW
        case _:
            return "inferred", _DIM


def print_results(results: list[PortResult], grab_banners: bool) -> None:
    """Print a formatted results table, then a summary line."""

    # --- header ---
    h_port = "PORT".ljust(_W_PORT)
    h_state = "STATE".ljust(_W_STATE)
    h_service = "SERVICE".ljust(_W_SERVICE)
    h_detect = "DETECTION".ljust(_W_DETECT)
    h_banner = "BANNER / INFO"

    if grab_banners:
        header = f"\n{h_port}  {h_state}  {h_service}  {h_detect}  {h_banner}"
        sep = (
            "-" * _W_PORT
            + "  "
            + "-" * _W_STATE
            + "  "
            + "-" * _W_SERVICE
            + "  "
            + "-" * _W_DETECT
            + "  "
            + "-" * 30
        )
    else:
        header = f"\n{h_port}  {h_state}  {h_service}  {h_detect}"
        sep = (
            "-" * _W_PORT
            + "  "
            + "-" * _W_STATE
            + "  "
            + "-" * _W_SERVICE
            + "  "
            + "-" * _W_DETECT
        )

    print(_c(header.lstrip("\n"), _BOLD))
    print(sep)

    # --- rows grouped: open → closed → unreachable ---
    counts = {STATUS_OPEN: 0, STATUS_CLOSED: 0, STATUS_UNREACHABLE: 0}
    grouped: dict[str, list[PortResult]] = {
        STATUS_OPEN: [],
        STATUS_CLOSED: [],
        STATUS_UNREACHABLE: [],
    }
    for r in results:
        grouped[r.status].append(r)
        counts[r.status] += 1

    first_group = True
    for status in (STATUS_OPEN, STATUS_CLOSED, STATUS_UNREACHABLE):
        group = grouped[status]
        if not group:
            continue
        if not first_group:
            print()
        first_group = False

        state_color = _STATUS_COLOR[status]

        for r in group:
            col_port = f"{r.port}/tcp".ljust(_W_PORT)
            col_state = _c(status.ljust(_W_STATE), state_color)
            col_service = r.service_name.ljust(_W_SERVICE)

            detect_label, detect_color = _detection_label(r.banner)
            col_detect = _c(detect_label.ljust(_W_DETECT), detect_color)

            if grab_banners:
                banner_text = ""
                if r.banner and r.banner.raw:
                    banner_text = _c(r.banner.raw, _CYAN)
                elif r.status == STATUS_OPEN:
                    # Provide the service description as a fallback hint
                    info = services.lookup(r.port)
                    if info:
                        banner_text = _c(f"({info.description})", _DIM)
                print(
                    f"{col_port}  {col_state}  {col_service}  {col_detect}  {banner_text}"
                )
            else:
                # No banner column — show service description inline as a hint
                info = services.lookup(r.port)
                hint = (
                    _c(f"  # {info.description}", _DIM)
                    if info and status == STATUS_OPEN
                    else ""
                )
                print(f"{col_port}  {col_state}  {col_service}  {col_detect}{hint}")

    # --- summary ---
    print(
        f"\nScan complete: "
        f"{_c(str(counts[STATUS_OPEN]) + ' open', _GREEN)}, "
        f"{counts[STATUS_CLOSED]} closed, "
        f"{_c(str(counts[STATUS_UNREACHABLE]) + ' unreachable', _YELLOW)}."
    )


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="defensivePortScanner",
        description=(
            "Defensive TCP port scanner — scan only hosts you are authorized to test."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python defensivePortScanner.py --target 192.168.1.10 --ports 22,80,443\n"
            "  python defensivePortScanner.py --target localhost --ports 1-1024 --timeout 0.5\n"
            "  python defensivePortScanner.py --target 10.0.0.1 --ports 22,80-85,443 --no-banner\n"
        ),
    )
    parser.add_argument(
        "--target",
        required=True,
        metavar="HOST",
        help="IP address or hostname to scan.",
    )
    parser.add_argument(
        "--ports",
        required=True,
        metavar="PORTS",
        help="Comma-separated ports and/or ranges. E.g. 22,80,443 | 1-1024 | 22,80-85,443",
    )
    parser.add_argument(
        "--timeout",
        default=1.0,
        type=validate_timeout,
        metavar="SECONDS",
        help="TCP connect timeout per port in seconds (default: 1.0).",
    )
    parser.add_argument(
        "--no-banner",
        dest="no_banner",
        action="store_true",
        help="Skip banner grabbing; show inferred service names only.",
    )
    parser.add_argument(
        "--banner-timeout",
        dest="banner_timeout",
        default=2.0,
        type=validate_timeout,
        metavar="SECONDS",
        help="Timeout for each banner read in seconds (default: 2.0).",
    )
    return parser


def main() -> None:
    print(BANNER())

    parser = build_parser()
    args = parser.parse_args()

    try:
        target = validate_target(args.target)
    except ValueError as exc:
        parser.error(str(exc))

    try:
        ports = parse_ports(args.ports)
    except ValueError as exc:
        parser.error(str(exc))

    try:
        resolved_ip = socket.gethostbyname(target)
    except socket.gaierror as exc:
        parser.error(f"Could not resolve host '{target}': {exc}")

    grab_banners = not args.no_banner

    display_host = target if target == resolved_ip else f"{target} ({resolved_ip})"
    print(f"  Target         : {display_host}")
    if len(ports) > 1:
        print(f"  Ports          : {len(ports)} port(s)  [{ports[0]}-{ports[-1]}]")
    else:
        print(f"  Ports          : {ports[0]}")
    print(f"  Scan timeout   : {args.timeout}s per port")
    if grab_banners:
        print(f"  Banner timeout : {args.banner_timeout}s per port")
    else:
        print(f"  Banner grabbing: disabled")
    print(f"  Started        : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print()

    try:
        results = scan_ports(
            resolved_ip, ports, args.timeout, grab_banners, args.banner_timeout
        )
    except socket.gaierror as exc:
        sys.exit(f"Error during scan: {exc}")

    print_results(results, grab_banners)
    print()


if __name__ == "__main__":
    main()

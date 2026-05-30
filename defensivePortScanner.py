"""
Defensive Port Scanner - Iteration 5
=====================================
A lightweight TCP port scanner built with Python stdlib only.
Intended strictly for authorized, defensive security assessments.

Iteration 5 additions:
  - --targets accepts one or more hosts/CIDRs directly on the CLI
  - --targets-file reads targets from a file (one per line, # comments)
  - CIDR notation expanded to individual hosts (max 1024 per range)
  - Public IP detection with mandatory confirmation prompt
  - Large-scan confirmation prompt (>5 hosts, overridable with --yes)
  - Inter-host rate limiting (--rate-limit, default 0.5s)
  - targets.py: all resolution, CIDR expansion, and safety logic
"""

import argparse
import socket
import sys
import time
from datetime import datetime

import banner as banner_mod
import report as report_mod
import services
import targets as targets_mod
from banner import BannerResult, DetectionMethod
from models import STATUS_CLOSED, STATUS_OPEN, STATUS_UNREACHABLE, PortResult
from targets import ResolvedTarget, TargetClassification

# ---------------------------------------------------------------------------
# Banner (startup)
# ---------------------------------------------------------------------------

_BANNER_UTF8 = """
\u2554\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2557
\u2551           Defensive Port Scanner  \u2014  Iteration 5            \u2551
\u2551                                                              \u2551
\u2551  ETHICAL USE ONLY. Scan only hosts you own or have explicit  \u2551
\u2551  written permission to test. Unauthorized port scanning may  \u2551
\u2551  be illegal and is strictly prohibited.                      \u2551
\u255a\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u255d
"""

_BANNER_ASCII = """
+--------------------------------------------------------------+
|          Defensive Port Scanner  -  Iteration 5             |
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

# Number of hosts beyond which the user must confirm before scanning.
CONFIRM_THRESHOLD = 5

# Default inter-host delay in seconds.
DEFAULT_RATE_LIMIT = 0.5


def confirm_scan(
    classification: TargetClassification,
    skip_confirm: bool,
) -> bool:
    """
    Display safety warnings and request confirmation when needed.

    Returns True if the scan should proceed, False if the user cancelled.
    Confirmation is skipped when skip_confirm=True (--yes flag).

    Two distinct warning levels:
      1. Public IPs present          — always warns; requires explicit 'y'
         regardless of --yes, because public scanning carries legal risk.
      2. Large host count (>threshold) — warns; suppressed by --yes.
    """
    proceed = True

    # --- public IP warning (cannot be suppressed by --yes) ---
    if classification.public > 0:
        sample = classification.public_ips[:5]
        extra = classification.public - len(sample)
        sample_str = ", ".join(sample)
        if extra:
            sample_str += f" ... (+{extra} more)"

        print()
        _warn = lambda t: (
            print(f"\033[31m{t}\033[0m") if sys.stdout.isatty() else print(t)
        )
        _warn("  [!] WARNING: PUBLIC IP ADDRESSES DETECTED")
        _warn(f"      {sample_str}")
        print()
        print("  Scanning public IP addresses without explicit written")
        print("  authorization from the owner may be illegal under the")
        print("  Computer Fraud and Abuse Act (CFAA) and equivalent laws.")
        print()
        try:
            answer = (
                input(
                    "  Type 'yes' to confirm you are authorized to scan these hosts: "
                )
                .strip()
                .lower()
            )
        except (EOFError, KeyboardInterrupt):
            print()
            return False
        if answer != "yes":
            print("  Scan cancelled.")
            return False
        print()

    # --- large-scan warning (skippable with --yes) ---
    if classification.total > CONFIRM_THRESHOLD and not skip_confirm:
        msg = f"  [!] You are about to scan {classification.total} hosts."
        print(f"\033[33m{msg}\033[0m" if sys.stdout.isatty() else msg)
        print("      Use --yes to suppress this prompt in scripts.")
        try:
            answer = input("  Proceed? [y/N]: ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            print()
            return False
        if answer not in ("y", "yes"):
            print("  Scan cancelled.")
            return False
        print()

    return proceed


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
    label: str = "",
) -> list[PortResult]:
    """Scan all ports on host; optionally grab banners for open ports."""
    results: list[PortResult] = []
    total = len(ports)
    width = len(str(total))
    prefix = f"[{label}] " if label else ""

    for idx, port in enumerate(ports, start=1):
        print(
            f"\r  {prefix}Scanning port {port:<6}  [{idx:{width}d}/{total}]",
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
            "  python defensivePortScanner.py --targets 192.168.1.10 --ports 22,80,443\n"
            "  python defensivePortScanner.py --targets 192.168.1.0/28 --ports 22,80,443\n"
            "  python defensivePortScanner.py --targets-file hosts.txt --ports 1-1024\n"
            "  python defensivePortScanner.py --targets 10.0.0.1 10.0.0.2 --ports 22,80 --banner\n"
            "  python defensivePortScanner.py --targets-file hosts.txt --ports 22,80,443 --output report\n"
        ),
    )

    # --- target arguments (at least one of --targets or --targets-file required) ---
    target_group = parser.add_argument_group("targets")
    target_group.add_argument(
        "--targets",
        nargs="+",
        metavar="HOST",
        default=[],
        help=(
            "One or more targets: IPv4 addresses, hostnames, or CIDR ranges. "
            "E.g. --targets 192.168.1.10 192.168.1.20 10.0.0.0/28"
        ),
    )
    target_group.add_argument(
        "--targets-file",
        dest="targets_file",
        default=None,
        metavar="FILE",
        help=(
            "Path to a file containing targets, one per line. "
            "Lines starting with '#' are treated as comments."
        ),
    )

    # --- scan arguments ---
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
        "--banner",
        dest="banner",
        action="store_true",
        help="Grab service banners from open ports (opt-in; off by default).",
    )
    parser.add_argument(
        "--banner-timeout",
        dest="banner_timeout",
        default=2.0,
        type=validate_timeout,
        metavar="SECONDS",
        help="Timeout for each banner read in seconds (default: 2.0; requires --banner).",
    )
    parser.add_argument(
        "--rate-limit",
        dest="rate_limit",
        default=DEFAULT_RATE_LIMIT,
        type=validate_timeout,
        metavar="SECONDS",
        help=(
            f"Delay between hosts in seconds (default: {DEFAULT_RATE_LIMIT}). "
            "Set to 0 to disable. Applies only when scanning multiple targets."
        ),
    )

    # --- safety arguments ---
    parser.add_argument(
        "--yes",
        "-y",
        dest="yes",
        action="store_true",
        help=(
            "Skip the large-scan confirmation prompt. "
            "The public-IP warning always requires explicit confirmation."
        ),
    )

    # --- output arguments ---
    parser.add_argument(
        "--output",
        dest="output",
        default=None,
        metavar="STEM",
        help=(
            "Write report(s) with this base name. With multiple targets, each "
            "host gets its own file: {stem}_{ip}.json etc."
        ),
    )
    parser.add_argument(
        "--format",
        dest="formats",
        default=["all"],
        metavar="FORMAT",
        nargs="+",
        choices=["json", "csv", "text", "all"],
        help="Report format(s): json, csv, text, all (default: all). Requires --output.",
    )
    return parser


def main() -> None:
    print(BANNER())

    parser = build_parser()
    args = parser.parse_args()

    # --- require at least one target source ---
    if not args.targets and not args.targets_file:
        parser.error("Provide at least one target via --targets or --targets-file.")

    # --- parse ports ---
    try:
        ports = parse_ports(args.ports)
    except ValueError as exc:
        parser.error(str(exc))

    # --- collect raw target strings ---
    raw_entries: list[str] = list(args.targets)
    if args.targets_file:
        try:
            raw_entries += targets_mod.parse_targets_file(args.targets_file)
        except (FileNotFoundError, ValueError) as exc:
            parser.error(str(exc))

    # --- resolve all targets ---
    try:
        resolved = targets_mod.resolve_targets(raw_entries)
    except (ValueError, socket.gaierror) as exc:
        parser.error(str(exc))

    if not resolved:
        parser.error("No valid targets found after resolution.")

    # --- classify for safety checks ---
    classification = targets_mod.classify_targets(resolved)
    grab_banners = args.banner

    # --- print scan summary ---
    if len(resolved) == 1:
        rt = resolved[0]
        display = rt.display if rt.display == rt.ip else f"{rt.display} ({rt.ip})"
        print(f"  Target         : {display}")
    else:
        print(f"  Targets        : {len(resolved)} host(s)")
        if classification.public:
            pub_note = (
                f"  ({classification.public} public, {classification.private} private)"
            )
            print(f"                   {pub_note}")

    port_display = (
        f"{len(ports)} port(s)  [{ports[0]}-{ports[-1]}]"
        if len(ports) > 1
        else str(ports[0])
    )
    print(f"  Ports          : {port_display}")
    print(f"  Scan timeout   : {args.timeout}s per port")
    if grab_banners:
        print(f"  Banner grabbing: enabled (timeout: {args.banner_timeout}s per port)")
    else:
        print(f"  Banner grabbing: disabled  (use --banner to enable)")
    if len(resolved) > 1:
        print(f"  Rate limit     : {args.rate_limit}s between hosts")
    if args.output:
        fmt_str = ", ".join(args.formats)
        if len(resolved) > 1:
            print(f"  Output         : {args.output}_{{ip}}.*  ({fmt_str})")
        else:
            print(f"  Output         : {args.output}.*  ({fmt_str})")
    print()

    # --- safety confirmation ---
    if not confirm_scan(classification, skip_confirm=args.yes):
        sys.exit(0)

    # -------------------------------------------------------------------
    # Multi-target scan loop
    # -------------------------------------------------------------------
    overall_started = datetime.now()
    total_open = total_closed = total_unreachable = 0

    for host_idx, rt in enumerate(resolved):
        if host_idx > 0 and args.rate_limit > 0:
            time.sleep(args.rate_limit)

        if len(resolved) > 1:
            print(
                f"  [{host_idx + 1}/{len(resolved)}] Scanning {rt.display} ({rt.ip}) ..."
            )

        scan_started = datetime.now()

        try:
            results = scan_ports(
                rt.ip,
                ports,
                args.timeout,
                grab_banners,
                args.banner_timeout,
                label=rt.display if len(resolved) > 1 else "",
            )
        except socket.gaierror as exc:
            print(f"  [!] Skipping {rt.display}: {exc}")
            continue

        scan_finished = datetime.now()

        print_results(results, grab_banners)
        print()

        # accumulate totals
        for r in results:
            if r.status == STATUS_OPEN:
                total_open += 1
            elif r.status == STATUS_CLOSED:
                total_closed += 1
            else:
                total_unreachable += 1

        # --- per-host report export ---
        if args.output:
            # sanitise IP for use in filename (replace dots and colons)
            safe_ip = rt.ip.replace(".", "_").replace(":", "_")
            stem = f"{args.output}_{safe_ip}" if len(resolved) > 1 else args.output
            rpt = report_mod.build_report(
                target=rt.display,
                resolved_ip=rt.ip,
                ports_requested=args.ports,
                scan_started=scan_started,
                scan_finished=scan_finished,
                timeout=args.timeout,
                banner_grabbing=grab_banners,
                banner_timeout=args.banner_timeout if grab_banners else None,
                results=results,
            )
            try:
                written = report_mod.write_reports(rpt, stem, args.formats)
                for p in written:
                    print(f"  Report saved   : {p}")
                print()
            except OSError as exc:
                print(f"  [!] Could not write report: {exc}")

    # --- multi-target summary ---
    if len(resolved) > 1:
        overall_duration = (datetime.now() - overall_started).total_seconds()
        print(f"  {'=' * 54}")
        print(f"  Multi-target scan complete")
        print(f"  Hosts scanned  : {len(resolved)}")
        print(f"  Total open     : {total_open}")
        print(f"  Total closed   : {total_closed}")
        print(f"  Total unreachable: {total_unreachable}")
        print(f"  Duration       : {overall_duration:.1f}s")
        print()


if __name__ == "__main__":
    main()

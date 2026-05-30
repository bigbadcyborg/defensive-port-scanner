"""
Defensive Port Scanner - Iteration 6
=====================================
A lightweight TCP port scanner built with Python stdlib only.
Intended strictly for authorized, defensive security assessments.

Iteration 6 additions:
  - Concurrent port scanning via ThreadPoolExecutor
  - --concurrency N  (default 100, hard cap 500)
  - --host-concurrency N  (default 1; concurrent multi-host scanning)
  - Live progress bar: completed/total, % done, elapsed, ETA
  - Graceful Ctrl-C cancellation via threading.Event + SIGINT handler
  - Results sorted by port number regardless of completion order
  - Deterministic output: open ports still printed before closed
"""

import argparse
import signal
import socket
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
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
\u2551           Defensive Port Scanner  \u2014  Iteration 6            \u2551
\u2551                                                              \u2551
\u2551  ETHICAL USE ONLY. Scan only hosts you own or have explicit  \u2551
\u2551  written permission to test. Unauthorized port scanning may  \u2551
\u2551  be illegal and is strictly prohibited.                      \u2551
\u255a\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u255d
"""

_BANNER_ASCII = """
+--------------------------------------------------------------+
|          Defensive Port Scanner  -  Iteration 6             |
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

# Concurrency defaults and hard cap.
DEFAULT_CONCURRENCY = 100  # simultaneous port probes per host
DEFAULT_HOST_CONCURRENCY = 1  # simultaneous hosts (safe default)
MAX_CONCURRENCY = 500  # absolute ceiling


def validate_concurrency(value: str) -> int:
    """Parse and validate a concurrency value: positive integer, <= MAX_CONCURRENCY."""
    try:
        n = int(value)
    except ValueError:
        raise argparse.ArgumentTypeError(
            f"Invalid concurrency '{value}'. Must be a positive integer."
        )
    if n < 1:
        raise argparse.ArgumentTypeError(f"Concurrency must be >= 1, got {n}.")
    if n > MAX_CONCURRENCY:
        raise argparse.ArgumentTypeError(
            f"Concurrency {n} exceeds the safety cap of {MAX_CONCURRENCY}."
        )
    return n


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


# ---------------------------------------------------------------------------
# Progress display
# ---------------------------------------------------------------------------

_PROGRESS_LOCK = threading.Lock()


def _render_progress(
    label: str,
    done: int,
    total: int,
    start_time: float,
) -> None:
    """
    Overwrite the current terminal line with a progress bar.
    Thread-safe via _PROGRESS_LOCK. No-op when stdout is not a TTY.
    """
    if not sys.stdout.isatty():
        return

    pct = done / total if total else 0
    bar_width = 20
    filled = int(bar_width * pct)
    bar = "#" * filled + "-" * (bar_width - filled)

    elapsed = time.monotonic() - start_time
    if done > 0:
        eta = elapsed / done * (total - done)
        eta_str = f"ETA {eta:4.0f}s"
    else:
        eta_str = "ETA    ?s"

    prefix = f"[{label}] " if label else ""
    line = (
        f"\r  {prefix}[{bar}] {done:>{len(str(total))}}/{total} "
        f"({pct:5.1%})  {elapsed:5.1f}s elapsed  {eta_str}"
    )
    with _PROGRESS_LOCK:
        print(line[:120], end="", flush=True)


def _clear_progress() -> None:
    """Erase the progress line."""
    if sys.stdout.isatty():
        print("\r" + " " * 120 + "\r", end="", flush=True)


# ---------------------------------------------------------------------------
# Concurrent scanner
# ---------------------------------------------------------------------------


def scan_ports(
    host: str,
    ports: list[int],
    timeout: float,
    grab_banners: bool,
    banner_timeout: float,
    concurrency: int = DEFAULT_CONCURRENCY,
    label: str = "",
    cancel_event: threading.Event | None = None,
) -> list[PortResult]:
    """
    Scan all ports on host concurrently using a ThreadPoolExecutor.

    - Up to `concurrency` port probes run simultaneously.
    - Results are sorted by port number for deterministic output.
    - If `cancel_event` is set before or during the scan, pending futures
      are cancelled and the partial result set is returned.
    - Banner grabs run on the calling thread after all port probes finish,
      so the progress bar accurately reflects the TCP-connect phase.
    """
    if cancel_event is None:
        cancel_event = threading.Event()

    total = len(ports)
    results_map: dict[int, PortResult] = {}
    done_count = 0
    start_time = time.monotonic()

    def _worker(port: int) -> tuple[int, str]:
        """Return (port, status). Checked-in by the executor."""
        if cancel_event.is_set():
            return port, STATUS_UNREACHABLE
        return port, scan_port(host, port, timeout)

    with ThreadPoolExecutor(max_workers=concurrency) as executor:
        future_to_port = {executor.submit(_worker, p): p for p in ports}

        for future in as_completed(future_to_port):
            if cancel_event.is_set():
                # Cancel remaining futures and drain
                for f in future_to_port:
                    f.cancel()
                break

            port = future_to_port[future]
            try:
                _, status = future.result()
            except Exception:
                status = STATUS_UNREACHABLE

            svc_name = services.service_name(port)
            results_map[port] = PortResult(port, status, svc_name, None)

            done_count += 1
            _render_progress(label, done_count, total, start_time)

    _clear_progress()

    # --- banner phase: sequential, only for open ports ---
    if grab_banners and not cancel_event.is_set():
        open_ports = [p for p, r in results_map.items() if r.status == STATUS_OPEN]
        for i, port in enumerate(open_ports, start=1):
            if cancel_event.is_set():
                break
            prefix = f"[{label}] " if label else ""
            if sys.stdout.isatty():
                print(
                    f"\r  {prefix}Grabbing banner {i}/{len(open_ports)}"
                    f" (port {port})...",
                    end="",
                    flush=True,
                )
            r = results_map[port]
            br = banner_mod.grab_banner(host, port, banner_timeout)
            results_map[port] = PortResult(port, r.status, r.service_name, br)
        _clear_progress()

    # Return results sorted by port number
    return [results_map[p] for p in sorted(results_map)]


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
            "  python defensivePortScanner.py --targets 192.168.1.10 --ports 1-1000 --concurrency 50\n"
            "  python defensivePortScanner.py --targets 192.168.1.0/28 --ports 22,80,443 --yes\n"
            "  python defensivePortScanner.py --targets-file hosts.txt --ports 1-1024 --host-concurrency 4\n"
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
        "--concurrency",
        dest="concurrency",
        default=DEFAULT_CONCURRENCY,
        type=validate_concurrency,
        metavar="N",
        help=(
            f"Number of ports to probe simultaneously per host "
            f"(default: {DEFAULT_CONCURRENCY}, max: {MAX_CONCURRENCY})."
        ),
    )
    parser.add_argument(
        "--host-concurrency",
        dest="host_concurrency",
        default=DEFAULT_HOST_CONCURRENCY,
        type=validate_concurrency,
        metavar="N",
        help=(
            f"Number of hosts to scan simultaneously (default: {DEFAULT_HOST_CONCURRENCY}). "
            "Increase with caution — each host uses up to --concurrency threads."
        ),
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
    # SIGINT handler — set cancel_event so workers finish cleanly
    # -------------------------------------------------------------------
    cancel_event = threading.Event()

    def _handle_sigint(signum, frame):
        print("\n  [!] Ctrl-C received — cancelling scan, please wait...")
        cancel_event.set()

    signal.signal(signal.SIGINT, _handle_sigint)

    # -------------------------------------------------------------------
    # Print concurrency info
    # -------------------------------------------------------------------
    print(f"  Concurrency    : {args.concurrency} ports/host", end="")
    if args.host_concurrency > 1:
        print(f",  {args.host_concurrency} hosts in parallel")
    else:
        print()
    print()

    # -------------------------------------------------------------------
    # Per-host scan function (called directly or via executor)
    # -------------------------------------------------------------------
    overall_started = datetime.now()
    total_open = total_closed = total_unreachable = 0
    results_lock = threading.Lock()

    def _scan_one_host(host_idx: int, rt: ResolvedTarget) -> None:
        nonlocal total_open, total_closed, total_unreachable

        if cancel_event.is_set():
            return

        # Rate-limit delay between hosts (only for sequential scanning;
        # with host_concurrency > 1 the executor handles parallelism).
        if host_idx > 0 and args.host_concurrency == 1 and args.rate_limit > 0:
            time.sleep(args.rate_limit)

        if len(resolved) > 1:
            print(
                f"  [{host_idx + 1}/{len(resolved)}] Scanning "
                f"{rt.display} ({rt.ip}) ..."
            )

        scan_started = datetime.now()

        try:
            results = scan_ports(
                rt.ip,
                ports,
                args.timeout,
                grab_banners,
                args.banner_timeout,
                concurrency=args.concurrency,
                label=rt.display if len(resolved) > 1 else "",
                cancel_event=cancel_event,
            )
        except socket.gaierror as exc:
            print(f"  [!] Skipping {rt.display}: {exc}")
            return

        scan_finished = datetime.now()

        # Serialise output so concurrent hosts don't interleave lines.
        with results_lock:
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

            # per-host report export
            if args.output:
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

    # -------------------------------------------------------------------
    # Execute: sequential or concurrent hosts
    # -------------------------------------------------------------------
    if args.host_concurrency == 1:
        for host_idx, rt in enumerate(resolved):
            if cancel_event.is_set():
                break
            _scan_one_host(host_idx, rt)
    else:
        with ThreadPoolExecutor(max_workers=args.host_concurrency) as host_executor:
            host_futures = [
                host_executor.submit(_scan_one_host, i, rt)
                for i, rt in enumerate(resolved)
            ]
            try:
                for f in as_completed(host_futures):
                    f.result()  # surface any unexpected exceptions
                    if cancel_event.is_set():
                        for hf in host_futures:
                            hf.cancel()
                        break
            except KeyboardInterrupt:
                cancel_event.set()

    # --- multi-target summary ---
    if len(resolved) > 1:
        overall_duration = (datetime.now() - overall_started).total_seconds()
        status_note = " (cancelled)" if cancel_event.is_set() else ""
        print(f"  {'=' * 54}")
        print(f"  Multi-target scan complete{status_note}")
        print(f"  Hosts scanned  : {len(resolved)}")
        print(f"  Total open     : {total_open}")
        print(f"  Total closed   : {total_closed}")
        print(f"  Total unreachable: {total_unreachable}")
        print(f"  Duration       : {overall_duration:.1f}s")
        print()


if __name__ == "__main__":
    main()

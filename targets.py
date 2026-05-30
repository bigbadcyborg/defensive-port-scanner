"""
targets.py — Target resolution for defensivePortScanner.

Handles all forms of target input and expands them into a deduplicated,
ordered list of (display_name, resolved_ip) pairs ready for scanning.

Supported input forms
---------------------
  Single host (CLI)    : --targets 192.168.1.10
  Multiple hosts (CLI) : --targets 192.168.1.10 192.168.1.20 webserver
  CIDR range           : --targets 192.168.1.0/24
  Targets file         : --targets-file hosts.txt
  Mixed                : --targets 10.0.0.1 192.168.1.0/28 --targets-file extra.txt

Target file format
------------------
  One entry per line. Entries may be:
    - IPv4 addresses         (192.168.1.1)
    - Hostnames              (myserver.local)
    - CIDR notation          (10.0.0.0/24)
  Lines starting with '#' are comments and are ignored.
  Blank lines are ignored.

Safety
------
  is_private(ip)     — True for RFC 1918 / loopback / link-local addresses
  is_public(ip)      — True for any address NOT in a known private range
  classify_targets() — returns counts of private vs. public hosts in a list

Public API
----------
  ResolvedTarget     — NamedTuple(display, ip)
  parse_target_args  — parse --targets and --targets-file into raw strings
  resolve_targets    — expand + resolve raw strings → list[ResolvedTarget]
  classify_targets   — count private/public in a resolved list
"""

import ipaddress
import socket
from pathlib import Path
from typing import NamedTuple

# ---------------------------------------------------------------------------
# Public types
# ---------------------------------------------------------------------------


class ResolvedTarget(NamedTuple):
    display: str  # Label shown in output (hostname or CIDR base address)
    ip: str  # Resolved IPv4 address string


# ---------------------------------------------------------------------------
# Private address space detection
# ---------------------------------------------------------------------------

# All address ranges considered "private" for warning purposes.
# Includes RFC 1918, loopback, link-local, and documentation ranges.
_PRIVATE_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),  # loopback
    ipaddress.ip_network("169.254.0.0/16"),  # link-local
    ipaddress.ip_network("100.64.0.0/10"),  # shared address (RFC 6598)
    ipaddress.ip_network("192.0.2.0/24"),  # TEST-NET-1 (RFC 5737)
    ipaddress.ip_network("198.51.100.0/24"),  # TEST-NET-2
    ipaddress.ip_network("203.0.113.0/24"),  # TEST-NET-3
]


def is_private(ip: str) -> bool:
    """Return True if *ip* falls within any known private/reserved range."""
    try:
        addr = ipaddress.ip_address(ip)
        return any(addr in net for net in _PRIVATE_NETWORKS)
    except ValueError:
        return False


def is_public(ip: str) -> bool:
    """Return True if *ip* is a routable public address."""
    return not is_private(ip)


# ---------------------------------------------------------------------------
# CIDR expansion
# ---------------------------------------------------------------------------

# Hard limit on CIDR expansion to prevent accidental /8 scans.
MAX_CIDR_HOSTS = 1024


def expand_cidr(cidr: str) -> list[str]:
    """
    Expand a CIDR notation string into a list of host IP strings.

    Network and broadcast addresses are excluded (standard host range).
    Raises ValueError if the CIDR is invalid or exceeds MAX_CIDR_HOSTS.
    """
    try:
        network = ipaddress.ip_network(cidr, strict=False)
    except ValueError as exc:
        raise ValueError(f"Invalid CIDR notation '{cidr}': {exc}") from exc

    # For /31 and /32 include all addresses (point-to-point / single host)
    if network.prefixlen >= 31:
        hosts = list(network.hosts()) or [network.network_address]
    else:
        hosts = list(network.hosts())

    if len(hosts) > MAX_CIDR_HOSTS:
        raise ValueError(
            f"CIDR '{cidr}' expands to {len(hosts)} hosts, which exceeds the "
            f"safety limit of {MAX_CIDR_HOSTS}. Split into smaller ranges or "
            f"use a prefix length of /{32 - (len(hosts) - 1).bit_length()} or smaller."
        )

    return [str(h) for h in hosts]


# ---------------------------------------------------------------------------
# Target file parser
# ---------------------------------------------------------------------------


def parse_targets_file(path: str) -> list[str]:
    """
    Read a targets file and return a list of raw target strings.

    File format: one entry per line; '#' starts a comment; blank lines ignored.
    Raises FileNotFoundError or PermissionError if the file cannot be read.
    """
    file = Path(path)
    if not file.exists():
        raise FileNotFoundError(f"Targets file not found: '{path}'")
    if not file.is_file():
        raise ValueError(f"Targets path is not a file: '{path}'")

    entries: list[str] = []
    for lineno, raw_line in enumerate(file.read_text(encoding="utf-8").splitlines(), 1):
        line = raw_line.split("#", 1)[0].strip()  # strip inline comments
        if not line:
            continue
        entries.append(line)

    return entries


# ---------------------------------------------------------------------------
# Single-target resolver
# ---------------------------------------------------------------------------


def _resolve_single(entry: str) -> list[ResolvedTarget]:
    """
    Resolve one raw entry (hostname, IP, or CIDR) into ResolvedTarget(s).
    Raises ValueError on bad input or socket.gaierror on DNS failure.
    """
    entry = entry.strip()
    if not entry:
        return []

    # CIDR block?
    if "/" in entry:
        ips = expand_cidr(entry)
        return [ResolvedTarget(display=ip, ip=ip) for ip in ips]

    # Plain IPv4?
    try:
        socket.inet_pton(socket.AF_INET, entry)
        return [ResolvedTarget(display=entry, ip=entry)]
    except (socket.error, OSError):
        pass

    # Hostname — resolve to IPv4
    try:
        ip = socket.gethostbyname(entry)
        return [ResolvedTarget(display=entry, ip=ip)]
    except socket.gaierror as exc:
        raise socket.gaierror(f"Could not resolve host '{entry}': {exc}") from exc


# ---------------------------------------------------------------------------
# Public resolver
# ---------------------------------------------------------------------------


def resolve_targets(raw_entries: list[str]) -> list[ResolvedTarget]:
    """
    Expand and resolve a list of raw target strings.

    - CIDR ranges are expanded to individual hosts.
    - Hostnames are resolved to IPv4 addresses.
    - Duplicate IPs are removed (first occurrence wins).
    - Original entry order is preserved after deduplication.

    Raises ValueError for invalid CIDR or bad hostnames.
    Raises socket.gaierror for DNS failures.
    """
    seen: set[str] = set()
    resolved: list[ResolvedTarget] = []

    for entry in raw_entries:
        for rt in _resolve_single(entry):
            if rt.ip not in seen:
                seen.add(rt.ip)
                resolved.append(rt)

    return resolved


# ---------------------------------------------------------------------------
# Safety classification
# ---------------------------------------------------------------------------


class TargetClassification(NamedTuple):
    total: int
    private: int
    public: int
    public_ips: list[str]  # list of public IP strings for display


def classify_targets(targets: list[ResolvedTarget]) -> TargetClassification:
    """
    Count private vs. public hosts in a resolved target list.
    Returns a TargetClassification with counts and the public IP list.
    """
    public_ips: list[str] = []
    private_count = 0

    for rt in targets:
        if is_public(rt.ip):
            public_ips.append(rt.ip)
        else:
            private_count += 1

    return TargetClassification(
        total=len(targets),
        private=private_count,
        public=len(public_ips),
        public_ips=public_ips,
    )

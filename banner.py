"""
banner.py — TCP service banner grabbing for defensivePortScanner.

Attempts to read the first bytes a service sends after a connection is
established (a "server-first" banner).  For protocols where the client
must speak first (e.g. HTTP), a minimal probe is sent and the response
is captured.

All results are tagged with a DetectionMethod so the caller can clearly
distinguish between:
  - DETECTED  : text actually received from the service
  - INFERRED  : nothing received; service name comes from the port table only
  - FAILED    : connection succeeded but banner read raised an error
"""

import socket
import ssl
from enum import Enum
from typing import NamedTuple

# ---------------------------------------------------------------------------
# Public types
# ---------------------------------------------------------------------------


class DetectionMethod(Enum):
    DETECTED = "detected"  # Banner text received from the service
    INFERRED = "inferred"  # Port-table lookup only; no live data
    FAILED = "failed"  # Open port but banner read failed / empty


class BannerResult(NamedTuple):
    raw: str  # Raw banner text (empty string when INFERRED/FAILED)
    method: DetectionMethod


# ---------------------------------------------------------------------------
# Probe definitions
# ---------------------------------------------------------------------------
# For "client-first" protocols we send a minimal probe and wait for a reply.
# The key is the port number; None means "wait — server speaks first".

_CLIENT_PROBES: dict[int, bytes] = {
    80: b"HEAD / HTTP/1.0\r\nHost: localhost\r\n\r\n",
    8080: b"HEAD / HTTP/1.0\r\nHost: localhost\r\n\r\n",
    8008: b"HEAD / HTTP/1.0\r\nHost: localhost\r\n\r\n",
    8443: b"HEAD / HTTP/1.0\r\nHost: localhost\r\n\r\n",
    3000: b"HEAD / HTTP/1.0\r\nHost: localhost\r\n\r\n",
    5000: b"HEAD / HTTP/1.0\r\nHost: localhost\r\n\r\n",
    8888: b"HEAD / HTTP/1.0\r\nHost: localhost\r\n\r\n",
}

# Ports that use TLS — we wrap the socket before reading.
_TLS_PORTS: frozenset[int] = frozenset(
    {
        443,
        465,
        636,
        993,
        995,
        989,
        990,
        8443,
        5671,
        5986,
        6697,
        2376,
        3269,
    }
)

_RECV_BYTES = 1024
_DEFAULT_BANNER_TIMEOUT = 2.0


# ---------------------------------------------------------------------------
# Banner grabber
# ---------------------------------------------------------------------------


def grab_banner(
    host: str,
    port: int,
    timeout: float = _DEFAULT_BANNER_TIMEOUT,
) -> BannerResult:
    """
    Connect to host:port and attempt to read a banner.

    Returns a BannerResult with:
      - raw  : printable single-line summary of what was received
      - method : DETECTED, INFERRED, or FAILED
    """
    try:
        raw_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        raw_sock.settimeout(timeout)
        raw_sock.connect((host, port))

        # Optionally wrap in TLS
        if port in _TLS_PORTS:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            sock = ctx.wrap_socket(raw_sock, server_hostname=host)
        else:
            sock = raw_sock

        # Send a probe if this is a client-first protocol
        probe = _CLIENT_PROBES.get(port)
        if probe:
            sock.sendall(probe)

        # Read the response
        data = sock.recv(_RECV_BYTES)
        sock.close()

        if data:
            text = _sanitize(data)
            return BannerResult(raw=text, method=DetectionMethod.DETECTED)
        else:
            return BannerResult(raw="", method=DetectionMethod.INFERRED)

    except (socket.timeout, TimeoutError):
        return BannerResult(raw="", method=DetectionMethod.INFERRED)
    except (ConnectionRefusedError, ConnectionResetError, OSError):
        return BannerResult(raw="", method=DetectionMethod.FAILED)
    except ssl.SSLError:
        # TLS negotiation failed — port is open but we can't read the banner
        return BannerResult(raw="", method=DetectionMethod.FAILED)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _sanitize(data: bytes) -> str:
    """
    Convert raw bytes to a clean, single-line printable string.
    - Decode as UTF-8 with replacement for non-UTF bytes
    - Strip leading/trailing whitespace
    - Collapse the result to the first non-empty line (≤ 120 chars)
    """
    text = data.decode("utf-8", errors="replace").strip()
    # Take only the first non-empty line
    for line in text.splitlines():
        line = line.strip()
        if line:
            return line[:120]
    return ""

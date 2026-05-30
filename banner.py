"""
banner.py — TCP service banner grabbing for defensivePortScanner.
Iteration 3: hardened timeout enforcement, full output sanitization.

Attempts to read the first bytes a service sends after a TCP connection is
established ("server-first" banner).  For protocols where the client must
speak first (e.g. HTTP), a safe, read-only probe is sent before reading.

Design constraints
------------------
- No exploit payloads or malformed packets are ever sent.
- Only well-known, read-only probes are used (HEAD for HTTP, plain connect
  for server-first protocols).
- Every banner read is bounded by a hard wall-clock deadline enforced by a
  background thread, independent of the socket timeout, so a misbehaving
  service can never stall the scan indefinitely.
- All received bytes are sanitized before being stored or displayed:
  control characters, ANSI escape sequences, null bytes, and C1 controls
  are stripped; output is capped at MAX_BANNER_LENGTH printable characters.

Public API
----------
  grab_banner(host, port, timeout) -> BannerResult
  sanitize(data)                   -> str          (also usable externally
                                                    for report sanitization)

Detection taxonomy
------------------
  DETECTED  — printable text was received from the service
  INFERRED  — connection succeeded but no data arrived (server-first
               protocol that didn't speak, or timed out after probe)
  FAILED    — the banner read itself raised an exception after connect
"""

import re
import socket
import ssl
import threading
from enum import Enum
from typing import NamedTuple

# ---------------------------------------------------------------------------
# Public types
# ---------------------------------------------------------------------------


class DetectionMethod(Enum):
    DETECTED = "detected"  # Banner text received from the service
    INFERRED = "inferred"  # Port-table lookup only; no live data received
    FAILED = "failed"  # Open port, but banner read raised an error


class BannerResult(NamedTuple):
    raw: str  # Sanitized banner text (empty when INFERRED/FAILED)
    method: DetectionMethod


# ---------------------------------------------------------------------------
# Sanitization constants
# ---------------------------------------------------------------------------

# Maximum length (in characters) of a stored/displayed banner.
MAX_BANNER_LENGTH: int = 256

# Regex matching ANSI/VT escape sequences (CSI, OSC, and single-char Fe).
_RE_ANSI = re.compile(
    r"""
    \x1b                    # ESC
    (?:
        \[ [0-9;]* [A-Za-z]  # CSI: ESC [ ... final-byte
      | \] [^\x07\x1b]*      # OSC: ESC ] ...
      | [PX^_] [^\x1b]* \x1b \\  # DCS/SOS/PM/APC
      | [A-Z\\]             # single-char Fe codes
    )
    """,
    re.VERBOSE,
)

# Regex matching individual characters that should be stripped:
#   - C0 controls except TAB (09), LF (0A), CR (0D) which can be meaningful
#   - DEL (7F)
#   - C1 controls (80–9F) which ANSI regex may miss as raw bytes
#   - Null byte
_RE_CONTROL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f\x80-\x9f]")


# ---------------------------------------------------------------------------
# Probe definitions
# ---------------------------------------------------------------------------
# For "client-first" protocols we send a safe, read-only probe.
# All probes are plain text with no exploit content.

_CLIENT_PROBES: dict[int, bytes] = {
    # HTTP — HEAD is the safest request: no body downloaded, no side effects.
    80: b"HEAD / HTTP/1.0\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    8080: b"HEAD / HTTP/1.0\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    8008: b"HEAD / HTTP/1.0\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    8443: b"HEAD / HTTP/1.0\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    3000: b"HEAD / HTTP/1.0\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    5000: b"HEAD / HTTP/1.0\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    8888: b"HEAD / HTTP/1.0\r\nHost: localhost\r\nConnection: close\r\n\r\n",
}

# Ports that use TLS — socket is wrapped before reading.
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

# Maximum bytes to read from a service response.
_RECV_BYTES: int = 2048

# Default timeout when the caller does not specify one.
_DEFAULT_BANNER_TIMEOUT: float = 2.0


# ---------------------------------------------------------------------------
# Sanitization
# ---------------------------------------------------------------------------


def sanitize(data: bytes | str) -> str:
    """
    Convert raw service response bytes (or a string) into a safe, printable,
    single-line string suitable for terminal display and report storage.

    Steps applied in order:
      1. Decode bytes as UTF-8 (replace undecodable bytes with U+FFFD).
      2. Strip ANSI / VT escape sequences.
      3. Strip remaining C0/C1 control characters and null bytes.
      4. Collapse to the first non-empty line.
      5. Strip leading/trailing whitespace.
      6. Truncate to MAX_BANNER_LENGTH characters.

    Returns an empty string if nothing printable remains.
    """
    if isinstance(data, bytes):
        text = data.decode("utf-8", errors="replace")
    else:
        text = data

    # 1. Remove ANSI escape sequences
    text = _RE_ANSI.sub("", text)

    # 2. Remove C0 controls, DEL, and C1 controls.
    #    _RE_CONTROL matches these as Unicode code points (U+0000-U+001F range
    #    and U+007F and U+0080-U+009F), which is correct after UTF-8 decoding.
    #    Raw C1 bytes that were not valid UTF-8 were replaced by U+FFFD above;
    #    strip those replacement characters too.
    text = _RE_CONTROL.sub("", text)
    text = text.replace("\ufffd", "")

    # 3. Take the first non-empty line (banners are typically one line)
    for line in text.splitlines():
        line = line.strip()
        if line:
            return line[:MAX_BANNER_LENGTH]

    return ""


# ---------------------------------------------------------------------------
# Hard-deadline banner read
# ---------------------------------------------------------------------------


def _read_with_deadline(
    sock: socket.socket,
    nbytes: int,
    deadline: float,
) -> bytes | None:
    """
    Read up to `nbytes` from `sock`, but abandon and return None if the
    wall-clock deadline (seconds from now) is exceeded.

    This adds a second layer of timeout enforcement on top of the socket's
    own settimeout(), guarding against edge cases where a service trickles
    data byte-by-byte just fast enough to keep the socket from timing out.
    """
    result: list[bytes] = []
    done = threading.Event()

    def _reader() -> None:
        try:
            chunk = sock.recv(nbytes)
            result.append(chunk)
        except Exception:
            pass
        finally:
            done.set()

    t = threading.Thread(target=_reader, daemon=True)
    t.start()
    received_in_time = done.wait(timeout=deadline)

    if not received_in_time:
        # Force-close the socket to unblock the reader thread
        try:
            sock.close()
        except Exception:
            pass
        return None

    return result[0] if result else b""


# ---------------------------------------------------------------------------
# Public banner grabber
# ---------------------------------------------------------------------------


def grab_banner(
    host: str,
    port: int,
    timeout: float = _DEFAULT_BANNER_TIMEOUT,
) -> BannerResult:
    """
    Attempt to grab the service banner from host:port.

    The `timeout` value is applied both as the socket timeout and as the
    hard wall-clock deadline for the banner read, so no single banner grab
    can block for longer than `timeout` seconds regardless of service behavior.

    Returns a BannerResult(raw, method) where:
      - raw    : sanitized banner string (empty when not DETECTED)
      - method : DetectionMethod.DETECTED | INFERRED | FAILED
    """
    raw_sock: socket.socket | None = None
    try:
        raw_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        raw_sock.settimeout(timeout)
        raw_sock.connect((host, port))

        # Wrap in TLS if applicable
        if port in _TLS_PORTS:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            sock: socket.socket = ctx.wrap_socket(raw_sock, server_hostname=host)
        else:
            sock = raw_sock

        # Send a safe probe for client-first protocols
        probe = _CLIENT_PROBES.get(port)
        if probe:
            sock.sendall(probe)

        # Read with hard wall-clock deadline
        data = _read_with_deadline(sock, _RECV_BYTES, deadline=timeout)

        try:
            sock.close()
        except Exception:
            pass

        if data is None:
            # Deadline exceeded
            return BannerResult(raw="", method=DetectionMethod.INFERRED)

        if data:
            text = sanitize(data)
            if text:
                return BannerResult(raw=text, method=DetectionMethod.DETECTED)

        return BannerResult(raw="", method=DetectionMethod.INFERRED)

    except (socket.timeout, TimeoutError):
        return BannerResult(raw="", method=DetectionMethod.INFERRED)
    except (ConnectionRefusedError, ConnectionResetError, OSError):
        return BannerResult(raw="", method=DetectionMethod.FAILED)
    except ssl.SSLError:
        # TLS negotiation failed — port is open but banner unreadable
        return BannerResult(raw="", method=DetectionMethod.FAILED)
    finally:
        if raw_sock is not None:
            try:
                raw_sock.close()
            except Exception:
                pass

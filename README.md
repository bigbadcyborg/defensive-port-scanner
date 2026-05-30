# Defensive Port Scanner

> **Current version: Iteration 2 — Service Identification**

A lightweight, dependency-free TCP port scanner written in Python.  
Built for **authorized, defensive security assessments only.**

---

## Description

This tool performs TCP connect scans against a target host to identify which ports are open, closed, or unreachable (filtered). It is designed as a transparent, readable reference implementation — no third-party libraries, no raw packet injection, no OS-level privilege requirements.

Each port is classified as:

| Status        | Meaning                                                          |
|---------------|------------------------------------------------------------------|
| `open`        | A service accepted the TCP connection                            |
| `closed`      | The host responded with a connection reset (port not listening)  |
| `unreachable` | The connection timed out — port may be filtered by a firewall    |

### Iteration 2 additions

- **Service identification** — every port is matched against a built-in lookup table (`services.py`) covering 80+ well-known TCP services
- **Banner grabbing** — for open ports, the scanner attempts to read the service's greeting or send a minimal probe (e.g. an HTTP `HEAD` request) and captures the response
- **Detection transparency** — the `DETECTION` column always tells you whether a service name was `detected` (live data received) or `inferred` (port-table lookup only)
- **`--no-banner`** flag to skip banner grabbing for fast scans
- **`--banner-timeout`** flag for independent banner read timeout control

---

## Requirements

- **Python 3.6+**
- No external dependencies — uses the Python standard library only (`socket`, `argparse`, `re`, `datetime`)

---

## Usage

```
python defensivePortScanner.py --target <HOST> --ports <PORTS> [OPTIONS]
```

### Arguments

| Argument           | Required | Description                                              | Default |
|--------------------|----------|----------------------------------------------------------|---------|
| `--target`         | Yes      | IPv4 address, IPv6 address, or hostname to scan          | —       |
| `--ports`          | Yes      | Comma-separated ports and/or ranges (see examples below) | —       |
| `--timeout`        | No       | TCP connect timeout per port in seconds                  | `1.0`   |
| `--no-banner`      | No       | Skip banner grabbing; show inferred service names only   | off     |
| `--banner-timeout` | No       | Timeout for each banner read in seconds                  | `2.0`   |

### Port Specification

| Format            | Expands to                   |
|-------------------|------------------------------|
| `22,80,443`       | ports 22, 80, 443            |
| `80-90`           | ports 80 through 90          |
| `22,80-85,443`    | ports 22, 80, 81, 82, 83, 84, 85, 443 |

Ranges are inclusive. Duplicate ports are deduplicated automatically. All ports must be in the range **1–65535**.

### Examples

```bash
# Scan three specific ports (banner grabbing on by default)
python defensivePortScanner.py --target 192.168.1.10 --ports 22,80,443

# Fast scan of the first 1024 ports — skip banner grabbing
python defensivePortScanner.py --target localhost --ports 1-1024 --timeout 0.5 --no-banner

# Mixed list with a range; give banner reads extra time
python defensivePortScanner.py --target example.com --ports 22,80-85,443 --banner-timeout 3.0

# Single port
python defensivePortScanner.py --target 10.0.0.1 --ports 3306
```

---

## Output

The scanner prints an ethical use banner at startup, followed by scan metadata, and a results table grouped by status (open → closed → unreachable).

```
╔══════════════════════════════════════════════════════════════╗
║           Defensive Port Scanner  —  Iteration 2            ║
║                                                              ║
║  ETHICAL USE ONLY. Scan only hosts you own or have explicit  ║
║  written permission to test. Unauthorized port scanning may  ║
║  be illegal and is strictly prohibited.                      ║
╚══════════════════════════════════════════════════════════════╝

  Target         : scanme.nmap.org (45.33.32.156)
  Ports          : 4 port(s)  [22-3306]
  Scan timeout   : 1.0s per port
  Banner timeout : 3.0s per port
  Started        : 2026-05-30 14:00:00

PORT       STATE          SERVICE         DETECTION    BANNER / INFO
---------  -------------  --------------  -----------  ------------------------------
22/tcp     open           SSH             detected     SSH-2.0-OpenSSH_6.6.1p1 Ubuntu-2ubuntu2.13
80/tcp     open           HTTP            detected     HTTP/1.1 200 OK

443/tcp    closed         HTTPS           inferred
3306/tcp   closed         MySQL           inferred

Scan complete: 2 open, 2 closed, 0 unreachable.
```

### Column reference

| Column        | Meaning                                                                          |
|---------------|----------------------------------------------------------------------------------|
| `PORT`        | Port number and protocol (always TCP)                                            |
| `STATE`       | `open`, `closed`, or `unreachable`                                               |
| `SERVICE`     | Service name from the local lookup table (`services.py`)                         |
| `DETECTION`   | `detected` = live banner received; `inferred` = port-table only; `failed` = error |
| `BANNER/INFO` | Raw first line received from the service, or the service description as a hint   |

Open ports are highlighted **green**, unreachable in **yellow**, closed in gray, and detected banners in **cyan**. Color is suppressed automatically when output is piped.

---

## Input Validation

The tool strictly validates all inputs before scanning:

- **Target**: Must be a valid IPv4 address, IPv6 address, or well-formed hostname. Empty strings, bare numbers, and malformed labels are rejected.
- **Ports**: Each token must be a positive integer or a valid range (`start-end`). Non-numeric values, out-of-range ports (< 1 or > 65535), and inverted ranges (e.g. `90-80`) are all rejected with a clear error message.
- **Timeout**: Must be a positive numeric value. Zero and negative values are rejected.

---

## Ethical Use Notice

> **This tool must only be used on hosts and networks you own or have explicit written authorization to test.**
>
> Unauthorized port scanning may violate local, national, and international laws including (but not limited to) the Computer Fraud and Abuse Act (CFAA) in the United States and equivalent legislation in other jurisdictions.
>
> The authors accept no responsibility for misuse of this software.

---

## Project Notes

### `Main.java` — Java Prototype

The file `Main.java` in this repository is an earlier prototype of the scanner written in Java. It served as the conceptual baseline for this Python iteration. The Python implementation (`defensivePortScanner.py`) is the primary, actively developed version. The Java file is retained for reference and is not modified by the Python tooling.

---

## Module structure

| File                      | Purpose                                                         |
|---------------------------|-----------------------------------------------------------------|
| `defensivePortScanner.py` | CLI entry point, scanning engine, output formatting             |
| `services.py`             | Local port → service name/description lookup table (80+ ports) |
| `banner.py`               | TCP banner grabbing with probe support and TLS handling         |
| `Main.java`               | Original Java prototype (retained for reference)                |

## Roadmap

Planned improvements for future iterations:

- [x] Service identification via local lookup table
- [x] Banner grabbing with inferred vs. detected distinction
- [ ] Concurrent scanning with `threading` or `asyncio` for large port ranges
- [ ] JSON / CSV output modes for integration with other tools
- [ ] `--output` flag to write results to a file
- [ ] UDP scan support
- [ ] Risk flagging for dangerous exposed services (e.g. Docker daemon, Telnet)

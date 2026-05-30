# Defensive Port Scanner

> **Current version: Iteration 5 — Multiple Target Support**

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

### Iteration 5 additions

- **`--targets`** — accepts one or more hosts, IPs, or CIDR ranges directly on the command line
- **`--targets-file`** — reads targets from a file (one per line; `#` comments supported)
- **CIDR expansion** — e.g. `192.168.1.0/28` expands to all 14 host addresses; hard limit of 1024 hosts per range
- **Public IP warning** — any public (non-RFC-1918) address triggers a mandatory `yes` confirmation that cannot be bypassed by `--yes`
- **Large-scan confirmation** — scanning more than 5 hosts asks for confirmation; skippable with `--yes` / `-y` for scripting
- **Rate limiting** — `--rate-limit` (default 0.5s) inserts a delay between hosts to avoid overwhelming networks
- **`targets.py`** — all target resolution, CIDR expansion, private/public detection, and safety classification logic

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

#### Target arguments (at least one required)

| Argument          | Required | Description                                                       |
|-------------------|----------|-------------------------------------------------------------------|
| `--targets`       | *        | One or more hosts, IPs, or CIDR ranges                            |
| `--targets-file`  | *        | Path to a file of targets, one per line (`#` = comment)           |

\* At least one of `--targets` or `--targets-file` must be provided.

#### Scan arguments

| Argument           | Required | Description                                              | Default |
|--------------------|----------|----------------------------------------------------------|---------|
| `--ports`          | Yes      | Comma-separated ports and/or ranges (see examples below) | —       |
| `--timeout`        | No       | TCP connect timeout per port in seconds                  | `1.0`   |
| `--banner`         | No       | Enable banner grabbing for open ports (opt-in)           | off     |
| `--banner-timeout` | No       | Timeout for each banner read in seconds                  | `2.0`   |
| `--rate-limit`     | No       | Delay between hosts in seconds (multi-target only)       | `0.5`   |

#### Safety arguments

| Argument | Description                                                                    |
|----------|--------------------------------------------------------------------------------|
| `--yes`, `-y` | Skip the large-scan (>5 hosts) confirmation prompt. Cannot suppress the public-IP warning. |

#### Output arguments

| Argument   | Description                                                                 | Default |
|------------|-----------------------------------------------------------------------------|---------|
| `--output` | Base name for report file(s). With multiple targets: `{stem}_{ip}.*`        | —       |
| `--format` | Report format(s): `json`, `csv`, `text`, `all`                              | `all`   |

### Port Specification

| Format            | Expands to                   |
|-------------------|------------------------------|
| `22,80,443`       | ports 22, 80, 443            |
| `80-90`           | ports 80 through 90          |
| `22,80-85,443`    | ports 22, 80, 81, 82, 83, 84, 85, 443 |

Ranges are inclusive. Duplicate ports are deduplicated automatically. All ports must be in the range **1–65535**.

### Examples

```bash
# Single host
python defensivePortScanner.py --targets 192.168.1.10 --ports 22,80,443

# Multiple hosts from the command line
python defensivePortScanner.py --targets 192.168.1.10 192.168.1.20 --ports 22,80,443

# CIDR range (expands to all host addresses)
python defensivePortScanner.py --targets 192.168.1.0/28 --ports 22,80,443 --yes

# Targets from a file
python defensivePortScanner.py --targets-file hosts.txt --ports 1-1024

# Mixed: inline + file, with banner grabbing, reports, and custom rate limit
python defensivePortScanner.py --targets 10.0.0.1 --targets-file extra.txt \
    --ports 22,80,443 --banner --rate-limit 1.0 --output results

# Skip large-scan confirmation (scripting use)
python defensivePortScanner.py --targets-file hosts.txt --ports 22,80 --yes
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
  Banner grabbing: enabled (timeout: 3.0s per port)
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
| `defensivePortScanner.py` | CLI entry point, scanning engine, output formatting                    |
| `targets.py`              | Target resolution, CIDR expansion, public/private detection            |
| `models.py`               | Shared `PortResult` class and port status constants                    |
| `services.py`             | Local port → service name/description lookup table (80+ ports)        |
| `banner.py`               | Banner grabbing, hard deadline enforcement, output sanitization        |
| `report.py`               | JSON, CSV, and text report writers; `ScanReport` dataclass             |
| `REPORT_SCHEMA.md`        | Full field-level schema reference for all report formats               |
| `Main.java`               | Original Java prototype (retained for reference)                       |

## Roadmap

Planned improvements for future iterations:

- [x] Service identification via local lookup table
- [x] Banner grabbing with inferred vs. detected distinction
- [x] Hard timeout enforcement and full output sanitization
- [x] JSON, CSV, and text report export (`--output`, `--format`)
- [x] Multiple targets, CIDR ranges, and target files
- [x] Public IP warnings and large-scan confirmation
- [x] Inter-host rate limiting
- [ ] Concurrent scanning with `threading` or `asyncio` for large port ranges
- [ ] UDP scan support
- [ ] Risk flagging for dangerous exposed services (e.g. Docker daemon, Telnet)

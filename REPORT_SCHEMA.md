# Report Schema Reference

Schema reference for all output formats produced by `report.py`.
Current schema version: **1.1** (added risk classification fields)

---

## JSON Report

The JSON file has three top-level keys: `schemaVersion`, `meta`, and `ports`.

### `meta` object

| Field | Type | Nullable | Description |
|---|---|---|---|
| `target` | `string` | No | Hostname or IP address as entered by the user |
| `resolvedIp` | `string` | No | IPv4 address the target hostname resolved to |
| `portsRequested` | `string` | No | Raw `--ports` argument passed to the scanner (e.g. `"1-1024"`, `"22,80,443"`) |
| `scanStarted` | `string` | No | ISO 8601 timestamp when the scan began (`datetime.isoformat()`) |
| `scanFinished` | `string` | No | ISO 8601 timestamp when the scan completed |
| `durationSeconds` | `number` | No | Elapsed wall-clock time in seconds, rounded to 2 decimal places |
| `scanTimeoutSeconds` | `number` | No | TCP connect timeout per port in seconds |
| `bannerGrabbing` | `boolean` | No | `true` when `--banner` was passed; `false` otherwise |
| `bannerTimeoutSeconds` | `number` | **Yes** | Per-port banner read timeout in seconds; `null` when `bannerGrabbing` is `false` |
| `riskAnalysis` | `boolean` | No | `true` when `--risk` was passed; `false` otherwise |
| `summary.total` | `integer` | No | Total number of ports scanned |
| `summary.open` | `integer` | No | Number of ports with state `open` |
| `summary.closed` | `integer` | No | Number of ports with state `closed` |
| `summary.unreachable` | `integer` | No | Number of ports with state `unreachable` |

### `ports` array — per-port objects

| Field | Type | Nullable | Description |
|---|---|---|---|
| `port` | `integer` | No | Port number (1–65535) |
| `protocol` | `string` | No | Always `"tcp"` |
| `state` | `string` | No | Connection result: `"open"`, `"closed"`, or `"unreachable"` (see Notes) |
| `service` | `string` | No | Service name from the local port-table lookup, or `"unknown"` |
| `detection` | `string` | No | How the service was identified (see Notes) |
| `banner` | `string` | **Yes** | Sanitized banner text received from the service; `null` when no text was received or banner grabbing was disabled |
| `risk` | `object` | **Yes** | Risk assessment object (see below); `null` when `--risk` was not passed or port is not open |
| `risk.level` | `string` | No | One of `info`, `low`, `medium`, `high`, `critical` |
| `risk.reason` | `string` | No | One sentence explaining why this level was assigned |
| `risk.recommendation` | `string` | No | One or two sentences of defensive guidance |

When `riskAnalysis` is `true`, a top-level `riskDisclaimer` string is also present.

### Example

```json
{
  "schemaVersion": "1.0",
  "meta": {
    "target": "192.168.1.10",
    "resolvedIp": "192.168.1.10",
    "portsRequested": "22,80,443",
    "scanStarted": "2026-05-30T14:00:00",
    "scanFinished": "2026-05-30T14:00:05",
    "durationSeconds": 5.0,
    "scanTimeoutSeconds": 1.0,
    "bannerGrabbing": true,
    "bannerTimeoutSeconds": 2.0,
    "summary": {
      "total": 3,
      "open": 1,
      "closed": 1,
      "unreachable": 1
    }
  },
  "ports": [
    {
      "port": 22,
      "protocol": "tcp",
      "state": "open",
      "service": "SSH",
      "detection": "detected",
      "banner": "SSH-2.0-OpenSSH_8.9p1"
    }
  ]
}
```

---

## CSV Report

One header row followed by one data row per scanned port.
Encoding: UTF-8. Line terminator: `\n`. Quoting follows RFC 4180 (only fields
containing commas, double-quotes, or newlines are quoted).

| Column | Type | Description |
|---|---|---|
| `port` | integer | Port number (1–65535) |
| `protocol` | string | Always `tcp` |
| `state` | string | `open`, `closed`, or `unreachable` |
| `service` | string | Service name from the port table, or `unknown` |
| `detection` | string | How the service was identified (see Notes) |
| `banner` | string | Sanitized banner text, or empty string when absent |
| `risk_level` | string | Risk level value (`info`/`low`/`medium`/`high`/`critical`), or empty for non-open ports / when `--risk` not used |
| `risk_reason` | string | Risk reason sentence, or empty |
| `risk_recommendation` | string | Defensive recommendation, or empty |
| `scan_target` | string | Hostname or IP as entered by the user (repeated on every row) |
| `resolved_ip` | string | IPv4 address the target resolved to (repeated on every row) |
| `scan_started` | string | ISO 8601 start timestamp (repeated on every row) |

`scan_target`, `resolved_ip`, and `scan_started` are repeated on every row so
that individual rows remain self-contained when the file is filtered or split.

---

## Text Report

Plain UTF-8, no ANSI colour codes. Suitable for archiving or sharing via email.

### Header section

Key–value pairs describing the scan parameters and timing:

```
Defensive Port Scanner — Report
================================
Generated  : <scan_finished>
Target     : <target>
Resolved IP: <resolved_ip>
Ports      : <ports_requested>
Started    : <scan_started>
Finished   : <scan_finished>
Duration   : <duration>
Timeout    : <timeout> per port
Banners    : enabled (timeout: <banner_timeout>s) | disabled
Risk       : enabled | disabled
```

### Results table

Fixed-width columns with a header row and separator. One row per port, sorted
in scan order (as returned by the scanner). Column widths:

| Column | Width | Notes |
|---|---|---|
| `PORT` | 9 | Formatted as `{port}/tcp`, e.g. `22/tcp` |
| `STATE` | 13 | `open`, `closed`, or `unreachable` |
| `SERVICE` | 14 | Port-table service name |
| `DETECTION` | 11 | Detection method (see Notes) |
| `BANNER` | — | Remainder of line; omitted (trailing whitespace stripped) when empty |

### Risk Assessment section

Present only when `--risk` was passed and at least one open port was found.

```
Risk Assessment
----------------------------------------------------------------------
  <port>/tcp  <service>  [<LEVEL>]
  Reason         : <reason>
  Recommendation : <recommendation (word-wrapped at 72 chars)>

* <disclaimer>
```

### Summary section

```
Summary
-------
Total ports scanned : <total>
Open                : <open>
Closed              : <closed>
Unreachable         : <unreachable>
```

---

## Notes

### State values

| Value | Meaning |
|---|---|
| `open` | TCP connect succeeded (port accepted the connection) |
| `closed` | TCP connect was actively refused by the host |
| `unreachable` | No response within the timeout; host may be down or port filtered |

### Detection values

| Value | Meaning |
|---|---|
| `detected` | Banner text was received from the service over the live connection |
| `inferred` | Service name was looked up from the local port table only; no live data |
| `failed` | Port was open but the banner read raised an error (e.g. TLS failure) |

`inferred` is used for all closed and unreachable ports, for all ports when
`--banner` is not passed, and for open ports where the service sent no data.

### Risk level values

| Value | Meaning |
|---|---|
| `info` | Expected or normal service; no action needed |
| `low` | Noteworthy; worth monitoring |
| `medium` | Review recommended |
| `high` | Prompt action recommended |
| `critical` | Should not be exposed; remediate immediately |

Risk levels are assigned by port convention and optional banner context.
**No vulnerability is confirmed.** Always verify findings manually.

### Schema versioning

The JSON `schemaVersion` field is `"1.1"` as of Iteration 7 (risk fields added).
If the structure changes in a backwards-incompatible way in a future iteration,
this value will be incremented. Consumers should check this field before parsing.

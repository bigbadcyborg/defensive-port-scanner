"""
config.py — Configuration file support for defensivePortScanner.

Loads scan parameters from a YAML or JSON file and merges them with
parsed CLI arguments so that:

    CLI argument  >  config file value  >  built-in default

Supported formats
-----------------
  YAML (.yaml, .yml)   Requires PyYAML (pip install pyyaml).
                       Provides a helpful error if PyYAML is missing.
  JSON (.json)         Always available (Python stdlib json module).
  TOML (.toml)         Requires Python 3.11+ (stdlib tomllib) or
                       the tomli back-port (pip install tomli).

Config file keys
----------------
  scanName            str   — Human-readable label; printed in scan header.
  targets             list  — One or more IPv4 addresses, hostnames, or CIDRs.
  targetsFile         str   — Path to a targets file (same format as --targets-file).
  ports               str   — Port specification, e.g. "1-1024" or "22,80,443".
  timeoutSeconds      float — TCP connect timeout per port.
  concurrency         int   — Simultaneous port probes per host.
  hostConcurrency     int   — Simultaneous hosts to scan.
  bannerGrab          bool  — Enable service banner grabbing.
  bannerTimeoutSeconds float — Timeout for banner reads.
  riskAnalysis        bool  — Enable exposure risk classification.
  rateLimit           float — Inter-host delay in seconds.
  skipConfirm         bool  — Skip large-scan confirmation prompt.
  output              str   — Output file stem for reports.
  outputFormat        list  — Report format(s): json, csv, text, all.

Merge rules
-----------
  A key in the config file only takes effect if the corresponding CLI
  argument was NOT explicitly provided on the command line.  CLI always wins.

  Detection strategy: after argparse runs, any argument that still holds its
  sentinel value (argparse.SUPPRESS or the registered default) is considered
  "not set by the user".  We compare against the parser's known defaults to
  determine which args the user explicitly supplied.

Public API
----------
  load_config(path)               -> dict
  validate_config(cfg, path)      -> None          (raises ConfigError)
  apply_config(cfg, args, parser) -> argparse.Namespace
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


class ConfigError(Exception):
    """Raised for config file format or validation failures."""


# ---------------------------------------------------------------------------
# Loader
# ---------------------------------------------------------------------------

_YAML_EXTENSIONS = {".yaml", ".yml"}
_JSON_EXTENSIONS = {".json"}
_TOML_EXTENSIONS = {".toml"}


def load_config(path: str) -> dict[str, Any]:
    """
    Load a config file and return its contents as a plain dict.

    Supports YAML, JSON, and TOML based on file extension.
    Raises ConfigError for format errors or missing optional dependencies.
    Raises FileNotFoundError if the file does not exist.
    """
    file = Path(path)
    if not file.exists():
        raise FileNotFoundError(f"Config file not found: '{path}'")
    if not file.is_file():
        raise ConfigError(f"Config path is not a file: '{path}'")

    ext = file.suffix.lower()
    raw = file.read_text(encoding="utf-8")

    if ext in _YAML_EXTENSIONS:
        return _load_yaml(raw, path)
    elif ext in _JSON_EXTENSIONS:
        return _load_json(raw, path)
    elif ext in _TOML_EXTENSIONS:
        return _load_toml(raw, path)
    else:
        raise ConfigError(
            f"Unrecognised config file extension '{ext}'. "
            "Supported formats: .yaml, .yml, .json, .toml"
        )


def _load_yaml(raw: str, path: str) -> dict[str, Any]:
    try:
        import yaml  # type: ignore[import]
    except ImportError:
        raise ConfigError(
            f"Cannot load YAML config '{path}': PyYAML is not installed.\n"
            "  Install it with:  pip install pyyaml\n"
            "  Or convert your config to JSON format."
        ) from None
    try:
        data = yaml.safe_load(raw)
    except yaml.YAMLError as exc:
        raise ConfigError(f"YAML parse error in '{path}': {exc}") from exc
    if data is None:
        return {}
    if not isinstance(data, dict):
        raise ConfigError(
            f"Config file '{path}' must contain a YAML mapping at the top level, "
            f"got {type(data).__name__}."
        )
    return data


def _load_json(raw: str, path: str) -> dict[str, Any]:
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ConfigError(f"JSON parse error in '{path}': {exc}") from exc
    if not isinstance(data, dict):
        raise ConfigError(
            f"Config file '{path}' must contain a JSON object at the top level."
        )
    # Strip comment-style keys (starting with '_') used in sample files.
    return {k: v for k, v in data.items() if not k.startswith("_")}


def _load_toml(raw: str, path: str) -> dict[str, Any]:
    try:
        # Python 3.11+
        import tomllib  # type: ignore[import]

        return tomllib.loads(raw)
    except ImportError:
        pass
    try:
        import tomli  # type: ignore[import]

        return tomli.loads(raw)
    except ImportError:
        raise ConfigError(
            f"Cannot load TOML config '{path}': tomllib (Python 3.11+) or the "
            "'tomli' package is required.\n"
            "  Install the back-port with:  pip install tomli\n"
            "  Or convert your config to JSON format."
        ) from None


# ---------------------------------------------------------------------------
# Validator
# ---------------------------------------------------------------------------

# Schema: key → (expected Python type(s), nullable, description)
_SCHEMA: dict[str, tuple[tuple[type, ...], bool, str]] = {
    "scanName": ((str,), True, "string scan label"),
    "targets": ((list,), True, "list of target strings"),
    "targetsFile": ((str,), True, "path to a targets file"),
    "ports": ((str,), True, "port specification string"),
    "timeoutSeconds": ((float, int), True, "positive number"),
    "concurrency": ((int,), True, "positive integer"),
    "hostConcurrency": ((int,), True, "positive integer"),
    "bannerGrab": ((bool,), True, "true or false"),
    "bannerTimeoutSeconds": ((float, int), True, "positive number"),
    "riskAnalysis": ((bool,), True, "true or false"),
    "rateLimit": ((float, int), True, "non-negative number"),
    "skipConfirm": ((bool,), True, "true or false"),
    "output": ((str,), True, "report output file stem"),
    "outputFormat": ((list, str), True, "format string or list of format strings"),
    "monitorIntervalSeconds": ((float, int), True, "scan interval in seconds"),
    "monitorRuns": ((int,), True, "number of scheduled runs (0 = infinite)"),
    "historyDir": ((str,), True, "directory for monitoring history and alerts"),
    "scanProfile": ((str,), True, "defensive scan profile label"),
}

_VALID_OUTPUT_FORMATS = {"json", "csv", "text", "all"}


def validate_config(cfg: dict[str, Any], path: str) -> None:
    """
    Validate config dict structure and value types.
    Raises ConfigError with a descriptive message on the first problem found.
    """
    # Unknown keys
    unknown = set(cfg) - set(_SCHEMA)
    if unknown:
        raise ConfigError(
            f"Config file '{path}' contains unrecognised key(s): "
            + ", ".join(f"'{k}'" for k in sorted(unknown))
            + f"\n  Valid keys: {', '.join(sorted(_SCHEMA))}"
        )

    for key, value in cfg.items():
        expected_types, nullable, desc = _SCHEMA[key]
        if value is None:
            if not nullable:
                raise ConfigError(f"Config key '{key}' in '{path}' cannot be null.")
            continue
        if not isinstance(value, expected_types):
            # YAML parses bare true/false as bool; int is a subclass of bool
            # in Python — guard against that for numeric fields.
            if isinstance(value, bool) and bool not in expected_types:
                raise ConfigError(
                    f"Config key '{key}' in '{path}' must be a {desc}, got boolean."
                )
            if not isinstance(value, expected_types):
                type_names = " or ".join(t.__name__ for t in expected_types)
                raise ConfigError(
                    f"Config key '{key}' in '{path}' must be a {desc} "
                    f"({type_names}), got {type(value).__name__}."
                )

    # Numeric bounds
    if "timeoutSeconds" in cfg and cfg["timeoutSeconds"] is not None:
        if cfg["timeoutSeconds"] <= 0:
            raise ConfigError(
                f"Config key 'timeoutSeconds' in '{path}' must be > 0, "
                f"got {cfg['timeoutSeconds']}."
            )
    if "bannerTimeoutSeconds" in cfg and cfg["bannerTimeoutSeconds"] is not None:
        if cfg["bannerTimeoutSeconds"] <= 0:
            raise ConfigError(
                f"Config key 'bannerTimeoutSeconds' in '{path}' must be > 0, "
                f"got {cfg['bannerTimeoutSeconds']}."
            )
    if "rateLimit" in cfg and cfg["rateLimit"] is not None:
        if cfg["rateLimit"] < 0:
            raise ConfigError(
                f"Config key 'rateLimit' in '{path}' must be >= 0, "
                f"got {cfg['rateLimit']}."
            )
    if "concurrency" in cfg and cfg["concurrency"] is not None:
        if cfg["concurrency"] < 1:
            raise ConfigError(
                f"Config key 'concurrency' in '{path}' must be >= 1, "
                f"got {cfg['concurrency']}."
            )
        from defensivePortScanner import MAX_CONCURRENCY

        if cfg["concurrency"] > MAX_CONCURRENCY:
            raise ConfigError(
                f"Config key 'concurrency' in '{path}' exceeds the safety cap "
                f"of {MAX_CONCURRENCY} (got {cfg['concurrency']})."
            )
    if "hostConcurrency" in cfg and cfg["hostConcurrency"] is not None:
        if cfg["hostConcurrency"] < 1:
            raise ConfigError(
                f"Config key 'hostConcurrency' in '{path}' must be >= 1, "
                f"got {cfg['hostConcurrency']}."
            )
        from defensivePortScanner import MAX_CONCURRENCY

        if cfg["hostConcurrency"] > MAX_CONCURRENCY:
            raise ConfigError(
                f"Config key 'hostConcurrency' in '{path}' exceeds the safety "
                f"cap of {MAX_CONCURRENCY}."
            )

    if "monitorIntervalSeconds" in cfg and cfg["monitorIntervalSeconds"] is not None:
        if cfg["monitorIntervalSeconds"] <= 0:
            raise ConfigError(
                f"Config key 'monitorIntervalSeconds' in '{path}' must be > 0, "
                f"got {cfg['monitorIntervalSeconds']}."
            )

    if "monitorRuns" in cfg and cfg["monitorRuns"] is not None:
        if cfg["monitorRuns"] < 0:
            raise ConfigError(
                f"Config key 'monitorRuns' in '{path}' must be >= 0 (0 means infinite), "
                f"got {cfg['monitorRuns']}."
            )

    # targets must be a list of strings
    if "targets" in cfg and cfg["targets"] is not None:
        if not all(isinstance(t, str) for t in cfg["targets"]):
            raise ConfigError(
                f"Config key 'targets' in '{path}' must be a list of strings."
            )

    # outputFormat: each value must be a valid format string
    if "outputFormat" in cfg and cfg["outputFormat"] is not None:
        fmt_val = cfg["outputFormat"]
        if isinstance(fmt_val, str):
            fmt_val = [fmt_val]
        for fmt in fmt_val:
            if not isinstance(fmt, str):
                raise ConfigError(
                    f"Config key 'outputFormat' in '{path}': each entry must be "
                    f"a string, got {type(fmt).__name__}."
                )
            if fmt not in _VALID_OUTPUT_FORMATS:
                raise ConfigError(
                    f"Config key 'outputFormat' in '{path}': '{fmt}' is not a "
                    f"valid format. Valid values: {', '.join(sorted(_VALID_OUTPUT_FORMATS))}."
                )


# ---------------------------------------------------------------------------
# Merger
# ---------------------------------------------------------------------------

# Maps config file key → argparse dest name
_KEY_TO_DEST: dict[str, str] = {
    "targets": "targets",
    "targetsFile": "targets_file",
    "ports": "ports",
    "timeoutSeconds": "timeout",
    "concurrency": "concurrency",
    "hostConcurrency": "host_concurrency",
    "bannerGrab": "banner",
    "bannerTimeoutSeconds": "banner_timeout",
    "riskAnalysis": "risk",
    "rateLimit": "rate_limit",
    "skipConfirm": "yes",
    "output": "output",
    "outputFormat": "formats",
    "monitorIntervalSeconds": "monitor_interval",
    "monitorRuns": "monitor_runs",
    "historyDir": "history_dir",
    "scanProfile": "scan_profile",
}


def apply_config(
    cfg: dict[str, Any],
    args: argparse.Namespace,
    parser: argparse.ArgumentParser,
    cli_argv: list[str] | None = None,
) -> argparse.Namespace:
    """
    Merge config file values into an already-parsed argparse Namespace.

    CLI arguments win over config file values.  A CLI argument is
    considered "explicitly set" when its value differs from the parser's
    registered default for that dest — except for boolean store_true flags,
    which are considered set when True (the user passed them) and unset
    when False (the default).

    Returns the (mutated) Namespace.

    Parameters
    ----------
    cfg:
        Validated config dict from load_config() / validate_config().
    args:
        Namespace returned by parser.parse_args().
    parser:
        The ArgumentParser used to produce args (needed to read defaults).
    cli_argv:
        The raw sys.argv[1:] list, used to precisely detect which flags
        were explicitly supplied.  Defaults to sys.argv[1:] when None.
    """
    if cli_argv is None:
        cli_argv = sys.argv[1:]

    # Build a set of dest names that appeared explicitly on the command line.
    # We do this by re-parsing with parse_known_args and comparing; the more
    # reliable approach is to inspect the raw argv for flag names.
    explicit_dests: set[str] = _find_explicit_cli_dests(parser, cli_argv)

    # Walk each config key and apply it if the dest was not set on CLI.
    for cfg_key, dest in _KEY_TO_DEST.items():
        if cfg_key not in cfg or cfg[cfg_key] is None:
            continue
        if dest in explicit_dests:
            continue  # CLI wins

        value = cfg[cfg_key]

        # Type coercions
        if dest == "timeout":
            value = float(value)
        elif dest == "banner_timeout":
            value = float(value)
        elif dest == "rate_limit":
            value = float(value)
        elif dest == "concurrency":
            value = int(value)
        elif dest == "host_concurrency":
            value = int(value)
        elif dest == "monitor_interval":
            value = float(value)
        elif dest == "monitor_runs":
            value = int(value)
        elif dest == "formats":
            # normalise to a list
            if isinstance(value, str):
                value = [value]

        setattr(args, dest, value)

    # Carry scanName through as a plain attribute (no CLI equivalent).
    if "scanName" in cfg and cfg["scanName"]:
        args.scan_name = str(cfg["scanName"])
    elif not hasattr(args, "scan_name"):
        args.scan_name = None

    return args


def _find_explicit_cli_dests(
    parser: argparse.ArgumentParser,
    cli_argv: list[str],
) -> set[str]:
    """
    Return the set of argparse dest names that were *explicitly* provided
    on the command line (i.e. appeared in cli_argv as a flag or positional).

    Strategy: compare the namespace produced by parsing cli_argv against
    a namespace built from defaults only.  Any dest whose value differs
    was explicitly set.  Boolean store_true flags are considered explicit
    when True.
    """
    # Build defaults-only namespace
    defaults_ns = argparse.Namespace(
        **{
            action.dest: action.default
            for action in parser._actions
            if action.dest != argparse.SUPPRESS
        }
    )

    # Parse cli_argv (use parse_known_args to avoid errors from --config)
    try:
        parsed_ns, _ = parser.parse_known_args(cli_argv)
    except SystemExit:
        return set()

    explicit: set[str] = set()
    for dest in vars(defaults_ns):
        default_val = getattr(defaults_ns, dest)
        parsed_val = getattr(parsed_ns, dest, default_val)
        if parsed_val != default_val:
            explicit.add(dest)
        # store_true flags: explicit when True regardless of default
        elif isinstance(parsed_val, bool) and parsed_val is True:
            explicit.add(dest)

    return explicit

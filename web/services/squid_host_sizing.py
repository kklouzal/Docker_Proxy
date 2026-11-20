"""Host resource sizing overlay for the proxy's effective squid.conf.

Contract (see README "Host resource sizing"):

* Config revisions in the control-plane database are the Admin UI's saved
  desired state for a proxy. A proxy container can pin its own resource
  sizing through these environment variables; when one is set to a valid
  value it is authoritative over the revision for the directive(s) it owns:

  ``SQUID_WORKERS``                    ``workers N``
  ``SQUID_CACHE_MEM_MB``               ``cache_mem N MB``
  ``SQUID_CACHE_DIR_MB``               size field of every ``cache_dir`` line
  ``SQUID_SSLCRTD_CHILDREN``           ``sslcrtd_children N`` (startup/idle
                                       capped at N, other options kept)
  ``SQUID_DYNAMIC_CERT_MEM_CACHE_MB``  ``dynamic_cert_mem_cache_size=NMB`` on
                                       every certificate-generating
                                       ``http_port``/``https_port``
  ``SQUID_MAX_FILEDESCRIPTORS``        ``max_filedescriptors N``

* Unset variables leave the revision unchanged. Set but non-integer or
  out-of-range values are ignored with a warning.
* The proxy entrypoint validates the operator's variables once, before it
  derives its own defaults into the same names, and exports the accepted set
  as ``SQUID_HOST_SIZING_OVERRIDES`` (``NAME=VALUE`` pairs, canonical order).
  Every proxy process reads only that variable, so later in-process
  environment updates (for example ``SQUID_WORKERS`` after an apply) are never
  mistaken for operator overrides, and processes without it (the admin UI)
  apply no overlay.
* The overlay runs inside ``SquidController.normalize_config_text``, i.e.
  wherever the proxy renders, validates, applies, persists (last-known-good),
  rolls back or compares squid.conf. It is idempotent, so
  ``current_config_sha`` is the SHA-256 of the effective file and equals the
  SHA-256 of the normalized+overlaid active revision once reconciled; the
  revision's own SHA stays its database identity.
* A directive the overlay owns but the revision lacks is appended, except
  ``cache_dir`` (the overlay never invents a disk cache) and ports that do not
  generate certificates.
"""

from __future__ import annotations

import functools
import logging
import os
import pathlib
import re
import sys
from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Mapping

logger = logging.getLogger(__name__)

OVERRIDES_ENV = "SQUID_HOST_SIZING_OVERRIDES"


@dataclass(frozen=True)
class HostSizingSetting:
    env: str
    directive: str
    minimum: int
    maximum: int
    unit: str = ""


SETTINGS: tuple[HostSizingSetting, ...] = (
    # The proxy's ICAP/helper layout supports at most four Squid workers.
    HostSizingSetting("SQUID_WORKERS", "workers", 1, 4),
    HostSizingSetting("SQUID_CACHE_MEM_MB", "cache_mem", 0, 1_048_576, " MB"),
    HostSizingSetting("SQUID_CACHE_DIR_MB", "cache_dir", 1, 16_777_216, " MB"),
    HostSizingSetting("SQUID_SSLCRTD_CHILDREN", "sslcrtd_children", 1, 64),
    HostSizingSetting(
        "SQUID_DYNAMIC_CERT_MEM_CACHE_MB",
        "dynamic_cert_mem_cache_size",
        0,
        4096,
        " MB",
    ),
    HostSizingSetting(
        "SQUID_MAX_FILEDESCRIPTORS",
        "max_filedescriptors",
        1024,
        1_048_576,
    ),
)
_SETTINGS_BY_ENV = {setting.env: setting for setting in SETTINGS}
_DIGITS_RE = re.compile(r"[0-9]{1,12}")
_SSLCRTD_DEFAULT_OPTIONS = (("startup", 2), ("idle", 1), ("queue-size", 32))
_DYNAMIC_CERT_RE = re.compile(r"dynamic_cert_mem_cache_size=[^\s\\]*")


def _bounded_int(setting: HostSizingSetting, raw: str) -> tuple[int | None, str]:
    value = raw.strip()
    if not _DIGITS_RE.fullmatch(value):
        return None, (
            f"{setting.env}={raw!r} is not a non-negative integer; "
            "ignoring it and keeping the config revision value."
        )
    parsed = int(value)
    if not setting.minimum <= parsed <= setting.maximum:
        return None, (
            f"{setting.env}={parsed} is outside {setting.minimum}..{setting.maximum}; "
            "ignoring it and keeping the config revision value."
        )
    return parsed, ""


def parse_host_sizing(environ: Mapping[str, str]) -> tuple[dict[str, int], list[str]]:
    """Validate operator sizing variables; return accepted values and warnings."""
    overrides: dict[str, int] = {}
    warnings: list[str] = []
    for setting in SETTINGS:
        raw = environ.get(setting.env)
        if raw is None or not raw.strip():
            continue
        value, warning = _bounded_int(setting, raw)
        if value is None:
            warnings.append(warning)
        else:
            overrides[setting.env] = value
    return overrides, warnings


def encode_overrides(overrides: Mapping[str, int]) -> str:
    return " ".join(
        f"{setting.env}={overrides[setting.env]}"
        for setting in SETTINGS
        if setting.env in overrides
    )


@functools.lru_cache(maxsize=8)
def decode_overrides(encoded: str) -> Mapping[str, int]:
    """Decode the entrypoint-exported override set (validated again)."""
    pairs: dict[str, str] = {}
    for token in (encoded or "").split():
        name, sep, value = token.partition("=")
        if not sep or name not in _SETTINGS_BY_ENV:
            logger.warning("Ignoring malformed %s entry %r", OVERRIDES_ENV, token)
            continue
        pairs[name] = value
    overrides, warnings = parse_host_sizing(pairs)
    for warning in warnings:
        logger.warning("%s: %s", OVERRIDES_ENV, warning)
    return dict(overrides)


def active_overrides(environ: Mapping[str, str] | None = None) -> Mapping[str, int]:
    source = os.environ if environ is None else environ
    return decode_overrides(str(source.get(OVERRIDES_ENV) or "").strip())


def describe_overrides(overrides: Mapping[str, int]) -> list[dict[str, str]]:
    """Operator-facing summary of directives pinned by this host's environment."""
    return [
        {
            "env": setting.env,
            "directive": setting.directive,
            "value": f"{overrides[setting.env]}{setting.unit}",
        }
        for setting in SETTINGS
        if setting.env in overrides
    ]


def _is_skipped_line(line: str) -> bool:
    """Squid skips blank and comment lines, even inside a continued directive."""
    stripped = line.strip()
    return not stripped or stripped.startswith("#")


def _continues(line: str) -> bool:
    # Squid continues a directive only when the backslash is the last
    # character of the physical line (after CR/LF removal).
    return line.rstrip("\r").endswith("\\")


def _logical_groups(lines: list[str]) -> list[tuple[int, int]]:
    """Return [start, end) physical-line ranges of logical squid.conf lines.

    Mirrors Squid's parseOneConfigFile(): a non-comment line ending in a
    backslash continues onto the next non-blank, non-comment line; skipped
    lines between the parts belong to the same range.
    """
    groups: list[tuple[int, int]] = []
    start = 0
    continuing = False
    for index, line in enumerate(lines):
        if _is_skipped_line(line):
            if not continuing:
                groups.append((index, index + 1))
                start = index + 1
            continue
        if _continues(line):
            continuing = True
            continue
        groups.append((start, index + 1))
        start = index + 1
        continuing = False
    if start < len(lines):
        groups.append((start, len(lines)))
    return groups


def _logical_tokens(lines: list[str], start: int, end: int) -> list[str]:
    """Tokens of one logical line, joined the way Squid joins continuations."""
    joined = ""
    for line in lines[start:end]:
        if _is_skipped_line(line):
            continue
        part = line.rstrip("\r").lstrip()
        if _continues(part):
            part = part[:-1]
        joined += part
    return joined.split()


def _skipped_lines(lines: list[str], start: int, end: int) -> list[str]:
    return [line for line in lines[start:end] if _is_skipped_line(line)]


def _sslcrtd_children_value(children: int, current_tokens: list[str]) -> str:
    options: dict[str, str] = {}
    order: list[str] = []
    for token in current_tokens:
        key, sep, value = token.partition("=")
        if not sep:
            continue
        lowered = key.lower()
        if lowered not in options:
            order.append(lowered)
        options[lowered] = value
    rendered: list[str] = [str(children)]
    for key, default in _SSLCRTD_DEFAULT_OPTIONS:
        raw = options.get(key, "")
        value = int(raw) if raw.isdigit() else default
        if key in {"startup", "idle"}:
            # Squid caps these at the child maximum and warns on every parse.
            value = min(value, children)
        rendered.append(f"{key}={value}")
    known = {key for key, _default in _SSLCRTD_DEFAULT_OPTIONS}
    rendered.extend(f"{key}={options[key]}" for key in order if key not in known)
    return " ".join(rendered)


def _generates_certificates(tokens: list[str]) -> bool:
    """Whether Squid generates host certificates on this port (last option wins)."""
    options = tokens[2:]
    # Squid generates host certificates on ssl-bump ports unless disabled.
    enabled = "ssl-bump" in options
    for option in options:
        if option in {"generate-host-certificates", "generate-host-certificates=on"}:
            enabled = True
        elif option == "generate-host-certificates=off":
            enabled = False
    return enabled


def _replace_value(line: str, directive: str, value: str) -> str:
    match = re.match(rf"^(\s*{re.escape(directive)}\s+)", line, re.IGNORECASE)
    if match is None:
        return line
    return match.group(1) + value


def apply_host_sizing(config_text: str, overrides: Mapping[str, int]) -> str:
    """Return ``config_text`` with the host-owned directives pinned (idempotent)."""
    if not overrides or not (config_text or "").strip():
        return config_text
    lines = config_text.split("\n")
    trailing_newline = config_text.endswith("\n")
    if trailing_newline:
        lines.pop()
    simple: dict[str, str] = {}
    if "SQUID_WORKERS" in overrides:
        simple["workers"] = str(overrides["SQUID_WORKERS"])
    if "SQUID_CACHE_MEM_MB" in overrides:
        simple["cache_mem"] = f"{overrides['SQUID_CACHE_MEM_MB']} MB"
    if "SQUID_MAX_FILEDESCRIPTORS" in overrides:
        simple["max_filedescriptors"] = str(overrides["SQUID_MAX_FILEDESCRIPTORS"])
    children = overrides.get("SQUID_SSLCRTD_CHILDREN")
    cache_dir_mb = overrides.get("SQUID_CACHE_DIR_MB")
    cert_cache_mb = overrides.get("SQUID_DYNAMIC_CERT_MEM_CACHE_MB")

    seen: set[str] = set()
    out: list[str] = []
    for start, end in _logical_groups(lines):
        tokens = _logical_tokens(lines, start, end)
        directive = tokens[0].lower() if tokens else ""
        group = lines[start:end]
        single_line = end - start == 1
        if directive in simple or (directive == "sslcrtd_children" and children):
            value = (
                simple[directive]
                if directive in simple
                else _sslcrtd_children_value(children or 0, tokens[2:])
            )
            if single_line:
                out.append(_replace_value(group[0], directive, value))
            else:
                out.extend(_skipped_lines(lines, start, end))
                out.append(f"{directive} {value}")
            seen.add(directive)
        elif (
            directive == "cache_dir"
            and cache_dir_mb is not None
            and len(tokens) >= 4
            and tokens[3].isdigit()
        ):
            if single_line:
                out.append(
                    re.sub(
                        r"^(\s*cache_dir\s+\S+\s+\S+\s+)[0-9]+",
                        lambda match: f"{match.group(1)}{cache_dir_mb}",
                        group[0],
                        count=1,
                        flags=re.IGNORECASE,
                    ),
                )
            else:
                out.extend(_skipped_lines(lines, start, end))
                out.append(" ".join([*tokens[:3], str(cache_dir_mb), *tokens[4:]]))
        elif (
            directive in {"http_port", "https_port"}
            and cert_cache_mb is not None
            and _generates_certificates(tokens)
        ):
            replacement = f"dynamic_cert_mem_cache_size={cert_cache_mb}MB"
            if any(
                token.startswith("dynamic_cert_mem_cache_size=") for token in tokens
            ):
                out.extend(
                    line
                    if _is_skipped_line(line)
                    else _DYNAMIC_CERT_RE.sub(replacement, line)
                    for line in group
                )
            else:
                out.extend(group[:-1])
                out.append(f"{group[-1].rstrip()} {replacement}")
        else:
            out.extend(group)

    if children and "sslcrtd_children" not in seen:
        simple["sslcrtd_children"] = _sslcrtd_children_value(children, [])
    missing = [
        f"{directive} {value}"
        for directive, value in simple.items()
        if directive not in seen
    ]
    if missing:
        while out and not out[-1].strip():
            out.pop()
        out.extend(["", "# Host resource sizing from the proxy container environment."])
        out.extend(missing)
    rendered = "\n".join(out)
    return rendered + "\n" if trailing_newline or missing else rendered


def _main(argv: list[str]) -> int:
    """Run an entrypoint helper command.

    ``capture`` prints the validated override set (warnings on stderr);
    ``apply PATH`` pins the exported overrides into a squid.conf file.
    """
    if argv == ["capture"]:
        overrides, warnings = parse_host_sizing(os.environ)
        for warning in warnings:
            sys.stderr.write(f"[proxy-entrypoint] WARNING: {warning}\n")
        sys.stdout.write(encode_overrides(overrides) + "\n")
        return 0
    if len(argv) == 2 and argv[0] == "apply":
        overrides = active_overrides()
        path = pathlib.Path(argv[1])
        text = path.read_text(encoding="utf-8")
        rendered = apply_host_sizing(text, overrides)
        if rendered != text:
            tmp_path = path.with_name(f"{path.name}.host-sizing.tmp")
            tmp_path.write_text(rendered, encoding="utf-8")
            tmp_path.replace(path)
        return 0
    sys.stderr.write("usage: squid_host_sizing.py capture | apply PATH\n")
    return 2


if __name__ == "__main__":
    raise SystemExit(_main(sys.argv[1:]))

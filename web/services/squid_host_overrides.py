"""Host configuration overlay for the proxy's effective squid.conf.

Contract (see README "Host configuration overrides"):

* Config revisions in the control-plane database are the Admin UI's saved
  desired state for a proxy. Resource sizing and listener ports belong to the
  host the container runs on (memory budget, container port publishing,
  router REDIRECT/DNAT rules), so a proxy container can pin them through these
  environment variables; when one is set to a valid value it is authoritative
  over the revision for what it owns:

  ``SQUID_WORKERS``                    ``workers N``
  ``SQUID_CACHE_MEM_MB``               ``cache_mem N MB``
  ``SQUID_CACHE_DIR_MB``               size field of every ``cache_dir`` line
  ``SQUID_SSLCRTD_CHILDREN``           ``sslcrtd_children N`` (startup/idle
                                       capped at N, other options kept)
  ``SQUID_DYNAMIC_CERT_MEM_CACHE_MB``  ``dynamic_cert_mem_cache_size=NMB`` on
                                       every certificate-generating
                                       ``http_port``/``https_port``
  ``SQUID_MAX_FILEDESCRIPTORS``        ``max_filedescriptors N``
  ``SQUID_HTTP_PORT``                  port of the explicit (first non-intercept,
                                       non-tproxy) ``http_port``; the Admin UI's
                                       standard listener is added when missing
  ``SQUID_INTERCEPT_ENABLED``          presence of the Admin UI managed HTTP
                                       NAT intercept listener block
  ``SQUID_INTERCEPT_PORT``             its port; set without
                                       ``SQUID_INTERCEPT_ENABLED`` it also
                                       enables the listener
  ``SQUID_HTTPS_INTERCEPT_ENABLED``    presence of the managed HTTPS NAT
                                       intercept listener block (off also
                                       removes the splice rule)
  ``SQUID_HTTPS_INTERCEPT_PORT``       its port; set alone it enables it
  ``SQUID_HTTPS_INTERCEPT_SPLICE_ONLY`` the splice rule for that listener
                                       (added only while the listener exists)

* Unset variables leave the revision unchanged. Set but invalid values
  (non-integer, out of range, not a boolean, a port already pinned by an
  earlier listener variable) are ignored with a warning. Listener lines the
  Admin UI does not manage (custom ``http_port``/``https_port`` lines) are kept;
  a pinned port that another listener of the config also binds on an
  overlapping address (either is a wildcard, or both name the same address)
  is a deployment conflict and raises ``HostOverrideError`` instead of being
  moved, because the container publishes and the router redirects exactly that
  port. Distinct specific addresses may share a port.
* The proxy entrypoint validates the operator's variables once, before it
  derives its own defaults into the same names, and exports the accepted set
  as ``SQUID_HOST_CONFIG_OVERRIDES`` (``NAME=VALUE`` pairs, canonical order;
  booleans as 1/0). Every proxy process reads only that variable, so later
  in-process environment updates (for example ``SQUID_WORKERS`` after an
  apply) are never mistaken for operator overrides, and processes without it
  (the admin UI) apply no overlay.
* The overlay runs inside ``SquidController.normalize_config_text``, i.e.
  wherever the proxy renders, validates, applies, persists (last-known-good),
  rolls back or compares squid.conf, and in the entrypoint (``apply``) before
  Squid starts. It is idempotent, so ``current_config_sha`` is the SHA-256 of
  the effective file and equals the SHA-256 of the normalized+overlaid active
  revision once reconciled; the revision's own SHA stays its database
  identity.
* A sizing directive the overlay owns but the revision lacks is appended,
  except ``cache_dir`` (the overlay never invents a disk cache) and ports that
  do not generate certificates.
"""

from __future__ import annotations

import functools
import ipaddress
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

OVERRIDES_ENV = "SQUID_HOST_CONFIG_OVERRIDES"


class HostOverrideError(ValueError):
    """A host-pinned listener port collides with another listener of the config."""


@dataclass(frozen=True)
class HostSetting:
    env: str
    directive: str
    kind: str = "int"  # "int", "port" or "bool"
    minimum: int = 0
    maximum: int = 0
    unit: str = ""


SETTINGS: tuple[HostSetting, ...] = (
    # The proxy's ICAP/helper layout supports at most four Squid workers.
    HostSetting("SQUID_WORKERS", "workers", "int", 1, 4),
    HostSetting("SQUID_CACHE_MEM_MB", "cache_mem", "int", 0, 1_048_576, " MB"),
    HostSetting("SQUID_CACHE_DIR_MB", "cache_dir", "int", 1, 16_777_216, " MB"),
    HostSetting("SQUID_SSLCRTD_CHILDREN", "sslcrtd_children", "int", 1, 64),
    HostSetting(
        "SQUID_DYNAMIC_CERT_MEM_CACHE_MB",
        "dynamic_cert_mem_cache_size",
        "int",
        0,
        4096,
        " MB",
    ),
    HostSetting(
        "SQUID_MAX_FILEDESCRIPTORS",
        "max_filedescriptors",
        "int",
        1024,
        1_048_576,
    ),
    HostSetting("SQUID_HTTP_PORT", "http_port", "port", 1, 65535),
    HostSetting("SQUID_INTERCEPT_ENABLED", "http_port intercept", "bool"),
    HostSetting("SQUID_INTERCEPT_PORT", "http_port intercept port", "port", 1, 65535),
    HostSetting("SQUID_HTTPS_INTERCEPT_ENABLED", "https_port intercept", "bool"),
    HostSetting(
        "SQUID_HTTPS_INTERCEPT_PORT",
        "https_port intercept port",
        "port",
        1,
        65535,
    ),
    HostSetting(
        "SQUID_HTTPS_INTERCEPT_SPLICE_ONLY",
        "ssl_bump splice https_intercept_listener",
        "bool",
    ),
)
_SETTINGS_BY_ENV = {setting.env: setting for setting in SETTINGS}
_DIGITS_RE = re.compile(r"[0-9]{1,12}")
_TRUE_VALUES = frozenset({"1", "true", "yes", "on"})
_FALSE_VALUES = frozenset({"0", "false", "no", "off"})
_SSLCRTD_DEFAULT_OPTIONS = (("startup", 2), ("idle", 1), ("queue-size", 32))
_DYNAMIC_CERT_RE = re.compile(r"dynamic_cert_mem_cache_size=[^\s\\]*")


def _parse_value(setting: HostSetting, raw: str) -> tuple[int | None, str]:
    value = raw.strip()
    if setting.kind == "bool":
        lowered = value.lower()
        if lowered in _TRUE_VALUES:
            return 1, ""
        if lowered in _FALSE_VALUES:
            return 0, ""
        return None, (
            f"{setting.env}={raw!r} is not a boolean (1/0, true/false, yes/no, "
            "on/off); ignoring it and keeping the config revision value."
        )
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


def parse_host_overrides(
    environ: Mapping[str, str],
) -> tuple[dict[str, int], list[str]]:
    """Validate operator host variables; return accepted values and warnings."""
    overrides: dict[str, int] = {}
    warnings: list[str] = []
    pinned_ports: dict[int, str] = {}
    for setting in SETTINGS:
        raw = environ.get(setting.env)
        if raw is None or not raw.strip():
            continue
        value, warning = _parse_value(setting, raw)
        if value is not None and setting.kind == "port" and value in pinned_ports:
            value, warning = (
                None,
                (
                    f"{setting.env}={value} is already pinned by "
                    f"{pinned_ports[value]}; ignoring it and keeping the config "
                    "revision value."
                ),
            )
        if value is None:
            warnings.append(warning)
            continue
        overrides[setting.env] = value
        if setting.kind == "port":
            pinned_ports[value] = setting.env
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
    overrides, warnings = parse_host_overrides(pairs)
    for warning in warnings:
        logger.warning("%s: %s", OVERRIDES_ENV, warning)
    return dict(overrides)


def active_overrides(environ: Mapping[str, str] | None = None) -> Mapping[str, int]:
    source = os.environ if environ is None else environ
    return decode_overrides(str(source.get(OVERRIDES_ENV) or "").strip())


def _display_value(setting: HostSetting, value: int) -> str:
    if setting.kind == "bool":
        return "on" if value else "off"
    return f"{value}{setting.unit}"


def describe_overrides(overrides: Mapping[str, int]) -> list[dict[str, str]]:
    """Operator-facing summary of what this host's environment pins."""
    return [
        {
            "env": setting.env,
            "directive": setting.directive,
            "value": _display_value(setting, overrides[setting.env]),
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


def _apply_host_sizing(config_text: str, overrides: Mapping[str, int]) -> str:
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


_INTERCEPT_BLOCK = (
    "# BEGIN SQUID-UI INTERCEPT LISTENER",
    "# END SQUID-UI INTERCEPT LISTENER",
)
_HTTPS_INTERCEPT_BLOCK = (
    "# BEGIN SQUID-UI HTTPS INTERCEPT LISTENER",
    "# END SQUID-UI HTTPS INTERCEPT LISTENER",
)
# Marked splice block written by earlier entrypoint versions; the Admin UI
# renders SPLICE_RULE_LINES without markers.
_LEGACY_SPLICE_BLOCK = (
    "# BEGIN SQUID-UI HTTPS INTERCEPT SPLICE",
    "# END SQUID-UI HTTPS INTERCEPT SPLICE",
)
_MANAGED_BLOCKS = {
    "intercept": _INTERCEPT_BLOCK,
    "https_intercept": _HTTPS_INTERCEPT_BLOCK,
    "splice": _LEGACY_SPLICE_BLOCK,
}
SPLICE_RULE_LINES = (
    "# Splice all traffic arriving on the dedicated HTTPS NAT intercept listener.",
    "acl https_intercept_listener myportname https_intercept",
    "ssl_bump splice https_intercept_listener",
)
_LISTENER_DIRECTIVES = frozenset({"http_port", "https_port"})
_LISTENER_PORT_RE = re.compile(
    r"^(\s*https?_port\s+(?:\S*:)?)([0-9]+)(?=[\s\\]|$)",
    re.IGNORECASE,
)
_DYNAMIC_CERT_MB_RE = re.compile(r"dynamic_cert_mem_cache_size=([0-9]+)MB")
_DEFAULT_DYNAMIC_CERT_MB = 128


def default_intercept_port(explicit_port: int) -> int:
    return explicit_port + 1 if explicit_port < 65535 else 3129


def default_https_intercept_port(explicit_port: int) -> int:
    return 3130 if explicit_port != 3130 else 3131


def first_available_port(preferred: int, used_ports: set[int]) -> int:
    candidate = preferred
    for _ in range(65535):
        if candidate not in used_ports:
            return candidate
        candidate = 1 if candidate >= 65535 else candidate + 1
    msg = "No available TCP listener ports remain."
    raise ValueError(msg)


def render_explicit_http_port(port: int, dynamic_cert_mem_cache_mb: int) -> list[str]:
    """The Admin UI's explicit forward-proxy listener."""
    return [
        f"http_port 0.0.0.0:{port} ssl-bump \\",
        "\tcert=/etc/squid/ssl/certs/ca.crt \\",
        "\tkey=/etc/squid/ssl/certs/ca.key \\",
        "\tgenerate-host-certificates=on \\",
        f"\tdynamic_cert_mem_cache_size={max(0, dynamic_cert_mem_cache_mb)}MB",
    ]


def render_intercept_block(port: int) -> list[str]:
    """The Admin UI's managed HTTP NAT intercept listener block."""
    return [
        _INTERCEPT_BLOCK[0],
        "# HTTP NAT intercept listener. Requires external REDIRECT/DNAT rules; do not expose directly.",
        f"http_port 0.0.0.0:{port} intercept",
        _INTERCEPT_BLOCK[1],
    ]


def render_https_intercept_block(
    port: int,
    dynamic_cert_mem_cache_mb: int,
) -> list[str]:
    """The Admin UI's managed HTTPS NAT intercept listener block."""
    return [
        _HTTPS_INTERCEPT_BLOCK[0],
        "# HTTPS NAT intercept listener. Requires TCP/443 REDIRECT/DNAT and explicit operator consent.",
        f"https_port 0.0.0.0:{port} intercept ssl-bump \\",
        "\tname=https_intercept \\",
        "\tcert=/etc/squid/ssl/certs/ca.crt \\",
        "\tkey=/etc/squid/ssl/certs/ca.key \\",
        "\tgenerate-host-certificates=on \\",
        f"\tdynamic_cert_mem_cache_size={max(0, dynamic_cert_mem_cache_mb)}MB",
        _HTTPS_INTERCEPT_BLOCK[1],
    ]


def _address_port(token: str) -> int | None:
    candidate = token.rsplit(":", 1)[1] if ":" in token else token
    if not candidate.isdigit():
        return None
    port = int(candidate)
    return port if 1 <= port <= 65535 else None


@dataclass
class _Piece:
    """One logical squid.conf line, or a whole Admin UI managed block."""

    lines: list[str]
    kind: str = ""  # "" or a _MANAGED_BLOCKS key
    tokens: tuple[str, ...] = ()

    @property
    def directive(self) -> str:
        return self.tokens[0].lower() if self.tokens else ""

    def is_explicit_listener(self) -> bool:
        if self.kind or self.directive != "http_port" or len(self.tokens) < 2:
            return False
        modes = {token.lower() for token in self.tokens[2:]}
        return not modes & {"intercept", "tproxy"}

    def stripped(self) -> str:
        return " ".join(self.tokens).lower()


def _pieces(lines: list[str]) -> list[_Piece]:
    pieces: list[_Piece] = []
    open_block: _Piece | None = None
    for start, end in _logical_groups(lines):
        group = lines[start:end]
        if open_block is not None:
            open_block.lines.extend(group)
            if any(_MANAGED_BLOCKS[open_block.kind][1] in line for line in group):
                open_block = None
            continue
        kind = next(
            (
                name
                for name, (begin, _end) in _MANAGED_BLOCKS.items()
                if any(begin in line for line in group)
            ),
            "",
        )
        piece = _Piece(group, kind, tuple(_logical_tokens(lines, start, end)))
        pieces.append(piece)
        if kind and not any(_MANAGED_BLOCKS[kind][1] in line for line in group):
            open_block = piece
    return pieces


def _listener_ports(lines: list[str]) -> list[int]:
    ports: list[int] = []
    for start, end in _logical_groups(lines):
        tokens = _logical_tokens(lines, start, end)
        if len(tokens) >= 2 and tokens[0].lower() in _LISTENER_DIRECTIVES:
            port = _address_port(tokens[1])
            if port is not None:
                ports.append(port)
    return ports


def _bind_scope(token: str) -> tuple[str, str]:
    """Address family and address a listener token binds (``any`` = all).

    A bare port and ``[::]`` bind every address (Squid opens IPv6 wildcard
    sockets dual-stack); ``0.0.0.0`` binds every IPv4 address. Host names
    may resolve to anything, so they are treated as binding every address.
    """
    host = token.rsplit(":", 1)[0] if ":" in token else ""
    host = host.removeprefix("[").removesuffix("]")
    try:
        address = ipaddress.ip_address(host.split("%", 1)[0])
    except ValueError:
        return "any", ""
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped:
        address = address.ipv4_mapped
    if address.is_unspecified:
        return ("v4", "") if address.version == 4 else ("any", "")
    return f"v{address.version}", str(address)


def _binds_overlap(first: tuple[str, str], second: tuple[str, str]) -> bool:
    """Whether two listeners on one port would compete for the same socket."""
    if "any" in {first[0], second[0]}:
        return True
    if first[0] != second[0]:
        return False
    return not first[1] or not second[1] or first[1] == second[1]


def _conflicting_ports(lines: list[str]) -> set[int]:
    """Ports bound by more than one listener on overlapping addresses."""
    binds: dict[int, list[tuple[str, str]]] = {}
    conflicts: set[int] = set()
    for start, end in _logical_groups(lines):
        tokens = _logical_tokens(lines, start, end)
        if len(tokens) < 2 or tokens[0].lower() not in _LISTENER_DIRECTIVES:
            continue
        port = _address_port(tokens[1])
        if port is None:
            continue
        scope = _bind_scope(tokens[1])
        seen = binds.setdefault(port, [])
        if any(_binds_overlap(scope, other) for other in seen):
            conflicts.add(port)
        seen.append(scope)
    return conflicts


def _flatten(pieces: list[_Piece]) -> list[str]:
    return [line for piece in pieces for line in piece.lines]


def _pin_listener_port(lines: list[str], port: int) -> list[str]:
    """Set the port of the first listener line in ``lines`` (host kept)."""
    for start, end in _logical_groups(lines):
        tokens = _logical_tokens(lines, start, end)
        if len(tokens) < 2 or tokens[0].lower() not in _LISTENER_DIRECTIVES:
            continue
        first = next(
            index for index in range(start, end) if not _is_skipped_line(lines[index])
        )
        pinned, count = _LISTENER_PORT_RE.subn(
            lambda match: f"{match.group(1)}{port}",
            lines[first],
            count=1,
        )
        if count:
            return [*lines[:first], pinned, *lines[first + 1 :]]
        # The address is not on the directive's first physical line.
        host, sep, _old = tokens[1].rpartition(":")
        address = f"{host}{sep}{port}" if sep else str(port)
        return [
            *lines[:start],
            *_skipped_lines(lines, start, end),
            " ".join([tokens[0], address, *tokens[2:]]),
            *lines[end:],
        ]
    return lines


def _strip_splice_rule(pieces: list[_Piece]) -> list[_Piece]:
    rule = {line.lower() for line in SPLICE_RULE_LINES[1:]}
    comment = SPLICE_RULE_LINES[0]
    return [
        piece
        for piece in pieces
        if piece.kind != "splice"
        and piece.stripped() not in rule
        and not (len(piece.lines) == 1 and piece.lines[0].strip() == comment)
    ]


def _with_splice_rule(pieces: list[_Piece]) -> list[_Piece]:
    present = {piece.stripped() for piece in pieces if not piece.kind}
    if all(line.lower() in present for line in SPLICE_RULE_LINES[1:]):
        return pieces
    pieces = _strip_splice_rule(pieces)
    block = _Piece(list(SPLICE_RULE_LINES))
    for index, piece in enumerate(pieces):
        if piece.stripped() == "ssl_bump peek step1":
            return [*pieces[: index + 1], block, *pieces[index + 1 :]]
    for index, piece in enumerate(pieces):
        if piece.stripped().startswith("include /etc/squid/conf.d/10-sslfilter.conf"):
            return [*pieces[:index], block, *pieces[index:]]
    return [*pieces, _Piece([""]), block]


def _pinned_presence(
    overrides: Mapping[str, int],
    enabled_env: str,
    port_env: str,
) -> bool | None:
    if enabled_env in overrides:
        return bool(overrides[enabled_env])
    return True if port_env in overrides else None


def _apply_managed_listener(
    pieces: list[_Piece],
    *,
    kind: str,
    enabled: bool | None,
    port: int | None,
    render,
    insert_after: tuple[str, ...],
) -> list[_Piece]:
    if enabled is None:
        return pieces
    if not enabled:
        return [piece for piece in pieces if piece.kind != kind]
    for piece in pieces:
        if piece.kind == kind:
            if port is not None:
                piece.lines = _pin_listener_port(piece.lines, port)
            return pieces
    anchors = [
        position for position, piece in enumerate(pieces) if piece.kind in insert_after
    ]
    explicit = next(
        (
            position
            for position, piece in enumerate(pieces)
            if piece.is_explicit_listener()
        ),
        None,
    )
    if explicit is not None:
        anchors.append(explicit)
    index = max(anchors) + 1 if anchors else 0
    block = _Piece(render(pieces), kind)
    return [*pieces[:index], block, *pieces[index:]]


def _apply_host_listeners(config_text: str, overrides: Mapping[str, int]) -> str:
    http_port = overrides.get("SQUID_HTTP_PORT")
    intercept_port = overrides.get("SQUID_INTERCEPT_PORT")
    https_port = overrides.get("SQUID_HTTPS_INTERCEPT_PORT")
    intercept_on = _pinned_presence(
        overrides, "SQUID_INTERCEPT_ENABLED", "SQUID_INTERCEPT_PORT"
    )
    https_on = _pinned_presence(
        overrides, "SQUID_HTTPS_INTERCEPT_ENABLED", "SQUID_HTTPS_INTERCEPT_PORT"
    )
    splice = overrides.get("SQUID_HTTPS_INTERCEPT_SPLICE_ONLY")
    if (
        http_port is None
        and intercept_on is None
        and https_on is None
        and splice is None
    ):
        return config_text
    lines = config_text.split("\n")
    trailing_newline = config_text.endswith("\n")
    if trailing_newline:
        lines.pop()
    match = _DYNAMIC_CERT_MB_RE.search(config_text)
    dynamic_cert_mb = int(match.group(1)) if match else _DEFAULT_DYNAMIC_CERT_MB

    pieces = _pieces(lines)
    explicit = next((piece for piece in pieces if piece.is_explicit_listener()), None)
    if http_port is not None:
        if explicit is None:
            explicit = _Piece(render_explicit_http_port(http_port, dynamic_cert_mb))
            explicit.tokens = ("http_port", f"0.0.0.0:{http_port}", "ssl-bump")
            pieces = [explicit, _Piece([""]), *pieces]
        else:
            explicit.lines = _pin_listener_port(explicit.lines, http_port)
    explicit_port = (
        http_port
        if http_port is not None
        else (_address_port(explicit.tokens[1]) if explicit else None)
    ) or 3128

    def used_ports(current: list[_Piece]) -> set[int]:
        return set(_listener_ports(_flatten(current)))

    pieces = _apply_managed_listener(
        pieces,
        kind="intercept",
        enabled=intercept_on,
        port=intercept_port,
        render=lambda current: render_intercept_block(
            intercept_port
            or first_available_port(
                default_intercept_port(explicit_port), used_ports(current)
            ),
        ),
        insert_after=(),
    )
    pieces = _apply_managed_listener(
        pieces,
        kind="https_intercept",
        enabled=https_on,
        port=https_port,
        render=lambda current: render_https_intercept_block(
            https_port
            or first_available_port(
                default_https_intercept_port(explicit_port), used_ports(current)
            ),
            dynamic_cert_mb,
        ),
        insert_after=("intercept",),
    )
    if https_on is False or splice == 0:
        pieces = _strip_splice_rule(pieces)
    elif splice and any(piece.kind == "https_intercept" for piece in pieces):
        pieces = _with_splice_rule(pieces)

    out = _flatten(pieces)
    conflicting = _conflicting_ports(out)
    pinned = (
        ("SQUID_HTTP_PORT", http_port),
        ("SQUID_INTERCEPT_PORT", intercept_port if intercept_on else None),
        ("SQUID_HTTPS_INTERCEPT_PORT", https_port if https_on else None),
    )
    conflicts = [
        f"{env}={port}"
        for env, port in pinned
        if port is not None and port in conflicting
    ]
    if conflicts:
        msg = (
            f"Host-pinned listener port(s) {', '.join(conflicts)} are also used by "
            "another listener in this config; change the config's listener or the "
            "proxy container environment."
        )
        raise HostOverrideError(msg)
    rendered = "\n".join(out)
    return rendered + "\n" if trailing_newline else rendered


def apply_host_overrides(config_text: str, overrides: Mapping[str, int]) -> str:
    """Return ``config_text`` with the host-owned settings pinned (idempotent).

    Raises ``HostOverrideError`` when a pinned listener port is also used by
    another listener of ``config_text``.
    """
    if not overrides or not (config_text or "").strip():
        return config_text
    return _apply_host_sizing(_apply_host_listeners(config_text, overrides), overrides)


def _main(argv: list[str]) -> int:
    """Run an entrypoint helper command.

    ``capture`` prints the validated override set (warnings on stderr);
    ``apply PATH`` pins the exported overrides into a squid.conf file.
    """
    if argv == ["capture"]:
        overrides, warnings = parse_host_overrides(os.environ)
        for warning in warnings:
            sys.stderr.write(f"[proxy-entrypoint] WARNING: {warning}\n")
        sys.stdout.write(encode_overrides(overrides) + "\n")
        return 0
    if len(argv) == 2 and argv[0] == "apply":
        overrides = active_overrides()
        path = pathlib.Path(argv[1])
        text = path.read_text(encoding="utf-8")
        try:
            rendered = apply_host_overrides(text, overrides)
        except HostOverrideError as exc:
            sys.stderr.write(f"[proxy-entrypoint] ERROR: {exc}\n")
            return 1
        if rendered != text:
            tmp_path = path.with_name(f"{path.name}.host-overrides.tmp")
            tmp_path.write_text(rendered, encoding="utf-8")
            tmp_path.replace(path)
        return 0
    sys.stderr.write("usage: squid_host_overrides.py capture | apply PATH\n")
    return 2


if __name__ == "__main__":
    raise SystemExit(_main(sys.argv[1:]))

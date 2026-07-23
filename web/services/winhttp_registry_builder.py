from __future__ import annotations

import ipaddress
import json
import re
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Literal
from urllib.parse import urlsplit

if TYPE_CHECKING:
    from collections.abc import Iterable

REGISTRY_PATH = r"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Connections"
VALUE_NAME = "WinHttpSettings"
VALUE_TYPE = "REG_BINARY"

# Microsoft documents WINHTTP_ACCESS_TYPE_NAMED_PROXY. The byte layout below is
# the observed legacy WinHttpSettings value used by current static-proxy GPO
# workflows; Microsoft does not publish this as a formal all-mode binary schema.
ACCESS_TYPE_NAMED_PROXY = 0x00000003
HEADER_MARKER = 0x28

ADVPROXY_SCOPES = ("machine", "user")
DOCUMENTED_ADVPROXY_KEYS = ("Proxy", "ProxyBypass", "AutoconfigUrl", "AutoDetect")
DESTINATION_SCHEMES = ("http", "https", "ftp", "socks")
TRACING_OUTPUTS = ("file", "debugger", "both")
TRACING_LEVELS = ("default", "verbose")
TRACING_FORMATS = ("ansi", "hex")
COMMAND_UNSAFE_RE = re.compile(r'["&|\x00-\x1f\x7f]')
RAW_HEX_INPUT_RE = re.compile(r"^[0-9a-fA-F,\s\\-]*$")
CUSTOM_PROXY_SCHEME_RE = re.compile(r"^[A-Za-z][A-Za-z0-9+.-]*$")


class WinHttpBuilderError(ValueError):
    pass


@dataclass(frozen=True)
class DecodedBasicWinHttpSettings:
    header_marker: int
    reserved: int
    access_type: int
    proxy_string: str
    bypass_string: str


@dataclass(frozen=True)
class WinHttpContractOutput:
    proxy_string: str
    bypass_string: str
    static_registry_available: bool
    normalized_hex: str
    reg_file: str
    decoded: DecodedBasicWinHttpSettings | None
    legacy_set_proxy_command: str
    advproxy_json: str
    advproxy_command: str
    advproxy_settings_file_json: str
    advproxy_settings_file_command: str
    reset_proxy_command: str
    import_ie_command: str
    show_proxy_command: str
    show_advproxy_command: str
    tracing_command: str
    show_tracing_command: str
    reset_tracing_command: str
    flush_logbuffer_command: str
    warnings: tuple[str, ...]


def _quote_cmd(value: str) -> str:
    return '"' + str(value or "").replace('"', r"\"") + '"'


def _validate_command_value(value: str, field_name: str) -> None:
    _ascii_bytes(value)
    if COMMAND_UNSAFE_RE.search(value or ""):
        msg = f"{field_name} must not contain quotes, control characters, or command separators."
        raise WinHttpBuilderError(msg)


def _write_dword_le(out: list[int], value: int) -> None:
    if not isinstance(value, int) or value < 0 or value > 0xFFFFFFFF:
        msg = f"Invalid DWORD value: {value}"
        raise WinHttpBuilderError(msg)
    out.extend(
        (value & 0xFF, (value >> 8) & 0xFF, (value >> 16) & 0xFF, (value >> 24) & 0xFF),
    )


def _ascii_bytes(value: str) -> list[int]:
    if re.search(r"[^\x00-\x7f]", value or ""):
        msg = f"Only ASCII characters are supported: {value}"
        raise WinHttpBuilderError(msg)
    return [ord(ch) for ch in value or ""]


def _bytes_to_hex(bytes_: Iterable[int]) -> str:
    return "".join(f"{int(byte) & 0xFF:02x}" for byte in bytes_)


def normalize_hex_only(value: str) -> str:
    return re.sub(r"[^0-9a-fA-F]", "", value or "").lower()


def hex_to_bytes(hex_value: str) -> list[int]:
    clean = normalize_hex_only(hex_value)
    if len(clean) % 2:
        msg = "Hex string must contain an even number of characters."
        raise WinHttpBuilderError(msg)
    return [int(clean[i : i + 2], 16) for i in range(0, len(clean), 2)]


def _read_dword_le(bytes_: list[int], offset: int) -> int:
    if offset + 4 > len(bytes_):
        msg = "Unexpected end of binary while reading DWORD."
        raise WinHttpBuilderError(msg)
    return (
        bytes_[offset]
        | (bytes_[offset + 1] << 8)
        | (bytes_[offset + 2] << 16)
        | (bytes_[offset + 3] << 24)
    ) & 0xFFFFFFFF


def _ascii_from_bytes(bytes_: list[int]) -> str:
    if any(byte > 0x7F for byte in bytes_):
        msg = "Basic WinHTTP strings must be ASCII."
        raise WinHttpBuilderError(msg)
    return "".join(chr(byte) for byte in bytes_)


def normalize_bypass_list(
    value: str | Iterable[str] | None,
    *,
    include_local: bool,
) -> str:
    raw_items = (
        list(value)
        if isinstance(value, (list, tuple))
        else re.split(r"[\r\n;\s]+", str(value or ""))
    )
    seen: set[str] = set()
    normalized: list[str] = []
    for item in raw_items:
        cleaned = str(item or "").strip()
        if not cleaned:
            continue
        if "," in cleaned:
            msg = "Bypass entries must not contain commas."
            raise WinHttpBuilderError(msg)
        key = cleaned.lower()
        if key in seen:
            continue
        seen.add(key)
        normalized.append(cleaned)
    if include_local and "<local>" not in seen:
        normalized.append("<local>")
    bypass = ";".join(normalized)
    _validate_command_value(bypass, "Bypass list")
    return bypass


def _normalize_proxy_host(host: str) -> tuple[str, str | None]:
    value = (host or "").strip()
    warning = None
    inline_port_warning = (
        "Proxy host/IP should not include an inline port; the separate proxy port field "
        "is used for generated destination scheme mappings."
    )
    inline_port_error = (
        "Proxy host/IP inline port is invalid; use the separate proxy port field."
    )
    if not value:
        msg = "Proxy host/IP is required."
        raise WinHttpBuilderError(msg)
    if "://" in value:
        warning = "Normal proxy host should not include http:// or https://; destination scheme mappings are generated separately."
        try:
            parsed = urlsplit(value)
            inline_port = parsed.port
            if inline_port is not None and inline_port < 1:
                raise ValueError
            if inline_port is not None:
                warning = f"{warning} {inline_port_warning}"
            if parsed.path or parsed.query or parsed.fragment or parsed.username or parsed.password:
                msg = "Proxy host/IP must be only a host name or IP address, not a full URL."
                raise WinHttpBuilderError(msg)
            value = parsed.hostname or ""
            if not value:
                msg = "Proxy host/IP is invalid."
                raise WinHttpBuilderError(msg)
        except WinHttpBuilderError:
            raise
        except ValueError as exc:
            msg = "Proxy host/IP is invalid."
            raise WinHttpBuilderError(msg) from exc
    elif value.startswith("["):
        end = value.find("]")
        if end <= 1:
            raise WinHttpBuilderError(inline_port_error)
        host_part = value[1:end]
        try:
            parsed_host = ipaddress.ip_address(host_part)
        except ValueError as exc:
            msg = "Proxy host/IP is invalid."
            raise WinHttpBuilderError(msg) from exc
        if parsed_host.version != 6:
            msg = "Proxy host/IP is invalid."
            raise WinHttpBuilderError(msg)
        suffix = value[end + 1 :]
        if suffix:
            if not suffix.startswith(":") or not suffix[1:].isdecimal():
                raise WinHttpBuilderError(inline_port_error)
            inline_port = int(suffix[1:])
            if inline_port < 1 or inline_port > 65535:
                raise WinHttpBuilderError(inline_port_error)
            warning = inline_port_warning
        value = host_part
    elif "[" in value or "]" in value:
        msg = "Proxy host/IP is invalid."
        raise WinHttpBuilderError(msg)
    elif value.count(":") == 1:
        host_part, port_part = value.rsplit(":", 1)
        if not host_part or not port_part.isdecimal():
            raise WinHttpBuilderError(inline_port_error)
        inline_port = int(port_part)
        if inline_port < 1 or inline_port > 65535:
            raise WinHttpBuilderError(inline_port_error)
        warning = inline_port_warning
        value = host_part
    elif ":" in value:
        try:
            parsed_host = ipaddress.ip_address(value)
        except ValueError as exc:
            msg = "Proxy host/IP is invalid."
            raise WinHttpBuilderError(msg) from exc
        if parsed_host.version != 6:
            msg = "Proxy host/IP is invalid."
            raise WinHttpBuilderError(msg)
    if "/" in value or any(ch.isspace() for ch in value):
        msg = "Proxy host/IP must not contain spaces or path separators."
        raise WinHttpBuilderError(msg)
    _validate_command_value(value, "Proxy host/IP")
    return value, warning


def _format_proxy_mapping_host(host: str) -> str:
    value = (host or "").strip()
    candidate = value[1:-1] if value.startswith("[") and value.endswith("]") else value
    try:
        parsed = ipaddress.ip_address(candidate)
    except ValueError:
        return host
    if parsed.version == 6:
        return f"[{parsed.compressed}]"
    return host


def _normalize_port(port: object) -> int:
    try:
        parsed = int(str(port or "").strip())
    except Exception as exc:
        msg = "Proxy port must be an integer from 1 to 65535."
        raise WinHttpBuilderError(msg) from exc
    if parsed < 1 or parsed > 65535:
        msg = "Proxy port must be an integer from 1 to 65535."
        raise WinHttpBuilderError(msg)
    return parsed


def _normalize_scheme_list(values: Iterable[str]) -> list[str]:
    normalized: list[str] = []
    for value in values:
        scheme = str(value or "").strip().lower()
        if not scheme:
            continue
        if scheme not in DESTINATION_SCHEMES:
            msg = f"Unsupported destination scheme for documented WinHTTP mapping: {scheme}"
            raise WinHttpBuilderError(msg)
        if scheme not in normalized:
            normalized.append(scheme)
    return normalized


def _validate_custom_proxy_target(target: str) -> None:
    value = (target or "").strip()
    if not value:
        msg = "Custom proxy map targets must not be empty."
        raise WinHttpBuilderError(msg)
    if "://" in value or any(ch in value for ch in "/?#@="):
        msg = "Custom proxy map targets must be proxy host[:port] values, not URLs."
        raise WinHttpBuilderError(msg)
    if any(ch.isspace() for ch in value):
        msg = "Custom proxy map entries must be separated with semicolons and contain no whitespace."
        raise WinHttpBuilderError(msg)
    if value.startswith("["):
        end = value.find("]")
        if end <= 1:
            msg = "Custom proxy map target contains malformed bracketed IPv6."
            raise WinHttpBuilderError(msg)
        host_part = value[1:end]
        try:
            parsed_host = ipaddress.ip_address(host_part)
        except ValueError as exc:
            msg = "Custom proxy map target contains malformed bracketed IPv6."
            raise WinHttpBuilderError(msg) from exc
        if parsed_host.version != 6:
            msg = "Custom proxy map target contains malformed bracketed IPv6."
            raise WinHttpBuilderError(msg)
        suffix = value[end + 1 :]
        if suffix:
            if not suffix.startswith(":") or not suffix[1:].isdecimal():
                msg = "Custom proxy map target port must be an integer from 1 to 65535."
                raise WinHttpBuilderError(msg)
            port = int(suffix[1:])
            if port < 1 or port > 65535:
                msg = "Custom proxy map target port must be an integer from 1 to 65535."
                raise WinHttpBuilderError(msg)
        return
    if "[" in value or "]" in value:
        msg = "Custom proxy map target contains malformed bracketed IPv6."
        raise WinHttpBuilderError(msg)
    if value.count(":") == 1:
        host_part, port_part = value.rsplit(":", 1)
        if not host_part or not port_part.isdecimal():
            msg = "Custom proxy map target port must be an integer from 1 to 65535."
            raise WinHttpBuilderError(msg)
        port = int(port_part)
        if port < 1 or port > 65535:
            msg = "Custom proxy map target port must be an integer from 1 to 65535."
            raise WinHttpBuilderError(msg)
    elif ":" in value:
        msg = "Custom proxy map IPv6 targets must use bracket notation."
        raise WinHttpBuilderError(msg)


def _validate_custom_proxy_map(proxy_string: str) -> tuple[str, tuple[str, ...]]:
    _validate_command_value(proxy_string, "Custom proxy map")
    entries = [entry.strip() for entry in proxy_string.split(";") if entry.strip()]
    if not entries:
        msg = "Custom proxy map is enabled but empty."
        raise WinHttpBuilderError(msg)
    has_mapping = any("=" in entry for entry in entries)
    warnings: list[str] = []
    for entry in entries:
        if any(ch.isspace() for ch in entry):
            msg = "Custom proxy map entries must be separated with semicolons and contain no whitespace."
            raise WinHttpBuilderError(msg)
        if "=" not in entry:
            if has_mapping:
                msg = "Custom proxy map must not mix scheme mappings with bare proxy targets."
                raise WinHttpBuilderError(msg)
            _validate_custom_proxy_target(entry)
            continue
        scheme, target = entry.split("=", 1)
        scheme = scheme.strip().lower()
        if not scheme or not CUSTOM_PROXY_SCHEME_RE.fullmatch(scheme):
            msg = "Custom proxy map contains an invalid scheme mapping."
            raise WinHttpBuilderError(msg)
        _validate_custom_proxy_target(target)
        if scheme not in DESTINATION_SCHEMES:
            warnings.append(
                f"Custom proxy map contains a nonstandard WinHTTP scheme mapping: {scheme}.",
            )
        if scheme == "socks":
            warnings.append(
                "Microsoft's advproxy documentation includes a socks example but also states SOCKS5 is not supported; verify target Windows behavior before deploying socks mappings.",
            )
    return ";".join(entries), tuple(warnings)


def build_proxy_string(
    *,
    proxy_host: str,
    proxy_port: object,
    destination_schemes: Iterable[str],
    custom_proxy_map: str = "",
    use_custom_proxy_map: bool = False,
) -> tuple[str, tuple[str, ...]]:
    warnings: list[str] = []
    if use_custom_proxy_map or (custom_proxy_map or "").strip():
        proxy_string = (custom_proxy_map or "").strip()
        if not proxy_string:
            msg = "Custom proxy map is enabled but empty."
            raise WinHttpBuilderError(msg)
        return _validate_custom_proxy_map(proxy_string)

    host, host_warning = _normalize_proxy_host(proxy_host)
    if host_warning:
        warnings.append(host_warning)
    port = _normalize_port(proxy_port)
    schemes = _normalize_scheme_list(destination_schemes)
    if not schemes:
        msg = "At least one destination scheme must be selected."
        raise WinHttpBuilderError(msg)
    if "socks" in schemes:
        warnings.append(
            "Microsoft's advproxy documentation includes a socks example but also states SOCKS5 is not supported; verify target Windows behavior before deploying socks mappings.",
        )
    mapping_host = _format_proxy_mapping_host(host)
    return ";".join(f"{scheme}={mapping_host}:{port}" for scheme in schemes), tuple(warnings)


def generate_basic_winhttp_binary(proxy_string: str, bypass_string: str) -> str:
    proxy_bytes = _ascii_bytes(proxy_string)
    bypass_bytes = _ascii_bytes(bypass_string)
    out: list[int] = []
    _write_dword_le(out, HEADER_MARKER)
    _write_dword_le(out, 0)
    _write_dword_le(out, ACCESS_TYPE_NAMED_PROXY)
    _write_dword_le(out, len(proxy_bytes))
    out.extend(proxy_bytes)
    _write_dword_le(out, len(bypass_bytes))
    out.extend(bypass_bytes)
    return _bytes_to_hex(out)


def decode_basic_winhttp_settings_hex(hex_value: str) -> DecodedBasicWinHttpSettings:
    bytes_ = hex_to_bytes(hex_value)
    offset = 0
    header = _read_dword_le(bytes_, offset)
    offset += 4
    reserved = _read_dword_le(bytes_, offset)
    offset += 4
    access_type = _read_dword_le(bytes_, offset)
    offset += 4
    if header != HEADER_MARKER:
        msg = (
            "Unsupported WinHttpSettings header marker: "
            f"expected 0x{HEADER_MARKER:08x}, got 0x{header:08x}."
        )
        raise WinHttpBuilderError(msg)
    if reserved != 0:
        msg = (
            "Unsupported WinHttpSettings reserved field: "
            f"expected 0x00000000, got 0x{reserved:08x}."
        )
        raise WinHttpBuilderError(msg)
    if access_type != ACCESS_TYPE_NAMED_PROXY:
        msg = (
            "Unsupported WinHTTP access type: "
            f"expected named proxy 0x{ACCESS_TYPE_NAMED_PROXY:08x}, "
            f"got 0x{access_type:08x}."
        )
        raise WinHttpBuilderError(msg)
    proxy_length = _read_dword_le(bytes_, offset)
    offset += 4
    if offset + proxy_length > len(bytes_):
        msg = "Proxy string length exceeds available binary data."
        raise WinHttpBuilderError(msg)
    proxy_string = _ascii_from_bytes(bytes_[offset : offset + proxy_length])
    offset += proxy_length
    bypass_length = _read_dword_le(bytes_, offset)
    offset += 4
    if offset + bypass_length > len(bytes_):
        msg = "Bypass string length exceeds available binary data."
        raise WinHttpBuilderError(msg)
    bypass_string = _ascii_from_bytes(bytes_[offset : offset + bypass_length])
    offset += bypass_length
    if offset != len(bytes_):
        msg = "Unexpected trailing data after bypass string."
        raise WinHttpBuilderError(msg)
    return DecodedBasicWinHttpSettings(
        header_marker=header,
        reserved=reserved,
        access_type=access_type,
        proxy_string=proxy_string,
        bypass_string=bypass_string,
    )


def generate_reg_file_from_hex(hex_value: str, *, bytes_per_line: int = 25) -> str:
    clean = normalize_hex_only(hex_value)
    if len(clean) % 2:
        msg = "Hex string must contain an even number of characters."
        raise WinHttpBuilderError(msg)
    pairs = re.findall(r"..", clean)
    lines: list[str] = []
    for idx in range(0, len(pairs), bytes_per_line):
        chunk = ",".join(pairs[idx : idx + bytes_per_line])
        last = idx + bytes_per_line >= len(pairs)
        prefix = f'"{VALUE_NAME}"=hex:' if idx == 0 else " "
        continuation = "" if last else ",\\"
        lines.append(f"{prefix}{chunk}{continuation}")
    return "\r\n".join(
        ["Windows Registry Editor Version 5.00", "", f"[{REGISTRY_PATH}]", *lines, ""],
    )


def normalize_reg_binary_export(value: str) -> str:
    text = value or ""
    chunks: list[str] = []
    collecting = False

    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not collecting:
            match = re.match(
                r'"WinHttpSettings"\s*=\s*hex:(.*)$',
                line,
                flags=re.IGNORECASE,
            )
            if not match:
                continue
            collecting = True
            body = match.group(1)
        else:
            if line.startswith("[") or re.match(r'"[^"]+"\s*=', line):
                break
            body = line

        continued = body.rstrip().endswith("\\")
        if continued:
            body = body.rstrip()[:-1]
        chunks.append(body)
        if not continued:
            break

    if chunks:
        body = "".join(chunks)
    else:
        if text.strip() and not RAW_HEX_INPUT_RE.fullmatch(text):
            msg = (
                f'No {VALUE_NAME} {VALUE_TYPE} value was found; paste a registry export '
                f'containing "{VALUE_NAME}"=hex:... or raw hex bytes.'
            )
            raise WinHttpBuilderError(msg)
        body = text
    clean = normalize_hex_only(body)
    if not chunks and text.strip() and not clean:
        msg = (
            f'No {VALUE_NAME} {VALUE_TYPE} value was found; paste a registry export '
            f'containing "{VALUE_NAME}"=hex:... or raw hex bytes.'
        )
        raise WinHttpBuilderError(msg)
    if len(clean) % 2:
        msg = "Normalized WinHttpSettings hex has an odd number of characters."
        raise WinHttpBuilderError(msg)
    return clean


def build_advproxy_settings_json(
    *,
    proxy_string: str = "",
    bypass_string: str = "",
    autoconfig_url: str = "",
    autodetect: bool = False,
) -> str:
    payload = {
        "Proxy": proxy_string or "",
        "ProxyBypass": bypass_string or "",
        "AutoconfigUrl": (autoconfig_url or "").strip(),
        "AutoDetect": bool(autodetect),
    }
    for key in DOCUMENTED_ADVPROXY_KEYS:
        _validate_command_value(str(payload[key]), key)
    return json.dumps(payload, separators=(",", ":"))


def build_advproxy_command(
    *,
    scope: Literal["machine", "user"],
    settings_json: str,
) -> str:
    chosen_scope = scope if scope in ADVPROXY_SCOPES else "machine"
    return f"netsh winhttp set advproxy setting-scope={chosen_scope} settings={_quote_cmd(settings_json)}"


def build_legacy_set_proxy_command(proxy_string: str, bypass_string: str) -> str:
    command = f"netsh winhttp set proxy proxy-server={_quote_cmd(proxy_string)}"
    if bypass_string:
        command += f" bypass-list={_quote_cmd(bypass_string)}"
    return command


def build_tracing_command(
    *,
    state: str,
    output: str = "",
    trace_file_prefix: str = "",
    level: str = "",
    format_: str = "",
    max_trace_file_size: object = "",
) -> str:
    state_value = (state or "disabled").strip().lower()
    if state_value not in {"enabled", "disabled"}:
        msg = "Tracing state must be enabled or disabled."
        raise WinHttpBuilderError(msg)
    parts = ["netsh winhttp set tracing"]
    output_value = (output or "").strip().lower()
    if output_value:
        if output_value not in TRACING_OUTPUTS:
            msg = "Tracing output must be file, debugger, or both."
            raise WinHttpBuilderError(msg)
        parts.append(f"output={output_value}")
    if trace_file_prefix:
        _validate_command_value(trace_file_prefix, "Trace file prefix")
        parts.append(f"trace-file-prefix={_quote_cmd(trace_file_prefix)}")
    level_value = (level or "").strip().lower()
    if level_value:
        if level_value not in TRACING_LEVELS:
            msg = "Tracing level must be default or verbose."
            raise WinHttpBuilderError(msg)
        parts.append(f"level={level_value}")
    format_value = (format_ or "").strip().lower()
    if format_value:
        if format_value not in TRACING_FORMATS:
            msg = "Tracing format must be ansi or hex."
            raise WinHttpBuilderError(msg)
        parts.append(f"format={format_value}")
    size_value = str(max_trace_file_size or "").strip()
    if size_value:
        try:
            size = int(size_value)
        except Exception as exc:
            msg = "Maximum trace file size must be an integer."
            raise WinHttpBuilderError(msg) from exc
        if size < 1:
            msg = "Maximum trace file size must be positive."
            raise WinHttpBuilderError(msg)
        parts.append(f"max-trace-file-size={size}")
    parts.append(f"state={state_value}")
    return " ".join(parts)


def _form_bool(form: dict[str, Any], key: str) -> bool:
    return bool(form.get(key))


def build_contract_output(form: dict[str, Any]) -> WinHttpContractOutput:
    schemes = form.get("destination_schemes") or []
    if isinstance(schemes, str):
        schemes = [schemes]
    autoconfig_url = str(form.get("autoconfig_url") or "").strip()
    autodetect = _form_bool(form, "autodetect")
    proxy_host = str(form.get("proxy_host") or "")
    custom_proxy_map = str(form.get("custom_proxy_map") or "")
    use_custom_proxy_map = _form_bool(form, "use_custom_proxy_map")
    if (
        not proxy_host.strip()
        and not custom_proxy_map.strip()
        and (autoconfig_url or autodetect)
    ):
        proxy_string = ""
        proxy_warnings: tuple[str, ...] = ()
    else:
        proxy_string, proxy_warnings = build_proxy_string(
            proxy_host=proxy_host,
            proxy_port=form.get("proxy_port") or "",
            destination_schemes=schemes,
            custom_proxy_map=custom_proxy_map,
            use_custom_proxy_map=use_custom_proxy_map,
        )
    bypass_string = normalize_bypass_list(
        form.get("bypass_list") or "",
        include_local=_form_bool(form, "include_local_bypass"),
    )
    scope = (
        "user"
        if str(form.get("advproxy_scope") or "").strip().lower() == "user"
        else "machine"
    )

    warnings = list(proxy_warnings)
    if not bypass_string:
        warnings.append("Bypass list is empty.")
    if "<local>" not in bypass_string.lower().split(";"):
        warnings.append("<local> is not present in the bypass list.")
    if autoconfig_url:
        _validate_command_value(autoconfig_url, "Autoconfig URL")
        warnings.append(
            "Autoconfig/PAC URL deployment is represented by advproxy JSON/commands, not by the basic static WinHttpSettings binary.",
        )
    if autodetect:
        warnings.append(
            "AutoDetect deployment is represented by advproxy JSON/commands, not by the basic static WinHttpSettings binary.",
        )

    static_registry_available = (
        bool(proxy_string) and not autoconfig_url and not autodetect
    )
    normalized_hex = ""
    reg_file = ""
    decoded: DecodedBasicWinHttpSettings | None = None
    if static_registry_available:
        normalized_hex = generate_basic_winhttp_binary(proxy_string, bypass_string)
        decoded = decode_basic_winhttp_settings_hex(normalized_hex)
        if (
            decoded.proxy_string != proxy_string
            or decoded.bypass_string != bypass_string
        ):
            msg = "Generated WinHttpSettings failed decode verification."
            raise WinHttpBuilderError(msg)
        if (
            decoded.header_marker != HEADER_MARKER
            or decoded.access_type != ACCESS_TYPE_NAMED_PROXY
        ):
            msg = "Generated WinHttpSettings header failed verification."
            raise WinHttpBuilderError(msg)
        reg_file = generate_reg_file_from_hex(normalized_hex)
    elif not proxy_string:
        warnings.append(
            "No static proxy was supplied; use the advproxy JSON/commands or reset command rather than a WinHttpSettings REG_BINARY value.",
        )
    else:
        warnings.append(
            "Microsoft documents WinHTTP PAC and AutoDetect through advproxy; no official byte-for-byte registry serialization contract is published for those modes.",
        )

    advproxy_json_compact = build_advproxy_settings_json(
        proxy_string=proxy_string,
        bypass_string=bypass_string,
        autoconfig_url=autoconfig_url,
        autodetect=autodetect,
    )
    advproxy_json_pretty = json.dumps(json.loads(advproxy_json_compact), indent=2)
    return WinHttpContractOutput(
        proxy_string=proxy_string,
        bypass_string=bypass_string,
        static_registry_available=static_registry_available,
        normalized_hex=normalized_hex,
        reg_file=reg_file,
        decoded=decoded,
        legacy_set_proxy_command=build_legacy_set_proxy_command(
            proxy_string,
            bypass_string,
        )
        if proxy_string
        else "netsh winhttp reset proxy",
        advproxy_json=advproxy_json_pretty,
        advproxy_command=build_advproxy_command(
            scope=scope,
            settings_json=advproxy_json_compact,
        ),
        advproxy_settings_file_json=advproxy_json_pretty,
        advproxy_settings_file_command=f"netsh winhttp set advproxy setting-scope={scope} settings-file=winhttp-proxy-settings.json",
        reset_proxy_command="netsh winhttp reset proxy",
        import_ie_command="netsh winhttp import proxy source=ie",
        show_proxy_command="netsh winhttp show proxy",
        show_advproxy_command="netsh winhttp show advproxy",
        tracing_command=build_tracing_command(
            state=str(form.get("tracing_state") or "disabled"),
            output=str(form.get("tracing_output") or ""),
            trace_file_prefix=str(form.get("trace_file_prefix") or ""),
            level=str(form.get("tracing_level") or ""),
            format_=str(form.get("tracing_format") or ""),
            max_trace_file_size=form.get("max_trace_file_size") or "",
        ),
        show_tracing_command="netsh winhttp show tracing",
        reset_tracing_command="netsh winhttp reset tracing",
        flush_logbuffer_command="netsh winhttp flush logbuffer",
        warnings=tuple(warnings),
    )

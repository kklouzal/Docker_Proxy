from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

FormMap = Mapping[str, Any]
CLAMAV_SETTINGS_START = "# BEGIN SQUID-UI CLAMAV SETTINGS"
CLAMAV_SETTINGS_END = "# END SQUID-UI CLAMAV SETTINGS"

DEFAULTS: dict[str, Any] = {
    "clamav_fail_mode": "open",
    "file_security_preset": "balanced",
    "file_security_scan_downloads": True,
    "file_security_scan_uploads": True,
    "file_security_block_risky_extensions": True,
    "file_security_risky_extensions": "exe dll msi bat cmd com scr ps1 vbs js jar apk",
    "file_security_block_archives": False,
    "file_security_archive_extensions": "zip 7z rar tar gz bz2 xz iso",
    "file_security_block_nested_archives": False,
    "file_security_block_executable_content": True,
    "file_security_executable_extensions": "exe dll msi com scr jar apk",
    "file_security_blocked_mime_types": "application/x-msdownload application/x-msdos-program application/x-ms-installer",
    "file_security_max_download_size": "0",
    "file_security_max_upload_size": "0",
    "file_security_quarantine_metadata": True,
    "virus_scan_scan_file_types": "TEXT DATA BINARY",
    "virus_scan_send_percent_data": 99,
    "virus_scan_start_send_percent_after": "1K",
    "virus_scan_allow_204_on": True,
    "virus_scan_max_object_size": "128M",
    "virus_scan_default_engine": "",
}

_PRESET_DEFAULTS: dict[str, dict[str, Any]] = {
    "monitor": {
        "file_security_scan_downloads": True,
        "file_security_scan_uploads": True,
        "file_security_block_risky_extensions": False,
        "file_security_block_archives": False,
        "file_security_block_nested_archives": False,
        "file_security_block_executable_content": False,
        "file_security_max_download_size": "0",
        "file_security_max_upload_size": "0",
        "file_security_quarantine_metadata": True,
    },
    "balanced": {},
    "strict": {
        "file_security_scan_downloads": True,
        "file_security_scan_uploads": True,
        "file_security_block_risky_extensions": True,
        "file_security_block_archives": True,
        "file_security_block_nested_archives": True,
        "file_security_block_executable_content": True,
        "file_security_max_download_size": "0",
        "file_security_max_upload_size": "0",
        "file_security_quarantine_metadata": True,
    },
}

_PRESET_MANAGED_FIELDS: tuple[str, ...] = (
    "file_security_scan_downloads",
    "file_security_scan_uploads",
    "file_security_block_risky_extensions",
    "file_security_risky_extensions",
    "file_security_block_archives",
    "file_security_archive_extensions",
    "file_security_block_nested_archives",
    "file_security_block_executable_content",
    "file_security_executable_extensions",
    "file_security_blocked_mime_types",
    "file_security_max_download_size",
    "file_security_max_upload_size",
    "file_security_quarantine_metadata",
)

_SIZE_RE = re.compile(r"^(?:0|[1-9][0-9]*)(?:[KMG])?$", re.IGNORECASE)
_SCAN_TYPES_RE = re.compile(r"^[A-Z][A-Z0-9_]*(?:\s+[A-Z][A-Z0-9_]*)*$")
_ENGINE_RE = re.compile(r"^[A-Za-z0-9_.-]+$")
_TOKEN_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.+_-]*$")
_MIME_TOKEN_RE = re.compile(
    r"^[A-Za-z0-9][A-Za-z0-9.+_-]*/[A-Za-z0-9][A-Za-z0-9.+_-]*$",
)
_BLOCK_RE = re.compile(
    rf"^\s*{re.escape(CLAMAV_SETTINGS_START)}\s*$\n?(.*?)^\s*{re.escape(CLAMAV_SETTINGS_END)}\s*$\n?",
    re.MULTILINE | re.DOTALL,
)


@dataclass(frozen=True)
class UiChoiceSpec:
    value: str
    label: str


@dataclass(frozen=True)
class ClamavFieldSpec:
    key: str
    group: str
    label: str
    directive: str
    input_type: str
    help_text: str = ""
    placeholder: str = ""
    minimum: int | None = None
    maximum: int | None = None
    step: int | None = None
    rows: int = 3
    choices: tuple[UiChoiceSpec, ...] = ()


@dataclass(frozen=True)
class ClamavGroupSpec:
    key: str
    title: str
    description: str
    field_keys: tuple[str, ...]


@dataclass(frozen=True)
class ClamavSectionSpec:
    key: str
    label: str
    description: str
    apply_note: str
    groups: tuple[ClamavGroupSpec, ...]


def _choice(value: str, label: str) -> UiChoiceSpec:
    return UiChoiceSpec(value, label)


def _field(
    key: str, group: str, label: str, directive: str, input_type: str, **kwargs: Any,
) -> ClamavFieldSpec:
    choices = tuple(kwargs.pop("choices", ()))
    return ClamavFieldSpec(
        key, group, label, directive, input_type, choices=choices, **kwargs,
    )


CLAMAV_FIELDS: tuple[ClamavFieldSpec, ...] = (
    _field(
        "clamav_fail_mode",
        "failure",
        "Failure behavior",
        "icap_service ... bypass / virus_scan.PassOnError",
        "select",
        help_text="Fail-open keeps browsing available if AV ICAP or clamd fails. Fail-closed blocks affected transfers when scanning cannot complete.",
        choices=(_choice("open", "Fail open"), _choice("closed", "Fail closed")),
    ),
    _field(
        "file_security_preset",
        "preset",
        "Policy preset",
        "Squid + ICAP file policy",
        "select",
        help_text="Balanced is the default foundation: scan uploads and downloads, block common executable payload names, and keep size/archive limits explicit.",
        choices=(
            _choice("balanced", "Balanced"),
            _choice("monitor", "Monitor"),
            _choice("strict", "Strict"),
        ),
    ),
    _field(
        "file_security_scan_downloads",
        "coverage",
        "Scan downloads",
        "adaptation_access av_resp_set",
        "checkbox",
        help_text="Send eligible GET responses through ClamAV RESPMod scanning.",
    ),
    _field(
        "file_security_scan_uploads",
        "coverage",
        "Scan uploads",
        "adaptation_access av_req_set",
        "checkbox",
        help_text="Send POST, PUT, and PATCH request bodies through ClamAV REQMod scanning where Squid/c-icap can adapt the request.",
    ),
    _field(
        "virus_scan_scan_file_types",
        "coverage",
        "Scan data types",
        "virus_scan.ScanFileTypes",
        "text",
        help_text="Space-separated c-icap data classes. The packaged module default is TEXT DATA BINARY.",
        placeholder="TEXT DATA BINARY",
    ),
    _field(
        "virus_scan_max_object_size",
        "coverage",
        "Maximum object size",
        "virus_scan.MaxObjectSize",
        "text",
        help_text="Largest response object c-icap will scan. Use c-icap size syntax such as 64M, 128M, or 1G.",
        placeholder="128M",
    ),
    _field(
        "file_security_block_risky_extensions",
        "blocking",
        "Block risky extensions",
        "http_access deny urlpath_regex",
        "checkbox",
        help_text="Block common script, installer, and binary file names before transfer.",
    ),
    _field(
        "file_security_risky_extensions",
        "blocking",
        "Risky extensions",
        "urlpath_regex",
        "text",
        help_text="Space or comma separated extensions without leading dots.",
        placeholder="exe dll msi bat cmd com scr ps1 vbs js jar apk",
    ),
    _field(
        "file_security_block_executable_content",
        "blocking",
        "Block executable payload names",
        "http_access deny urlpath_regex / req_header Content-Type",
        "checkbox",
        help_text="Block executable-looking file names and upload content-types before they reach the destination.",
    ),
    _field(
        "file_security_executable_extensions",
        "blocking",
        "Executable extensions",
        "urlpath_regex",
        "text",
        help_text="Space or comma separated executable extensions without leading dots.",
        placeholder="exe dll msi com scr jar apk",
    ),
    _field(
        "file_security_block_archives",
        "archives",
        "Block archives",
        "http_access deny urlpath_regex",
        "checkbox",
        help_text="Block archive file names. Leave off for normal business use; enable for stricter environments.",
    ),
    _field(
        "file_security_archive_extensions",
        "archives",
        "Archive extensions",
        "urlpath_regex",
        "text",
        help_text="Space or comma separated archive extensions without leading dots.",
        placeholder="zip 7z rar tar gz bz2 xz iso",
    ),
    _field(
        "file_security_block_nested_archives",
        "archives",
        "Block nested archives",
        "Policy metadata",
        "checkbox",
        help_text="Records the stricter policy intent for downstream ICAP/content engines. Squid URL ACLs cannot prove nested archive structure by themselves.",
    ),
    _field(
        "file_security_max_download_size",
        "size",
        "Maximum download size",
        "reply_body_max_size",
        "text",
        help_text="Optional hard block for downloads above this size. 0 disables the size block.",
        placeholder="0",
    ),
    _field(
        "file_security_max_upload_size",
        "size",
        "Maximum upload size",
        "request_body_max_size",
        "text",
        help_text="Optional hard block for uploads above this size. 0 disables the size block.",
        placeholder="0",
    ),
    _field(
        "file_security_blocked_mime_types",
        "types",
        "Blocked upload content types",
        "req_header Content-Type",
        "text",
        help_text="Space or comma separated upload Content-Type hints to block when executable-content blocking is enabled.",
        placeholder="application/x-msdownload application/x-ms-installer",
    ),
    _field(
        "file_security_quarantine_metadata",
        "diagnostics",
        "Record quarantine metadata",
        "Policy diagnostics",
        "checkbox",
        help_text="Keep sample metadata in the managed policy block for diagnostics/quarantine workflows without storing file contents.",
    ),
    _field(
        "virus_scan_send_percent_data",
        "streaming",
        "Early-send percentage",
        "virus_scan.SendPercentData",
        "number",
        help_text="Percentage of response data c-icap may stream before the scan fully completes. Keep below 100 to reserve a tail for final blocking.",
        minimum=0,
        maximum=99,
        step=1,
    ),
    _field(
        "virus_scan_start_send_percent_after",
        "streaming",
        "Start early-send after",
        "virus_scan.StartSendPercentDataAfter",
        "text",
        help_text="Amount of response data c-icap should receive before early-send begins. Default 1K makes browser downloads show progress almost immediately.",
        placeholder="1K",
    ),
    _field(
        "virus_scan_allow_204_on",
        "responses",
        "Allow ICAP 204 no-modification responses",
        "virus_scan.Allow204Responces",
        "checkbox",
        help_text="Leave enabled for Squid; clean responses can return 204 instead of a rewritten body.",
    ),
    _field(
        "virus_scan_default_engine",
        "responses",
        "Default engine override",
        "virus_scan.DefaultEngine",
        "text",
        help_text="Usually blank. Leaving this unset lets virus_scan choose the first available engine after clamd_mod registers.",
        placeholder="auto",
    ),
)
CLAMAV_FIELD_MAP = {field.key: field for field in CLAMAV_FIELDS}
CLAMAV_SECTIONS = (
    ClamavSectionSpec(
        "virus_scan",
        "File security policy",
        "Schema-backed controls for file scanning, file blocking, c-icap virus_scan behavior, and Squid AV ICAP failure behavior.",
        "Applies to the selected proxy by storing managed settings in the active config revision; the proxy materializes /etc/virus_scan.conf and the local ICAP include during sync.",
        (
            ClamavGroupSpec(
                "preset",
                "Preset",
                "Start with a compact policy posture, then adjust specific controls only when needed.",
                ("file_security_preset",),
            ),
            ClamavGroupSpec(
                "failure",
                "Failure behavior",
                "Choose whether traffic is allowed or blocked when AV scanning infrastructure is unavailable.",
                ("clamav_fail_mode",),
            ),
            ClamavGroupSpec(
                "coverage",
                "Scan coverage",
                "Uploads and downloads sent to c-icap virus_scan plus object classes handled by the scanner.",
                (
                    "file_security_scan_downloads",
                    "file_security_scan_uploads",
                    "virus_scan_scan_file_types",
                    "virus_scan_max_object_size",
                ),
            ),
            ClamavGroupSpec(
                "blocking",
                "File blocking",
                "Fast Squid-side blocks for risky file names and executable-looking uploads.",
                (
                    "file_security_block_risky_extensions",
                    "file_security_risky_extensions",
                    "file_security_block_executable_content",
                    "file_security_executable_extensions",
                ),
            ),
            ClamavGroupSpec(
                "archives",
                "Archives",
                "Archive controls with explicit metadata for nested archive handling.",
                (
                    "file_security_block_archives",
                    "file_security_archive_extensions",
                    "file_security_block_nested_archives",
                ),
            ),
            ClamavGroupSpec(
                "size",
                "Size thresholds",
                "Optional hard caps for transfers that should be blocked before or during body handling.",
                ("file_security_max_download_size", "file_security_max_upload_size"),
            ),
            ClamavGroupSpec(
                "types",
                "Upload content-type hints",
                "Request Content-Type blocking where the existing Squid request path can enforce it. This is header-based, not deep file sniffing.",
                ("file_security_blocked_mime_types",),
            ),
            ClamavGroupSpec(
                "diagnostics",
                "Diagnostics",
                "Policy metadata that supports quarantine and audit trails without storing file contents.",
                ("file_security_quarantine_metadata",),
            ),
            ClamavGroupSpec(
                "streaming",
                "Download streaming",
                "Early-send controls that balance download UX against retaining enough response body to block infected objects.",
                ("virus_scan_send_percent_data", "virus_scan_start_send_percent_after"),
            ),
            ClamavGroupSpec(
                "responses",
                "Response behavior",
                "ICAP response and engine-selection behavior for clean scans.",
                ("virus_scan_allow_204_on", "virus_scan_default_engine"),
            ),
        ),
    ),
)


def get_clamav_ui_sections() -> tuple[ClamavSectionSpec, ...]:
    return CLAMAV_SECTIONS


def get_clamav_ui_field_map() -> Mapping[str, ClamavFieldSpec]:
    return CLAMAV_FIELD_MAP


def _clean_bool(value: Any, default: bool) -> bool:
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    text = str(value).strip().lower()
    if text in {"1", "true", "yes", "on"}:
        return True
    if text in {"0", "false", "no", "off"}:
        return False
    return default


def _clean_size(value: Any, default: str) -> str:
    text = str(value or "").strip().upper()
    return text if text and _SIZE_RE.match(text) else default


def _clean_scan_types(value: Any) -> str:
    text = " ".join(str(value or "").strip().upper().split())
    return (
        text
        if text and _SCAN_TYPES_RE.match(text)
        else str(DEFAULTS["virus_scan_scan_file_types"])
    )


def _clean_token_list(value: Any, default: str, *, lower: bool = True) -> str:
    raw = str(value if value is not None else default)
    tokens = []
    for item in re.split(r"[\s,]+", raw.strip()):
        token = item.strip().lstrip(".")
        if not token:
            continue
        token = token.lower() if lower else token.lower()
        if _TOKEN_RE.match(token):
            tokens.append(token)
    if not tokens:
        return str(default)
    return " ".join(dict.fromkeys(tokens))


def _split_policy_tokens(value: Any) -> tuple[str, ...]:
    text = str(value or "").strip()
    if not text:
        return ()
    tokens: list[str] = []
    for raw in re.split(r"[\s,]+", text):
        token = raw.strip().lstrip(".").lower()
        if token and _TOKEN_RE.match(token) and token not in tokens:
            tokens.append(token)
    return tuple(tokens)


def _split_mime_tokens(value: Any) -> tuple[str, ...]:
    text = str(value or "").strip()
    if not text:
        return ()
    tokens: list[str] = []
    for raw in re.split(r"[\s,]+", text):
        token = raw.strip().lower()
        if token and _MIME_TOKEN_RE.match(token) and token not in tokens:
            tokens.append(token)
    return tuple(tokens)


def _render_squid_size(size_text: str) -> str:
    text = str(size_text or "0").strip().upper()
    match = re.fullmatch(r"(\d+)([KMG])?", text)
    if not match:
        return "0"
    amount, unit = match.groups()
    if int(amount) == 0:
        return "0"
    units = {"": "MB", "K": "KB", "M": "MB", "G": "GB"}
    return f"{amount} {units[unit or '']}"


def _render_regex_tokens(tokens: tuple[str, ...]) -> str:
    if not tokens:
        return ""
    return "(?:" + "|".join(re.escape(token) for token in tokens) + ")"


def _normalize_preset_name(value: Any) -> str:
    preset = str(value or DEFAULTS["file_security_preset"]).strip().lower()
    if preset not in _PRESET_DEFAULTS:
        return str(DEFAULTS["file_security_preset"])
    return preset


def _preset_defaults(preset: Any) -> dict[str, Any]:
    defaults = dict(DEFAULTS)
    defaults.update(_PRESET_DEFAULTS.get(_normalize_preset_name(preset), {}))
    defaults["file_security_preset"] = _normalize_preset_name(preset)
    return defaults


def render_file_security_policy_config(options: Mapping[str, Any] | None = None) -> str:
    opts = normalize_clamav_options(options)
    risky_exts = _split_policy_tokens(opts["file_security_risky_extensions"])
    archive_exts = _split_policy_tokens(opts["file_security_archive_extensions"])
    exec_exts = _split_policy_tokens(opts["file_security_executable_extensions"])
    blocked_mimes = _split_mime_tokens(opts["file_security_blocked_mime_types"])

    lines = [
        "# Squid-side file security policy generated from the ClamAV page.",
        f"request_body_max_size {_render_squid_size(opts['file_security_max_upload_size'])}",
        f"reply_body_max_size {_render_squid_size(opts['file_security_max_download_size'])}",
    ]
    lines.extend(
        (
            "acl file_security_upload_methods method POST PUT PATCH",
            "acl file_security_download_methods method GET HEAD",
            "acl file_security_range_request req_header Range .+",
            "acl file_security_partial_response http_status 206",
        ),
    )

    if opts["file_security_block_risky_extensions"] and risky_exts:
        lines.append(
            f"acl file_security_risky_path urlpath_regex -i \\.{_render_regex_tokens(risky_exts)}(?:$|[?#])",
        )
    if opts["file_security_block_archives"] and archive_exts:
        lines.append(
            f"acl file_security_archive_path urlpath_regex -i \\.{_render_regex_tokens(archive_exts)}(?:$|[?#])",
        )
    if opts["file_security_block_executable_content"] and exec_exts:
        lines.append(
            f"acl file_security_executable_path urlpath_regex -i \\.{_render_regex_tokens(exec_exts)}(?:$|[?#])",
        )
    if opts["file_security_block_executable_content"] and blocked_mimes:
        lines.append(
            f"acl file_security_executable_mime req_header Content-Type -i {_render_regex_tokens(blocked_mimes)}",
        )
    if opts["file_security_block_nested_archives"]:
        lines.append(
            "# Nested archive blocking is recorded as policy metadata for downstream scanners.",
        )
    if opts["file_security_quarantine_metadata"]:
        lines.append(
            "# Quarantine metadata is retained in the managed policy block for audit trails.",
        )

    if opts["file_security_scan_uploads"]:
        lines.extend(
            [
                "adaptation_access av_req_set allow file_security_upload_methods",
                "adaptation_access av_req_set deny all",
            ],
        )
    if opts["file_security_scan_downloads"]:
        lines.extend(
            [
                "adaptation_access av_resp_set deny file_security_range_request",
                "adaptation_access av_resp_set deny file_security_partial_response",
                "adaptation_access av_resp_set allow file_security_download_methods",
                "adaptation_access av_resp_set deny all",
            ],
        )

    if opts["file_security_block_risky_extensions"] and risky_exts:
        lines.append("http_access deny file_security_risky_path")
    if opts["file_security_block_archives"] and archive_exts:
        lines.append("http_access deny file_security_archive_path")
    if opts["file_security_block_executable_content"]:
        if exec_exts:
            lines.append("http_access deny file_security_executable_path")
        if blocked_mimes:
            lines.append(
                "http_access deny file_security_executable_mime file_security_upload_methods",
            )

    return "\n".join(lines).rstrip() + "\n"


def normalize_clamav_options(values: Mapping[str, Any] | None = None) -> dict[str, Any]:
    source = values or {}
    fail_mode = (
        str(source.get("clamav_fail_mode") or DEFAULTS["clamav_fail_mode"])
        .strip()
        .lower()
    )
    if fail_mode not in {"open", "closed"}:
        fail_mode = str(DEFAULTS["clamav_fail_mode"])
    preset = _normalize_preset_name(source.get("file_security_preset"))
    preset_defaults = _preset_defaults(preset)
    try:
        send_percent = int(
            str(
                source.get(
                    "virus_scan_send_percent_data",
                    DEFAULTS["virus_scan_send_percent_data"],
                ),
            ).strip(),
        )
    except Exception:
        send_percent = int(DEFAULTS["virus_scan_send_percent_data"])
    engine = str(source.get("virus_scan_default_engine") or "").strip()
    if engine and not _ENGINE_RE.match(engine):
        engine = ""
    return {
        "clamav_fail_mode": fail_mode,
        "file_security_preset": preset,
        "file_security_scan_downloads": _clean_bool(
            source.get("file_security_scan_downloads"),
            bool(preset_defaults["file_security_scan_downloads"]),
        ),
        "file_security_scan_uploads": _clean_bool(
            source.get("file_security_scan_uploads"),
            bool(preset_defaults["file_security_scan_uploads"]),
        ),
        "file_security_block_risky_extensions": _clean_bool(
            source.get("file_security_block_risky_extensions"),
            bool(preset_defaults["file_security_block_risky_extensions"]),
        ),
        "file_security_risky_extensions": _clean_token_list(
            source.get("file_security_risky_extensions"),
            str(preset_defaults["file_security_risky_extensions"]),
        ),
        "file_security_block_archives": _clean_bool(
            source.get("file_security_block_archives"),
            bool(preset_defaults["file_security_block_archives"]),
        ),
        "file_security_archive_extensions": _clean_token_list(
            source.get("file_security_archive_extensions"),
            str(preset_defaults["file_security_archive_extensions"]),
        ),
        "file_security_block_nested_archives": _clean_bool(
            source.get("file_security_block_nested_archives"),
            bool(preset_defaults["file_security_block_nested_archives"]),
        ),
        "file_security_block_executable_content": _clean_bool(
            source.get("file_security_block_executable_content"),
            bool(preset_defaults["file_security_block_executable_content"]),
        ),
        "file_security_executable_extensions": _clean_token_list(
            source.get("file_security_executable_extensions"),
            str(preset_defaults["file_security_executable_extensions"]),
        ),
        "file_security_blocked_mime_types": " ".join(
            _split_mime_tokens(
                source.get("file_security_blocked_mime_types")
                or preset_defaults["file_security_blocked_mime_types"],
            ),
        )
        or str(preset_defaults["file_security_blocked_mime_types"]),
        "file_security_max_download_size": _clean_size(
            source.get("file_security_max_download_size"),
            str(preset_defaults["file_security_max_download_size"]),
        ),
        "file_security_max_upload_size": _clean_size(
            source.get("file_security_max_upload_size"),
            str(preset_defaults["file_security_max_upload_size"]),
        ),
        "file_security_quarantine_metadata": _clean_bool(
            source.get("file_security_quarantine_metadata"),
            bool(preset_defaults["file_security_quarantine_metadata"]),
        ),
        "virus_scan_scan_file_types": _clean_scan_types(
            source.get("virus_scan_scan_file_types"),
        ),
        "virus_scan_send_percent_data": max(0, min(99, send_percent)),
        "virus_scan_start_send_percent_after": _clean_size(
            source.get("virus_scan_start_send_percent_after"),
            str(DEFAULTS["virus_scan_start_send_percent_after"]),
        ),
        "virus_scan_allow_204_on": _clean_bool(
            source.get("virus_scan_allow_204_on"),
            bool(DEFAULTS["virus_scan_allow_204_on"]),
        ),
        "virus_scan_max_object_size": _clean_size(
            source.get("virus_scan_max_object_size"),
            str(DEFAULTS["virus_scan_max_object_size"]),
        ),
        "virus_scan_default_engine": engine,
    }


def extract_clamav_options(config_text: str | None) -> dict[str, Any]:
    values: dict[str, Any] = {}
    match = _BLOCK_RE.search(config_text or "")
    if match:
        for raw_line in (match.group(1) or "").splitlines():
            line = raw_line.strip()
            if line.startswith("#"):
                line = line[1:].strip()
            if ":" not in line:
                continue
            key, value = line.split(":", 1)
            if key.strip() in DEFAULTS:
                values[key.strip()] = value.strip()
    return normalize_clamav_options(values)


def read_clamav_options_from_form(
    form: FormMap, current: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    current_values = normalize_clamav_options(current)
    values = dict(current_values)
    requested_preset = _normalize_preset_name(
        form.get("file_security_preset", current_values.get("file_security_preset")),
    )
    preset_changed = requested_preset != current_values.get("file_security_preset")
    for field in CLAMAV_FIELDS:
        if field.input_type == "checkbox":
            if field.key in form:
                values[field.key] = form.get(field.key) == "on"
            elif not preset_changed:
                values[field.key] = False
        elif field.key in form:
            values[field.key] = form.get(field.key)
    selected_preset = _normalize_preset_name(values.get("file_security_preset"))
    if preset_changed:
        preset_values = normalize_clamav_options(
            {"file_security_preset": selected_preset},
        )
        for key in _PRESET_MANAGED_FIELDS:
            if values.get(key) == current_values.get(key):
                values[key] = preset_values[key]
    return normalize_clamav_options(values)


def render_clamav_settings_block(options: Mapping[str, Any] | None = None) -> str:
    opts = normalize_clamav_options(options)
    lines = [
        CLAMAV_SETTINGS_START,
        "# Managed by the ClamAV page. These comment values are materialized by the selected proxy runtime.",
    ]
    for field in CLAMAV_FIELDS:
        value = opts[field.key]
        lines.append(
            f"# {field.key}: {'on' if value is True else 'off' if value is False else value}",
        )
    lines.append(CLAMAV_SETTINGS_END)
    return "\n".join(lines) + "\n"


def apply_clamav_options_to_config(
    config_text: str, options: Mapping[str, Any] | None = None,
) -> str:
    text = _BLOCK_RE.sub("", config_text or "").rstrip() + "\n"
    block = render_clamav_settings_block(options)
    anchor = re.search(
        r"^\s*(#\s*)?adaptation_access\s+av_resp_set\s+",
        text,
        re.IGNORECASE | re.MULTILINE,
    )
    if anchor:
        return text[: anchor.start()] + block + text[anchor.start() :]
    return text.rstrip() + "\n" + block


def clamav_fail_open(options: Mapping[str, Any] | None = None) -> bool:
    return normalize_clamav_options(options).get("clamav_fail_mode") != "closed"


def render_virus_scan_config(options: Mapping[str, Any] | None = None) -> str:
    opts = normalize_clamav_options(options)
    lines = [
        "# c-icap virus_scan configuration for squid-flask-proxy",
        "# Managed by the ClamAV page; defaults match the packaged container config.",
        "",
        "# Keep scanning focused.",
        f"virus_scan.ScanFileTypes {opts['virus_scan_scan_file_types']}",
        "",
        "# Stream partial content quickly while scanning continues; keep SendPercentData below 100.",
        f"virus_scan.SendPercentData {opts['virus_scan_send_percent_data']}",
        f"virus_scan.StartSendPercentDataAfter {opts['virus_scan_start_send_percent_after']}",
        "",
        "# Scanner/service error behavior.",
        f"virus_scan.PassOnError {'on' if clamav_fail_open(opts) else 'off'}",
        "",
        "# Squid supports 204 responses for clean objects.",
        f"virus_scan.Allow204Responces {'on' if opts['virus_scan_allow_204_on'] else 'off'}",
        "",
        "# Max object size to scan.",
        f"virus_scan.MaxObjectSize {opts['virus_scan_max_object_size']}",
        "",
        "# Select the default engine.",
    ]
    if opts["virus_scan_default_engine"]:
        lines.append(f"virus_scan.DefaultEngine {opts['virus_scan_default_engine']}")
    else:
        lines.extend(
            [
                "# Leaving this unset lets virus_scan pick the first available engine after clamd_mod registers.",
                "# virus_scan.DefaultEngine clamd",
            ],
        )
    return "\n".join(lines).rstrip() + "\n"

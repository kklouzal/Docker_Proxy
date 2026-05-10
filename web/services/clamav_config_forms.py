from __future__ import annotations

from dataclasses import dataclass
import re
from typing import Any, Mapping

FormMap = Mapping[str, Any]
CLAMAV_SETTINGS_START = '# BEGIN SQUID-UI CLAMAV SETTINGS'
CLAMAV_SETTINGS_END = '# END SQUID-UI CLAMAV SETTINGS'

DEFAULTS: dict[str, Any] = {
    'clamav_fail_mode': 'open',
    'virus_scan_scan_file_types': 'TEXT DATA BINARY',
    'virus_scan_send_percent_data': 99,
    'virus_scan_start_send_percent_after': '32K',
    'virus_scan_allow_204_on': True,
    'virus_scan_max_object_size': '128M',
    'virus_scan_default_engine': '',
}

_SIZE_RE = re.compile(r'^(?:0|[1-9][0-9]*)(?:[KMG])?$', re.I)
_SCAN_TYPES_RE = re.compile(r'^[A-Z][A-Z0-9_]*(?:\s+[A-Z][A-Z0-9_]*)*$')
_ENGINE_RE = re.compile(r'^[A-Za-z0-9_.-]+$')
_BLOCK_RE = re.compile(rf'^\s*{re.escape(CLAMAV_SETTINGS_START)}\s*$\n?(.*?)^\s*{re.escape(CLAMAV_SETTINGS_END)}\s*$\n?', re.M | re.S)

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
    help_text: str = ''
    placeholder: str = ''
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

def _field(key: str, group: str, label: str, directive: str, input_type: str, **kwargs: Any) -> ClamavFieldSpec:
    choices = tuple(kwargs.pop('choices', ()))
    return ClamavFieldSpec(key, group, label, directive, input_type, choices=choices, **kwargs)

CLAMAV_FIELDS: tuple[ClamavFieldSpec, ...] = (
    _field('clamav_fail_mode', 'failure', 'Failure behavior', 'icap_service ... bypass / virus_scan.PassOnError', 'select', help_text='Fail-open keeps browsing available if AV ICAP or clamd fails. Fail-closed blocks affected transfers when scanning cannot complete.', choices=(_choice('open', 'Fail open'), _choice('closed', 'Fail closed'))),
    _field('virus_scan_scan_file_types', 'coverage', 'Scan data types', 'virus_scan.ScanFileTypes', 'text', help_text='Space-separated c-icap data classes. The packaged module default is TEXT DATA BINARY.', placeholder='TEXT DATA BINARY'),
    _field('virus_scan_max_object_size', 'coverage', 'Maximum object size', 'virus_scan.MaxObjectSize', 'text', help_text='Largest response object c-icap will scan. Use c-icap size syntax such as 64M, 128M, or 1G.', placeholder='128M'),
    _field('virus_scan_send_percent_data', 'streaming', 'Early-send percentage', 'virus_scan.SendPercentData', 'number', help_text='Percentage of response data c-icap may stream before the scan fully completes. Keep below 100 to reserve a tail for final blocking.', minimum=0, maximum=99, step=1),
    _field('virus_scan_start_send_percent_after', 'streaming', 'Start early-send after', 'virus_scan.StartSendPercentDataAfter', 'text', help_text='Amount of response data c-icap should receive before early-send begins. Default 32K keeps browser downloads responsive.', placeholder='32K'),
    _field('virus_scan_allow_204_on', 'responses', 'Allow ICAP 204 no-modification responses', 'virus_scan.Allow204Responces', 'checkbox', help_text='Leave enabled for Squid; clean responses can return 204 instead of a rewritten body.'),
    _field('virus_scan_default_engine', 'responses', 'Default engine override', 'virus_scan.DefaultEngine', 'text', help_text='Usually blank. Leaving this unset lets virus_scan choose the first available engine after clamd_mod registers.', placeholder='auto'),
)
CLAMAV_FIELD_MAP = {field.key: field for field in CLAMAV_FIELDS}
CLAMAV_SECTIONS = (
    ClamavSectionSpec('virus_scan', 'virus_scan', 'Schema-backed controls for the container-local c-icap virus_scan service and Squid AV ICAP failure behavior.', 'Applies to the selected proxy by storing managed settings in the active config revision; the proxy materializes /etc/virus_scan.conf and the local ICAP include during sync.', (
        ClamavGroupSpec('failure', 'Failure behavior', 'Choose whether traffic is allowed or blocked when AV scanning infrastructure is unavailable.', ('clamav_fail_mode',)),
        ClamavGroupSpec('coverage', 'Scan coverage', 'Object classes and size ceilings handled by c-icap virus_scan.', ('virus_scan_scan_file_types', 'virus_scan_max_object_size')),
        ClamavGroupSpec('streaming', 'Download streaming', 'Early-send controls that balance download UX against retaining enough response body to block infected objects.', ('virus_scan_send_percent_data', 'virus_scan_start_send_percent_after')),
        ClamavGroupSpec('responses', 'Response behavior', 'ICAP response and engine-selection behavior for clean scans.', ('virus_scan_allow_204_on', 'virus_scan_default_engine')),
    )),
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
    if text in {'1', 'true', 'yes', 'on'}:
        return True
    if text in {'0', 'false', 'no', 'off'}:
        return False
    return default

def _clean_size(value: Any, default: str) -> str:
    text = str(value or '').strip().upper()
    return text if text and _SIZE_RE.match(text) else default

def _clean_scan_types(value: Any) -> str:
    text = ' '.join(str(value or '').strip().upper().split())
    return text if text and _SCAN_TYPES_RE.match(text) else str(DEFAULTS['virus_scan_scan_file_types'])

def normalize_clamav_options(values: Mapping[str, Any] | None = None) -> dict[str, Any]:
    source = values or {}
    fail_mode = str(source.get('clamav_fail_mode') or DEFAULTS['clamav_fail_mode']).strip().lower()
    if fail_mode not in {'open', 'closed'}:
        fail_mode = str(DEFAULTS['clamav_fail_mode'])
    try:
        send_percent = int(str(source.get('virus_scan_send_percent_data', DEFAULTS['virus_scan_send_percent_data'])).strip())
    except Exception:
        send_percent = int(DEFAULTS['virus_scan_send_percent_data'])
    engine = str(source.get('virus_scan_default_engine') or '').strip()
    if engine and not _ENGINE_RE.match(engine):
        engine = ''
    return {
        'clamav_fail_mode': fail_mode,
        'virus_scan_scan_file_types': _clean_scan_types(source.get('virus_scan_scan_file_types')),
        'virus_scan_send_percent_data': max(0, min(99, send_percent)),
        'virus_scan_start_send_percent_after': _clean_size(source.get('virus_scan_start_send_percent_after'), str(DEFAULTS['virus_scan_start_send_percent_after'])),
        'virus_scan_allow_204_on': _clean_bool(source.get('virus_scan_allow_204_on'), bool(DEFAULTS['virus_scan_allow_204_on'])),
        'virus_scan_max_object_size': _clean_size(source.get('virus_scan_max_object_size'), str(DEFAULTS['virus_scan_max_object_size'])),
        'virus_scan_default_engine': engine,
    }

def extract_clamav_options(config_text: str | None) -> dict[str, Any]:
    values: dict[str, Any] = {}
    match = _BLOCK_RE.search(config_text or '')
    if match:
        for raw_line in (match.group(1) or '').splitlines():
            line = raw_line.strip()
            if line.startswith('#'):
                line = line[1:].strip()
            if ':' not in line:
                continue
            key, value = line.split(':', 1)
            if key.strip() in DEFAULTS:
                values[key.strip()] = value.strip()
    return normalize_clamav_options(values)

def read_clamav_options_from_form(form: FormMap, current: Mapping[str, Any] | None = None) -> dict[str, Any]:
    values = dict(current or {})
    for field in CLAMAV_FIELDS:
        if field.input_type == 'checkbox':
            values[field.key] = form.get(field.key) == 'on'
        elif field.key in form:
            values[field.key] = form.get(field.key)
    return normalize_clamav_options(values)

def render_clamav_settings_block(options: Mapping[str, Any] | None = None) -> str:
    opts = normalize_clamav_options(options)
    lines = [CLAMAV_SETTINGS_START, '# Managed by the ClamAV page. These comment values are materialized by the selected proxy runtime.']
    for field in CLAMAV_FIELDS:
        value = opts[field.key]
        lines.append(f"# {field.key}: {'on' if value is True else 'off' if value is False else value}")
    lines.append(CLAMAV_SETTINGS_END)
    return '\n'.join(lines) + '\n'

def apply_clamav_options_to_config(config_text: str, options: Mapping[str, Any] | None = None) -> str:
    text = _BLOCK_RE.sub('', config_text or '').rstrip() + '\n'
    block = render_clamav_settings_block(options)
    anchor = re.search(r'^\s*(#\s*)?adaptation_access\s+av_resp_set\s+', text, re.I | re.M)
    if anchor:
        return text[:anchor.start()] + block + text[anchor.start():]
    return text.rstrip() + '\n' + block

def clamav_fail_open(options: Mapping[str, Any] | None = None) -> bool:
    return normalize_clamav_options(options).get('clamav_fail_mode') != 'closed'

def render_virus_scan_config(options: Mapping[str, Any] | None = None) -> str:
    opts = normalize_clamav_options(options)
    lines = [
        '# c-icap virus_scan configuration for squid-flask-proxy',
        '# Managed by the ClamAV page; defaults match the packaged container config.',
        '',
        '# Keep scanning focused.',
        f"virus_scan.ScanFileTypes {opts['virus_scan_scan_file_types']}",
        '',
        '# Stream partial content while scanning continues; keep SendPercentData below 100.',
        f"virus_scan.SendPercentData {opts['virus_scan_send_percent_data']}",
        f"virus_scan.StartSendPercentDataAfter {opts['virus_scan_start_send_percent_after']}",
        '',
        '# Scanner/service error behavior.',
        f"virus_scan.PassOnError {'on' if clamav_fail_open(opts) else 'off'}",
        '',
        '# Squid supports 204 responses for clean objects.',
        f"virus_scan.Allow204Responces {'on' if opts['virus_scan_allow_204_on'] else 'off'}",
        '',
        '# Max object size to scan.',
        f"virus_scan.MaxObjectSize {opts['virus_scan_max_object_size']}",
        '',
        '# Select the default engine.',
    ]
    if opts['virus_scan_default_engine']:
        lines.append(f"virus_scan.DefaultEngine {opts['virus_scan_default_engine']}")
    else:
        lines.extend(['# Leaving this unset lets virus_scan pick the first available engine after clamd_mod registers.', '# virus_scan.DefaultEngine clamd'])
    return '\n'.join(lines).rstrip() + '\n'

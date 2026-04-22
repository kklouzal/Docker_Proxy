from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Mapping, MutableMapping


TunableMap = Mapping[str, Any]
FormMap = Mapping[str, Any]
OptionMap = MutableMapping[str, Any]
OptionResolver = Callable[[TunableMap, int], Any]
FieldReader = Callable[[FormMap, Any, int], tuple[bool, Any]]


@dataclass(frozen=True)
class OptionDefaultSpec:
    key: str
    resolver: OptionResolver


@dataclass(frozen=True)
class FormFieldSpec:
    key: str
    reader: FieldReader


def _tunable_or_default(key: str, default: Any) -> OptionResolver:
    def resolve(tunables: TunableMap, _max_workers: int) -> Any:
        value = tunables.get(key)
        return value or default

    return resolve



def _tunable_or_default_if_none(key: str, default: Any) -> OptionResolver:
    def resolve(tunables: TunableMap, _max_workers: int) -> Any:
        value = tunables.get(key)
        return value if value is not None else default

    return resolve



def _tunable_bool_or_default(key: str, default: bool) -> OptionResolver:
    def resolve(tunables: TunableMap, _max_workers: int) -> bool:
        value = tunables.get(key)
        return bool(value) if value is not None else default

    return resolve



def _tunable_optional(key: str) -> OptionResolver:
    def resolve(tunables: TunableMap, _max_workers: int) -> Any:
        value = tunables.get(key)
        return value if value is not None else None

    return resolve



def _resolve_workers(tunables: TunableMap, max_workers: int) -> int:
    try:
        value = int(tunables.get("workers") or 1)
    except Exception:
        value = 1
    return min(max_workers, max(1, value))



def _resolve_range_cache(tunables: TunableMap, _max_workers: int) -> bool:
    value = tunables.get("range_offset_limit")
    return (value != 0) if value is not None else True



def _coerce_current_int(current: Any, default: int = 0) -> int:
    try:
        return int(current)
    except Exception:
        return default



def _posted_int_reader(field: str, *, clamp: Callable[[int, int], int] | None = None) -> FieldReader:
    def reader(form: FormMap, current: Any, max_workers: int) -> tuple[bool, Any]:
        raw = form.get(field)
        if raw is None:
            return False, current
        try:
            value = int(str(raw).strip())
        except ValueError:
            value = _coerce_current_int(current)
        if clamp is not None:
            value = clamp(value, max_workers)
        return True, value

    return reader



def _posted_optional_int_reader(field: str) -> FieldReader:
    def reader(form: FormMap, current: Any, _max_workers: int) -> tuple[bool, Any]:
        raw = form.get(field)
        if raw is None:
            return False, current
        text = str(raw).strip()
        if text == "":
            return False, current
        try:
            return True, int(text)
        except ValueError:
            return False, current

    return reader



def _posted_string_reader(field: str, *, default: str = "") -> FieldReader:
    def reader(form: FormMap, current: Any, _max_workers: int) -> tuple[bool, Any]:
        raw = form.get(field)
        if raw is None:
            return False, current
        fallback = str(current or default)
        return True, str(raw).strip() or fallback

    return reader



def _posted_nonempty_string_reader(field: str) -> FieldReader:
    def reader(form: FormMap, current: Any, _max_workers: int) -> tuple[bool, Any]:
        raw = form.get(field)
        if raw is None:
            return False, current
        text = str(raw).strip()
        if text == "":
            return False, current
        return True, text

    return reader



def _checkbox_reader(field: str) -> FieldReader:
    def reader(form: FormMap, current: Any, _max_workers: int) -> tuple[bool, Any]:
        return True, field in form

    return reader



def _clamp_workers(value: int, max_workers: int) -> int:
    return min(max_workers, max(1, int(value)))


OPTION_DEFAULT_SPECS: tuple[OptionDefaultSpec, ...] = (
    OptionDefaultSpec("cache_dir_size_mb", _tunable_or_default("cache_dir_size_mb", 10000)),
    OptionDefaultSpec("cache_mem_mb", _tunable_or_default("cache_mem_mb", 96)),
    OptionDefaultSpec("maximum_object_size_mb", _tunable_or_default("maximum_object_size_mb", 64)),
    OptionDefaultSpec("maximum_object_size_in_memory_kb", _tunable_or_default("maximum_object_size_in_memory_kb", 1024)),
    OptionDefaultSpec("minimum_object_size_kb", _tunable_or_default_if_none("minimum_object_size_kb", 0)),
    OptionDefaultSpec("cache_swap_low", _tunable_or_default("cache_swap_low", 90)),
    OptionDefaultSpec("cache_swap_high", _tunable_or_default("cache_swap_high", 95)),
    OptionDefaultSpec("collapsed_forwarding_on", _tunable_bool_or_default("collapsed_forwarding", True)),
    OptionDefaultSpec("range_cache_on", _resolve_range_cache),
    OptionDefaultSpec("workers", _resolve_workers),
    OptionDefaultSpec("cache_replacement_policy", _tunable_or_default("cache_replacement_policy", "heap GDSF")),
    OptionDefaultSpec("memory_replacement_policy", _tunable_or_default("memory_replacement_policy", "heap GDSF")),
    OptionDefaultSpec("pipeline_prefetch_on", _tunable_bool_or_default("pipeline_prefetch", True)),
    OptionDefaultSpec("client_persistent_connections_on", _tunable_bool_or_default("client_persistent_connections", True)),
    OptionDefaultSpec("server_persistent_connections_on", _tunable_bool_or_default("server_persistent_connections", True)),
    OptionDefaultSpec("negative_ttl_seconds", _tunable_optional("negative_ttl_seconds")),
    OptionDefaultSpec("positive_dns_ttl_seconds", _tunable_optional("positive_dns_ttl_seconds")),
    OptionDefaultSpec("negative_dns_ttl_seconds", _tunable_optional("negative_dns_ttl_seconds")),
    OptionDefaultSpec("read_ahead_gap_kb", _tunable_optional("read_ahead_gap_kb")),
    OptionDefaultSpec("quick_abort_min_kb", _tunable_or_default_if_none("quick_abort_min_kb", 0)),
    OptionDefaultSpec("quick_abort_max_kb", _tunable_or_default_if_none("quick_abort_max_kb", 0)),
    OptionDefaultSpec("quick_abort_pct", _tunable_or_default_if_none("quick_abort_pct", 100)),
    OptionDefaultSpec("connect_timeout_seconds", _tunable_or_default_if_none("connect_timeout_seconds", 90)),
    OptionDefaultSpec("request_timeout_seconds", _tunable_or_default_if_none("request_timeout_seconds", 1800)),
    OptionDefaultSpec("read_timeout_seconds", _tunable_or_default_if_none("read_timeout_seconds", 1800)),
    OptionDefaultSpec("forward_timeout_seconds", _tunable_or_default_if_none("forward_timeout_seconds", 1800)),
    OptionDefaultSpec("shutdown_lifetime_seconds", _tunable_or_default_if_none("shutdown_lifetime_seconds", 30)),
    OptionDefaultSpec("logfile_rotate", _tunable_or_default_if_none("logfile_rotate", 10)),
    OptionDefaultSpec("pconn_timeout_seconds", _tunable_or_default_if_none("pconn_timeout_seconds", 120)),
    OptionDefaultSpec("client_lifetime_seconds", _tunable_or_default_if_none("client_lifetime_seconds", 3600)),
    OptionDefaultSpec("max_filedescriptors", _tunable_or_default_if_none("max_filedescriptors", 8192)),
    OptionDefaultSpec("dns_timeout_seconds", _tunable_or_default_if_none("dns_timeout_seconds", 5)),
    OptionDefaultSpec("dns_nameservers", _tunable_or_default("dns_nameservers", "")),
    OptionDefaultSpec("hosts_file", _tunable_or_default("hosts_file", "")),
    OptionDefaultSpec("ipcache_size", _tunable_or_default_if_none("ipcache_size", 8192)),
    OptionDefaultSpec("fqdncache_size", _tunable_or_default_if_none("fqdncache_size", 8192)),
    OptionDefaultSpec("sslcrtd_children", _tunable_or_default_if_none("sslcrtd_children", 8)),
    OptionDefaultSpec("icap_enable_on", _tunable_bool_or_default("icap_enable", True)),
    OptionDefaultSpec("icap_send_client_ip_on", _tunable_bool_or_default("icap_send_client_ip", True)),
    OptionDefaultSpec("icap_send_client_username_on", _tunable_bool_or_default("icap_send_client_username", False)),
    OptionDefaultSpec("icap_preview_enable_on", _tunable_bool_or_default("icap_preview_enable", False)),
    OptionDefaultSpec("icap_preview_size_kb", _tunable_optional("icap_preview_size_kb")),
    OptionDefaultSpec("icap_connect_timeout_seconds", _tunable_or_default_if_none("icap_connect_timeout_seconds", 60)),
    OptionDefaultSpec("icap_io_timeout_seconds", _tunable_or_default_if_none("icap_io_timeout_seconds", 600)),
    OptionDefaultSpec("forwarded_for_value", _tunable_or_default("forwarded_for_value", "")),
    OptionDefaultSpec("via_on", _tunable_optional("via")),
    OptionDefaultSpec("follow_x_forwarded_for_value", _tunable_or_default("follow_x_forwarded_for_value", "")),
    OptionDefaultSpec("request_header_max_size_kb", _tunable_optional("request_header_max_size_kb")),
    OptionDefaultSpec("reply_header_max_size_kb", _tunable_optional("reply_header_max_size_kb")),
    OptionDefaultSpec("request_body_max_size_mb", _tunable_optional("request_body_max_size_mb")),
    OptionDefaultSpec("client_request_buffer_max_size_kb", _tunable_optional("client_request_buffer_max_size_kb")),
    OptionDefaultSpec("memory_pools_on", _tunable_optional("memory_pools")),
    OptionDefaultSpec("memory_pools_limit_mb", _tunable_optional("memory_pools_limit_mb")),
    OptionDefaultSpec("store_avg_object_size_kb", _tunable_optional("store_avg_object_size_kb")),
    OptionDefaultSpec("store_objects_per_bucket", _tunable_optional("store_objects_per_bucket")),
    OptionDefaultSpec("visible_hostname", _tunable_or_default("visible_hostname", "")),
    OptionDefaultSpec("httpd_suppress_version_string_on", _tunable_optional("httpd_suppress_version_string")),
)


FORM_KIND_FIELD_SPECS: dict[str, tuple[FormFieldSpec, ...]] = {
    "caching": (
        FormFieldSpec("cache_dir_size_mb", _posted_int_reader("cache_dir_size_mb")),
        FormFieldSpec("cache_mem_mb", _posted_int_reader("cache_mem_mb")),
        FormFieldSpec("maximum_object_size_mb", _posted_int_reader("maximum_object_size_mb")),
        FormFieldSpec("maximum_object_size_in_memory_kb", _posted_int_reader("maximum_object_size_in_memory_kb")),
        FormFieldSpec("minimum_object_size_kb", _posted_int_reader("minimum_object_size_kb")),
        FormFieldSpec("cache_swap_low", _posted_int_reader("cache_swap_low")),
        FormFieldSpec("cache_swap_high", _posted_int_reader("cache_swap_high")),
        FormFieldSpec("collapsed_forwarding_on", _checkbox_reader("collapsed_forwarding_on")),
        FormFieldSpec("range_cache_on", _checkbox_reader("range_cache_on")),
        FormFieldSpec("workers", _posted_int_reader("workers", clamp=_clamp_workers)),
        FormFieldSpec("cache_replacement_policy", _posted_string_reader("cache_replacement_policy", default="heap GDSF")),
        FormFieldSpec("memory_replacement_policy", _posted_string_reader("memory_replacement_policy", default="heap GDSF")),
        FormFieldSpec("pipeline_prefetch_on", _checkbox_reader("pipeline_prefetch_on")),
        FormFieldSpec("client_persistent_connections_on", _checkbox_reader("client_persistent_connections_on")),
        FormFieldSpec("server_persistent_connections_on", _checkbox_reader("server_persistent_connections_on")),
        FormFieldSpec("negative_ttl_seconds", _posted_optional_int_reader("negative_ttl_seconds")),
        FormFieldSpec("positive_dns_ttl_seconds", _posted_optional_int_reader("positive_dns_ttl_seconds")),
        FormFieldSpec("negative_dns_ttl_seconds", _posted_optional_int_reader("negative_dns_ttl_seconds")),
        FormFieldSpec("read_ahead_gap_kb", _posted_optional_int_reader("read_ahead_gap_kb")),
        FormFieldSpec("quick_abort_min_kb", _posted_int_reader("quick_abort_min_kb")),
        FormFieldSpec("quick_abort_max_kb", _posted_int_reader("quick_abort_max_kb")),
        FormFieldSpec("quick_abort_pct", _posted_int_reader("quick_abort_pct")),
    ),
    "timeouts": (
        FormFieldSpec("connect_timeout_seconds", _posted_int_reader("connect_timeout_seconds")),
        FormFieldSpec("request_timeout_seconds", _posted_int_reader("request_timeout_seconds")),
        FormFieldSpec("read_timeout_seconds", _posted_int_reader("read_timeout_seconds")),
        FormFieldSpec("forward_timeout_seconds", _posted_int_reader("forward_timeout_seconds")),
        FormFieldSpec("shutdown_lifetime_seconds", _posted_int_reader("shutdown_lifetime_seconds")),
    ),
    "logging": (
        FormFieldSpec("logfile_rotate", _posted_int_reader("logfile_rotate")),
    ),
    "network": (
        FormFieldSpec("pconn_timeout_seconds", _posted_int_reader("pconn_timeout_seconds")),
        FormFieldSpec("client_lifetime_seconds", _posted_int_reader("client_lifetime_seconds")),
        FormFieldSpec("max_filedescriptors", _posted_int_reader("max_filedescriptors")),
    ),
    "dns": (
        FormFieldSpec("dns_nameservers", _posted_nonempty_string_reader("dns_nameservers")),
        FormFieldSpec("hosts_file", _posted_nonempty_string_reader("hosts_file")),
        FormFieldSpec("dns_timeout_seconds", _posted_int_reader("dns_timeout_seconds")),
        FormFieldSpec("ipcache_size", _posted_int_reader("ipcache_size")),
        FormFieldSpec("fqdncache_size", _posted_int_reader("fqdncache_size")),
    ),
    "ssl": (
        FormFieldSpec("sslcrtd_children", _posted_int_reader("sslcrtd_children")),
    ),
    "icap": (
        FormFieldSpec("icap_enable_on", _checkbox_reader("icap_enable_on")),
        FormFieldSpec("icap_send_client_ip_on", _checkbox_reader("icap_send_client_ip_on")),
        FormFieldSpec("icap_send_client_username_on", _checkbox_reader("icap_send_client_username_on")),
        FormFieldSpec("icap_preview_enable_on", _checkbox_reader("icap_preview_enable_on")),
        FormFieldSpec("icap_preview_size_kb", _posted_optional_int_reader("icap_preview_size_kb")),
        FormFieldSpec("icap_connect_timeout_seconds", _posted_int_reader("icap_connect_timeout_seconds")),
        FormFieldSpec("icap_io_timeout_seconds", _posted_int_reader("icap_io_timeout_seconds")),
    ),
    "privacy": (
        FormFieldSpec("via_on", _checkbox_reader("via_on")),
        FormFieldSpec("forwarded_for_value", _posted_nonempty_string_reader("forwarded_for_value")),
        FormFieldSpec("follow_x_forwarded_for_value", _posted_nonempty_string_reader("follow_x_forwarded_for_value")),
    ),
    "limits": (
        FormFieldSpec("request_header_max_size_kb", _posted_optional_int_reader("request_header_max_size_kb")),
        FormFieldSpec("reply_header_max_size_kb", _posted_optional_int_reader("reply_header_max_size_kb")),
        FormFieldSpec("request_body_max_size_mb", _posted_optional_int_reader("request_body_max_size_mb")),
        FormFieldSpec("client_request_buffer_max_size_kb", _posted_optional_int_reader("client_request_buffer_max_size_kb")),
    ),
    "performance": (
        FormFieldSpec("memory_pools_on", _checkbox_reader("memory_pools_on")),
        FormFieldSpec("memory_pools_limit_mb", _posted_optional_int_reader("memory_pools_limit_mb")),
        FormFieldSpec("store_avg_object_size_kb", _posted_optional_int_reader("store_avg_object_size_kb")),
        FormFieldSpec("store_objects_per_bucket", _posted_optional_int_reader("store_objects_per_bucket")),
    ),
    "http": (
        FormFieldSpec("httpd_suppress_version_string_on", _checkbox_reader("httpd_suppress_version_string_on")),
        FormFieldSpec("visible_hostname", _posted_nonempty_string_reader("visible_hostname")),
    ),
}


SAFE_FORM_KINDS = frozenset(FORM_KIND_FIELD_SPECS)


CACHE_OVERRIDE_FIELDS: tuple[str, ...] = (
    "client_no_cache",
    "client_no_store",
    "origin_private",
    "origin_no_store",
    "origin_no_cache",
    "ignore_auth",
)



def normalize_safe_form_kind(form_kind: object | None) -> str:
    candidate = str(form_kind or "caching").strip().lower()
    return candidate if candidate in SAFE_FORM_KINDS else "caching"



def build_template_options(tunables: TunableMap, *, max_workers: int) -> dict[str, Any]:
    return {spec.key: spec.resolver(tunables, max_workers) for spec in OPTION_DEFAULT_SPECS}



def apply_form_overrides(
    options: OptionMap,
    form: FormMap,
    *,
    form_kind: str,
    max_workers: int,
) -> OptionMap:
    for spec in FORM_KIND_FIELD_SPECS.get(form_kind, ()):
        should_update, value = spec.reader(form, options.get(spec.key), max_workers)
        if should_update:
            options[spec.key] = value
    return options



def build_template_options_from_form(
    tunables: TunableMap,
    form: FormMap,
    *,
    form_kind: str,
    max_workers: int,
) -> dict[str, Any]:
    options = build_template_options(tunables, max_workers=max_workers)
    apply_form_overrides(options, form, form_kind=form_kind, max_workers=max_workers)
    return options



def parse_cache_override_form(form: FormMap) -> dict[str, bool]:
    return {field: form.get(f"override_{field}") == "on" for field in CACHE_OVERRIDE_FIELDS}

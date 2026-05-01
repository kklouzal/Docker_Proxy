from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Iterable, Mapping, MutableMapping


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


def _tunable_choice_or_default(key: str, allowed: Iterable[str], default: str) -> OptionResolver:
    allowed_values = tuple(allowed)

    def resolve(tunables: TunableMap, _max_workers: int) -> str:
        value = str(tunables.get(key) or "").strip()
        return value if value in allowed_values else default

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


def _current_workers(tunables: TunableMap, max_workers: int) -> int:
    try:
        value = int(tunables.get("workers") or 1)
    except Exception:
        value = 1
    return min(max_workers, max(1, value))


def _resolve_sslcrtd_children(tunables: TunableMap, max_workers: int) -> int:
    value = tunables.get("sslcrtd_children")
    if value is not None:
        try:
            return min(32, max(1, int(value)))
        except Exception:
            pass
    workers = _current_workers(tunables, max_workers)
    return min(32, max(4, workers * 4))


def _resolve_sslcrtd_children_startup(tunables: TunableMap, max_workers: int) -> int:
    value = tunables.get("sslcrtd_children_startup")
    if value is not None:
        try:
            return max(0, int(value))
        except Exception:
            pass
    workers = _current_workers(tunables, max_workers)
    children = _resolve_sslcrtd_children(tunables, max_workers)
    return min(children, max(2, workers))


def _resolve_sslcrtd_children_idle(tunables: TunableMap, max_workers: int) -> int:
    value = tunables.get("sslcrtd_children_idle")
    if value is not None:
        try:
            return max(1, int(value))
        except Exception:
            pass
    workers = _current_workers(tunables, max_workers)
    return max(1, min(4, workers))


def _resolve_sslcrtd_children_queue_size(tunables: TunableMap, max_workers: int) -> int:
    value = tunables.get("sslcrtd_children_queue_size")
    if value is not None:
        try:
            return max(1, int(value))
        except Exception:
            pass
    children = _resolve_sslcrtd_children(tunables, max_workers)
    return min(256, max(32, children * 8))


def _resolve_dynamic_cert_mem_cache_mb(tunables: TunableMap, max_workers: int) -> int:
    value = tunables.get("dynamic_cert_mem_cache_size_mb")
    if value is not None:
        try:
            return max(0, int(value))
        except Exception:
            pass
    workers = _current_workers(tunables, max_workers)
    derived = workers * 128
    return min(512, max(128, derived))


def _resolve_memory_cache_shared_on(tunables: TunableMap, max_workers: int) -> bool:
    value = tunables.get("memory_cache_shared")
    if value is not None:
        return bool(value)
    workers = _current_workers(tunables, max_workers)
    return workers > 1


def _resolve_shared_transient_entries_limit(tunables: TunableMap, max_workers: int) -> int:
    value = tunables.get("shared_transient_entries_limit")
    if value is not None:
        try:
            return max(0, int(value))
        except Exception:
            pass
    workers = _current_workers(tunables, max_workers)
    if workers <= 1:
        return 8192
    return max(32768, workers * 8192)


def _resolve_sslproxy_session_cache_size_mb(tunables: TunableMap, max_workers: int) -> int:
    value = tunables.get("sslproxy_session_cache_size_mb")
    if value is not None:
        try:
            return max(0, int(value))
        except Exception:
            pass
    workers = _current_workers(tunables, max_workers)
    return min(32, max(16, workers * 8))



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


def _posted_optional_int_or_none_reader(field: str) -> FieldReader:
    def reader(form: FormMap, current: Any, _max_workers: int) -> tuple[bool, Any]:
        raw = form.get(field)
        if raw is None:
            return False, current
        text = str(raw).strip()
        if text == "":
            return False, current
        if text.lower() == "none":
            return True, "none"
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


def _posted_choice_reader(field: str, *, allowed: Iterable[str], default: str) -> FieldReader:
    allowed_values = tuple(allowed)

    def reader(form: FormMap, current: Any, _max_workers: int) -> tuple[bool, Any]:
        raw = form.get(field)
        if raw is None:
            return False, current
        fallback = str(current or default)
        text = str(raw).strip()
        if text in allowed_values:
            return True, text
        if fallback in allowed_values:
            return True, fallback
        return True, default

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
    OptionDefaultSpec("cache_dir_type", _tunable_choice_or_default("cache_dir_type", ("rock", "ufs"), "rock")),
    OptionDefaultSpec("cache_dir_size_mb", _tunable_or_default("cache_dir_size_mb", 10000)),
    OptionDefaultSpec("cache_dir_ufs_l1", _tunable_or_default_if_none("cache_dir_ufs_l1", 16)),
    OptionDefaultSpec("cache_dir_ufs_l2", _tunable_or_default_if_none("cache_dir_ufs_l2", 256)),
    OptionDefaultSpec("cache_dir_rock_slot_size_kb", _tunable_or_default_if_none("cache_dir_rock_slot_size_kb", 32)),
    OptionDefaultSpec("cache_dir_rock_swap_timeout_ms", _tunable_optional("cache_dir_rock_swap_timeout_ms")),
    OptionDefaultSpec("cache_dir_rock_max_swap_rate", _tunable_optional("cache_dir_rock_max_swap_rate")),
    OptionDefaultSpec("cache_mem_mb", _tunable_or_default("cache_mem_mb", 256)),
    OptionDefaultSpec("maximum_object_size_mb", _tunable_or_default("maximum_object_size_mb", 128)),
    OptionDefaultSpec("maximum_object_size_in_memory_kb", _tunable_or_default("maximum_object_size_in_memory_kb", 2048)),
    OptionDefaultSpec("minimum_object_size_kb", _tunable_or_default_if_none("minimum_object_size_kb", 0)),
    OptionDefaultSpec("memory_cache_mode", _tunable_choice_or_default("memory_cache_mode", ("always", "disk", "network"), "always")),
    OptionDefaultSpec("memory_cache_shared_on", _resolve_memory_cache_shared_on),
    OptionDefaultSpec("shared_transient_entries_limit", _resolve_shared_transient_entries_limit),
    OptionDefaultSpec("cache_swap_low", _tunable_or_default("cache_swap_low", 90)),
    OptionDefaultSpec("cache_swap_high", _tunable_or_default("cache_swap_high", 95)),
    OptionDefaultSpec("collapsed_forwarding_on", _tunable_bool_or_default("collapsed_forwarding", True)),
    OptionDefaultSpec("range_cache_on", _resolve_range_cache),
    OptionDefaultSpec("workers", _resolve_workers),
    OptionDefaultSpec("cache_replacement_policy", _tunable_or_default("cache_replacement_policy", "heap GDSF")),
    OptionDefaultSpec("memory_replacement_policy", _tunable_or_default("memory_replacement_policy", "heap GDSF")),
    OptionDefaultSpec("cache_miss_revalidate_on", _tunable_bool_or_default("cache_miss_revalidate", True)),
    OptionDefaultSpec("pipeline_prefetch_on", _tunable_bool_or_default("pipeline_prefetch", True)),
    OptionDefaultSpec("client_persistent_connections_on", _tunable_bool_or_default("client_persistent_connections", True)),
    OptionDefaultSpec("server_persistent_connections_on", _tunable_bool_or_default("server_persistent_connections", True)),
    OptionDefaultSpec("negative_ttl_seconds", _tunable_optional("negative_ttl_seconds")),
    OptionDefaultSpec("positive_dns_ttl_seconds", _tunable_optional("positive_dns_ttl_seconds")),
    OptionDefaultSpec("negative_dns_ttl_seconds", _tunable_optional("negative_dns_ttl_seconds")),
    OptionDefaultSpec("minimum_expiry_time_seconds", _tunable_or_default_if_none("minimum_expiry_time_seconds", 60)),
    OptionDefaultSpec("max_stale_seconds", _tunable_or_default_if_none("max_stale_seconds", 7 * 24 * 3600)),
    OptionDefaultSpec("refresh_all_ims_on", _tunable_bool_or_default("refresh_all_ims", False)),
    OptionDefaultSpec("read_ahead_gap_kb", _tunable_or_default_if_none("read_ahead_gap_kb", 256)),
    OptionDefaultSpec("quick_abort_min_kb", _tunable_or_default_if_none("quick_abort_min_kb", 0)),
    OptionDefaultSpec("quick_abort_max_kb", _tunable_or_default_if_none("quick_abort_max_kb", 0)),
    OptionDefaultSpec("quick_abort_pct", _tunable_or_default_if_none("quick_abort_pct", 100)),
    OptionDefaultSpec("connect_timeout_seconds", _tunable_or_default_if_none("connect_timeout_seconds", 90)),
    OptionDefaultSpec("request_timeout_seconds", _tunable_or_default_if_none("request_timeout_seconds", 1800)),
    OptionDefaultSpec("read_timeout_seconds", _tunable_or_default_if_none("read_timeout_seconds", 1800)),
    OptionDefaultSpec("forward_timeout_seconds", _tunable_or_default_if_none("forward_timeout_seconds", 1800)),
    OptionDefaultSpec("request_start_timeout_seconds", _tunable_or_default_if_none("request_start_timeout_seconds", 60)),
    OptionDefaultSpec("write_timeout_seconds", _tunable_or_default_if_none("write_timeout_seconds", 900)),
    OptionDefaultSpec("shutdown_lifetime_seconds", _tunable_or_default_if_none("shutdown_lifetime_seconds", 30)),
    OptionDefaultSpec("logfile_rotate", _tunable_or_default_if_none("logfile_rotate", 10)),
    OptionDefaultSpec("buffered_logs_on", _tunable_bool_or_default("buffered_logs", True)),
    OptionDefaultSpec("server_idle_pconn_timeout_seconds", _tunable_or_default_if_none("server_idle_pconn_timeout_seconds", 120)),
    OptionDefaultSpec("client_idle_pconn_timeout_seconds", _tunable_or_default_if_none("client_idle_pconn_timeout_seconds", 120)),
    OptionDefaultSpec("pconn_lifetime_seconds", _tunable_or_default_if_none("pconn_lifetime_seconds", 0)),
    OptionDefaultSpec("persistent_connection_after_error_on", _tunable_bool_or_default("persistent_connection_after_error", True)),
    OptionDefaultSpec("detect_broken_pconn_on", _tunable_bool_or_default("detect_broken_pconn", False)),
    OptionDefaultSpec("connect_retries", _tunable_or_default_if_none("connect_retries", 1)),
    OptionDefaultSpec("forward_max_tries", _tunable_or_default_if_none("forward_max_tries", 10)),
    OptionDefaultSpec("client_lifetime_seconds", _tunable_or_default_if_none("client_lifetime_seconds", 3600)),
    OptionDefaultSpec("max_filedescriptors", _tunable_or_default_if_none("max_filedescriptors", 65535)),
    OptionDefaultSpec("dns_timeout_seconds", _tunable_or_default_if_none("dns_timeout_seconds", 15)),
    OptionDefaultSpec("dns_retransmit_interval_seconds", _tunable_or_default_if_none("dns_retransmit_interval_seconds", 5)),
    OptionDefaultSpec("dns_packet_max", _tunable_optional("dns_packet_max")),
    OptionDefaultSpec("dns_nameservers", _tunable_or_default("dns_nameservers", "")),
    OptionDefaultSpec("hosts_file", _tunable_or_default("hosts_file", "")),
    OptionDefaultSpec("ipcache_size", _tunable_or_default_if_none("ipcache_size", 8192)),
    OptionDefaultSpec("ipcache_low", _tunable_or_default_if_none("ipcache_low", 90)),
    OptionDefaultSpec("ipcache_high", _tunable_or_default_if_none("ipcache_high", 95)),
    OptionDefaultSpec("fqdncache_size", _tunable_or_default_if_none("fqdncache_size", 8192)),
    OptionDefaultSpec("sslcrtd_children", _resolve_sslcrtd_children),
    OptionDefaultSpec("sslcrtd_children_startup", _resolve_sslcrtd_children_startup),
    OptionDefaultSpec("sslcrtd_children_idle", _resolve_sslcrtd_children_idle),
    OptionDefaultSpec("sslcrtd_children_queue_size", _resolve_sslcrtd_children_queue_size),
    OptionDefaultSpec("dynamic_cert_mem_cache_size_mb", _resolve_dynamic_cert_mem_cache_mb),
    OptionDefaultSpec("sslproxy_session_ttl_seconds", _tunable_or_default_if_none("sslproxy_session_ttl_seconds", 600)),
    OptionDefaultSpec("sslproxy_session_cache_size_mb", _resolve_sslproxy_session_cache_size_mb),
    OptionDefaultSpec("icap_enable_on", _tunable_bool_or_default("icap_enable", True)),
    OptionDefaultSpec("icap_send_client_ip_on", _tunable_bool_or_default("icap_send_client_ip", True)),
    OptionDefaultSpec("icap_send_client_username_on", _tunable_bool_or_default("icap_send_client_username", False)),
    OptionDefaultSpec("icap_persistent_connections_on", _tunable_bool_or_default("icap_persistent_connections", True)),
    OptionDefaultSpec("icap_preview_enable_on", _tunable_bool_or_default("icap_preview_enable", True)),
    OptionDefaultSpec("icap_preview_size_kb", _tunable_or_default_if_none("icap_preview_size_kb", 1024)),
    OptionDefaultSpec("icap_default_options_ttl_seconds", _tunable_or_default_if_none("icap_default_options_ttl_seconds", 300)),
    OptionDefaultSpec("icap_connect_timeout_seconds", _tunable_or_default_if_none("icap_connect_timeout_seconds", 15)),
    OptionDefaultSpec("icap_io_timeout_seconds", _tunable_or_default_if_none("icap_io_timeout_seconds", 300)),
    OptionDefaultSpec("icap_service_failure_limit", _tunable_or_default_if_none("icap_service_failure_limit", 10)),
    OptionDefaultSpec("icap_service_failure_limit_window_seconds", _tunable_or_default_if_none("icap_service_failure_limit_window_seconds", 30)),
    OptionDefaultSpec("icap_service_revival_delay_seconds", _tunable_or_default_if_none("icap_service_revival_delay_seconds", 60)),
    OptionDefaultSpec("forwarded_for_value", _tunable_or_default("forwarded_for_value", "")),
    OptionDefaultSpec("via_on", _tunable_optional("via")),
    OptionDefaultSpec("follow_x_forwarded_for_value", _tunable_or_default("follow_x_forwarded_for_value", "")),
    OptionDefaultSpec("request_header_max_size_kb", _tunable_optional("request_header_max_size_kb")),
    OptionDefaultSpec("reply_header_max_size_kb", _tunable_optional("reply_header_max_size_kb")),
    OptionDefaultSpec("request_body_max_size_mb", _tunable_optional("request_body_max_size_mb")),
    OptionDefaultSpec("client_request_buffer_max_size_kb", _tunable_optional("client_request_buffer_max_size_kb")),
    OptionDefaultSpec("memory_pools_on", _tunable_bool_or_default("memory_pools", True)),
    OptionDefaultSpec("memory_pools_limit_mb", _tunable_or_default_if_none("memory_pools_limit_mb", 64)),
    OptionDefaultSpec("shared_memory_locking_on", _tunable_bool_or_default("shared_memory_locking", False)),
    OptionDefaultSpec("max_open_disk_fds", _tunable_or_default_if_none("max_open_disk_fds", 0)),
    OptionDefaultSpec("store_avg_object_size_kb", _tunable_or_default_if_none("store_avg_object_size_kb", 32)),
    OptionDefaultSpec("store_objects_per_bucket", _tunable_or_default_if_none("store_objects_per_bucket", 16)),
    OptionDefaultSpec("cpu_affinity_map", _tunable_or_default("cpu_affinity_map", "")),
    OptionDefaultSpec("visible_hostname", _tunable_or_default("visible_hostname", "")),
    OptionDefaultSpec("httpd_suppress_version_string_on", _tunable_optional("httpd_suppress_version_string")),
)


FORM_KIND_FIELD_SPECS: dict[str, tuple[FormFieldSpec, ...]] = {
    "caching": (
        FormFieldSpec("cache_dir_type", _posted_choice_reader("cache_dir_type", allowed=("rock", "ufs"), default="rock")),
        FormFieldSpec("cache_dir_size_mb", _posted_int_reader("cache_dir_size_mb")),
        FormFieldSpec("cache_dir_ufs_l1", _posted_int_reader("cache_dir_ufs_l1")),
        FormFieldSpec("cache_dir_ufs_l2", _posted_int_reader("cache_dir_ufs_l2")),
        FormFieldSpec("cache_dir_rock_slot_size_kb", _posted_int_reader("cache_dir_rock_slot_size_kb")),
        FormFieldSpec("cache_dir_rock_swap_timeout_ms", _posted_optional_int_reader("cache_dir_rock_swap_timeout_ms")),
        FormFieldSpec("cache_dir_rock_max_swap_rate", _posted_optional_int_reader("cache_dir_rock_max_swap_rate")),
        FormFieldSpec("cache_mem_mb", _posted_int_reader("cache_mem_mb")),
        FormFieldSpec("maximum_object_size_mb", _posted_int_reader("maximum_object_size_mb")),
        FormFieldSpec("maximum_object_size_in_memory_kb", _posted_int_reader("maximum_object_size_in_memory_kb")),
        FormFieldSpec("minimum_object_size_kb", _posted_int_reader("minimum_object_size_kb")),
        FormFieldSpec("memory_cache_mode", _posted_choice_reader("memory_cache_mode", allowed=("always", "disk", "network"), default="always")),
        FormFieldSpec("memory_cache_shared_on", _checkbox_reader("memory_cache_shared_on")),
        FormFieldSpec("shared_transient_entries_limit", _posted_int_reader("shared_transient_entries_limit")),
        FormFieldSpec("cache_swap_low", _posted_int_reader("cache_swap_low")),
        FormFieldSpec("cache_swap_high", _posted_int_reader("cache_swap_high")),
        FormFieldSpec("collapsed_forwarding_on", _checkbox_reader("collapsed_forwarding_on")),
        FormFieldSpec("range_cache_on", _checkbox_reader("range_cache_on")),
        FormFieldSpec("workers", _posted_int_reader("workers", clamp=_clamp_workers)),
        FormFieldSpec("cache_replacement_policy", _posted_string_reader("cache_replacement_policy", default="heap GDSF")),
        FormFieldSpec("memory_replacement_policy", _posted_string_reader("memory_replacement_policy", default="heap GDSF")),
        FormFieldSpec("cache_miss_revalidate_on", _checkbox_reader("cache_miss_revalidate_on")),
        FormFieldSpec("pipeline_prefetch_on", _checkbox_reader("pipeline_prefetch_on")),
        FormFieldSpec("client_persistent_connections_on", _checkbox_reader("client_persistent_connections_on")),
        FormFieldSpec("server_persistent_connections_on", _checkbox_reader("server_persistent_connections_on")),
        FormFieldSpec("negative_ttl_seconds", _posted_optional_int_reader("negative_ttl_seconds")),
        FormFieldSpec("positive_dns_ttl_seconds", _posted_optional_int_reader("positive_dns_ttl_seconds")),
        FormFieldSpec("negative_dns_ttl_seconds", _posted_optional_int_reader("negative_dns_ttl_seconds")),
        FormFieldSpec("minimum_expiry_time_seconds", _posted_int_reader("minimum_expiry_time_seconds")),
        FormFieldSpec("max_stale_seconds", _posted_int_reader("max_stale_seconds")),
        FormFieldSpec("refresh_all_ims_on", _checkbox_reader("refresh_all_ims_on")),
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
        FormFieldSpec("request_start_timeout_seconds", _posted_int_reader("request_start_timeout_seconds")),
        FormFieldSpec("write_timeout_seconds", _posted_int_reader("write_timeout_seconds")),
        FormFieldSpec("shutdown_lifetime_seconds", _posted_int_reader("shutdown_lifetime_seconds")),
    ),
    "logging": (
        FormFieldSpec("logfile_rotate", _posted_int_reader("logfile_rotate")),
        FormFieldSpec("buffered_logs_on", _checkbox_reader("buffered_logs_on")),
    ),
    "network": (
        FormFieldSpec("server_idle_pconn_timeout_seconds", _posted_int_reader("server_idle_pconn_timeout_seconds")),
        FormFieldSpec("client_idle_pconn_timeout_seconds", _posted_int_reader("client_idle_pconn_timeout_seconds")),
        FormFieldSpec("pconn_lifetime_seconds", _posted_optional_int_reader("pconn_lifetime_seconds")),
        FormFieldSpec("persistent_connection_after_error_on", _checkbox_reader("persistent_connection_after_error_on")),
        FormFieldSpec("detect_broken_pconn_on", _checkbox_reader("detect_broken_pconn_on")),
        FormFieldSpec("connect_retries", _posted_int_reader("connect_retries")),
        FormFieldSpec("forward_max_tries", _posted_int_reader("forward_max_tries")),
        FormFieldSpec("client_lifetime_seconds", _posted_int_reader("client_lifetime_seconds")),
        FormFieldSpec("max_filedescriptors", _posted_int_reader("max_filedescriptors")),
    ),
    "dns": (
        FormFieldSpec("dns_retransmit_interval_seconds", _posted_int_reader("dns_retransmit_interval_seconds")),
        FormFieldSpec("dns_packet_max", _posted_optional_int_or_none_reader("dns_packet_max")),
        FormFieldSpec("dns_nameservers", _posted_nonempty_string_reader("dns_nameservers")),
        FormFieldSpec("hosts_file", _posted_nonempty_string_reader("hosts_file")),
        FormFieldSpec("dns_timeout_seconds", _posted_int_reader("dns_timeout_seconds")),
        FormFieldSpec("ipcache_size", _posted_int_reader("ipcache_size")),
        FormFieldSpec("ipcache_low", _posted_int_reader("ipcache_low")),
        FormFieldSpec("ipcache_high", _posted_int_reader("ipcache_high")),
        FormFieldSpec("fqdncache_size", _posted_int_reader("fqdncache_size")),
    ),
    "ssl": (
        FormFieldSpec("sslcrtd_children", _posted_int_reader("sslcrtd_children")),
        FormFieldSpec("sslcrtd_children_startup", _posted_optional_int_reader("sslcrtd_children_startup")),
        FormFieldSpec("sslcrtd_children_idle", _posted_optional_int_reader("sslcrtd_children_idle")),
        FormFieldSpec("sslcrtd_children_queue_size", _posted_optional_int_reader("sslcrtd_children_queue_size")),
        FormFieldSpec("dynamic_cert_mem_cache_size_mb", _posted_int_reader("dynamic_cert_mem_cache_size_mb")),
        FormFieldSpec("sslproxy_session_ttl_seconds", _posted_int_reader("sslproxy_session_ttl_seconds")),
        FormFieldSpec("sslproxy_session_cache_size_mb", _posted_int_reader("sslproxy_session_cache_size_mb")),
    ),
    "icap": (
        FormFieldSpec("icap_enable_on", _checkbox_reader("icap_enable_on")),
        FormFieldSpec("icap_send_client_ip_on", _checkbox_reader("icap_send_client_ip_on")),
        FormFieldSpec("icap_send_client_username_on", _checkbox_reader("icap_send_client_username_on")),
        FormFieldSpec("icap_persistent_connections_on", _checkbox_reader("icap_persistent_connections_on")),
        FormFieldSpec("icap_preview_enable_on", _checkbox_reader("icap_preview_enable_on")),
        FormFieldSpec("icap_preview_size_kb", _posted_int_reader("icap_preview_size_kb")),
        FormFieldSpec("icap_default_options_ttl_seconds", _posted_int_reader("icap_default_options_ttl_seconds")),
        FormFieldSpec("icap_connect_timeout_seconds", _posted_int_reader("icap_connect_timeout_seconds")),
        FormFieldSpec("icap_io_timeout_seconds", _posted_int_reader("icap_io_timeout_seconds")),
        FormFieldSpec("icap_service_failure_limit", _posted_optional_int_reader("icap_service_failure_limit")),
        FormFieldSpec("icap_service_failure_limit_window_seconds", _posted_optional_int_reader("icap_service_failure_limit_window_seconds")),
        FormFieldSpec("icap_service_revival_delay_seconds", _posted_int_reader("icap_service_revival_delay_seconds")),
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
        FormFieldSpec("memory_pools_limit_mb", _posted_optional_int_or_none_reader("memory_pools_limit_mb")),
        FormFieldSpec("shared_memory_locking_on", _checkbox_reader("shared_memory_locking_on")),
        FormFieldSpec("max_open_disk_fds", _posted_optional_int_reader("max_open_disk_fds")),
        FormFieldSpec("store_avg_object_size_kb", _posted_optional_int_reader("store_avg_object_size_kb")),
        FormFieldSpec("store_objects_per_bucket", _posted_optional_int_reader("store_objects_per_bucket")),
        FormFieldSpec("cpu_affinity_map", _posted_nonempty_string_reader("cpu_affinity_map")),
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

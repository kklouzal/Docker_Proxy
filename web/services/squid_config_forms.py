from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Iterable, Mapping, MutableMapping


TunableMap = Mapping[str, Any]
FormMap = Mapping[str, Any]
OptionMap = MutableMapping[str, Any]
OptionResolver = Callable[[TunableMap, int], Any]
FieldReader = Callable[[FormMap, Any, int], tuple[bool, Any]]


DEFAULT_CACHE_POLICY_RULES = """# Never cache authenticated or cookie-bearing traffic.
acl has_auth req_header Authorization .
acl has_cookie req_header Cookie .
note cache_bypass auth has_auth
note cache_bypass cookie has_cookie
cache deny has_auth
cache deny has_cookie

# Prevent caching responses with complex Vary headers.
acl has_vary rep_header Vary .
acl vary_encoding_only rep_header Vary ^Accept-Encoding$
store_miss deny has_vary !vary_encoding_only"""


DEFAULT_REFRESH_PATTERNS = r"""# Safe heuristic caching when explicit expiry headers are absent.
# Add more specific allow-lists above broader fallback rules.
refresh_pattern -i (fonts\.gstatic\.com|fonts\.googleapis\.com)/.* 1440 80% 10080 store-stale
refresh_pattern -i \.(iso|img|dmg|bin|exe|msi|msu)(\?|$) 43800 100% 129600 store-stale
refresh_pattern -i \.(rar|jar|gz|tgz|tar|bz2|zip|7z)(\?|$) 43800 100% 129600 store-stale
refresh_pattern -i \.(mp4|mkv|flv|mov|avi|mpeg|webm)(\?|$) 43800 100% 129600 store-stale
refresh_pattern -i \.(mp3|wav|ogg|flac|aac)(\?|$) 43800 100% 129600 store-stale
refresh_pattern -i \.(png|jpe?g|gif|webp|bmp|ico|svg|tiff)(\?|$) 43800 100% 129600 store-stale
refresh_pattern -i \.(woff2?|ttf|otf|eot)(\?|$) 43800 85% 129600 store-stale
refresh_pattern -i \.(pdf|docx?|xlsx?|pptx?)(\?|$) 10080 90% 43200 store-stale
refresh_pattern -i \.(css)(\?|$) 10080 80% 43800 store-stale
refresh_pattern -i \.(js)(\?|$) 1440 80% 10080 store-stale
refresh_pattern -i \.(xhtml|html|htm)\?.* 0 0% 0 store-stale
refresh_pattern -i \.(xml)(\?|$) 360 80% 1440 store-stale
refresh_pattern -i \.(xhtml|html|htm)$ 360 80% 1440 store-stale
refresh_pattern -i (/cgi-bin/|\?) 0 0% 0
refresh_pattern . 0 20% 4320"""


@dataclass(frozen=True)
class UiChoiceSpec:
    value: str
    label: str


@dataclass(frozen=True)
class ConfigFieldSpec:
    key: str
    section: str
    group: str
    label: str
    directive: str
    input_type: str
    resolver: OptionResolver
    reader: FieldReader
    help_text: str = ""
    placeholder: str = ""
    minimum: int | None = None
    maximum: int | None = None
    step: int | None = None
    rows: int = 6
    choices: tuple[UiChoiceSpec, ...] = ()
    depends_on: tuple[str, ...] = ()
    show_when: tuple[str, ...] = ()


@dataclass(frozen=True)
class UiGroupSpec:
    key: str
    title: str
    description: str
    field_keys: tuple[str, ...]


@dataclass(frozen=True)
class UiSectionSpec:
    key: str
    label: str
    description: str
    apply_note: str
    groups: tuple[UiGroupSpec, ...]


def _choice(value: str, label: str) -> UiChoiceSpec:
    return UiChoiceSpec(value=value, label=label)


def _field(
    key: str,
    section: str,
    group: str,
    label: str,
    directive: str,
    input_type: str,
    resolver: OptionResolver,
    reader: FieldReader,
    *,
    help_text: str = "",
    placeholder: str = "",
    minimum: int | None = None,
    maximum: int | None = None,
    step: int | None = None,
    rows: int = 6,
    choices: Iterable[UiChoiceSpec] = (),
    depends_on: Iterable[str] = (),
    show_when: Iterable[str] = (),
) -> ConfigFieldSpec:
    return ConfigFieldSpec(
        key=key,
        section=section,
        group=group,
        label=label,
        directive=directive,
        input_type=input_type,
        resolver=resolver,
        reader=reader,
        help_text=help_text,
        placeholder=placeholder,
        minimum=minimum,
        maximum=maximum,
        step=step,
        rows=rows,
        choices=tuple(choices),
        depends_on=tuple(depends_on),
        show_when=tuple(show_when),
    )


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


def _current_workers(tunables: TunableMap, max_workers: int) -> int:
    try:
        value = int(tunables.get("workers") or 1)
    except Exception:
        value = 1
    return min(max_workers, max(1, value))


def _resolve_workers(tunables: TunableMap, max_workers: int) -> int:
    return _current_workers(tunables, max_workers)


def _range_value_enabled(value: Any) -> bool:
    text = str(value or "").strip().lower()
    return text not in ("", "0", "0 b", "0 byte", "0 bytes", "0 kb", "0 mb", "off", "false")


def _normalize_range_offset_limit_value(value: Any, *, default: str = "128 MB") -> str:
    if value is None:
        return default
    text = str(value).strip()
    if text == "":
        return default
    if text == "-1":
        return "none"
    return text


def _resolve_range_offset_limit_value(tunables: TunableMap, _max_workers: int) -> str:
    if tunables.get("range_offset_limit_value") is not None:
        return _normalize_range_offset_limit_value(tunables.get("range_offset_limit_value"))
    value = tunables.get("range_offset_limit")
    if value is None:
        return "128 MB"
    if value == -1:
        return "none"
    return _normalize_range_offset_limit_value(f"{value} MB")


def _resolve_range_cache(tunables: TunableMap, _max_workers: int) -> bool:
    if tunables.get("range_cache_on") is not None:
        return bool(tunables.get("range_cache_on"))
    if tunables.get("range_offset_limit_value") is not None:
        return _range_value_enabled(tunables.get("range_offset_limit_value"))
    value = tunables.get("range_offset_limit")
    return (value != 0) if value is not None else True


def _resolve_pipeline_prefetch_count(tunables: TunableMap, _max_workers: int) -> int:
    value = tunables.get("pipeline_prefetch_count")
    if value is not None:
        try:
            return max(0, int(value))
        except Exception:
            pass
    raw = tunables.get("pipeline_prefetch")
    if raw is None:
        return 1
    if isinstance(raw, bool):
        return 1 if raw else 0
    try:
        return max(0, int(raw))
    except Exception:
        text = str(raw).strip().lower()
        return 1 if text in ("on", "true", "yes") else 0


def _resolve_pipeline_prefetch_on(tunables: TunableMap, max_workers: int) -> bool:
    return _resolve_pipeline_prefetch_count(tunables, max_workers) > 0


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


def _resolve_sslcrtd_program_cache_size_mb(tunables: TunableMap, _max_workers: int) -> int:
    value = tunables.get("sslcrtd_program_cache_size_mb")
    if value is not None:
        try:
            return max(1, int(value))
        except Exception:
            pass
    return 16


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


def _resolve_shared_transient_entries_limit(tunables: TunableMap, max_workers: int) -> int:
    value = tunables.get("shared_transient_entries_limit")
    if value is not None:
        try:
            return max(0, int(value))
        except Exception:
            pass
    workers = _current_workers(tunables, max_workers)
    return max(32768, workers * 8192)


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


def _posted_text_reader(field: str) -> FieldReader:
    def reader(form: FormMap, current: Any, _max_workers: int) -> tuple[bool, Any]:
        raw = form.get(field)
        if raw is None:
            return False, current
        return True, str(raw).strip()

    return reader


def _posted_multiline_reader(field: str) -> FieldReader:
    def reader(form: FormMap, current: Any, _max_workers: int) -> tuple[bool, Any]:
        raw = form.get(field)
        if raw is None:
            return False, current
        text = str(raw).replace("\r\n", "\n").replace("\r", "\n").strip("\n")
        return True, text

    return reader


def _posted_choice_reader(field: str, *, allowed: Iterable[str], default: str) -> FieldReader:
    allowed_values = tuple(allowed)

    def reader(form: FormMap, current: Any, _max_workers: int) -> tuple[bool, Any]:
        raw = form.get(field)
        if raw is None:
            return False, current
        fallback = str(current if current is not None else default)
        text = str(raw).strip()
        if text in allowed_values:
            return True, text
        if fallback in allowed_values:
            return True, fallback
        return True, default

    return reader


def _checkbox_reader(field: str) -> FieldReader:
    def reader(form: FormMap, current: Any, _max_workers: int) -> tuple[bool, Any]:
        return True, field in form

    return reader


def _clamp_workers(value: int, max_workers: int) -> int:
    return min(max_workers, max(1, int(value)))


CACHE_DIR_TYPE_CHOICES = (
    _choice("rock", "rock (recommended for SMP)"),
    _choice("ufs", "ufs (legacy directory store)"),
)

MEMORY_CACHE_MODE_CHOICES = (
    _choice("always", "always"),
    _choice("disk", "disk"),
    _choice("network", "network"),
)

REPLACEMENT_POLICY_CHOICES = (
    _choice("heap GDSF", "heap GDSF"),
    _choice("heap LFUDA", "heap LFUDA"),
    _choice("heap LRU", "heap LRU"),
    _choice("lru", "lru"),
)

STORE_DIR_SELECT_CHOICES = (
    _choice("least-load", "least-load"),
    _choice("round-robin", "round-robin"),
)

FORWARDED_FOR_CHOICES = (
    _choice("", "Use Squid default (on)"),
    _choice("on", "on"),
    _choice("off", "off"),
    _choice("transparent", "transparent"),
    _choice("delete", "delete"),
    _choice("truncate", "truncate"),
)

RELAXED_HEADER_PARSER_CHOICES = (
    _choice("on", "on"),
    _choice("warn", "warn"),
    _choice("off", "off"),
)

URI_WHITESPACE_CHOICES = (
    _choice("strip", "strip"),
    _choice("deny", "deny"),
    _choice("allow", "allow"),
    _choice("encode", "encode"),
    _choice("chop", "chop"),
)

ON_UNSUPPORTED_PROTOCOL_CHOICES = (
    _choice("respond", "respond"),
    _choice("tunnel", "tunnel"),
)

SSL_CERT_SIGN_HASH_CHOICES = (
    _choice("sha256", "sha256"),
    _choice("sha512", "sha512"),
    _choice("sha1", "sha1"),
    _choice("md5", "md5"),
)


CONFIG_FIELDS: tuple[ConfigFieldSpec, ...] = (
    _field(
        "cache_dir_type",
        "caching",
        "store",
        "Disk cache store type",
        "cache_dir",
        "select",
        _tunable_choice_or_default("cache_dir_type", ("rock", "ufs"), "rock"),
        _posted_choice_reader("cache_dir_type", allowed=("rock", "ufs"), default="rock"),
        help_text="Rock is the only SMP-aware disk store documented by Squid 7.x.",
        choices=CACHE_DIR_TYPE_CHOICES,
    ),
    _field(
        "cache_dir_size_mb",
        "caching",
        "store",
        "Disk cache size (MB)",
        "cache_dir",
        "number",
        _tunable_or_default("cache_dir_size_mb", 10000),
        _posted_int_reader("cache_dir_size_mb"),
        minimum=100,
        step=100,
        help_text="Amount of disk space reserved for the main cache store.",
    ),
    _field(
        "cache_dir_ufs_l1",
        "caching",
        "store",
        "ufs L1 directories",
        "cache_dir",
        "number",
        _tunable_or_default_if_none("cache_dir_ufs_l1", 16),
        _posted_int_reader("cache_dir_ufs_l1"),
        minimum=1,
        step=1,
        help_text="Only used when the ufs store type is selected.",
        depends_on=("cache_dir_type",),
        show_when=("ufs",),
    ),
    _field(
        "cache_dir_ufs_l2",
        "caching",
        "store",
        "ufs L2 directories",
        "cache_dir",
        "number",
        _tunable_or_default_if_none("cache_dir_ufs_l2", 256),
        _posted_int_reader("cache_dir_ufs_l2"),
        minimum=1,
        step=1,
        help_text="Only used when the ufs store type is selected.",
        depends_on=("cache_dir_type",),
        show_when=("ufs",),
    ),
    _field(
        "cache_dir_rock_slot_size_kb",
        "caching",
        "store",
        "rock slot size (KB)",
        "cache_dir",
        "number",
        _tunable_or_default_if_none("cache_dir_rock_slot_size_kb", 32),
        _posted_int_reader("cache_dir_rock_slot_size_kb"),
        minimum=4,
        step=4,
        help_text="Smaller slot sizes waste less space on small objects; larger slot sizes favor large objects.",
        depends_on=("cache_dir_type",),
        show_when=("rock",),
    ),
    _field(
        "cache_dir_rock_swap_timeout_ms",
        "caching",
        "store",
        "rock swap timeout (ms)",
        "cache_dir",
        "number",
        _tunable_optional("cache_dir_rock_swap_timeout_ms"),
        _posted_optional_int_reader("cache_dir_rock_swap_timeout_ms"),
        minimum=0,
        step=1,
        help_text="Leave blank to let Squid use its own behavior.",
        depends_on=("cache_dir_type",),
        show_when=("rock",),
    ),
    _field(
        "cache_dir_rock_max_swap_rate",
        "caching",
        "store",
        "rock max swap rate",
        "cache_dir",
        "number",
        _tunable_optional("cache_dir_rock_max_swap_rate"),
        _posted_optional_int_reader("cache_dir_rock_max_swap_rate"),
        minimum=0,
        step=1,
        help_text="Optional limiter for disk pressure on rock stores.",
        depends_on=("cache_dir_type",),
        show_when=("rock",),
    ),
    _field(
        "store_dir_select_algorithm",
        "caching",
        "store",
        "Store selection algorithm",
        "store_dir_select_algorithm",
        "select",
        _tunable_choice_or_default("store_dir_select_algorithm", ("least-load", "round-robin"), "least-load"),
        _posted_choice_reader("store_dir_select_algorithm", allowed=("least-load", "round-robin"), default="least-load"),
        choices=STORE_DIR_SELECT_CHOICES,
        help_text="Use round-robin when you intentionally mix unequal cache_dir sizes.",
    ),
    _field(
        "cache_replacement_policy",
        "caching",
        "store",
        "Disk cache replacement policy",
        "cache_replacement_policy",
        "select",
        _tunable_or_default("cache_replacement_policy", "heap GDSF"),
        _posted_choice_reader(
            "cache_replacement_policy",
            allowed=("heap GDSF", "heap LFUDA", "heap LRU", "lru"),
            default="heap GDSF",
        ),
        choices=REPLACEMENT_POLICY_CHOICES,
        help_text="GDSF improves object hit rate; LFUDA prioritizes byte hit rate.",
    ),
    _field(
        "cache_swap_low",
        "caching",
        "store",
        "cache_swap_low (%)",
        "cache_swap_low",
        "number",
        _tunable_or_default("cache_swap_low", 90),
        _posted_int_reader("cache_swap_low"),
        minimum=0,
        maximum=100,
        step=1,
        help_text="Lower watermark for disk eviction aggressiveness.",
    ),
    _field(
        "cache_swap_high",
        "caching",
        "store",
        "cache_swap_high (%)",
        "cache_swap_high",
        "number",
        _tunable_or_default("cache_swap_high", 95),
        _posted_int_reader("cache_swap_high"),
        minimum=0,
        maximum=100,
        step=1,
        help_text="Upper watermark for disk eviction aggressiveness.",
    ),
    _field(
        "cache_mem_mb",
        "caching",
        "memory",
        "Memory cache (MB)",
        "cache_mem",
        "number",
        _tunable_or_default("cache_mem_mb", 256),
        _posted_int_reader("cache_mem_mb"),
        minimum=16,
        step=16,
        help_text="Ideal memory budget for in-transit, hot, and negative-cached objects.",
    ),
    _field(
        "maximum_object_size_mb",
        "caching",
        "memory",
        "Maximum cached object size (MB)",
        "maximum_object_size",
        "number",
        _tunable_or_default("maximum_object_size_mb", 128),
        _posted_int_reader("maximum_object_size_mb"),
        minimum=1,
        step=1,
        help_text="Raised above Squid's small default to improve byte hit rate for software and media downloads.",
    ),
    _field(
        "maximum_object_size_in_memory_kb",
        "caching",
        "memory",
        "Maximum in-memory object (KB)",
        "maximum_object_size_in_memory",
        "number",
        _tunable_or_default("maximum_object_size_in_memory_kb", 2048),
        _posted_int_reader("maximum_object_size_in_memory_kb"),
        minimum=0,
        step=64,
        help_text="Prevent large objects from crowding out hot small content in cache_mem.",
    ),
    _field(
        "minimum_object_size_kb",
        "caching",
        "memory",
        "Minimum object size (KB)",
        "minimum_object_size",
        "number",
        _tunable_or_default_if_none("minimum_object_size_kb", 0),
        _posted_int_reader("minimum_object_size_kb"),
        minimum=0,
        step=1,
        help_text="Objects smaller than this are not written to disk.",
    ),
    _field(
        "memory_cache_mode",
        "caching",
        "memory",
        "Memory cache mode",
        "memory_cache_mode",
        "select",
        _tunable_choice_or_default("memory_cache_mode", ("always", "disk", "network"), "always"),
        _posted_choice_reader("memory_cache_mode", allowed=("always", "disk", "network"), default="always"),
        choices=MEMORY_CACHE_MODE_CHOICES,
        help_text="Keep the most useful recently fetched objects in memory.",
    ),
    _field(
        "memory_cache_shared_on",
        "caching",
        "memory",
        "Share memory cache across workers",
        "memory_cache_shared",
        "checkbox",
        _tunable_bool_or_default("memory_cache_shared", True),
        _checkbox_reader("memory_cache_shared_on"),
        help_text="Squid shares cache_mem in SMP mode when the platform supports it.",
    ),
    _field(
        "memory_replacement_policy",
        "caching",
        "memory",
        "Memory replacement policy",
        "memory_replacement_policy",
        "select",
        _tunable_or_default("memory_replacement_policy", "heap GDSF"),
        _posted_choice_reader(
            "memory_replacement_policy",
            allowed=("heap GDSF", "heap LFUDA", "heap LRU", "lru"),
            default="heap GDSF",
        ),
        choices=REPLACEMENT_POLICY_CHOICES,
        help_text="Memory eviction policy for cache_mem.",
    ),
    _field(
        "shared_transient_entries_limit",
        "caching",
        "memory",
        "Shared transient entries limit",
        "shared_transient_entries_limit",
        "number",
        _resolve_shared_transient_entries_limit,
        _posted_int_reader("shared_transient_entries_limit"),
        minimum=0,
        step=1024,
        help_text="SMP coordination table for in-flight cachable responses.",
    ),
    _field(
        "collapsed_forwarding_on",
        "caching",
        "heuristics",
        "Enable collapsed forwarding",
        "collapsed_forwarding",
        "checkbox",
        _tunable_bool_or_default("collapsed_forwarding", True),
        _checkbox_reader("collapsed_forwarding_on"),
        help_text="Merges concurrent requests for the same cachable object.",
    ),
    _field(
        "collapsed_forwarding_access_rules_text",
        "caching",
        "heuristics",
        "collapsed_forwarding_access rules",
        "collapsed_forwarding_access",
        "textarea",
        _tunable_or_default_if_none("collapsed_forwarding_access_rules_text", ""),
        _posted_multiline_reader("collapsed_forwarding_access_rules_text"),
        rows=6,
        placeholder="allow all",
        help_text="Optional ACL rules to restrict where collapsed forwarding applies.",
        depends_on=("collapsed_forwarding_on",),
        show_when=("checked",),
    ),
    _field(
        "range_cache_on",
        "caching",
        "heuristics",
        "Enable range request caching",
        "range_offset_limit",
        "checkbox",
        _resolve_range_cache,
        _checkbox_reader("range_cache_on"),
        help_text="Turns off range prefetching by forcing range_offset_limit to 0.",
    ),
    _field(
        "range_offset_limit_value",
        "caching",
        "heuristics",
        "range_offset_limit value",
        "range_offset_limit",
        "text",
        _resolve_range_offset_limit_value,
        _posted_text_reader("range_offset_limit_value"),
        placeholder="128 MB or none",
        help_text="Squid default is effectively 0; this deployment defaults to 128 MB for better resumable-download caching.",
        depends_on=("range_cache_on",),
        show_when=("checked",),
    ),
    _field(
        "cache_miss_revalidate_on",
        "caching",
        "heuristics",
        "Preserve client validators on MISS",
        "cache_miss_revalidate",
        "checkbox",
        _tunable_bool_or_default("cache_miss_revalidate", True),
        _checkbox_reader("cache_miss_revalidate_on"),
        help_text="Disable this while warming a cold cache if you prefer more 200 responses over preserving client If-* semantics.",
    ),
    _field(
        "pipeline_prefetch_on",
        "caching",
        "heuristics",
        "Enable pipeline prefetch",
        "pipeline_prefetch",
        "checkbox",
        _resolve_pipeline_prefetch_on,
        _checkbox_reader("pipeline_prefetch_on"),
        help_text="Requires persistent client connections; documented to break NTLM and Negotiate/Kerberos auth.",
    ),
    _field(
        "pipeline_prefetch_count",
        "caching",
        "heuristics",
        "pipeline_prefetch concurrency",
        "pipeline_prefetch",
        "number",
        _resolve_pipeline_prefetch_count,
        _posted_int_reader("pipeline_prefetch_count"),
        minimum=0,
        maximum=16,
        step=1,
        help_text="Squid will try to process up to 1+N pipelined requests concurrently on the same client connection.",
        depends_on=("pipeline_prefetch_on",),
        show_when=("checked",),
    ),
    _field(
        "read_ahead_gap_kb",
        "caching",
        "heuristics",
        "read_ahead_gap (KB)",
        "read_ahead_gap",
        "number",
        _tunable_or_default_if_none("read_ahead_gap_kb", 256),
        _posted_optional_int_reader("read_ahead_gap_kb"),
        minimum=0,
        step=1,
        help_text="How far ahead Squid buffers origin data beyond what the client has already consumed.",
    ),
    _field(
        "quick_abort_min_kb",
        "caching",
        "heuristics",
        "quick_abort_min (KB)",
        "quick_abort_min",
        "number",
        _tunable_or_default_if_none("quick_abort_min_kb", 0),
        _posted_int_reader("quick_abort_min_kb"),
        minimum=-1,
        step=1,
        help_text="-1 forces continued retrieval of cacheable responses even after the client disconnects.",
    ),
    _field(
        "quick_abort_max_kb",
        "caching",
        "heuristics",
        "quick_abort_max (KB)",
        "quick_abort_max",
        "number",
        _tunable_or_default_if_none("quick_abort_max_kb", 0),
        _posted_int_reader("quick_abort_max_kb"),
        minimum=0,
        step=1,
        help_text="0 means never continue a download solely because a large chunk remains.",
    ),
    _field(
        "quick_abort_pct",
        "caching",
        "heuristics",
        "quick_abort_pct",
        "quick_abort_pct",
        "number",
        _tunable_or_default_if_none("quick_abort_pct", 100),
        _posted_int_reader("quick_abort_pct"),
        minimum=0,
        maximum=100,
        step=1,
        help_text="Continue retrieval when at least this percentage of the object is already downloaded.",
    ),
    _field(
        "negative_ttl_seconds",
        "caching",
        "heuristics",
        "negative_ttl (seconds)",
        "negative_ttl",
        "number",
        _tunable_or_default_if_none("negative_ttl_seconds", 0),
        _posted_optional_int_reader("negative_ttl_seconds"),
        minimum=0,
        step=1,
        help_text="HTTP negative caching is an HTTP-violation feature; 0 keeps it disabled.",
    ),
    _field(
        "minimum_expiry_time_seconds",
        "caching",
        "heuristics",
        "minimum_expiry_time (seconds)",
        "minimum_expiry_time",
        "number",
        _tunable_or_default_if_none("minimum_expiry_time_seconds", 60),
        _posted_int_reader("minimum_expiry_time_seconds"),
        minimum=0,
        step=1,
        help_text="Minimum freshness Squid honors for responses that cannot be revalidated.",
    ),
    _field(
        "max_stale_seconds",
        "caching",
        "heuristics",
        "max_stale (seconds)",
        "max_stale",
        "number",
        _tunable_or_default_if_none("max_stale_seconds", 7 * 24 * 3600),
        _posted_int_reader("max_stale_seconds"),
        minimum=0,
        step=60,
        help_text="Maximum stale age Squid may serve if revalidation fails.",
    ),
    _field(
        "refresh_all_ims_on",
        "caching",
        "heuristics",
        "Always refresh client IMS requests",
        "refresh_all_ims",
        "checkbox",
        _tunable_bool_or_default("refresh_all_ims", False),
        _checkbox_reader("refresh_all_ims_on"),
        help_text="Force origin revalidation when clients send If-Modified-Since.",
    ),
    _field(
        "cache_policy_rules_text",
        "caching",
        "rules",
        "Cache policy ACL rules",
        "cache / send_hit / store_miss",
        "textarea",
        _tunable_or_default_if_none("cache_policy_rules_text", DEFAULT_CACHE_POLICY_RULES),
        _posted_multiline_reader("cache_policy_rules_text"),
        rows=14,
        help_text="Multi-line ACL block for cache, send_hit, and store_miss policy.",
    ),
    _field(
        "refresh_patterns_text",
        "caching",
        "rules",
        "refresh_pattern rules",
        "refresh_pattern",
        "textarea",
        _tunable_or_default_if_none("refresh_patterns_text", DEFAULT_REFRESH_PATTERNS),
        _posted_multiline_reader("refresh_patterns_text"),
        rows=16,
        help_text="Ordered refresh_pattern list; place more specific regexes above broad fallbacks.",
    ),
    _field(
        "connect_timeout_seconds",
        "timeouts",
        "request_path",
        "connect_timeout (seconds)",
        "connect_timeout",
        "number",
        _tunable_or_default_if_none("connect_timeout_seconds", 90),
        _posted_int_reader("connect_timeout_seconds"),
        minimum=0,
        step=1,
        help_text="How long Squid waits for a TCP connect to complete before trying a different path.",
    ),
    _field(
        "peer_connect_timeout_seconds",
        "timeouts",
        "request_path",
        "peer_connect_timeout (seconds)",
        "peer_connect_timeout",
        "number",
        _tunable_or_default_if_none("peer_connect_timeout_seconds", 30),
        _posted_int_reader("peer_connect_timeout_seconds"),
        minimum=0,
        step=1,
        help_text="Used when forwarding to cache_peer neighbors.",
    ),
    _field(
        "request_start_timeout_seconds",
        "timeouts",
        "request_path",
        "request_start_timeout (seconds)",
        "request_start_timeout",
        "number",
        _tunable_or_default_if_none("request_start_timeout_seconds", 60),
        _posted_int_reader("request_start_timeout_seconds"),
        minimum=0,
        step=1,
        help_text="How long to wait for the first request byte after a client connects.",
    ),
    _field(
        "request_timeout_seconds",
        "timeouts",
        "request_path",
        "request_timeout (seconds)",
        "request_timeout",
        "number",
        _tunable_or_default_if_none("request_timeout_seconds", 1800),
        _posted_int_reader("request_timeout_seconds"),
        minimum=0,
        step=1,
        help_text="How long to wait for complete request headers after the connection begins.",
    ),
    _field(
        "read_timeout_seconds",
        "timeouts",
        "request_path",
        "read_timeout (seconds)",
        "read_timeout",
        "number",
        _tunable_or_default_if_none("read_timeout_seconds", 1800),
        _posted_int_reader("read_timeout_seconds"),
        minimum=0,
        step=1,
        help_text="Server-side idle read timeout after a successful read.",
    ),
    _field(
        "forward_timeout_seconds",
        "timeouts",
        "request_path",
        "forward_timeout (seconds)",
        "forward_timeout",
        "number",
        _tunable_or_default_if_none("forward_timeout_seconds", 1800),
        _posted_int_reader("forward_timeout_seconds"),
        minimum=0,
        step=1,
        help_text="Maximum total time spent trying to find a forwarding path.",
    ),
    _field(
        "write_timeout_seconds",
        "timeouts",
        "request_path",
        "write_timeout (seconds)",
        "write_timeout",
        "number",
        _tunable_or_default_if_none("write_timeout_seconds", 900),
        _posted_int_reader("write_timeout_seconds"),
        minimum=0,
        step=1,
        help_text="Applied to connections waiting for the socket to become writable.",
    ),
    _field(
        "client_idle_pconn_timeout_seconds",
        "timeouts",
        "lifecycle",
        "client_idle_pconn_timeout (seconds)",
        "client_idle_pconn_timeout",
        "number",
        _tunable_or_default_if_none("client_idle_pconn_timeout_seconds", 120),
        _posted_int_reader("client_idle_pconn_timeout_seconds"),
        minimum=0,
        step=1,
        help_text="How long to keep an idle client-side persistent connection open.",
    ),
    _field(
        "server_idle_pconn_timeout_seconds",
        "timeouts",
        "lifecycle",
        "server_idle_pconn_timeout (seconds)",
        "server_idle_pconn_timeout",
        "number",
        _tunable_or_default_if_none("server_idle_pconn_timeout_seconds", 120),
        _posted_int_reader("server_idle_pconn_timeout_seconds"),
        minimum=0,
        step=1,
        help_text="How long to keep an idle upstream persistent connection open.",
    ),
    _field(
        "pconn_lifetime_seconds",
        "timeouts",
        "lifecycle",
        "pconn_lifetime (seconds)",
        "pconn_lifetime",
        "number",
        _tunable_or_default_if_none("pconn_lifetime_seconds", 0),
        _posted_optional_int_reader("pconn_lifetime_seconds"),
        minimum=0,
        step=1,
        help_text="0 keeps persistent-connection lifetime unlimited.",
    ),
    _field(
        "client_lifetime_seconds",
        "timeouts",
        "lifecycle",
        "client_lifetime (seconds)",
        "client_lifetime",
        "number",
        _tunable_or_default_if_none("client_lifetime_seconds", 3600),
        _posted_int_reader("client_lifetime_seconds"),
        minimum=0,
        step=1,
        help_text="Upper bound for how long a client connection may exist.",
    ),
    _field(
        "shutdown_lifetime_seconds",
        "timeouts",
        "lifecycle",
        "shutdown_lifetime (seconds)",
        "shutdown_lifetime",
        "number",
        _tunable_or_default_if_none("shutdown_lifetime_seconds", 30),
        _posted_int_reader("shutdown_lifetime_seconds"),
        minimum=0,
        step=1,
        help_text="Active connections still open after this long during shutdown are timed out.",
    ),
    _field(
        "logfile_rotate",
        "logging",
        "retention",
        "logfile_rotate",
        "logfile_rotate",
        "number",
        _tunable_or_default_if_none("logfile_rotate", 10),
        _posted_int_reader("logfile_rotate"),
        minimum=0,
        step=1,
        help_text="Default rotation count for stdio logs when Squid receives a rotate signal.",
    ),
    _field(
        "buffered_logs_on",
        "logging",
        "retention",
        "buffered_logs on",
        "buffered_logs",
        "checkbox",
        _tunable_bool_or_default("buffered_logs", True),
        _checkbox_reader("buffered_logs_on"),
        help_text="Can reduce log I/O overhead but delays log availability.",
    ),
    _field(
        "log_mime_hdrs_on",
        "logging",
        "retention",
        "log_mime_hdrs on",
        "log_mime_hdrs",
        "checkbox",
        _tunable_bool_or_default("log_mime_hdrs", False),
        _checkbox_reader("log_mime_hdrs_on"),
        help_text="Log request and response MIME headers in the access log.",
    ),
    _field(
        "stats_collection_rules_text",
        "logging",
        "observability",
        "stats_collection rules",
        "stats_collection",
        "textarea",
        _tunable_or_default_if_none("stats_collection_rules_text", ""),
        _posted_multiline_reader("stats_collection_rules_text"),
        rows=6,
        help_text="Optional ACL rules controlling which requests contribute to performance counters.",
    ),
    _field(
        "tls_key_log_path",
        "logging",
        "observability",
        "tls_key_log destination",
        "tls_key_log",
        "text",
        _tunable_or_default_if_none("tls_key_log_path", ""),
        _posted_text_reader("tls_key_log_path"),
        placeholder="leave blank to disable",
        help_text="Dangerous troubleshooting feature for Wireshark-style TLS decryption; keep disabled unless actively debugging.",
    ),
    _field(
        "client_persistent_connections_on",
        "network",
        "persistent",
        "Client persistent connections",
        "client_persistent_connections",
        "checkbox",
        _tunable_bool_or_default("client_persistent_connections", True),
        _checkbox_reader("client_persistent_connections_on"),
        help_text="Persistent client connections are required for pipeline_prefetch and reduce handshake churn.",
    ),
    _field(
        "server_persistent_connections_on",
        "network",
        "persistent",
        "Server persistent connections",
        "server_persistent_connections",
        "checkbox",
        _tunable_bool_or_default("server_persistent_connections", True),
        _checkbox_reader("server_persistent_connections_on"),
        help_text="Reuses upstream connections when origin servers allow it.",
    ),
    _field(
        "persistent_connection_after_error_on",
        "network",
        "persistent",
        "persistent_connection_after_error on",
        "persistent_connection_after_error",
        "checkbox",
        _tunable_bool_or_default("persistent_connection_after_error", True),
        _checkbox_reader("persistent_connection_after_error_on"),
        help_text="Disable only for buggy clients that mishandle HTTP errors on keep-alive connections.",
    ),
    _field(
        "detect_broken_pconn_on",
        "network",
        "persistent",
        "detect_broken_pconn on",
        "detect_broken_pconn",
        "checkbox",
        _tunable_bool_or_default("detect_broken_pconn", False),
        _checkbox_reader("detect_broken_pconn_on"),
        help_text="Workaround for servers that incorrectly advertise persistence.",
    ),
    _field(
        "half_closed_clients_on",
        "network",
        "persistent",
        "half_closed_clients on",
        "half_closed_clients",
        "checkbox",
        _tunable_bool_or_default("half_closed_clients", False),
        _checkbox_reader("half_closed_clients_on"),
        help_text="Usually leave off unless you specifically benefit from keeping half-closed client sockets alive.",
    ),
    _field(
        "server_pconn_for_nonretriable_rules_text",
        "network",
        "persistent",
        "server_pconn_for_nonretriable rules",
        "server_pconn_for_nonretriable",
        "textarea",
        _tunable_or_default_if_none("server_pconn_for_nonretriable_rules_text", ""),
        _posted_multiline_reader("server_pconn_for_nonretriable_rules_text"),
        rows=6,
        help_text="Advanced ACLs to permit reuse of upstream keep-alive connections for non-retriable requests.",
    ),
    _field(
        "connect_retries",
        "network",
        "retry",
        "connect_retries",
        "connect_retries",
        "number",
        _tunable_or_default_if_none("connect_retries", 1),
        _posted_int_reader("connect_retries"),
        minimum=0,
        maximum=10,
        step=1,
        help_text="Low-level connection reopening attempts before connect_timeout expires.",
    ),
    _field(
        "forward_max_tries",
        "network",
        "retry",
        "forward_max_tries",
        "forward_max_tries",
        "number",
        _tunable_or_default_if_none("forward_max_tries", 10),
        _posted_int_reader("forward_max_tries"),
        minimum=1,
        step=1,
        help_text="High-level forwarding attempts across retries and alternative peers.",
    ),
    _field(
        "retry_on_error_on",
        "network",
        "retry",
        "retry_on_error on",
        "retry_on_error",
        "checkbox",
        _tunable_bool_or_default("retry_on_error", False),
        _checkbox_reader("retry_on_error_on"),
        help_text="Retries a subset of origin errors by seeking another destination.",
    ),
    _field(
        "client_ip_max_connections",
        "network",
        "retry",
        "client_ip_max_connections",
        "client_ip_max_connections",
        "number",
        _tunable_optional("client_ip_max_connections"),
        _posted_optional_int_reader("client_ip_max_connections"),
        minimum=0,
        step=1,
        help_text="Global per-client connection cap; be careful behind NAT or upstream proxies.",
    ),
    _field(
        "tcp_recv_bufsize_kb",
        "network",
        "retry",
        "tcp_recv_bufsize (KB)",
        "tcp_recv_bufsize",
        "number",
        _tunable_optional("tcp_recv_bufsize_kb"),
        _posted_optional_int_reader("tcp_recv_bufsize_kb"),
        minimum=0,
        step=1,
        help_text="Usually best left to the operating system defaults.",
    ),
    _field(
        "accept_filter_value",
        "network",
        "retry",
        "accept_filter",
        "accept_filter",
        "text",
        _tunable_or_default_if_none("accept_filter_value", ""),
        _posted_text_reader("accept_filter_value"),
        placeholder="data or data=30",
        help_text="Kernel-assisted deferred accept; platform dependent.",
    ),
    _field(
        "client_dst_passthru_on",
        "network",
        "intercept",
        "client_dst_passthru on",
        "client_dst_passthru",
        "checkbox",
        _tunable_bool_or_default("client_dst_passthru", True),
        _checkbox_reader("client_dst_passthru_on"),
        help_text="Recommended for intercepted traffic to preserve the original destination IP.",
    ),
    _field(
        "host_verify_strict_on",
        "network",
        "intercept",
        "host_verify_strict on",
        "host_verify_strict",
        "checkbox",
        _tunable_bool_or_default("host_verify_strict", False),
        _checkbox_reader("host_verify_strict_on"),
        help_text="Strict Host header verification; safer but may expose misbehaving clients and servers.",
    ),
    _field(
        "on_unsupported_protocol_action",
        "network",
        "intercept",
        "on_unsupported_protocol action",
        "on_unsupported_protocol",
        "select",
        _tunable_choice_or_default("on_unsupported_protocol_action", ("respond", "tunnel"), "respond"),
        _posted_choice_reader("on_unsupported_protocol_action", allowed=("respond", "tunnel"), default="respond"),
        choices=ON_UNSUPPORTED_PROTOCOL_CHOICES,
        help_text="Global action for strange intercepted traffic. Squid's default is to respond with an error.",
    ),
    _field(
        "happy_eyeballs_connect_timeout_ms",
        "network",
        "intercept",
        "happy_eyeballs_connect_timeout (ms)",
        "happy_eyeballs_connect_timeout",
        "number",
        _tunable_or_default_if_none("happy_eyeballs_connect_timeout_ms", 250),
        _posted_int_reader("happy_eyeballs_connect_timeout_ms"),
        minimum=0,
        step=1,
        help_text="Delay before opening the first spare Happy Eyeballs connection attempt.",
    ),
    _field(
        "happy_eyeballs_connect_gap_ms",
        "network",
        "intercept",
        "happy_eyeballs_connect_gap (ms)",
        "happy_eyeballs_connect_gap",
        "number",
        _tunable_optional("happy_eyeballs_connect_gap_ms"),
        _posted_optional_int_reader("happy_eyeballs_connect_gap_ms"),
        minimum=0,
        step=1,
        help_text="Optional global delay between spare Happy Eyeballs attempts.",
    ),
    _field(
        "happy_eyeballs_connect_limit",
        "network",
        "intercept",
        "happy_eyeballs_connect_limit",
        "happy_eyeballs_connect_limit",
        "number",
        _tunable_optional("happy_eyeballs_connect_limit"),
        _posted_optional_int_reader("happy_eyeballs_connect_limit"),
        minimum=0,
        step=1,
        help_text="0 disables concurrent spare attempts; blank uses Squid's unlimited default.",
    ),
    _field(
        "dns_timeout_seconds",
        "dns",
        "resolver",
        "dns_timeout (seconds)",
        "dns_timeout",
        "number",
        _tunable_or_default_if_none("dns_timeout_seconds", 15),
        _posted_int_reader("dns_timeout_seconds"),
        minimum=0,
        step=1,
        help_text="How long Squid waits before declaring a DNS query failed.",
    ),
    _field(
        "dns_retransmit_interval_seconds",
        "dns",
        "resolver",
        "dns_retransmit_interval (seconds)",
        "dns_retransmit_interval",
        "number",
        _tunable_or_default_if_none("dns_retransmit_interval_seconds", 5),
        _posted_int_reader("dns_retransmit_interval_seconds"),
        minimum=0,
        step=1,
        help_text="Initial DNS retransmit interval before backoff kicks in.",
    ),
    _field(
        "dns_packet_max",
        "dns",
        "resolver",
        "dns_packet_max",
        "dns_packet_max",
        "text",
        _tunable_or_default_if_none("dns_packet_max", None),
        _posted_text_reader("dns_packet_max"),
        placeholder="1232 or none",
        help_text="Advertised EDNS UDP size; use 'none' to disable EDNS.",
    ),
    _field(
        "dns_nameservers",
        "dns",
        "resolver",
        "dns_nameservers",
        "dns_nameservers",
        "text",
        _tunable_or_default_if_none("dns_nameservers", ""),
        _posted_text_reader("dns_nameservers"),
        help_text="Space-separated IPs or hostnames. Leave blank to use the operating system configuration.",
    ),
    _field(
        "hosts_file",
        "dns",
        "resolver",
        "hosts_file",
        "hosts_file",
        "text",
        _tunable_or_default_if_none("hosts_file", "/etc/hosts"),
        _posted_text_reader("hosts_file"),
        help_text="Use 'none' to disable hosts-file checks entirely.",
    ),
    _field(
        "append_domain",
        "dns",
        "resolver",
        "append_domain",
        "append_domain",
        "text",
        _tunable_or_default_if_none("append_domain", ""),
        _posted_text_reader("append_domain"),
        placeholder=".example.local",
        help_text="Appends a local domain to single-label host names. Use with care.",
    ),
    _field(
        "dns_defnames_on",
        "dns",
        "resolver",
        "dns_defnames on",
        "dns_defnames",
        "checkbox",
        _tunable_bool_or_default("dns_defnames", False),
        _checkbox_reader("dns_defnames_on"),
        help_text="Allow Squid to search local domains for single-label host names.",
    ),
    _field(
        "dns_multicast_local_on",
        "dns",
        "resolver",
        "dns_multicast_local on",
        "dns_multicast_local",
        "checkbox",
        _tunable_bool_or_default("dns_multicast_local", False),
        _checkbox_reader("dns_multicast_local_on"),
        help_text="Enable mDNS lookups for .local/.arpa names.",
    ),
    _field(
        "ignore_unknown_nameservers_on",
        "dns",
        "resolver",
        "ignore_unknown_nameservers on",
        "ignore_unknown_nameservers",
        "checkbox",
        _tunable_bool_or_default("ignore_unknown_nameservers", True),
        _checkbox_reader("ignore_unknown_nameservers_on"),
        help_text="When off, Squid accepts DNS responses from IPs it did not query.",
    ),
    _field(
        "check_hostnames_on",
        "dns",
        "validation",
        "check_hostnames on",
        "check_hostnames",
        "checkbox",
        _tunable_bool_or_default("check_hostnames", False),
        _checkbox_reader("check_hostnames_on"),
        help_text="Validate hostnames for RFC-style correctness.",
    ),
    _field(
        "allow_underscore_on",
        "dns",
        "validation",
        "allow_underscore on",
        "allow_underscore",
        "checkbox",
        _tunable_bool_or_default("allow_underscore", True),
        _checkbox_reader("allow_underscore_on"),
        help_text="Only applies when check_hostnames is enabled.",
        depends_on=("check_hostnames_on",),
        show_when=("checked",),
    ),
    _field(
        "positive_dns_ttl_seconds",
        "dns",
        "caches",
        "positive_dns_ttl (seconds)",
        "positive_dns_ttl",
        "number",
        _tunable_or_default_if_none("positive_dns_ttl_seconds", 6 * 3600),
        _posted_optional_int_reader("positive_dns_ttl_seconds"),
        minimum=1,
        step=1,
        help_text="Upper bound for how long Squid caches successful DNS answers.",
    ),
    _field(
        "negative_dns_ttl_seconds",
        "dns",
        "caches",
        "negative_dns_ttl (seconds)",
        "negative_dns_ttl",
        "number",
        _tunable_or_default_if_none("negative_dns_ttl_seconds", 60),
        _posted_optional_int_reader("negative_dns_ttl_seconds"),
        minimum=1,
        step=1,
        help_text="Lower bound for positive lookups and TTL for failed DNS lookups.",
    ),
    _field(
        "ipcache_size",
        "dns",
        "caches",
        "ipcache_size",
        "ipcache_size",
        "number",
        _tunable_or_default_if_none("ipcache_size", 8192),
        _posted_int_reader("ipcache_size"),
        minimum=0,
        step=1,
        help_text="Maximum number of DNS IP cache entries.",
    ),
    _field(
        "ipcache_low",
        "dns",
        "caches",
        "ipcache_low (%)",
        "ipcache_low",
        "number",
        _tunable_or_default_if_none("ipcache_low", 90),
        _posted_int_reader("ipcache_low"),
        minimum=0,
        maximum=100,
        step=1,
        help_text="Low-water mark for the IP cache.",
    ),
    _field(
        "ipcache_high",
        "dns",
        "caches",
        "ipcache_high (%)",
        "ipcache_high",
        "number",
        _tunable_or_default_if_none("ipcache_high", 95),
        _posted_int_reader("ipcache_high"),
        minimum=0,
        maximum=100,
        step=1,
        help_text="High-water mark for the IP cache.",
    ),
    _field(
        "fqdncache_size",
        "dns",
        "caches",
        "fqdncache_size",
        "fqdncache_size",
        "number",
        _tunable_or_default_if_none("fqdncache_size", 8192),
        _posted_int_reader("fqdncache_size"),
        minimum=0,
        step=1,
        help_text="Maximum number of FQDN cache entries.",
    ),
    _field(
        "sslcrtd_program_cache_size_mb",
        "ssl",
        "tls",
        "sslcrtd program cache (MB)",
        "sslcrtd_program",
        "number",
        _resolve_sslcrtd_program_cache_size_mb,
        _posted_int_reader("sslcrtd_program_cache_size_mb"),
        minimum=1,
        step=1,
        help_text="Disk-backed certificate cache used by the helper to speed up repeated MITM certificate generation.",
    ),
    _field(
        "sslcrtd_children",
        "ssl",
        "tls",
        "sslcrtd_children",
        "sslcrtd_children",
        "number",
        _resolve_sslcrtd_children,
        _posted_int_reader("sslcrtd_children"),
        minimum=1,
        maximum=32,
        step=1,
        help_text="Maximum certificate-generation helper processes.",
    ),
    _field(
        "sslcrtd_children_startup",
        "ssl",
        "tls",
        "sslcrtd_children startup",
        "sslcrtd_children",
        "number",
        _resolve_sslcrtd_children_startup,
        _posted_optional_int_reader("sslcrtd_children_startup"),
        minimum=0,
        step=1,
        help_text="Minimum helpers to spawn immediately on startup/reconfigure.",
    ),
    _field(
        "sslcrtd_children_idle",
        "ssl",
        "tls",
        "sslcrtd_children idle",
        "sslcrtd_children",
        "number",
        _resolve_sslcrtd_children_idle,
        _posted_optional_int_reader("sslcrtd_children_idle"),
        minimum=1,
        step=1,
        help_text="Minimum number of idle helpers Squid tries to maintain.",
    ),
    _field(
        "sslcrtd_children_queue_size",
        "ssl",
        "tls",
        "sslcrtd_children queue-size",
        "sslcrtd_children",
        "number",
        _resolve_sslcrtd_children_queue_size,
        _posted_optional_int_reader("sslcrtd_children_queue_size"),
        minimum=1,
        step=1,
        help_text="Maximum queued helper requests when no child is idle.",
    ),
    _field(
        "dynamic_cert_mem_cache_size_mb",
        "ssl",
        "tls",
        "dynamic_cert_mem_cache_size (MB)",
        "http_port generate-host-certificates",
        "number",
        _resolve_dynamic_cert_mem_cache_mb,
        _posted_int_reader("dynamic_cert_mem_cache_size_mb"),
        minimum=0,
        step=1,
        help_text="In-memory cache for generated host certificates.",
    ),
    _field(
        "tls_outgoing_options_line",
        "ssl",
        "tls",
        "tls_outgoing_options",
        "tls_outgoing_options",
        "text",
        _tunable_or_default_if_none("tls_outgoing_options_line", "min-version=1.2 options=NO_SSLv3"),
        _posted_text_reader("tls_outgoing_options_line"),
        help_text="Origin-facing TLS baseline. Clear to use Squid's own default.",
    ),
    _field(
        "sslproxy_session_ttl_seconds",
        "ssl",
        "tls",
        "sslproxy_session_ttl (seconds)",
        "sslproxy_session_ttl",
        "number",
        _tunable_or_default_if_none("sslproxy_session_ttl_seconds", 600),
        _posted_int_reader("sslproxy_session_ttl_seconds"),
        minimum=0,
        step=1,
        help_text="Origin TLS session cache entry lifetime.",
    ),
    _field(
        "sslproxy_session_cache_size_mb",
        "ssl",
        "tls",
        "sslproxy_session_cache_size (MB)",
        "sslproxy_session_cache_size",
        "number",
        _tunable_or_default_if_none("sslproxy_session_cache_size_mb", 32),
        _posted_int_reader("sslproxy_session_cache_size_mb"),
        minimum=0,
        step=1,
        help_text="Origin TLS session cache size.",
    ),
    _field(
        "sslproxy_foreign_intermediate_certs",
        "ssl",
        "tls",
        "sslproxy_foreign_intermediate_certs",
        "sslproxy_foreign_intermediate_certs",
        "text",
        _tunable_or_default_if_none("sslproxy_foreign_intermediate_certs", ""),
        _posted_text_reader("sslproxy_foreign_intermediate_certs"),
        help_text="Optional PEM bundle of untrusted intermediates Squid can use to complete broken origin certificate chains.",
    ),
    _field(
        "sslproxy_cert_sign_hash",
        "ssl",
        "tls",
        "sslproxy_cert_sign_hash",
        "sslproxy_cert_sign_hash",
        "select",
        _tunable_choice_or_default("sslproxy_cert_sign_hash", ("sha256", "sha512", "sha1", "md5"), "sha256"),
        _posted_choice_reader("sslproxy_cert_sign_hash", allowed=("sha256", "sha512", "sha1", "md5"), default="sha256"),
        choices=SSL_CERT_SIGN_HASH_CHOICES,
        help_text="Hash used when signing generated MITM certificates.",
    ),
    _field(
        "ssl_unclean_shutdown_on",
        "ssl",
        "tls",
        "ssl_unclean_shutdown on",
        "ssl_unclean_shutdown",
        "checkbox",
        _tunable_bool_or_default("ssl_unclean_shutdown", False),
        _checkbox_reader("ssl_unclean_shutdown_on"),
        help_text="Compatibility workaround for buggy TLS clients; normally leave off.",
    ),
    _field(
        "additional_ssl_rules_text",
        "ssl",
        "rules",
        "Additional ssl_bump rules",
        "ssl_bump",
        "textarea",
        _tunable_or_default_if_none("additional_ssl_rules_text", ""),
        _posted_multiline_reader("additional_ssl_rules_text"),
        rows=8,
        help_text="Inserted before the final 'ssl_bump bump all'. Exclusions and SSL-filter CIDR bypasses remain managed on their dedicated pages.",
    ),
    _field(
        "sslproxy_cert_error_rules_text",
        "ssl",
        "rules",
        "sslproxy_cert_error rules",
        "sslproxy_cert_error",
        "textarea",
        _tunable_or_default_if_none("sslproxy_cert_error_rules_text", ""),
        _posted_multiline_reader("sslproxy_cert_error_rules_text"),
        rows=6,
        help_text="Advanced ACL rules that bypass origin certificate validation errors.",
    ),
    _field(
        "sslproxy_cert_sign_rules_text",
        "ssl",
        "rules",
        "sslproxy_cert_sign rules",
        "sslproxy_cert_sign",
        "textarea",
        _tunable_or_default_if_none("sslproxy_cert_sign_rules_text", ""),
        _posted_multiline_reader("sslproxy_cert_sign_rules_text"),
        rows=6,
        help_text="Advanced signing-algorithm overrides for generated certificates.",
    ),
    _field(
        "sslproxy_cert_adapt_rules_text",
        "ssl",
        "rules",
        "sslproxy_cert_adapt rules",
        "sslproxy_cert_adapt",
        "textarea",
        _tunable_or_default_if_none("sslproxy_cert_adapt_rules_text", ""),
        _posted_multiline_reader("sslproxy_cert_adapt_rules_text"),
        rows=6,
        help_text="Advanced generated-certificate adaptation rules.",
    ),
    _field(
        "icap_enable_on",
        "icap",
        "controls",
        "icap_enable on",
        "icap_enable",
        "checkbox",
        _tunable_bool_or_default("icap_enable", True),
        _checkbox_reader("icap_enable_on"),
        help_text="Global ICAP enable/disable switch.",
    ),
    _field(
        "icap_send_client_ip_on",
        "icap",
        "controls",
        "icap_send_client_ip on",
        "adaptation_send_client_ip",
        "checkbox",
        _tunable_bool_or_default("icap_send_client_ip", True),
        _checkbox_reader("icap_send_client_ip_on"),
        help_text="Forward client IP metadata to ICAP services.",
    ),
    _field(
        "icap_send_client_username_on",
        "icap",
        "controls",
        "icap_send_client_username on",
        "adaptation_send_username",
        "checkbox",
        _tunable_bool_or_default("icap_send_client_username", False),
        _checkbox_reader("icap_send_client_username_on"),
        help_text="Forward authenticated usernames to ICAP services when available.",
    ),
    _field(
        "icap_persistent_connections_on",
        "icap",
        "controls",
        "icap_persistent_connections on",
        "icap_persistent_connections",
        "checkbox",
        _tunable_bool_or_default("icap_persistent_connections", True),
        _checkbox_reader("icap_persistent_connections_on"),
        help_text="Reuse connections to ICAP services.",
    ),
    _field(
        "icap_preview_enable_on",
        "icap",
        "controls",
        "icap_preview_enable on",
        "icap_preview_enable",
        "checkbox",
        _tunable_bool_or_default("icap_preview_enable", True),
        _checkbox_reader("icap_preview_enable_on"),
        help_text="Let ICAP services request preview data for early decisions.",
    ),
    _field(
        "icap_preview_size_kb",
        "icap",
        "timers",
        "icap_preview_size (KB)",
        "icap_preview_size",
        "number",
        _tunable_or_default_if_none("icap_preview_size_kb", 1024),
        _posted_int_reader("icap_preview_size_kb"),
        minimum=0,
        step=1,
        help_text="Maximum preview data offered to ICAP services.",
        depends_on=("icap_enable_on", "icap_preview_enable_on"),
        show_when=("checked", "checked"),
    ),
    _field(
        "icap_default_options_ttl_seconds",
        "icap",
        "timers",
        "icap_default_options_ttl (seconds)",
        "icap_default_options_ttl",
        "number",
        _tunable_or_default_if_none("icap_default_options_ttl_seconds", 300),
        _posted_int_reader("icap_default_options_ttl_seconds"),
        minimum=0,
        step=1,
        help_text="How long Squid caches ICAP OPTIONS responses by default.",
        depends_on=("icap_enable_on",),
        show_when=("checked",),
    ),
    _field(
        "icap_connect_timeout_seconds",
        "icap",
        "timers",
        "icap_connect_timeout (seconds)",
        "icap_connect_timeout",
        "number",
        _tunable_or_default_if_none("icap_connect_timeout_seconds", 15),
        _posted_int_reader("icap_connect_timeout_seconds"),
        minimum=0,
        step=1,
        help_text="ICAP TCP connect timeout.",
        depends_on=("icap_enable_on",),
        show_when=("checked",),
    ),
    _field(
        "icap_io_timeout_seconds",
        "icap",
        "timers",
        "icap_io_timeout (seconds)",
        "icap_io_timeout",
        "number",
        _tunable_or_default_if_none("icap_io_timeout_seconds", 300),
        _posted_int_reader("icap_io_timeout_seconds"),
        minimum=0,
        step=1,
        help_text="ICAP response I/O timeout.",
        depends_on=("icap_enable_on",),
        show_when=("checked",),
    ),
    _field(
        "icap_service_failure_limit",
        "icap",
        "timers",
        "icap_service_failure_limit",
        "icap_service_failure_limit",
        "number",
        _tunable_or_default_if_none("icap_service_failure_limit", 10),
        _posted_optional_int_reader("icap_service_failure_limit"),
        step=1,
        help_text="How many failures within the configured window mark a service unusable.",
        depends_on=("icap_enable_on",),
        show_when=("checked",),
    ),
    _field(
        "icap_service_failure_limit_window_seconds",
        "icap",
        "timers",
        "icap_service_failure_limit window (seconds)",
        "icap_service_failure_limit",
        "number",
        _tunable_or_default_if_none("icap_service_failure_limit_window_seconds", 30),
        _posted_optional_int_reader("icap_service_failure_limit_window_seconds"),
        minimum=0,
        step=1,
        help_text="Rolling window for service failure accounting.",
        depends_on=("icap_enable_on",),
        show_when=("checked",),
    ),
    _field(
        "icap_service_revival_delay_seconds",
        "icap",
        "timers",
        "icap_service_revival_delay (seconds)",
        "icap_service_revival_delay",
        "number",
        _tunable_or_default_if_none("icap_service_revival_delay_seconds", 60),
        _posted_int_reader("icap_service_revival_delay_seconds"),
        minimum=0,
        step=1,
        help_text="How long Squid waits before retrying a failed ICAP service.",
        depends_on=("icap_enable_on",),
        show_when=("checked",),
    ),
    _field(
        "forwarded_for_value",
        "privacy",
        "headers",
        "forwarded_for",
        "forwarded_for",
        "select",
        _tunable_or_default_if_none("forwarded_for_value", ""),
        _posted_choice_reader(
            "forwarded_for_value",
            allowed=("", "on", "off", "transparent", "delete", "truncate"),
            default="",
        ),
        choices=FORWARDED_FOR_CHOICES,
        help_text="Controls how Squid emits X-Forwarded-For upstream.",
    ),
    _field(
        "via_on",
        "privacy",
        "headers",
        "via on",
        "via",
        "checkbox",
        _tunable_bool_or_default("via", True),
        _checkbox_reader("via_on"),
        help_text="RFC-style Via header in forwarded requests and responses.",
    ),
    _field(
        "follow_x_forwarded_for_value",
        "privacy",
        "headers",
        "follow_x_forwarded_for",
        "follow_x_forwarded_for",
        "text",
        _tunable_or_default_if_none("follow_x_forwarded_for_value", ""),
        _posted_text_reader("follow_x_forwarded_for_value"),
        placeholder="allow all or allow trusted_proxies",
        help_text="Advanced trust rules for upstream proxies that provide real client IP information.",
    ),
    _field(
        "client_netmask_value",
        "privacy",
        "logging",
        "client_netmask",
        "client_netmask",
        "text",
        _tunable_or_default_if_none("client_netmask_value", ""),
        _posted_text_reader("client_netmask_value"),
        placeholder="255.255.255.0",
        help_text="Optional log anonymization mask for client IPs.",
    ),
    _field(
        "strip_query_terms_on",
        "privacy",
        "logging",
        "strip_query_terms on",
        "strip_query_terms",
        "checkbox",
        _tunable_bool_or_default("strip_query_terms", True),
        _checkbox_reader("strip_query_terms_on"),
        help_text="Strips query strings from access logs to reduce privacy exposure and log volume.",
    ),
    _field(
        "request_header_max_size_kb",
        "limits",
        "sizes",
        "request_header_max_size (KB)",
        "request_header_max_size",
        "number",
        _tunable_or_default_if_none("request_header_max_size_kb", 64),
        _posted_optional_int_reader("request_header_max_size_kb"),
        minimum=1,
        step=1,
        help_text="Increasing this beyond 64 KB can expose older Squid code paths to DoS risk.",
    ),
    _field(
        "reply_header_max_size_kb",
        "limits",
        "sizes",
        "reply_header_max_size (KB)",
        "reply_header_max_size",
        "number",
        _tunable_or_default_if_none("reply_header_max_size_kb", 64),
        _posted_optional_int_reader("reply_header_max_size_kb"),
        minimum=1,
        step=1,
        help_text="Increasing this beyond 64 KB can expose older Squid code paths to DoS risk.",
    ),
    _field(
        "request_body_max_size_mb",
        "limits",
        "sizes",
        "request_body_max_size (MB)",
        "request_body_max_size",
        "number",
        _tunable_or_default_if_none("request_body_max_size_mb", 0),
        _posted_optional_int_reader("request_body_max_size_mb"),
        minimum=0,
        step=1,
        help_text="0 means no limit on request body size.",
    ),
    _field(
        "client_request_buffer_max_size_kb",
        "limits",
        "sizes",
        "client_request_buffer_max_size (KB)",
        "client_request_buffer_max_size",
        "number",
        _tunable_or_default_if_none("client_request_buffer_max_size_kb", 512),
        _posted_optional_int_reader("client_request_buffer_max_size_kb"),
        minimum=0,
        step=1,
        help_text="Limits how much of an upload Squid buffers from a client.",
    ),
    _field(
        "relaxed_header_parser_mode",
        "limits",
        "parser",
        "relaxed_header_parser",
        "relaxed_header_parser",
        "select",
        _tunable_choice_or_default("relaxed_header_parser_mode", ("on", "warn", "off"), "on"),
        _posted_choice_reader("relaxed_header_parser_mode", allowed=("on", "warn", "off"), default="on"),
        choices=RELAXED_HEADER_PARSER_CHOICES,
        help_text="On by default; set to warn to surface malformed traffic without rejecting it.",
    ),
    _field(
        "uri_whitespace_mode",
        "limits",
        "parser",
        "uri_whitespace",
        "uri_whitespace",
        "select",
        _tunable_choice_or_default("uri_whitespace_mode", ("strip", "deny", "allow", "encode", "chop"), "strip"),
        _posted_choice_reader("uri_whitespace_mode", allowed=("strip", "deny", "allow", "encode", "chop"), default="strip"),
        choices=URI_WHITESPACE_CHOICES,
        help_text="Tolerant default keeps generic URIs working while normalizing unsafe whitespace.",
    ),
    _field(
        "http_upgrade_request_protocols_rules_text",
        "limits",
        "parser",
        "http_upgrade_request_protocols rules",
        "http_upgrade_request_protocols",
        "textarea",
        _tunable_or_default_if_none("http_upgrade_request_protocols_rules_text", ""),
        _posted_multiline_reader("http_upgrade_request_protocols_rules_text"),
        rows=6,
        help_text="Optional allow/deny rules for protocol upgrades such as WebSocket.",
    ),
    _field(
        "memory_pools_on",
        "performance",
        "smp",
        "memory_pools on",
        "memory_pools",
        "checkbox",
        _tunable_bool_or_default("memory_pools", True),
        _checkbox_reader("memory_pools_on"),
        help_text="Keep reusable memory chunks available for future allocations.",
    ),
    _field(
        "memory_pools_limit_mb",
        "performance",
        "smp",
        "memory_pools_limit (MB)",
        "memory_pools_limit",
        "text",
        _tunable_or_default_if_none("memory_pools_limit_mb", 64),
        _posted_optional_int_or_none_reader("memory_pools_limit_mb"),
        placeholder="64 or none",
        help_text="Use 'none' to keep all free pooled memory; use memory_pools off to disable the feature entirely.",
        depends_on=("memory_pools_on",),
        show_when=("checked",),
    ),
    _field(
        "shared_memory_locking_on",
        "performance",
        "smp",
        "shared_memory_locking on",
        "shared_memory_locking",
        "checkbox",
        _tunable_bool_or_default("shared_memory_locking", False),
        _checkbox_reader("shared_memory_locking_on"),
        help_text="Reduces the risk of optimistic-kernel SIGBUS crashes in SMP mode.",
    ),
    _field(
        "workers",
        "performance",
        "smp",
        "workers",
        "workers",
        "number",
        _resolve_workers,
        _posted_int_reader("workers", clamp=_clamp_workers),
        minimum=1,
        maximum=4,
        step=1,
        help_text="Changing workers requires a full Squid restart and cache metadata reinitialization.",
    ),
    _field(
        "cpu_affinity_map",
        "performance",
        "smp",
        "cpu_affinity_map",
        "cpu_affinity_map",
        "text",
        _tunable_or_default_if_none("cpu_affinity_map", ""),
        _posted_text_reader("cpu_affinity_map"),
        placeholder="process_numbers=1,2 cores=1,3",
        help_text="Optional 1:1 worker-to-core pinning; leave blank to let the OS schedule workers normally.",
    ),
    _field(
        "max_filedescriptors",
        "performance",
        "store",
        "max_filedescriptors",
        "max_filedescriptors",
        "number",
        _tunable_or_default_if_none("max_filedescriptors", 65535),
        _posted_int_reader("max_filedescriptors"),
        minimum=0,
        step=1,
        help_text="Requires a restart and cannot exceed the container's hard limit.",
    ),
    _field(
        "max_open_disk_fds",
        "performance",
        "store",
        "max_open_disk_fds",
        "max_open_disk_fds",
        "number",
        _tunable_or_default_if_none("max_open_disk_fds", 0),
        _posted_optional_int_reader("max_open_disk_fds"),
        minimum=0,
        step=1,
        help_text="0 means no limit.",
    ),
    _field(
        "store_avg_object_size_kb",
        "performance",
        "store",
        "store_avg_object_size (KB)",
        "store_avg_object_size",
        "number",
        _tunable_or_default_if_none("store_avg_object_size_kb", 32),
        _posted_optional_int_reader("store_avg_object_size_kb"),
        minimum=0,
        step=1,
        help_text="Seed for cache-index sizing; check cachemgr info before tuning aggressively.",
    ),
    _field(
        "store_objects_per_bucket",
        "performance",
        "store",
        "store_objects_per_bucket",
        "store_objects_per_bucket",
        "number",
        _tunable_or_default_if_none("store_objects_per_bucket", 16),
        _posted_optional_int_reader("store_objects_per_bucket"),
        minimum=0,
        step=1,
        help_text="Lower values increase bucket count and maintenance rate.",
    ),
    _field(
        "client_db_on",
        "performance",
        "store",
        "client_db on",
        "client_db",
        "checkbox",
        _tunable_bool_or_default("client_db", True),
        _checkbox_reader("client_db_on"),
        help_text="Needed for some per-client limits like client_ip_max_connections.",
    ),
    _field(
        "offline_mode_on",
        "performance",
        "store",
        "offline_mode on",
        "offline_mode",
        "checkbox",
        _tunable_bool_or_default("offline_mode", False),
        _checkbox_reader("offline_mode_on"),
        help_text="Never revalidate cached objects. Powerful and dangerous; default is off for good reasons.",
    ),
    _field(
        "paranoid_hit_validation_value",
        "performance",
        "store",
        "paranoid_hit_validation",
        "paranoid_hit_validation",
        "text",
        _tunable_or_default_if_none("paranoid_hit_validation_value", "0"),
        _posted_text_reader("paranoid_hit_validation_value"),
        placeholder="0 or 250 milliseconds",
        help_text="0 disables it; positive values enable metadata integrity checks on cache hits.",
    ),
    _field(
        "visible_hostname",
        "http",
        "identity",
        "visible_hostname",
        "visible_hostname",
        "text",
        _tunable_or_default_if_none("visible_hostname", ""),
        _posted_text_reader("visible_hostname"),
        help_text="Displayed in Squid-generated error pages and some diagnostics.",
    ),
    _field(
        "httpd_suppress_version_string_on",
        "http",
        "identity",
        "httpd_suppress_version_string on",
        "httpd_suppress_version_string",
        "checkbox",
        _tunable_bool_or_default("httpd_suppress_version_string", False),
        _checkbox_reader("httpd_suppress_version_string_on"),
        help_text="Hide Squid version details from generated content where possible.",
    ),
    _field(
        "vary_ignore_expire_on",
        "http",
        "identity",
        "vary_ignore_expire on",
        "vary_ignore_expire",
        "checkbox",
        _tunable_bool_or_default("vary_ignore_expire", False),
        _checkbox_reader("vary_ignore_expire_on"),
        help_text="Compatibility feature for some varying responses; can make unsafe objects cacheable.",
    ),
)


FIELD_MAP: dict[str, ConfigFieldSpec] = {field.key: field for field in CONFIG_FIELDS}


FORM_KIND_FIELD_SPECS: dict[str, tuple[ConfigFieldSpec, ...]] = {
    section: tuple(field for field in CONFIG_FIELDS if field.section == section)
    for section in (
        "caching",
        "timeouts",
        "logging",
        "network",
        "dns",
        "ssl",
        "icap",
        "privacy",
        "limits",
        "performance",
        "http",
    )
}

# Keep workers accepted on the caching form path for backward compatibility with
# older tests and any bookmarked/manual POST workflows, even though the UI now
# presents it under the Performance section.
FORM_KIND_FIELD_SPECS["caching"] = FORM_KIND_FIELD_SPECS["caching"] + (FIELD_MAP["workers"],)


CONFIG_UI_SECTIONS: tuple[UiSectionSpec, ...] = (
    UiSectionSpec(
        key="caching",
        label="Caching",
        description="Disk, memory, heuristics, and cache-policy rules.",
        apply_note="Generates the managed cache block, validates it, and applies it.",
        groups=(
            UiGroupSpec(
                key="store",
                title="Cache store and eviction",
                description="Disk layout, replacement policy, and swap watermarks.",
                field_keys=(
                    "cache_dir_type",
                    "cache_dir_size_mb",
                    "cache_dir_ufs_l1",
                    "cache_dir_ufs_l2",
                    "cache_dir_rock_slot_size_kb",
                    "cache_dir_rock_swap_timeout_ms",
                    "cache_dir_rock_max_swap_rate",
                    "store_dir_select_algorithm",
                    "cache_replacement_policy",
                    "cache_swap_low",
                    "cache_swap_high",
                ),
            ),
            UiGroupSpec(
                key="memory",
                title="Memory and object sizing",
                description="cache_mem, object-size limits, and SMP shared-memory behavior.",
                field_keys=(
                    "cache_mem_mb",
                    "maximum_object_size_mb",
                    "maximum_object_size_in_memory_kb",
                    "minimum_object_size_kb",
                    "memory_cache_mode",
                    "memory_cache_shared_on",
                    "memory_replacement_policy",
                    "shared_transient_entries_limit",
                ),
            ),
            UiGroupSpec(
                key="heuristics",
                title="Heuristics and range handling",
                description="Controls how aggressively Squid coalesces, prefetches, and finishes cacheable downloads.",
                field_keys=(
                    "collapsed_forwarding_on",
                    "collapsed_forwarding_access_rules_text",
                    "range_cache_on",
                    "range_offset_limit_value",
                    "cache_miss_revalidate_on",
                    "pipeline_prefetch_on",
                    "pipeline_prefetch_count",
                    "read_ahead_gap_kb",
                    "quick_abort_min_kb",
                    "quick_abort_max_kb",
                    "quick_abort_pct",
                    "negative_ttl_seconds",
                    "minimum_expiry_time_seconds",
                    "max_stale_seconds",
                    "refresh_all_ims_on",
                ),
            ),
            UiGroupSpec(
                key="rules",
                title="Policy and refresh rules",
                description="Multi-line directive blocks for cache admission and refresh heuristics.",
                field_keys=("cache_policy_rules_text", "refresh_patterns_text"),
            ),
        ),
    ),
    UiSectionSpec(
        key="timeouts",
        label="Timeouts",
        description="Client, server, and forwarding timeouts.",
        apply_note="Updates the managed timeout block and applies it to the selected proxy.",
        groups=(
            UiGroupSpec(
                key="request_path",
                title="Request path",
                description="Timeouts for establishing, forwarding, and actively reading/writing requests.",
                field_keys=(
                    "connect_timeout_seconds",
                    "peer_connect_timeout_seconds",
                    "request_start_timeout_seconds",
                    "request_timeout_seconds",
                    "read_timeout_seconds",
                    "forward_timeout_seconds",
                    "write_timeout_seconds",
                ),
            ),
            UiGroupSpec(
                key="lifecycle",
                title="Connection lifecycle",
                description="Persistent-connection idle timeouts and shutdown behavior.",
                field_keys=(
                    "client_idle_pconn_timeout_seconds",
                    "server_idle_pconn_timeout_seconds",
                    "pconn_lifetime_seconds",
                    "client_lifetime_seconds",
                    "shutdown_lifetime_seconds",
                ),
            ),
        ),
    ),
    UiSectionSpec(
        key="logging",
        label="Logging",
        description="Log retention, MIME/header logging, and observability toggles.",
        apply_note="The Admin UI keeps the core access/cache/ICAP log destinations and formats managed for observability.",
        groups=(
            UiGroupSpec(
                key="retention",
                title="Retention and detail",
                description="Controls how verbose Squid's standard logs are and how long rotated logs are kept.",
                field_keys=("logfile_rotate", "buffered_logs_on", "log_mime_hdrs_on"),
            ),
            UiGroupSpec(
                key="observability",
                title="Advanced observability",
                description="Optional ACL-based stats scoping and TLS key logging.",
                field_keys=("stats_collection_rules_text", "tls_key_log_path"),
            ),
        ),
    ),
    UiSectionSpec(
        key="network",
        label="Network",
        description="Persistent connections, retries, socket tuning, and interception behavior.",
        apply_note="Use conservative changes here; several directives alter failure semantics and client compatibility.",
        groups=(
            UiGroupSpec(
                key="persistent",
                title="Persistent connections",
                description="Keep-alive behavior for clients and servers.",
                field_keys=(
                    "client_persistent_connections_on",
                    "server_persistent_connections_on",
                    "persistent_connection_after_error_on",
                    "detect_broken_pconn_on",
                    "half_closed_clients_on",
                    "server_pconn_for_nonretriable_rules_text",
                ),
            ),
            UiGroupSpec(
                key="retry",
                title="Retries and socket tuning",
                description="How aggressively Squid retries failed forwards and tunes per-socket buffering.",
                field_keys=(
                    "connect_retries",
                    "forward_max_tries",
                    "retry_on_error_on",
                    "client_ip_max_connections",
                    "tcp_recv_bufsize_kb",
                    "accept_filter_value",
                ),
            ),
            UiGroupSpec(
                key="intercept",
                title="Intercepted and dual-stack traffic",
                description="Traffic-shaping features that matter most for transparent or mixed IPv4/IPv6 deployments.",
                field_keys=(
                    "client_dst_passthru_on",
                    "host_verify_strict_on",
                    "on_unsupported_protocol_action",
                    "happy_eyeballs_connect_timeout_ms",
                    "happy_eyeballs_connect_gap_ms",
                    "happy_eyeballs_connect_limit",
                ),
            ),
        ),
    ),
    UiSectionSpec(
        key="dns",
        label="DNS",
        description="Resolver settings, hostname validation, and DNS cache sizing.",
        apply_note="These settings affect both latency and resilience when origin names resolve poorly.",
        groups=(
            UiGroupSpec(
                key="resolver",
                title="Resolver behavior",
                description="Which resolvers Squid queries and how it retries them.",
                field_keys=(
                    "dns_timeout_seconds",
                    "dns_retransmit_interval_seconds",
                    "dns_packet_max",
                    "dns_nameservers",
                    "hosts_file",
                    "append_domain",
                    "dns_defnames_on",
                    "dns_multicast_local_on",
                    "ignore_unknown_nameservers_on",
                ),
            ),
            UiGroupSpec(
                key="validation",
                title="Hostname validation",
                description="Controls how strictly Squid validates DNS names.",
                field_keys=("check_hostnames_on", "allow_underscore_on"),
            ),
            UiGroupSpec(
                key="caches",
                title="DNS caches",
                description="Positive/negative TTLs and cache capacities for IP and FQDN entries.",
                field_keys=(
                    "positive_dns_ttl_seconds",
                    "negative_dns_ttl_seconds",
                    "ipcache_size",
                    "ipcache_low",
                    "ipcache_high",
                    "fqdncache_size",
                ),
            ),
        ),
    ),
    UiSectionSpec(
        key="ssl",
        label="SSL/TLS",
        description="Bump helper sizing, outgoing TLS policy, and advanced certificate behavior.",
        apply_note="Exclusions and SSL-filter CIDR bypasses remain managed on their dedicated pages; this tab focuses on Squid's TLS machinery itself.",
        groups=(
            UiGroupSpec(
                key="tls",
                title="TLS baseline",
                description="Helper sizing and origin-facing TLS session behavior.",
                field_keys=(
                    "sslcrtd_program_cache_size_mb",
                    "sslcrtd_children",
                    "sslcrtd_children_startup",
                    "sslcrtd_children_idle",
                    "sslcrtd_children_queue_size",
                    "dynamic_cert_mem_cache_size_mb",
                    "tls_outgoing_options_line",
                    "sslproxy_session_ttl_seconds",
                    "sslproxy_session_cache_size_mb",
                    "sslproxy_foreign_intermediate_certs",
                    "sslproxy_cert_sign_hash",
                    "ssl_unclean_shutdown_on",
                ),
            ),
            UiGroupSpec(
                key="rules",
                title="Advanced certificate and bump rules",
                description="Multi-line rule blocks for certificate validation/signing/adaptation and custom ssl_bump policy.",
                field_keys=(
                    "additional_ssl_rules_text",
                    "sslproxy_cert_error_rules_text",
                    "sslproxy_cert_sign_rules_text",
                    "sslproxy_cert_adapt_rules_text",
                ),
            ),
        ),
    ),
    UiSectionSpec(
        key="icap",
        label="ICAP",
        description="ICAP service reuse, previews, and failure handling.",
        apply_note="The service endpoints themselves remain generated from the container environment; this tab manages Squid-side adaptation behavior.",
        groups=(
            UiGroupSpec(
                key="controls",
                title="ICAP controls",
                description="Global enablement and metadata forwarding.",
                field_keys=(
                    "icap_enable_on",
                    "icap_send_client_ip_on",
                    "icap_send_client_username_on",
                    "icap_persistent_connections_on",
                    "icap_preview_enable_on",
                ),
            ),
            UiGroupSpec(
                key="timers",
                title="ICAP timeouts and failure handling",
                description="How Squid caches OPTIONS, previews bodies, and suppresses flapping services.",
                field_keys=(
                    "icap_preview_size_kb",
                    "icap_default_options_ttl_seconds",
                    "icap_connect_timeout_seconds",
                    "icap_io_timeout_seconds",
                    "icap_service_failure_limit",
                    "icap_service_failure_limit_window_seconds",
                    "icap_service_revival_delay_seconds",
                ),
            ),
        ),
    ),
    UiSectionSpec(
        key="privacy",
        label="Privacy",
        description="Forwarding headers and log-privacy controls.",
        apply_note="These settings change what upstream services and operators can infer about clients.",
        groups=(
            UiGroupSpec(
                key="headers",
                title="Forwarding headers",
                description="How Squid emits and trusts client-address metadata.",
                field_keys=("forwarded_for_value", "via_on", "follow_x_forwarded_for_value"),
            ),
            UiGroupSpec(
                key="logging",
                title="Log privacy",
                description="Protect or expose client details in log files.",
                field_keys=("client_netmask_value", "strip_query_terms_on"),
            ),
        ),
    ),
    UiSectionSpec(
        key="limits",
        label="Limits",
        description="HTTP size limits, parser tolerance, and upgrade handling.",
        apply_note="Higher limits help unusual traffic but can widen the blast radius of malformed or hostile requests.",
        groups=(
            UiGroupSpec(
                key="sizes",
                title="HTTP size limits",
                description="Bounds on request/response headers, uploads, and client buffering.",
                field_keys=(
                    "request_header_max_size_kb",
                    "reply_header_max_size_kb",
                    "request_body_max_size_mb",
                    "client_request_buffer_max_size_kb",
                ),
            ),
            UiGroupSpec(
                key="parser",
                title="Parser and upgrades",
                description="Parser strictness, URI normalization, and explicit protocol-upgrade policy.",
                field_keys=(
                    "relaxed_header_parser_mode",
                    "uri_whitespace_mode",
                    "http_upgrade_request_protocols_rules_text",
                ),
            ),
        ),
    ),
    UiSectionSpec(
        key="performance",
        label="Performance",
        description="SMP sizing, memory pools, file descriptors, and cache-index tuning.",
        apply_note="Changes to workers and max_filedescriptors require a restart to take full effect.",
        groups=(
            UiGroupSpec(
                key="smp",
                title="SMP and memory pools",
                description="Worker process count, core pinning, and shared-memory behavior.",
                field_keys=(
                    "memory_pools_on",
                    "memory_pools_limit_mb",
                    "shared_memory_locking_on",
                    "workers",
                    "cpu_affinity_map",
                ),
            ),
            UiGroupSpec(
                key="store",
                title="Store and resource limits",
                description="Descriptors, cache-index sizing, and advanced storage behavior.",
                field_keys=(
                    "max_filedescriptors",
                    "max_open_disk_fds",
                    "store_avg_object_size_kb",
                    "store_objects_per_bucket",
                    "client_db_on",
                    "offline_mode_on",
                    "paranoid_hit_validation_value",
                ),
            ),
        ),
    ),
    UiSectionSpec(
        key="http",
        label="HTTP",
        description="Identity and compatibility features for HTTP traffic itself.",
        apply_note="These settings are usually low-risk but can affect caches that front many misbehaving applications.",
        groups=(
            UiGroupSpec(
                key="identity",
                title="Identity and compatibility",
                description="How Squid names itself and handles some Vary edge cases.",
                field_keys=("visible_hostname", "httpd_suppress_version_string_on", "vary_ignore_expire_on"),
            ),
        ),
    ),
)


SAFE_FORM_KINDS = frozenset(FORM_KIND_FIELD_SPECS)


CACHE_OVERRIDE_FIELDS: tuple[str, ...] = (
    "client_no_cache",
    "client_no_store",
    "origin_private",
    "origin_no_store",
    "origin_no_cache",
    "ignore_auth",
)


def get_config_ui_sections() -> tuple[UiSectionSpec, ...]:
    return CONFIG_UI_SECTIONS


def get_config_ui_field_map() -> Mapping[str, ConfigFieldSpec]:
    return FIELD_MAP


def normalize_safe_form_kind(form_kind: object | None) -> str:
    candidate = str(form_kind or "caching").strip().lower()
    return candidate if candidate in SAFE_FORM_KINDS else "caching"


def _normalize_template_options(options: OptionMap) -> OptionMap:
    range_value = _normalize_range_offset_limit_value(options.get("range_offset_limit_value"))
    if not bool(options.get("range_cache_on", True)):
        range_value = "0"
    elif not _range_value_enabled(range_value):
        range_value = "128 MB"
    options["range_offset_limit_value"] = range_value
    options["range_cache_on"] = _range_value_enabled(range_value)

    try:
        pipeline_count = max(0, int(options.get("pipeline_prefetch_count") or 0))
    except Exception:
        pipeline_count = 0
    if not bool(options.get("pipeline_prefetch_on", False)):
        pipeline_count = 0
    elif pipeline_count <= 0:
        pipeline_count = 1
    options["pipeline_prefetch_count"] = pipeline_count
    options["pipeline_prefetch_on"] = pipeline_count > 0
    return options


def build_template_options(tunables: TunableMap, *, max_workers: int) -> dict[str, Any]:
    options = {field.key: field.resolver(tunables, max_workers) for field in CONFIG_FIELDS}
    return dict(_normalize_template_options(options))


def apply_form_overrides(
    options: OptionMap,
    form: FormMap,
    *,
    form_kind: str,
    max_workers: int,
) -> OptionMap:
    for spec in FORM_KIND_FIELD_SPECS.get(form_kind, ()):  # pragma: no branch
        should_update, value = spec.reader(form, options.get(spec.key), max_workers)
        if should_update:
            options[spec.key] = value
    return _normalize_template_options(options)


def build_template_options_from_form(
    tunables: TunableMap,
    form: FormMap,
    *,
    form_kind: str,
    max_workers: int,
) -> dict[str, Any]:
    options = build_template_options(tunables, max_workers=max_workers)
    apply_form_overrides(options, form, form_kind=form_kind, max_workers=max_workers)
    return dict(options)


def parse_cache_override_form(form: FormMap) -> dict[str, bool]:
    return {field: form.get(f"override_{field}") == "on" for field in CACHE_OVERRIDE_FIELDS}

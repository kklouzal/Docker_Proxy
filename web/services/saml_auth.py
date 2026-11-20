from __future__ import annotations

import hashlib
import json
import logging
import random
import re
import ssl
import threading
import time
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any
from urllib.parse import urlsplit
from urllib.request import (
    HTTPRedirectHandler,
    HTTPSHandler,
    ProxyHandler,
    Request,
    build_opener,
)
from xml.sax.saxutils import escape as xml_escape

try:
    from defusedxml import ElementTree
    from defusedxml.common import DefusedXmlException

    _DEFUSEDXML_AVAILABLE = True
except ImportError:  # pragma: no cover - production image installs defusedxml.
    from xml.etree import ElementTree  # ruff: ignore[unconventional-import-alias, suspicious-xml-etree-import]

    DefusedXmlException = ()  # type: ignore[assignment]
    _DEFUSEDXML_AVAILABLE = False

from services.db import (
    DATABASE_ERRORS,
    acquire_mysql_named_lock,
    connect,
    connect_unpooled,
    mysql_error_code,
    release_mysql_named_lock,
)
from services.errors import clean_text, redact_sensitive_text
from services.external_auth_groups import (
    candidate_group_match_tokens,
    required_group_match_tokens,
)
from services.logutil import log_exception_throttled
from services.public_endpoint import normalize_public_host
from services.revision_lifecycle import scoped_lock_name
from services.runtime_helpers import (
    authority_has_empty_explicit_port,
    normalize_config_bool,
)
from services.url_validation import (
    has_malformed_percent_encoding,
    has_url_whitespace_or_control_chars,
    repeatedly_percent_decode,
)

logger = logging.getLogger(__name__)

PROVIDER_SAML = "saml"
DEFAULT_METADATA_TIMEOUT_SECONDS = 10
DEFAULT_METADATA_MAX_BYTES = 2 * 1024 * 1024
_MD_NS = "urn:oasis:names:tc:SAML:2.0:metadata"
_DS_NS = "http://www.w3.org/2000/09/xmldsig#"
_NS = {"md": _MD_NS, "ds": _DS_NS}
_SAML_METADATA_REQUEST_HEADERS = {
    "Accept": "application/samlmetadata+xml, application/xml, text/xml",
}
_SAML_HTTP_REDIRECT_BINDING = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
_MAX_URL_PERCENT_DECODE_PASSES = 8
# Mirrors OneLogin_Saml2_Constants.ALLOWED_CLOCK_DRIFT (python3-saml 1.16), the
# skew python3-saml grants to Conditions NotBefore/NotOnOrAfter. The replay
# cache reuses it as the bound on clock skew between Admin UI workers and the
# housekeeping pruner; a test pins it to the library constant.
SAML_CLOCK_DRIFT_SECONDS = 300
SAML_ASSERTION_REPLAY_TABLE = "saml_assertion_replay"
# Single-use claims of accepted assertions, keyed by SHA-256 of the IdP entity
# ID plus assertion ID. Rows are pruned by control-plane housekeeping once
# expires_ts has passed (see saml_assertion_use for the expiry contract).
_SAML_ASSERTION_REPLAY_DDL = """
CREATE TABLE IF NOT EXISTS saml_assertion_replay (
    replay_key CHAR(64) NOT NULL PRIMARY KEY,
    expires_ts BIGINT NOT NULL,
    created_ts BIGINT NOT NULL,
    INDEX idx_saml_assertion_replay_expires (expires_ts)
)
"""
_INSERT_ASSERTION_REPLAY_SQL = (
    "INSERT INTO saml_assertion_replay(replay_key, expires_ts, created_ts) "
    "VALUES (%s, %s, %s)"
)
_MYSQL_DUPLICATE_KEY = 1062

# Metadata lifetime and automatic refresh (README "SAML metadata refresh").
# Without validUntil/cacheDuration the IdP metadata is cached for 24 hours.
DEFAULT_METADATA_CACHE_SECONDS = 24 * 60 * 60
# After cache expiry (never past validUntil) the last good metadata stays
# usable for at most this long, or the length of its cache window when that is
# shorter, so a transient IdP/metadata outage does not end every SAML session.
SAML_METADATA_STALE_GRACE_SECONDS = 6 * 60 * 60
# The background refresher fetches again once this fraction of the cache
# window has elapsed (jittered), leaving the rest of the window for retries.
_REFRESH_WINDOW_FRACTION = 0.5
_REFRESH_SUCCESS_JITTER = 0.1
_REFRESH_MIN_INTERVAL_SECONDS = 60
# Failed refreshes retry with capped exponential backoff and equal jitter.
_REFRESH_RETRY_BASE_SECONDS = 60
_REFRESH_RETRY_MAX_SECONDS = 60 * 60
_REFRESH_LOCK_NAMESPACE = "saml_metadata_refresh"
# Lazy-store copy of schema migration 38.
_SAML_REFRESH_SCHEDULE_COLUMNS = (
    (
        "refresh_failures",
        "ALTER TABLE saml_auth_profiles ADD COLUMN refresh_failures INT NOT NULL DEFAULT 0 AFTER updated_ts",
    ),
    (
        "next_refresh_ts",
        "ALTER TABLE saml_auth_profiles ADD COLUMN next_refresh_ts BIGINT NOT NULL DEFAULT 0 AFTER refresh_failures",
    ),
)


# Fetched metadata is cached only while the fetch settings still match.
_RECORD_CURRENT_METADATA_SQL = """
UPDATE saml_auth_profiles
   SET raw_metadata_xml = %s, parsed_metadata_json = %s,
       entity_id = %s, fetched_ts = %s, cache_expires_ts = %s,
       valid_until_ts = %s, last_refresh_ok = 1,
       last_refresh_ts = %s, last_refresh_detail = %s,
       refresh_failures = 0, next_refresh_ts = %s,
       updated_ts = %s
 WHERE provider = %s AND metadata_url = %s AND require_https = %s
   AND verify_tls = %s AND ca_bundle = %s AND timeout_seconds = %s
   AND max_metadata_bytes = %s
"""
_CURRENT_FETCH_SETTINGS_SQL = """
SELECT 1 FROM saml_auth_profiles
 WHERE provider = %s AND metadata_url = %s AND require_https = %s
   AND verify_tls = %s AND ca_bundle = %s AND timeout_seconds = %s
   AND max_metadata_bytes = %s
"""


def _has_unsafe_url_text(value: str) -> bool:
    return has_url_whitespace_or_control_chars(value)


def _repeatedly_decode_url_component(value: str) -> tuple[list[str], bool]:
    result = repeatedly_percent_decode(
        str(value or ""),
        max_passes=_MAX_URL_PERCENT_DECODE_PASSES,
        reject_malformed=False,
    )
    return list(result.values), result.excessive_nesting


def _decoded_url_component_is_unsafe(value: str) -> bool:
    decoded_values, is_excessively_nested = _repeatedly_decode_url_component(value)
    return is_excessively_nested or any(
        _has_unsafe_url_text(decoded) or "\\" in decoded for decoded in decoded_values
    )


def _decoded_authority_component_is_unsafe(value: str) -> bool:
    if has_malformed_percent_encoding(value):
        return True
    decoded_values, is_excessively_nested = _repeatedly_decode_url_component(value)
    return is_excessively_nested or any(
        _has_unsafe_url_text(decoded)
        or "\\" in decoded
        or any(delimiter in decoded for delimiter in ("/", "?", "#", "@"))
        for decoded in decoded_values
    )


def _normalize_saml_url(value: Any, *, label: str) -> str:
    url = str(value or "").strip()
    if not url:
        msg = f"SAML {label} URL is required."
        raise ValueError(msg)
    if _has_unsafe_url_text(url) or "\\" in url:
        msg = f"SAML {label} URL must not include whitespace, control characters, or backslashes."
        raise ValueError(msg)
    parsed = urlsplit(url)
    if parsed.scheme.lower() not in {"https", "http"} or not parsed.netloc:
        msg = f"SAML {label} URL must be a valid http:// or https:// URL."
        raise ValueError(msg)
    if parsed.username or parsed.password or parsed.fragment:
        msg = f"SAML {label} URL must not include credentials or fragments."
        raise ValueError(msg)
    try:
        port = parsed.port
    except ValueError as exc:
        msg = f"SAML {label} URL includes an invalid port."
        raise ValueError(msg) from exc
    if authority_has_empty_explicit_port(parsed.netloc) or port == 0:
        msg = f"SAML {label} URL includes an invalid port."
        raise ValueError(msg)
    if _decoded_authority_component_is_unsafe(parsed.netloc) or any(
        _decoded_url_component_is_unsafe(component)
        for component in (parsed.path, parsed.query)
    ):
        msg = f"SAML {label} URL must not include encoded whitespace, control characters, or backslashes, encoded authority delimiters, or malformed percent-encoding."
        raise ValueError(msg)
    return parsed.geturl()


def _validate_saml_fetch_url(value: Any, *, label: str, require_https: bool) -> str:
    url = _normalize_saml_url(value, label=label)
    if require_https and urlsplit(url).scheme.lower() != "https":
        msg = f"SAML {label} URL must use https://."
        raise ValueError(msg)
    return url


def _remaining_saml_metadata_timeout(deadline: float, timeout_seconds: float) -> float:
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        msg = f"SAML metadata fetch timed out after {timeout_seconds:g} seconds."
        raise TimeoutError(msg)
    return remaining


def _tighten_saml_response_timeout(response, timeout: float) -> None:
    sock = getattr(
        getattr(getattr(response, "fp", None), "raw", None),
        "_sock",
        None,
    )
    set_timeout = getattr(sock, "settimeout", None)
    if callable(set_timeout):
        try:
            set_timeout(timeout)
        except OSError, ValueError:
            pass


class _SamlMetadataRedirectHandler(HTTPRedirectHandler):
    def __init__(
        self,
        *,
        require_https: bool,
        deadline: float | None = None,
        timeout_seconds: float | None = None,
    ) -> None:
        super().__init__()
        self._require_https = require_https
        self._deadline = deadline
        self._timeout_seconds = timeout_seconds

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        _validate_saml_fetch_url(
            newurl,
            label="metadata redirect",
            require_https=self._require_https,
        )
        if self._deadline is not None and self._timeout_seconds is not None:
            # HTTPRedirectHandler reopens the returned request using req.timeout.
            req.timeout = _remaining_saml_metadata_timeout(
                self._deadline,
                self._timeout_seconds,
            )
            # The base handler drains the redirect response before reopening.
            _tighten_saml_response_timeout(fp, req.timeout)
        redirected = super().redirect_request(req, fp, code, msg, headers, newurl)
        if redirected is not None:
            for header, value in _SAML_METADATA_REQUEST_HEADERS.items():
                if not redirected.has_header(header):
                    redirected.add_header(header, value)
        return redirected


@dataclass(frozen=True)
class SamlProviderProfile:
    provider: str
    enabled: bool
    metadata_url: str
    require_https: bool
    verify_tls: bool
    ca_bundle: str
    timeout_seconds: int
    max_metadata_bytes: int
    raw_metadata_xml: str
    parsed_metadata_json: str
    entity_id: str
    fetched_ts: int
    cache_expires_ts: int
    valid_until_ts: int
    last_refresh_ok: bool
    last_refresh_ts: int
    last_refresh_detail: str
    public_base_url: str
    username_attribute: str
    groups_attribute: str
    required_group: str
    updated_ts: int
    # Automatic refresh schedule: consecutive failed refreshes and the
    # earliest time the background refresher fetches again (0 = due now).
    refresh_failures: int = 0
    next_refresh_ts: int = 0

    @property
    def has_metadata(self) -> bool:
        return bool(self.raw_metadata_xml and self.parsed_metadata_json)

    @property
    def parsed_metadata(self) -> dict[str, Any]:
        if not self.parsed_metadata_json:
            return {}
        try:
            value = json.loads(self.parsed_metadata_json)
        except json.JSONDecodeError:
            return {}
        return value if isinstance(value, dict) else {}


@dataclass(frozen=True)
class SamlMetadataRefreshResult:
    ok: bool
    provider: str
    detail: str
    parsed_metadata: dict[str, Any] | None = None


@dataclass(frozen=True)
class SamlAssertionUse:
    """One accepted assertion's replay-cache claim."""

    replay_key: str
    expires_ts: int


@dataclass(frozen=True)
class SamlSessionPolicy:
    """What per-request SAML session checks need, without the metadata XML."""

    ready: bool
    fingerprint: str


@dataclass(frozen=True)
class SamlAuthResult:
    ok: bool
    username: str = ""
    detail: str = ""
    attributes: dict[str, Any] | None = None
    session_index: str = ""
    name_id: str = ""


class SamlAuthStore:
    def __init__(self) -> None:
        self._schema_ready = False
        self._schema_lock = threading.Lock()

    def _connect(self):
        return connect()

    def _connect_lock_session(self):
        # The refresh lock is held across the metadata fetch; a dedicated
        # session keeps it from occupying a pooled request connection.
        return connect_unpooled()

    def ensure_schema(self) -> None:
        if self._schema_ready:
            return
        with self._schema_lock:
            if self._schema_ready:
                return
            with self._connect() as conn:
                from services.schema_lifecycle import (
                    runtime_schema_ready_for_lazy_store,
                )

                if runtime_schema_ready_for_lazy_store(conn):
                    self._schema_ready = True
                    return
                conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS saml_auth_profiles (
                        provider VARCHAR(32) PRIMARY KEY,
                        enabled TINYINT(1) NOT NULL DEFAULT 0,
                        metadata_url TEXT NOT NULL,
                        require_https TINYINT(1) NOT NULL DEFAULT 1,
                        verify_tls TINYINT(1) NOT NULL DEFAULT 1,
                        ca_bundle TEXT NOT NULL,
                        timeout_seconds INT NOT NULL DEFAULT 10,
                        max_metadata_bytes INT NOT NULL DEFAULT 2097152,
                        raw_metadata_xml LONGTEXT NOT NULL,
                        parsed_metadata_json LONGTEXT NOT NULL,
                        entity_id TEXT NOT NULL,
                        fetched_ts BIGINT NOT NULL DEFAULT 0,
                        cache_expires_ts BIGINT NOT NULL DEFAULT 0,
                        valid_until_ts BIGINT NOT NULL DEFAULT 0,
                        last_refresh_ok TINYINT(1) NOT NULL DEFAULT 0,
                        last_refresh_ts BIGINT NOT NULL DEFAULT 0,
                        last_refresh_detail TEXT NOT NULL,
                        public_base_url TEXT NOT NULL,
                        username_attribute VARCHAR(255) NOT NULL DEFAULT 'NameID',
                        groups_attribute VARCHAR(255) NOT NULL DEFAULT 'groups',
                        required_group TEXT NOT NULL,
                        updated_ts BIGINT NOT NULL,
                        refresh_failures INT NOT NULL DEFAULT 0,
                        next_refresh_ts BIGINT NOT NULL DEFAULT 0
                    )
                    """,
                )
                self._ensure_column(
                    conn,
                    "public_base_url",
                    "ALTER TABLE saml_auth_profiles ADD COLUMN public_base_url TEXT NOT NULL AFTER last_refresh_detail",
                )
                self._ensure_column(
                    conn,
                    "username_attribute",
                    "ALTER TABLE saml_auth_profiles ADD COLUMN username_attribute VARCHAR(255) NOT NULL DEFAULT 'NameID' AFTER public_base_url",
                )
                self._ensure_column(
                    conn,
                    "groups_attribute",
                    "ALTER TABLE saml_auth_profiles ADD COLUMN groups_attribute VARCHAR(255) NOT NULL DEFAULT 'groups' AFTER username_attribute",
                )
                self._ensure_column(
                    conn,
                    "required_group",
                    "ALTER TABLE saml_auth_profiles ADD COLUMN required_group TEXT NOT NULL AFTER groups_attribute",
                )
                for column_name, ddl in _SAML_REFRESH_SCHEDULE_COLUMNS:
                    self._ensure_column(conn, column_name, ddl)
                conn.execute(_SAML_ASSERTION_REPLAY_DDL)
            self._schema_ready = True

    def ensure_default_profile(self) -> None:
        self.ensure_schema()
        with self._connect() as conn:
            row = conn.execute(
                "SELECT provider FROM saml_auth_profiles WHERE provider = %s",
                (PROVIDER_SAML,),
            ).fetchone()
            if row:
                return
            defaults = self.default_profile()
            conn.execute(
                """
                INSERT INTO saml_auth_profiles(
                    provider, enabled, metadata_url, require_https, verify_tls,
                    ca_bundle, timeout_seconds, max_metadata_bytes,
                    raw_metadata_xml, parsed_metadata_json, entity_id,
                    fetched_ts, cache_expires_ts, valid_until_ts,
                    last_refresh_ok, last_refresh_ts, last_refresh_detail,
                    public_base_url, username_attribute, groups_attribute,
                    required_group, updated_ts
                ) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
                """,
                (
                    defaults.provider,
                    int(defaults.enabled),
                    defaults.metadata_url,
                    int(defaults.require_https),
                    int(defaults.verify_tls),
                    defaults.ca_bundle,
                    defaults.timeout_seconds,
                    defaults.max_metadata_bytes,
                    defaults.raw_metadata_xml,
                    defaults.parsed_metadata_json,
                    defaults.entity_id,
                    defaults.fetched_ts,
                    defaults.cache_expires_ts,
                    defaults.valid_until_ts,
                    int(defaults.last_refresh_ok),
                    defaults.last_refresh_ts,
                    defaults.last_refresh_detail,
                    defaults.public_base_url,
                    defaults.username_attribute,
                    defaults.groups_attribute,
                    defaults.required_group,
                    int(time.time()),
                ),
            )

    def default_profile(self) -> SamlProviderProfile:
        return SamlProviderProfile(
            provider=PROVIDER_SAML,
            enabled=False,
            metadata_url="https://adfs.example.local/FederationMetadata/2007-06/FederationMetadata.xml",
            require_https=True,
            verify_tls=True,
            ca_bundle="",
            timeout_seconds=DEFAULT_METADATA_TIMEOUT_SECONDS,
            max_metadata_bytes=DEFAULT_METADATA_MAX_BYTES,
            raw_metadata_xml="",
            parsed_metadata_json="",
            entity_id="",
            fetched_ts=0,
            cache_expires_ts=0,
            valid_until_ts=0,
            last_refresh_ok=False,
            last_refresh_ts=0,
            last_refresh_detail="",
            public_base_url="",
            username_attribute="NameID",
            groups_attribute="groups",
            required_group="",
            updated_ts=0,
        )

    def get_profile(self) -> SamlProviderProfile:
        self.ensure_default_profile()
        with self._connect() as conn:
            row = conn.execute(
                """
                SELECT provider, enabled, metadata_url, require_https, verify_tls,
                       ca_bundle, timeout_seconds, max_metadata_bytes,
                       raw_metadata_xml, parsed_metadata_json, entity_id,
                       fetched_ts, cache_expires_ts, valid_until_ts,
                       last_refresh_ok, last_refresh_ts, last_refresh_detail,
                       public_base_url, username_attribute, groups_attribute,
                       required_group, updated_ts, refresh_failures,
                       next_refresh_ts
                  FROM saml_auth_profiles
                 WHERE provider = %s
                """,
                (PROVIDER_SAML,),
            ).fetchone()
        return self._row_to_profile(row) if row else self.default_profile()

    def get_session_policy(self, *, now: int | None = None) -> SamlSessionPolicy:
        """Per-request readiness/fingerprint read that skips the metadata blobs.

        ``profile_metadata_ready`` only needs to know whether the cached
        metadata columns are non-empty, so they are tested server-side instead
        of transferring up to max_metadata_bytes on every admin request.
        """
        self.ensure_schema()
        with self._connect() as conn:
            row = conn.execute(
                """
                SELECT enabled, raw_metadata_xml <> '', parsed_metadata_json <> '',
                       fetched_ts, cache_expires_ts, valid_until_ts,
                       entity_id, metadata_url, public_base_url,
                       username_attribute, groups_attribute, required_group
                  FROM saml_auth_profiles
                 WHERE provider = %s
                """,
                (PROVIDER_SAML,),
            ).fetchone()
        if not row:
            return SamlSessionPolicy(ready=False, fingerprint="")
        ready = bool(row[0]) and _metadata_cache_ready(
            has_metadata=bool(row[1]) and bool(row[2]),
            fetched_ts=int(row[3] or 0),
            cache_expires_ts=int(row[4] or 0),
            valid_until_ts=int(row[5] or 0),
            now=now,
        )
        return SamlSessionPolicy(
            ready=ready,
            fingerprint=_saml_policy_fingerprint(
                entity_id=str(row[6] or ""),
                metadata_url=str(row[7] or ""),
                public_base_url=str(row[8] or ""),
                username_attribute=str(row[9] or "NameID"),
                groups_attribute=str(row[10] or "groups"),
                required_group=str(row[11] or ""),
            ),
        )

    def record_assertion_use(self, use: SamlAssertionUse, *, now: int) -> bool:
        """Atomically claim an assertion; False means it was already used.

        The primary key makes the INSERT the single check-and-set, so two
        workers racing on the same assertion cannot both succeed. Any other
        database error propagates and the caller must fail the login closed.
        """
        self.ensure_schema()
        try:
            with self._connect() as conn:
                conn.execute(
                    _INSERT_ASSERTION_REPLAY_SQL,
                    (use.replay_key, int(use.expires_ts), int(now)),
                )
        except DATABASE_ERRORS as exc:
            if mysql_error_code(exc) == _MYSQL_DUPLICATE_KEY:
                return False
            raise
        return True

    def save_profile(self, payload: dict[str, Any]) -> SamlProviderProfile:
        current = self.get_profile()
        metadata_url = self._normalize_metadata_url(payload.get("metadata_url"))
        require_https = normalize_config_bool(
            payload.get("require_https"), default=True
        )
        verify_tls = normalize_config_bool(payload.get("verify_tls"), default=True)
        ca_bundle = str(payload.get("ca_bundle") or "").strip()
        public_base_url = self._normalize_public_base_url(
            payload.get("public_base_url")
        )
        username_attribute = self._normalize_attribute_name(
            payload.get("username_attribute"),
            default="NameID",
        )
        groups_attribute = self._normalize_attribute_name(
            payload.get("groups_attribute"),
            default="groups",
        )
        required_group = str(payload.get("required_group") or "").strip()
        timeout_seconds = self._bounded_int(payload.get("timeout_seconds"), 1, 60, 10)
        max_metadata_bytes = self._bounded_int(
            payload.get("max_metadata_bytes"),
            64 * 1024,
            10 * 1024 * 1024,
            DEFAULT_METADATA_MAX_BYTES,
        )
        enabled = normalize_config_bool(payload.get("enabled"))

        if require_https and not metadata_url.lower().startswith("https://"):
            msg = "SAML metadata URL must use https:// unless HTTPS enforcement is disabled."
            raise ValueError(msg)

        connection_changed = (
            metadata_url != current.metadata_url
            or require_https != current.require_https
            or verify_tls != current.verify_tls
            or ca_bundle != current.ca_bundle
            or timeout_seconds != current.timeout_seconds
            or max_metadata_bytes != current.max_metadata_bytes
        )
        last_refresh_ok = current.last_refresh_ok and not connection_changed
        last_refresh_ts = current.last_refresh_ts if not connection_changed else 0
        last_refresh_detail = (
            current.last_refresh_detail
            if not connection_changed
            else "Configuration changed since the last successful metadata refresh."
        )
        raw_metadata_xml = current.raw_metadata_xml if not connection_changed else ""
        parsed_metadata_json = (
            current.parsed_metadata_json if not connection_changed else ""
        )
        entity_id = current.entity_id if not connection_changed else ""
        fetched_ts = current.fetched_ts if not connection_changed else 0
        cache_expires_ts = current.cache_expires_ts if not connection_changed else 0
        valid_until_ts = current.valid_until_ts if not connection_changed else 0
        refresh_failures = current.refresh_failures if not connection_changed else 0
        next_refresh_ts = current.next_refresh_ts if not connection_changed else 0

        profile = SamlProviderProfile(
            provider=PROVIDER_SAML,
            enabled=enabled,
            metadata_url=metadata_url,
            require_https=require_https,
            verify_tls=verify_tls,
            ca_bundle=ca_bundle,
            timeout_seconds=timeout_seconds,
            max_metadata_bytes=max_metadata_bytes,
            raw_metadata_xml=raw_metadata_xml,
            parsed_metadata_json=parsed_metadata_json,
            entity_id=entity_id,
            fetched_ts=fetched_ts,
            cache_expires_ts=cache_expires_ts,
            valid_until_ts=valid_until_ts,
            last_refresh_ok=last_refresh_ok,
            last_refresh_ts=last_refresh_ts,
            last_refresh_detail=last_refresh_detail,
            public_base_url=public_base_url,
            username_attribute=username_attribute,
            groups_attribute=groups_attribute,
            required_group=required_group,
            updated_ts=int(time.time()),
            refresh_failures=refresh_failures,
            next_refresh_ts=next_refresh_ts,
        )
        if profile.enabled and not profile.public_base_url:
            msg = "Set the SAML public admin base URL before enabling the provider."
            raise ValueError(msg)
        if profile.enabled and not profile_metadata_cache_ready(profile):
            msg = "Refresh SAML metadata successfully before enabling the provider."
            raise ValueError(msg)
        self._persist(profile)
        return self.get_profile()

    def disable_provider(self) -> None:
        self.ensure_default_profile()
        with self._connect() as conn:
            conn.execute(
                "UPDATE saml_auth_profiles SET enabled = 0, updated_ts = %s WHERE provider = %s",
                (int(time.time()), PROVIDER_SAML),
            )

    def refresh_metadata(self) -> SamlMetadataRefreshResult:
        profile = self.get_profile()
        try:
            raw_xml = self.fetch_metadata(profile)
            parsed = parse_saml_metadata(raw_xml)
            _validate_saml_metadata_service_locations(
                parsed,
                require_https=profile.require_https,
            )
            if not self.record_metadata_refresh(
                profile, raw_xml=raw_xml, parsed=parsed
            ):
                return SamlMetadataRefreshResult(
                    False,
                    profile.provider,
                    "SAML configuration changed while metadata was being refreshed; "
                    "refresh again.",
                )
            return SamlMetadataRefreshResult(
                True,
                profile.provider,
                "SAML IdP metadata refreshed successfully.",
                parsed,
            )
        except Exception as exc:
            detail = self._public_error(exc)
            failures = profile.refresh_failures + 1
            self.record_refresh_status(
                ok=False,
                detail=detail,
                refresh_failures=failures,
                next_refresh_ts=_next_retry_ts(failures, int(time.time())),
            )
            log_exception_throttled(
                logger,
                "saml_auth.refresh_metadata",
                interval_seconds=300.0,
                message="SAML metadata refresh failed",
            )
            return SamlMetadataRefreshResult(False, profile.provider, detail)

    def fetch_metadata(self, profile: SamlProviderProfile) -> str:
        timeout_seconds = float(profile.timeout_seconds)
        deadline = time.monotonic() + timeout_seconds
        metadata_url = _validate_saml_fetch_url(
            profile.metadata_url,
            label="metadata",
            require_https=profile.require_https,
        )
        context = ssl.create_default_context(cadata=profile.ca_bundle or None)
        if not profile.verify_tls:
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
        request = Request(  # ruff: ignore[suspicious-url-open-usage] - scheme is validated before fetch.
            metadata_url,
            headers=_SAML_METADATA_REQUEST_HEADERS,
        )
        opener = build_opener(
            ProxyHandler({}),
            HTTPSHandler(context=context),
            _SamlMetadataRedirectHandler(
                require_https=profile.require_https,
                deadline=deadline,
                timeout_seconds=timeout_seconds,
            ),
        )
        open_timeout = _remaining_saml_metadata_timeout(deadline, timeout_seconds)
        with opener.open(request, timeout=open_timeout) as resp:
            final_url = resp.geturl()
            _validate_saml_fetch_url(
                final_url,
                label="metadata final response",
                require_https=profile.require_https,
            )
            chunks: list[bytes] = []
            total = 0
            while True:
                remaining = _remaining_saml_metadata_timeout(
                    deadline,
                    timeout_seconds,
                )
                # Tighten the per-operation socket timeout so repeated body
                # reads cannot each consume the full configured timeout.
                _tighten_saml_response_timeout(resp, remaining)
                chunk = resp.read(min(65536, profile.max_metadata_bytes + 1 - total))
                _remaining_saml_metadata_timeout(deadline, timeout_seconds)
                if not chunk:
                    break
                chunks.append(chunk)
                total += len(chunk)
                if total > profile.max_metadata_bytes:
                    msg = "SAML metadata response exceeded the configured size limit."
                    raise ValueError(msg)
        return b"".join(chunks).decode("utf-8", errors="replace")

    def record_metadata_refresh(
        self,
        profile: SamlProviderProfile,
        *,
        raw_xml: str,
        parsed: dict[str, Any],
    ) -> bool:
        """Store fetched metadata only if the fetch settings are still current.

        Returns False when the profile's fetch configuration changed while the
        metadata was in flight, so stale IdP trust material is never cached.
        """
        now = int(time.time())
        cache_expires_ts = _cache_expires_ts(parsed, now)
        valid_until_ts = int(parsed.get("valid_until_ts") or 0)
        next_refresh_ts = _next_scheduled_refresh_ts(
            fetched_ts=now,
            cache_expires_ts=cache_expires_ts,
            valid_until_ts=valid_until_ts,
        )
        current_params = (
            profile.provider,
            profile.metadata_url,
            int(profile.require_https),
            int(profile.verify_tls),
            profile.ca_bundle,
            profile.timeout_seconds,
            profile.max_metadata_bytes,
        )
        with self._connect() as conn:
            cursor = conn.execute(
                _RECORD_CURRENT_METADATA_SQL,
                (
                    raw_xml,
                    json.dumps(parsed, sort_keys=True),
                    str(parsed.get("entity_id") or ""),
                    now,
                    cache_expires_ts,
                    valid_until_ts,
                    now,
                    "SAML IdP metadata refreshed successfully.",
                    next_refresh_ts,
                    now,
                    *current_params,
                ),
            )
            if cursor.rowcount:
                return True
            # MySQL reports changed rows; an identical same-second refresh of an
            # unchanged profile updates nothing but is still current.
            return (
                conn.execute(_CURRENT_FETCH_SETTINGS_SQL, current_params).fetchone()
                is not None
            )

    def record_refresh_status(
        self,
        *,
        ok: bool,
        detail: str,
        refresh_failures: int,
        next_refresh_ts: int,
    ) -> None:
        """Record a refresh attempt that stored no metadata.

        The cached metadata is kept: it stays usable until its own expiry plus
        the bounded stale grace (see ``metadata_usable_until``).
        """
        self.ensure_default_profile()
        with self._connect() as conn:
            conn.execute(
                """
                UPDATE saml_auth_profiles
                   SET last_refresh_ok = %s, last_refresh_ts = %s,
                       last_refresh_detail = %s, refresh_failures = %s,
                       next_refresh_ts = %s
                 WHERE provider = %s
                """,
                (
                    int(ok),
                    int(time.time()),
                    str(detail or "")[:2000],
                    int(refresh_failures),
                    int(next_refresh_ts),
                    PROVIDER_SAML,
                ),
            )

    def refresh_metadata_if_due(self, *, now: int | None = None) -> int:
        """Background refresh of an enabled provider's metadata when due.

        Single-flight across Admin UI processes and pods through a
        non-blocking MySQL named lock; the due check is repeated under the lock
        so a refresh another holder just finished is not repeated. Returns the
        earliest time this provider is due again (0 when automatic refresh does
        not apply), for the caller's sleep.
        """
        profile = self.get_profile()
        current = int(time.time()) if now is None else int(now)
        if not _refresh_applies(profile):
            return 0
        if profile.next_refresh_ts > current:
            return profile.next_refresh_ts
        lock_name = scoped_lock_name(_REFRESH_LOCK_NAMESPACE)
        with self._connect_lock_session() as conn:
            if not acquire_mysql_named_lock(conn, lock_name, 0):
                # Another process is refreshing; look again shortly.
                return current + _REFRESH_MIN_INTERVAL_SECONDS
            try:
                profile = self.get_profile()
                if not _refresh_applies(profile):
                    return 0
                if profile.next_refresh_ts > int(time.time()):
                    return profile.next_refresh_ts
                self.refresh_metadata()
                return self.get_profile().next_refresh_ts
            finally:
                release_mysql_named_lock(conn, lock_name)

    def _persist(self, profile: SamlProviderProfile) -> None:
        self.ensure_default_profile()
        with self._connect() as conn:
            conn.execute(
                """
                UPDATE saml_auth_profiles
                   SET enabled = %s, metadata_url = %s, require_https = %s,
                       verify_tls = %s, ca_bundle = %s, timeout_seconds = %s,
                       max_metadata_bytes = %s, raw_metadata_xml = %s,
                       parsed_metadata_json = %s, entity_id = %s, fetched_ts = %s,
                       cache_expires_ts = %s, valid_until_ts = %s,
                       last_refresh_ok = %s, last_refresh_ts = %s,
                       last_refresh_detail = %s, public_base_url = %s,
                       username_attribute = %s, groups_attribute = %s,
                       required_group = %s, updated_ts = %s,
                       refresh_failures = %s, next_refresh_ts = %s
                 WHERE provider = %s
                """,
                (
                    int(profile.enabled),
                    profile.metadata_url,
                    int(profile.require_https),
                    int(profile.verify_tls),
                    profile.ca_bundle,
                    profile.timeout_seconds,
                    profile.max_metadata_bytes,
                    profile.raw_metadata_xml,
                    profile.parsed_metadata_json,
                    profile.entity_id,
                    profile.fetched_ts,
                    profile.cache_expires_ts,
                    profile.valid_until_ts,
                    int(profile.last_refresh_ok),
                    profile.last_refresh_ts,
                    profile.last_refresh_detail,
                    profile.public_base_url,
                    profile.username_attribute,
                    profile.groups_attribute,
                    profile.required_group,
                    profile.updated_ts,
                    profile.refresh_failures,
                    profile.next_refresh_ts,
                    profile.provider,
                ),
            )

    def _row_to_profile(self, row: Any) -> SamlProviderProfile:
        return SamlProviderProfile(
            provider=str(row[0]),
            enabled=bool(row[1]),
            metadata_url=str(row[2] or ""),
            require_https=bool(row[3]),
            verify_tls=bool(row[4]),
            ca_bundle=str(row[5] or ""),
            timeout_seconds=int(row[6] or DEFAULT_METADATA_TIMEOUT_SECONDS),
            max_metadata_bytes=int(row[7] or DEFAULT_METADATA_MAX_BYTES),
            raw_metadata_xml=str(row[8] or ""),
            parsed_metadata_json=str(row[9] or ""),
            entity_id=str(row[10] or ""),
            fetched_ts=int(row[11] or 0),
            cache_expires_ts=int(row[12] or 0),
            valid_until_ts=int(row[13] or 0),
            last_refresh_ok=bool(row[14]),
            last_refresh_ts=int(row[15] or 0),
            last_refresh_detail=str(row[16] or ""),
            public_base_url=str(row[17] or ""),
            username_attribute=str(row[18] or "NameID"),
            groups_attribute=str(row[19] or "groups"),
            required_group=str(row[20] or ""),
            updated_ts=int(row[21] or 0),
            refresh_failures=int(row[22] or 0),
            next_refresh_ts=int(row[23] or 0),
        )

    def _ensure_column(self, conn: Any, column_name: str, ddl: str) -> None:
        row = conn.execute(
            """
            SELECT 1 FROM information_schema.columns
            WHERE table_schema = DATABASE() AND table_name = %s AND column_name = %s
            LIMIT 1
            """,
            ("saml_auth_profiles", column_name),
        ).fetchone()
        if row is None:
            conn.execute(ddl)

    def _normalize_metadata_url(self, value: Any) -> str:
        return _normalize_saml_url(value, label="metadata")

    def _normalize_public_base_url(self, value: Any) -> str:
        url = str(value or "").strip().rstrip("/")
        if not url:
            return ""
        if _has_unsafe_url_text(url) or "\\" in url:
            msg = "SAML public base URL must not include whitespace, control characters, or backslashes."
            raise ValueError(msg)
        parsed = urlsplit(url)
        if parsed.scheme.lower() not in {"https", "http"} or not parsed.netloc:
            msg = "SAML public base URL must be a valid http:// or https:// URL."
            raise ValueError(msg)
        if parsed.username or parsed.password or parsed.query or parsed.fragment:
            msg = (
                "SAML public base URL must not include credentials, query, or fragment."
            )
            raise ValueError(msg)
        try:
            port = parsed.port
        except ValueError as exc:
            msg = "SAML public base URL includes an invalid port."
            raise ValueError(msg) from exc
        if authority_has_empty_explicit_port(parsed.netloc) or port == 0:
            msg = "SAML public base URL includes an invalid port."
            raise ValueError(msg)
        if _decoded_authority_component_is_unsafe(parsed.netloc) or any(
            _decoded_url_component_is_unsafe(component) for component in (parsed.path,)
        ):
            msg = "SAML public base URL must not include encoded whitespace, control characters, or backslashes, encoded authority delimiters, or malformed percent-encoding."
            raise ValueError(msg)
        public_host = normalize_public_host(parsed.hostname)
        if not public_host:
            msg = (
                "SAML public base URL must use a public DNS name or global IP address."
            )
            raise ValueError(msg)
        authority = f"[{public_host}]" if ":" in public_host else public_host
        if port is not None:
            authority = f"{authority}:{port}"
        return (
            parsed._replace(
                scheme=parsed.scheme.lower(),
                netloc=authority,
            )
            .geturl()
            .rstrip("/")
        )

    def _normalize_attribute_name(self, value: Any, *, default: str) -> str:
        text = str(value or "").strip() or default
        if len(text) > 255 or any(ord(char) < 0x20 for char in text):
            msg = "SAML claim attribute names must be printable and at most 255 characters."
            raise ValueError(msg)
        return text

    def _bounded_int(self, value: Any, minimum: int, maximum: int, default: int) -> int:
        try:
            parsed = int(str(value).strip())
        except Exception:
            return default
        return max(minimum, min(maximum, parsed))

    def _public_error(self, exc: Exception) -> str:
        text = str(exc).strip()
        if not text:
            text = exc.__class__.__name__
        return clean_text(redact_sensitive_text(text), max_len=2000)


def parse_saml_metadata(raw_xml: str) -> dict[str, Any]:
    if re.search(r"<!\s*(?:DOCTYPE|ENTITY)\b", raw_xml, flags=re.IGNORECASE):
        msg = "SAML metadata XML contains disallowed DTD or entity declarations."
        raise ValueError(msg)

    try:
        if _DEFUSEDXML_AVAILABLE:
            root = ElementTree.fromstring(raw_xml, forbid_dtd=True)  # ruff: ignore[suspicious-xml-element-tree-usage]
        else:  # pragma: no cover - production image installs defusedxml.
            root = ElementTree.fromstring(raw_xml)  # ruff: ignore[suspicious-xml-element-tree-usage]
    except DefusedXmlException as exc:
        msg = "SAML metadata XML contains disallowed DTD or entity declarations."
        raise ValueError(msg) from exc
    except ElementTree.ParseError as exc:
        msg = "SAML metadata XML could not be parsed."
        raise ValueError(msg) from exc

    entity = _first_entity_descriptor(root)
    entity_id = (entity.attrib.get("entityID") or "").strip()
    if not entity_id:
        msg = "SAML metadata is missing EntityDescriptor entityID."
        raise ValueError(msg)
    idp = entity.find("md:IDPSSODescriptor", _NS)
    if idp is None:
        msg = "SAML metadata does not include an IDPSSODescriptor."
        raise ValueError(msg)

    sso_services = _services(idp, "SingleSignOnService")
    if not sso_services:
        msg = "SAML IdP metadata does not include a SingleSignOnService endpoint."
        raise ValueError(msg)
    slo_services = _services(idp, "SingleLogoutService")
    signing_certs, encryption_certs = _certificates(idp)
    if not signing_certs:
        msg = "SAML IdP metadata does not include a signing certificate."
        raise ValueError(msg)

    name_id_formats = [
        (item.text or "").strip()
        for item in idp.findall("md:NameIDFormat", _NS)
        if (item.text or "").strip()
    ]
    valid_until_ts = _timestamp(entity.attrib.get("validUntil"))
    cache_duration_seconds = _duration_seconds(entity.attrib.get("cacheDuration"))
    settings = {
        "idp": {
            "entityId": entity_id,
            "singleSignOnService": _preferred_location(sso_services),
            "singleLogoutService": _preferred_location(slo_services),
            "x509certMulti": {
                "signing": signing_certs,
                "encryption": encryption_certs,
            },
        },
    }
    if signing_certs:
        settings["idp"]["x509cert"] = signing_certs[0]

    return {
        "entity_id": entity_id,
        "valid_until": entity.attrib.get("validUntil") or "",
        "valid_until_ts": valid_until_ts,
        "cache_duration": entity.attrib.get("cacheDuration") or "",
        "cache_duration_seconds": cache_duration_seconds,
        "sso_services": sso_services,
        "slo_services": slo_services,
        "signing_certs": signing_certs,
        "encryption_certs": encryption_certs,
        "name_id_formats": name_id_formats,
        "settings": settings,
    }


def _validate_saml_metadata_service_locations(
    parsed: dict[str, Any],
    *,
    require_https: bool,
) -> None:
    for key, label in (
        ("sso_services", "IdP SingleSignOnService Location"),
        ("slo_services", "IdP SingleLogoutService Location"),
    ):
        services = parsed.get(key) or []
        if not isinstance(services, list):
            continue
        for service in services:
            if not isinstance(service, dict):
                continue
            normalized = _normalize_saml_url(
                service.get("location"),
                label=label,
            )
            if require_https and urlsplit(normalized).scheme.lower() != "https":
                msg = f"SAML {label} URL must use https://."
                raise ValueError(msg)


def _first_entity_descriptor(root: ElementTree.Element) -> ElementTree.Element:
    entity_tags = {f"{{{_MD_NS}}}EntityDescriptor", "EntityDescriptor"}
    if root.tag in entity_tags:
        return root
    for entity in root.findall(".//md:EntityDescriptor", _NS):
        if entity.find("md:IDPSSODescriptor", _NS) is not None:
            return entity
    for entity in root.iter():
        if entity.tag in entity_tags:
            return entity
    msg = "SAML metadata does not include an EntityDescriptor."
    raise ValueError(msg)


def _services(parent: ElementTree.Element, local_name: str) -> list[dict[str, str]]:
    tag = f"md:{local_name}"
    services: list[dict[str, str]] = []
    for node in parent.findall(tag, _NS):
        binding = (node.attrib.get("Binding") or "").strip()
        location = (node.attrib.get("Location") or "").strip()
        if not binding or not location:
            continue
        services.append({"binding": binding, "location": location})
    return services


def _first_location(services: list[dict[str, str]]) -> dict[str, str]:
    for service in services:
        binding = str(service.get("binding") or "").strip()
        location = str(service.get("location") or "").strip()
        if binding and location:
            return {
                "url": location,
                "binding": binding,
            }
    return {}


def _preferred_location(services: list[dict[str, str]]) -> dict[str, str]:
    for service in services:
        binding = str(service.get("binding") or "").strip()
        location = str(service.get("location") or "").strip()
        if binding == _SAML_HTTP_REDIRECT_BINDING and location:
            return {
                "url": location,
                "binding": binding,
            }
    return _first_location(services)


def _preferred_idp_settings(parsed: dict[str, Any]) -> dict[str, Any]:
    settings = dict(parsed.get("settings") or {})
    idp_settings = dict(settings.get("idp") or {})
    sso_service = _preferred_location(parsed.get("sso_services") or [])
    slo_service = _preferred_location(parsed.get("slo_services") or [])
    if sso_service:
        idp_settings["singleSignOnService"] = sso_service
    if slo_service:
        idp_settings["singleLogoutService"] = slo_service
    if idp_settings:
        settings["idp"] = idp_settings
    return settings


def _certificates(parent: ElementTree.Element) -> tuple[list[str], list[str]]:
    signing: list[str] = []
    encryption: list[str] = []
    for descriptor in parent.findall("md:KeyDescriptor", _NS):
        use = (descriptor.attrib.get("use") or "signing").strip().lower()
        for cert_node in descriptor.findall(".//ds:X509Certificate", _NS):
            cert = _normalize_cert(cert_node.text or "")
            if not cert:
                continue
            if use == "encryption":
                encryption.append(cert)
            else:
                signing.append(cert)
    return list(dict.fromkeys(signing)), list(dict.fromkeys(encryption))


def _normalize_cert(value: str) -> str:
    return "".join(str(value or "").strip().split())


def _timestamp(value: str | None) -> int:
    if not value:
        return 0
    text = value.strip()
    if text.endswith("Z"):
        text = f"{text[:-1]}+00:00"
    try:
        return int(datetime.fromisoformat(text).timestamp())
    except ValueError:
        return 0


def _duration_seconds(value: str | None) -> int:
    if not value:
        return 0
    match = re.fullmatch(
        r"P(?:(?P<days>\d+)D)?(?:T(?:(?P<hours>\d+)H)?(?:(?P<minutes>\d+)M)?(?:(?P<seconds>\d+)S)?)?",
        value.strip(),
    )
    if not match:
        return 0
    days = int(match.group("days") or 0)
    hours = int(match.group("hours") or 0)
    minutes = int(match.group("minutes") or 0)
    seconds = int(match.group("seconds") or 0)
    return int(
        timedelta(
            days=days, hours=hours, minutes=minutes, seconds=seconds
        ).total_seconds()
    )


def _cache_expires_ts(parsed: dict[str, Any], now: int) -> int:
    candidates: list[int] = []
    valid_until_ts = int(parsed.get("valid_until_ts") or 0)
    if valid_until_ts:
        candidates.append(valid_until_ts)
    cache_duration_seconds = int(parsed.get("cache_duration_seconds") or 0)
    if cache_duration_seconds:
        candidates.append(now + cache_duration_seconds)
    if not candidates:
        candidates.append(now + DEFAULT_METADATA_CACHE_SECONDS)
    return min(candidates)


def metadata_usable_until(
    *, fetched_ts: int, cache_expires_ts: int, valid_until_ts: int
) -> int:
    """Last second the cached metadata may be used (0 = no expiry recorded).

    Past ``cache_expires_ts`` the last good metadata keeps working for the
    bounded stale grace (the shorter of SAML_METADATA_STALE_GRACE_SECONDS and
    the cache window), so a failed background refresh does not end sessions
    or logins at once. ``validUntil`` is a hard limit the grace never passes.
    """
    limits: list[int] = []
    if cache_expires_ts:
        window = max(0, cache_expires_ts - fetched_ts) if fetched_ts else 0
        limits.append(cache_expires_ts + min(SAML_METADATA_STALE_GRACE_SECONDS, window))
    if valid_until_ts:
        limits.append(valid_until_ts)
    return min(limits) if limits else 0


def _metadata_cache_ready(
    *,
    has_metadata: bool,
    fetched_ts: int,
    cache_expires_ts: int,
    valid_until_ts: int,
    now: int | None,
) -> bool:
    now = int(time.time()) if now is None else int(now)
    usable_until = metadata_usable_until(
        fetched_ts=fetched_ts,
        cache_expires_ts=cache_expires_ts,
        valid_until_ts=valid_until_ts,
    )
    return bool(has_metadata and (not usable_until or usable_until > now))


def _refresh_applies(profile: SamlProviderProfile) -> bool:
    return bool(profile.enabled and profile.metadata_url)


def _next_scheduled_refresh_ts(
    *, fetched_ts: int, cache_expires_ts: int, valid_until_ts: int
) -> int:
    """When to refresh after a success: part-way through the cache window."""
    expiry_candidates = [ts for ts in (cache_expires_ts, valid_until_ts) if ts]
    expiry = min(expiry_candidates) if expiry_candidates else 0
    window = max(0, expiry - fetched_ts) if expiry else DEFAULT_METADATA_CACHE_SECONDS
    delay = window * _REFRESH_WINDOW_FRACTION
    delay *= random.uniform(1.0 - _REFRESH_SUCCESS_JITTER, 1.0)  # ruff: ignore[suspicious-non-cryptographic-random-usage] - schedule jitter only.
    return fetched_ts + max(_REFRESH_MIN_INTERVAL_SECONDS, int(delay))


def _next_retry_ts(failures: int, now: int) -> int:
    """Capped exponential backoff with equal jitter after a failed refresh."""
    exponent = min(max(0, int(failures) - 1), 16)
    delay = min(_REFRESH_RETRY_MAX_SECONDS, _REFRESH_RETRY_BASE_SECONDS * 2**exponent)
    jittered = random.uniform(delay / 2, delay)  # ruff: ignore[suspicious-non-cryptographic-random-usage] - schedule jitter only.
    return now + max(1, int(jittered))


def profile_metadata_cache_ready(
    profile: SamlProviderProfile, *, now: int | None = None
) -> bool:
    return _metadata_cache_ready(
        has_metadata=profile.has_metadata,
        fetched_ts=profile.fetched_ts,
        cache_expires_ts=profile.cache_expires_ts,
        valid_until_ts=profile.valid_until_ts,
        now=now,
    )


def _saml_policy_fingerprint(
    *,
    entity_id: str,
    metadata_url: str,
    public_base_url: str,
    username_attribute: str,
    groups_attribute: str,
    required_group: str,
) -> str:
    fields = (
        PROVIDER_SAML,
        entity_id,
        metadata_url,
        public_base_url,
        username_attribute,
        groups_attribute,
        required_group,
    )
    encoded = json.dumps(fields, separators=(",", ":")).encode()
    return hashlib.sha256(encoded).hexdigest()


def saml_policy_fingerprint(profile: SamlProviderProfile) -> str:
    """Hash the SAML settings that decide who an admin session belongs to.

    Covers the IdP identity (metadata URL and entity ID), the SP identity
    (public base URL, which derives the SP entity ID/ACS URL) and the
    username/group mapping. Excludes the enabled flag and metadata freshness
    (checked separately through readiness), signing certificates (routine
    rollover via metadata refresh), and the fetched_ts/last_refresh_*/
    updated_ts bookkeeping that every metadata refresh rewrites.
    """
    return _saml_policy_fingerprint(
        entity_id=profile.entity_id,
        metadata_url=profile.metadata_url,
        public_base_url=profile.public_base_url,
        username_attribute=profile.username_attribute,
        groups_attribute=profile.groups_attribute,
        required_group=profile.required_group,
    )


def saml_session_policy(
    profile: SamlProviderProfile, *, now: int | None = None
) -> SamlSessionPolicy:
    """Session policy computed from an already-loaded full profile."""
    return SamlSessionPolicy(
        ready=profile_metadata_ready(profile, now=now),
        fingerprint=saml_policy_fingerprint(profile),
    )


def profile_metadata_ready(
    profile: SamlProviderProfile, *, now: int | None = None
) -> bool:
    return bool(profile.enabled and profile_metadata_cache_ready(profile, now=now))


def public_base_url(profile: SamlProviderProfile) -> str:
    configured = (profile.public_base_url or "").strip().rstrip("/")
    if configured:
        return configured
    msg = (
        "SAML public admin base URL must be configured before generating "
        "service-provider URLs."
    )
    raise ValueError(msg)


def build_sp_info(profile: SamlProviderProfile) -> dict[str, str]:
    base = public_base_url(profile)
    return {
        "entity_id": f"{base}/auth/saml/metadata",
        "acs_url": f"{base}/auth/saml/acs",
        "sls_url": f"{base}/auth/saml/sls",
    }


def build_sp_metadata(profile: SamlProviderProfile) -> str:
    sp = build_sp_info(profile)
    return f"""<?xml version="1.0"?>
<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" entityID="{xml_escape(sp["entity_id"])}">
  <md:SPSSODescriptor AuthnRequestsSigned="false" WantAssertionsSigned="true" protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified</md:NameIDFormat>
    <md:AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="{xml_escape(sp["acs_url"])}" index="1" isDefault="true"/>
    <md:SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="{xml_escape(sp["sls_url"])}"/>
  </md:SPSSODescriptor>
</md:EntityDescriptor>
"""


def build_saml_settings(
    profile: SamlProviderProfile,
    *,
    require_idp_metadata: bool = True,
) -> dict[str, Any]:
    if require_idp_metadata and not profile.has_metadata:
        msg = "SAML metadata cache is empty. Refresh metadata before using SAML."
        raise ValueError(msg)
    parsed = profile.parsed_metadata if profile.has_metadata else {}
    _validate_saml_metadata_service_locations(
        parsed,
        require_https=profile.require_https,
    )
    sp = build_sp_info(profile)
    return {
        "strict": True,
        "debug": False,
        "sp": {
            "entityId": sp["entity_id"],
            "assertionConsumerService": {
                "url": sp["acs_url"],
                "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
            },
            "singleLogoutService": {
                "url": sp["sls_url"],
                "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect",
            },
            "NameIDFormat": "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified",
        },
        **_preferred_idp_settings(parsed),
        "security": {
            "authnRequestsSigned": False,
            "logoutRequestSigned": False,
            "logoutResponseSigned": False,
            "wantAssertionsSigned": True,
            "wantMessagesSigned": True,
            "wantNameId": True,
            "wantNameIdEncrypted": False,
            "wantAttributeStatement": False,
            "requestedAuthnContext": False,
            "signatureAlgorithm": "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
            "digestAlgorithm": "http://www.w3.org/2001/04/xmlenc#sha256",
        },
    }


def prepare_flask_request(request: Any) -> dict[str, Any]:
    url_data = urlsplit(request.url)
    return {
        "https": "on" if request.scheme == "https" else "off",
        "http_host": request.host,
        "script_name": request.path,
        "server_port": _server_port_for_saml_request(request, url_data),
        "get_data": request.args.copy(),
        "post_data": request.form.copy(),
        "query_string": request.query_string.decode("utf-8", errors="replace"),
    }


def _server_port_for_saml_request(request: Any, url_data: Any) -> str:
    if url_data.port is not None:
        return str(url_data.port)
    environ_port = str(request.environ.get("SERVER_PORT") or "").strip()
    if environ_port:
        return environ_port
    return "443" if request.scheme == "https" else "80"


def build_saml_auth(profile: SamlProviderProfile, request: Any) -> Any:
    try:
        from onelogin.saml2.auth import OneLogin_Saml2_Auth
    except ImportError as exc:  # pragma: no cover - dependency is packaged.
        msg = "python3-saml is not installed in the admin UI image."
        raise RuntimeError(msg) from exc
    return OneLogin_Saml2_Auth(
        prepare_flask_request(request),
        old_settings=build_saml_settings(profile),
    )


def resolve_saml_login(auth: Any, profile: SamlProviderProfile) -> SamlAuthResult:
    errors = list(auth.get_errors() or [])
    if errors:
        reason = auth.get_last_error_reason() or ", ".join(errors)
        return SamlAuthResult(False, detail=_sanitize_saml_detail(reason))
    if not bool(auth.is_authenticated()):
        return SamlAuthResult(False, detail="SAML response was not authenticated.")

    attributes = auth.get_attributes() or {}
    name_id = str(auth.get_nameid() or "").strip()
    username = _first_attribute_value(attributes, profile.username_attribute)
    if profile.username_attribute == "NameID" or not username:
        username = name_id
    username = username.strip()
    if not username:
        return SamlAuthResult(False, detail="SAML response did not include a username.")

    required_group = (profile.required_group or "").strip()
    if required_group:
        if not any(
            _saml_group_matches_required(required_group, item)
            for item in _attribute_values(attributes, profile.groups_attribute)
        ):
            return SamlAuthResult(
                False,
                username=username,
                detail="SAML user is missing the required admin group.",
                attributes=attributes,
                name_id=name_id,
            )

    return SamlAuthResult(
        True,
        username=username,
        detail="SAML authentication succeeded.",
        attributes=attributes,
        session_index=str(auth.get_session_index() or ""),
        name_id=name_id,
    )


def saml_assertion_use(
    auth: Any,
    profile: SamlProviderProfile,
    *,
    request_id: str,
    acceptance_window_seconds: int,
    now: int,
) -> SamlAssertionUse:
    """Build the replay-cache claim for a toolkit-validated SAML response.

    Expiry contract: the row must outlive every moment at which python3-saml
    plus the ACS could accept the same assertion again, measured on any
    worker's clock, because the pruner deletes rows by its own clock.

    * The response must answer this pending request (InResponseTo equal to
      the request ID). The ACS accepts a pending request only while it is
      younger than ``acceptance_window_seconds`` (pending TTL plus the future
      tolerance for the creating worker's clock), so a replay is impossible
      after ``now + acceptance_window_seconds``.
    * python3-saml rejects a SubjectConfirmationData NotOnOrAfter at or before
      its ``now`` with no drift, so a replay is also impossible after that
      NotOnOrAfter when present.

    A replay needs both, so the tighter bound is safe; adding
    SAML_CLOCK_DRIFT_SECONDS covers skew between the accepting worker and the
    pruner. The pending window also caps the expiry (16 minutes by default),
    so an IdP issuing long-lived assertions cannot grow the table.
    """
    assertion_id = str(auth.get_last_assertion_id() or "").strip()
    if not assertion_id:
        msg = "SAML assertion did not include an ID."
        raise ValueError(msg)
    if str(auth.get_last_response_in_response_to() or "") != str(request_id):
        # Without this binding the pending-request window would not bound
        # replays of an unsolicited response, only its (optional) timestamps.
        msg = "SAML response does not answer the pending login request."
        raise ValueError(msg)
    idp_entity_id = (profile.entity_id or "").strip()
    if not idp_entity_id:
        msg = "SAML IdP entity ID is unknown; refresh metadata."
        raise ValueError(msg)
    now = int(now)
    expires_ts = now + int(acceptance_window_seconds)
    not_on_or_after = auth.get_last_assertion_not_on_or_after()
    if not_on_or_after:
        expires_ts = min(expires_ts, max(int(not_on_or_after), now))
    replay_key = hashlib.sha256(
        json.dumps([idp_entity_id, assertion_id], separators=(",", ":")).encode()
    ).hexdigest()
    return SamlAssertionUse(
        replay_key=replay_key,
        expires_ts=expires_ts + SAML_CLOCK_DRIFT_SECONDS,
    )


def saml_response_authenticated(auth: Any) -> bool:
    """Whether python3-saml validated the response (signature, timing, audience)."""
    return not list(auth.get_errors() or []) and bool(auth.is_authenticated())


def _saml_group_matches_required(required_group: str, candidate_group: str) -> bool:
    required = _required_saml_group_match_tokens(required_group)
    candidate = _candidate_saml_group_match_tokens(candidate_group)
    return bool(required and candidate and required.intersection(candidate))


def _required_saml_group_match_tokens(value: Any) -> set[str]:
    return required_group_match_tokens(value, preserve_full_dn=False)


def _candidate_saml_group_match_tokens(value: Any) -> set[str]:
    return candidate_group_match_tokens(value, preserve_full_dn=False)


def _attribute_values(attributes: dict[str, Any], key: str) -> list[str]:
    raw = attributes.get(key)
    if raw is None:
        return []
    if isinstance(raw, (list, tuple, set)):
        return [str(item).strip() for item in raw if str(item).strip()]
    text = str(raw).strip()
    return [text] if text else []


def _first_attribute_value(attributes: dict[str, Any], key: str) -> str:
    values = _attribute_values(attributes, key)
    return values[0] if values else ""


def _sanitize_saml_detail(value: Any) -> str:
    return clean_text(redact_sensitive_text(value), max_len=1000)


_saml_auth_store: SamlAuthStore | None = None
_saml_auth_store_lock = threading.Lock()


def get_saml_auth_store() -> SamlAuthStore:
    global _saml_auth_store
    if _saml_auth_store is not None:
        return _saml_auth_store
    with _saml_auth_store_lock:
        if _saml_auth_store is None:
            _saml_auth_store = SamlAuthStore()
    return _saml_auth_store

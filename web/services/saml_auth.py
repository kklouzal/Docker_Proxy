from __future__ import annotations

import json
import logging
import re
import ssl
import threading
import time
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any
from urllib.parse import urlsplit
from urllib.request import Request, urlopen
from xml.sax.saxutils import escape as xml_escape

try:
    from defusedxml import ElementTree
    from defusedxml.common import DefusedXmlException

    _DEFUSEDXML_AVAILABLE = True
except ImportError:  # pragma: no cover - production image installs defusedxml.
    from xml.etree import ElementTree  # noqa: ICN001, S405

    DefusedXmlException = ()  # type: ignore[assignment]
    _DEFUSEDXML_AVAILABLE = False

from services.db import connect
from services.logutil import log_exception_throttled

logger = logging.getLogger(__name__)

PROVIDER_SAML = "saml"
DEFAULT_METADATA_TIMEOUT_SECONDS = 10
DEFAULT_METADATA_MAX_BYTES = 2 * 1024 * 1024
_MD_NS = "urn:oasis:names:tc:SAML:2.0:metadata"
_DS_NS = "http://www.w3.org/2000/09/xmldsig#"
_NS = {"md": _MD_NS, "ds": _DS_NS}


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
class SamlAuthResult:
    ok: bool
    username: str = ""
    detail: str = ""
    attributes: dict[str, Any] | None = None
    session_index: str = ""
    name_id: str = ""


class SamlAuthStore:
    def _connect(self):
        return connect()

    def ensure_schema(self) -> None:
        with self._connect() as conn:
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
                    updated_ts BIGINT NOT NULL
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
                       required_group, updated_ts
                  FROM saml_auth_profiles
                 WHERE provider = %s
                """,
                (PROVIDER_SAML,),
            ).fetchone()
        return self._row_to_profile(row) if row else self.default_profile()

    def save_profile(self, payload: dict[str, Any]) -> SamlProviderProfile:
        current = self.get_profile()
        metadata_url = self._normalize_metadata_url(payload.get("metadata_url"))
        require_https = self._truthy(payload.get("require_https"), default=True)
        verify_tls = self._truthy(payload.get("verify_tls"), default=True)
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
        enabled = self._truthy(payload.get("enabled"))

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
        )
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
            self.record_metadata_refresh(profile, raw_xml=raw_xml, parsed=parsed)
            return SamlMetadataRefreshResult(
                True,
                profile.provider,
                "SAML IdP metadata refreshed successfully.",
                parsed,
            )
        except Exception as exc:
            detail = self._public_error(exc)
            self.record_refresh_status(ok=False, detail=detail)
            log_exception_throttled(
                logger,
                "saml_auth.refresh_metadata",
                interval_seconds=300.0,
                message="SAML metadata refresh failed",
            )
            return SamlMetadataRefreshResult(False, profile.provider, detail)

    def fetch_metadata(self, profile: SamlProviderProfile) -> str:
        if profile.require_https and not profile.metadata_url.lower().startswith(
            "https://"
        ):
            msg = "SAML metadata URL must use https://."
            raise ValueError(msg)
        context = ssl.create_default_context(cadata=profile.ca_bundle or None)
        if not profile.verify_tls:
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
        request = Request(  # noqa: S310 - scheme is validated before fetch.
            profile.metadata_url,
            headers={"Accept": "application/samlmetadata+xml, application/xml, text/xml"},
        )
        with urlopen(  # noqa: S310 - scheme is validated before fetch.
            request,
            timeout=profile.timeout_seconds,
            context=context,
        ) as resp:
            chunks: list[bytes] = []
            total = 0
            while True:
                chunk = resp.read(min(65536, profile.max_metadata_bytes + 1 - total))
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
    ) -> None:
        now = int(time.time())
        cache_expires_ts = _cache_expires_ts(parsed, now)
        valid_until_ts = int(parsed.get("valid_until_ts") or 0)
        with self._connect() as conn:
            conn.execute(
                """
                UPDATE saml_auth_profiles
                   SET raw_metadata_xml = %s, parsed_metadata_json = %s,
                       entity_id = %s, fetched_ts = %s, cache_expires_ts = %s,
                       valid_until_ts = %s, last_refresh_ok = 1,
                       last_refresh_ts = %s, last_refresh_detail = %s,
                       updated_ts = %s
                 WHERE provider = %s
                """,
                (
                    raw_xml,
                    json.dumps(parsed, sort_keys=True),
                    str(parsed.get("entity_id") or ""),
                    now,
                    cache_expires_ts,
                    valid_until_ts,
                    now,
                    "SAML IdP metadata refreshed successfully.",
                    now,
                    profile.provider,
                ),
            )

    def record_refresh_status(self, *, ok: bool, detail: str) -> None:
        self.ensure_default_profile()
        with self._connect() as conn:
            conn.execute(
                """
                UPDATE saml_auth_profiles
                   SET last_refresh_ok = %s, last_refresh_ts = %s,
                       last_refresh_detail = %s
                 WHERE provider = %s
                """,
                (int(ok), int(time.time()), str(detail or "")[:2000], PROVIDER_SAML),
            )

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
                       required_group = %s, updated_ts = %s
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
        url = str(value or "").strip()
        if not url:
            msg = "SAML metadata URL is required."
            raise ValueError(msg)
        parsed = urlsplit(url)
        if parsed.scheme.lower() not in {"https", "http"} or not parsed.netloc:
            msg = "SAML metadata URL must be a valid http:// or https:// URL."
            raise ValueError(msg)
        if parsed.username or parsed.password or parsed.fragment:
            msg = "SAML metadata URL must not include credentials or fragments."
            raise ValueError(msg)
        try:
            _port = parsed.port
        except ValueError as exc:
            msg = "SAML metadata URL includes an invalid port."
            raise ValueError(msg) from exc
        return parsed.geturl()

    def _normalize_public_base_url(self, value: Any) -> str:
        url = str(value or "").strip().rstrip("/")
        if not url:
            return ""
        parsed = urlsplit(url)
        if parsed.scheme.lower() not in {"https", "http"} or not parsed.netloc:
            msg = "SAML public base URL must be a valid http:// or https:// URL."
            raise ValueError(msg)
        if parsed.username or parsed.password or parsed.query or parsed.fragment:
            msg = "SAML public base URL must not include credentials, query, or fragment."
            raise ValueError(msg)
        return parsed.geturl().rstrip("/")

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

    def _truthy(self, value: Any, *, default: bool = False) -> bool:
        if value is None:
            return default
        return str(value).strip().lower() in {"1", "true", "yes", "on", "enabled"}

    def _public_error(self, exc: Exception) -> str:
        text = str(exc).strip()
        if not text:
            text = exc.__class__.__name__
        return re.sub(r"\s+", " ", text)[:2000]


def parse_saml_metadata(raw_xml: str) -> dict[str, Any]:
    if re.search(r"<!\s*(?:DOCTYPE|ENTITY)\b", raw_xml, flags=re.IGNORECASE):
        msg = "SAML metadata XML contains disallowed DTD or entity declarations."
        raise ValueError(msg)

    try:
        if _DEFUSEDXML_AVAILABLE:
            root = ElementTree.fromstring(raw_xml, forbid_dtd=True)  # noqa: S314
        else:  # pragma: no cover - production image installs defusedxml.
            root = ElementTree.fromstring(raw_xml)  # noqa: S314
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
            "singleSignOnService": _first_location(sso_services),
            "singleLogoutService": _first_location(slo_services),
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


def _first_entity_descriptor(root: ElementTree.Element) -> ElementTree.Element:
    if root.tag in {f"{{{_MD_NS}}}EntityDescriptor", "EntityDescriptor"}:
        return root
    entity = root.find("md:EntityDescriptor", _NS)
    if entity is not None:
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
    if not services:
        return {}
    return {
        "url": services[0]["location"],
        "binding": services[0]["binding"],
    }


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
    return int(timedelta(days=days, hours=hours, minutes=minutes, seconds=seconds).total_seconds())


def _cache_expires_ts(parsed: dict[str, Any], now: int) -> int:
    candidates: list[int] = []
    valid_until_ts = int(parsed.get("valid_until_ts") or 0)
    if valid_until_ts:
        candidates.append(valid_until_ts)
    cache_duration_seconds = int(parsed.get("cache_duration_seconds") or 0)
    if cache_duration_seconds:
        candidates.append(now + cache_duration_seconds)
    if not candidates:
        candidates.append(now + 24 * 60 * 60)
    return min(candidates)


def profile_metadata_cache_ready(
    profile: SamlProviderProfile, *, now: int | None = None
) -> bool:
    now = int(time.time()) if now is None else int(now)
    return bool(
        profile.has_metadata
        and profile.last_refresh_ok
        and (not profile.cache_expires_ts or profile.cache_expires_ts > now)
        and (not profile.valid_until_ts or profile.valid_until_ts > now)
    )


def profile_metadata_ready(profile: SamlProviderProfile, *, now: int | None = None) -> bool:
    return bool(profile.enabled and profile_metadata_cache_ready(profile, now=now))


def public_base_url(profile: SamlProviderProfile, request: Any) -> str:
    configured = (profile.public_base_url or "").strip().rstrip("/")
    if configured:
        return configured
    return request.url_root.rstrip("/")


def build_sp_info(profile: SamlProviderProfile, request: Any) -> dict[str, str]:
    base = public_base_url(profile, request)
    return {
        "entity_id": f"{base}/auth/saml/metadata",
        "acs_url": f"{base}/auth/saml/acs",
        "sls_url": f"{base}/auth/saml/sls",
    }


def build_sp_metadata(profile: SamlProviderProfile, request: Any) -> str:
    sp = build_sp_info(profile, request)
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
    request: Any,
    *,
    require_idp_metadata: bool = True,
) -> dict[str, Any]:
    if require_idp_metadata and not profile.has_metadata:
        msg = "SAML metadata cache is empty. Refresh metadata before using SAML."
        raise ValueError(msg)
    parsed = profile.parsed_metadata if profile.has_metadata else {}
    sp = build_sp_info(profile, request)
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
        **(parsed.get("settings") or {}),
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
        old_settings=build_saml_settings(profile, request),
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
        groups = {
            item.casefold()
            for item in _attribute_values(attributes, profile.groups_attribute)
            if item
        }
        if required_group.casefold() not in groups:
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
    text = re.sub(r"\s+", " ", str(value or "")).strip()
    text = re.sub(r"(?i)SAMLResponse=[^&\s]+", "SAMLResponse=[redacted]", text)
    return text[:1000]


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

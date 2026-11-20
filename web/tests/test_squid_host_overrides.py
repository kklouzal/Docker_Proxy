from __future__ import annotations

import hashlib
import os
import sys
import threading
from types import SimpleNamespace

import pytest
from services import squid_host_overrides
from services.squid_host_overrides import (
    OVERRIDES_ENV,
    HostOverrideError,
    apply_host_overrides,
    decode_overrides,
    describe_overrides,
    encode_overrides,
    parse_host_overrides,
)

from .mysql_test_utils import REPO_ROOT
from .subprocess_test_utils import run_test_process

HELPER = REPO_ROOT / "web/services/squid_host_overrides.py"

# Mirrors the sizing-relevant shape of the production RB5009 revision.
FLEET_REVISION = """http_port 0.0.0.0:3128 ssl-bump \\
\tcert=/etc/squid/ssl/certs/ca.crt \\
\tkey=/etc/squid/ssl/certs/ca.key \\
\tgenerate-host-certificates=on \\
\tdynamic_cert_mem_cache_size=128MB
https_port 0.0.0.0:3130 intercept ssl-bump name=https_intercept cert=/etc/squid/ssl/certs/ca.crt
http_port 0.0.0.0:3129 intercept
# cache_mem 512 MB
workers 2
sslcrtd_program /usr/lib/squid/ssl_crtd -s /var/lib/ssl_db/store -M 16MB
sslcrtd_children 4 startup=3 idle=2 queue-size=96 on-persistent-overload=ERR
cache_dir rock /var/spool/squid 10000 slot-size=32768
cache_mem 256 MB
max_filedescriptors 65535
"""

RB5009 = {
    "SQUID_WORKERS": 1,
    "SQUID_CACHE_MEM_MB": 32,
    "SQUID_CACHE_DIR_MB": 1024,
    "SQUID_SSLCRTD_CHILDREN": 1,
    "SQUID_DYNAMIC_CERT_MEM_CACHE_MB": 16,
    "SQUID_MAX_FILEDESCRIPTORS": 16384,
}


def test_parse_accepts_bounded_values_and_warns_on_invalid_ones() -> None:
    overrides, warnings = parse_host_overrides(
        {
            "SQUID_WORKERS": "9",
            "SQUID_CACHE_MEM_MB": " 032 ",
            "SQUID_CACHE_DIR_MB": "",
            "SQUID_SSLCRTD_CHILDREN": "two",
            "SQUID_DYNAMIC_CERT_MEM_CACHE_MB": "0",
            "SQUID_MAX_FILEDESCRIPTORS": "512",
        },
    )

    assert overrides == {"SQUID_CACHE_MEM_MB": 32, "SQUID_DYNAMIC_CERT_MEM_CACHE_MB": 0}
    assert len(warnings) == 3
    assert any("SQUID_WORKERS=9 is outside 1..4" in item for item in warnings)
    assert any("SQUID_SSLCRTD_CHILDREN='two'" in item for item in warnings)
    assert any("SQUID_MAX_FILEDESCRIPTORS=512" in item for item in warnings)


def test_encoded_overrides_round_trip_and_reject_malformed_entries() -> None:
    encoded = encode_overrides({"SQUID_MAX_FILEDESCRIPTORS": 4096, "SQUID_WORKERS": 1})

    assert encoded == "SQUID_WORKERS=1 SQUID_MAX_FILEDESCRIPTORS=4096"
    assert decode_overrides(encoded) == {
        "SQUID_WORKERS": 1,
        "SQUID_MAX_FILEDESCRIPTORS": 4096,
    }
    assert decode_overrides("SQUID_WORKERS=7 BOGUS=1 SQUID_CACHE_MEM_MB") == {}


def test_overlay_pins_every_owned_directive_and_keeps_the_rest() -> None:
    rendered = apply_host_overrides(FLEET_REVISION, RB5009)

    assert rendered == (
        "http_port 0.0.0.0:3128 ssl-bump \\\n"
        "\tcert=/etc/squid/ssl/certs/ca.crt \\\n"
        "\tkey=/etc/squid/ssl/certs/ca.key \\\n"
        "\tgenerate-host-certificates=on \\\n"
        "\tdynamic_cert_mem_cache_size=16MB\n"
        "https_port 0.0.0.0:3130 intercept ssl-bump name=https_intercept "
        "cert=/etc/squid/ssl/certs/ca.crt dynamic_cert_mem_cache_size=16MB\n"
        "http_port 0.0.0.0:3129 intercept\n"
        "# cache_mem 512 MB\n"
        "workers 1\n"
        "sslcrtd_program /usr/lib/squid/ssl_crtd -s /var/lib/ssl_db/store -M 16MB\n"
        "sslcrtd_children 1 startup=1 idle=1 queue-size=96 on-persistent-overload=ERR\n"
        "cache_dir rock /var/spool/squid 1024 slot-size=32768\n"
        "cache_mem 32 MB\n"
        "max_filedescriptors 16384\n"
    )
    assert apply_host_overrides(rendered, RB5009) == rendered


def test_overlay_without_overrides_keeps_the_revision_byte_identical() -> None:
    assert apply_host_overrides(FLEET_REVISION, {}) is FLEET_REVISION
    assert (
        apply_host_overrides(FLEET_REVISION, {"SQUID_CACHE_MEM_MB": 256})
        == FLEET_REVISION
    )


def test_overlay_appends_missing_directives_but_never_invents_a_cache_dir() -> None:
    revision = "http_port 3128\nhttp_access deny all\n"

    rendered = apply_host_overrides(revision, RB5009)

    assert "cache_dir" not in rendered
    assert "dynamic_cert_mem_cache_size" not in rendered
    assert rendered.endswith(
        "http_access deny all\n"
        "\n"
        "# Host resource sizing from the proxy container environment.\n"
        "workers 1\n"
        "cache_mem 32 MB\n"
        "max_filedescriptors 16384\n"
        "sslcrtd_children 1 startup=1 idle=1 queue-size=32\n",
    )
    assert apply_host_overrides(rendered, RB5009) == rendered


def test_overlay_leaves_ports_that_do_not_generate_certificates() -> None:
    revision = (
        "http_port 3128 ssl-bump generate-host-certificates=off cert=/c.pem\n"
        "https_port 3130 tls-cert=/c.pem\n"
    )

    assert (
        apply_host_overrides(revision, {"SQUID_DYNAMIC_CERT_MEM_CACHE_MB": 8})
        == revision
    )


def test_overlay_follows_squid_continuation_and_comment_rules() -> None:
    # Squid skips comment and blank lines even inside a continued directive,
    # and a comment ending in a backslash does not continue onto the next line.
    revision = (
        "# see C:\\squid\\\n"
        "cache_mem 256 MB\n"
        "cache_dir rock /var/spool/squid \\\n"
        "# size below\n"
        "\n"
        "\t10000 slot-size=32768\n"
        "http_port 3128 ssl-bump \\\n"
        "# cert options\n"
        "\tcert=/c.pem dynamic_cert_mem_cache_size=128MB\\\n"
        "\t generate-host-certificates\n"
        "http_port 3129 ssl-bump generate-host-certificates=off \\\n"
        "\tgenerate-host-certificates=on\n"
    )
    overrides = {
        "SQUID_CACHE_MEM_MB": 32,
        "SQUID_CACHE_DIR_MB": 2048,
        "SQUID_DYNAMIC_CERT_MEM_CACHE_MB": 16,
    }

    rendered = apply_host_overrides(revision, overrides)

    assert rendered == (
        "# see C:\\squid\\\n"
        "cache_mem 32 MB\n"
        "# size below\n"
        "\n"
        "cache_dir rock /var/spool/squid 2048 slot-size=32768\n"
        "http_port 3128 ssl-bump \\\n"
        "# cert options\n"
        "\tcert=/c.pem dynamic_cert_mem_cache_size=16MB\\\n"
        "\t generate-host-certificates\n"
        "http_port 3129 ssl-bump generate-host-certificates=off \\\n"
        "\tgenerate-host-certificates=on dynamic_cert_mem_cache_size=16MB\n"
    )
    assert apply_host_overrides(rendered, overrides) == rendered


def test_normalize_is_idempotent_for_revisions_without_managed_logformats(
    monkeypatch,
) -> None:
    from services.squid_core import SquidController

    monkeypatch.delenv(OVERRIDES_ENV, raising=False)
    controller = SquidController()
    once = controller.normalize_config_text("http_port 3128\nhttp_access allow all\n")

    assert controller.normalize_config_text(once) == once
    assert "logformat liveui %ts\t%tr\t" in once
    assert "\\t" not in once


def test_describe_overrides_lists_pinned_directives_in_canonical_order() -> None:
    assert describe_overrides({"SQUID_CACHE_DIR_MB": 1024, "SQUID_WORKERS": 1}) == [
        {"env": "SQUID_WORKERS", "directive": "workers", "value": "1"},
        {"env": "SQUID_CACHE_DIR_MB", "directive": "cache_dir", "value": "1024 MB"},
    ]


def test_capture_cli_exports_validated_set_and_warns_on_stderr() -> None:
    env = {
        key: value for key, value in os.environ.items() if not key.startswith("SQUID_")
    }
    env.update({"SQUID_CACHE_MEM_MB": "32", "SQUID_WORKERS": "0"})

    result = run_test_process(
        [sys.executable, str(HELPER), "capture"],
        check=True,
        capture_output=True,
        text=True,
        env=env,
    )

    assert result.stdout.strip() == "SQUID_CACHE_MEM_MB=32"
    assert "WARNING: SQUID_WORKERS=0 is outside 1..4" in result.stderr


def test_apply_cli_rewrites_file_with_exported_overrides(tmp_path) -> None:
    config = tmp_path / "squid.conf"
    config.write_text(FLEET_REVISION, encoding="utf-8")
    env = {**os.environ, OVERRIDES_ENV: encode_overrides(RB5009)}

    run_test_process(
        [sys.executable, str(HELPER), "apply", str(config)],
        check=True,
        env=env,
    )

    assert config.read_text(encoding="utf-8") == apply_host_overrides(
        FLEET_REVISION,
        RB5009,
    )


def test_normalize_applies_overlay_only_with_exported_overrides(monkeypatch) -> None:
    from services.squid_core import SquidController

    revision = _stable_fleet_revision(monkeypatch)
    controller = SquidController()
    # In-process SQUID_* values (the entrypoint's derived defaults or the
    # worker count published after an apply) are not operator overrides.
    monkeypatch.setenv("SQUID_WORKERS", "1")
    monkeypatch.setenv("SQUID_CACHE_MEM_MB", "32")
    plain = controller.normalize_config_text(revision)

    monkeypatch.setenv(OVERRIDES_ENV, encode_overrides(RB5009))
    pinned = controller.normalize_config_text(revision)

    assert plain == revision
    assert "cache_mem 256 MB" in plain
    assert "workers 2" in plain
    assert "cache_mem 32 MB" in pinned
    assert "cache_dir rock /var/spool/squid 1024 slot-size=32768" in pinned
    assert controller.normalize_config_text(pinned) == pinned


def _stable_fleet_revision(monkeypatch) -> str:
    """The fleet revision as the Admin UI stores it after normalization."""
    from services.squid_core import SquidController

    monkeypatch.delenv(OVERRIDES_ENV, raising=False)
    return SquidController().normalize_config_text(FLEET_REVISION)


def _sync_runtime(controller, revision_text: str, current: dict[str, str]):
    """Runtime with real normalization and in-memory config/revision state."""
    from proxy.runtime import ProxyRuntime  # type: ignore

    runtime = ProxyRuntime.__new__(ProxyRuntime)
    applied: list[str] = []
    marked: list[str] = []

    def apply_config_text(text: str):
        applied.append(text)
        current["text"] = text
        return True, "applied"

    runtime.controller = SimpleNamespace(
        get_current_config=lambda: current["text"],
        normalize_config_text=controller.normalize_config_text,
        apply_config_text=apply_config_text,
    )
    revision_sha = hashlib.sha256(revision_text.encode()).hexdigest()
    runtime.revisions = SimpleNamespace(
        get_active_revision_metadata=lambda _proxy_id: SimpleNamespace(
            revision_id=272,
            config_sha256=revision_sha,
        ),
        get_active_revision=lambda _proxy_id: SimpleNamespace(
            revision_id=272,
            config_sha256=revision_sha,
            config_text=revision_text,
        ),
        latest_apply=lambda _proxy_id: None,
        record_apply_result=lambda *_args, **_kwargs: SimpleNamespace(
            application_id=1,
        ),
    )
    runtime.registry = SimpleNamespace(
        mark_apply_result=lambda _proxy_id, **kwargs: marked.append(
            kwargs["current_config_sha"],
        ),
    )
    runtime.services = SimpleNamespace(current_config_sha_reader=None)
    runtime._invalidate_health_cache = lambda: None
    runtime.ensure_registered = lambda: None
    runtime.bootstrap_revision_if_missing = lambda: None
    runtime.sync_certificate_bundle = lambda force=False: {"ok": True, "changed": False}
    runtime.sync_policy_state = lambda force=False: {
        "ok": True,
        "changed": False,
        "reload_required": False,
    }
    runtime.sync_adblock_state = lambda force=False: {"ok": True, "changed": False}
    runtime.sync_pac_state = lambda force=False: {"ok": True, "changed": False}
    runtime._reload_for_policy_update = lambda **_kwargs: (True, "")
    runtime._current_adblock_enabled = lambda: True
    runtime._capture_recovery_bundle_after_sync = lambda _result: None
    return runtime, applied, marked


@pytest.mark.parametrize("raw_revision_running", [True, False])
@pytest.mark.parametrize(
    "overrides",
    [RB5009, {**RB5009, "SQUID_HTTP_PORT": 3138, "SQUID_INTERCEPT_ENABLED": 1}],
    ids=["sizing", "sizing+listeners"],
)
def test_sync_applies_overlay_once_and_then_reconciles_without_reapply(
    monkeypatch,
    raw_revision_running: bool,
    overrides: dict[str, int],
) -> None:
    from services.squid_core import SquidController

    revision = _stable_fleet_revision(monkeypatch)
    monkeypatch.setenv(OVERRIDES_ENV, encode_overrides(overrides))
    controller = SquidController()
    effective = controller.normalize_config_text(revision)
    # Either the fleet revision is still running (first boot after adding the
    # env) or the entrypoint already started the overlaid config.
    current = {"text": revision if raw_revision_running else effective}
    runtime, applied, _marked = _sync_runtime(controller, revision, current)
    import proxy.runtime as runtime_module  # type: ignore

    monkeypatch.setattr(
        runtime_module,
        "get_operation_ledger",
        lambda: SimpleNamespace(
            requeue_stale_applying=lambda *_args, **_kwargs: 0,
            claim_pending=lambda *_args, **_kwargs: [],
        ),
    )

    first = runtime.sync_from_db(force=False)
    second = runtime.sync_from_db(force=False)

    effective_sha = hashlib.sha256(effective.encode()).hexdigest()
    assert "cache_mem 32 MB" in effective
    if "SQUID_HTTP_PORT" in overrides:
        assert "http_port 0.0.0.0:3138 ssl-bump" in effective
        assert "http_port 0.0.0.0:3139 intercept" in effective
    assert applied == ([effective] if raw_revision_running else [])
    assert first["ok"] is True
    assert first["current_config_sha"] == effective_sha
    assert second["ok"] is True
    assert second["config_changed"] is False
    assert second["detail"] == "Proxy is already using the active config revision."


def test_health_reports_effective_sha_and_host_overrides_without_drift(
    monkeypatch,
) -> None:
    from services.squid_core import SquidController

    monkeypatch.setenv(OVERRIDES_ENV, encode_overrides({"SQUID_CACHE_MEM_MB": 32}))
    controller = SquidController()
    effective = controller.normalize_config_text(FLEET_REVISION)
    revision_sha = hashlib.sha256(FLEET_REVISION.encode()).hexdigest()
    effective_sha = hashlib.sha256(effective.encode()).hexdigest()

    from proxy.runtime import ProxyRuntime  # type: ignore

    runtime = ProxyRuntime.__new__(ProxyRuntime)
    runtime._operation_ledger_health = lambda: {"ok": True, "detail": "ok"}
    runtime._squid_transaction_health = lambda: {
        "ok": True,
        "ready": True,
        "status": "complete",
        "detail": "ok",
    }
    runtime.health_cache_ttl_seconds = 0.0
    runtime._health_cache_lock = threading.Lock()
    runtime._health_refresh_lock = threading.Lock()
    runtime.controller = SimpleNamespace(
        get_status=lambda: (b"squid ok", b""),
        _http_listener_details=lambda: ({"port": 3128, "mode": "explicit"},),
        _wait_for_http_listener=lambda *, timeout: True,
        normalize_config_text=controller.normalize_config_text,
    )
    runtime.stats_provider = dict
    runtime.runtime_services_builder = lambda **_kwargs: {"icap": {"ok": True}}
    runtime._supervisor_programs_health = lambda: {"ok": True, "programs": {}}
    runtime.revisions = SimpleNamespace(
        get_active_revision_metadata=lambda _proxy_id: SimpleNamespace(
            revision_id=272,
            config_sha256=revision_sha,
        ),
        get_active_revision=lambda _proxy_id: SimpleNamespace(
            revision_id=272,
            config_sha256=revision_sha,
            config_text=FLEET_REVISION,
        ),
    )
    runtime.certificate_bundles = SimpleNamespace(
        get_active_bundle_metadata=lambda: None,
    )
    runtime.adblock_artifacts = SimpleNamespace(
        get_active_artifact_metadata=lambda: None,
    )
    runtime._current_config_sha = lambda: effective_sha
    runtime._current_certificate_bundle_sha = lambda: ""
    runtime._current_adblock_artifact_sha = lambda: ""
    runtime._current_policy_sha = lambda: "policy-sha"
    runtime._current_pac_state_sha = lambda: "pac-sha"
    runtime.policy_state_builder = lambda _proxy_id: SimpleNamespace(
        policy_sha256="policy-sha",
        files=(),
    )
    runtime.pac_state_builder = lambda _proxy_id: SimpleNamespace(
        state_sha256="pac-sha",
    )

    result = runtime.collect_health(force=True)

    assert result["state_errors"] == []
    assert result["active_revision_sha"] == revision_sha
    assert result["effective_config_sha"] == effective_sha
    assert result["current_config_sha"] == effective_sha
    assert result["host_config_overrides"] == [
        {"env": "SQUID_CACHE_MEM_MB", "directive": "cache_mem", "value": "32 MB"},
    ]


def test_module_has_no_project_imports_for_entrypoint_use() -> None:
    # The entrypoint runs the helper by path before PYTHONPATH-dependent code.
    source = HELPER.read_text(encoding="utf-8")
    assert "from services" not in source
    assert squid_host_overrides.__file__.endswith("squid_host_overrides.py")


# The production RB5009 revision's listener (rev 272) and the Admin UI's
# managed intercept blocks, as squidctl renders them.
UI_EXPLICIT = (
    "http_port 0.0.0.0:3128 ssl-bump \\\n"
    "\tcert=/etc/squid/ssl/certs/ca.crt \\\n"
    "\tkey=/etc/squid/ssl/certs/ca.key \\\n"
    "\tgenerate-host-certificates=on \\\n"
    "\tdynamic_cert_mem_cache_size=128MB\n"
)
UI_INTERCEPT = (
    "# BEGIN SQUID-UI INTERCEPT LISTENER\n"
    "# HTTP NAT intercept listener. Requires external REDIRECT/DNAT rules; do not expose directly.\n"
    "http_port 0.0.0.0:3129 intercept\n"
    "# END SQUID-UI INTERCEPT LISTENER\n"
)
UI_HTTPS_INTERCEPT = (
    "# BEGIN SQUID-UI HTTPS INTERCEPT LISTENER\n"
    "# HTTPS NAT intercept listener. Requires TCP/443 REDIRECT/DNAT and explicit operator consent.\n"
    "https_port 0.0.0.0:3130 intercept ssl-bump \\\n"
    "\tname=https_intercept \\\n"
    "\tcert=/etc/squid/ssl/certs/ca.crt \\\n"
    "\tkey=/etc/squid/ssl/certs/ca.key \\\n"
    "\tgenerate-host-certificates=on \\\n"
    "\tdynamic_cert_mem_cache_size=128MB\n"
    "# END SQUID-UI HTTPS INTERCEPT LISTENER\n"
)
UI_SPLICE = (
    "# Splice all traffic arriving on the dedicated HTTPS NAT intercept listener.\n"
    "acl https_intercept_listener myportname https_intercept\n"
    "ssl_bump splice https_intercept_listener\n"
)
SSL_RULES = "ssl_bump peek step1\ninclude /etc/squid/conf.d/10-sslfilter.conf\n"
PROD_LISTENER_ENV = {"SQUID_INTERCEPT_ENABLED": "0", "SQUID_INTERCEPT_PORT": "3129"}


def test_parse_listener_values_and_reject_ports_pinned_twice() -> None:
    overrides, warnings = parse_host_overrides(
        {
            "SQUID_HTTP_PORT": "3128",
            "SQUID_INTERCEPT_ENABLED": "Off",
            "SQUID_INTERCEPT_PORT": "3128",
            "SQUID_HTTPS_INTERCEPT_ENABLED": "maybe",
            "SQUID_HTTPS_INTERCEPT_PORT": "70000",
            "SQUID_HTTPS_INTERCEPT_SPLICE_ONLY": "yes",
        },
    )

    assert overrides == {
        "SQUID_HTTP_PORT": 3128,
        "SQUID_INTERCEPT_ENABLED": 0,
        "SQUID_HTTPS_INTERCEPT_SPLICE_ONLY": 1,
    }
    assert len(warnings) == 3
    assert any(
        "SQUID_INTERCEPT_PORT=3128 is already pinned by SQUID_HTTP_PORT" in w
        for w in warnings
    )
    assert any(
        "SQUID_HTTPS_INTERCEPT_ENABLED='maybe' is not a boolean" in w for w in warnings
    )
    assert any(
        "SQUID_HTTPS_INTERCEPT_PORT=70000 is outside 1..65535" in w for w in warnings
    )
    assert decode_overrides(encode_overrides(overrides)) == overrides
    assert describe_overrides(overrides) == [
        {"env": "SQUID_HTTP_PORT", "directive": "http_port", "value": "3128"},
        {
            "env": "SQUID_INTERCEPT_ENABLED",
            "directive": "http_port intercept",
            "value": "off",
        },
        {
            "env": "SQUID_HTTPS_INTERCEPT_SPLICE_ONLY",
            "directive": "ssl_bump splice https_intercept_listener",
            "value": "on",
        },
    ]


def test_production_listener_env_keeps_the_production_revision_byte_identical() -> None:
    overrides, warnings = parse_host_overrides(PROD_LISTENER_ENV)
    revision = UI_EXPLICIT + SSL_RULES

    assert warnings == []
    assert apply_host_overrides(revision, overrides) == revision


def test_listener_env_matching_the_ui_rendering_is_a_no_op() -> None:
    revision = (
        UI_EXPLICIT
        + UI_INTERCEPT
        + UI_HTTPS_INTERCEPT
        + "ssl_bump peek step1\n"
        + UI_SPLICE
    )
    overrides, _warnings = parse_host_overrides(
        {
            "SQUID_HTTP_PORT": "3128",
            "SQUID_INTERCEPT_ENABLED": "1",
            "SQUID_INTERCEPT_PORT": "3129",
            "SQUID_HTTPS_INTERCEPT_ENABLED": "1",
            "SQUID_HTTPS_INTERCEPT_PORT": "3130",
            "SQUID_HTTPS_INTERCEPT_SPLICE_ONLY": "1",
        },
    )

    assert apply_host_overrides(revision, overrides) == revision


def test_listener_env_pins_ports_and_presence_over_the_revision() -> None:
    revision = (
        UI_EXPLICIT + UI_INTERCEPT + SSL_RULES + "http_port 127.0.0.1:3199 tproxy\n"
    )
    overrides = {
        "SQUID_HTTP_PORT": 8080,
        "SQUID_INTERCEPT_PORT": 8081,
        "SQUID_HTTPS_INTERCEPT_PORT": 8443,
        "SQUID_HTTPS_INTERCEPT_SPLICE_ONLY": 1,
        "SQUID_DYNAMIC_CERT_MEM_CACHE_MB": 16,
    }

    rendered = apply_host_overrides(revision, overrides)

    assert rendered == (
        UI_EXPLICIT.replace(":3128 ", ":8080 ").replace("=128MB", "=16MB")
        + UI_INTERCEPT.replace(":3129 ", ":8081 ")
        + UI_HTTPS_INTERCEPT.replace(":3130 ", ":8443 ").replace("=128MB", "=16MB")
        + "ssl_bump peek step1\n"
        + UI_SPLICE
        + "include /etc/squid/conf.d/10-sslfilter.conf\n"
        + "http_port 127.0.0.1:3199 tproxy\n"
    )
    assert apply_host_overrides(rendered, overrides) == rendered

    disabled = apply_host_overrides(
        rendered,
        {"SQUID_INTERCEPT_ENABLED": 0, "SQUID_HTTPS_INTERCEPT_ENABLED": 0},
    )
    assert disabled == (
        UI_EXPLICIT.replace(":3128 ", ":8080 ").replace("=128MB", "=16MB")
        + SSL_RULES
        + "http_port 127.0.0.1:3199 tproxy\n"
    )


def test_listener_env_adds_missing_listeners_with_ui_defaults() -> None:
    revision = "http_port 3200 intercept\nhttp_access deny all\n"

    rendered = apply_host_overrides(
        revision,
        {"SQUID_HTTP_PORT": 3199, "SQUID_INTERCEPT_ENABLED": 1},
    )

    # The explicit listener is the Admin UI's; the intercept default
    # (explicit + 1 = 3200) moves off the revision's own listener.
    assert rendered == (
        UI_EXPLICIT.replace(":3128 ", ":3199 ")
        + UI_INTERCEPT.replace(":3129 ", ":3201 ")
        + "\n"
        + revision
    )
    assert (
        apply_host_overrides(
            rendered, {"SQUID_HTTP_PORT": 3199, "SQUID_INTERCEPT_ENABLED": 1}
        )
        == rendered
    )


def test_listener_port_pin_keeps_host_and_options_across_continuations() -> None:
    revision = "http_port \\\n\t[::1]:3128 ssl-bump\nhttps_port 3130 tls-cert=/c.pem\n"

    assert apply_host_overrides(revision, {"SQUID_HTTP_PORT": 3138}) == (
        "http_port [::1]:3138 ssl-bump\nhttps_port 3130 tls-cert=/c.pem\n"
    )
    assert apply_host_overrides("http_port 3128\n", {"SQUID_HTTP_PORT": 3138}) == (
        "http_port 3138\n"
    )


def test_pinned_port_used_by_another_listener_is_a_conflict() -> None:
    revision = UI_EXPLICIT + "https_port 3130 tls-cert=/c.pem\n"

    with pytest.raises(HostOverrideError, match="SQUID_HTTP_PORT=3130"):
        apply_host_overrides(revision, {"SQUID_HTTP_PORT": 3130})
    # A pinned-off listener's port is not in use.
    assert (
        apply_host_overrides(
            revision,
            {"SQUID_INTERCEPT_ENABLED": 0, "SQUID_INTERCEPT_PORT": 3130},
        )
        == revision
    )


@pytest.mark.parametrize(
    "other",
    [
        "http_port 3138",
        "http_port 0.0.0.0:3138",
        "http_port [::]:3138",
        "http_port 192.0.2.7:3138",
        "http_port [::ffff:192.0.2.7]:3138",
        "http_port proxy.example:3138",
    ],
)
def test_pinned_port_on_an_overlapping_address_is_a_conflict(other: str) -> None:
    # The pinned explicit listener binds 0.0.0.0 (every IPv4 address).
    with pytest.raises(HostOverrideError, match="SQUID_HTTP_PORT=3138"):
        apply_host_overrides(f"{UI_EXPLICIT}{other}\n", {"SQUID_HTTP_PORT": 3138})


@pytest.mark.parametrize(
    ("explicit", "other"),
    [
        ("http_port 0.0.0.0:3128 ssl-bump", "http_port [::1]:3138"),
        ("http_port 192.0.2.1:3128 ssl-bump", "http_port 192.0.2.2:3138"),
        ("http_port [2001:db8::1]:3128", "https_port [2001:db8::2]:3138 tls-cert=/c"),
    ],
)
def test_pinned_port_shared_by_distinct_addresses_is_not_a_conflict(
    explicit: str, other: str
) -> None:
    revision = f"{explicit}\n{other}\n"

    rendered = apply_host_overrides(revision, {"SQUID_HTTP_PORT": 3138})

    assert rendered == revision.replace(":3128", ":3138", 1)


def test_conflicting_revision_fails_validation_and_apply_once(monkeypatch) -> None:
    from services.squid_core import SquidController

    import proxy.runtime as runtime_module  # type: ignore

    monkeypatch.setenv(OVERRIDES_ENV, encode_overrides({"SQUID_INTERCEPT_PORT": 3129}))
    controller = SquidController()
    good = controller.normalize_config_text(UI_EXPLICIT + SSL_RULES)
    conflicting = UI_EXPLICIT.replace(":3128 ", ":3129 ") + SSL_RULES
    current = {"text": good}
    runtime, applied, marked = _sync_runtime(controller, conflicting, current)
    results: list[SimpleNamespace] = []

    def record_apply_result(_proxy_id, revision_id, *, ok, detail, applied_by):
        results.append(SimpleNamespace(revision_id=revision_id, ok=ok, detail=detail))
        return SimpleNamespace(application_id=len(results))

    runtime.revisions.record_apply_result = record_apply_result
    runtime.revisions.latest_apply = lambda _proxy_id: results[-1] if results else None
    monkeypatch.setattr(
        runtime_module,
        "get_operation_ledger",
        lambda: SimpleNamespace(
            requeue_stale_applying=lambda *_args, **_kwargs: 0,
            claim_pending=lambda *_args, **_kwargs: [],
        ),
    )

    validation = runtime.validate_config_text(conflicting)
    first = runtime.sync_from_db(force=False)
    second = runtime.sync_from_db(force=False)

    assert validation["ok"] is False
    assert "SQUID_INTERCEPT_PORT=3129" in validation["detail"]
    assert first["ok"] is False
    assert "SQUID_INTERCEPT_PORT=3129" in first["detail"]
    assert applied == []
    assert current["text"] == good
    assert set(marked) == {hashlib.sha256(good.encode()).hexdigest()}
    assert [item.ok for item in results] == [False]
    assert second["ok"] is False
    assert "previously failed" in second["detail"]

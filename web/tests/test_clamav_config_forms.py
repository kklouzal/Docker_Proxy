from __future__ import annotations

from pathlib import Path

import pytest


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[2]


@pytest.fixture(autouse=True)
def _isolated_squid_transaction_journal(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv(
        "SQUID_TRANSACTION_JOURNAL_PATH",
        str(tmp_path / "squid-transaction.json"),
    )


def _directives(config_text: str) -> dict[str, str]:
    directives: dict[str, str] = {}
    for raw_line in config_text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or not line.startswith("virus_scan."):
            continue
        key, value = line.split(None, 1)
        directives[key] = value
    return directives


def test_clamav_defaults_keep_upload_and_filename_blocking_controls_off() -> None:
    from services.clamav_config_forms import (
        DEFAULTS,
        normalize_clamav_options,
        render_file_security_policy_config,
        render_virus_scan_config,
    )

    options = normalize_clamav_options()

    assert options["clamav_fail_mode"] == "open"
    assert options["file_security_preset"] == "balanced"
    assert options["file_security_scan_downloads"] is True
    assert options["file_security_scan_uploads"] is False
    assert options["file_security_block_risky_extensions"] is False
    assert options["file_security_block_archives"] is False
    assert options["file_security_block_executable_content"] is False
    assert options["virus_scan_start_send_percent_after"] == "2M"
    assert options["virus_scan_send_percent_data"] == 5
    assert DEFAULTS["virus_scan_start_send_percent_after"] == "2M"

    rendered = render_virus_scan_config()
    assert "virus_scan.StartSendPercentDataAfter 2M" in rendered
    assert "virus_scan.SendPercentData 5" in rendered
    assert "virus_scan.PassOnError on" in rendered

    policy = render_file_security_policy_config()
    assert "request_body_max_size" not in policy
    assert "reply_body_max_size" not in policy
    assert (
        "adaptation_access av_req_set allow file_security_upload_methods" not in policy
    )
    assert "adaptation_access av_resp_set deny file_security_range_request" in policy
    assert "adaptation_access av_resp_set deny file_security_partial_response" in policy
    assert (
        "adaptation_access av_resp_set allow file_security_download_methods" in policy
    )
    assert "acl file_security_risky_path" not in policy
    assert "http_access deny file_security_risky_path" not in policy
    assert "acl file_security_executable_path" not in policy
    assert "http_access deny file_security_executable_path" not in policy
    assert "http_access deny file_security_executable_mime" not in policy
    assert "|js|" not in policy
    assert "OAWrapper.exe" not in policy


def test_download_respmod_policy_remains_enabled_for_stream_safe_remote_clamd() -> None:
    from services.clamav_config_forms import render_file_security_policy_config

    policy = render_file_security_policy_config()

    assert (
        "adaptation_access av_req_set allow file_security_upload_methods" not in policy
    )
    assert "adaptation_access av_resp_set deny file_security_range_request" in policy
    assert "adaptation_access av_resp_set deny file_security_partial_response" in policy
    assert (
        "adaptation_access av_resp_set allow file_security_download_methods" in policy
    )
    assert "adaptation_access av_resp_set deny all" in policy
    assert "download/RESPMOD AV scanning disabled" not in policy


def test_legacy_default_risky_extensions_drop_web_script_assets() -> None:
    from services.clamav_config_forms import normalize_clamav_options

    options = normalize_clamav_options(
        {
            "file_security_risky_extensions": "exe dll msi bat cmd com scr ps1 vbs js jar apk",
        },
    )

    assert (
        options["file_security_risky_extensions"]
        == "exe dll msi bat cmd scr ps1 vbs jar apk"
    )


def test_clamav_options_round_trip_and_fail_closed_rendering() -> None:
    from services.clamav_config_forms import (
        apply_clamav_options_to_config,
        extract_clamav_options,
        render_file_security_policy_config,
        render_virus_scan_config,
    )

    config = "workers 1\nadaptation_access av_resp_set allow icap_av_scanable\n"
    updated = apply_clamav_options_to_config(
        config,
        {
            "clamav_fail_mode": "closed",
            "file_security_scan_downloads": True,
            "file_security_scan_uploads": True,
            "file_security_block_risky_extensions": True,
            "file_security_risky_extensions": "exe, dll, js",
            "file_security_block_executable_content": True,
            "file_security_executable_extensions": "exe dll msi",
            "file_security_block_archives": True,
            "file_security_archive_extensions": "zip 7z",
            "file_security_max_download_size": "64M",
            "file_security_max_upload_size": "32M",
            "virus_scan_scan_file_types": "TEXT DATA",
            "virus_scan_send_percent_data": "150",
            "virus_scan_start_send_percent_after": "64K",
            "virus_scan_allow_204_on": False,
            "virus_scan_max_object_size": "256M",
            "virus_scan_default_engine": "clamd",
        },
    )

    options = extract_clamav_options(updated)
    assert options["clamav_fail_mode"] == "closed"
    assert options["file_security_scan_uploads"] is True
    assert options["file_security_block_risky_extensions"] is True
    assert options["file_security_block_executable_content"] is True
    assert options["virus_scan_send_percent_data"] == 99
    assert options["virus_scan_allow_204_on"] is False
    assert options["file_security_max_download_size"] == "64M"
    assert options["file_security_max_upload_size"] == "32M"

    rendered = render_virus_scan_config(options)
    assert "virus_scan.PassOnError off" in rendered
    assert "virus_scan.Allow204Responces off" in rendered
    assert "virus_scan.DefaultEngine clamd" in rendered

    policy = render_file_security_policy_config(options)
    assert "request_body_max_size 32 MB" in policy
    assert "reply_body_max_size 64 MB" in policy
    assert "adaptation_access av_resp_set deny file_security_range_request" in policy
    assert "acl file_security_risky_path" in policy
    assert "acl file_security_archive_path" in policy
    assert "acl file_security_executable_path" in policy
    assert (
        "note file_security_policy file_security_risky_extension file_security_risky_path"
        in policy
    )
    assert (
        "note file_security_policy file_security_archive_extension file_security_archive_path"
        in policy
    )
    assert (
        "note file_security_policy file_security_executable_upload_mime file_security_executable_mime file_security_upload_methods"
        in policy
    )
    assert "http_access deny file_security_risky_path" in policy
    assert "http_access deny file_security_archive_path" in policy
    assert "http_access deny file_security_executable_path" in policy
    assert (
        "http_access deny file_security_executable_mime file_security_upload_methods"
        in policy
    )


def test_strict_policy_blocks_only_path_extensions_and_attributes_denials() -> None:
    from services.clamav_config_forms import render_file_security_policy_config

    policy = render_file_security_policy_config({"file_security_preset": "strict"})

    assert "^[^?#]*\\.(exe|dll|msi|bat|cmd|scr|ps1|vbs|jar|apk)([?#].*)?$" in policy
    assert (
        "note file_security_policy file_security_risky_extension file_security_risky_path"
        in policy
    )
    assert (
        "note file_security_policy file_security_executable_extension file_security_executable_path"
        in policy
    )
    assert (
        "note file_security_policy file_security_archive_extension file_security_archive_path"
        in policy
    )
    assert "file_security_email_identifier" not in policy
    assert "http_access deny file_security_risky_path" in policy
    assert "http_access deny file_security_archive_path" in policy
    assert "http_access deny file_security_executable_path" in policy


def test_explicit_upload_scan_opt_in_survives_saved_config_round_trip() -> None:
    from services.clamav_config_forms import (
        apply_clamav_options_to_config,
        extract_clamav_options,
        render_file_security_policy_config,
    )

    saved = apply_clamav_options_to_config(
        "workers 1\n",
        {
            "file_security_preset": "balanced",
            "file_security_scan_uploads": True,
        },
    )
    restored = extract_clamav_options(saved)

    assert restored["file_security_scan_uploads"] is True
    assert (
        "adaptation_access av_req_set allow file_security_upload_methods"
        in render_file_security_policy_config(restored)
    )


@pytest.mark.parametrize("preset", ["balanced", "monitor"])
def test_non_strict_defaults_scan_without_pretransfer_extension_denial(
    preset: str,
) -> None:
    from services.clamav_config_forms import render_file_security_policy_config

    policy = render_file_security_policy_config({"file_security_preset": preset})

    for filename in (
        "OAWrapper.exe",
        "vs_installer.msi",
        "windows-update.exe",
        "install.ps1",
    ):
        assert filename.lower().rsplit(".", 1)[1] in {
            "exe",
            "msi",
            "ps1",
        }
    assert (
        "adaptation_access av_resp_set allow file_security_download_methods" in policy
    )
    assert "http_access deny file_security_risky_path" not in policy
    assert "http_access deny file_security_archive_path" not in policy
    assert "http_access deny file_security_executable_path" not in policy
    assert "http_access deny file_security_executable_mime" not in policy


@pytest.mark.parametrize(
    ("field", "acl", "note", "deny"),
    [
        (
            "file_security_block_risky_extensions",
            "acl file_security_risky_path",
            "note file_security_policy file_security_risky_extension file_security_risky_path",
            "http_access deny file_security_risky_path",
        ),
        (
            "file_security_block_archives",
            "acl file_security_archive_path",
            "note file_security_policy file_security_archive_extension file_security_archive_path",
            "http_access deny file_security_archive_path",
        ),
        (
            "file_security_block_executable_content",
            "acl file_security_executable_path",
            "note file_security_policy file_security_executable_extension file_security_executable_path",
            "http_access deny file_security_executable_path",
        ),
    ],
)
def test_balanced_explicit_block_opt_in_survives_form_and_config_round_trip(
    field: str,
    acl: str,
    note: str,
    deny: str,
) -> None:
    from services.clamav_config_forms import (
        apply_clamav_options_to_config,
        extract_clamav_options,
        read_clamav_options_from_form,
        render_file_security_policy_config,
    )

    submitted = read_clamav_options_from_form(
        {"file_security_preset": "balanced", field: "on"},
        {"file_security_preset": "balanced"},
    )
    restored = extract_clamav_options(
        apply_clamav_options_to_config("workers 1\n", submitted),
    )
    policy = render_file_security_policy_config(restored)

    assert restored["file_security_preset"] == "balanced"
    assert restored[field] is True
    assert acl in policy
    assert note in policy
    assert deny in policy


def test_strict_acl_input_keeps_installers_blocked_without_com_false_positive() -> None:
    import re

    from services.clamav_config_forms import render_file_security_policy_config

    policy = render_file_security_policy_config({"file_security_preset": "strict"})
    regex_text = next(
        line.rsplit(" -i ", 1)[1]
        for line in policy.splitlines()
        if line.startswith("acl file_security_risky_path ")
    )
    path_pattern = re.compile(regex_text, re.IGNORECASE)

    # Squid urlpath_regex evaluates the request path; some builds retain its
    # query suffix. In either case, a true installer suffix is before the query
    # and remains blocked even when an email appears in the name or query.
    assert path_pattern.fullmatch("/downloads/OAWrapper.exe")
    assert path_pattern.fullmatch("/downloads/malware@vendor.exe")
    assert path_pattern.fullmatch("/downloads/malware.exe?email=a@b.com")
    assert path_pattern.fullmatch("/downloads/vs.msi?email=a%40b.com")
    assert not path_pattern.fullmatch("/outlook/user@domain.com")
    assert not path_pattern.fullmatch("/outlook/user%40domain.com")
    assert not path_pattern.fullmatch("/lookup?user=person@domain.com")
    assert not path_pattern.fullmatch("/lookup?user=person%40domain.com")


def test_operator_supplied_com_extension_is_removed_from_strict_path_acl() -> None:
    from services.clamav_config_forms import render_file_security_policy_config

    policy = render_file_security_policy_config(
        {
            "file_security_preset": "strict",
            "file_security_risky_extensions": "exe com msi",
            "file_security_executable_extensions": "exe com",
        },
    )

    assert "\\.(exe|msi)" in policy
    assert (
        "acl file_security_executable_path urlpath_regex -i ^[^?#]*\\.(exe)" in policy
    )
    assert "|com" not in policy
    assert "com|" not in policy
    assert "file_security_executable_mime" in policy


def test_strict_policy_notes_use_the_exact_denial_acl_conditions() -> None:
    from services.clamav_config_forms import render_file_security_policy_config

    lines = render_file_security_policy_config(
        {"file_security_preset": "strict"},
    ).splitlines()

    assert lines.index(
        "note file_security_policy file_security_risky_extension file_security_risky_path",
    ) + 1 == lines.index("http_access deny file_security_risky_path")
    assert lines.index(
        "note file_security_policy file_security_executable_extension file_security_executable_path",
    ) + 1 == lines.index("http_access deny file_security_executable_path")
    assert lines.index(
        "note file_security_policy file_security_executable_upload_mime file_security_executable_mime file_security_upload_methods",
    ) + 1 == lines.index(
        "http_access deny file_security_executable_mime file_security_upload_methods",
    )


def test_clamav_form_rejects_malformed_size_instead_of_disabling_existing_cap() -> None:
    from services.clamav_config_forms import read_clamav_options_from_form

    current = {
        "file_security_preset": "balanced",
        "file_security_max_download_size": "64M",
    }

    with pytest.raises(ValueError, match="Maximum download size"):
        read_clamav_options_from_form(
            {"file_security_max_download_size": "64 MB"},
            current,
        )


def test_clamav_preset_change_reseeds_untouched_policy_fields() -> None:
    from services.clamav_config_forms import read_clamav_options_from_form

    current = {
        "file_security_preset": "balanced",
        "file_security_scan_downloads": True,
        "file_security_scan_uploads": True,
        "file_security_block_risky_extensions": True,
        "file_security_block_archives": False,
        "file_security_block_nested_archives": False,
        "file_security_block_executable_content": True,
    }

    options = read_clamav_options_from_form({"file_security_preset": "strict"}, current)

    assert options["file_security_preset"] == "strict"
    assert options["file_security_scan_downloads"] is True
    assert options["file_security_scan_uploads"] is True
    assert options["file_security_block_risky_extensions"] is True
    assert options["file_security_block_archives"] is True
    assert options["file_security_block_nested_archives"] is True
    assert options["file_security_block_executable_content"] is True


def test_clamav_monitor_preset_relaxes_untouched_blocking_controls() -> None:
    from services.clamav_config_forms import read_clamav_options_from_form

    current = {
        "file_security_preset": "balanced",
        "file_security_scan_downloads": True,
        "file_security_scan_uploads": True,
        "file_security_block_risky_extensions": True,
        "file_security_block_archives": True,
        "file_security_block_nested_archives": True,
        "file_security_block_executable_content": True,
    }

    options = read_clamav_options_from_form(
        {"file_security_preset": "monitor"}, current
    )

    assert options["file_security_preset"] == "monitor"
    assert options["file_security_scan_downloads"] is True
    assert options["file_security_scan_uploads"] is False
    assert options["file_security_block_risky_extensions"] is False
    assert options["file_security_block_archives"] is False
    assert options["file_security_block_nested_archives"] is False
    assert options["file_security_block_executable_content"] is False


def test_clamav_preset_change_preserves_explicit_checked_matching_current_value() -> (
    None
):
    from services.clamav_config_forms import read_clamav_options_from_form

    current = {
        "file_security_preset": "balanced",
        "file_security_scan_downloads": True,
        "file_security_scan_uploads": True,
        "file_security_block_risky_extensions": True,
        "file_security_block_archives": True,
        "file_security_block_nested_archives": True,
        "file_security_block_executable_content": True,
    }

    options = read_clamav_options_from_form(
        {
            "file_security_preset": "monitor",
            "file_security_block_archives": "on",
        },
        current,
    )

    assert options["file_security_preset"] == "monitor"
    assert options["file_security_block_archives"] is True
    assert options["file_security_block_risky_extensions"] is False
    assert options["file_security_block_nested_archives"] is False
    assert options["file_security_block_executable_content"] is False


def test_clamav_unchecked_checkbox_absence_still_clears_when_preset_unchanged() -> None:
    from services.clamav_config_forms import read_clamav_options_from_form

    current = {
        "file_security_preset": "balanced",
        "file_security_block_archives": True,
    }

    options = read_clamav_options_from_form(
        {"file_security_preset": "balanced"},
        current,
    )

    assert options["file_security_preset"] == "balanced"
    assert options["file_security_block_archives"] is False


def test_packaged_virus_scan_config_matches_schema_streaming_defaults() -> None:
    from services.clamav_config_forms import render_virus_scan_config

    packaged = _directives(
        (_repo_root() / "docker" / "virus_scan.conf").read_text(encoding="utf-8")
    )
    rendered = _directives(render_virus_scan_config())

    assert (
        packaged["virus_scan.StartSendPercentDataAfter"]
        == rendered["virus_scan.StartSendPercentDataAfter"]
        == "2M"
    )
    assert (
        packaged["virus_scan.SendPercentData"]
        == rendered["virus_scan.SendPercentData"]
        == "5"
    )
    assert (
        packaged["virus_scan.PassOnError"] == rendered["virus_scan.PassOnError"] == "on"
    )


def test_cicap_alias_does_not_override_schema_allow_204_policy() -> None:
    from services.clamav_config_forms import render_virus_scan_config

    rendered = render_virus_scan_config({"virus_scan_allow_204_on": False})
    cicap_config = (_repo_root() / "docker" / "c-icap.conf").read_text(encoding="utf-8")
    alias = next(
        line
        for line in cicap_config.splitlines()
        if line.startswith("ServiceAlias avrespmod ")
    )

    assert "virus_scan.Allow204Responces off" in rendered
    assert "allow204=" not in alias
    assert alias == "ServiceAlias avrespmod virus_scan?sizelimit=off&mode=simple"


def test_squid_controller_materializes_clamav_runtime_files(
    tmp_path, monkeypatch
) -> None:
    from services.clamav_config_forms import apply_clamav_options_to_config
    from services.squid_core import SquidController

    icap_path = tmp_path / "20-icap.conf"
    virus_path = tmp_path / "virus_scan.conf"
    monkeypatch.setenv("SQUID_ICAP_INCLUDE_PATH", str(icap_path))
    monkeypatch.setenv("VIRUS_SCAN_CONFIG_PATH", str(virus_path))
    from services.squid_core import (
        _cached_icap_include_path,
        _cached_virus_scan_config_path,
    )

    _cached_icap_include_path.cache_clear()
    _cached_virus_scan_config_path.cache_clear()

    config = apply_clamav_options_to_config(
        "workers 1\nadaptation_access av_resp_set allow icap_av_scanable\n",
        {
            "clamav_fail_mode": "closed",
            "file_security_scan_downloads": True,
            "file_security_scan_uploads": True,
            "file_security_block_risky_extensions": True,
            "file_security_risky_extensions": "exe dll",
            "file_security_block_executable_content": True,
            "file_security_executable_extensions": "exe msi",
            "file_security_blocked_mime_types": "application/x-msdownload application/x-ms-installer",
            "file_security_max_download_size": "128M",
            "file_security_max_upload_size": "64M",
            "virus_scan_max_object_size": "64M",
        },
    )
    controller = SquidController(squid_conf_path=str(tmp_path / "squid.conf"))

    ok, detail = controller.materialize_clamav_runtime_files(config)

    assert ok is True
    assert "updated" in detail
    include_text = icap_path.read_text(encoding="utf-8")
    assert "icap_service av_req reqmod_precache" in include_text
    assert (
        "adaptation_access av_req_set allow file_security_upload_methods"
        in include_text
    )
    assert (
        "adaptation_access av_resp_set deny file_security_range_request" in include_text
    )
    assert (
        "adaptation_access av_resp_set deny file_security_partial_response"
        in include_text
    )
    assert "request_body_max_size 64 MB" in include_text
    assert "reply_body_max_size 128 MB" in include_text
    assert "acl file_security_risky_path" in include_text
    assert "acl file_security_executable_path" in include_text
    assert (
        "note file_security_policy file_security_risky_extension file_security_risky_path"
        in include_text
    )
    assert "http_access deny file_security_risky_path" in include_text
    assert (
        "http_access deny file_security_executable_mime file_security_upload_methods"
        in include_text
    )
    virus_conf = virus_path.read_text(encoding="utf-8")
    assert "virus_scan.PassOnError off" in virus_conf
    assert "virus_scan.SendPercentData 5" in virus_conf
    assert "virus_scan.StartSendPercentDataAfter 2M" in virus_conf
    assert "virus_scan.MaxObjectSize 64M" in virus_conf


def test_squid_controller_routes_remote_clamd_download_scan_to_stream_helper(
    tmp_path,
    monkeypatch,
) -> None:
    from services.clamav_config_forms import apply_clamav_options_to_config
    from services.squid_core import SquidController

    icap_path = tmp_path / "20-icap.conf"
    virus_path = tmp_path / "virus_scan.conf"
    monkeypatch.setenv("SQUID_ICAP_INCLUDE_PATH", str(icap_path))
    monkeypatch.setenv("VIRUS_SCAN_CONFIG_PATH", str(virus_path))
    monkeypatch.setenv("CLAMD_HOST", "192.168.1.10")
    from services.squid_core import (
        _cached_icap_include_path,
        _cached_virus_scan_config_path,
    )

    _cached_icap_include_path.cache_clear()
    _cached_virus_scan_config_path.cache_clear()

    config = apply_clamav_options_to_config(
        "workers 1\n",
        {
            "file_security_scan_downloads": True,
            "file_security_scan_uploads": True,
        },
    )
    controller = SquidController(squid_conf_path=str(tmp_path / "squid.conf"))

    ok, detail = controller.materialize_clamav_runtime_files(config)

    assert ok is True
    assert "updated" in detail
    include_text = icap_path.read_text(encoding="utf-8")
    assert (
        "icap_service av_req reqmod_precache icap://127.0.0.1:14001/avrespmod"
        in include_text
    )
    assert (
        "icap_service av_resp respmod_precache icap://127.0.0.1:14002/avrespmod"
        in include_text
    )
    assert "adaptation_service_set av_resp_set av_resp" in include_text
    assert (
        "adaptation_access av_req_set allow file_security_upload_methods"
        in include_text
    )
    assert (
        "adaptation_access av_resp_set deny file_security_range_request" in include_text
    )
    assert (
        "adaptation_access av_resp_set deny file_security_partial_response"
        in include_text
    )
    assert (
        "adaptation_access av_resp_set allow file_security_download_methods"
        in include_text
    )
    assert "adaptation_access av_resp_set deny all" in include_text
    assert "download/RESPMOD AV scanning disabled" not in include_text
    assert "c-icap virus_scan passes local temporary file paths" not in include_text

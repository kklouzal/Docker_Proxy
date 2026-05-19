from __future__ import annotations

import sys
from pathlib import Path


def _add_web_path() -> None:
    web_root = Path(__file__).resolve().parents[1]
    if str(web_root) not in sys.path:
        sys.path.insert(0, str(web_root))


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[2]


def _directives(config_text: str) -> dict[str, str]:
    directives: dict[str, str] = {}
    for raw_line in config_text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or not line.startswith("virus_scan."):
            continue
        key, value = line.split(None, 1)
        directives[key] = value
    return directives


def test_clamav_defaults_preserve_download_progress_and_tail_blocking_contract() -> None:
    _add_web_path()
    from services.clamav_config_forms import DEFAULTS, normalize_clamav_options, render_file_security_policy_config, render_virus_scan_config

    options = normalize_clamav_options()

    assert options["clamav_fail_mode"] == "open"
    assert options["file_security_preset"] == "balanced"
    assert options["file_security_scan_downloads"] is True
    assert options["file_security_scan_uploads"] is True
    assert options["virus_scan_start_send_percent_after"] == "1K"
    assert options["virus_scan_send_percent_data"] == 99
    assert DEFAULTS["virus_scan_start_send_percent_after"] == "1K"

    rendered = render_virus_scan_config()
    assert "virus_scan.StartSendPercentDataAfter 1K" in rendered
    assert "virus_scan.SendPercentData 99" in rendered
    assert "virus_scan.PassOnError on" in rendered

    policy = render_file_security_policy_config()
    assert "request_body_max_size 0 MB" in policy
    assert "reply_body_max_size 0 MB" in policy
    assert "adaptation_access av_req_set allow file_security_upload_methods" in policy
    assert "adaptation_access av_resp_set deny file_security_range_request" in policy
    assert "adaptation_access av_resp_set deny file_security_partial_response" in policy
    assert "adaptation_access av_resp_set allow file_security_download_methods" in policy
    assert "acl file_security_risky_path urlpath_regex -i" in policy


def test_clamav_options_round_trip_and_fail_closed_rendering() -> None:
    _add_web_path()
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
    assert "acl file_security_risky_path urlpath_regex -i" in policy
    assert "http_access deny file_security_executable_mime file_security_upload_methods" in policy


def test_clamav_preset_change_reseeds_untouched_policy_fields() -> None:
    _add_web_path()
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
    _add_web_path()
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

    options = read_clamav_options_from_form({"file_security_preset": "monitor"}, current)

    assert options["file_security_preset"] == "monitor"
    assert options["file_security_scan_downloads"] is True
    assert options["file_security_scan_uploads"] is True
    assert options["file_security_block_risky_extensions"] is False
    assert options["file_security_block_archives"] is False
    assert options["file_security_block_nested_archives"] is False
    assert options["file_security_block_executable_content"] is False


def test_packaged_virus_scan_config_matches_schema_streaming_defaults() -> None:
    _add_web_path()
    from services.clamav_config_forms import render_virus_scan_config

    packaged = _directives((_repo_root() / "docker" / "virus_scan.conf").read_text(encoding="utf-8"))
    rendered = _directives(render_virus_scan_config())

    assert packaged["virus_scan.StartSendPercentDataAfter"] == rendered["virus_scan.StartSendPercentDataAfter"] == "1K"
    assert packaged["virus_scan.SendPercentData"] == rendered["virus_scan.SendPercentData"] == "99"
    assert packaged["virus_scan.PassOnError"] == rendered["virus_scan.PassOnError"] == "on"


def test_squid_controller_materializes_clamav_runtime_files(tmp_path, monkeypatch) -> None:
    _add_web_path()
    from services.clamav_config_forms import apply_clamav_options_to_config
    from services.squid_core import SquidController

    icap_path = tmp_path / "20-icap.conf"
    virus_path = tmp_path / "virus_scan.conf"
    monkeypatch.setenv("SQUID_ICAP_INCLUDE_PATH", str(icap_path))
    monkeypatch.setenv("VIRUS_SCAN_CONFIG_PATH", str(virus_path))
    from services.squid_core import _cached_icap_include_path, _cached_virus_scan_config_path

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
    assert "adaptation_access av_req_set allow file_security_upload_methods" in include_text
    assert "adaptation_access av_resp_set deny file_security_range_request" in include_text
    assert "adaptation_access av_resp_set deny file_security_partial_response" in include_text
    assert "request_body_max_size 64 MB" in include_text
    assert "reply_body_max_size 128 MB" in include_text
    assert "http_access deny file_security_risky_path" in include_text
    assert "http_access deny file_security_executable_mime file_security_upload_methods" in include_text
    virus_conf = virus_path.read_text(encoding="utf-8")
    assert "virus_scan.PassOnError off" in virus_conf
    assert "virus_scan.SendPercentData 99" in virus_conf
    assert "virus_scan.StartSendPercentDataAfter 1K" in virus_conf
    assert "virus_scan.MaxObjectSize 64M" in virus_conf

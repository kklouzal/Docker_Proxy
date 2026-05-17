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
    from services.clamav_config_forms import DEFAULTS, normalize_clamav_options, render_virus_scan_config

    options = normalize_clamav_options()

    assert options["clamav_fail_mode"] == "open"
    assert options["virus_scan_start_send_percent_after"] == "1K"
    assert options["virus_scan_send_percent_data"] == 99
    assert DEFAULTS["virus_scan_start_send_percent_after"] == "1K"

    rendered = render_virus_scan_config()
    assert "virus_scan.StartSendPercentDataAfter 1K" in rendered
    assert "virus_scan.SendPercentData 99" in rendered
    assert "virus_scan.PassOnError on" in rendered


def test_clamav_options_round_trip_and_fail_closed_rendering() -> None:
    _add_web_path()
    from services.clamav_config_forms import (
        apply_clamav_options_to_config,
        extract_clamav_options,
        render_virus_scan_config,
    )

    config = "workers 1\nadaptation_access av_resp_set allow icap_av_scanable\n"
    updated = apply_clamav_options_to_config(
        config,
        {
            "clamav_fail_mode": "closed",
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

    rendered = render_virus_scan_config(options)
    assert "virus_scan.PassOnError off" in rendered
    assert "virus_scan.Allow204Responces off" in rendered
    assert "virus_scan.DefaultEngine clamd" in rendered



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
        {"clamav_fail_mode": "closed", "virus_scan_max_object_size": "64M"},
    )
    controller = SquidController(squid_conf_path=str(tmp_path / "squid.conf"))

    ok, detail = controller.materialize_clamav_runtime_files(config)

    assert ok is True
    assert "updated" in detail
    assert "avrespmod bypass=off" in icap_path.read_text(encoding="utf-8")
    virus_conf = virus_path.read_text(encoding="utf-8")
    assert "virus_scan.PassOnError off" in virus_conf
    assert "virus_scan.SendPercentData 99" in virus_conf
    assert "virus_scan.StartSendPercentDataAfter 1K" in virus_conf
    assert "virus_scan.MaxObjectSize 64M" in virus_conf


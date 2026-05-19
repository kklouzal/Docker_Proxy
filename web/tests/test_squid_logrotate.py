from pathlib import Path


def test_squid_logrotate_copytruncates_observability_logs_without_runtime_rotate() -> (
    None
):
    script = (
        Path(__file__).resolve().parents[2] / "docker" / "squid_logrotate.sh"
    ).read_text(encoding="utf-8")

    assert "if ! squid -k rotate" not in script
    assert "/var/log/squid/access-observe.log" in script
    assert "/var/log/squid/icap.log" in script
    assert 'cp -- "$logfile" "${logfile}.1"' in script
    assert ': > "$logfile"' in script

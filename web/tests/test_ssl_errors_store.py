from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from services.ssl_errors_store import _extract_domain  # type: ignore  # noqa: E402


def test_ssl_error_domain_extraction_accepts_peer_token() -> None:
    line = 'kid1| Error negotiating TLS on FD 42: SQUID_TLS_ERR_ACCEPT+TLS_LIB_ERR=1 peer=media.steampowered.com:443'
    assert _extract_domain(line) == 'media.steampowered.com'


def test_ssl_error_domain_extraction_accepts_server_name_token() -> None:
    line = 'kid1| Error negotiating TLS on FD 42: SQUID_TLS_ERR_ACCEPT server_name=api.steampowered.com'
    assert _extract_domain(line) == 'api.steampowered.com'


def test_steam_compatibility_preset_is_shipped_once() -> None:
    from services.ssl_compatibility_presets import COMPATIBILITY_PRESETS  # type: ignore  # noqa: E402
    matches = [preset for preset in COMPATIBILITY_PRESETS if preset.id == 'steam']
    assert len(matches) == 1
    assert '*.steamserver.net' in matches[0].domains
    assert 'cdn.cloudflare.steamstatic.com' in matches[0].domains

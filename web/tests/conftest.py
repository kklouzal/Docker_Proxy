from __future__ import annotations

# Expose shared live-stack fixtures to pytest collection. The fixture
# functions live beside the helper client so live tests can also import
# helpers directly, but pytest only makes fixtures available suite-wide
# when they are defined in conftest.py or a registered plugin.
from web.tests.live_test_helpers import admin_client as admin_client
from web.tests.live_test_helpers import live_stack_ready as live_stack_ready

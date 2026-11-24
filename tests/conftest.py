import pytest

from probe.sandbox import network_denial

# The probe refuses to run without a way to deny outbound network traffic (sandbox-exec on
# macOS). Where there is none, tests that launch it are skipped, never run unsandboxed.
needs_network_denial = pytest.mark.skipif(
    network_denial() is None, reason="no network denial available (macOS sandbox-exec)"
)

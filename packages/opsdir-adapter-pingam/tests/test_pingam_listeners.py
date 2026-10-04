"""PingAM's listener for the ports matrix, and that the adapter declares it."""
from opsdir.core.contract import Listener
from opsdir_adapter_pingam.adapter import ADAPTER


def test_https_for_clients():
    assert ADAPTER.listeners(None) == (Listener("am", 8443, "tcp", "HTTPS", ("clients",)),)

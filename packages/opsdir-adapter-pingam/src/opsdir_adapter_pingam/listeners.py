"""PingAM's listeners for the ports matrix: its HTTPS listener for clients (8443 unless the estate moved it; the record
holds no port for it). Pure."""
from opsdir.core.contract import Listener

HTTPS = Listener("am", 8443, "tcp", "HTTPS", ("clients",))


def listeners(m):
    """PingAM's listeners in environment m."""
    return (HTTPS,)

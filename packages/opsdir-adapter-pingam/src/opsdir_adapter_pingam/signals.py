"""The neutral signals PingAM servers expose at their Prometheus endpoint (/metrics/prometheus/0.0.4, once the
Monitoring service's prometheus configuration is enabled), as the PingAM 8 metrics reference names them
(docs.pingidentity.com/pingam/8/maintenance/monitoring-metrics.html). Heap use isn't declared: the reference doesn't
state its unit."""
from opsdir.core.contract import Signal
from .realms import SERVER_ROLES

AM = SERVER_ROLES[0]

SIGNALS = (
    Signal("login-failures", AM, 'sum by (instance) (rate(am_authentication_count{outcome="failure"}[5m]))', "/s",
           "authentication flows ending in failure, per second"),)

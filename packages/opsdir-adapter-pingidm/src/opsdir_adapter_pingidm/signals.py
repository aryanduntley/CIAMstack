"""The neutral signals PingIDM servers expose at their Prometheus endpoint (/openidm/metrics/prometheus, once
conf/metrics.json enables metrics; basic authentication since PingIDM 8), as the PingIDM 8.1 Prometheus metrics
reference names them (docs.pingidentity.com/pingidm/8.1/monitoring-guide/prometheus-metrics.html)."""
from opsdir.core.contract import Signal
from .naming import SERVER_ROLES

IDM = SERVER_ROLES[0]

SIGNALS = (
    Signal("heap-used", IDM, 'idm_jvm_memory_usage_used{location="heap"}', "bytes", "heap memory the JVM uses"),)

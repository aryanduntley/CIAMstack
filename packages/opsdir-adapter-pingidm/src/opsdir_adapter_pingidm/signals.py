"""The neutral signals PingIDM servers expose at their Prometheus endpoint (/openidm/metrics/prometheus, once
conf/metrics.json enables metrics; basic authentication since PingIDM 8), as each release line's Prometheus metrics
reference names them: IDM 8 labels JVM memory by location (docs.pingidentity.com/pingidm/8.1/monitoring-guide/
prometheus-metrics.html, and /pingidm/8/... for 8.0), IDM 7 names the heap in the metric (/pingidm/7.5/...: the
same on 7.2 and 7.4; research 2552)."""
from opsdir.core.contract import Signal
from .naming import SERVER_ROLES

IDM = SERVER_ROLES[0]
HEAP = "heap memory the JVM uses"

SIGNALS = (
    Signal("heap-used", IDM, 'idm_jvm_memory_usage_used{location="heap"}', "bytes", HEAP, ">=8"),
    Signal("heap-used", IDM, "idm_jvm_memory_usage_heap_used", "bytes", HEAP, "<8"),)

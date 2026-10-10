"""The neutral signals PingDS servers expose at their Prometheus endpoint (/metrics/prometheus/0.0.4 on the HTTP
connection handler, served to a monitor-privileged account), as the PingDS 8 monitoring guide names the metrics
(docs.pingidentity.com/pingds/8/monitoring-guide/monitoring-metrics-prometheus.html). One value per server (instance);
counters as a per-second rate over 5 minutes."""
from opsdir.core.contract import Signal
from opsdir.domains.directory.naming import DIRECTORY_SERVER_ROLE as DS

SIGNALS = (
    Signal("replication-delay", DS,
           "max by (instance) (ds_replication_replica_remote_replicas_receive_delay_seconds)", "s",
           "the longest current delay receiving replicated operations from a remote replica"),
    Signal("disk-free", DS, "min by (instance) (ds_disk_free_space_bytes)", "bytes",
           "the least free space on the disks holding the server's data"),
    Signal("heap-used", DS, "ds_jvm_memory_heap_used_bytes", "bytes", "heap memory the JVM uses"),
    Signal("ldap-errors", DS,
           "sum by (instance) (rate(ds_connection_handlers_ldap_requests_failure_seconds_count[5m]))", "/s",
           "LDAP requests failing per second (every LDAP connection handler, LDAPS included)"))

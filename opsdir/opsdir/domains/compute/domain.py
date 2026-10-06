"""Compute domain: what the platform's servers and containers run beyond its products. Host baselines per server role
(OS, Java runtime and truststore additions, limits, kernel settings, agents, service units), the compute groups and
managed clusters each environment runs them on, and workloads: server roles run as containers. Vendor-neutral: hosts'
and clouds' adapters and the Kubernetes package read their own sources into these entries."""
from ...core.contract import Domain, ImportKind, directory_report
from .hosts import BASELINE_HEADERS, COMPUTE_HEADERS, baseline_rows, check_hosts, compute_rows
from .schema import FRAGMENT
from .workloads import WORKLOAD_HEADERS, check_workloads, workload_rows

DOMAIN = Domain(name="compute", schema=FRAGMENT, required_roles=(), sql=(),
                reports={"baselines": directory_report(BASELINE_HEADERS, baseline_rows),
                         "compute": directory_report(COMPUTE_HEADERS, compute_rows),
                         "workloads": directory_report(WORKLOAD_HEADERS, workload_rows)},
                checks=(check_hosts, check_workloads), order=58, vocabulary={},
                import_kinds=(ImportKind("compute", "ciamComputeGroup", ("ciamTargetRole",)),
                              ImportKind("cluster", "ciamCluster")))

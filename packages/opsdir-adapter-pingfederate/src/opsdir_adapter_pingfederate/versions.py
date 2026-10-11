"""PingFederate versions: which one an environment runs (what its renders follow), and what changes between releases
(contract.VersionChange; milestone 86, from the vendor's release notes, research 2403): what the record holds that each
change touches, so the planner names it when a move upgrades PingFederate. Pure."""
from opsdir.core.contract import VersionChange
from opsdir.core.directory import children, one
from opsdir.core.versions import holds
from opsdir.domains.compute.workloads import role_versions
from .naming import DATA_STORES, SERVER_ROLES


def pingfederate_version(m):
    """(the PingFederate version environment m runs, the first by server or workload name, or None; the other
    versions it runs). Its servers' and, on Kubernetes, its workload bindings' (compute.role_versions)."""
    versions = tuple(dict.fromkeys(v for _, v in role_versions(m, SERVER_ROLES)))
    return (versions[0], versions[1:]) if versions else (None, ())


def runs_in(m, versions):
    """Whether the PingFederate version environment m runs (pingfederate_version; none recorded: the newest release)
    is in a PEP 440 range: what a render for some versions only (13.1's client authentication) asks."""
    version, _ = pingfederate_version(m)
    return holds(versions, (version,) if version else ())


def jdbc_stores(d, m, role):
    """The record's JDBC data stores (the Admin API validates their driver and URL from 13.1.3)."""
    return tuple(one(s, "cn") for s in children(d, DATA_STORES, "pingfedDataStore")
                 if (one(s, "pingfedStoreType") or "").upper() == "JDBC") if role in SERVER_ROLES else ()


VERSION_CHANGES = (
    VersionChange(">=12.2", "the cluster's JGroups thread pool is set in run.properties "
                  "(pf.cluster.thread.pool.max.threads)", "clustered nodes", "info", "Nothing to carry over: the "
                  "render writes run.properties for the target's version; tune the pool there if needed."),
    VersionChange(">=13.0", "the Admin API's request schemas change with the release", "every Admin API request the "
                  "render writes", "info", "The render checks each request against the spec of the target's "
                  "version; requests it rejects are named before the cutover."),
    VersionChange(">=13.1", "runtime-request.log replaces request.log", "log collection", "info", "The log sources "
                  "follow the target's version; move outside log readers too."),
    VersionChange(">=13.1.3", "the Admin API validates JDBC data stores' driver class and URL", "JDBC data stores",
                  "action", "Check each store's driver and URL against the drivers 13.1.3 allows before the "
                  "cutover: the Admin API rejects the others.", jdbc_stores),
)

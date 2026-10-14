"""Product logs to Cloud Logging buckets: the Ops Agent's configuration per role and install root (a files receiver per
file, JSON parsed), per route a sink taking its receivers' log names (and kinds) and its containers' entries on GKE
(cluster, namespaces, pod label, container, kinds), with an exclusion from _Default; the kept-line clauses as Cloud
Logging queries; what can't ship, or ships differently, named."""
import yaml

from opsdir.connectors.registry import services
from opsdir.core.contract import LogSource
from opsdir.core.interchange.ldif import LdifRecord
from opsdir.domains.compute.naming import WORKLOADS, workload_dn
from opsdir.domains.observability.naming import LOG_ROUTES
from opsdir.domains.observability.sources import kept_clauses
from opsdir_format_terraform.hcl import as_text
from opsdir_adapter_gcp.account import regime
from opsdir_adapter_gcp.log_sinks import log_sink_notes, render_log_sinks, route_filters
from opsdir_adapter_gcp.logging_filter import NOTHING, field_of, kept, literal, prefix_pattern
from opsdir_adapter_gcp.ops_agent import CONFIG, RELOAD, host_files, receiver_id
from network_fixtures import ALPHA, entry, model

BUCKET = "projects/{}/locations/global/buckets/{}"
GKE = "projects/{}/locations/us-east4/clusters/gke-ciam"
CLOUD = "cloud=alpha,ou=environments,dc=ciam-ops"
ACCESS_JSON = LogSource("ds", "servers", "logs/ldap-access.audit.json", "json-lines", "access")
AUDIT_JSON = LogSource("ds", "servers", "var/audit/*.json", "json-lines", "audit",
                       (("eventName", "AM-ACCESS", "access"),))
ERRORS = LogSource("ds", "servers", "logs/errors", "text", "error", line_start=r"^\[")
AM = LogSource("am", "kubernetes", None, "mixed", "debug",
               (("eventName", "AM-ACCESS", "access"), ("eventName", "", "audit")))
TAIL = LogSource("am", "kubernetes", None, "text", "audit", container="audit-tail")
SOURCES = (ACCESS_JSON, AUDIT_JSON, ERRORS, AM, TAIL)
OU = "dn: {}\nobjectClass: top\nobjectClass: organizationalUnit\nou: {}\n"


def _route(cn, kinds, roles, dest):
    return (f"dn: cn={cn},{LOG_ROUTES}\nobjectClass: top\nobjectClass: ciamObject\nobjectClass: ciamLogRoute\n"
            f"cn: {cn}\n" + "".join(f"ciamLogKind: {k}\n" for k in kinds)
            + "".join(f"ciamPublishedBy: {r}\n" for r in roles) + f"ciamLogDestinationRole: {dest}\n")


TREE = (OU.format(WORKLOADS, "workloads"),
        f"dn: {workload_dn('am')}\nobjectClass: top\nobjectClass: ciamWorkload\ncn: am\nciamWorkloadKind: deployment\n"
        "ciamTargetRole: am\nciamNamespace: ciam\nciamClusterRole: k8s\nciamWorkloadRole: am-workload\n",
        OU.format(LOG_ROUTES, "log-routes"), _route("access-logs", ("access",), ("ds", "am"), "ops-logs"),
        _route("audit-logs", ("audit",), ("am",), "audit-logs"), _route("errors", ("error",), ("ds",), "siem"))


def _bindings(cluster_project="proj-a"):
    return (entry(ALPHA, "am", "ciamWorkloadBinding", ciamBindingRole="am-workload",
                  ciamContainerImage="openam=registry.example.test/am:7.5.1"),
            entry(ALPHA, "gke", "ciamCluster", ciamBindingRole="k8s", ciamProviderRef=GKE.format(cluster_project)),
            entry(ALPHA, "ops", "ciamLogDestination", ciamBindingRole="ops-logs", ciamDestinationKind="log-group",
                  ciamProviderRef=BUCKET.format("proj-a", "ciam-ops")),
            entry(ALPHA, "audit", "ciamLogDestination", ciamBindingRole="audit-logs", ciamDestinationKind="log-group",
                  ciamProviderRef=BUCKET.format("proj-logs", "ciam-audit")),
            entry(ALPHA, "siem", "ciamLogDestination", ciamBindingRole="siem", ciamDestinationKind="siem-index",
                  ciamProviderRef="splunk://ciam"))


def _alpha(cluster_project="proj-a", levels=()):
    changes = (LdifRecord(CLOUD, "modify", {}, (("add", "ciamAccountRef", ("proj-a",)),)),
               *(LdifRecord(f"cn={s},{ALPHA}", "modify", {}, (("add", "ciamInstallRoot", (r,)),))
                 for s, r in (("ds-1", "/opt/ds"), ("ds-2", "/srv/ds"))),
               *((LdifRecord(ALPHA, "modify", {}, (("add", "ciamRequiredAuthorization", levels),)),) if levels else ()))
    _, alpha, _ = model(alpha=_bindings(cluster_project), tree=TREE, changes=changes)
    return alpha


def _services():
    return services()._replace(logs=lambda m: SOURCES)


def test_clauses_become_logging_queries():
    field, event = field_of("jsonPayload"), "jsonPayload.eventName"
    assert kept(kept_clauses(AM, ("access",)), field) == f'{event} =~ "^AM-ACCESS"'
    assert kept(kept_clauses(AM, ("audit",)), field) == f'{event}:* AND NOT ({event} =~ "^AM-ACCESS")'
    assert kept(kept_clauses(AM, ("access", "debug")), field) == f'({event} =~ "^AM-ACCESS") OR (NOT ({event}:*))'
    assert kept(kept_clauses(AM, ("access", "audit", "debug")), field) is None        # every line
    assert kept(kept_clauses(AM, ("error",)), field) == NOTHING
    assert field("audit-topic") == 'jsonPayload."audit-topic"'
    assert prefix_pattern("a.b(c") == "^a\\.b\\(c" and literal('a"b\\c') == '"a\\"b\\\\c"'


def test_an_ops_agent_configuration_per_role_and_install_root():
    files = host_files(_alpha(), _services())
    assert [(f.server_role, f.path, f.reload, f.hosts) for f in files] == [
        ("ds", CONFIG, RELOAD, ("ds-1",)), ("ds", CONFIG, RELOAD, ("ds-2",))]
    logging = yaml.safe_load(files[0].text)["logging"]
    assert logging["receivers"] == {
        "ciam_ds_logs_ldap_access_audit_json": {"type": "files",
                                                "include_paths": ["/opt/ds/logs/ldap-access.audit.json"],
                                                "record_log_file_path": True},
        "ciam_ds_var_audit_json": {"type": "files", "include_paths": ["/opt/ds/var/audit/*.json"],
                                   "record_log_file_path": True}}           # errors go to the SIEM: not here
    assert logging["processors"] == {"ciam_parse_json": {"type": "parse_json"}}
    assert logging["service"]["pipelines"]["ciam_ds_var_audit_json"] == {
        "receivers": ["ciam_ds_var_audit_json"], "processors": ["ciam_parse_json"]}
    assert "/srv/ds/logs/ldap-access.audit.json" in files[1].text
    assert receiver_id(type("X", (), {"role": "pf-engine", "source": ERRORS})) == "ciam_pf_engine_logs_errors"


def test_a_sink_and_an_exclusion_per_route_from_servers_and_containers():
    found = {r.dn.split(",")[0]: (dest, q) for r, dest, q in route_filters(_alpha(), _services())}
    assert set(found) == {"cn=access-logs", "cn=audit-logs"}                  # the SIEM route: no bucket
    access = found["cn=access-logs"][1]
    assert 'logName =~ "/logs/ciam_ds_logs_ldap_access_audit_json$"' in access           # all its lines
    assert '(logName =~ "/logs/ciam_ds_var_audit_json$" AND jsonPayload.eventName =~ "^AM-ACCESS")' in access
    assert ('resource.type = "k8s_container" AND resource.labels.cluster_name = "gke-ciam" AND '
            'resource.labels.location = "us-east4" AND resource.labels.namespace_name = "ciam"') in access
    assert ('(labels."k8s-pod/opsdir.io/role" = "am") OR (labels."k8s-pod/opsdir_io/role" = "am")') in access
    assert 'resource.labels.container_name != "audit-tail"' in access      # the main source: not the sidecar's
    audit = found["cn=audit-logs"][1]
    assert 'resource.labels.container_name = "audit-tail"' in audit         # the sidecar: all its lines
    hcl = "\n".join(as_text(render_log_sinks(_alpha(), _services())))
    assert hcl.count('resource "google_logging_project_sink"') == 2
    assert hcl.count('resource "google_logging_project_exclusion"') == 2
    assert 'name                   = "ciam-prod-access-logs"' in hcl
    assert 'destination            = "logging.googleapis.com/projects/proj-a/locations/global/buckets/ciam-ops"' in hcl
    assert "unique_writer_identity = true" in hcl


def _comments(notes):
    """The comments render_files writes for notes (flow 43)."""
    from opsdir.core.notes import note_comment
    return tuple(f"# {note_comment(n)}" for n in notes)


def test_what_isnt_shipped_or_ships_differently_is_named():
    found = log_sink_notes(_alpha(), _services())
    notes = _comments(found)
    assert {n.subject: n.severity for n in found if n.subject in ("Ops Agent configuration", "GKE clusters gke")} == {
        "Ops Agent configuration": "action", "GKE clusters gke": "note"}
    assert "# NOTE: log route errors: role ds's logs not shipped: its destination siem isn't a Cloud Logging " \
           "bucket (projects/<p>/locations/<l>/buckets/<b>)" in notes
    assert any(n.startswith("# NOTE: Ops Agent configuration: opsdir renders it for configuration management to "
                            "place") for n in notes)
    assert any("ships logs to ops-logs, but no workload principal" in n for n in notes)
    assert any(n.startswith("# NOTE: GKE clusters gke: their workload logging") for n in notes)
    assert ("# NOTE: log route audit-logs: bucket audit is in project proj-logs: grant the sink's writer identity "
            "roles/logging.bucketWriter there") in notes
    assert not any("Assured Workloads" in n for n in notes)
    elsewhere = _comments(log_sink_notes(_alpha(cluster_project="proj-b"), _services()))
    assert any("in cluster gke not shipped: the cluster is in project proj-b" in n for n in elsewhere)
    assert all(r.dn.split(",")[0] != "cn=audit-logs" for r, _, _ in route_filters(_alpha("proj-b"), _services()))


def test_an_assured_workloads_regime_is_named_with_what_to_confirm():
    alpha = _alpha(levels=("fedramp-high", "dod-il4"))
    assert regime(alpha) == "IL4"
    notes = _comments(log_sink_notes(alpha, _services()))
    assert any(n.startswith("# NOTE: Assured Workloads (IL4): Cloud Logging, Compute Engine and GKE are supported "
                            "products; the Ops Agent isn't listed") for n in notes)

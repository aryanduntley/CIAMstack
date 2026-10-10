"""Product logs from an environment's servers to CloudWatch: one agent configuration per server role and install root
(the files each route takes whole, to the log group its destination is), loaded with append-config beside the
baseline's; the FIPS endpoint when the cloud uses them; what can't be shipped, or only in part, named in main.tf."""
import json

from opsdir.connectors.registry import services
from opsdir.core.contract import LogSource
from opsdir.core.interchange.ldif import LdifRecord
from opsdir.domains.access.naming import PERMISSION_SETS, PRINCIPALS
from opsdir.domains.observability.naming import LOG_ROUTES
from opsdir_adapter_aws.log_agent import CONFIG, RELOAD, host_files, log_notes
from network_fixtures import ALPHA, entry, model

SOURCES = (LogSource("ds", "servers", "logs/ldap-access.audit.json", "json-lines", "access"),
           LogSource("ds", "servers", "logs/errors", "text", "error", line_start=r"^\["),
           LogSource("ds", "servers", "audit/*.json", "json-lines", "audit", (("eventName", "DJ-", "access"),)),
           LogSource("web", "servers", "log/web.log", "text", "access"))
OU = "dn: {}\nobjectClass: top\nobjectClass: organizationalUnit\nou: {}\n"


def _route(cn, kinds, roles, dest):
    return (f"dn: cn={cn},{LOG_ROUTES}\nobjectClass: top\nobjectClass: ciamObject\nobjectClass: ciamLogRoute\n"
            f"cn: {cn}\n" + "".join(f"ciamLogKind: {k}\n" for k in kinds)
            + "".join(f"ciamPublishedBy: {r}\n" for r in roles) + f"ciamLogDestinationRole: {dest}\n")


TREE = (OU.format(LOG_ROUTES, "log-routes"),
        _route("access-logs", ("access",), ("ds", "web"), "ops-logs"),
        _route("errors", ("error",), ("ds",), "audit-logs"),
        _route("to-siem", ("error",), ("ds",), "siem"),
        OU.format(PERMISSION_SETS, "permission-sets"), OU.format(PRINCIPALS, "principals"),
        f"dn: cn=ds-runtime,{PERMISSION_SETS}\nobjectClass: top\nobjectClass: ciamObject\n"
        "objectClass: ciamPermissionSet\ncn: ds-runtime\nciamPermits: write-logs ops-logs\n"
        "ciamPermits: write-logs audit-logs\n",
        f"dn: cn=pingds,{PRINCIPALS}\nobjectClass: top\nobjectClass: ciamObject\nobjectClass: ciamPrincipal\n"
        f"cn: pingds\nciamPrincipalKind: workload\nciamIdentityRole: identity-ds\nciamTargetRole: ds\n"
        f"ciamHoldsSet: cn=ds-runtime,{PERMISSION_SETS}\n")
GROUPS = (entry(ALPHA, "audit", "ciamLogDestination", ciamBindingRole="audit-logs", ciamDestinationKind="log-group",
                ciamProviderRef="arn:aws:logs:region-1:111122223333:log-group:/ciam/audit"),
          entry(ALPHA, "ops", "ciamLogDestination", ciamBindingRole="ops-logs", ciamDestinationKind="log-group",
                ciamProviderRef="arn:aws:logs:region-1:111122223333:log-group:/ciam/ops:*"),
          entry(ALPHA, "siem", "ciamLogDestination", ciamBindingRole="siem", ciamDestinationKind="siem-index",
                ciamProviderRef="splunk://ciam"))


def _root(server, root):
    return LdifRecord(f"cn={server},{ALPHA}", "modify", {}, (("add", "ciamInstallRoot", (root,)),))


def _alpha(*extra):
    _, alpha, _ = model(alpha=GROUPS, tree=TREE, changes=(_root("ds-1", "/opt/ds"), _root("ds-2", "/srv/ds"),
                                                          _root("web-1", "/opt/web"), *extra))
    return alpha


def _services():
    return services()._replace(logs=lambda m: SOURCES)


def test_one_agent_configuration_per_role_and_install_root():
    files = host_files(_alpha(), _services())
    assert [(f.server_role, f.path, f.hosts, f.reload) for f in files] == [
        ("ds", CONFIG, ("ds-1",), RELOAD), ("ds", CONFIG, ("ds-2",), RELOAD), ("web", CONFIG, ("web-1",), RELOAD)]
    assert RELOAD[1:3] == ("-a", "append-config")             # beside the baseline's configuration, never replacing it
    assert json.loads(files[0].text) == {"logs": {"logs_collected": {"files": {"collect_list": [
        {"file_path": "/opt/ds/logs/ldap-access.audit.json", "log_group_name": "/ciam/ops",
         "log_stream_name": "{instance_id}/logs/ldap-access.audit.json"},
        {"file_path": "/opt/ds/logs/errors", "log_group_name": "/ciam/audit",
         "log_stream_name": "{instance_id}/logs/errors", "multi_line_start_pattern": r"^\["}]}}}}
    assert json.loads(files[1].text)["logs"]["logs_collected"]["files"]["collect_list"][0]["file_path"] == (
        "/srv/ds/logs/ldap-access.audit.json")


def test_the_fips_endpoint_when_the_cloud_uses_them():
    fips = LdifRecord("cloud=alpha,ou=environments,dc=ciam-ops", "modify", {},
                      (("add", "objectClass", ("ciamCloudEndpoints",)), ("add", "ciamFipsEndpoints", ("TRUE",))))
    (first, *_) = host_files(_alpha(fips), _services())
    assert json.loads(first.text)["logs"]["endpoint_override"] == "https://logs-fips.region-1.amazonaws.com"


def test_what_isnt_shipped_or_only_in_part_is_named():
    assert log_notes(_alpha(), _services()) == (
        "# NOTE: log route access-logs: /opt/ds/audit/*.json on ds-1 not shipped: the route takes only some of its "
        "lines, and the CloudWatch agent can't tell them apart by their JSON fields",
        "# NOTE: log route access-logs: /srv/ds/audit/*.json on ds-2 not shipped: the route takes only some of its "
        "lines, and the CloudWatch agent can't tell them apart by their JSON fields",
        "# NOTE: log route to-siem: /opt/ds/logs/errors on ds-1 not shipped: its destination siem isn't a CloudWatch "
        "log group (kind log-group, a log group ARN)",
        "# NOTE: log route to-siem: /srv/ds/logs/errors on ds-2 not shipped: its destination siem isn't a CloudWatch "
        "log group (kind log-group, a log group ARN)",
        "# NOTE: role web ships logs to ops-logs, but no workload principal acting for it holds the permit "
        "`write-logs ops-logs`: its servers' instance role isn't granted the writes")


def test_a_glob_ships_only_the_newest_file_it_matches():
    globbed = (LogSource("web", "servers", "log/*.log", "text", "access"),)
    alpha = _alpha()
    (agent,) = host_files(alpha, services()._replace(logs=lambda m: globbed))
    assert json.loads(agent.text)["logs"]["logs_collected"]["files"]["collect_list"][0]["log_stream_name"] == (
        "{instance_id}/log/_.log")
    assert log_notes(alpha, services()._replace(logs=lambda m: globbed))[0] == (
        "# NOTE: log route access-logs: /opt/web/log/*.log on web-1: the CloudWatch agent ships only the most "
        "recently modified file the glob matches")

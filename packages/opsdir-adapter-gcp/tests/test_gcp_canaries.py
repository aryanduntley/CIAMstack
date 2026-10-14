"""Cloud Monitoring uptime checks rendered from the record: an HTTPS GET of the health page on the host's uptime_url
in the root's project, named as the canary binding; none for an internal service (its check is a synthetic monitor,
decision 2859: no private uptime check, no Service Directory, no checkers' firewall rule); none in an Assured
Workloads workload."""
from opsdir.core.contract import Endpoint
from opsdir.core.interchange.ldif import LdifRecord
from opsdir.domains.observability.naming import CANARIES
from opsdir_format_terraform.hcl import as_text
from opsdir_adapter_gcp.canaries import render_checks
from network_fixtures import BETA, entry, model

ENDPOINTS = (Endpoint("health", "/pf/heartbeat.ping", "web"),)


def _canary(cn, **attrs):
    return entry(CANARIES, cn, "ciamCanary", **attrs).replace("objectClass: ciamCanary",
                                                               "objectClass: ciamObject\nobjectClass: ciamCanary")


TREE = (f"dn: {CANARIES}\nobjectClass: top\nobjectClass: organizationalUnit\nou: canaries\n",
        _canary("sso-alive", ciamCheckedService="sso", ciamCanaryFlow="health", ciamInterval="5m"),
        _canary("admin-alive", ciamCheckedService="admin", ciamCanaryFlow="health"))
BINDINGS = (entry(BETA, "svc-sso", "ciamServiceName", ciamBindingRole="sso", ciamFqdn="sso.example.test",
                  ciamPort="8443", ciamTargetRole="web", ciamExposure="internet"),
            entry(BETA, "svc-admin", "ciamServiceName", ciamBindingRole="admin", ciamFqdn="admin.example.test",
                  ciamTargetRole="web", ciamExposure="internal"))


def test_a_health_check_is_an_https_uptime_check_of_its_host():
    _, _, beta = model(beta=BINDINGS, tree=TREE)
    out = as_text(render_checks(beta, ENDPOINTS))
    text = "\n".join(out)
    assert 'resource "google_monitoring_uptime_check_config" "sso_alive" {' in text
    assert 'period       = "300s"' in text and 'path           = "/pf/heartbeat.ping"' in text
    assert "port           = 8443" in text and "use_ssl        = true" in text
    assert 'host       = "sso.example.test"' in text and "project_id = var.project_id" in text
    assert 'realizes    = "sso-alive"' in text and 'bindingrole = "canary-sso-alive"' in text
    assert not [x for x in out if x.startswith("#")] and "admin" not in text        # a synthetic monitor's


PRIVATE = (BINDINGS[0],
           BINDINGS[1].replace("ciamExposure: internal", "ciamExposure: internal\nciamFrontendIp: 10.1.2.50"),
           entry(BETA, "admin-check", "ciamCanaryBinding", ciamBindingRole="canary-admin-alive",
                 ciamRealizes="admin-alive"))


def test_an_internal_service_gets_no_private_uptime_check():
    _, _, beta = model(beta=PRIVATE, tree=TREE)
    text = "\n".join(as_text(render_checks(beta, ENDPOINTS)))
    assert text.count('resource "google_monitoring_uptime_check_config"') == 1      # the public one only
    for absent in ("admin", "VPC_CHECKERS", "service_directory", "servicedirectory", "35.199.192.0/19", "Host"):
        assert absent not in text


def test_no_uptime_check_in_an_assured_workloads_workload():
    held = LdifRecord(BETA, "modify", {}, (("add", "objectClass", ("ciamEnvironmentPlacement",)),
                                           ("replace", "ciamRequiredAuthorization", ("fedramp-high",))))
    _, _, beta = model(beta=PRIVATE, tree=TREE, changes=(held,))
    out = as_text(render_checks(beta, ENDPOINTS))
    assert all(x.startswith("# NOTE: canary sso-alive") for x in out) and len(out) == 1     # admin-alive: monitors'
    assert "an Assured Workloads workload (FEDRAMP_HIGH), where Google supports neither uptime checks" in out[0]


def test_the_checkers_firewall_rule_isnt_read_as_one_of_the_records():
    from opsdir_adapter_gcp.health_checks import is_probe_rule
    assert is_probe_rule(["35.199.192.0/19"]) and not is_probe_rule(["35.199.192.0/19", "10.0.0.0/8"])


def test_an_assured_workloads_note_says_what_to_do_instead():
    from opsdir_adapter_gcp.canaries import uptime_notes
    held = LdifRecord(BETA, "modify", {}, (("add", "objectClass", ("ciamEnvironmentPlacement",)),
                                           ("replace", "ciamRequiredAuthorization", ("fedramp-high",))))
    _, _, beta = model(beta=PRIVATE, tree=TREE, changes=(held,))
    (n,) = uptime_notes(beta, ENDPOINTS)
    assert n.subject == "canary sso-alive"
    assert n.text.startswith("not rendered: the environment is an Assured Workloads")
    assert len(n.how) == 3 and n.how[0].startswith("Run the same check from inside the boundary")
    assert "authorizing official" in n.how[2]

"""Cloud Monitoring uptime checks rendered from the record: an HTTPS GET of the health page on the host's uptime_url
in the root's project, named as the canary binding; an internal service is named."""
from opsdir.core.contract import Endpoint
from opsdir.domains.observability.naming import CANARIES
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
    out = render_checks(beta, ENDPOINTS)
    text = "\n".join(out)
    assert 'resource "google_monitoring_uptime_check_config" "sso_alive" {' in text
    assert 'period       = "300s"' in text and 'path           = "/pf/heartbeat.ping"' in text
    assert "port           = 8443" in text and "use_ssl        = true" in text
    assert 'host       = "sso.example.test"' in text and "project_id = var.project_id" in text
    assert 'realizes    = "sso-alive"' in text and 'bindingrole = "canary-sso-alive"' in text
    assert [x for x in out if x.startswith("#")] == [
        "# NOTE: canary admin-alive: not rendered: service name svc-admin isn't recorded as internet-facing: uptime "
        "checks reach public endpoints"]

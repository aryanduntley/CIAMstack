"""Cloud Monitoring uptime checks rendered from the record: an HTTPS GET of the health page on the host's uptime_url
in the root's project, named as the canary binding; an internal service's as a private uptime check of a Service
Directory service at its frontend address (the agent's grants, the checkers' firewall rule), named when it has none;
none in an Assured Workloads workload."""
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
    assert [x for x in out if x.startswith("#")] == [
        "# NOTE: canary admin-alive: not rendered: service name svc-admin is internal and records no frontend address "
        "(ciamFrontendIp) for its private uptime check's Service Directory endpoint"]


PRIVATE = (BINDINGS[0],
           BINDINGS[1].replace("ciamExposure: internal", "ciamExposure: internal\nciamFrontendIp: 10.1.2.50"),
           entry(BETA, "admin-check", "ciamCanaryBinding", ciamBindingRole="canary-admin-alive",
                 ciamRealizes="admin-alive"))


def test_an_internal_service_gets_a_private_uptime_check_through_service_directory():
    _, _, beta = model(beta=PRIVATE, tree=TREE)
    text = "\n".join(as_text(render_checks(beta, ENDPOINTS)))
    assert ('resource "google_service_directory_endpoint" "admin_check" {\n  endpoint_id = "frontend"\n'
            '  service     = google_service_directory_service.admin_check.id\n  address     = "10.1.2.50"\n'
            '  port        = 443\n'
            '  network     = "projects/${data.google_project.checks_network.number}/locations/global/networks/'
            '${data.google_compute_network.main.name}"') in text
    assert 'checker_type = "VPC_CHECKERS"' in text and "validate_ssl   = false" in text
    assert 'Host = "admin.example.test"' in text and 'type = "servicedirectory_service"' in text
    assert "service_name   = google_service_directory_service.admin_check.service_id" in text
    assert "# admin-check: Google's private uptime checkers don't validate TLS certificates" in text
    assert 'namespace_id = "ciam-prod-checks"' in text
    assert ('  role    = "roles/servicedirectory.pscAuthorizedService"\n  member  = "serviceAccount:service-'
            '${data.google_project.checks.number}@gcp-sa-monitoring-notification.iam.gserviceaccount.com"') in text
    assert ('resource "google_compute_firewall" "svc_admin_uptime_checkers" {' in text
            and 'source_ranges = ["35.199.192.0/19"]' in text and 'target_tags   = ["ciam-prod-web"]' in text)
    assert text.count('resource "google_monitoring_uptime_check_config"') == 2      # the public one too


def test_no_uptime_check_in_an_assured_workloads_workload():
    held = LdifRecord(BETA, "modify", {}, (("add", "objectClass", ("ciamEnvironmentPlacement",)),
                                           ("replace", "ciamRequiredAuthorization", ("fedramp-high",))))
    _, _, beta = model(beta=PRIVATE, tree=TREE, changes=(held,))
    out = as_text(render_checks(beta, ENDPOINTS))
    assert all(x.startswith("# NOTE: canary ") for x in out) and len(out) == 2
    assert "an Assured Workloads workload (FEDRAMP_HIGH), where Google supports neither uptime checks" in out[0]


def test_the_checkers_firewall_rule_isnt_read_as_one_of_the_records():
    from opsdir_adapter_gcp.health_checks import is_probe_rule
    assert is_probe_rule(["35.199.192.0/19"]) and not is_probe_rule(["35.199.192.0/19", "10.0.0.0/8"])

"""The network depth the stack keeps as Google Cloud Terraform: the policy firewall model (network firewall policy and
association, a GCE_FIREWALL tag key and a value per role bound to each instance, the record's rules and the probe rules
by secure tag), a PSC endpoint for Google's APIs, service attachments on internal passthrough forwarding rules, an
egress firewall's allowlist as policy egress rules ending in a deny; comments otherwise."""
import pytest

import mini_estate
from opsdir_adapter_gcp import edge, terraform
from opsdir_adapter_gcp.firewall_policy import health_check_rule, policy_firewall
from opsdir_adapter_gcp.health_checks import probe_ranges
from opsdir_adapter_gcp.network import psc_name, render_network
from network_fixtures import ALPHA, entry, model

NETWORK = "ciamBindingRole: network\n"
TERMINATE = ("dn: ou=edge-policies,dc=ciam-ops\nobjectClass: top\nobjectClass: organizationalUnit\nou: edge-policies\n",
             entry("ou=edge-policies,dc=ciam-ops", "sso-edge", "ciamTrafficPolicy", ciamServiceRole="sso-service",
                   ciamTlsMode="terminate"))
RULE = entry(ALPHA, "fw-ds", "ciamFirewallRule", ciamBindingRole="fw-ds", ciamSourceCidr="10.1.2.0/24",
             ciamPort="1636", ciamTargetRole="ds", ciamRulePriority="100")
POLICY = entry(ALPHA, "policy", "ciamFirewallPolicy", ciamBindingRole="firewall-policy", ciamPolicyScope="network",
               ciamPolicyOrder="policy-first")
FIREWALL = entry(ALPHA, "egress-fw", "ciamProxy", ciamBindingRole="egress-firewall", ciamProxyKind="firewall",
                 ciamAllowedDestination=("idp.partner.example", "*.okta.example", "ocsp.ca.example:80"))


@pytest.fixture
def network(monkeypatch):
    """Sets attributes on the mini estate's networks (the Shared VPC host's network, the firewall model)."""
    def _set(**attrs):
        lines = "".join(f"{k}: {v}\n" for k, v in attrs.items())
        monkeypatch.setattr(mini_estate, "LDIF", mini_estate.LDIF.replace(NETWORK, NETWORK + lines))
    return _set


def _m(*records, tree=()):
    return model(alpha=records, tree=tree)[1]


def _render(*records, tree=()):
    return "\n\n".join(render_network(_m(*records, tree=tree)))


def test_nothing_recorded_renders_nothing():
    assert render_network(_m()) == ()


def test_the_policy_model_targets_secure_tags_in_the_networks_project(network):
    network(ciamProviderRef="projects/host-net/global/networks/ciam", ciamFirewallModel="policy")
    m = _m(RULE, POLICY)
    out = "\n\n".join(terraform._firewall(m))
    assert out == "\n\n".join(policy_firewall(m))
    assert "network_firewall_policy_enforcement_order = BEFORE_CLASSIC_FIREWALL" in out
    assert "# The network's project is host-net: the policy, its rules and the tag key live there" in out
    assert "roles/resourcemanager.tagUser" in out
    assert 'resource "google_compute_network_firewall_policy" "network_policy"' in out
    assert 'name        = "ciam-prod-policy"' in out and 'project     = "host-net"' in out
    assert "attachment_target = data.google_compute_network.main.self_link" in out
    assert 'parent      = "projects/host-net"' in out and 'purpose     = "GCE_FIREWALL"' in out
    assert 'network = "host-net/ciam"' in out
    assert 'resource "google_tags_tag_value" "ds"' in out and 'resource "google_tags_tag_value" "web"' in out
    assert ('parent    = "//compute.googleapis.com/projects/${var.project_id}/zones/zone-a/instances/'
            '${google_compute_instance.ds_1.instance_id}"') in out and 'location  = "zone-a"' in out
    assert 'resource "google_compute_network_firewall_policy_rule" "fw_ds"' in out
    assert "priority        = 100" in out and 'direction       = "INGRESS"' in out and 'rule_name       = "fw-ds"' in out
    assert 'src_ip_ranges = ["10.1.2.0/24"]' in out and 'ports       = ["1636"]' in out
    assert "name = google_tags_tag_value.ds.id" in out
    assert "google_compute_firewall" not in out


def test_the_rules_model_keeps_vpc_firewall_rules():
    out = "\n\n".join(terraform._firewall(_m(RULE, POLICY)))
    assert 'resource "google_compute_firewall" "fw_ds"' in out and "network_firewall_policy" not in out


def test_a_recorded_tag_key_and_a_policy_someone_else_keeps(network):
    network(ciamFirewallModel="policy")
    party = ("dn: ou=owners,dc=ciam-ops\nobjectClass: top\nobjectClass: organizationalUnit\nou: owners\n",
             "dn: cn=net-team,ou=owners,dc=ciam-ops\nobjectClass: top\nobjectClass: ciamParty\ncn: net-team\n"
             "ciamOwnerKind: team\n")
    m = _m(RULE, entry(ALPHA, "policy", "ciamFirewallPolicy", ciamBindingRole="firewall-policy",
                       ciamPolicyScope="network", ciamTagKeyRef="tagKeys/281", ciamProviderRef="ciam-shared",
                       ciamManagedBy="cn=net-team,ou=owners,dc=ciam-ops"),
           entry(ALPHA, "org", "ciamFirewallPolicy", ciamBindingRole="org-policy", ciamPolicyScope="hierarchical"),
           entry(ALPHA, "fw-org", "ciamFirewallRule", ciamBindingRole="fw-org", ciamSourceCidr="0.0.0.0/0",
                 ciamPort="22", ciamTargetRole="ds", ciamPolicyRole="org-policy"), tree=party)
    out = "\n\n".join(policy_firewall(m))
    assert "google_compute_network_firewall_policy\"" not in out and "google_tags_tag_key" not in out
    assert 'parent      = "tagKeys/281"' in out and 'firewall_policy = "ciam-shared"' in out
    assert "# fw-org belongs to the hierarchical policy 'org' (read, not rendered)" in out
    assert "# NOTE: fw-org" not in out and "fw_org" not in out


def test_the_probe_rule_follows_the_model(network):
    network(ciamFirewallModel="policy")
    m = _m()
    svc = next(b for b in m.bindings if b.dn.startswith("cn=svc-sso,"))
    out = terraform._health_check_rule(m, svc, "svc_sso", "ciam-prod-svc-sso", "INTERNAL", "443")
    assert out == health_check_rule(m, svc, "svc_sso", probe_ranges("INTERNAL"), "443")
    assert 'resource "google_compute_network_firewall_policy_rule" "svc_sso_health_checks"' in out
    assert "priority        = 70000" in out and "name = google_tags_tag_value.web.id" in out
    assert f'src_ip_ranges = {list(probe_ranges("INTERNAL"))}'.replace("'", '"') in out


def test_egress_sites_by_name_the_private_ranges_then_deny(network):
    network(ciamFirewallModel="policy")
    out = _render(FIREWALL)
    assert "# *.okta.example: a wildcard domain can't be an FQDN object; allow its hosts by name" in out
    assert 'resource "google_compute_network_firewall_policy_rule" "egress_fw_sites_80"' in out
    assert 'dest_fqdns = ["ocsp.ca.example"]' in out and 'dest_fqdns = ["idp.partner.example"]' in out
    assert "priority        = 80000" in out and "priority        = 80001" in out
    assert 'dest_ip_ranges = ["10.1.0.0/16"]' in out and 'ip_protocol = "all"' in out
    assert "priority        = 2147483000" in out and 'action          = "deny"' in out
    assert 'dest_ip_ranges = ["0.0.0.0/0"]' in out
    assert "name = google_tags_tag_value.ds.id" in out and "name = google_tags_tag_value.web.id" in out


def test_the_rules_model_has_no_fqdn_rules():
    out = _render(FIREWALL)
    assert "FQDN egress rules exist only in network firewall policies" in out
    assert "network_firewall_policy_rule" not in out


def test_a_psc_endpoint_for_googles_apis(network):
    network(ciamProviderRef="projects/host-net/global/networks/ciam")
    out = _render(entry(ALPHA, "psc-apis", "ciamPrivateEndpoint", ciamBindingRole="psc-apis", ciamPrivateService="apis",
                        ciamPrivateEndpointKind="all-apis", ciamFrontendIp="10.255.0.5", ciamPrivateDns="TRUE"))
    assert "# private DNS: the landing zone's private googleapis.com zone answers 10.255.0.5" in out
    assert 'purpose      = "PRIVATE_SERVICE_CONNECT"' in out and 'address      = "10.255.0.5"' in out
    assert 'name                  = "pscapis"' in out and 'target                = "all-apis"' in out
    assert "ip_address            = google_compute_global_address.psc_apis.id" in out
    assert 'project               = "host-net"' in out and 'load_balancing_scheme = ""' in out


def test_what_the_landing_zone_keeps_or_the_record_lacks_is_said():
    out = _render(entry(ALPHA, "pga", "ciamPrivateEndpoint", ciamBindingRole="pga", ciamPrivateService="apis",
                        ciamPrivateEndpointKind="subnet-access"),
                  entry(ALPHA, "sql", "ciamPrivateEndpoint", ciamBindingRole="sql", ciamPrivateService="database",
                        ciamPrivateEndpointKind="peered-service"),
                  entry(ALPHA, "psc", "ciamPrivateEndpoint", ciamBindingRole="psc", ciamPrivateService="apis"))
    assert "# Private endpoint 'pga' (subnet-access): Private Google Access is a subnet setting" in out
    assert "# Private endpoint 'sql' (peered-service): private services access" in out
    assert "# UNBOUND: private endpoint 'psc' to Google's APIs records no address (ciamFrontendIp)" in out


def test_psc_names_are_short_lowercase_alphanumerics():
    assert psc_name("psc-apis") == "pscapis" and psc_name("1-apis") == "p1apis"
    assert psc_name("private-google-apis-endpoint") == "privategoogleapisend"


def test_a_service_attachment_on_an_internal_passthrough_forwarding_rule():
    sso = entry(ALPHA, "svc-ldaps", "ciamServiceName", ciamBindingRole="ldaps-service", ciamFqdn="ldap.example.test",
                ciamPort="1636", ciamTargetRole="ds", ciamFrontendIp="10.1.1.100")
    attach = entry(ALPHA, "ldaps-link", "ciamEndpointService", ciamBindingRole="ldaps-link",
                   ciamServiceRole="ldaps-service", ciamSubnetRole="subnet-web", ciamAcceptanceRequired="TRUE",
                   ciamAllowedPrincipal=("projects/consumer-a", "projects/consumer-b/global/networks/vpc"))
    out = _render(sso, attach)
    assert 'connection_preference = "ACCEPT_MANUAL"' in out
    assert "target_service        = google_compute_forwarding_rule.svc_ldaps.id" in out
    assert "nat_subnets           = [data.google_compute_subnetwork.subnet_web.id]" in out
    assert 'project_id_or_num = "consumer-a"' in out
    assert 'network_url      = "projects/consumer-b/global/networks/vpc"' in out
    public = _render(entry(ALPHA, "ldaps-link", "ciamEndpointService", ciamBindingRole="ldaps-link",
                           ciamServiceRole="sso-service"))
    assert "isn't an internal passthrough load balancer" in public


def test_an_application_load_balancers_proxies_and_probes_are_policy_rules_when_admit_builds_them():
    m = _m()
    svc = next(b for b in m.bindings if b.dn.startswith("cn=svc-sso,"))
    out = "\n\n".join(edge._firewall(m, svc, "svc_sso", "ciam-prod-svc-sso", "443", "10.1.250.0/24", health_check_rule))
    assert 'resource "google_compute_network_firewall_policy_rule" "svc_sso_proxies"' in out
    assert "priority        = 75000" in out and 'src_ip_ranges = ["10.1.250.0/24"]' in out
    assert "Load balancer proxies for svc-sso" in out and "Google Cloud health checks for svc-sso" in out
    assert "google_compute_firewall" not in out
    assert 'resource "google_compute_firewall" "svc_sso_proxies"' in "\n\n".join(
        edge._firewall(m, svc, "svc_sso", "ciam-prod-svc-sso", "443", "10.1.250.0/24"))

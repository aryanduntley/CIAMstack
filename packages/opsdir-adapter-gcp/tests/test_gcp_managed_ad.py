"""Google Cloud's Managed Service for Microsoft AD as a managed directory (flow 76): the descriptor the planner reads
(Google's documented capabilities; in no Assured Workloads control package, so absent where a required level asks for
one), a target rendered as a domain in its regions with its reserved range and the environment's network authorized,
trusts and the rest actions; a neighbour a note. Read back from Terraform state."""
import json

from opsdir.connectors.managed_directory import managed_directory_check
from opsdir.core.contract import PlanContext
from opsdir.core.interchange.ldif import LdifRecord
from opsdir_format_terraform.hcl import as_text
from opsdir_adapter_gcp.adapter import ADAPTER
from opsdir_adapter_gcp.boundary import gcp_services
from opsdir_adapter_gcp.inventory import state_resources
from opsdir_adapter_gcp.managed_ad import (GOOGLE_MANAGED_AD, SERVICE, managed_ad_notes, managed_ad_resources,
                                           partition, render_managed_ad)
from network_fixtures import ALPHA, BETA, entry, model

GAD = dict(ciamBindingRole="user-dir", ciamManagedService=SERVICE, ciamRealizes="ds", ciamFqdn="corp.example.test",
           ciamRegion="us-central1", ciamReplicaRegion="us-east4", ciamCidr="10.250.0.0/24", ciamLdapsMode="private")
RECORDS = (entry(ALPHA, "user-dir", "ciamManagedDirectory", **GAD),
           entry(f"cn=user-dir,ou=bindings,{ALPHA}", "hq", "ciamDirectoryTrust", ciamFqdn="hq.example.test",
                 ciamTrustType="forest", ciamTrustDirection="two-way"))
NAME = "projects/ciam-prod/locations/global/domains/corp.example.test"


def _render(*records):
    return "\n\n".join(as_text(render_managed_ad(model(alpha=records)[1])))


def _required(env, *levels):
    return LdifRecord(env, "modify", {}, (("add", "objectClass", ("ciamEnvironmentPlacement",)),
                                          ("replace", "ciamRequiredAuthorization", levels)))


# ------------------------------------------------------------------ the descriptor
def test_the_adapter_declares_managed_ad_with_google_s_documented_capabilities():
    assert ADAPTER.managed_directory == (GOOGLE_MANAGED_AD,)
    assert ADAPTER.vocabulary["ciamManagedService"] == (SERVICE,)
    assert {"schema-extension", "password-policies", "ldaps", "multi-region", "trust:forest:two-way"} <= \
        set(GOOGLE_MANAGED_AD.supported)
    # external trusts: Google's guide excludes them while its API takes them: not established either way
    assert not {"trust:external:two-way", "ldaps-internet"} & {*GOOGLE_MANAGED_AD.supported,
                                                               *GOOGLE_MANAGED_AD.unsupported}
    assert GOOGLE_MANAGED_AD.limits["regions"][0] == 4 and GOOGLE_MANAGED_AD.limits["password-policies"][0] == 10
    assert set(GOOGLE_MANAGED_AD.absent) == {"assured:IL5", "assured:IL4", "assured:FEDRAMP_HIGH",
                                             "assured:FEDRAMP_MODERATE", "assured:IL2"}


def test_an_environment_needing_an_assured_workloads_package_is_its_partition():
    _, _, beta = model(changes=(_required(BETA, "fedramp-high"),))
    _, alpha, _ = model()
    assert (partition(beta), partition(alpha)) == ("assured:FEDRAMP_HIGH", "public")


def test_a_domain_is_managed_microsoft_ad_in_the_fedramp_boundary():
    assert ("Managed Service for Microsoft Active Directory", "user-dir") in gcp_services(model(alpha=RECORDS)[1])


# ------------------------------------------------------------------ render
def test_a_target_is_a_domain_in_its_regions_with_its_reserved_range():
    out = _render(*RECORDS)
    for line in ('resource "google_active_directory_domain" "user_dir"', 'domain_name         = "corp.example.test"',
                 'locations           = ["us-central1", "us-east4"]', 'reserved_ip_range   = "10.250.0.0/24"',
                 "authorized_networks = [data.google_compute_network.main.id]", "deletion_protection = true",
                 'realizes   = "ds"'):
        assert line in out, line
    assert "trust_handshake_secret" not in out and "google_active_directory_domain_trust" not in out


def test_what_isnt_rendered_is_an_action_and_a_neighbour_is_a_note():
    notes = {n.subject: n for n in managed_ad_notes(model(alpha=RECORDS)[1])}
    assert "its handshake secret is shared with the other forest" in notes["domain user-dir trust hq"].text
    assert "update-ldaps-settings" in notes["domain user-dir LDAPS"].how[0]
    neighbour = model(alpha=(entry(ALPHA, "corp-ad", "ciamManagedDirectory", ciamBindingRole="corp-ad",
                                   ciamManagedService=SERVICE),))[1]
    assert [x for x in render_managed_ad(neighbour) if x[0] != "#"] == []
    (n,) = managed_ad_notes(neighbour)
    assert (n.severity, n.subject) == ("note", "domain corp-ad") and "not rendered" in n.text


# ------------------------------------------------------------------ the planner
def test_the_planner_blocks_it_where_an_assured_workloads_package_is_required():
    check = managed_directory_check((ADAPTER,))
    target = entry(BETA, "user-dir", "ciamManagedDirectory", **GAD)
    d, alpha, beta = model(beta=(target,), changes=(_required(BETA, "fedramp-high"),))
    found = check(PlanContext(d, alpha, beta, None, None, {}, {}, ()))
    assert any("`user-dir` in beta/prod (assured:FEDRAMP_HIGH) is Managed Service for Microsoft Active Directory, "
               "which doesn't exist there (not among the Assured Workloads supported products of FEDRAMP_HIGH" in b[1]
               for b in found.blockers)
    d, alpha, beta = model(beta=(target,))
    assert not any("doesn't exist there" in b[1] for b in check(PlanContext(d, alpha, beta, None, None, {}, {},
                                                                            ())).blockers)


# ------------------------------------------------------------------ read back
def test_a_domain_is_read_back_from_state():
    state = json.dumps({"version": 4, "terraform_version": "1.16.5", "resources": [
        {"mode": "managed", "type": "google_active_directory_domain", "name": "user_dir",
         "provider": 'provider["registry.terraform.io/hashicorp/google"]',
         "instances": [{"attributes": {"id": NAME, "name": NAME, "domain_name": "corp.example.test",
                                       "locations": ["us-central1", "us-east4"], "reserved_ip_range": "10.250.0.0/24",
                                       "labels": {"role": "user-dir", "managed_by": "opsdir", "realizes": "ds"}}}]}]})
    resources, _ = state_resources(state)
    (ad,) = (r for r in resources if r.kind == "managed-directory")
    assert (ad.ref, ad.role) == (NAME, "user-dir")
    assert ad.attrs == {"ciamManagedService": (SERVICE,), "ciamRealizes": ("ds",), "ciamFqdn": ("corp.example.test",),
                        "ciamRegion": ("us-central1",), "ciamReplicaRegion": ("us-east4",),
                        "ciamCidr": ("10.250.0.0/24",)}


def test_what_it_renders_reads_back_as_recorded():
    (ad,) = managed_ad_resources((("google_active_directory_domain", {
        "id": NAME, "domain_name": "corp.example.test", "locations": ["us-central1", "us-east4"],
        "reserved_ip_range": "10.250.0.0/24", "labels": {"role": "user-dir", "realizes": "ds"}}),))
    assert {k: ad.attrs[k] for k in ("ciamFqdn", "ciamRegion", "ciamReplicaRegion", "ciamCidr", "ciamRealizes")} == {
        "ciamFqdn": ("corp.example.test",), "ciamRegion": ("us-central1",), "ciamReplicaRegion": ("us-east4",),
        "ciamCidr": ("10.250.0.0/24",), "ciamRealizes": ("ds",)}

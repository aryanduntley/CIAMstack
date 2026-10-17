"""Microsoft Entra Domain Services as a managed directory (flow 76): the descriptor the planner reads (Microsoft's
documented capabilities: no schema extension, forest trusts only; available in Azure Government, its newer trust
directions not established there), a target rendered as a managed domain with hardened security and its replica sets,
secure LDAP ignored (its PFX never in Terraform state), the rest actions; a neighbour a note. Read back from Terraform
state without secure LDAP's certificate or password."""
import json

from opsdir.connectors.managed_directory import managed_directory_check
from opsdir.core.contract import PlanContext
from opsdir.core.interchange.ldif import parse
from opsdir_format_terraform.hcl import as_text
from opsdir_adapter_azure.adapter import ADAPTER
from opsdir_adapter_azure.boundary import azure_services
from opsdir_adapter_azure.domain_services import (ENTRA_DOMAIN_SERVICES, SERVICE, domain_service_notes,
                                                  domain_service_resources, render_domain_services)
from opsdir_adapter_azure.inventory import state_resources
from opsdir_adapter_azure.terraform import render
from network_fixtures import ALPHA, BETA, entry, model

DOMAIN = f"cn=user-dir,ou=bindings,{ALPHA}"
AADDS = dict(ciamBindingRole="user-dir", ciamManagedService=SERVICE, ciamRealizes="ds", ciamFqdn="corp.example.test",
             ciamDirectoryEdition="enterprise", ciamSubnetRole="subnet-ds", ciamReplicaRegion="westus3",
             ciamLdapsMode="private")
RECORDS = (entry(ALPHA, "user-dir", "ciamManagedDirectory", **AADDS),
           entry(DOMAIN, "hq", "ciamDirectoryTrust", ciamFqdn="hq.example.test", ciamTrustType="forest",
                 ciamTrustDirection="one-way-outgoing", ciamForwardTarget="10.9.0.10"))
GOVERNMENT = tuple(parse("dn: cloud=beta,ou=environments,dc=ciam-ops\nchangetype: modify\nreplace: ciamRegion\n"
                         "ciamRegion: usgovvirginia\n"))
ID = ("/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-ciam/providers/Microsoft.AAD/"
      "domainServices/user-dir")


def _model(*records, changes=()):
    return model(alpha=records, changes=changes)[1]


def _render(*records, changes=()):
    return "\n\n".join(as_text(render_domain_services(_model(*records, changes=changes))))


# ------------------------------------------------------------------ the descriptor
def test_the_adapter_declares_entra_domain_services_with_microsoft_s_documented_capabilities():
    assert ADAPTER.managed_directory == (ENTRA_DOMAIN_SERVICES,)
    assert SERVICE in ADAPTER.vocabulary["ciamManagedService"]
    assert ADAPTER.vocabulary["ciamDirectoryEdition"] == ("standard", "enterprise", "premium")
    assert set(ENTRA_DOMAIN_SERVICES.available) == {"public", "usgovernment"} and not ENTRA_DOMAIN_SERVICES.absent
    assert "Schema extensions aren't supported" in ENTRA_DOMAIN_SERVICES.unsupported["schema-extension"]
    assert "trust:external:two-way" in ENTRA_DOMAIN_SERVICES.unsupported
    assert {"ldaps", "ldaps-internet", "password-policies", "multi-region", "trust:forest:one-way-incoming"} <= \
        set(ENTRA_DOMAIN_SERVICES.supported)
    # Azure Government's feature table lists trusts without their directions: the newer ones aren't established
    assert set(ENTRA_DOMAIN_SERVICES.partition_unestablished["usgovernment"]) == {
        "trust:forest:one-way-incoming", "trust:forest:two-way"}
    assert ENTRA_DOMAIN_SERVICES.editions["trust"][0] == ("enterprise", "premium")
    assert ENTRA_DOMAIN_SERVICES.default_base(None) is None             # the customer names the OU


def test_a_managed_domain_is_entra_domain_services_in_the_fedramp_boundary():
    assert ("Microsoft Entra Domain Services", "user-dir") in azure_services(_model(*RECORDS))


# ------------------------------------------------------------------ render
def test_a_target_is_a_hardened_managed_domain_with_its_replica_sets_and_no_secure_ldap_secret():
    out = _render(*RECORDS)
    for line in ('resource "azurerm_active_directory_domain_service" "user_dir"', 'domain_name         = '
                 '"corp.example.test"', 'sku                 = "Enterprise"',
                 "subnet_id = data.azurerm_subnet.subnet_ds.id", "notify_dc_admins     = true",
                 "ntlm_v1_enabled                 = false", "tls_v1_enabled                  = false",
                 "kerberos_rc4_encryption_enabled = false", "sync_ntlm_passwords             = true",
                 "sync_on_prem_passwords          = false", 'Realizes  = "ds"',
                 "ignore_changes = [secure_ldap]",
                 'resource "azurerm_active_directory_domain_service_replica_set" "user_dir_westus3"',
                 "domain_service_id = azurerm_active_directory_domain_service.user_dir.id",
                 'location          = "westus3"', "subnet_id         = var.user_dir_westus3_subnet_id"):
        assert line in out, line
    assert "pfx_certificate" not in out and "secure_ldap {" not in out and "password =" not in out


def test_what_isnt_rendered_is_an_action_and_a_neighbour_is_a_note():
    notes = {n.subject: n for n in domain_service_notes(_model(*RECORDS))}
    assert "2565bd9d-da50-47d4-8b85-4c97f669dc36" in notes["managed domain user-dir prerequisites"].text
    assert "uploaded by hand" in notes["managed domain user-dir secure LDAP"].text
    assert "the trust with hq.example.test (forest, one-way outgoing)" in notes["managed domain user-dir trust hq"].text
    assert notes["managed domain user-dir OU"].how == ("Create it, record it (ciamWritableBase)",)
    assert "var.user_dir_westus3_subnet_id" in notes["managed domain user-dir replica sets"].how[0]
    neighbour = _model(entry(ALPHA, "corp-ad", "ciamManagedDirectory", ciamBindingRole="corp-ad",
                             ciamManagedService=SERVICE))
    assert [x for x in render_domain_services(neighbour) if x[0] != "#"] == []
    (n,) = domain_service_notes(neighbour)
    assert (n.severity, n.subject) == ("note", "managed domain corp-ad") and "not rendered" in n.text


def test_an_unrecorded_edition_is_unbound_so_applying_fails_naming_it():
    out = _render(*RECORDS, changes=parse(f"dn: {DOMAIN}\nchangetype: modify\ndelete: ciamDirectoryEdition\n"))
    assert 'sku                 = "UNBOUND:user-dir-edition"' in out


def test_an_arm_render_keeps_the_managed_domain_and_its_replica_sets_in_terraform():
    placements = json.loads(render(_model(*RECORDS), None, ("bicep",))["bicep/placements.json"])
    assert placements["azurerm_active_directory_domain_service.user_dir"]["in"] == "terraform/main.tf"
    assert "replicaSets" in placements["azurerm_active_directory_domain_service_replica_set.user_dir_westus3"]["why"]


# ------------------------------------------------------------------ the planner, on what Microsoft documents
def test_the_planner_blocks_the_schema_and_external_trusts_and_asks_government_to_confirm_new_directions():
    check = managed_directory_check((ADAPTER,))
    schema = ("dn: ou=user-schema,dc=ciam-ops\nobjectClass: top\nobjectClass: organizationalUnit\nou: user-schema\n",
              "dn: cn=badge,ou=user-schema,dc=ciam-ops\nobjectClass: top\nobjectClass: ciamUserAttribute\ncn: badge\n"
              "ciamLdapName: exBadge\nciamPiiClass: low\nciamLdapOid: 1.3.6.1.4.1.32473.7.1\n")
    target = entry(BETA, "user-dir", "ciamManagedDirectory", **AADDS)
    trusts = (entry(f"cn=user-dir,ou=bindings,{BETA}", "hq", "ciamDirectoryTrust", ciamFqdn="hq.example.test",
                    ciamTrustType="forest", ciamTrustDirection="two-way"),
              entry(f"cn=user-dir,ou=bindings,{BETA}", "lab", "ciamDirectoryTrust", ciamFqdn="lab.example.test",
                    ciamTrustType="external", ciamTrustDirection="one-way-outgoing"))
    d, alpha, beta = model(beta=(target, *trusts), tree=schema, changes=GOVERNMENT)
    found = check(PlanContext(d, alpha, beta, None, None, {}, {}, ()))
    blockers = [b[1] for b in found.blockers]
    assert any("which Microsoft Entra Domain Services can't (Schema extensions aren't supported" in t for t in blockers)
    assert any("keep a one-way outgoing external trust, which Microsoft Entra Domain Services can't (only forest "
               "trusts" in t for t in blockers)
    assert any("keep a two-way forest trust, and no vendor documentation establishes that it can" in t
               for t in blockers)
    assert any("US Gov Texas isn't established" in a[1] for a in found.actions)
    d, alpha, beta = model(beta=(target, *trusts), tree=schema)
    public = check(PlanContext(d, alpha, beta, None, None, {}, {}, ()))
    assert not any("two-way forest trust" in b[1] for b in public.blockers)


# ------------------------------------------------------------------ read back
def _state(*resources):
    return json.dumps({"version": 4, "terraform_version": "1.16.5", "resources": [
        {"mode": "managed", "type": t, "name": n, "provider": 'provider["registry.terraform.io/hashicorp/azurerm"]',
         "instances": [{"attributes": a}]} for t, n, a in resources]})


def test_a_managed_domain_is_read_back_from_state_without_secure_ldap_secrets():
    resources, _ = state_resources(_state(
        ("azurerm_active_directory_domain_service", "user_dir", {
            "id": ID, "name": "user-dir", "domain_name": "corp.example.test", "sku": "Enterprise",
            "location": "eastus2", "secure_ldap": [{"enabled": True, "pfx_certificate": "never-read-this",
                                                    "pfx_certificate_password": "nor-this"}],
            "tags": {"Role": "user-dir", "Realizes": "ds"}}),
        ("azurerm_active_directory_domain_service_replica_set", "r", {"domain_service_id": ID,
                                                                       "location": "westus3"})))
    (ad,) = (r for r in resources if r.kind == "managed-directory")
    assert (ad.ref, ad.role) == (ID, "user-dir")
    assert ad.attrs == {"ciamManagedService": (SERVICE,), "ciamRealizes": ("ds",), "ciamFqdn": ("corp.example.test",),
                        "ciamDirectoryEdition": ("enterprise",), "ciamRegion": ("eastus2",),
                        "ciamReplicaRegion": ("westus3",)}
    assert "never-read-this" not in repr(resources) and "nor-this" not in repr(resources)


def test_what_it_renders_reads_back_as_recorded():
    (ad,) = domain_service_resources((("azurerm_active_directory_domain_service", {
        "id": ID, "name": "user-dir", "domain_name": "corp.example.test", "sku": "Enterprise",
        "tags": {"Role": "user-dir", "Realizes": "ds"}}),))
    assert {k: ad.attrs[k] for k in ("ciamFqdn", "ciamDirectoryEdition", "ciamRealizes")} == {
        k: (AADDS[k],) for k in ("ciamFqdn", "ciamDirectoryEdition", "ciamRealizes")}

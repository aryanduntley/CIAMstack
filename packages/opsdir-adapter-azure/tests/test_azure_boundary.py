"""The Azure services an environment uses, named as Microsoft's compliance-scope page names them (with the page's
qualifiers matched), and the planner's check against the authorization the target relies on (Azure Communication
Services: on neither of the page's tables; a forwarder on the environment's own DNS servers: Virtual Machines, not
the DNS Private Resolver)."""
from opsdir.core.interchange.ldif import LdifRecord
from opsdir_adapter_azure.boundary import azure_services, check_boundary
from network_fixtures import BETA, context, entry, model

AUTH = "cn=F1603087869,ou=authorizations,dc=ciam-ops"
SCOPE = ("Virtual Machines", "Virtual Network", "Load Balancer", "Azure Database for PostgreSQL",
         "Storage: Blobs (incl. Azure Data Lake Storage Gen2)", "Azure Monitor (incl. Application Insights and Log "
         "Analytics)", "Key Vault", "DNS")
TREE = ("dn: ou=authorizations,dc=ciam-ops\nobjectClass: top\nobjectClass: organizationalUnit\nou: authorizations\n",
        f"dn: {AUTH}\nobjectClass: top\nobjectClass: ciamCloudAuthorization\ncn: F1603087869\n"
        "ciamPackageId: F1603087869\nciamAuthorizationLevel: fedramp-high\nciamAuthorizationLevel: dod-il5\n"
        "ciamAuthorizationStatus: certified\nciamScopeAsOf: 20261001000000Z\n"
        + "".join(f"ciamInScopeService: {s}\n" for s in SCOPE))
BINDINGS = (entry(BETA, "grants", "ciamDatabase", ciamBindingRole="pf-grants-db", ciamDbEngine="postgresql"),
            entry(BETA, "logs", "ciamLogDestination", ciamBindingRole="audit-logs", ciamDestinationKind="workspace"),
            entry(BETA, "mail", "ciamSendingIdentity", ciamBindingRole="mail-sender", ciamSenderDomain="example.test"),
            entry(BETA, "fwd", "ciamDnsForwarder", ciamBindingRole="ad-forwarder", ciamForwardDomain="corp.example",
                  ciamForwardTarget="10.9.0.2", ciamResolverHost="10.2.0.4"))


def test_the_services_an_environment_uses_and_those_outside_its_authorization():
    held = LdifRecord(BETA, "modify", {}, (("add", "objectClass", ("ciamEnvironmentPlacement",)),
                                           ("replace", "ciamAuthorizationRef", (AUTH,)),
                                           ("replace", "ciamRequiredAuthorization", ("dod-il4",))))
    d, a, b = model(beta=BINDINGS, tree=TREE, changes=(held,))
    used = dict(azure_services(b))
    assert used["Azure Database for PostgreSQL"] == "pf-grants-db" and used["Azure Monitor"] == "audit-logs"
    assert used["Virtual Machines"].endswith("and 1 more") and "DNS Private Resolver" not in used   # + the forwarder
    f = check_boundary(context(d, a, b, cutover="2026-12-01"))
    assert [x[1].split(", which")[0] for x in f.blockers if "Communication" in x[1]] == [
        "beta/prod uses Azure Communication Services (mail-sender)"]
    assert not [x for x in f.blockers if "Azure Monitor" in x[1] or "Storage: Blobs" in x[1]]


def test_external_id_is_covered_by_microsoft_entra_id_on_the_scope_page():
    # no row of its own: the Microsoft Entra ID row's footnote applies Entra ID's authorizations to External ID
    tenant = entry(BETA, "sso-tenant", "ciamManagedIdentity", ciamBindingRole="sso-tenant",
                   ciamManagedService="entra-external-id", ciamRealizes="sso")
    held = LdifRecord(BETA, "modify", {}, (("add", "objectClass", ("ciamEnvironmentPlacement",)),
                                           ("replace", "ciamAuthorizationRef", (AUTH,)),
                                           ("replace", "ciamRequiredAuthorization", ("fedramp-high",))))
    listed = LdifRecord(AUTH, "modify", {}, (("add", "ciamInScopeService", ("Microsoft Entra ID (P1 + P2)",)),))
    d, a, b = model(beta=(tenant,), tree=TREE, changes=(held, listed))
    assert ("Microsoft Entra External ID", "sso-tenant") in azure_services(b)
    f = check_boundary(context(d, a, b))
    assert not [x for x in f.blockers if "External ID" in x[1]]
    assert any("Microsoft Entra External ID (sso-tenant), which `F1603087869` covers as part of Microsoft Entra ID"
               in x for x in f.ok)
    d, a, b = model(beta=(tenant,), tree=TREE, changes=(held,))           # Entra ID not listed: outside
    assert [x[1].split(", which")[0] for x in check_boundary(context(d, a, b)).blockers] == [
        "beta/prod uses Microsoft Entra External ID (sso-tenant)"]

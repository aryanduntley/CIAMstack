"""The Azure services an environment uses, named as Microsoft's compliance-scope page names them (with the page's
qualifiers matched), and the planner's check against the authorization the target relies on (Azure Communication
Services: on neither of the page's tables)."""
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
            entry(BETA, "mail", "ciamSendingIdentity", ciamBindingRole="mail-sender", ciamSenderDomain="example.test"))


def test_the_services_an_environment_uses_and_those_outside_its_authorization():
    held = LdifRecord(BETA, "modify", {}, (("add", "objectClass", ("ciamEnvironmentPlacement",)),
                                           ("replace", "ciamAuthorizationRef", (AUTH,)),
                                           ("replace", "ciamRequiredAuthorization", ("dod-il4",))))
    d, a, b = model(beta=BINDINGS, tree=TREE, changes=(held,))
    used = dict(azure_services(b))
    assert used["Azure Database for PostgreSQL"] == "pf-grants-db" and used["Azure Monitor"] == "audit-logs"
    f = check_boundary(context(d, a, b, cutover="2026-12-01"))
    assert [x[1].split(", which")[0] for x in f.blockers if "Communication" in x[1]] == [
        "beta/prod uses Azure Communication Services (mail-sender)"]
    assert not [x for x in f.blockers if "Azure Monitor" in x[1] or "Storage: Blobs" in x[1]]

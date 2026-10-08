"""The Google Cloud services an environment uses (named as Google's Assured Workloads supported-products page names
them), the planner's boundary check, and the Assured Workloads workload an environment recording the assured-workload
configuration has in its landing zone (the regime of its most demanding required level), read back as a notice."""
from opsdir.core.directory import make_entry
from opsdir.core.interchange.ldif import LdifRecord
from opsdir_adapter_gcp.boundary import check_boundary, gcp_services, render_workload, workload_notices
from network_fixtures import BETA, context, entry, model

AUTH = "cn=FR1805751477,ou=authorizations,dc=ciam-ops"
TREE = ("dn: ou=authorizations,dc=ciam-ops\nobjectClass: top\nobjectClass: organizationalUnit\nou: authorizations\n",
        f"dn: {AUTH}\nobjectClass: top\nobjectClass: ciamCloudAuthorization\ncn: FR1805751477\n"
        "ciamPackageId: FR1805751477\nciamAuthorizationLevel: fedramp-high\nciamAuthorizationStatus: certified\n"
        "ciamScopeAsOf: 20261001000000Z\nciamRequiresConfiguration: assured-workload\n"
        "ciamInScopeService: Compute Engine\nciamInScopeService: Virtual Private Cloud (VPC)\n"
        "ciamInScopeService: Cloud Monitoring [6]\n")
BINDINGS = (entry(BETA, "grants", "ciamDatabase", ciamBindingRole="pf-grants-db", ciamDbEngine="postgresql"),
            entry(BETA, "page", "ciamAlertChannel", ciamBindingRole="alerts-page", ciamChannelKind="paging-service"))


def _model(met=("assured-workload",), levels=("fedramp-high", "dod-il4")):
    held = LdifRecord(BETA, "modify", {}, (("add", "objectClass", ("ciamEnvironmentPlacement",)),
                                           ("replace", "ciamAuthorizationRef", (AUTH,)),
                                           ("replace", "ciamRequiredAuthorization", tuple(levels)),
                                           *((("replace", "ciamConfigurationMet", tuple(met)),) if met else ())))
    d, a, b = model(beta=BINDINGS, tree=TREE, changes=(held,))
    cloud = make_entry(b.cloud.dn, (*b.cloud.classes, "ciamCloudAccount"),
                       {**b.cloud.attrs, "ciamOrganizationRef": ("organizations/123456789",),
                        "ciamBillingAccountRef": ("01A2B3-C4D5E6-F7A8B9",)})
    return d, a, b._replace(cloud=cloud)


def test_services_and_the_boundary_check():
    d, a, b = _model()
    used = dict(gcp_services(b))
    assert used["Cloud SQL"] == "pf-grants-db" and used["Cloud Monitoring"] == "alerts-page"
    f = check_boundary(context(d, a, b, cutover="2026-12-01"))
    assert [x[1].split(", which")[0] for x in f.blockers] == [
        "beta/prod uses Cloud SQL (pf-grants-db)", "beta/prod uses Cloud Load Balancing (sso-service)"]


def test_the_workload_takes_the_most_demanding_regime_or_is_a_note():
    d, a, b = _model()
    (out,) = render_workload(b)
    assert 'compliance_regime = "IL4"' in out and 'organization      = "123456789"' in out
    assert 'billing_account   = "billingAccounts/01A2B3-C4D5E6-F7A8B9"' in out
    assert render_workload(_model(met=())[2]) == ()
    assert render_workload(_model(levels=("fedramp-moderate",))[2])[0].count('"FEDRAMP_MODERATE"') == 1
    _, _, bare = model(beta=BINDINGS, tree=TREE, changes=(LdifRecord(BETA, "modify", {}, (
        ("add", "objectClass", ("ciamEnvironmentPlacement",)),
        ("replace", "ciamConfigurationMet", ("assured-workload",)))),))
    assert render_workload(bare)[0].startswith("# NOTE: beta/prod's Assured Workloads workload: not rendered")


def test_workloads_are_named_in_an_import_notice():
    assert workload_notices([("google_assured_workloads_workload", {"display_name": "ciam-prod",
                                                                    "compliance_regime": "FEDRAMP_HIGH"})]) == (
        "Assured Workloads workload ciam-prod: FEDRAMP_HIGH (record it on the environment: ciamConfigurationMet "
        "assured-workload)",)

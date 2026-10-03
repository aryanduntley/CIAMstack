"""The Google Cloud landing zone rendered for whoever keeps it: a workload identity pool and an OIDC provider accepting
only the deployers' subjects, a deployer's service account its pipeline may act as with its IAM members, an operator
group's IAM members; nothing when the environment needs nothing from one."""
from opsdir.core.environment import env_model
from opsdir.core.interchange.ldif import parse
from opsdir_adapter_gcp.landing import render_landing
from support import REGISTRY, build_directory

ENV = "env=prod,cloud=gcp,ou=environments,dc=ciam-ops"
GITHUB = "https://token.actions.githubusercontent.com"
SUBJECT = "repo:example-aero/ciam-ops:environment:prod"


def _entry(dn, oc, **attrs):
    return f"dn: {dn}\nobjectClass: top\nobjectClass: {oc}\n" + "".join(
        f"{k}: {v}\n" for k, vs in attrs.items() for v in (vs if isinstance(vs, tuple) else (vs,)))


RECORDS = "\n".join((
    "dn: dc=ciam-ops\nobjectClass: top\nobjectClass: domain\ndc: ciam-ops\n",
    "dn: ou=environments,dc=ciam-ops\nobjectClass: top\nobjectClass: organizationalUnit\nou: environments\n",
    _entry("cloud=gcp,ou=environments,dc=ciam-ops", "ciamCloud", cloud="gcp", ciamCloudProvider="gcp",
           ciamRegion="us-central1"),
    _entry(ENV, "ciamEnvironment", env="prod"),
    _entry(f"ou=bindings,{ENV}", "organizationalUnit", ou="bindings"),
    _entry(f"cn=secret,ou=bindings,{ENV}", "ciamSecretRef", cn="secret", ciamBindingRole="pf-admin-password",
           ciamRefUri="gcp-sm://projects/ciam-prod/secrets/pf-admin-password"),
    "dn: ou=permission-sets,dc=ciam-ops\nobjectClass: top\nobjectClass: organizationalUnit\nou: permission-sets\n",
    _entry("cn=release,ou=permission-sets,dc=ciam-ops", "ciamPermissionSet", cn="release",
           ciamPermits="read-secret pf-admin-password"),
    "dn: ou=principals,dc=ciam-ops\nobjectClass: top\nobjectClass: organizationalUnit\nou: principals\n",
    _entry("cn=ci-deploy,ou=principals,dc=ciam-ops", "ciamPrincipal", cn="ci-deploy", ciamPrincipalKind="deployer",
           ciamIdentityRole="identity-ci", ciamHoldsSet="cn=release,ou=permission-sets,dc=ciam-ops"),
    _entry("cn=ops-admins,ou=principals,dc=ciam-ops", "ciamPrincipal", cn="ops-admins", ciamPrincipalKind="operator",
           ciamIdentityRole="admin-group", ciamHoldsSet="cn=release,ou=permission-sets,dc=ciam-ops"),
    _entry(f"cn=identity-ci,ou=bindings,{ENV}", "ciamIdentityBinding", cn="identity-ci", ciamBindingRole="identity-ci",
           ciamProviderRef="ciam-prod-deploy@ciam-prod.iam.gserviceaccount.com", ciamIdentityKind="federated",
           ciamTrustedBy=f"{GITHUB} {SUBJECT}"),
    _entry(f"cn=admin-group,ou=bindings,{ENV}", "ciamIdentityBinding", cn="admin-group",
           ciamBindingRole="admin-group", ciamProviderRef="ciam-admins@example-aero.test", ciamIdentityKind="group")))


def test_a_deployers_workload_identity_and_an_operator_groups_members():
    out = render_landing(env_model(build_directory(REGISTRY, tuple(parse(RECORDS))), "gcp/prod"))[
        "terraform/landing-zone/main.tf"]
    assert 'workload_identity_pool_id = "ciam-prod-ci"' in out
    assert f'attribute_condition = "assertion.sub in [\'{SUBJECT}\']"' in out
    assert f'issuer_uri = "{GITHUB}"' in out and '"google.subject" = "assertion.sub"' in out
    assert 'account_id   = "ciam-prod-deploy"' in out and 'role               = "roles/iam.workloadIdentityUser"' in out
    assert f"/subject/{SUBJECT}" in out
    assert 'member    = "serviceAccount:${google_service_account.identity_ci.email}"' in out
    assert 'member    = "group:ciam-admins@example-aero.test"' in out


def test_guardrails_as_organization_policies_each_constraint_once():
    guardrails = "\n".join(_entry(f"cn={cn},ou=bindings,{ENV}", "ciamGuardrail", cn=cn, ciamBindingRole=cn,
                                  ciamGuardrailKind="org-constraint", ciamDenies=denies)
                           for cn, denies in (("baseline", ("region-escape", "service-account-keys", "metadata-v1")),
                                              ("keys", ("service-account-keys", "key-deletion"))))
    out = render_landing(env_model(build_directory(REGISTRY, tuple(parse(RECORDS + "\n" + guardrails))), "gcp/prod"))[
        "terraform/landing-zone/main.tf"]
    assert 'name   = "projects/${var.project_id}/policies/gcp.resourceLocations"' in out
    assert 'allowed_values = ["in:us-central1-locations"]' in out and 'enforce = "TRUE"' in out
    assert out.count('resource "google_org_policy_policy" "iam_disableserviceaccountkeycreation"') == 1
    assert "cloudkms.disableBeforeDestroy" in out
    assert "# NOTE: guardrail baseline: metadata-v1: the metadata server already requires" in out

"""The AWS landing zone rendered for whoever keeps it: an OIDC provider and the role a CI pipeline assumes with its
token (audience and subject pinned) with its least-privilege policy, an IAM Identity Center permission set assigned
to an operator group, the owner in the header and the landing-zone scope in the MANIFEST; nothing when the
environment needs nothing from one."""
from opsdir.connectors.render import render_env
from opsdir.core.environment import env_model
from opsdir.core.interchange.ldif import parse
from opsdir_adapter_aws.landing import render_landing
from support import REGISTRY, build_directory

ENV = "env=prod,cloud=aws,ou=environments,dc=ciam-ops"
SECRET = "arn:aws:secretsmanager:us-east-1:111122223333:secret:ciam/prod/pf-admin-password"
GITHUB = "https://token.actions.githubusercontent.com"


def _entry(dn, oc, **attrs):
    return f"dn: {dn}\nobjectClass: top\nobjectClass: {oc}\n" + "".join(
        f"{k}: {v}\n" for k, vs in attrs.items() for v in (vs if isinstance(vs, tuple) else (vs,)))


def _records(*extra):
    return "\n".join((
        "dn: dc=ciam-ops\nobjectClass: top\nobjectClass: domain\ndc: ciam-ops\n",
        "dn: ou=owners,dc=ciam-ops\nobjectClass: top\nobjectClass: organizationalUnit\nou: owners\n",
        _entry("cn=landing-zone,ou=owners,dc=ciam-ops", "ciamParty", cn="landing-zone", ciamOwnerKind="team"),
        "dn: ou=environments,dc=ciam-ops\nobjectClass: top\nobjectClass: organizationalUnit\nou: environments\n",
        _entry("cloud=aws,ou=environments,dc=ciam-ops", "ciamCloud", cloud="aws", ciamCloudProvider="aws",
               ciamRegion="us-east-1", ciamOwner="cn=landing-zone,ou=owners,dc=ciam-ops"),
        _entry(ENV, "ciamEnvironment", env="prod"),
        _entry(f"ou=bindings,{ENV}", "organizationalUnit", ou="bindings"),
        _entry(f"cn=secret,ou=bindings,{ENV}", "ciamSecretRef", cn="secret", ciamBindingRole="pf-admin-password",
               ciamRefUri=f"aws-sm://{SECRET}"),
        _entry(f"cn=vpc,ou=bindings,{ENV}", "ciamNetwork", cn="vpc", ciamBindingRole="network", ciamCidr="10.20.0.0/16",
               ciamProviderRef="vpc-0a1b2c3d4e5f67890"),
        *extra))


PRINCIPALS = (
    "dn: ou=permission-sets,dc=ciam-ops\nobjectClass: top\nobjectClass: organizationalUnit\nou: permission-sets\n",
    _entry("cn=release,ou=permission-sets,dc=ciam-ops", "ciamPermissionSet", cn="release",
           ciamPermits="read-secret pf-admin-password"),
    "dn: ou=principals,dc=ciam-ops\nobjectClass: top\nobjectClass: organizationalUnit\nou: principals\n",
    _entry("cn=ci-deploy,ou=principals,dc=ciam-ops", "ciamPrincipal", cn="ci-deploy", ciamPrincipalKind="deployer",
           ciamIdentityRole="identity-ci", ciamHoldsSet="cn=release,ou=permission-sets,dc=ciam-ops"),
    _entry("cn=ops-admins,ou=principals,dc=ciam-ops", "ciamPrincipal", cn="ops-admins", ciamPrincipalKind="operator",
           ciamIdentityRole="admin-sso", ciamHoldsSet="cn=release,ou=permission-sets,dc=ciam-ops"),
    _entry(f"cn=identity-ci,ou=bindings,{ENV}", "ciamIdentityBinding", cn="identity-ci", ciamBindingRole="identity-ci",
           ciamProviderRef="arn:aws:iam::111122223333:role/ciam-prod-deploy", ciamIdentityKind="federated",
           ciamTrustedBy=f"{GITHUB} repo:example-aero/ciam-ops:environment:prod"),
    _entry(f"cn=admin-sso,ou=bindings,{ENV}", "ciamIdentityBinding", cn="admin-sso", ciamBindingRole="admin-sso",
           ciamProviderRef="9a4f7c2e-0000-4000-8000-000000000001", ciamIdentityKind="group"))


def test_ci_trust_and_workforce_access_for_the_landing_zone():
    m = env_model(build_directory(REGISTRY, tuple(parse(_records(*PRINCIPALS)))), "aws/prod")
    out = render_landing(m)["terraform/landing-zone/main.tf"]
    assert "kept by landing-zone" in out and "not by the platform's pipeline" in out
    assert 'resource "aws_iam_openid_connect_provider" "token_actions_githubusercontent_com"' in out
    assert '"Action" : "sts:AssumeRoleWithWebIdentity"' in out and 'name = "ciam-prod-deploy"' in out
    assert '"token.actions.githubusercontent.com:aud" : "sts.amazonaws.com"' in out
    assert '"token.actions.githubusercontent.com:sub" : "repo:example-aero/ciam-ops:environment:prod"' in out
    assert '"secretsmanager:GetSecretValue"' in out
    assert 'resource "aws_ssoadmin_permission_set" "admin_sso"' in out
    assert 'name             = "ciam-prod-ops-admins"' in out and 'principal_type     = "GROUP"' in out
    assert 'principal_id       = "9a4f7c2e-0000-4000-8000-000000000001"' in out
    assert "variable \"account_id\"" in render_landing(m)["terraform/landing-zone/providers.tf"]


def test_the_manifest_scopes_it_and_nothing_is_rendered_without_need():
    d = build_directory(REGISTRY, tuple(parse(_records(*PRINCIPALS))))
    _, files = render_env(d, "aws/prod")
    assert '"scope": "landing-zone"' in files["MANIFEST.json"] and "terraform/landing-zone/main.tf" in files
    assert render_landing(env_model(build_directory(REGISTRY, tuple(parse(_records()))), "aws/prod")) == {}


def test_guardrails_as_service_control_policies():
    guardrail = _entry(f"cn=baseline,ou=bindings,{ENV}", "ciamGuardrail", cn="baseline", ciamBindingRole="guardrails",
                       ciamGuardrailKind="service-control",
                       ciamDenies=("region-escape", "root-use", "public-storage"))
    files = render_landing(env_model(build_directory(REGISTRY, tuple(parse(_records(guardrail)))), "aws/prod"))
    out = files["terraform/landing-zone/main.tf"]
    assert 'resource "aws_organizations_policy" "baseline"' in out and 'type        = "SERVICE_CONTROL_POLICY"' in out
    assert '"aws:RequestedRegion" : [' in out and '"us-east-1"' in out and '"Sid" : "DenyRoot"' in out
    assert "# NOTE: guardrail baseline: public-storage: AWS's mechanism is the Organizations S3 policy type" in out
    assert 'target_id = var.guardrail_target_id' in out
    assert 'variable "guardrail_target_id"' in files["terraform/landing-zone/providers.tf"]

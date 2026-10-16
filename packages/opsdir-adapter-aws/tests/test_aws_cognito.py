"""Amazon Cognito user pools as managed identity services: the descriptor the planner reads (AWS's documented
capabilities, GovCloud's differences), a target rendered as a user pool with its domain, a client per OIDC client it
serves, a resource server for custom scopes and a SAML provider per partner identity provider, in Terraform and in
CloudFormation; a neighbour isn't rendered. Read back from Terraform state and from the CLI's describe-user-pool,
projected: no client or provider secret is ever read."""
import json

from opsdir.core.contract import PlanContext
from opsdir_format_terraform.hcl import as_text, written
from opsdir_adapter_aws.adapter import ADAPTER
from opsdir_adapter_aws.boundary import aws_services
from opsdir_adapter_aws.cfn_types import cloudformation_files
from opsdir_adapter_aws.cli import cli_resources
from opsdir_adapter_aws.cli_cognito import POOL_QUERY
from opsdir_adapter_aws.cognito import COGNITO, SERVICE, cognito_notes, cognito_resources, render_cognito
from opsdir_adapter_aws.inventory import state_resources
from opsdir_adapter_aws.terraform import WHAT, render_files
from opsdir.connectors.managed_identity import managed_identity_check
from opsdir.core.interchange.ldif import parse
from network_fixtures import ALPHA, entry, model

POOL_ARN = "arn:aws:cognito-idp:us-east-1:111122223333:userpool/us-east-1_AbC123"
CERT_ARN = "arn:aws:acm:us-east-1:111122223333:certificate/c-1"
EXCHANGE = "urn:ietf:params:oauth:grant-type:token-exchange"
INTEGRATIONS = "ou=integrations,dc=ciam-ops"


def _integration(cn, protocol, **attrs):
    return entry(INTEGRATIONS, cn, "ciamIntegration", ciamProtocolType=protocol, **attrs)


TREE = ("dn: ou=integrations,dc=ciam-ops\nobjectClass: top\nobjectClass: organizationalUnit\nou: integrations\n",
        "dn: cn=pf-signing,dc=ciam-ops\nobjectClass: top\nobjectClass: ciamCertificate\ncn: pf-signing\n"
        "ciamCertPurpose: tls-server\n",
        _integration("portal", "oidc-client", ciamClientId="portal", ciamTokenAuthMethod="client_secret_basic",
                     ciamGrantType=("authorization_code", "refresh_token", EXCHANGE),
                     ciamRedirectUri="https://portal.example.test/cb",
                     ciamPostLogoutRedirectUri="https://portal.example.test/bye",
                     ciamScope=("openid", "email", "offline_access", "orders.read"), ciamMfaRequired="TRUE"),
        _integration("mobile", "oidc-client", ciamClientId="mobile", ciamTokenAuthMethod="none",
                     ciamGrantType="authorization_code", ciamRedirectUri="com.example.app:/cb", ciamScope="openid"),
        _integration("crm", "saml2-sp", ciamEntityId="https://crm.example.test", ciamAcsUrl="https://crm.example.test/a"),
        _integration("skyline", "saml2-idp", ciamEntityId="https://idp.skyline.test",
                     ciamSsoUrl="https://idp.skyline.test/sso"))
POOL = dict(ciamBindingRole="sso-pool", ciamManagedService=SERVICE, ciamRealizes="sso", ciamFqdn="sso.example.test",
            ciamTlsCertificate="cn=pf-signing,dc=ciam-ops")
CERT = entry(ALPHA, "cert-sso", "ciamCertificateRef", ciamBindingRole="sso-cert", ciamRefUri=f"aws-acm://{CERT_ARN}",
             ciamHoldsCertificate="cn=pf-signing,dc=ciam-ops")


def _model(*records, changes=()):
    return model(alpha=records, tree=TREE, changes=changes)[1]


def _render(*records, changes=()):
    return "\n\n".join(as_text(render_cognito(_model(*records, changes=changes))))


# ------------------------------------------------------------------ the descriptor
def test_the_adapter_declares_cognito_with_aws_s_documented_capabilities():
    assert ADAPTER.managed_identity == (COGNITO,) and ADAPTER.vocabulary["ciamManagedService"] == (SERVICE,)
    assert {"issue:saml", f"grant:{EXCHANGE}", "custom-issuer"} <= set(COGNITO.unsupported)
    assert set(COGNITO.available) == {"aws", "aws-us-gov"} and not COGNITO.absent
    assert set(COGNITO.partition_unsupported["aws-us-gov"]) == {"custom-domain"}
    assert [topic for topic, _, _ in COGNITO.notes["aws-us-gov"]] == ["FIPS endpoints", "password hashes", "Pinpoint"]
    # what AWS documents neither way stays not established: DPoP, mTLS and private-key client authentication
    assert not {"dpop-bound", "token-auth:tls_client_auth", "token-auth:private_key_jwt"} & {
        *COGNITO.supported, *COGNITO.unsupported}


def test_a_user_pool_is_amazon_cognito_in_the_fedramp_boundary():
    m = _model(entry(ALPHA, "sso-pool", "ciamManagedIdentity", **POOL))
    assert ("Amazon Cognito", "sso-pool") in aws_services(m)


# ------------------------------------------------------------------ render
def test_a_target_is_a_user_pool_with_its_domain_clients_scopes_and_partner():
    out = _render(CERT, entry(ALPHA, "sso-pool", "ciamManagedIdentity", **POOL))
    for line in ('resource "aws_cognito_user_pool" "sso_pool"', 'name                = "sso-pool"',
                 'deletion_protection = "ACTIVE"', 'mfa_configuration   = "OPTIONAL"',
                 'software_token_mfa_configuration {\n    enabled = true\n  }', 'Realizes  = "sso"',
                 'resource "aws_cognito_user_pool_domain" "sso_pool"', 'domain          = "sso.example.test"',
                 f'certificate_arn = "{CERT_ARN}"',
                 'resource "aws_cognito_user_pool_client" "sso_pool_portal"',
                 "generate_secret                      = true",
                 'allowed_oauth_flows                  = ["code"]',
                 'allowed_oauth_scopes                 = ["openid", "email", "https://sso.example.test/orders.read"]',
                 'callback_urls                        = ["https://portal.example.test/cb"]',
                 'logout_urls                          = ["https://portal.example.test/bye"]',
                 'supported_identity_providers         = ["COGNITO", "skyline"]',
                 'resource "aws_cognito_user_pool_client" "sso_pool_mobile"',
                 'resource "aws_cognito_resource_server" "sso_pool"', 'identifier   = "https://sso.example.test"',
                 'scope_name        = "orders.read"', 'variable "sso_pool_skyline_metadata_url"',
                 'resource "aws_cognito_identity_provider" "sso_pool_skyline"', 'provider_type = "SAML"',
                 "MetadataURL = var.sso_pool_skyline_metadata_url"):
        assert line in out, line
    assert f"grant {EXCHANGE} isn't rendered" in out and "offline_access isn't a Cognito scope" in out
    assert "saml2-sp integration crm isn't rendered: Cognito can't serve it" in out
    assert "NOTE: user pool sso-pool scopes" in out and "NOTE: user pool sso-pool partner metadata" in out
    assert "client_secret =" not in out and "import {" not in out


def test_an_adopted_pool_is_imported_and_a_prefix_domain_is_its_prefix():
    out = _render(entry(ALPHA, "sso-pool", "ciamManagedIdentity", **{
        **POOL, "ciamFqdn": "example-sso.auth.us-east-1.amazoncognito.com", "ciamProviderRef": POOL_ARN}))
    assert 'import {\n  to = aws_cognito_user_pool.sso_pool\n  id = "us-east-1_AbC123"\n}' in out
    assert 'domain       = "example-sso"' in out and "certificate_arn" not in out


def test_govcloud_has_no_custom_domain_and_a_neighbour_is_a_note():
    gov = parse("dn: cloud=alpha,ou=environments,dc=ciam-ops\nchangetype: modify\nreplace: ciamRegion\n"
                "ciamRegion: us-gov-west-1\n")
    out = _render(CERT, entry(ALPHA, "sso-pool", "ciamManagedIdentity", **POOL), changes=gov)
    assert "UNBOUND: GovCloud has no custom user pool domains: sso.example.test isn't rendered" in out
    neighbour = _model(entry(ALPHA, "app-pool", "ciamManagedIdentity", ciamBindingRole="app-pool",
                             ciamManagedService=SERVICE, ciamPartnerOf=f"cn=portal,{INTEGRATIONS}"))
    assert [x for x in render_cognito(neighbour) if x[0] != "#"] == []
    (n,) = cognito_notes(neighbour)
    assert (n.severity, n.subject) == ("note", "user pool app-pool") and "not rendered" in n.text


def test_the_render_translates_to_cloudformation():
    m = _model(CERT, entry(ALPHA, "sso-pool", "ciamManagedIdentity", **POOL))
    files = cloudformation_files(m, render_files(m, None), WHAT)
    template = written(files)["cloudformation/template.yaml"]
    for line in ("Type: AWS::Cognito::UserPool", "UserPoolName: sso-pool", "MfaConfiguration: OPTIONAL",
                 "- SOFTWARE_TOKEN_MFA", "UserPoolTags:", "Type: AWS::Cognito::UserPoolDomain",
                 f"CertificateArn: {CERT_ARN}", "Type: AWS::Cognito::UserPoolClient", "AllowedOAuthFlows:",
                 "Type: AWS::Cognito::UserPoolResourceServer", "ScopeName: orders.read",
                 "Type: AWS::Cognito::UserPoolIdentityProvider", "ProviderType: SAML"):
        assert line in template, line


# ------------------------------------------------------------------ the planner, on what AWS documents
def test_the_planner_blocks_what_cognito_can_t_do_and_govcloud_s_custom_domain():
    check = managed_identity_check((ADAPTER,))
    gov = parse("dn: cloud=beta,ou=environments,dc=ciam-ops\nchangetype: modify\nreplace: ciamRegion\n"
                "ciamRegion: us-gov-west-1\n")
    d, alpha, beta = model(beta=(entry("env=prod,cloud=beta,ou=environments,dc=ciam-ops", "sso-pool",
                                       "ciamManagedIdentity", **POOL),), tree=TREE, changes=gov)
    found = check(PlanContext(d, alpha, beta, None, None, {}, {}, ()))
    blockers = [b[1] for b in found.blockers]
    assert any("`crm` (saml2-sp)" in t and "provides no downstream SAML identity provider" in t for t in blockers)
    assert any("token-exchange grant, which Amazon Cognito user pool can't" in t for t in blockers)
    assert any("serve sign-in at a custom domain, which Amazon Cognito user pool can't (GovCloud has no custom user "
               "pool domains" in t for t in blockers)
    assert any("Cognito requires its FIPS endpoints there" in a[1] for a in found.actions)


# ------------------------------------------------------------------ read back
def _state(*resources):
    return json.dumps({"version": 4, "terraform_version": "1.9.0", "resources": [
        {"mode": "managed", "type": t, "name": n, "provider": 'provider["registry.terraform.io/hashicorp/aws"]',
         "instances": [{"attributes": a}]} for t, n, a in resources]})


POOL_STATE = {"id": "us-east-1_AbC123", "arn": POOL_ARN, "name": "sso-pool", "custom_domain": "sso.example.test",
              "tags": {"Name": "sso-pool", "Role": "sso-pool", "Realizes": "sso"}}


def test_a_pool_is_read_back_from_state_without_any_secret():
    resources, _ = state_resources(_state(
        ("aws_cognito_user_pool", "sso_pool", POOL_STATE),
        ("aws_cognito_user_pool_client", "c", {"name": "portal", "client_secret": "never-read-this",
                                               "user_pool_id": "us-east-1_AbC123"})))
    (pool,) = (r for r in resources if r.kind == "managed-identity")
    assert (pool.ref, pool.name, pool.role) == (POOL_ARN, "sso-pool", "sso-pool")
    assert pool.attrs == {"ciamManagedService": (SERVICE,), "ciamRealizes": ("sso",), "ciamFqdn": ("sso.example.test",)}
    assert "never-read-this" not in repr(resources)


def test_what_it_renders_reads_back_as_recorded():
    rendered = cognito_resources((
        ("aws_cognito_user_pool", {"id": "p-1", "name": "sso-pool", "tags": {"Name": "sso-pool", "Role": "sso-pool",
                                                                              "Realizes": "sso"}}),
        ("aws_cognito_user_pool_domain", {"domain": "sso.example.test", "user_pool_id": "p-1",
                                          "certificate_arn": CERT_ARN})))
    (pool,) = rendered
    assert {k: pool.attrs[k] for k in ("ciamManagedService", "ciamRealizes", "ciamFqdn")} == {
        k: (POOL[k],) for k in ("ciamManagedService", "ciamRealizes", "ciamFqdn")}


def test_the_cli_reads_the_projected_pool_and_never_a_client():
    texts = {"user-pools/us-east-1_AbC123.json": json.dumps({"UserPool": {
                 "Id": "us-east-1_AbC123", "Arn": POOL_ARN, "Name": "sso-pool", "CustomDomain": "sso.example.test",
                 "UserPoolTags": {"Role": "sso-pool", "Realizes": "sso"}}}),
             "client.json": json.dumps({"UserPoolClient": {"ClientId": "c", "ClientSecret": "s3cr3t"}})}
    resources, notices = cli_resources(texts)
    (pool,) = (r for r in resources if r.kind == "managed-identity")
    assert (pool.ref, pool.attrs["ciamFqdn"], pool.attrs["ciamRealizes"]) == (POOL_ARN, ("sso.example.test",),
                                                                               ("sso",))
    assert "client.json: not an AWS CLI output this importer reads; not read" in notices
    assert "s3cr3t" not in repr(resources)
    assert "UserPool.{Id: Id, Name: Name, Arn: Arn, UserPoolTags: UserPoolTags, CustomDomain: CustomDomain}" in \
        POOL_QUERY

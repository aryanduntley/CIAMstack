"""Amazon Cognito user pools as cloud-managed identity services (core federation domain: ciamManagedIdentity, flow 63):
what the planner knows of them (the ManagedService descriptor, from AWS's documentation, research note 3078, read
2026-10-15), their Terraform render and their read back. Pure.

A target binding (ciamManagedService cognito-user-pool, ciamRealizes: the identity service it runs) is rendered, each
block stamped with its entry (hcl.from_entry, so the render places it by its keeper):

  aws_cognito_user_pool             named after the binding, deletion protection on, MFA by the integrations it serves
                                    (ON when every one requires it, OPTIONAL when some do, else OFF; TOTP software
                                    tokens), tagged with its name, role and the identity service it realizes
  aws_cognito_user_pool_domain      its sign-in host (ciamFqdn): a custom domain with the ACM certificate holding its
                                    ciamTlsCertificate, or the prefix of a *.amazoncognito.com host
  aws_cognito_user_pool_client      one per public oidc-client integration the service serves: redirect and logout
                                    URIs, the code and client credentials flows of its grants, its scopes (the OIDC
                                    ones as they are, the others as the resource server's), the user pool and every
                                    upstream provider as its identity providers
  aws_cloudformation_stack          one per confidential client (one authenticating with a secret): the same settings
                                    as an AWS::Cognito::UserPoolClient with GenerateSecret, outputting only its client
                                    ID, so the secret Cognito generates never reaches Terraform state (U.5, decision
                                    3289); storing it where the application's reference points is an action
  aws_cognito_resource_server       one, when a client asks for scopes beyond OIDC's: identifier the service's base URL
  aws_cognito_identity_provider     one SAML provider per saml2-idp integration the service serves, its metadata read
                                    from a URL a variable gives (the record holds the partner's entity ID and SSO URL)

What Cognito can't do (a SAML identity provider to service providers, the token-exchange grant, a custom issuer,
per-application MFA, claim transformations without a trigger) is the planner's (connectors.managed_identity) by the
descriptor; the render leaves it out with a comment. A neighbour (ciamPartnerOf) isn't the platform's to render: a
note. Read back from Terraform state, or from the CLI normalized to it (cli_cognito.py): a user pool (its ARN, its
tags' role and Realizes) with its custom domain (ciamFqdn). Client secrets and upstream providers' secrets are never
read.
"""
import re
from itertools import chain

from opsdir.core.contract import ManagedService
from opsdir.core.directory import get, one, rdn_value, values
from opsdir.core.environment import of_class
from opsdir.core.inventory import of_types, resource, tagged_role
from opsdir.core.notes import RECORD, note, note_comment
from opsdir.domains.edge.resolve import certificate_ref
from opsdir.domains.federation.managed import is_target, realized_service, served
from opsdir_format_terraform.hcl import Block, comment, from_entry, jsonencoded, ref, tf_block, tf_import, tf_name
from .account import partition
from .network import binding_tags
from .tags import state_tags

SERVICE = "cognito-user-pool"
AREA = "Identity"
COGNITO_HOST = ".amazoncognito.com"
OIDC_SCOPES = ("openid", "email", "phone", "profile")        # what Cognito issues without a resource server
FLOWS = {"authorization_code": "code", "client_credentials": "client_credentials"}
SECRET_METHODS = ("client_secret_basic", "client_secret_post")

# ------------------------------------------------------------------ what AWS documents (read 2026-10-15)
_API = "Cognito user pools API reference (2026-10)"
_TOKEN = "Cognito token endpoint (2026-10)"
_ROLES = "Cognito managed login protocol roles (2026-10)"
_ENDPOINTS = "Cognito user pool endpoints and issuer (2026-10)"
_GOV = "AWS GovCloud (US) User Guide, Amazon Cognito (2026-10)"
COGNITO = ManagedService(
    name=SERVICE, title="Amazon Cognito user pool", partition=partition,
    available={"aws": _API, "aws-us-gov": f"{_GOV}: both GovCloud regions"},
    absent={},
    supported={
        "issue:oidc": f"an OAuth 2.0 and OIDC issuer to applications ({_ENDPOINTS})",
        "trust:saml": f"a SAML service provider of upstream identity providers ({_ROLES})",
        "trust:oidc": f"an OIDC relying party of upstream providers ({_ROLES})",
        "grant:authorization_code": _TOKEN, "grant:client_credentials": _TOKEN, "grant:refresh_token": _TOKEN,
        "token-auth:none": f"public clients, PKCE on the code flow ({_TOKEN})",
        "token-auth:client_secret_basic": _TOKEN, "token-auth:client_secret_post": _TOKEN,
        "signing-alg:RS256": "Cognito ID tokens (2026-10)",
        "custom-domain": _ENDPOINTS},
    unsupported={
        "issue:saml": f"it consumes SAML assertions and provides no downstream SAML identity provider ({_ROLES})",
        "grant:urn:ietf:params:oauth:grant-type:token-exchange": f"its token endpoint isn't an RFC 8693 "
                                                                f"token-exchange endpoint ({_TOKEN})",
        **{f"grant:urn:ietf:params:oauth:grant-type:{g}": f"its token endpoint takes only the authorization_code, "
                                                          f"refresh_token and client_credentials grants ({_TOKEN})"
           for g in ("device_code", "jwt-bearer", "saml2-bearer")},
        "custom-issuer": f"its issuer is the user pool's own, distinct from its sign-in domain ({_ENDPOINTS})",
        "mfa-per-client": f"MFA is a setting of the user pool, not of an app client ({_API}: SetUserPoolMfaConfig)",
        "claim-transform": "claims beyond the attribute mappings need a pre-token-generation Lambda trigger (Cognito "
                           "ID tokens, attribute mapping, 2026-10)"},
    partition_unsupported={"aws-us-gov": {"custom-domain": f"GovCloud has no custom user pool domains ({_GOV})"}},
    conditions={},
    notes={"aws-us-gov": (
        ("FIPS endpoints", f"Cognito requires its FIPS endpoints there ({_GOV}).",
         "Point every client and SDK at the FIPS endpoints."),
        ("password hashes", "AWS doesn't document whether GovCloud user pools can import password hashes (Cognito "
         "user import guide, 2026-10).",
         "Confirm with AWS before planning a hash import; else users reset, or move just in time through the "
         "user-migration Lambda trigger."),
        ("Pinpoint", f"Cognito's Amazon Pinpoint integration is unavailable there ({_GOV}).",
         "Don't rely on Pinpoint analytics or campaigns from the user pool."))},
    users="Cognito imports users from CSV files (100 MB and 500,000 users each); a user pool on the current "
          "infrastructure also takes password hashes, one algorithm per import job (bcrypt up to cost 12, scrypt, "
          "Argon2id, PBKDF2-SHA256 up to 600,000 iterations), and those users can't use SRP before their first "
          "sign-in; otherwise users reset, or move just in time through the user-migration Lambda trigger (Cognito "
          "user import guide, quotas, just-in-time migration, 2026-10). Plan how users move, and record it.")
MANAGED = (COGNITO,)


# ------------------------------------------------------------------ render
def cognito_bindings(m):
    """Environment m's Cognito user pool bindings."""
    return tuple(b for b in of_class(m, "ciamManagedIdentity") if one(b, "ciamManagedService") == SERVICE)


def _targets(m):
    return tuple(b for b in cognito_bindings(m) if is_target(b) and realized_service(m.d, b) is not None)


def custom_domain(host):
    """Whether a sign-in host is a custom domain (not a prefix of Cognito's own)."""
    return not host.lower().endswith(COGNITO_HOST)


def _served(m, b):
    return served(m.d, realized_service(m.d, b))


def _of(m, b, protocol):
    return tuple(i for i in _served(m, b) if one(i, "ciamProtocolType") == protocol)


def custom_scopes(m, b):
    """The scopes the oidc-client integrations a binding serves ask for beyond OIDC's (offline_access aside: Cognito
    issues refresh tokens without it), each once."""
    return tuple(dict.fromkeys(s for i in _of(m, b, "oidc-client") for s in values(i, "ciamScope")
                               if s not in OIDC_SCOPES and s != "offline_access"))


def _identifier(m, b):
    return one(realized_service(m.d, b), "ciamBaseUrl")


def _mfa(integrations):
    required = [i for i in integrations if one(i, "ciamMfaRequired") == "TRUE"]
    return "OFF" if not required else "ON" if len(required) == len(integrations) else "OPTIONAL"


def _pool(m, b, n):
    mfa = _mfa(_served(m, b))
    return tf_block("resource", ["aws_cognito_user_pool", n], [
        ("name", rdn_value(b)), ("deletion_protection", "ACTIVE"), ("mfa_configuration", mfa),
        *((("software_token_mfa_configuration", Block((("enabled", True),))),) if mfa != "OFF" else ()),
        ("tags", {**binding_tags(b), "Realizes": one(b, "ciamRealizes")})])


def _domain(m, b, n):
    host = one(b, "ciamFqdn")
    if not host:
        return (comment(f"UNBOUND: `{rdn_value(b)}` records no sign-in host (ciamFqdn): no user pool domain"),)
    if not custom_domain(host):
        return (tf_block("resource", ["aws_cognito_user_pool_domain", n], [
            ("domain", host.split(".", 1)[0]), ("user_pool_id", ref(f"aws_cognito_user_pool.{n}.id"))]),)
    if partition(m) == "aws-us-gov":
        return (comment(f"UNBOUND: GovCloud has no custom user pool domains: {host} isn't rendered"),)
    cert = certificate_ref(m, b) or ""
    arn = cert.split("://", 1)[1] if cert.startswith("aws-acm://") else None
    return (tf_block("resource", ["aws_cognito_user_pool_domain", n], [
        ("domain", host), ("user_pool_id", ref(f"aws_cognito_user_pool.{n}.id")),
        *((("certificate_arn", arn),) if arn else
          (("#", "UNBOUND: no ACM certificate holds the domain's certificate (ciamTlsCertificate) here"),))]),)


def _scopes(m, b, i):
    own = values(i, "ciamScope")
    return [*(s for s in own if s in OIDC_SCOPES),
            *(f"{_identifier(m, b)}/{s}" for s in own if s not in OIDC_SCOPES and s != "offline_access")]


def confidential(i):
    """Whether an integration authenticates to Cognito with a client secret (the client is then generated one)."""
    return any(t in SECRET_METHODS for t in values(i, "ciamTokenAuthMethod"))


def _settings(m, b, i, providers):
    """(Terraform argument, CloudFormation property, value) of an app client's settings, absent ones left out: the
    same settings whichever form the client takes."""
    grants = values(i, "ciamGrantType")
    return tuple(x for x in (
        ("allowed_oauth_flows_user_pool_client", "AllowedOAuthFlowsUserPoolClient", True),
        ("allowed_oauth_flows", "AllowedOAuthFlows", [FLOWS[g] for g in grants if g in FLOWS]),
        ("allowed_oauth_scopes", "AllowedOAuthScopes", _scopes(m, b, i)),
        ("callback_urls", "CallbackURLs", list(values(i, "ciamRedirectUri")) or None),
        ("logout_urls", "LogoutURLs", list(values(i, "ciamPostLogoutRedirectUri")) or None),
        ("supported_identity_providers", "SupportedIdentityProviders", ["COGNITO", *providers]),
        ("enable_token_revocation", "EnableTokenRevocation", True),
        ("prevent_user_existence_errors", "PreventUserExistenceErrors", "ENABLED")) if x[2] is not None)


def _client_comments(i):
    dropped = [g for g in values(i, "ciamGrantType") if g not in FLOWS and g != "refresh_token"]
    return (*(("#", f"grant {g} isn't rendered: Cognito's token endpoint doesn't take it (the planner's)")
              for g in dropped),
            *((("#", "offline_access isn't a Cognito scope: refresh tokens come with the code flow"),)
              if "offline_access" in values(i, "ciamScope") else ()))


def client_template(m, b, n, i, providers):
    """The CloudFormation template of a confidential app client: Cognito generates its secret; the only output is its
    client ID, so neither the stack's outputs nor the Terraform state around it ever holds the secret (U.5)."""
    return {"AWSTemplateFormatVersion": "2010-09-09",
            "Description": f"Cognito app client {rdn_value(i)} of user pool {rdn_value(b)} ({m.label}), rendered by "
                           "opsdir: Cognito generates its secret, which no output names",
            "Resources": {"Client": {"Type": "AWS::Cognito::UserPoolClient", "Properties": {
                "ClientName": rdn_value(i), "UserPoolId": ref(f"aws_cognito_user_pool.{n}.id"), "GenerateSecret": True,
                **{prop: v for _, prop, v in _settings(m, b, i, providers)}}}},
            "Outputs": {"ClientId": {"Value": {"Fn::GetAtt": ["Client", "ClientId"]}}}}


def _stack_name(*parts):
    """A CloudFormation stack name of parts: letters, digits and hyphens, starting with a letter, at most 128."""
    return re.sub(r"-+", "-", re.sub(r"[^A-Za-z0-9-]", "-", "-".join(parts))).strip("-")[:128]


def _client(m, b, n, i, providers):
    """A public client as aws_cognito_user_pool_client; a confidential one as a CloudFormation stack (client_template),
    after the resource server and upstream providers its scopes and identity providers name."""
    c = f"{n}_{tf_name(rdn_value(i))}"
    if not confidential(i):
        return tf_block("resource", ["aws_cognito_user_pool_client", c], [
            ("name", rdn_value(i)), ("user_pool_id", ref(f"aws_cognito_user_pool.{n}.id")),
            ("generate_secret", False), *((arg, v) for arg, _, v in _settings(m, b, i, providers)),
            *_client_comments(i)])
    after = [*([ref(f"aws_cognito_resource_server.{n}")] if custom_scopes(m, b) else []),
             *(ref(f"aws_cognito_identity_provider.{n}_{tf_name(rdn_value(p))}") for p in _of(m, b, "saml2-idp"))]
    return tf_block("resource", ["aws_cloudformation_stack", c], [
        ("name", _stack_name("ciam", rdn_value(m.env), rdn_value(b), rdn_value(i), "client")),
        ("template_body", jsonencoded(client_template(m, b, n, i, providers))),
        ("tags", binding_tags(b)), *((("depends_on", after),) if after else ()),
        ("#", "a client secret: Cognito generates it inside this stack, so Terraform state never holds it"),
        *_client_comments(i)])


def _resource_server(m, b, n):
    scopes = custom_scopes(m, b)
    if not scopes:
        return ()
    return (tf_block("resource", ["aws_cognito_resource_server", n], [
        ("identifier", _identifier(m, b)), ("name", one(realized_service(m.d, b), "cn") or rdn_value(b)),
        ("user_pool_id", ref(f"aws_cognito_user_pool.{n}.id")),
        *(("scope", Block((("scope_name", s), ("scope_description", f"{s} (as the record names it)"))))
          for s in scopes)]),)


def _provider_variable(n, p):
    return f"{n}_{tf_name(rdn_value(p))}_metadata_url"


def _providers(m, b, n):
    return tuple(chain.from_iterable((
        tf_block("variable", [_provider_variable(n, p)], [
            ("type", ref("string")),
            ("description", f"The SAML metadata URL of partner identity provider {rdn_value(p)} "
                            f"({one(p, 'ciamEntityId') or 'no entity ID recorded'})")]),
        tf_block("resource", ["aws_cognito_identity_provider", f"{n}_{tf_name(rdn_value(p))}"], [
            ("user_pool_id", ref(f"aws_cognito_user_pool.{n}.id")), ("provider_name", rdn_value(p)[:32]),
            ("provider_type", "SAML"),
            ("provider_details", {"MetadataURL": ref(f"var.{_provider_variable(n, p)}")})]))
        for p in _of(m, b, "saml2-idp")))


def _target(m, b):
    n = tf_name(rdn_value(b))
    upstream = [rdn_value(p)[:32] for p in _of(m, b, "saml2-idp")]
    clients = tuple(_client(m, b, n, i, upstream) for i in _of(m, b, "oidc-client"))
    adopt = (tf_import(f"aws_cognito_user_pool.{n}", one(b, "ciamProviderRef").rsplit("/", 1)[-1]),) \
        if one(b, "ciamProviderRef") else ()
    return (*(comment(note_comment(x)) for x in _notes(m, b)), _pool(m, b, n), *adopt, *_domain(m, b, n),
            *_resource_server(m, b, n), *_providers(m, b, n), *clients,
            *(comment(f"{one(i, 'ciamProtocolType')} integration {rdn_value(i)} isn't rendered: Cognito can't serve "
                      "it (the planner's)") for i in _served(m, b) if one(i, "ciamProtocolType") not in
              ("oidc-client", "saml2-idp")))


def render_cognito(m):
    """HCL for environment m's Cognito user pools the platform runs its identity services on, each stamped with its
    entry (the render places it by its keeper), and a neighbour's note as its comment."""
    return (*(x for b in _targets(m) for x in from_entry(b.dn, _target(m, b))),
            *(comment(note_comment(_neighbour_note(m, b))) for b in cognito_bindings(m) if not is_target(b)))


# ------------------------------------------------------------------ notes
def _notes(m, b):
    """The render notes of a target binding: the scopes applications now request by the resource server's name, and
    the partner metadata URLs to give."""
    scopes, label = custom_scopes(m, b), rdn_value(b)
    idps = _of(m, b, "saml2-idp")
    return (*((note(AREA, "action", f"user pool {label} scopes",
                    f"Cognito names custom scopes after their resource server: applications request "
                    f"{', '.join(f'{_identifier(m, b)}/{s}' for s in scopes)} instead of {', '.join(scopes)}",
                    ("Tell the teams of the applications asking for these scopes to request the new names",),
                    b.dn, m.label),) if scopes else ()),
            *((note(AREA, "action", f"user pool {label} partner metadata",
                    f"Cognito reads a SAML partner's metadata from a URL the record doesn't hold: give "
                    f"{', '.join(f'var.{_provider_variable(tf_name(label), p)}' for p in idps)}",
                    ("Ask each partner for its SAML metadata URL and pass it as the variable when applying",),
                    b.dn, m.label),) if idps else ()),
            *(note(AREA, "action", f"user pool {label} client {rdn_value(i)} secret",
                   f"Cognito generates client {rdn_value(i)}'s secret inside its CloudFormation stack, so no render "
                   "or state holds it",
                   (f"Read it once the stack is applied (aws cognito-idp describe-user-pool-client, the client ID "
                    "from the stack's ClientId output) and store it where the application's secret reference "
                    "points; give the application its client ID",), i.dn, m.label)
              for i in _of(m, b, "oidc-client") if confidential(i)))


def _neighbour_note(m, b):
    keeper = get(m.d, one(b, "ciamManagedBy")) if one(b, "ciamManagedBy") else None
    return note(AREA, "note", f"user pool {rdn_value(b)}",
                f"a neighbour the platform federates with, kept by {rdn_value(keeper) if keeper else 'its owner'}: "
                "not rendered", (f"Record changes its owner makes to it {RECORD}",), b.dn, m.label)


def cognito_notes(m):
    """The render notes of environment m's Cognito user pools: each target's (cognito _notes), and a neighbour's: not
    the platform's to render."""
    return (*chain.from_iterable(_notes(m, b) for b in _targets(m)),
            *(_neighbour_note(m, b) for b in cognito_bindings(m) if not is_target(b)))


# ------------------------------------------------------------------ read back
def _custom(domains, a):
    """The custom domain of a user pool: its own custom_domain (state, the CLI), else the domain with a certificate
    among its aws_cognito_user_pool_domain attributes (a render read back), or None."""
    return a.get("custom_domain") or next((x.get("domain") for x in domains if x.get("certificate_arn")
                                           and x.get("user_pool_id") == a.get("id")), None)


def cognito_resources(pairs):
    """Managed identity resources of (Terraform type, attributes) pairs: a user pool per aws_cognito_user_pool (its
    ARN, else its id), its custom domain, the role and identity service its tags name. Nothing of its clients or
    providers is read (their secrets with them)."""
    domains = of_types(pairs, "aws_cognito_user_pool_domain")
    return tuple(resource("managed-identity", a.get("arn") or a.get("id"), {
        "ciamManagedService": SERVICE, "ciamRealizes": state_tags(a).get("Realizes"),
        "ciamFqdn": _custom(domains, a)},
        name=state_tags(a).get("Name") or a.get("name"), role=tagged_role(state_tags(a)), tags=state_tags(a))
        for a in of_types(pairs, "aws_cognito_user_pool") if a.get("arn") or a.get("id") or a.get("name"))

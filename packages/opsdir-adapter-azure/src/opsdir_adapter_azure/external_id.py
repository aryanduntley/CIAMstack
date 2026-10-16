"""Microsoft Entra External ID (external tenants) as a cloud-managed identity service (core federation domain:
ciamManagedIdentity, flow 66): what the planner knows of it (the ManagedService descriptor, from Microsoft's
documentation, research notes 3078 and 3139, read 2026-10-15 and 2026-10-16), its Terraform render and its render
notes. Pure.

External ID is not a rename of Azure AD B2C: B2C closed to new customers on 2025-05-01 (supported to at least May
2030). External tenants exist in public clouds only: an Azure Government target is blocked by the planner
(connectors.managed_identity), never rendered around. A target binding (ciamRealizes: the identity service it runs)
renders, each block stamped with its entry (hcl.from_entry, so the render places it by its keeper):

  azapi_resource                    the external tenant (Microsoft.AzureActiveDirectory/ciamDirectories at
    (ciamDirectories)                 2023-05-17-preview, the only version Microsoft's template reference and the Bicep
                                      type index have), named by its initial subdomain (the label of its
                                      *.ciamlogin.com sign-in host, else its name's letters and digits) in the
                                      environment's resource group, in its data geography (ciamDataGeography), its
                                      display name and country inputs (set once, when it is created: azapi ignores
                                      what the tenant's GET leaves out); adopted by an import block once its tenant
                                      ID is recorded (ciamProviderRef). Only where the cloud allows the azapi add-on;
                                      else an action to create it by hand
  provider "azuread" (aliased)      the tenant, once its ID is recorded (ciamProviderRef): how Terraform signs in to
                                      it is the operator's (an application registered there), never rendered
  azuread_application +             one per oidc-client integration the identity service serves: its redirect URIs
    azuread_service_principal         (web for a confidential client, public_client for one authenticating with
                                      none), implicit grant off, Microsoft Graph's openid requested (and
                                      offline_access when it refreshes tokens), the service's API scopes it asks for
  azuread_application (the API)     one per identity service whose clients ask for scopes beyond OIDC's: its base URL
                                      as identifier, a delegated scope per name (ids derived from the names: stable)
  azuread_application +             one per saml2-sp integration: Microsoft's custom (non-gallery) application
    azuread_service_principal +       template, its entity ID as identifier URI and its ACS URL as redirect URI, the
    token signing certificate         service principal in SAML mode with a signing certificate Entra makes

Not rendered, as actions: client credentials (azuread_application_password would put the secret in the Terraform
state; a certificate's public key isn't recorded), user flows, upstream identity providers and custom authentication
extensions (azuread has no resource for them; the tenant's Graph configuration reads back through azure/external-id,
external_id_graph). A neighbour (ciamPartnerOf) isn't the platform's to render: a note.
"""
import re
from types import MappingProxyType
from urllib.parse import urlsplit
from uuid import NAMESPACE_URL, uuid5

from opsdir.core.contract import ManagedService
from opsdir.core.directory import get, one, rdn_value, values
from opsdir.core.environment import of_class
from opsdir.core.notes import RECORD, note, note_comment
from opsdir.domains.federation.managed import is_target, realized_service, served
from opsdir_format_terraform.hcl import Block, comment, from_entry, ref, tf_block, tf_import, tf_name
from .account import azapi_allowed, government, tagged
from .identities import GROUP
from .network import binding_tags

SERVICE = "entra-external-id"
AREA = "Identity"
_FAQ = "Microsoft Entra External ID FAQ (updated 2026-05-20)"
_FEATURES = "External ID external tenant features (2026-10)"
_CREDENTIALS = "Microsoft identity platform application credentials (2026-10)"
_AUTH_CODE = "Microsoft identity platform authorization code flow (2026-10)"
_TOKENS = "Microsoft identity platform access tokens (2026-10)"
_DOMAINS = "External ID custom URL domains (2026-10; generally available)"
_MFA = "External ID multifactor authentication for customers (2026-10)"
_CLAIMS = "Microsoft identity platform custom claims provider (2026-10)"


def partition(m):
    """The Azure cloud environment m's cloud is in: usgovernment (Azure Government), else public."""
    return "usgovernment" if government(m) or one(m.cloud, "ciamCloudEnvironment") == "usgovernment" else "public"


EXTERNAL_ID = ManagedService(
    name=SERVICE, title="Microsoft Entra External ID", partition=partition,
    available={"public": f"external tenants, in public clouds ({_FAQ})"},
    absent={"usgovernment": f"external tenants support public clouds only, and Azure AD B2C isn't offered in Azure "
                            f"Government either ({_FAQ}; B2C data residency, 2026-10)"},
    supported={
        "issue:oidc": f"OAuth 2.0 and OIDC with the code flow and PKCE ({_FEATURES})",
        "issue:saml": "SAML applications (registering a SAML app in an external tenant, updated 2025-10-07)",
        "trust:saml": f"upstream identity providers (Microsoft Graph identityProviders; {_FEATURES})",
        "trust:oidc": f"upstream identity providers (Microsoft Graph identityProviders; {_FEATURES})",
        "grant:authorization_code": _FEATURES, "grant:client_credentials": "the client credentials flow (2026-10)",
        "grant:refresh_token": f"refresh tokens of the code flow (offline_access; {_AUTH_CODE})",
        "grant:urn:ietf:params:oauth:grant-type:device_code": f"device authorization ({_FEATURES})",
        "grant:urn:ietf:params:oauth:grant-type:jwt-bearer": f"the on-behalf-of flow ({_FEATURES})",
        "token-auth:none": f"public clients with PKCE ({_FEATURES})",
        "token-auth:client_secret_basic": f"client credentials in the Authorization header ({_AUTH_CODE})",
        "token-auth:client_secret_post": _CREDENTIALS,
        "token-auth:private_key_jwt": f"certificate-based JWT assertions ({_CREDENTIALS})",
        "signing-alg:RS256": f"RSA-signed tokens ({_TOKENS})",
        "custom-domain": f"custom URL domains in front of the tenant (Azure Front Door; {_DOMAINS})",
        "mfa-per-client": f"Conditional Access policies targeting chosen applications ({_MFA})",
        "claim-transform": f"claims from a custom claims provider ({_CLAIMS})"},
    unsupported={"grant:password": f"external tenants don't take resource owner password credentials; native "
                                   f"authentication is the alternative ({_FEATURES})"},
    partition_unsupported={},
    conditions={"grant:client_credentials": "the External ID M2M Premium add-on (client credentials flow, 2026-10)",
                "claim-transform": "a custom authentication extension (OnTokenIssuanceStart) calling a REST API the "
                                   f"customer runs ({_CLAIMS})"},
    notes={"*": (
        ("user flows", "Its user flows and custom authentication extensions (Graph authenticationEventsFlows, "
         "customAuthenticationExtensions) hold sign-up, attribute collection and token enrichment; exporting an "
         "extension doesn't export its remote implementation.",
         "Recreate the sign-in journeys as user flows and say where each extension's implementation runs; the "
         "tenant's Graph configuration reads back into the record (azure/external-id)."),)},
    users="Microsoft Graph creates consumer accounts and their attributes but imports no password hashes: create the "
          "accounts in bulk and have users reset, set known passwords in a controlled migration, or move passwords "
          "just in time through an OnPasswordSubmit custom authentication extension validating against the old store "
          "(External ID user migration, 2026-10); Graph throttles (20 requests a second per IP per tenant). Plan how "
          "users move, and record it.")
MANAGED = (EXTERNAL_ID,)

# ------------------------------------------------------------------ what Microsoft names (read 2026-10-16)
# a binding's data geography (ciamDataGeography, the adapter's vocabulary) -> the tenant's location in ARM
GEOGRAPHIES = MappingProxyType({"united-states": "United States", "europe": "Europe", "asia-pacific": "Asia Pacific",
                                "australia": "Australia"})
TENANT_TYPE = "Microsoft.AzureActiveDirectory/ciamDirectories@2023-05-17-preview"
CIAM_HOST = ".ciamlogin.com"
SAML_TEMPLATE = "8adf8e6e-67b2-4cf2-a259-e3dc5476c621"     # Microsoft's custom (non-gallery) application template
GRAPH = "00000003-0000-0000-c000-000000000000"              # Microsoft Graph's application ID
GRAPH_SCOPES = MappingProxyType({"openid": "37f7f235-527c-4136-accd-4a02d197296e",
                                 "offline_access": "7427e0e9-2fba-42fe-b0c0-848c9e6a8182"})
OIDC_SCOPES = ("openid", "profile", "email", "offline_access")    # what a client asks of Entra itself, not an API


def external_id_bindings(m):
    """Environment m's Entra External ID bindings."""
    return tuple(b for b in of_class(m, "ciamManagedIdentity") if one(b, "ciamManagedService") == SERVICE)


def _targets(m):
    """Environment m's External ID targets running an identity service the record holds, in a public cloud."""
    return tuple(b for b in external_id_bindings(m) if is_target(b) and realized_service(m.d, b) is not None
                 and partition(m) == "public")


def tenant_name(b):
    """The initial subdomain of a binding's external tenant (its ARM resource name): the label of its *.ciamlogin.com
    sign-in host, else its name's letters and digits (at most 26)."""
    host = (one(b, "ciamFqdn") or "").lower()
    return host[:-len(CIAM_HOST)] if host.endswith(CIAM_HOST) else re.sub(r"[^a-z0-9]", "", rdn_value(b).lower())[:26]


def renders_tenant(m):
    """Whether environment m's render writes an external tenant (azapi: the cloud allows the add-on)."""
    return azapi_allowed(m) and bool(_targets(m))


def renders_applications(m):
    """Whether environment m's render writes app registrations (azuread): a target whose tenant ID is recorded."""
    return any(one(b, "ciamProviderRef") for b in _targets(m))


def _of(m, b, protocol):
    return tuple(i for i in served(m.d, realized_service(m.d, b)) if one(i, "ciamProtocolType") == protocol)


def custom_scopes(m, b):
    """The scopes the oidc-client integrations a target serves ask for beyond OIDC's, each once: its API's."""
    return tuple(dict.fromkeys(s for i in _of(m, b, "oidc-client") for s in values(i, "ciamScope")
                               if s not in OIDC_SCOPES))


def scope_id(service, scope):
    """The stable id of an identity service's API scope (derived from its base URL and the scope's name)."""
    return str(uuid5(NAMESPACE_URL, f"{one(service, 'ciamBaseUrl')}#{scope}"))


def confidential(i):
    """Whether an oidc-client integration authenticates at the token endpoint (a credential to give it)."""
    return any(t != "none" for t in values(i, "ciamTokenAuthMethod")) or not values(i, "ciamTokenAuthMethod")


# ------------------------------------------------------------------ render
def _tenant(m, b, n):
    if not azapi_allowed(m):
        return ()
    geo = one(b, "ciamDataGeography")
    inputs = ((f"{n}_display_name", f"The display name of external tenant {rdn_value(b)} (set when it is created)"),
              (f"{n}_country_code", f"The two-letter country code of external tenant {rdn_value(b)} (set when it is "
                                    "created)"))
    adopt = (tf_import(f"azapi_resource.{n}", f"{GROUP}/providers/{TENANT_TYPE.split('@')[0]}/{tenant_name(b)}"),) \
        if one(b, "ciamProviderRef") else ()
    return (*(tf_block("variable", [v], [("type", ref("string")), ("description", d)]) for v, d in inputs),
            tf_block("resource", ["azapi_resource", n], [
                ("type", TENANT_TYPE), ("name", tenant_name(b)),
                ("parent_id", ref("data.azurerm_resource_group.main.id")),
                ("location", GEOGRAPHIES[geo]) if geo in GEOGRAPHIES else
                ("#", "UNBOUND: the binding records no data geography (ciamDataGeography)"),
                ("body", {"sku": {"name": "Standard", "tier": "A0"}, "properties": {"createTenantProperties": {
                    "displayName": ref(f"var.{inputs[0][0]}"), "countryCode": ref(f"var.{inputs[1][0]}")}}}),
                ("tags", tagged(m, {**binding_tags(b), "Realizes": one(b, "ciamRealizes")}))]),
            *adopt)


def _api(m, b, n):
    """The identity service's API application holding the scopes its clients ask for beyond OIDC's, or ()."""
    service, scopes = realized_service(m.d, b), custom_scopes(m, b)
    if not scopes:
        return ()
    return (tf_block("resource", ["azuread_application", f"{n}_api"], [
        ("provider", ref(f"azuread.{n}")), ("display_name", f"{rdn_value(service)} API"),
        ("sign_in_audience", "AzureADMyOrg"), ("identifier_uris", [one(service, "ciamBaseUrl")]),
        ("api", Block((("requested_access_token_version", 2),
                       *(("oauth2_permission_scope", Block((
                           ("id", scope_id(service, s)), ("value", s), ("type", "User"), ("enabled", True),
                           ("admin_consent_display_name", s),
                           ("admin_consent_description", f"{s} (as the record names it)")))) for s in scopes))))]),)


def _access(m, b, n, i):
    own = values(i, "ciamScope")
    graph = [s for s in ("openid", "offline_access") if s == "openid" or s in own
             or "refresh_token" in values(i, "ciamGrantType")]
    api = [s for s in own if s not in OIDC_SCOPES]
    service = realized_service(m.d, b)
    return (("required_resource_access", Block((
                ("resource_app_id", GRAPH),
                *(("resource_access", Block((("id", GRAPH_SCOPES[s]), ("type", "Scope")))) for s in graph)))),
            *((("required_resource_access", Block((
                ("resource_app_id", ref(f"azuread_application.{n}_api.client_id")),
                *(("resource_access", Block((("id", scope_id(service, s)), ("type", "Scope")))) for s in api)))),)
              if api else ()))


def hostless(uri):
    """Whether a redirect URI has no host (com.example.app:/cb, RFC 8252's private-use form): azuread refuses it."""
    return not urlsplit(uri).hostname


def _client(m, b, n, i):
    a = f"{n}_{tf_name(rdn_value(i))}"
    uris = [u for u in values(i, "ciamRedirectUri") if not hostless(u)]
    refused = [u for u in values(i, "ciamRedirectUri") if hostless(u)]
    where = Block((("redirect_uris", uris), ("implicit_grant", Block((("access_token_issuance_enabled", False),
                                                                        ("id_token_issuance_enabled", False)))))) \
        if confidential(i) else Block((("redirect_uris", uris),))
    return (tf_block("resource", ["azuread_application", a], [
                ("provider", ref(f"azuread.{n}")), ("display_name", rdn_value(i)),
                ("sign_in_audience", "AzureADMyOrg"), ("web" if confidential(i) else "public_client", where),
                *(("#", f"redirect URI {u} has no host, which azuread refuses: register it in the tenant by hand")
                  for u in refused),
                *_access(m, b, n, i)]),
            tf_block("resource", ["azuread_service_principal", a], [
                ("provider", ref(f"azuread.{n}")), ("client_id", ref(f"azuread_application.{a}.client_id"))]))


def _saml(n, i):
    a = f"{n}_{tf_name(rdn_value(i))}"
    return (tf_block("resource", ["azuread_application", a], [
                ("provider", ref(f"azuread.{n}")), ("display_name", rdn_value(i)), ("template_id", SAML_TEMPLATE),
                *((("identifier_uris", [one(i, "ciamEntityId")]),) if one(i, "ciamEntityId") else ()),
                *((("web", Block((("redirect_uris", [one(i, "ciamAcsUrl")]),))),) if one(i, "ciamAcsUrl") else ())]),
            tf_block("resource", ["azuread_service_principal", a], [
                ("provider", ref(f"azuread.{n}")), ("client_id", ref(f"azuread_application.{a}.client_id")),
                ("use_existing", True), ("preferred_single_sign_on_mode", "saml")]),
            tf_block("resource", ["azuread_service_principal_token_signing_certificate", a], [
                ("provider", ref(f"azuread.{n}")),
                ("service_principal_id", ref(f"azuread_service_principal.{a}.id"))]))


def _applications(m, b, n):
    if not one(b, "ciamProviderRef"):
        return ()
    others = [i for i in served(m.d, realized_service(m.d, b))
              if one(i, "ciamProtocolType") not in ("oidc-client", "saml2-sp", "saml2-idp")]
    return (*_api(m, b, n), *(x for i in _of(m, b, "oidc-client") for x in _client(m, b, n, i)),
            *(x for i in _of(m, b, "saml2-sp") for x in _saml(n, i)),
            *(comment(f"{one(i, 'ciamProtocolType')} integration {rdn_value(i)} isn't rendered: an external tenant "
                      "can't serve it (the planner's)") for i in others))


def external_id_providers(m):
    """The aliased azuread provider of each External ID target whose tenant ID is recorded (its providers.tf: the
    placement leaves it out of the roots that don't use it)."""
    return tuple(tf_block("provider", ["azuread"], [("alias", tf_name(rdn_value(b))),
                                                    ("tenant_id", one(b, "ciamProviderRef"))])
                 for b in _targets(m) if one(b, "ciamProviderRef"))


def _target(m, b):
    n = tf_name(rdn_value(b))
    return (*(comment(note_comment(x)) for x in _target_notes(m, b)), *_tenant(m, b, n), *_applications(m, b, n))


def render_external_id(m):
    """HCL for environment m's External ID targets (the tenant, its app registrations), each stamped with its entry,
    their notes as comments, and a neighbour's note as its comment."""
    return (*(x for b in _targets(m) for x in from_entry(b.dn, _target(m, b))),
            *(comment(note_comment(n)) for b in external_id_bindings(m) if b not in _targets(m)
              for n in _other_notes(m, b)))


# ------------------------------------------------------------------ notes
def _returns(i):
    return ", ".join((*values(i, "ciamRedirectUri"), *values(i, "ciamAcsUrl"))) or "no return URL"


def _tenant_note(m, b):
    label = rdn_value(b)
    if one(b, "ciamProviderRef"):
        return ()
    if not azapi_allowed(m):
        return (note(AREA, "action", f"external tenant {label}",
                     "the external tenant isn't rendered (the cloud doesn't allow the azapi add-on): create it by hand "
                     "and record its tenant ID; its app registrations render then",
                     ("Create the external tenant (public cloud) in the environment's resource group, or allow the "
                      "azapi add-on (ciamProviderAddOn azapi)",
                      f"Record its tenant ID as the binding's ciamProviderRef {RECORD}"), b.dn, m.label),)
    return (note(AREA, "action", f"external tenant {label}",
                 f"the external tenant renders through a preview API ({TENANT_TYPE}); its app registrations render "
                 "once its tenant ID is recorded",
                 ("Apply it as an identity with the Tenant Creator role on the resource group (Microsoft's pricing "
                  "page asks Contributor there for the billing link: grant both until a live run settles it)",
                  "Record the tenant ID it reports (properties.tenantId of the resource, or the tenant's overview) "
                  f"as the binding's ciamProviderRef {RECORD}"),
                 b.dn, m.label),)


def _registrations_note(m, b):
    service = realized_service(m.d, b)
    apps = tuple(f"{rdn_value(i)} ({one(i, 'ciamProtocolType')}: {_returns(i)})" for i in served(m.d, service)
                 if one(i, "ciamProtocolType") in ("oidc-client", "saml2-sp"))
    if one(b, "ciamProviderRef") or not apps:
        return ()
    return (note(AREA, "action", f"external tenant {rdn_value(b)} applications",
                 f"the app registrations of `{rdn_value(service)}` render once the tenant ID is recorded: "
                 f"{', '.join(apps)}", ("Record the tenant ID (ciamProviderRef) and re-render",), b.dn, m.label),)


def _credentials_note(m, b):
    clients = tuple(i for i in _of(m, b, "oidc-client") if confidential(i))
    if not one(b, "ciamProviderRef") or not clients:
        return ()
    how = tuple(f"{rdn_value(i)}: upload the public key of the certificate it signs its assertions with" if
                "private_key_jwt" in values(i, "ciamTokenAuthMethod") else
                f"{rdn_value(i)}: create its client secret and store it where the application reads it"
                for i in clients)
    return (note(AREA, "action", f"external tenant {rdn_value(b)} credentials",
                 "client credentials aren't rendered (a client secret made by Terraform sits in its state): give "
                 f"{', '.join(rdn_value(i) for i in clients)} theirs in the tenant by hand", how, b.dn, m.label),)


def _journeys_note(m, b):
    partners = _of(m, b, "saml2-idp")
    saml = _of(m, b, "saml2-sp")
    return (note(AREA, "action", f"external tenant {rdn_value(b)} user flows",
                 "user flows, upstream identity providers and custom authentication extensions aren't rendered "
                 "(azuread has no resource for them): set them up in the tenant, then read them back "
                 "(azure/external-id)",
                 ("Create the sign-up and sign-in user flows and add each application to one"
                  + (" (a SAML application needs one: " + ", ".join(rdn_value(i) for i in saml) + ")" if saml else ""),
                  *((f"Federate with the upstream identity providers: {', '.join(rdn_value(p) for p in partners)}",)
                    if partners else ()),
                  "Read the tenant's configuration back with `opsdir collect --adapter azure` (external-id)"),
                 b.dn, m.label),)


def _target_notes(m, b):
    return (*_tenant_note(m, b), *_registrations_note(m, b), *_credentials_note(m, b), *_journeys_note(m, b))


def _neighbour_note(m, b):
    keeper = get(m.d, one(b, "ciamManagedBy")) if one(b, "ciamManagedBy") else None
    return note(AREA, "note", f"external tenant {rdn_value(b)}",
                f"a neighbour the platform federates with, kept by {rdn_value(keeper) if keeper else 'its owner'}: "
                "not rendered", (f"Record changes its owner makes to it {RECORD}",), b.dn, m.label)


def _other_notes(m, b):
    """The notes of a binding that renders nothing: a neighbour's; a target outside a public cloud or realizing no
    identity service the record holds renders nothing either (the planner's)."""
    return (_neighbour_note(m, b),) if not is_target(b) else ()


def external_id_notes(m):
    """The render notes of environment m's Entra External ID bindings: each target's (the tenant, its app
    registrations, its credentials and user flows: actions) and a neighbour's (not the platform's to render)."""
    return tuple(n for b in external_id_bindings(m)
                 for n in (_target_notes(m, b) if b in _targets(m) else _other_notes(m, b)))

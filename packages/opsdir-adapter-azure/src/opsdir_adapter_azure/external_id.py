"""Microsoft Entra External ID (external tenants) as a cloud-managed identity service (core federation domain:
ciamManagedIdentity, flow 63): what the planner knows of it (the ManagedService descriptor, from Microsoft's
documentation, research note 3078, read 2026-10-15) and its render notes. Pure.

External ID is not a rename of Azure AD B2C: B2C closed to new customers on 2025-05-01 (supported to at least May
2030). External tenants exist in public clouds only: an Azure Government target is blocked by the planner
(connectors.managed_identity), never rendered around. Nothing of an external tenant is rendered yet (a later
milestone: its app registrations through hashicorp/azuread against the tenant, the tenant itself): a target binding
(ciamRealizes) is an action naming what to create by hand, a neighbour (ciamPartnerOf) a note.
"""
from opsdir.core.contract import ManagedService
from opsdir.core.directory import get, one, rdn_value, values
from opsdir.core.environment import of_class
from opsdir.core.notes import RECORD, note
from opsdir.domains.federation.managed import is_target, realized_service, served
from .account import government

SERVICE = "entra-external-id"
AREA = "Identity"
_FAQ = "Microsoft Entra External ID FAQ (updated 2026-05-20)"
_FEATURES = "External ID external tenant features (2026-10)"
_CREDENTIALS = "Microsoft identity platform application credentials (2026-10)"


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
        "token-auth:none": f"public clients with PKCE ({_FEATURES})",
        "token-auth:client_secret_post": _CREDENTIALS,
        "token-auth:private_key_jwt": f"certificate-based JWT assertions ({_CREDENTIALS})"},
    unsupported={},
    partition_unsupported={},
    conditions={"grant:client_credentials": "the External ID M2M Premium add-on (client credentials flow, 2026-10)"},
    notes={"*": (
        ("user flows", "Its user flows and custom authentication extensions (Graph authenticationEventsFlows, "
         "customAuthenticationExtensions) hold sign-up, attribute collection and token enrichment; exporting an "
         "extension doesn't export its remote implementation.",
         "Recreate the sign-in journeys as user flows, and record where each extension's implementation runs."),)},
    users="Microsoft Graph creates consumer accounts and their attributes but imports no password hashes: create the "
          "accounts in bulk and have users reset, set known passwords in a controlled migration, or move passwords "
          "just in time through an OnPasswordSubmit custom authentication extension validating against the old store "
          "(External ID user migration, 2026-10); Graph throttles (20 requests a second per IP per tenant). Plan how "
          "users move, and record it.")
MANAGED = (EXTERNAL_ID,)


def external_id_bindings(m):
    """Environment m's Entra External ID bindings."""
    return tuple(b for b in of_class(m, "ciamManagedIdentity") if one(b, "ciamManagedService") == SERVICE)


def _apps(m, service):
    """'name (protocol: where it returns)' for each integration an identity service serves, in record order."""
    return tuple(f"{rdn_value(i)} ({one(i, 'ciamProtocolType')}: "
                 f"{', '.join((*values(i, 'ciamRedirectUri'), *values(i, 'ciamAcsUrl'))) or 'no return URL'})"
                 for i in served(m.d, service))


def _target_note(m, b):
    service, label = realized_service(m.d, b), rdn_value(b)
    name = rdn_value(service) if service is not None else one(b, "ciamRealizes")
    apps = _apps(m, service) if service is not None else ()
    return note(AREA, "action", f"external tenant {label}",
                f"Entra External ID isn't rendered: the external tenant running `{name}` and its app registrations "
                f"are created by hand ({', '.join(apps) or 'no integrations served'})",
                ("Create the external tenant (public cloud) and record its tenant ID as the binding's ciamProviderRef "
                 f"{RECORD}",
                 *(f"Register {a} in it" for a in apps),
                 "Set up its user flows and the upstream identity providers its partner integrations need"),
                b.dn, m.label)


def _neighbour_note(m, b):
    keeper = get(m.d, one(b, "ciamManagedBy")) if one(b, "ciamManagedBy") else None
    return note(AREA, "note", f"external tenant {rdn_value(b)}",
                f"a neighbour the platform federates with, kept by {rdn_value(keeper) if keeper else 'its owner'}: "
                "not rendered", (f"Record changes its owner makes to it {RECORD}",), b.dn, m.label)


def external_id_notes(m):
    """The render notes of environment m's Entra External ID bindings: a target's what to create by hand (an action),
    a neighbour's not the platform's to render (a note)."""
    return tuple(_target_note(m, b) if is_target(b) else _neighbour_note(m, b) for b in external_id_bindings(m))

"""Cloud-managed identity services (ciamManagedIdentity bindings): what each one is to the platform and what the
platform's use of it needs, as capabilities an adapter's ManagedService descriptor says the vendor supports, doesn't
support, or doesn't establish. Pure.

Two dimensions, kept apart. Target or neighbour: a binding that realizes one of the platform's identity services
(ciamRealizes, the service's name) runs it on the managed service in that environment; one that is the partner side of
integrations (ciamPartnerOf) is a neighbour the platform federates with. Issuer or relying party follows from the
integrations' protocol types, never stored: a target issues to the oidc-client and saml2-sp integrations it serves
and relies on the saml2-idp ones; a neighbour relies on the platform when it is the partner of an oidc-client or
saml2-sp integration and issues to it when it is the partner of a saml2-idp one.

Capabilities: issue:oidc, issue:saml (to applications and service providers), trust:oidc, trust:saml (of upstream
providers), ldap, grant:<grant type>, token-auth:<method>, dpop-bound, pkce-required, signing-alg:<alg>,
custom-domain, custom-issuer, mfa-per-client, claim-transform.
"""
import re

from ...core.directory import children, get, one, rdn_value, subtree, values
from ...core.environment import environment_of, of_class
from ...core.naming import branch, env_label
from .naming import IDENTITY_SERVICES
from .services import integrations_served

MANAGED_CLASS = "ciamManagedIdentity"
MANAGED_HEADERS = ("environment", "binding", "service", "as", "realizes / partner of", "issuer to", "relying party of",
                   "kept by", "resource")
# what an integration of a protocol type needs of a target serving it, and of a neighbour that is its partner side
AS_TARGET = {"oidc-client": "issue:oidc", "saml2-sp": "issue:saml", "saml2-idp": "trust:saml", "ldap": "ldap"}
AS_PARTNER = {"oidc-client": "trust:oidc", "saml2-sp": "trust:saml", "saml2-idp": "issue:saml", "ldap": "ldap"}
ISSUED_TO = ("oidc-client", "saml2-sp")       # a target issues to these; a neighbour partner of these relies on us
# published URLs of an identity service whose host a managed service must keep: the base URL and entity ID by a custom
# domain, the issuer by a custom issuer
HOST_CAPABILITY = (("ciamBaseUrl", "custom-domain"), ("ciamEntityId", "custom-domain"),
                   ("ciamOidcIssuer", "custom-issuer"))
WORDS = {"issue:oidc": "issue tokens to OIDC clients", "issue:saml": "act as a SAML identity provider to service "
         "providers", "trust:oidc": "rely on an upstream OpenID provider", "trust:saml": "rely on an upstream SAML "
         "identity provider", "ldap": "serve LDAP", "dpop-bound": "bind access tokens to DPoP proofs (RFC 9449)",
         "pkce-required": "require PKCE of a client", "custom-domain": "serve sign-in at a custom domain",
         "custom-issuer": "issue tokens under a custom issuer", "mfa-per-client": "require MFA for some applications "
         "only", "claim-transform": "transform claim values per application"}
SUPPORTED, UNSUPPORTED, UNESTABLISHED = "supported", "unsupported", "not established"
GRANT_URN = "urn:ietf:params:oauth:grant-type:"         # an extension grant's URN prefix (its name follows)


def managed_identities(m):
    """Environment m's managed identity service bindings."""
    return of_class(m, MANAGED_CLASS)


def is_target(b):
    """Whether a binding runs one of the platform's identity services (ciamRealizes)."""
    return one(b, "ciamRealizes") is not None


def realized_service(d, b):
    """The identity service a target binding realizes, or None (a neighbour, or a name no identity service has)."""
    name = one(b, "ciamRealizes")
    return get(d, f"cn={name},{IDENTITY_SERVICES}") if name else None


def realizing(m, service):
    """Environment m's binding realizing an identity service, or None."""
    return next((b for b in managed_identities(m) if one(b, "ciamRealizes") == rdn_value(service)), None)


def partners(d, b):
    """The integrations a neighbour binding is the partner side of (those the record holds), in record order."""
    return tuple(i for i in (get(d, x) for x in values(b, "ciamPartnerOf")) if i is not None)


def words(capability):
    """A capability in words: what the service would have to do."""
    kind, _, value = capability.partition(":")
    if capability in WORDS:
        return WORDS[capability]
    if kind == "grant":
        return f"accept the {value.replace(GRANT_URN, '')} grant"
    if kind == "token-auth":
        return f"authenticate clients by {value}"
    return f"sign tokens with {value}" if kind == "signing-alg" else capability


def slug(capability):
    """A capability as a name part: lower case, a grant URN by its grant type."""
    short = capability.replace(GRANT_URN, "")
    return re.sub(r"[^a-z0-9]+", "-", short.lower()).strip("-")


def integration_needs(i, as_partner=False):
    """The capabilities an integration needs of the managed service serving it (or, as_partner, of the neighbour that is
    its partner side), in order: its protocol, then (served) its grants, token authentication, DPoP and PKCE."""
    protocol = (AS_PARTNER if as_partner else AS_TARGET).get(one(i, "ciamProtocolType"), "ldap")
    if as_partner:
        return (protocol,)
    return (protocol, *(f"grant:{g}" for g in values(i, "ciamGrantType")),
            *(f"token-auth:{t}" for t in values(i, "ciamTokenAuthMethod")),
            *(("dpop-bound",) if one(i, "ciamDpopBound") == "TRUE" else ()),
            *(("pkce-required",) if one(i, "ciamPkceRequired") == "TRUE" else ()))


def service_needs(service):
    """The capabilities an identity service's own settings need: its signing algorithms."""
    return tuple(f"signing-alg:{a}" for a in values(service, "ciamSigningAlg"))


def status(spec, partition, capability):
    """(status, source) of a capability on a managed service in a partition: unsupported where the partition or the
    service is documented to lack it, supported where documented, else not established (None)."""
    lacking = spec.partition_unsupported.get(partition, {})
    if capability in lacking:
        return UNSUPPORTED, lacking[capability]
    if capability in spec.unsupported:
        return UNSUPPORTED, spec.unsupported[capability]
    if capability in spec.supported:
        return SUPPORTED, spec.supported[capability]
    return UNESTABLISHED, None


def availability(spec, partition):
    """(status, source) of a managed service existing in a partition."""
    if partition in spec.absent:
        return UNSUPPORTED, spec.absent[partition]
    if partition in spec.available:
        return SUPPORTED, spec.available[partition]
    return UNESTABLISHED, None


def served(d, service):
    """The integrations an identity service serves (those registered with it, and with none)."""
    return integrations_served(d, (service,))


def mfa_split(integrations):
    """The integrations requiring MFA when the others don't (some do, some don't), else ()."""
    required = tuple(i for i in integrations if one(i, "ciamMfaRequired") == "TRUE")
    return required if required and len(required) < len(integrations) else ()


def transforms(d, integrations):
    """The integrations releasing a claim with a transformation (ciamTransform)."""
    return tuple(i for i in integrations if any(one(c, "ciamTransform") for c in children(d, f"ou=claims,{i.dn}",
                                                                                          "ciamClaimMap")))


def roles(d, b):
    """(issuer to, relying party of): the integration names a binding issues to and relies on, derived from their
    protocol types (a target's served integrations; a neighbour's partner integrations, seen from its side)."""
    if is_target(b):
        service = realized_service(d, b)
        found = served(d, service) if service is not None else ()
        return (tuple(rdn_value(i) for i in found if one(i, "ciamProtocolType") in ISSUED_TO),
                tuple(rdn_value(i) for i in found if one(i, "ciamProtocolType") == "saml2-idp"))
    found = partners(d, b)
    return (tuple(rdn_value(i) for i in found if one(i, "ciamProtocolType") == "saml2-idp"),
            tuple(rdn_value(i) for i in found if one(i, "ciamProtocolType") in ISSUED_TO))


def managed_rows(d, dn=None):
    """One row per managed identity service binding of every environment: the service, target or neighbour, what it
    realizes or is the partner of, whom it issues to and relies on, who keeps it, its resource."""
    def row(b):
        issuer_to, relies_on = roles(d, b)
        keeper = get(d, one(b, "ciamManagedBy")) if one(b, "ciamManagedBy") else None
        return (env_label(environment_of(b)), rdn_value(b), one(b, "ciamManagedService"),
                "target" if is_target(b) else "neighbour",
                one(b, "ciamRealizes") or ", ".join(rdn_value(i) for i in partners(d, b)),
                ", ".join(issuer_to), ", ".join(relies_on), rdn_value(keeper) if keeper is not None else "platform",
                one(b, "ciamProviderRef") or "")
    return sorted(row(b) for b in subtree(d, branch("environments"), MANAGED_CLASS))

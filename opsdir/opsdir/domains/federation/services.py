"""Federation domain lookups every product adapter and standard base reads: the integrations by protocol, the claims
an integration releases, and the platform's own identity services."""
from ...core.directory import children, follow, norm_dn, one, values
from .naming import IDENTITY_SERVICES, INTEGRATIONS


def integrations(d, protocol=None):
    """Integrations in DN order, optionally only those of one protocol type (saml2-sp, oidc-client, saml2-idp, ...)."""
    return tuple(i for i in children(d, INTEGRATIONS, "ciamIntegration")
                 if protocol is None or one(i, "ciamProtocolType") == protocol)


def serves(service, i):
    """Whether an identity service serves an integration: the one it is registered with (ciamServedBy), or any when
    it names none."""
    served_by = one(i, "ciamServedBy")
    return served_by is None or norm_dn(served_by) == service.norm


def integrations_served(d, services, protocol=None):
    """The integrations some of these identity services serve (and those registered with none), in DN order."""
    return tuple(i for i in integrations(d, protocol)
                 if one(i, "ciamServedBy") is None or any(serves(s, i) for s in services))


def claims(d, i):
    """(claim name, user-directory attribute name, transform or None) for every claim the integration releases."""
    return tuple((one(c, "ciamClaimName"), one(follow(d, c, "ciamSourceAttribute"), "ciamLdapName"),
                  one(c, "ciamTransform"))
                 for c in children(d, f"ou=claims,{i.dn}", "ciamClaimMap"))


def identity_services(d, target_roles=None):
    """The platform's identity services in DN order; with target_roles, only those served by servers of those roles
    (so each product renders the services it serves)."""
    return tuple(s for s in children(d, IDENTITY_SERVICES, "ciamIdentityService")
                 if target_roles is None or one(s, "ciamTargetRole") in target_roles)


def endpoint(service, path):
    """An endpoint URL of an identity service: its public base URL and a product's path."""
    return one(service, "ciamBaseUrl").rstrip("/") + path


def in_order(standard, found):
    """The values found, in the standard's order, each once."""
    present = set(found)
    return tuple(v for v in standard if v in present)


def union(entries, attr):
    """Every value of attr over the entries, first appearance first."""
    return tuple(dict.fromkeys(v for e in entries for v in values(e, attr)))

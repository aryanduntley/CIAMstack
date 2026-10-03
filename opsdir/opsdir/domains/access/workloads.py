"""The identities an environment's renderers write, and what the cloud adapters' renderers share. Pure.

Workloads: each workload principal some server of the environment runs as (its ciamTargetRole). For the landing zone
(terraform/landing-zone/, applied by whoever keeps it): each deployer principal whose identity the environment binds
with an OIDC trust (ciamTrustedBy '<issuer URL> <subject>': a CI pipeline), and each operator principal whose identity
binding names the group it is granted to (its provider ref). For each: the cloud identity's name, and for each permit
the binding and the cloud's table row that grant it there. A permit whose role the environment doesn't bind, or that
the cloud's table has no row for, can't be granted: it is a note the renderer writes as a comment, so nothing is
silently left out.
"""
from collections import namedtuple

from ...core.directory import get, one, rdn_value, values
from ...core.environment import of_class, one_role, servers_with_role
from ...core.findings import responsible
from .grants import rows_for
from .principals import permits, principals

# kind: the principal's kind; trust: (issuer, subject) of a deployer's OIDC trust; group: an operator's group (the
# identity binding's provider ref); conditions: the principal's (jit: granted eligible, not active)
WorkloadIdentity = namedtuple("WorkloadIdentity", ("principal", "identity_role", "server_role", "name", "grants",
                                                   "notes", "kind", "trust", "group", "conditions"),
                              defaults=("workload", None, None, ()))


def identity_name(m, role, default):
    """The name of the cloud identity a role names in environment m: the last part of its binding's provider ref (an
    IAM role's name, a resource ID's last segment, a service account's account id), else default."""
    b = one_role(m, role)
    ref = one(b, "ciamProviderRef") if b is not None else None
    return ref.rsplit("/", 1)[-1].split("@", 1)[0] if ref else default


def _grant(m, model, permit):
    """((permit, binding, row), None) when the cloud can grant a permit in m, else (None, why not)."""
    verb, _, role = permit.partition(" ")
    b = one_role(m, role)
    rows = rows_for(model, b, verb) if b is not None else ()
    if b is None:
        return None, f"{permit}: role `{role}` has no binding in this environment"
    return ((permit, b, rows[0]), None) if rows else (None, f"{permit}: this cloud has no mapping for it")


def oidc_trust(binding):
    """(issuer URL, subject) of an identity binding's OIDC trust ('<issuer URL> <subject>'), or None."""
    trust = next((v for v in values(binding, "ciamTrustedBy") if v.startswith("https://") and " " in v), None)
    return tuple(trust.split(" ", 1)) if trust else None


def _identity(m, model, p, default, named=True, **extra):
    done = [_grant(m, model, x) for x in permits(m.d, p)]
    role = one(p, "ciamIdentityRole")
    return WorkloadIdentity(rdn_value(p), role, one(p, "ciamTargetRole"),
                            identity_name(m, role, default) if named else default,
                            tuple(g for g, _ in done if g), tuple(n for _, n in done if n),
                            one(p, "ciamPrincipalKind"), conditions=tuple(values(p, "ciamCondition")), **extra)


def workload_identities(m, model):
    """The workload principals environment m's servers run as, each with what its permits need there."""
    return tuple(_identity(m, model, p, f"ciam-{rdn_value(m.env)}-{one(p, 'ciamTargetRole')}")
                 for p in principals(m.d) if one(p, "ciamPrincipalKind") == "workload"
                 and one(p, "ciamTargetRole") and servers_with_role(m, one(p, "ciamTargetRole")))


def landing_identities(m, model):
    """(deployers, operators) environment m's landing zone grants: deployer principals whose identity m binds with an
    OIDC trust, operator principals whose identity binding names their group."""
    def bound(p):
        return one_role(m, one(p, "ciamIdentityRole"))
    deployers = tuple(_identity(m, model, p, f"ciam-{rdn_value(m.env)}-{rdn_value(p)}", trust=oidc_trust(bound(p)))
                      for p in principals(m.d) if one(p, "ciamPrincipalKind") == "deployer"
                      and bound(p) is not None and oidc_trust(bound(p)))
    operators = tuple(_identity(m, model, p, f"ciam-{rdn_value(m.env)}-{rdn_value(p)}", named=False,
                                group=one(bound(p), "ciamProviderRef"))         # the provider ref is the group
                      for p in principals(m.d) if one(p, "ciamPrincipalKind") in ("operator", "break-glass")
                      and bound(p) is not None and one(bound(p), "ciamIdentityKind") in ("group", "permission-set"))
    return deployers, operators


def landing_zone_owner(m):
    """Who keeps environment m's landing zone: the owners of its guardrails, else of its cloud, else of m."""
    return responsible(m.d, *of_class(m, "ciamGuardrail"), m.cloud, m.env)


def landing_zone_party(m):
    """The party entry that keeps environment m's landing zone (as landing_zone_owner finds it), or None."""
    owned = next((e for e in (*of_class(m, "ciamGuardrail"), m.cloud, m.env) if values(e, "ciamOwner")), None)
    return get(m.d, values(owned, "ciamOwner")[0]) if owned is not None else None


def identity_of(identities, server_role):
    """The workload identity servers of a role run as, or None."""
    return next((w for w in identities if w.server_role == server_role), None)

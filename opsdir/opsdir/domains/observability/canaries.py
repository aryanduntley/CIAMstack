"""What a cloud renders of an environment's synthetic checks, cloud-neutral (each cloud adapter maps it to its own
checks). Pure.

A canary (ciamCanary) the environment can run (it binds the canary's checked service, ciamCheckedService) is rendered
as the cloud's synthetic check named as the canary binding realizing it (ciamCanaryBinding, ciamRealizes), else as
the canary. Its URL: https:// the service name's ciamFqdn (its ciamPort when not 443) and the path the service's
products serve for the flow (core.contract.Endpoint, through the edge's policies: health -> health, login-page ->
login, oidc-token -> token), when that path is concrete (no '*'). Its credentials: the first of its ciamUsesRole bound
here (a secret reference read at run time, never rendered). Not rendered, and said so: a flow that isn't one HTTP
request the record can describe (saml-sso needs a service provider to start from, ldap-bind isn't HTTP, other), an
oidc-token check without credentials, a path the products don't name; a check someone else keeps, or an overlay
inherits from its base (rendered there), is named with its keeper. A canary whose service the environment doesn't
bind is the planner's blocker, not a renderer's concern.
"""
from collections import namedtuple

from ...core.directory import one, rdn_value, values
from ...core.environment import of_class, one_role
from ...core.inventory import duration_seconds
from ..edge.policies import policy_for
from ..edge.resolve import declared_endpoints
from .alerts import canaries
from .realized import keeper_of

# A canary as one environment renders it: the canary, the canary binding realizing it (or None), its name there, the
# flow, the URL it requests, how often it runs (seconds), its credentials' secret binding (or None), who keeps it when
# this environment doesn't (realized.keeper_of: a party, or the base an overlay inherits it from; or None), and why it
# isn't rendered (None when it is).
CanarySpec = namedtuple("CanarySpec", ("canary", "binding", "name", "flow", "url", "every", "secret", "keeper", "why"))

FLOW_ENDPOINTS = {"health": "health", "login-page": "login", "oidc-token": "token"}
DEFAULT_EVERY = 300
UNRENDERED_FLOWS = {"saml-sso": "a SAML sign-in needs a service provider to start from, which the record doesn't name",
                    "ldap-bind": "an LDAP bind isn't an HTTP request the clouds' synthetic checks make",
                    "other": "its flow (other) says nothing a check could request"}


def _binding(m, c):
    name = rdn_value(c)
    return next((b for b in of_class(m, "ciamCanaryBinding") if one(b, "ciamRealizes") == name), None)


def _url(m, endpoints, svc, flow):
    """(URL, None) the check requests on a service name, or (None, why not)."""
    fqdn, port = one(svc, "ciamFqdn"), one(svc, "ciamPort")
    if not fqdn:
        return None, f"service name {rdn_value(svc)} records no ciamFqdn"
    role = one(svc, "ciamBindingRole")
    served = declared_endpoints(endpoints, one(svc, "ciamTargetRole"), policy_for(m.d, "ciamTrafficPolicy", role),
                                policy_for(m.d, "ciamProtectionPolicy", role))
    kind = FLOW_ENDPOINTS[flow]
    path = next((p for p in served.get(kind, ()) if "*" not in p), None)
    if path is None:
        return None, (f"the products serving {one(svc, 'ciamTargetRole')} name no {kind} path without wildcards"
                      if served.get(kind) else f"the products serving {one(svc, 'ciamTargetRole')} name no {kind} "
                                               "path")
    host = fqdn if not port or str(port) == "443" else f"{fqdn}:{port}"
    return f"https://{host}{path}", None


def _spec(m, endpoints, c):
    b, flow = _binding(m, c), one(c, "ciamCanaryFlow")
    svc = one_role(m, one(c, "ciamCheckedService"))
    secret = next((s for s in (one_role(m, r) for r in values(c, "ciamUsesRole")) if s is not None), None)
    keeper = keeper_of(m, b)
    every = duration_seconds(one(b, "ciamInterval") if b is not None and one(b, "ciamInterval")
                             else one(c, "ciamInterval")) or DEFAULT_EVERY
    url, why = (None, UNRENDERED_FLOWS.get(flow, UNRENDERED_FLOWS["other"])) if flow not in FLOW_ENDPOINTS \
        else (None, "an oidc-token check needs credentials and none of its ciamUsesRole is bound here") \
        if flow == "oidc-token" and secret is None else _url(m, endpoints, svc, flow)
    return CanarySpec(c, b, rdn_value(b) if b is not None else rdn_value(c), flow, url, every, secret, keeper, why)


def canary_specs(m, endpoints):
    """Environment m's canaries whose checked service it binds, as CanarySpecs, given the products' Endpoints."""
    return tuple(_spec(m, endpoints, c) for c in canaries(m.d) if one_role(m, one(c, "ciamCheckedService")) is not None)

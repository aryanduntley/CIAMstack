"""What a cloud renders of an environment's synthetic checks, cloud-neutral (each cloud adapter maps it to its own
checks). Pure.

A canary (ciamCanary) the environment can run (it binds the canary's checked service, ciamCheckedService) is rendered as
the cloud's synthetic check named as the canary binding realizing it (ciamCanaryBinding, ciamRealizes), else as the
canary. What it requests, on the service name's ciamFqdn (and its ciamPort):
- health, login-page, oidc-token: https:// and the path the service's products serve for the flow (core.contract
  Endpoint, through the edge's policies: health -> health, login-page -> login, oidc-token -> token), when that path
  is concrete (no '*'); an oidc-token check needs credentials;
- saml-sso: the identity provider's own start of a SAML sign-in (Endpoint kind saml-start, its query naming the
  service provider) to the SAML integration the canary starts from (ciamStartsFrom: a saml2-sp with an entity ID);
  an unauthenticated GET reaching the sign-in page passes (the entry point and the partner are there; no assertion is
  issued);
- ldap-bind: ldaps://fqdn:port, a simple bind over TLS (port 389 is plain LDAP: not rendered), as the credentials'
  account, else anonymously.
Its credentials: the first of its ciamUsesRole bound here (a secret reference read at run time, never rendered).
Whether the service name is internal or internet-facing (edge.exposure), and for an internal one the subnets its check
runs from: those its canary binding names (ciamSubnetRole), else the first subnet role whose subnets the firewall
rules admit to the service's servers on its port.

Not rendered, and said so: a flow that says nothing a check could do (other), what the record doesn't describe (above);
a check an overlay inherits from its base (rendered there) is named with it, and one someone else keeps is placed by
its keeper (governance.keepers). A canary whose service the environment doesn't bind is the planner's blocker, not a
renderer's concern.
"""
from collections import namedtuple
from urllib.parse import quote

from ...core.directory import follow, one, rdn_value, values
from ...core.environment import of_class, one_role
from ...core.inventory import duration_seconds
from ...core.network import covers
from ..compute.workloads import recorded_versions
from ..edge.exposure import service_exposure
from ..edge.policies import policy_for
from ..edge.resolve import declared_endpoints, endpoint_query
from ..network.stack import subnets
from .alerts import canaries, starts_nowhere
from .realized import keeper_of

# A canary as one environment renders it: the canary, the canary binding realizing it (or None), its name there, the
# flow, the URL it requests, how often it runs (seconds), its credentials' secret binding (or None), who keeps it when
# this environment doesn't (realized.keeper_of: the base an overlay inherits it from; or None), why it isn't rendered
# (None when it is), the checked service name's exposure (edge.exposure: internal, internet or None), and the subnet
# bindings an internal one's check runs from.
CanarySpec = namedtuple("CanarySpec", ("canary", "binding", "name", "flow", "url", "every", "secret", "keeper", "why",
                                       "exposure", "subnets"))

FLOW_ENDPOINTS = {"health": "health", "login-page": "login", "oidc-token": "token", "saml-sso": "saml-start"}
# the flows one unauthenticated GET answers (any answer below 400, redirects followed)
GET_FLOWS = ("health", "login-page", "saml-sso")
DEFAULT_EVERY = 300
PLAIN_LDAP = "389"
OTHER = "its flow (other) says nothing a check could request"


def _binding(m, c):
    name = rdn_value(c)
    return next((b for b in of_class(m, "ciamCanaryBinding") if one(b, "ciamRealizes") == name), None)


def _start(m, c):
    """(the entity ID of the SAML service provider a saml-sso check starts from, None), or (None, why not)."""
    sp = follow(m.d, c, "ciamStartsFrom")
    if not starts_nowhere(m.d, c):
        return one(sp, "ciamEntityId"), None
    return None, ("a SAML sign-in check names no SAML integration to start from (ciamStartsFrom)" if sp is None else
                  f"integration {rdn_value(sp)} isn't a SAML service provider with an entity ID (ciamProtocolType "
                  "saml2-sp, ciamEntityId)")


def _host(svc):
    fqdn, port = one(svc, "ciamFqdn"), one(svc, "ciamPort")
    return fqdn if not port or str(port) == "443" else f"{fqdn}:{port}"


def _url(m, endpoints, svc, flow, entity=None):
    """(URL, None) the check requests on a service name, or (None, why not)."""
    target = one(svc, "ciamTargetRole")
    recorded = recorded_versions(m, target)
    role = one(svc, "ciamBindingRole")
    served = declared_endpoints(endpoints, target, policy_for(m.d, "ciamTrafficPolicy", role),
                                policy_for(m.d, "ciamProtectionPolicy", role), recorded=recorded)
    kind = FLOW_ENDPOINTS[flow]
    path = next((p for p in served.get(kind, ()) if "*" not in p), None)
    if path is None:
        return None, (f"the products serving {target} name no {kind} path without wildcards" if served.get(kind)
                      else f"the products serving {target} name no {kind} path")
    query = endpoint_query(endpoints, target, kind, recorded)
    if entity is not None and query is None:
        return None, f"the products serving {target} name no query naming the service provider at their {kind} path"
    tail = "?" + query.replace("{entity}", quote(entity, safe="")) if entity is not None else ""
    return f"https://{_host(svc)}{path}{tail}", None


def _ldap(svc):
    """(the ldaps:// URL an LDAP bind check connects to, None), or (None, why not)."""
    port = str(one(svc, "ciamPort") or "636")
    if port == PLAIN_LDAP:
        return None, (f"service name {rdn_value(svc)} serves plain LDAP (port 389): the checks bind over TLS (LDAPS) "
                      "and don't start TLS on a plain connection")
    return f"ldaps://{one(svc, 'ciamFqdn')}:{port}", None


def _request(m, endpoints, c, svc, flow, secret):
    """(URL, None) of what the check requests, or (None, why not)."""
    if not one(svc, "ciamFqdn"):
        return None, f"service name {rdn_value(svc)} records no ciamFqdn"
    if flow == "ldap-bind":
        return _ldap(svc)
    if flow not in FLOW_ENDPOINTS:
        return None, OTHER
    if flow == "oidc-token" and secret is None:
        return None, "an oidc-token check needs credentials and none of its ciamUsesRole is bound here"
    entity, why = _start(m, c) if flow == "saml-sso" else (None, None)
    return (None, why) if why else _url(m, endpoints, svc, flow, entity)


def admitted_subnets(m, svc):
    """The subnet bindings the firewall rules admit to a service name's servers on its port: those of the first subnet
    role (in record order) with a subnet inside a rule's source ranges."""
    role, port = one(svc, "ciamTargetRole"), one(svc, "ciamPort")
    sources = tuple(c for fw in of_class(m, "ciamFirewallRule") if one(fw, "ciamTargetRole") == role
                    and (port is None or port in values(fw, "ciamPort")) for c in values(fw, "ciamSourceCidr"))
    inside = tuple(s for s in of_class(m, "ciamSubnetBinding") if one(s, "ciamCidr") and covers(sources,
                                                                                                one(s, "ciamCidr")))
    first = one(inside[0], "ciamBindingRole") if inside else None
    return tuple(s for s in inside if one(s, "ciamBindingRole") == first)


def _vantage(m, b, svc, exposure):
    if exposure != "internal":
        return ()
    named = subnets(m, b) if b is not None else ()
    return named or admitted_subnets(m, svc)


def _spec(m, endpoints, c):
    b, flow = _binding(m, c), one(c, "ciamCanaryFlow")
    svc = one_role(m, one(c, "ciamCheckedService"))
    secret = next((s for s in (one_role(m, r) for r in values(c, "ciamUsesRole")) if s is not None), None)
    every = duration_seconds(one(b, "ciamInterval") if b is not None and one(b, "ciamInterval")
                             else one(c, "ciamInterval")) or DEFAULT_EVERY
    url, why = _request(m, endpoints, c, svc, flow, secret)
    exposure = service_exposure(svc)
    return CanarySpec(c, b, rdn_value(b) if b is not None else rdn_value(c), flow, url, every, secret, keeper_of(m, b),
                      why, exposure, _vantage(m, b, svc, exposure))


def canary_specs(m, endpoints):
    """Environment m's canaries whose checked service it binds, as CanarySpecs, given the products' Endpoints."""
    return tuple(_spec(m, endpoints, c) for c in canaries(m.d) if one_role(m, one(c, "ciamCheckedService")) is not None)

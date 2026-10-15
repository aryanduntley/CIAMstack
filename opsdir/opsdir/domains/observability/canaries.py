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

What a cloud doesn't render is a render note (core.notes, flow 43: unrendered_note): area Monitoring, `canary <name>`,
`not rendered: <why>` with how to handle it (the record change that makes it renderable, or what to do instead), about
its canary binding (else the canary), a blocker when the canary feeds an alert rule (the alert would go without it),
else an action. Each reason here carries its how (CanarySpec.how); the clouds' own reasons are Reasons. Where no adapter
rendering the environment renders synthetic checks (Adapter.renders_synthetic_checks), every canary it could run is a
note of its own (unrun_notes): nothing would check it, and nothing would say so.
"""
from collections import namedtuple
from urllib.parse import quote

from ...core.directory import follow, one, rdn_of, rdn_value, values
from ...core.environment import of_class, one_role
from ...core.inventory import duration_seconds
from ...core.network import covers
from ...core.notes import RECORD, note
from ..compute.workloads import recorded_versions
from ..edge.exposure import service_exposure
from ..edge.policies import policy_for
from ..edge.resolve import declared_endpoints, endpoint_query
from ..network.stack import subnets
from ..pki.credentials import role_uses
from .alerts import canaries, starts_nowhere
from .realized import keeper_of

# A canary as one environment renders it: the canary, the canary binding realizing it (or None), its name there, the
# flow, the URL it requests, how often it runs (seconds), its credentials' secret binding (or None), who keeps it when
# this environment doesn't (realized.keeper_of: the base an overlay inherits it from; or None), why it isn't rendered
# (None when it is), the checked service name's exposure (edge.exposure: internal, internet or None), and the subnet
# bindings an internal one's check runs from.
# how: the steps that would let it render (when why), each in words.
CanarySpec = namedtuple("CanarySpec", ("canary", "binding", "name", "flow", "url", "every", "secret", "keeper", "why",
                                       "exposure", "subnets", "how"), defaults=((),))
# Why a cloud doesn't render a check (in words, after "not rendered: ") and how to handle it (steps).
Reason = namedtuple("Reason", ("why", "how"))

FLOW_ENDPOINTS = {"health": "health", "login-page": "login", "oidc-token": "token", "saml-sso": "saml-start"}
# the flows one unauthenticated GET answers (any answer below 400, redirects followed)
GET_FLOWS = ("health", "login-page", "saml-sso")
DEFAULT_EVERY = 300
PLAIN_LDAP = "389"
OTHER = "its flow (other) says nothing a check could request"


def _no(why, *how):
    """(None, why, how) of what a check can't request."""
    return None, why, tuple(how)


def _binding(m, c):
    name = rdn_value(c)
    return next((b for b in of_class(m, "ciamCanaryBinding") if one(b, "ciamRealizes") == name), None)


def _start(m, c):
    """(the entity ID of the SAML service provider a saml-sso check starts from, None, ()), or (None, why not, how)."""
    sp = follow(m.d, c, "ciamStartsFrom")
    if not starts_nowhere(m.d, c):
        return one(sp, "ciamEntityId"), None, ()
    if sp is None:
        return _no("a SAML sign-in check names no SAML integration to start from (ciamStartsFrom)",
                   "Name the SAML service provider integration it starts from on the canary (ciamStartsFrom), "
                   + RECORD)
    return _no(f"integration {rdn_value(sp)} isn't a SAML service provider with an entity ID (ciamProtocolType "
               "saml2-sp, ciamEntityId)",
               f"Point ciamStartsFrom at a SAML service provider integration (ciamProtocolType saml2-sp) recording its "
               f"ciamEntityId, or record {rdn_value(sp)}'s, {RECORD}")


def _host(svc):
    fqdn, port = one(svc, "ciamFqdn"), one(svc, "ciamPort")
    return fqdn if not port or str(port) == "443" else f"{fqdn}:{port}"


def _url(m, endpoints, svc, flow, entity=None):
    """(URL, None, ()) the check requests on a service name, or (None, why not, how)."""
    target = one(svc, "ciamTargetRole")
    recorded = recorded_versions(m, target)
    role = one(svc, "ciamBindingRole")
    served = declared_endpoints(endpoints, target, policy_for(m.d, "ciamTrafficPolicy", role),
                                policy_for(m.d, "ciamProtectionPolicy", role), recorded=recorded)
    kind = FLOW_ENDPOINTS[flow]
    path = next((p for p in served.get(kind, ()) if "*" not in p), None)
    adapters = (f"Install the adapter of the product serving {target} at a version declaring its {kind} endpoint, or "
                f"give the canary a flow that product serves (ciamCanaryFlow), {RECORD}")
    if path is None:
        return _no(f"the products serving {target} name no {kind} path without wildcards" if served.get(kind)
                   else f"the products serving {target} name no {kind} path", adapters)
    query = endpoint_query(endpoints, target, kind, recorded)
    if entity is not None and query is None:
        return _no(f"the products serving {target} name no query naming the service provider at their {kind} path",
                   adapters)
    tail = "?" + query.replace("{entity}", quote(entity, safe="")) if entity is not None else ""
    return f"https://{_host(svc)}{path}{tail}", None, ()


def _ldap(svc):
    """(the ldaps:// URL an LDAP bind check connects to, None, ()), or (None, why not, how)."""
    port = str(one(svc, "ciamPort") or "636")
    if port == PLAIN_LDAP:
        return _no(f"service name {rdn_value(svc)} serves plain LDAP (port 389): the checks bind over TLS (LDAPS) "
                   "and don't start TLS on a plain connection",
                   "Check a service name serving LDAPS (usually port 636) instead (the canary's ciamCheckedService), "
                   f"{RECORD}")
    return f"ldaps://{one(svc, 'ciamFqdn')}:{port}", None, ()


def _request(m, endpoints, c, svc, flow, secret):
    """(URL, None, ()) of what the check requests, or (None, why not, how)."""
    if not one(svc, "ciamFqdn"):
        return _no(f"service name {rdn_value(svc)} records no ciamFqdn",
                   f"Record the service name's DNS name (ciamFqdn on {rdn_value(svc)}), {RECORD}")
    if flow == "ldap-bind":
        return _ldap(svc)
    if flow not in FLOW_ENDPOINTS:
        return _no(OTHER, "Give the canary a flow a check can make (ciamCanaryFlow: health, login-page, oidc-token, "
                          f"saml-sso, ldap-bind), or remove it, {RECORD}")
    if flow == "oidc-token" and secret is None:
        return _no("an oidc-token check needs credentials and none of its ciamUsesRole is bound here",
                   f"Bind one of its credential roles ({', '.join(values(c, 'ciamUsesRole')) or 'ciamUsesRole'}) here "
                   f"to the secret holding the check's client_id and client_secret, {RECORD}")
    entity, why, how = _start(m, c) if flow == "saml-sso" else (None, None, ())
    return (None, why, how) if why else _url(m, endpoints, svc, flow, entity)


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
    url, why, how = _request(m, endpoints, c, svc, flow, secret)
    exposure = service_exposure(svc)
    return CanarySpec(c, b, rdn_value(b) if b is not None else rdn_value(c), flow, url, every, secret, keeper_of(m, b),
                      why, exposure, _vantage(m, b, svc, exposure), how)


def canary_specs(m, endpoints):
    """Environment m's canaries whose checked service it binds, as CanarySpecs, given the products' Endpoints."""
    return tuple(_spec(m, endpoints, c) for c in canaries(m.d) if one_role(m, one(c, "ciamCheckedService")) is not None)


def unknown_exposure(m, spec):
    """The Reason a cloud can't place a check of a service name recording neither its exposure nor a frontend
    address."""
    svc = rdn_value(one_role(m, one(spec.canary, "ciamCheckedService")))
    return Reason(f"service name {svc} records neither a frontend address nor its exposure: whether its check is "
                  "public or runs in the network is unknown",
                  (f"Record whether {svc} is internet-facing or internal (ciamExposure) or its frontend address "
                   f"(ciamFrontendIp), {RECORD}",))


def no_subnet(m, spec):
    """The Reason a check of an internal service name with no subnet to run from (CanarySpec.subnets) isn't
    rendered."""
    svc = one_role(m, one(spec.canary, "ciamCheckedService"))
    port = f" on {one(svc, 'ciamPort')}" if one(svc, "ciamPort") else ""
    return Reason(f"service name {rdn_value(svc)} is internal and no subnet is named to run its check from",
                  (f"Name the subnet role it runs from on its canary binding (ciamSubnetRole), or record a firewall "
                   f"rule admitting a subnet to {one(svc, 'ciamTargetRole')}{port}, {RECORD}",))


def unrendered_note(m, spec, reason=None):
    """The render note of a check environment m's cloud doesn't render: the spec's own why and how, else the cloud's
    Reason; a blocker when the canary feeds an alert rule (ciamFeedsAlert: the alert would go without it), else an
    action; about its canary binding, else the canary."""
    why, how = (spec.why, spec.how) if spec.why else reason
    alert = one(spec.canary, "ciamFeedsAlert")
    svc = one(spec.canary, "ciamCheckedService")
    return note("Monitoring", "blocker" if alert else "action", f"canary {rdn_value(spec.canary)}",
                f"not rendered: {why}", how, (spec.binding if spec.binding is not None else spec.canary).dn,
                f"{spec.flow} check of {svc} in {m.label}"
                + (f"; alert rule {rdn_of(alert)} goes without it"
                   if alert else ""))


def unrun_notes(m, adapters, endpoints, renderers=()):
    """The render notes of environment m's canaries when none of the adapters rendering it (adapters) renders
    synthetic checks (Adapter.renders_synthetic_checks): each canary it could run (not one it inherits or someone
    else keeps) is not rendered at all; renderers: the installed adapters that render them, named in how; () when one
    of its adapters renders them."""
    if any(a.renders_synthetic_checks for a in adapters):
        return ()
    providers = ", ".join(a.name for a in adapters if a.kind == "provider") or "none"
    reason = Reason(f"no adapter in {m.label}'s stack renders synthetic checks (its provider: {providers})",
                    ("Declare an adapter that renders synthetic checks in the environment's stack"
                     + (f" (installed: {', '.join(renderers)})" if renderers else "") + f", {RECORD}",
                     "Or run the check on a schedule from the environment's own servers (configuration management), "
                     "feeding the alert rule it fires"))
    return tuple(unrendered_note(m, s._replace(why=None), reason) for s in canary_specs(m, endpoints)
                 if s.keeper is None)


def canary_roles(m):
    """(RoleUse, ...) of the credential roles (ciamUsesRole) of the canaries environment m checks: those whose checked
    service it binds (canary_specs)."""
    return role_uses((c for c in canaries(m.d) if one_role(m, one(c, "ciamCheckedService")) is not None),
                     "ciamUsesRole", "canary")

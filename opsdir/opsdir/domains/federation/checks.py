"""Federation planner checks: the platform's own identity services keep the addresses partners and applications
know them by."""
from urllib.parse import urlsplit

from ...core.directory import one, rdn_value
from ...core.environment import of_class
from ...core.findings import findings, merge_findings, responsible
from .services import identity_services

# The identity service's contracts that are URLs partners and applications hold (an entity ID may also be a URN)
PUBLISHED_URLS = ("ciamBaseUrl", "ciamOidcIssuer", "ciamEntityId")


def published_hosts(service):
    """The host names of an identity service's published URLs, lower-cased, each once, in attribute order."""
    urls = (one(service, a) for a in PUBLISHED_URLS)
    return tuple(dict.fromkeys(urlsplit(u).hostname for u in urls
                               if u and urlsplit(u).scheme in ("http", "https") and urlsplit(u).hostname))


def service_names(m, role):
    """The FQDNs (lower-cased) of an environment's service names in front of servers of that role."""
    return tuple(one(b, "ciamFqdn").lower() for b in of_class(m, "ciamServiceName")
                 if one(b, "ciamTargetRole") == role)


def _listed(names):
    return ", ".join(f"`{n}`" for n in names) or "none"


def _identity_service(ctx, service):
    role = one(service, "ciamTargetRole")
    if role is None:
        return findings()
    name, hosts = rdn_value(service), published_hosts(service)
    dst, src = service_names(ctx.dst, role), service_names(ctx.src, role)
    if all(h in dst for h in hosts):
        return findings(ok=[f"Identity service `{name}` keeps its published address in {ctx.dst.label} "
                            f"({', '.join(hosts)} served by the `{role}` service name)."])
    # a host the source serves and the target doesn't is a changed service name: the contract check reports it
    unserved = tuple(h for h in hosts if h not in dst and h not in src)
    if not unserved:
        return findings()
    return findings(blockers=[(
        "Identity service",
        f"`{name}` publishes {_listed(unserved)}, which no service name for `{role}` serves ({ctx.src.label}: "
        f"{_listed(src)}; {ctx.dst.label}: {_listed(dst)}), so nothing shows partners and applications keep that "
        "address after the move. Record the service name that serves it in the target, or correct the identity "
        "service's URLs as their own approved change (partners must update their metadata, clients their issuer).",
        responsible(ctx.d, service))])


def check_identity_services(ctx):
    """Every identity service's published hosts are served by the target's service names for its role. A host only
    the source serves is a changed service name, which the contract check (R9) already blocks."""
    return merge_findings([_identity_service(ctx, s) for s in identity_services(ctx.d)])

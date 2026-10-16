"""SiteMinder's policy objects read into its own branch: policy domains with their realms (rules below them) and
policies, authentication schemes, user directories (linked to the directory consumer they bind as, credentials
withheld) and agents (the server role each runs on). Pure."""
import re

from opsdir.core.directory import get, one, ou_entry, rdn_of
from opsdir.domains.directory.consumers import consumer_by_bind_dn
from opsdir.domains.infrastructure.external import hosts_role
from .entries import entry, sm_attrs
from .naming import ACCESS_GATEWAY, AGENT
from .xps import CUSTOM_SCHEME, GATEWAY_TYPES, is_true, kind, link_of, links_of, name, value_of, values_of

_SEPARATORS = re.compile(r"[\s,]+")
SM = ("top", "ciamObject")


def _bool(v):
    return (("TRUE" if is_true(v) else "FALSE"),) if v is not None else (None,)


def _int(v):
    return ((v.strip(),) if v and v.strip().isdigit() else (None,))


def agent_role(o):
    """The server role an agent runs on, from its type: an Access Gateway (SPS), else a web agent."""
    t = (value_of(o, "type") or "").lower()
    return ACCESS_GATEWAY if any(g in t for g in GATEWAY_TYPES) else AGENT


def is_custom_scheme(o):
    """Whether an authentication scheme runs the operator's own library (its type says so)."""
    return CUSTOM_SCHEME in (value_of(o, "type") or "").lower()


def agent_entry(d, x, o):
    dn = x.placed[o.xid][0]
    old = get(d, dn)
    role = () if old is not None and one(old, "ciamTargetRole") else {"ciamTargetRole": (agent_role(o),)}
    return entry(d, dn, (*SM, "smAgent", "smObject"),
                 {"cn": (rdn_of(dn),), "smAgentType": (value_of(o, "type"),), **dict(role),
                  **sm_attrs(x, o)})


def scheme_entry(d, x, o):
    dn = x.placed[o.xid][0]
    return entry(d, dn, (*SM, "smAuthScheme", "smObject"),
                 {"cn": (rdn_of(dn),), "smSchemeType": (value_of(o, "type"),),
                  "smProtectionLevel": _int(value_of(o, "level")), "smLibrary": (value_of(o, "library"),),
                  **sm_attrs(x, o)})


def directory_servers(o):
    """The host[:port] values a user directory's Server setting names."""
    return tuple(h for v in values_of(o, "servers") for h in _SEPARATORS.split(v) if h)


def directory_entry(d, x, o):
    """(entry, notices) for a user directory."""
    dn = x.placed[o.xid][0]
    hosts = directory_servers(o)
    role, port = hosts_role(d, hosts)
    bind = value_of(o, "bind")
    consumer = consumer_by_bind_dn(d, bind)
    label = f"user directory {name(o)}"
    notices = (*((f"{label}: binds as {bind}, which no consumer records: record it, so the directory's "
                  "consumers show SiteMinder until it is retired",) if bind and consumer is None else ()),
               *((f"{label}: its servers ({', '.join(hosts)}) aren't one service name or external host of the "
                  "record",) if hosts and role is None else ()),
               *((f"{label}: connects without TLS",) if value_of(o, "tls") is not None
                 and not is_true(value_of(o, "tls")) else ()))
    return entry(d, dn, (*SM, "smUserDirectory", "smObject"),
                 {"cn": (rdn_of(dn),), "smNamespace": (value_of(o, "namespace") or "unknown",),
                  "smServiceRole": (role,), "smPort": (str(port) if port else None,),
                  "smConsumer": (consumer.dn if consumer else None,), **sm_attrs(x, o)}), notices


def _dns(x, xids):
    """The DNs of the objects these XIDs name (a response: every entry it became), those not placed left out."""
    return tuple(dn for xid in xids for dn in x.placed.get(xid, ()))


def _rule(d, x, o):
    dn = x.placed[o.xid][0]
    actions = tuple(a for v in values_of(o, "actions") for a in _SEPARATORS.split(v) if a)
    return entry(d, dn, (*SM, "smRule", "smObject"),
                 {"cn": (rdn_of(dn),), "smResourceFilter": (value_of(o, "resource") or "*",),
                  "smRegex": _bool(value_of(o, "regex")), "smAction": actions or (None,),
                  "smAllow": _bool(value_of(o, "allow")), "smEnabled": _bool(value_of(o, "enabled")),
                  **sm_attrs(x, o)})


def _realm(d, x, o):
    dn = x.placed[o.xid][0]
    return entry(d, dn, (*SM, "smRealm", "smObject"),
                 {"cn": (rdn_of(dn),), "smResourceFilter": (value_of(o, "filter") or "/",),
                  "smAgent": _dns(x, links_of(o, "agent")) or (None,),
                  "smAuthScheme": _dns(x, links_of(o, "scheme")) or (None,),
                  "smIdleTimeout": _int(value_of(o, "idle")), "smMaxTimeout": _int(value_of(o, "max")),
                  **sm_attrs(x, o)})


def subject(x, up):
    """A user selection as "<user directory> <kind> <value>"."""
    directory = x.objects.get(link_of(up, "directory"))
    return " ".join(filter(None, (name(directory) if directory else "any-directory",
                                  (value_of(up, "kind") or "all").lower(), value_of(up, "path"))))


def _policy(d, x, o):
    dn = x.placed[o.xid][0]
    kids = tuple(x.objects[k] for k in o.children if k in x.objects)
    links = tuple(k for k in kids if kind(k) == "policy-link")
    return entry(d, dn, (*SM, "smPolicy", "smObject"),
                 {"cn": (rdn_of(dn),),
                  "smRule": _dns(x, tuple(r for k in links for r in links_of(k, "rule"))) or (None,),
                  "smResponse": _dns(x, tuple(r for k in links for r in links_of(k, "response"))) or (None,),
                  "smSubject": tuple(subject(x, k) for k in kids if kind(k) == "user-policy") or (None,),
                  "smEnabled": _bool(value_of(o, "enabled")), **sm_attrs(x, o)})


def _below(x, o, k):
    """The objects of kind k directly below o (a nested realm's rules are its own)."""
    return tuple(x.objects[c] for c in o.children if c in x.objects and kind(x.objects[c]) == k)


def realms_of(x, domain):
    """Every realm of a domain, nested realms too, in document order."""
    def walk(o):
        kids = tuple(x.objects[c] for c in o.children if c in x.objects)
        return tuple(r for c in kids if kind(c) == "realm" for r in (c, *walk(c)))
    return walk(domain)


def domain_group(d, x, o):
    """(domain DN, its entries): the domain, its realms with their rules and its policies (the import owns the
    domain's subtree)."""
    dn = x.placed[o.xid][0]
    realms = realms_of(x, o)
    rules = tuple(r for realm in realms for r in _below(x, realm, "rule"))
    policies = _below(x, o, "policy")
    return dn, (entry(d, dn, (*SM, "smPolicyDomain", "smObject"),
                      {"cn": (rdn_of(dn),), "description": (value_of(o, "description"),),
                       **sm_attrs(x, o)}),
                *((ou_entry(f"ou=realms,{dn}"),) if realms else ()), *(_realm(d, x, r) for r in realms),
                *(_rule(d, x, r) for r in rules),
                *((ou_entry(f"ou=policies,{dn}"),) if policies else ()), *(_policy(d, x, p) for p in policies))

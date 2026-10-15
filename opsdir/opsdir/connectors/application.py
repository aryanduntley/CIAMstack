"""The application view (milestone 6.4): everything an application touches across the record's domains, in sections,
each row naming the entry it comes from. Pure.

The view starts from any entry: an integration, a directory consumer, a service name, a canary, anything. An
application entry (ciamApplication, governance) starts it from the parts it records (ciamApplicationPart) and the
binding roles it uses (ciamUsesRole); nothing is grouped that the record doesn't group. What the view holds is what
the dependency graph (connectors.graph) reaches from each part, both ways, VIEW_DEPTH steps out, with the roles those
entries name realized by their bindings (the environment's when one is given, else every environment's), and the
canary and alarm bindings that realize a canary or alert rule it reaches (ciamRealizes, a name). Sections, in order:
identity, directory, edge and service names, secrets and keys (references only), certificates (with expiry), network,
monitoring, changes and incidents (the change records the entries name, the incidents involving them), owners.
"""
from typing import NamedTuple, Optional

from ..core.directory import get, gtime_date, is_kind, one, rdn_value, referrers, value_type, values
from ..core.environment import by_role
from .graph import (ROLE, SERVER_ROLE, SERVER_ROLE_REFS, dependency_graph, entry_kind, node_label, owners_of,
                    role_attributes)

VIEW_DEPTH = 2
HEADERS = ("environment", "kind", "name", "detail", "owner", "evidence")
# A section: name, rows (each HEADERS: the entry it comes from last, its DN)
Section = NamedTuple("Section", [("name", str), ("rows", tuple)])
# The view of root (an entry's DN): its name, the parts it starts from, the roles an application uses, the environment
# roles were bound in (label, or None), the sections
ApplicationView = NamedTuple("ApplicationView", [("root", str), ("name", str), ("parts", tuple), ("roles", tuple),
                                                 ("environment", Optional[str]), ("sections", tuple)])
APPLICATION = "ciamApplication"
# the object classes each section shows (an entry of a subclass too), in section order
SECTIONS = (
    ("identity", ("ciamApplication", "ciamIntegration", "ciamIdentityService", "ciamClaimMap")),
    ("directory", ("ciamConsumer", "ciamAci")),
    ("edge and service names", ("ciamServiceName", "ciamEdgeService", "ciamDnsRecord", "ciamTrafficPolicy",
                                "ciamProtectionPolicy", "ciamHeaderContract", "ciamClusterGateway")),
    ("secrets and keys", ("ciamSecretRef", "ciamKeyRef", "ciamCertificateRef", "ciamCredential", "ciamSecretStore")),
    ("certificates", ("ciamCertificate",)),
    ("network", ("ciamFirewallRule", "ciamExternalAllowlist", "ciamEgress", "ciamEgressDestination",
                 "ciamPrivateEndpoint", "ciamEndpointService", "ciamProxy", "ciamAccessPath")),
    ("monitoring", ("ciamCanary", "ciamCanaryBinding", "ciamAlertRule", "ciamAlarmBinding", "ciamLogRoute")),
)
CHANGES, OWNERS = "changes and incidents", "owners"
# what a row's detail says, by object class: the attributes it shows (name=value, comma-joined); description else
DETAIL = {
    "ciamApplication": ("ciamCriticality", "ciamUsesRole"), "ciamIntegration": ("ciamProtocolType", "ciamServedBy"),
    "ciamConsumer": ("ciamBindDn",), "ciamServiceName": ("ciamFqdn", "ciamPort", "ciamTargetRole"),
    "ciamSecretRef": ("ciamRefUri",), "ciamKeyRef": ("ciamRefUri",), "ciamCertificateRef": ("ciamRefUri",),
    "ciamCanary": ("ciamCanaryFlow", "ciamCheckedService", "ciamInterval"), "ciamCanaryBinding": ("ciamRealizes",),
    "ciamAlarmBinding": ("ciamRealizes",), "ciamExternalAllowlist": ("ciamRefersToRole", "ciamAllowlistDirection"),
    "ciamFirewallRule": ("ciamSourceCidr", "ciamTargetRole", "ciamPort", "ciamProtocol"),
    "ciamAci": ("ciamAciRight", "ciamAciTargetAttr"),
}


def environment_of_entry(e):
    """The cloud/env label of the environment an entry is in ('' for an estate-wide one)."""
    label = node_label(e)
    return label[label.rindex("[") + 1:-1] if label.endswith("]") else ""


def _detail(d, e, kind, as_of):
    if kind == "ciamCertificate":
        after = gtime_date(one(e, "ciamNotAfter")) if one(e, "ciamNotAfter") else None
        return f"expires {after.isoformat()} ({(after - as_of).days} days)" if after else "no expiry recorded"
    shown = tuple(f"{a}={rdn_value(get(d, v)) if value_type(d, a) == 'dn' and get(d, v) else v}"
                  for a in DETAIL.get(kind, ()) for v in values(e, a))
    return ", ".join(shown) if shown else one(e, "description", "")


def _row(d, e, as_of):
    kind = entry_kind(d, e)
    return (environment_of_entry(e), kind, rdn_value(e), _detail(d, e, kind, as_of), owners_of(d, e), e.dn)


def view_parts(d, e):
    """(the DNs a view of entry e starts from, the binding roles it adds): an application's parts and roles, else e
    itself."""
    if is_kind(d, e, APPLICATION):
        return tuple(get(d, p).dn for p in values(e, "ciamApplicationPart") if get(d, p) is not None), \
            tuple(values(e, "ciamUsesRole"))
    return (e.dn,), ()


def _realized_by(d, role, m):
    """What realizes a binding role: the estate-wide entries naming it as their own (a credential's intent), and the
    bindings of environment model m (None: of every environment)."""
    named = tuple(x for x in sorted(d.entries.values(), key=lambda x: x.dn) if role in values(x, "ciamBindingRole"))
    if m is None:
        return named
    return (*(x for x in named if not environment_of_entry(x)), *by_role(m, role))


def _related(d, parts, roles, m):
    """The entries the view holds: the parts, what the graph reaches from each (both ways, VIEW_DEPTH), the bindings
    of the roles reached or added, and the bindings realizing a canary or alert rule held (ciamRealizes)."""
    graphs = tuple(dependency_graph(d, p, "both", VIEW_DEPTH, m) for p in parts)
    nodes = tuple(dict.fromkeys(n.id for g in graphs for n in g.nodes))
    reached = tuple(get(d, n) for n in nodes if not n.startswith((ROLE, SERVER_ROLE)))
    named = tuple(v for e in reached for a in sorted(role_attributes(d) - SERVER_ROLE_REFS) for v in values(e, a))
    reached_roles = dict.fromkeys((*roles, *(n[len(ROLE):] for n in nodes if n.startswith(ROLE)), *named))
    held = tuple({x.norm: x for x in (*reached, *(b for r in reached_roles for b in _realized_by(d, r, m)))}.values())
    realized = {rdn_value(x) for x in held if is_kind(d, x, "ciamCanary") or is_kind(d, x, "ciamAlertRule")}
    realizing = tuple(x for x in sorted(d.entries.values(), key=lambda x: x.dn)
                      if set(values(x, "ciamRealizes")) & realized and (m is None or x.dn.endswith(m.dn)))
    return tuple({x.norm: x for x in (*held, *realizing)}.values())


def _changes(d, held):
    """The changes and incidents section's rows: the change records the entries name (ciamChangeRef), the incidents
    involving any of them (ciamInvolved)."""
    changes = tuple(dict.fromkeys(c for e in held for c in values(e, "ciamChangeRef")))
    incidents = {i.norm: i for e in held for _, i in referrers(d, e, "ciamInvolved")}
    return (*(("", "change", rdn_value(c), f"{one(c, 'ciamTitle', '')} ({one(c, 'ciamChangeStatus', '')})",
               owners_of(d, c), c.dn) for c in (get(d, x) for x in changes) if c is not None),
            *(("", "incident", rdn_value(i), f"{one(i, 'ciamTitle', '')} ({one(i, 'ciamSeverity', '')})",
               owners_of(d, i), i.dn) for i in sorted(incidents.values(), key=lambda x: x.dn)))


def _owners(d, held):
    """The owners section's rows: each party owning entries the view holds, with what it owns."""
    owners = tuple(dict.fromkeys(o for e in held for o in values(e, "ciamOwner")))

    def row(o):
        p = get(d, o)
        names = sorted({rdn_value(e) for e in held if o in values(e, "ciamOwner")})
        return ("", one(p, "ciamOwnerKind", "") if p is not None else "", rdn_value(p) if p is not None else o,
                f"owns {len(names)}: {', '.join(names)}", "", p.dn if p is not None else o)
    return tuple(sorted((row(o) for o in owners), key=lambda r: r[2]))


def application_view(d, dn, as_of, m=None):
    """The ApplicationView of entry dn of record d on date as_of (certificates' days left): its sections from what the
    view holds (_related); given environment model m, only that environment's bindings (else every environment's).
    SystemExit for an entry the record doesn't hold."""
    e = get(d, dn)
    if e is None:
        raise SystemExit(f"no entry {dn} in the record")
    parts, roles = view_parts(d, e)
    here = m.label if m is not None else None
    found = {x.norm: x for x in (*((e,) if is_kind(d, e, APPLICATION) else ()), *_related(d, parts, roles, m))}
    held = tuple(x for x in found.values()
                 if here is None or environment_of_entry(x) in ("", here))       # another environment's: not here
    rows = {name: tuple(sorted((_row(d, x, as_of) for x in held if any(is_kind(d, x, oc) for oc in classes)),
                               key=lambda r: (r[1], r[2], r[0])))
            for name, classes in SECTIONS}
    return ApplicationView(e.dn, rdn_value(e), parts, roles, m.label if m is not None else None,
                           (*(Section(name, rows[name]) for name, _ in SECTIONS),
                            Section(CHANGES, _changes(d, held)), Section(OWNERS, _owners(d, held))))


def view_document(view):
    """The view as a JSON-ready document: root, name, parts, roles, environment, and each section's rows as objects
    (HEADERS as keys)."""
    return {"root": view.root, "name": view.name, "parts": list(view.parts), "roles": list(view.roles),
            "environment": view.environment,
            "sections": [{"name": s.name, "rows": [dict(zip(HEADERS, r)) for r in s.rows]} for s in view.sections]}

"""Who keeps an environment's entries, and whether the default render gives that keeper a root (decisions 1860, 2732).
An entry is the stack's own unless ciamManagedBy names a party; what is the landing zone's by nature (its network
plumbing, the identities and guardrails it holds) is kept by the landing zone's owner when no party is named. A keeper
that takes generated infrastructure (ciamTakesGeneratedInfra TRUE on its party entry) gets its own complete root:
terraform/landing-zone/ for the landing zone's owner, terraform/landing-zone/<party>/ for any other party, applied by
that team. A keeper that doesn't is named in the render and asked in a request; its root is rendered only when a render
is scoped to it. A landing zone with no party recorded keeps its root, as there is no one to ask.

What an organization enables once for every member (an organization-wide security service's delegated administrator
and configuration, an organization audit trail: ciamAuditScope organization) is the landing zone's by nature too: a
renderer stamps that part with the entry's organization origin (organization_origin), kept by the party ciamManagedBy
names, else by the landing zone's owner, while the rest of the entry (its findings routing) stays where the entry
goes (decision 2777). Pure."""
import re
from typing import NamedTuple, Optional

from ...core.directory import follow, get, is_kind, one, rdn_value
from ..access.workloads import landing_zone_owner, landing_zone_party

LANDING_ZONE = "terraform/landing-zone"
TAKES = "ciamTakesGeneratedInfra"
# the origin of what a render writes for the landing zone by nature that no single entry keeps (its identities and
# guardrails): placed with the landing zone's keeper
LANDING = "landing-zone"
# a root name prefix: a keeper named and asked, whose root the default render leaves out (NAMED + its name)
NAMED = "named:"
# an origin prefix: the organization-wide part of an entry (ORGANIZATION + its DN), kept with the landing zone
ORGANIZATION = "organization:"
# the root a class or bindings scope renders as (its own, complete with the inputs it reads from the others)
SLICE = "terraform/slice"

# name: who keeps it (as findings name owners); folder: the root it renders into when rendered; party: their entry
# (None when the record names none); takes: whether the default render gives them that root
Keeper = NamedTuple("Keeper", [("name", str), ("folder", str), ("party", Optional[object]), ("takes", bool)])


def managed_by(d, e):
    """The party entry entry e's ciamManagedBy names, or None (it names none, or the record has no such entry): who
    keeps e when the stack doesn't."""
    return follow(d, e, "ciamManagedBy")


def managed_by_name(d, e, default=None):
    """The name of who keeps entry e as reports and findings show it: the RDN value of the party its ciamManagedBy
    names (managed_by), else default (e.g. 'platform', or the DN named when the record has no entry for it)."""
    party = managed_by(d, e)
    return rdn_value(party) if party is not None else default


def takes_generated(party):
    """Whether a party entry takes the infrastructure opsdir generates for what it keeps (its recorded setting; absent:
    it doesn't, it is asked)."""
    return party is not None and one(party, TAKES) == "TRUE"


def keeper_folder(dn):
    """The root a party keeps its own infrastructure in, under the landing zone's: terraform/landing-zone/<party>/,
    named from the party's RDN value."""
    name = dn.split(",", 1)[0].split("=", 1)[-1]
    return f"{LANDING_ZONE}/{re.sub(r'[^a-z0-9]+', '-', name.lower()).strip('-') or 'keeper'}"


def landing_zone_keeper(m):
    """Keeper of environment m's landing zone: its owner (workloads.landing_zone_owner), in terraform/landing-zone/;
    rooted by default when its party takes generated infrastructure, or when the record names no party to ask."""
    party = landing_zone_party(m)
    return Keeper(landing_zone_owner(m), LANDING_ZONE, party, party is None or takes_generated(party))


def party_keeper(m, dn):
    """Keeper for the party DN names in environment m: the landing zone's keeper when it is the landing zone's party,
    else that party in its own folder (named by its DN when the record has no entry for it)."""
    lz = landing_zone_party(m)
    if lz is not None and dn == lz.dn:
        return landing_zone_keeper(m)
    party = get(m.d, dn)
    return Keeper(rdn_value(party) if party is not None else dn, keeper_folder(dn), party, takes_generated(party))


def keeper(m, e, landing_zone=False):
    """Who keeps entry e of environment m: the party its ciamManagedBy names, else the landing zone's keeper when e is
    the landing zone's by nature (landing_zone), else None: the stack keeps it."""
    dn = one(e, "ciamManagedBy")
    if dn is not None:
        return party_keeper(m, dn)
    return landing_zone_keeper(m) if landing_zone else None


def _root(k):
    """The default render's root for keeper k: None (the stack's), its folder when it takes generated infrastructure,
    else NAMED + its name."""
    return None if k is None else k.folder if k.takes else NAMED + k.name


def root_of(m, e, landing_zone=False):
    """The root entry e of environment m renders into in the default render: None for the stack's own; its keeper's
    folder when the keeper takes generated infrastructure; else NAMED + the keeper's name (named and asked, not
    rendered)."""
    return _root(keeper(m, e, landing_zone))


def organization_wide(e):
    """Whether entry e is enabled for the whole organization (ciamAuditScope organization), not one account."""
    return one(e, "ciamAuditScope") == "organization"


def organization_origin(dn):
    """The origin a renderer stamps an entry's organization-wide part with (hcl.from_entry keeps a stamped origin): kept
    with the landing zone, apart from the rest of the entry."""
    return ORGANIZATION + dn


def origin_entry(origin):
    """The DN of the entry an origin renders (an organization origin's entry), or the origin itself (LANDING, None)."""
    return origin[len(ORGANIZATION):] if origin and origin.startswith(ORGANIZATION) else origin


def keeper_of_origin(m, origin, landing=frozenset()):
    """Who keeps what a rendered block of that origin (hcl.from_entry) renders in environment m: LANDING the landing
    zone's keeper; an entry's DN its keeper (landing: the DNs that are the landing zone's by nature, its plumbing); an
    entry's organization origin the keeper of what is the landing zone's by nature; None for the stack's own, for no
    origin (unstamped) or an origin naming no entry."""
    if origin == LANDING:
        return landing_zone_keeper(m)
    dn = origin_entry(origin)
    e = get(m.d, dn) if dn else None
    return None if e is None else keeper(m, e, dn in landing or dn != origin)


def organization_line(m, e):
    """What an environment's own render says of entry e's organization-wide part, kept elsewhere: who enables it for
    every account, in which root (or asked of them)."""
    k = keeper(m, e, True)
    where = f"in their root {k.folder}" if k.takes else "asked of them"
    return f"{rdn_value(e)}: organization-wide: enabled for every account by {k.name} ({where})"


def scope_folder(m):
    """The root environment m's scope (m.scope) renders: a keeper's folder, SLICE for a class or bindings scope, None
    for the whole environment."""
    s = m.scope
    if s is None or s.kind == "environment":
        return None
    return party_keeper(m, s.value[0]).folder if s.kind == "keeper" else SLICE


def _in_slice(m, origin, landing):
    """Whether a block of that origin is in environment m's (keeper, class or bindings) scope."""
    s = m.scope
    if s.kind == "keeper":
        k = keeper_of_origin(m, origin, landing)
        return k is not None and k.folder == scope_folder(m)
    e = get(m.d, origin_entry(origin)) if origin and origin != LANDING else None
    if e is None:
        return False
    return any(is_kind(m.d, e, oc) for oc in s.value) if s.kind == "class" else e.dn in s.value


def placement(m, landing=()):
    """The placement of environment m's rendered blocks: a function of a block's origin giving the root its
    keeper_of_origin's default render gives (None: the stack's); under a keeper, class or bindings scope (m.scope),
    the blocks in it go to the scope's root whatever their keeper's setting, the others where they would go (the slice
    reads them through inputs)."""
    landing = frozenset(landing)

    def default(origin):
        return _root(keeper_of_origin(m, origin, landing))
    target = scope_folder(m)
    if target is None:
        return default
    return lambda origin: target if _in_slice(m, origin, landing) else default(origin)


def in_scope(m, root):
    """Whether a render of environment m writes a root: every root for the whole environment, else the scope's own."""
    target = scope_folder(m)
    return target is None or root == target


def check_scope(m):
    """Environment m's scope, refused (SystemExit) when it names a keeper the record has no party for, or bindings
    the environment doesn't bind."""
    s = m.scope
    if s is None or s.kind in ("environment", "class"):
        return s
    if s.kind == "keeper":
        party = get(m.d, s.value[0])
        if party is None or not is_kind(m.d, party, "ciamParty"):
            raise SystemExit(f"no party {s.value[0]} to scope the render to (a keeper is a ciamParty entry)")
        return s
    unknown = sorted(set(s.value) - {b.dn for b in m.bindings})
    if unknown:
        raise SystemExit(f"{m.label} binds no {', '.join(unknown)}: nothing to scope the render to")
    return s


def named_keeper(root):
    """The keeper a NAMED root names, or None for a rendered root."""
    return root[len(NAMED):] if root and root.startswith(NAMED) else None


def source_label(root):
    """What an input a root reads from another root says of where its value comes from: an asked keeper (NAMED
    root) gives it, else that root's output, applied first."""
    asked = named_keeper(root)
    return f"kept by {asked}, who is asked for it" if asked else f"an output of root {root}, applied before this one"


def asked_lines(m, named):
    """The lines a stack's render writes for what keepers who take no generated infrastructure keep, one per entry:
    named: {NAMED root: ((origin, address), ...)} (the rendered resources each entry would have)."""
    def label(origin):
        e = get(m.d, origin_entry(origin)) if origin and origin != LANDING else None
        wide = " (organization-wide)" if origin != origin_entry(origin) else ""
        return "The landing zone" if origin == LANDING else rdn_value(e) + wide if e is not None else origin
    return tuple(f"{label(origin)}: kept by {named_keeper(root)}, not rendered here "
                 f"({', '.join(a for o, a in found if o == origin)}): they take no generated infrastructure, so it is "
                 "asked of them; a render scoped to them gives their root"
                 for root, found in named.items() for origin in dict.fromkeys(o for o, _ in found))


def root_keeper(m, origins, landing=frozenset()):
    """The name of who keeps a root, from the origins of what it holds (the first that names a keeper), or None."""
    return next((k.name for o in origins for k in (keeper_of_origin(m, o, landing),) if k), None)


def is_rendered(m, e, landing_zone=False):
    """Whether the default render writes entry e of environment m in some root (the stack's or a taking keeper's), so
    other blocks may reference its resources (across roots, through inputs); False when its keeper is only asked."""
    return named_keeper(root_of(m, e, landing_zone)) is None


def scope_title(m):
    """Environment m's scope in words, for a slice's headers: 'the entries of class X', 'bindings a, b', 'what P
    keeps'; '' for the whole environment."""
    s = m.scope
    if s is None or s.kind == "environment":
        return ""
    if s.kind == "keeper":
        return f"what {party_keeper(m, s.value[0]).name} keeps"
    named = ", ".join(rdn_value(get(m.d, v)) if get(m.d, v) is not None else v for v in s.value)
    return f"the entries of class {', '.join(s.value)}" if s.kind == "class" else f"bindings {named}"

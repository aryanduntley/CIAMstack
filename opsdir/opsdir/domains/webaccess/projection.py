"""Product importers' projections onto the neutral layer: what each one shares. Pure.

A product's importer reads its own objects into its own schema, and projects each protected application, path
resource and access rule onto the neutral layer, naming the product entry it comes from (ciamProjectedFrom). The
ownership rule:
  - an importer writes only the neutral entries projected from its own entries (or new ones);
  - it replaces the attributes it says something about (an attribute given no values: the product says there are
    none) and keeps those it doesn't (a published role or backend role the product can't name, owners, a credential
    role: what the record adds);
  - a neutral entry projected from another product's entry, or recorded by an operator, is never changed: the import
    says how what it read differs from it (how a target's read-back of a render made from another product's
    projection is compared);
  - a neutral entry projected from an object of a collection the import read, which the import no longer has, is
    removed with that object.
"""
from types import MappingProxyType
from typing import NamedTuple

from ...core.directory import children, get, in_record_order, make_entry, norm_dn, one, ou_entry, rdn_value, subtree, \
    values, within
from ..edge.naming import HEADER_CONTRACTS
from ..federation.services import identity_services
from .naming import ACCESS_RULES, PROTECTED_APPS

NEUTRAL = ("top", "ciamObject")
SOURCE = "ciamProjectedFrom"
# What a projection's entries are compared on when another product's or an operator's entry holds the DN
COMPARED = ("ciamBasePath", "ciamEnforcedByRole", "ciamPublishedAs", "ciamBackendRole", "ciamBackendPort",
            "ciamBackendTls", "ciamSignOn", "ciamSignInAs", "ciamServedBy", "ciamIdleTimeout", "ciamMaxSessionTime",
            "ciamSetsHeader", "ciamRuleRef", "ciamPathPattern", "ciamMatchKind", "ciamHttpMethod", "ciamAccessMode",
            "ciamOrder", "ciamEffect", "ciamWho", "ciamRuleMatch", "ciamIncludesRule", "ciamCaseSensitive")

# What a product importer adds to its Imported for its projections: the containers, the groups (scope DN, entries:
# each projected application with its resources, each projected rule; an empty group removes a projection whose object
# is gone) and the notices (differences from entries the import doesn't own)
Projected = NamedTuple("Projected", [("containers", tuple), ("groups", tuple), ("notices", tuple)])


def neutral_entry(dn, oc, attrs):
    """A projected neutral entry of object class oc: attrs {attribute: values}, an attribute given no values (or only
    None) being one the product says has none; an attribute left out, one it says nothing about."""
    return make_entry(dn, (*NEUTRAL, oc), {k: tuple(x for x in v if x is not None) for k, v in attrs.items()})


def _merged(existing, proposed):
    """A projection merged with what the record holds: what it says replaces, what it doesn't say is kept."""
    attrs = {**(existing.attrs if existing is not None else {}), **proposed.attrs}
    kept = tuple(c for c in (existing.classes if existing is not None else ()) if c not in proposed.classes)
    return make_entry(proposed.dn, (*proposed.classes, *kept),
                      in_record_order(existing, {k: v for k, v in attrs.items() if v}))


def owns(d, e):
    """Whether a projection may write e's DN: nothing holds it, or the record's entry there is projected from the same
    product entry."""
    held = get(d, e.dn)
    return held is None or norm_dn(one(held, SOURCE) or "") == norm_dn(one(e, SOURCE) or "")


def _shown(vals):
    return ", ".join(vals) or "none"


def differences(d, e):
    """How a projection differs from the entry another product (or an operator) holds at its DN: ("<attribute>
    <record's> -> <read>", ...) over what both say."""
    held = get(d, e.dn)
    return tuple(f"{a} {_shown(values(held, a))} -> {_shown(values(e, a))}" for a in COMPARED
                 if a in e.attrs and set(values(held, a)) != set(values(e, a)))


def _whose(d, e):
    source = one(get(d, e.dn), SOURCE)
    return f"projected from {source}" if source else "recorded by an operator"


def _projected_under(d, base, scopes):
    """The DNs of the neutral entries under base projected from a product entry within one of scopes."""
    return tuple(e.dn for e in subtree(d, base) if one(e, SOURCE)
                 and any(within(one(e, SOURCE), s) for s in scopes))


def _kept(d, app, res, scopes):
    """The resources the record holds below an application that a projection doesn't own: an operator's, or another
    product's (a resource projected from an object the import read is replaced by what it reads now)."""
    mine = {r.norm for r in res}
    return tuple(r for r in children(d, app.dn, "ciamPathResource") if r.norm not in mine
                 and not (one(r, SOURCE) and any(within(one(r, SOURCE), s) for s in scopes)))


def projected(d, apps, rules, scopes, label):
    """Projected of a product import: apps ((application entry, (its resource entries, ...)), ...) and rules (access
    rule entries) as the import projects them, scopes the product DNs whose subtrees the import replaces (what it
    read), label what the notices call the import. Each entry is written where the projection owns it (owns), merged
    with what the record holds; elsewhere the import's differences are notices. A neutral entry projected from an
    entry within scopes that the import doesn't project again is removed."""
    taken = tuple(a for a, _ in apps if not owns(d, a)) + tuple(r for r in rules if not owns(d, r))
    taken_dns = {e.norm for e in taken}
    app_groups = tuple((a.dn, (_merged(get(d, a.dn), a), *(_merged(get(d, r.dn), r) for r in res if owns(d, r)),
                               *_kept(d, a, res, scopes)))
                       for a, res in apps if a.norm not in taken_dns)
    rule_groups = tuple((r.dn, (_merged(get(d, r.dn), r),)) for r in rules if r.norm not in taken_dns)
    written = {norm_dn(dn) for dn, _ in (*app_groups, *rule_groups)}
    stale = tuple(dn for base in (PROTECTED_APPS, ACCESS_RULES) for dn in _projected_under(d, base, scopes)
                  if norm_dn(dn) not in written and not any(within(dn, w) for w in written)
                  and get(d, dn) is not None and "ciamPathResource" not in get(d, dn).classes)
    notices = tuple(f"{label}: {rdn_value(e)} ({e.dn.split(',', 1)[1].split(',')[0]}) is "
                    f"{_whose(d, e)}, which this import doesn't change"
                    + (f"; what it read differs: {'; '.join(diff)}" if diff else "; what it read matches it")
                    for e in taken for diff in (differences(d, e),))
    return Projected((ou_entry(PROTECTED_APPS), ou_entry(ACCESS_RULES)),
                     (*app_groups, *rule_groups, *((dn, ()) for dn in stale)), notices)


def after_import(d, imported):
    """The record as an Imported leaves it (each group's subtree made exactly its entries, its containers added),
    without the store's rules: what an importer projects its own objects from."""
    scopes = tuple(norm_dn(s) for s, _ in imported.groups)
    kept = {k: e for k, e in d.entries.items() if not any(within(k, s) for s in scopes)}
    made = {e.norm: e for e in (*imported.containers, *(e for _, entries in imported.groups for e in entries))}
    return d._replace(entries=MappingProxyType({**kept, **made}))


def merged_import(imported, extra):
    """An Imported with a projection's containers, groups and notices added after the product's own."""
    return imported._replace(containers=(*imported.containers, *extra.containers),
                             groups=(*imported.groups, *extra.groups), notices=(*imported.notices, *extra.notices))


def served_by_issuer(d, issuer):
    """The DN of the identity service whose OpenID Connect issuer is issuer (trailing slash aside), or None."""
    want = (issuer or "").rstrip("/")
    return next((s.dn for s in identity_services(d) if want and (one(s, "ciamOidcIssuer") or "").rstrip("/") == want),
                None)


def header_contracts(d, names):
    """The DNs of the header contracts naming these headers (case aside), in the names' order, each once."""
    held = {(one(c, "ciamHeaderName") or "").lower(): c.dn for c in children(d, HEADER_CONTRACTS,
                                                                                 "ciamHeaderContract")}
    return tuple(dict.fromkeys(held[n.lower()] for n in names if n and n.lower() in held))


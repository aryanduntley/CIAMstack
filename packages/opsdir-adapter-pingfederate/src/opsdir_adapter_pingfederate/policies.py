"""PingFederate's authentication policies: policy contracts, the default authentication policy's trees and policy
fragments, read from the Admin API into the record and rendered back (environment-neutral). Pure.

  /authenticationPolicyContracts     -> pingfedPolicyContract (cn: its id): the attributes it hands on
  /authenticationPolicies/default    -> pingfedAuthPolicySet cn=default (its own settings: fail if nothing is
                                        selected, tracked parameters, default sources), one pingfedAuthPolicy per tree
                                        below it (cn: the tree's name; its place, whether it is used, its tree)
  /authenticationPolicies/fragments  -> pingfedAuthPolicy (cn: its id) under ou=policy-fragments

A tree keeps its nodes as PingFederate writes them: each node's action (an IdP adapter or connection to authenticate
with, a selector, a policy contract to map to, a fragment, done, ...) and its children, by the result that leads to
them. The objects a tree runs are linked by DN (pingfedUses); a policy that names one the record doesn't have is
named in the notices and blocked by the planner. The default policy's trees are imported as one: a tree the export
no longer has is removed.
"""
import json

from opsdir.core.directory import children, get, make_entry, one, rdn_value
from opsdir.core.jsondata import canonical
from opsdir.core.naming import rdn_safe
from .naming import CONTRACTS, DEFAULT_POLICY, FRAGMENTS, named
from .objects import describe, links, merged_attrs

TREE_OWNED = ("cn", "pingfedPosition", "pingfedEnabled", "pingfedPolicyTree", "pingfedUses", "pingfedConfig")


def _id(ref):
    return ref.get("id") if isinstance(ref, dict) else None


def node_refs(node):
    """(kind, id) of the objects a tree node and the nodes below it run, each once."""
    if not isinstance(node, dict):
        return ()
    action = node.get("action") if isinstance(node.get("action"), dict) else {}
    kind = action.get("type")
    source = action.get("authenticationSource") if isinstance(action.get("authenticationSource"), dict) else {}
    own = (("idp-adapter", _id(source.get("sourceRef"))) if kind == "AUTHN_SOURCE" and source.get("type") == "IDP_ADAPTER"
           else ("selector", _id(action.get("authenticationSelectorRef"))) if kind == "AUTHN_SELECTOR"
           else ("contract", _id(action.get("authenticationPolicyContractRef"))) if kind == "APC_MAPPING"
           else ("fragment", _id(action.get("fragment"))) if kind == "FRAGMENT" else None)
    below = (r for child in node.get("children") or () for r in node_refs(child))
    return tuple(dict.fromkeys((*((own,) if own and own[1] else ()), *below)))


def fragment_refs(fragment):
    """(kind, id) of what a fragment runs and the contracts it takes and hands on."""
    ends = (("contract", _id(fragment.get(k))) for k in ("inputs", "outputs"))
    return tuple(dict.fromkeys((*node_refs(fragment.get("rootNode")), *((k, i) for k, i in ends if i))))


# ------------------------------------------------------------------ import
def contract_entry(d, item):
    """(DN, entry, notices) for one policy contract, or (None, None, notices) when its id can't name one."""
    cid = item.get("id")
    if not rdn_safe(cid or ""):
        return None, None, (f"policy contract {item.get('name') or cid}: its id can't name an entry, not imported",)
    dn = named(CONTRACTS, cid)
    owned = {"cn": (cid,), "pingfedConfig": (canonical({k: v for k, v in item.items() if k != "id"}),)}
    return dn, make_entry(dn, ("top", "ciamObject", "pingfedPolicyContract"),
                          merged_attrs(get(d, dn), owned, ("cn", "pingfedConfig"))), ()


def _tree(d, n, tree, exported):
    name = tree.get("name")
    uses, lost = links(d, node_refs(tree.get("rootNode")), exported)
    dn = named(DEFAULT_POLICY, name)
    rest = {k: v for k, v in tree.items() if k not in ("name", "enabled", "rootNode")}
    owned = {"cn": (name,), "pingfedPosition": (str(n),), "pingfedEnabled": ("FALSE" if tree.get("enabled") is False
                                                                            else "TRUE",),
             "pingfedPolicyTree": (canonical(tree.get("rootNode") or {}),), "pingfedUses": uses,
             "pingfedConfig": (canonical(rest) if rest else None,)}
    return (make_entry(dn, ("top", "ciamObject", "pingfedAuthPolicy"), merged_attrs(get(d, dn), owned, TREE_OWNED)),
            tuple(f"authentication policy {name}: runs {describe(k, i)}, which neither the export nor the record has"
                  for k, i in lost))


def policy_group(d, policy, exported):
    """((DN, entries), notices): the default authentication policy's settings and its trees, as one group."""
    trees = [t for t in policy.get("authnSelectionTrees") or () if isinstance(t, dict)]
    names = [t.get("name") for t in trees]
    usable = [(n, t) for n, t in enumerate(trees)
              if rdn_safe(t.get("name") or "") and names.index(t.get("name")) == n]
    built = [_tree(d, n, t, exported) for n, t in usable]
    settings = {k: v for k, v in policy.items() if k != "authnSelectionTrees"}
    owned = {"cn": ("default",), "pingfedConfig": (canonical(settings) if settings else None,)}
    head = make_entry(DEFAULT_POLICY, ("top", "ciamObject", "pingfedAuthPolicySet"),
                      merged_attrs(get(d, DEFAULT_POLICY), owned, ("cn", "pingfedConfig")))
    skipped = [t.get("name") for n, t in enumerate(trees) if (n, t) not in usable]
    return (DEFAULT_POLICY, (head, *(e for e, _ in built))), \
        (*(n for _, ns in built for n in ns),
         *(f"authentication policy {name!r}: its name can't name an entry, or another tree has it; not imported"
           for name in skipped))


def fragment_entry(d, item, exported):
    """(DN, entry, notices) for one policy fragment, or (None, None, notices) when its id can't name one."""
    fid = item.get("id")
    label = f"policy fragment {item.get('name') or fid}"
    if not rdn_safe(fid or ""):
        return None, None, (f"{label}: its id can't name an entry, not imported",)
    uses, lost = links(d, fragment_refs(item), exported)
    dn = named(FRAGMENTS, fid)
    rest = {k: v for k, v in item.items() if k not in ("id", "rootNode")}
    owned = {"cn": (fid,), "pingfedPolicyTree": (canonical(item.get("rootNode") or {}),), "pingfedUses": uses,
             "pingfedConfig": (canonical(rest) if rest else None,)}
    entry = make_entry(dn, ("top", "ciamObject", "pingfedAuthPolicy"), merged_attrs(get(d, dn), owned, TREE_OWNED))
    return dn, entry, tuple(f"{label}: runs {describe(k, i)}, which neither the export nor the record has"
                            for k, i in lost)


def policy_groups(d, found, exported):
    """(groups, notices) for the export's policy contracts, default authentication policy and fragments."""
    parts = [*(contract_entry(d, c) for c in found.get("contract", ())),
             *(fragment_entry(d, f, exported) for f in found.get("fragment", ()))]
    policies = [policy_group(d, p, exported) for p in found.get("policy", ())[:1]]
    return ((*((dn, (e,)) for dn, e, _ in parts if dn), *(g for g, _ in policies)),
            (*(n for _, _, ns in parts for n in ns), *(n for _, ns in policies for n in ns)))


# ------------------------------------------------------------------ render
def _json(e, attr):
    return json.loads(one(e, attr) or "{}")


def _in_order(entries):
    return sorted(entries, key=lambda e: (int(one(e, "pingfedPosition", "0")), rdn_value(e)))


def policy_files(d):
    """{pingfederate/<file>: text}: the policy contracts, the default authentication policy and the fragments the
    record has (environment-neutral)."""
    contracts = children(d, CONTRACTS, "pingfedPolicyContract")
    fragments = children(d, FRAGMENTS, "pingfedAuthPolicy")
    head = get(d, DEFAULT_POLICY)
    policy = {**_json(head, "pingfedConfig"), "authnSelectionTrees": [
        {"name": rdn_value(t), "enabled": one(t, "pingfedEnabled", "TRUE") == "TRUE", **_json(t, "pingfedConfig"),
         "rootNode": _json(t, "pingfedPolicyTree")}
        for t in _in_order(children(d, DEFAULT_POLICY, "pingfedAuthPolicy"))]} if head is not None else None
    out = {"authentication-policy-contracts.json": [{"id": rdn_value(c), **_json(c, "pingfedConfig")} for c in contracts]
           if contracts else None,
           "authentication-policies.json": policy,
           "authentication-policy-fragments.json": [{"id": rdn_value(f), **_json(f, "pingfedConfig"),
                                                     "rootNode": _json(f, "pingfedPolicyTree")} for f in fragments]
           if fragments else None}
    return {f"pingfederate/{p}": json.dumps(v, indent=2) + "\n" for p, v in out.items() if v is not None}

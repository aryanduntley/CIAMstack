"""Configuration drift: each server's latest observed snapshot compared with the declared configuration."""
from ...core.directory import children, get, norm_dn, one, rdn_value, subtree
from .naming import DECLARED, OBSERVED

# governance, and what a policy is for: not server configuration, so never observed
IGNORE = frozenset({"ciamLastChanged", "ciamChangeRef", "ciamOwner", "description", "ciamPopulation"})
DRIFT_HEADERS = ("server", "finding", "entry (relative to declared config)", "detail")


def _rel(dn, base):
    return dn[: -len(base) - 1] if dn.lower().endswith("," + base.lower()) else None


def _config(e):
    """The entry's configuration, attributes in name order (however the record happens to hold them)."""
    return {k: sorted(v) for k, v in sorted(e.attrs.items()) if k not in IGNORE}


def _fmt(attrs):
    return ", ".join(f"{k}={'|'.join(v)}" for k, v in attrs.items() if k not in ("cn", "ou"))


def latest_snapshots(d):
    """{server dn: its most recent snapshot} (the first one wins a tie on capture time)."""
    snaps = children(d, OBSERVED, "ciamSnapshot")
    servers = dict.fromkeys(one(s, "ciamServerRef") for s in snaps)
    return {srv: max((s for s in snaps if one(s, "ciamServerRef") == srv), key=lambda s: one(s, "ciamCapturedAt"))
            for srv in servers}


def _compare(server, rel, declared, observed):
    if declared and not observed:
        return ((server, "missing on server", rel, ""),)
    if observed and not declared:
        return ((server, "not declared (unrecorded change)", rel, _fmt(_config(observed))),)
    a, b = _config(declared), _config(observed)
    if a == b:
        return ()
    diffs = [f"{k}: declared {a.get(k)} observed {b.get(k)}" for k in sorted(set(a) | set(b)) if a.get(k) != b.get(k)]
    return ((server, "differs", rel, "; ".join(diffs)),)


def _branch_drift(d, server, snap, branch):
    rel_branch = _rel(branch.dn, snap.dn)
    declared = {_rel(e.dn, DECLARED): e for e in subtree(d, f"{rel_branch},{DECLARED}")}
    observed = {_rel(e.dn, snap.dn): e for e in subtree(d, branch.dn)}
    return tuple(f for rel in sorted(set(declared) | set(observed))
                 for f in _compare(server, rel, declared.get(rel), observed.get(rel)))


def drift(d, servers=None):
    """Compare the latest snapshot of each server with the declared config, branch by branch; `servers` (DNs)
    limits it to those servers. Only branches present in a snapshot are compared (a snapshot may capture part of
    the config)."""
    wanted = None if servers is None else {norm_dn(s) for s in servers}
    latest = {srv: snap for srv, snap in latest_snapshots(d).items() if wanted is None or norm_dn(srv) in wanted}
    return [f for srv in sorted(latest) for branch in children(d, latest[srv].dn)
            for f in _branch_drift(d, rdn_value(get(d, srv)), latest[srv], branch)]

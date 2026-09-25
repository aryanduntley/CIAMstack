"""Reports that need more than one SQL view: config drift."""
from .render.model import DECL

OBS = "ou=observed,ou=config,dc=ciam-ops"
IGNORE = {"ciamLastChanged", "ciamChangeRef", "ciamOwner", "description"}   # governance, not config


def _rel(dn, base):
    return dn[: -len(base) - 1] if dn.lower().endswith("," + base.lower()) else None


def _config(e):
    return {k: sorted(v) for k, v in e.attrs.items() if k not in IGNORE}


def drift(d):
    """Compare the latest snapshot of each server with the declared config, branch by branch.
    Only branches present in a snapshot are compared (a snapshot may capture part of the config)."""
    latest = {}
    for s in d.children(OBS, "ciamSnapshot"):
        srv = s.one("ciamServerRef")
        if srv not in latest or s.one("ciamCapturedAt") > latest[srv].one("ciamCapturedAt"):
            latest[srv] = s
    findings = []
    for srv, snap in sorted(latest.items()):
        server = d.get(srv)
        for branch in d.children(snap.dn):
            rel_branch = _rel(branch.dn, snap.dn)
            declared = {_rel(e.dn, DECL): e for e in d.subtree(f"{rel_branch},{DECL}")}
            observed = {_rel(e.dn, snap.dn): e for e in d.subtree(branch.dn)}
            for rel in sorted(set(declared) | set(observed)):
                a, b = declared.get(rel), observed.get(rel)
                if a and not b:
                    findings.append((server.name, "missing on server", rel, ""))
                elif b and not a:
                    findings.append((server.name, "not declared (unrecorded change)", rel, _fmt(_config(b))))
                elif _config(a) != _config(b):
                    diffs = [f"{k}: declared {_config(a).get(k)} observed {_config(b).get(k)}"
                             for k in sorted(set(_config(a)) | set(_config(b))) if _config(a).get(k) != _config(b).get(k)]
                    findings.append((server.name, "differs", rel, "; ".join(diffs)))
    return findings


def _fmt(attrs):
    return ", ".join(f"{k}={'|'.join(v)}" for k, v in attrs.items() if k not in ("cn", "ou"))

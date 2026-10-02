"""The importer `linux/baseline`: Linux servers' own files read into the record as host baselines. Pure.

Takes one folder per server, named by its hostname (or its record name), holding copies of the server's files at their
paths under / and the output of a few commands (java/version.txt, java/cacerts.txt, packages.txt: see host.py). A host
baseline is intent: one per server role (ciamTargetRole), from every server of the role found, in any environment.

  single facts     OS, Java runtime, huge pages, FIPS, SELinux: the first server's (by name); servers that differ
                   are named
  lists            limits, kernel settings, agents, service units, truststore additions: every value any server has;
                   values only some servers have are named (drift); a limit or kernel setting servers set to
                   different values is recorded once, the first server's, and named
  truststore       an addition the record holds a certificate for (by SHA-256 fingerprint) is linked to it
                   (ciamTrustsCertificate); the others are kept by fingerprint (ciamTrustedFingerprint) and named
  observed         names pinned in /etc/hosts and search domains: every server's
  not cleared      a fact none of the role's servers' files gave is left as the record has it

What the record adds to a baseline (owners, criticality) is kept on import.
"""
from opsdir.core.contract import Imported, Importer
from opsdir.core.directory import get, make_entry, merged_attrs, one, ou_entry, rdn_value
from opsdir.core.environment import server_named
from opsdir.core.sources import by_folder
from opsdir.domains.compute.naming import BASELINES, baseline_dn
from opsdir.domains.pki.credentials import certificates_by_fingerprint
from .host import host_facts

SINGLE = (("os", "ciamOs", "OS"), ("jdk", "ciamJdk", "Java runtime"), ("huge_pages", "ciamHugePages", "huge pages"),
          ("fips", "ciamFipsMode", "FIPS mode"), ("selinux", "ciamSelinuxMode", "SELinux mode"))
def _setting(v):
    """What a limit or kernel setting sets (its value left out): 'ds soft nofile', 'net.core.somaxconn'."""
    return v.split("=", 1)[0] if "=" in v else v.rsplit(" ", 1)[0]


def _whole(v):
    return v


LISTS = (("limits", "ciamOsLimit", "limit", _setting), ("kernel", "ciamKernelSetting", "kernel setting", _setting),
         ("agents", "ciamHostAgent", "agent", _whole), ("units", "ciamServiceUnit", "service unit", _whole))
OBSERVED = (("pinned", "ciamPinnedHost"), ("search", "ciamSearchDomain"))


def _roles(d):
    return tuple(dict.fromkeys(one(e, "ciamServerRole") for e in d.entries.values() if "ciamServer" in e.classes))


def _single(role, field, label, facts):
    """(value, notices): the first server's value; servers whose value differs are named."""
    given = [(s, getattr(f, field)) for s, f in facts if getattr(f, field) is not None]
    if not given:
        return None, ()
    first = given[0][1]
    odd = [f"{rdn_value(s)}: {v}" for s, v in given if v != first]
    return first, ((f"role {role}: {label} differs between servers ({rdn_value(given[0][0])}: {first}; "
                    f"{'; '.join(odd)}); recorded the first",) if odd else ())


def _union(role, field, label, facts, key=_whole):
    """(values, notices): every value a server has, one per key (the first server's); values only some of the role's
    servers have, and keys servers give different values, are named."""
    given = [(s, getattr(f, field)) for s, f in facts if getattr(f, field) is not None]
    if not given:
        return None, ()
    every = tuple(dict.fromkeys(v for _, vs in given for v in vs))
    first = {k: next(v for v in every if key(v) == k) for k in dict.fromkeys(key(v) for v in every)}
    kept = tuple(first.values())
    keys = {k: [(rdn_value(s), v) for s, vs in given for v in vs if key(v) == k] for k in first}
    differ = tuple(f"role {role}: {label} {k!r} differs between servers "
                   f"({'; '.join(f'{s}: {v}' for s, v in found)}); recorded {first[k]!r}"
                   for k, found in keys.items() if len({v for _, v in found}) > 1)
    partial = tuple(f"role {role}: {label} {v!r} is on {', '.join(on)} but not "
                    f"{', '.join(rdn_value(s) for s, vs in given if not any(key(x) == key(v) for x in vs))}: one "
                    "server has it, or the others drifted"
                    for v in kept for on in ([rdn_value(s) for s, vs in given if any(key(x) == key(v) for x in vs)],)
                    if len(on) < len(given))
    return kept, (*differ, *partial)


def baseline_entry(d, role, facts, held_certs):
    """(entry, notices) of one server role's baseline from its servers' facts ([(server, HostFacts)])."""
    dn = baseline_dn(role)
    singles = {attr: _single(role, field, label, facts) for field, attr, label in SINGLE}
    lists = {attr: _union(role, field, label, facts, key) for field, attr, label, key in LISTS}
    trusted, trust_notes = _union(role, "trusted", "truststore addition", facts)
    observed = {attr: _union(role, field, "", facts)[0] for field, attr in OBSERVED}
    linked = tuple(held_certs[f].dn for f in trusted or () if f in held_certs)
    unknown = tuple(f for f in trusted or () if f not in held_certs)
    owned = {"cn": (role,), "ciamTargetRole": (role,), "ciamFoundOn": tuple(sorted(s.dn for s, _ in facts)),
             **{a: (v,) for a, (v, _) in singles.items() if v is not None},
             **{a: v for a, (v, _) in lists.items() if v is not None},
             **({"ciamTrustsCertificate": linked, "ciamTrustedFingerprint": unknown} if trusted is not None else {}),
             **{a: v for a, v in observed.items() if v is not None}}
    names = (*(k for k, v in owned.items()), *(("ciamTrustsCertificate", "ciamTrustedFingerprint")
                                               if trusted is not None else ()))
    entry = make_entry(dn, ("top", "ciamObject", "ciamHostBaseline"),
                       merged_attrs(get(d, dn), owned, tuple(dict.fromkeys(names))))
    notices = (*(n for _, ns in singles.values() for n in ns), *(n for _, ns in lists.values() for n in ns),
               *(trust_notes if trusted is not None else ()),
               *((f"role {role}: its servers' Java truststore adds {len(unknown)} certificate(s) the record holds no "
                  f"certificate for ({', '.join(unknown)}): record them so a rebuilt server gets them",)
                 if unknown else ()))
    return entry, notices


def read_baseline(files, d, patterns, at=None):
    """Imported: one host baseline per server role, from its servers' own files."""
    folders = by_folder(files)
    placed = [(f, *server_named(d, f, _roles(d), "server")) for f in folders]
    facts = [(s, host_facts(folders[f], (one(s, "ciamHostname"), rdn_value(s)))) for f, s, _ in placed if s]
    roles = tuple(dict.fromkeys(one(s, "ciamServerRole") for s, _ in facts))
    held = certificates_by_fingerprint(d)
    built = [baseline_entry(d, r, sorted(((s, f) for s, f in facts if one(s, "ciamServerRole") == r),
                                         key=lambda sf: rdn_value(sf[0]).lower()), held) for r in roles]
    return Imported(
        containers=(ou_entry(BASELINES),),
        groups=tuple((e.dn, (e,)) for e, _ in built),
        notices=(*(why for _, s, why in placed if s is None),
                 *(f"{rdn_value(s)} {n}" for s, f in facts for n in f.notes), *(n for _, ns in built for n in ns),
                 *(("no server folders (one folder per server, named by its hostname, holding its files at their "
                    "paths under / and java/version.txt, java/cacerts.txt, packages.txt)",) if not folders else ())))


BASELINE_IMPORTER = Importer("baseline", "Linux servers' host baseline (one folder per server, named by its "
                                         "hostname, holding its files at their paths under /)", read_baseline)

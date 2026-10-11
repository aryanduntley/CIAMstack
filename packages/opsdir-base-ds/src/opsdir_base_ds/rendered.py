"""The lineage's own rendered files read back (config.py renders them), so a render imports back as the record it came
from. Pure.

  ds/dsconfig.batch   -> config.ldif-shaped records (batch_records), mapped as a server's config.ldif is
                         (observe.records_entries): backends from the batch's `# backend <name> (<base DN>)` lines
                         (setup --profile creates them; the type isn't in the render, so the record's is kept),
                         create-backend-index, create-password-policy and set-password-policy-prop, set-connection-
                         handler-prop (the product's handler names), set-log-publisher-prop; the replication purge
                         delay (set-synchronization-provider-prop) on the topology (purge_delay)
  ds/acis.ldif        -> the ACIs (aci_entries): name, target DN, target attributes as user-schema records (or all
                         attributes), rights, grantees as the consumers whose bind DN each userdn is; owners,
                         justification and review dates are the record's and kept
"""
import re
import shlex

from opsdir.core.directory import get, make_entry, merged_attrs, one
from opsdir.core.interchange.ldif import parse
from opsdir.domains.directory.consumers import consumer_by_bind_dn
from opsdir.domains.directory.naming import ACIS, DECLARED
from opsdir.domains.directory.user_schema import attribute_records

BACKEND_LINE = re.compile(r"^#\s*backend\s+(\S+)\s+\((.+)\)\s*$")
ACI = re.compile(r'^\(targetattr\s*=\s*"([^"]*)"\)\s*\(version 3\.0;\s*acl\s+"([^"]+)";\s*allow\s*\(([^)]*)\)\s*'
                 r'userdn\s*=\s*"([^"]*)";\s*\)$')
ACI_OWNED = ("cn", "ciamAciTargetDn", "ciamAciAllAttributes", "ciamAciTargetAttr", "ciamAciRight", "ciamAciGrantee")
READ = ("create-backend-index", "create-password-policy", "set-password-policy-prop", "set-connection-handler-prop",
        "set-log-publisher-prop", "set-synchronization-provider-prop")


# ------------------------------------------------------------------ the dsconfig batch
def _commands(text):
    """(subcommand, {option: (values, ...)}) of each command line; `--set prop:value` as option `prop`."""
    def options(tokens):
        pairs = list(zip(tokens[1::2], tokens[2::2]))
        sets = [v.split(":", 1) for o, v in pairs if o == "--set" and ":" in v]
        named = [(o[2:], v) for o, v in pairs if o != "--set" and o.startswith("--")]
        return {k: tuple(v for kk, v in (*named, *sets) if kk == k) for k, _ in (*named, *sets)}
    lines = (line.strip() for line in text.splitlines())
    return tuple((tokens[0], options(tokens)) for tokens in (shlex.split(line) for line in lines
                                                             if line and not line.startswith("#")) if tokens)


def _one(opts, name):
    return (opts.get(name) or (None,))[0]


def _backend(d, name, base):
    held = get(d, f"cn={name},ou=backends,{DECLARED}")
    kind = one(held, "ciamBackendType") if held else None
    return (f"ds-cfg-backend-id={name},cn=Backends,cn=config",
            {"objectclass": ("top", "ds-cfg-backend", f"ds-cfg-{kind}-backend"), "ds-cfg-backend-id": (name,),
             "ds-cfg-base-dn": (base,)}) if kind else None


def _record(command, opts):
    if command == "create-backend-index":
        return (f"ds-cfg-attribute={_one(opts, 'index-name')},cn=Indexes,"
                f"ds-cfg-backend-id={_one(opts, 'backend-name')},cn=Backends,cn=config",
                {"objectclass": ("ds-cfg-backend-index",), "ds-cfg-attribute": (_one(opts, "index-name"),),
                 "ds-cfg-index-type": opts.get("index-type", ())})
    kind, name = {"create-password-policy": ("ds-cfg-password-policy", "policy-name"),
                  "set-password-policy-prop": ("ds-cfg-password-policy", "policy-name"),
                  "set-connection-handler-prop": ("ds-cfg-connection-handler", "handler-name"),
                  "set-log-publisher-prop": ("ds-cfg-log-publisher", "publisher-name")}.get(command, (None, None))
    if kind is None:
        return None
    props = {f"ds-cfg-{k}": v for k, v in opts.items() if k not in (name, "type")}
    return f"cn={_one(opts, name)},cn=config", {"objectclass": (kind,), "cn": (_one(opts, name),), **props}


def batch_records(d, text):
    """(records, notices): the batch as config.ldif-shaped records ((dn, {lowercase attribute: values}))."""
    named = tuple(m.groups() for m in (BACKEND_LINE.match(line.strip()) for line in text.splitlines()) if m)
    backends = tuple((name, _backend(d, name, base)) for name, base in named)
    commands = _commands(text)
    records = tuple(r for r in (_record(c, o) for c, o in commands) if r)
    return ((*(r for _, r in backends if r), *records),
            (*(f"ds/dsconfig.batch: backend {name}: the record holds no type for it (setup creates it); not read"
               for name, r in backends if r is None),
             *(f"ds/dsconfig.batch: {c}: not read (opsdir doesn't render it)" for c in
               dict.fromkeys(c for c, _ in commands if c not in READ))))


def purge_delay(text):
    """The replication purge delay the batch sets, or None."""
    return next((_one(o, "replication-purge-delay") for c, o in _commands(text)
                 if c == "set-synchronization-provider-prop" and _one(o, "replication-purge-delay")), None)


# ------------------------------------------------------------------ the ACIs
def _aci(d, target, value, attrs, label):
    """(entry or None, notices) for one aci value at target DN."""
    m = ACI.match(value.strip())
    if not m:
        return None, (f"{label}: an ACI on {target} isn't in the form opsdir renders; not read: {value[:80]}",)
    targetattr, name, rights, userdn = m.groups()
    names = () if targetattr.strip() == "*" else tuple(a.strip() for a in targetattr.split("||") if a.strip())
    binds = tuple(u.strip().removeprefix("ldap:///") for u in userdn.split("||") if u.strip())
    grantees = tuple((b, consumer_by_bind_dn(d, b)) for b in binds)
    dn = f"cn={name},{ACIS}"
    owned = {"cn": (name,), "ciamAciTargetDn": (target,),
             "ciamAciAllAttributes": ("TRUE",) if targetattr.strip() == "*" else (None,),
             "ciamAciTargetAttr": tuple(attrs[a.lower()].dn for a in names if a.lower() in attrs),
             "ciamAciRight": tuple(r.strip() for r in rights.split(",") if r.strip()),
             "ciamAciGrantee": tuple(c.dn for _, c in grantees if c is not None)}
    return (make_entry(dn, ("top", "ciamAci"), merged_attrs(get(d, dn), owned, ACI_OWNED)),
            (*(f"{label}: ACI {name}: attribute {a} has no user-schema record; not recorded" for a in names
               if a.lower() not in attrs),
             *(f"{label}: ACI {name}: no consumer binds as {b}; grantee not recorded" for b, c in grantees
               if c is None)))


def aci_entries(d, text, label):
    """(entries, notices): the ACIs an ACI LDIF adds (ldapmodify `add: aci` records)."""
    attrs = attribute_records(d)
    found = tuple(_aci(d, r.dn, v, attrs, label) for r in parse(text) if r.changetype == "modify"
                  for op, attr, vals in r.mods if op == "add" and attr.lower() == "aci" for v in vals)
    return tuple(e for e, _ in found if e is not None), tuple(n for _, ns in found for n in ns)

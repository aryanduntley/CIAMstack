"""The read-back (importer panos/running-config, milestone 6.2c): a Panorama's or firewall's RUNNING security rules
against the record's firewall rules and what this add-on renders, read-only. Pure.

Files are laid out per environment and appliance, <cloud>/<env>/<appliance>/ (the appliance's record name: a
ciamAppliance of stack role network-firewall), holding running.py's forms: a running-config.xml snapshot, or the api/
answers `opsdir collect` saves. The environment's rules are read where the add-on writes them and where they would
still run: on a Panorama, its device group's pre- and post-rulebase and shared's (enforcement order: shared pre, the
device group's pre, its post, shared post); on a firewall, its vsys's rulebase (no scope: vsys1).

A running rule is the record's rule its description's marker names (opsdir <cloud>/<env>: <rule> -> role <role>), else
the one whose name the add-on writes (its description then differs: a fact). Its sources, ports, protocol and target
role are read into the rule (core.inventory, infrastructure ImportKind firewall): a difference is the import's conflict
to take or keep; a source or service that doesn't resolve leaves the record's values as they are. What the rule can't
hold is observed (core infrastructure.running): its state (committed on a Panorama, its delivery to the firewalls not
confirmed by this read; deployed on a firewall; disabled; missing: the record holds it and no rule runs for it) and
facts (an action other than allow, logging at session end off, destinations other than the target role's servers, a
description, members it can't resolve; negation, a schedule, another rulebase). A rule carrying the environment's marker
for a rule the record lacks, or an unmarked allow to the environment's servers (their addresses or the add-on's server
objects), is recorded on the appliance as unrecorded. An external allowlist whose ciamAllowlistRef is
panos:<management host>/<scope>/<address|address-group|rule>/<name> records the addresses that object holds
(a rule's sources for partner-ingress, else its destinations) when the files read hold it.
"""
import ipaddress
from functools import reduce
from typing import NamedTuple

from opsdir.core.contract import Imported, Importer
from opsdir.core.directory import get, one, rdn_value, within
from opsdir.core.environment import env_dn, env_model, of_class, servers_with_role
from opsdir.core.inventory import environment_groups, resource
from opsdir.core.secrets import scan
from opsdir.core.sources import by_folder, folders
from opsdir.domains.infrastructure.appliances import appliances
from opsdir.domains.infrastructure.running import allowlist_refs, observed_appliance, observed_rule, recorded_allowlist
from .rules import marked, rule_name, server_object
from .running import SHARED, read_running, resolve_addresses, resolve_services

ADAPTER = "panos"
STACK_ROLE = "network-firewall"
_UNREPORTED = "is in the record but not in what the cloud reports"      # core.inventory's notice; ours says more


def placement(a):
    """(kind, own scope, ((scope, rulebase), ...) in enforcement order, (scope, rulebase) the add-on writes to) of
    appliance a: a firewall's vsys (ciamApplianceScope vsys<n>, none: vsys1) or a Panorama device group."""
    scope = one(a, "ciamApplianceScope") or "vsys1"
    if scope.startswith("vsys"):
        own = f"vsys/{scope}"
        return "firewall", own, ((own, "rulebase"),), (own, "rulebase")
    own = f"device-group/{scope}"
    return "panorama", own, ((SHARED, "pre-rulebase"), (own, "pre-rulebase"), (own, "post-rulebase"),
                             (SHARED, "post-rulebase")), (own, "pre-rulebase")


def _net(ip):
    try:
        return str(ipaddress.ip_network(ip, strict=False))
    except ValueError:
        return None


def _server_nets(servers):
    return tuple(sorted({n for s in servers for n in (_net(one(s, "ciamPrivateIp") or ""),) if n}))


def _protocols(services):
    return tuple(dict.fromkeys(p for p, _ in services))


def _facts(m, r, run, rule, via, role, where, expected):
    """(attributes read into the rule, facts) of running rule rule matched to the record's rule r."""
    srcs, src_un = resolve_addresses(run, rule.scope, rule.sources)
    dsts, dst_un = resolve_addresses(run, rule.scope, rule.destinations)
    svcs, svc_un = resolve_services(run, rule.scope, rule.services)
    protos = _protocols(svcs)
    held = one(r, "ciamProtocol") or "tcp"
    wanted = _server_nets(servers_with_role(m, role or one(r, "ciamTargetRole")))
    attrs = {**({"ciamSourceCidr": srcs} if srcs and not src_un else {}),
             **({"ciamPort": tuple(sorted({p for _, p in svcs}, key=int))} if len(protos) == 1 and not svc_un else {}),
             **({"ciamProtocol": protos} if len(protos) == 1 and not svc_un and protos[0] != held else {}),
             **({"ciamTargetRole": (role,)} if role else {})}
    facts = (*((f"action {rule.action or 'none'}",) if rule.action != "allow" else ()),
             *(("log-end no",) if rule.log_end == "no" else ()),
             *(f"destination {u}" for u in dst_un),
             *((f"destination {', '.join(dsts) or 'none'}",) if not dst_un and dsts != wanted else ()),
             *(f"source {u}" for u in src_un),
             *(f"service {u}" for u in svc_un),
             *((f"service {', '.join(f'{p}/{n}' for p, n in svcs)}",) if len(protos) > 1 else ()),
             *((f"description {rule.description or 'none'}",) if via == "name" else ()),
             *(("negate-source yes",) if rule.negate_source else ()),
             *(("negate-destination yes",) if rule.negate_destination else ()),
             *((f"schedule {rule.schedule}",) if rule.schedule else ()),
             *((f"rulebase {' '.join(where)}",) if where != expected else ()))
    return attrs, facts


def _summary(where, rule):
    return (f"{' '.join(where)} {rule.name}: {','.join(rule.sources) or 'none'} -> "
            f"{','.join(rule.destinations) or 'none'} {','.join(rule.services) or 'none'}"
            + (f" ({rule.action})" if rule.action != "allow" else "") + (" (disabled)" if rule.disabled else ""))


def _to_servers(m, run, rule):
    """Whether an unmarked running rule allows traffic to environment m's servers (their addresses or objects)."""
    objects = {server_object(m, s) for s in m.servers}
    nets = [ipaddress.ip_network(n) for n in _server_nets(m.servers)]
    dsts, _ = resolve_addresses(run, rule.scope, rule.destinations)
    reached = [ipaddress.ip_network(x) for x in dsts if "/0" not in x]
    return rule.action == "allow" and (bool(objects & set(rule.destinations)) or any(
        n.version == x.version and n.subnet_of(x) for n in nets for x in reached))


# One running rule as the read meets it: the appliance and its running configuration, the rule, (scope, rulebase) it
# is in, and the appliance's placement
Seen = NamedTuple("Seen", [("appliance", object), ("run", object), ("rule", object), ("where", tuple),
                           ("expected", tuple), ("kind", str)])


def _seen(appliance_reads):
    """Every running rule of the appliances read, in enforcement order, appliance by appliance."""
    return tuple(Seen(a, run, rule, where, expected, kind) for a, run in appliance_reads
                 for kind, _, order, expected in (placement(a),) for where in order
                 for rule in run.rules.get(where, ()))


def _claim(m, by_name, held):
    """The step folding one Seen into (matched {rule: (Seen, via, role)}, unrecorded {appliance DN: (text, ...)})."""
    def step(acc, s):
        matched, unrecorded = acc
        mark = marked(s.rule.description)
        if mark and mark[0] != m.label:
            return acc                                         # another environment's rule
        cn = mark[1] if mark else by_name.get(s.rule.name)
        if cn in held and cn not in matched:
            return {**matched, cn: (s, "marker" if mark else "name", mark[2] if mark else None)}, unrecorded
        if mark or cn in held or _to_servers(m, s.run, s.rule):
            return matched, {**unrecorded, s.appliance.dn: (*unrecorded.get(s.appliance.dn, ()),
                                                            _summary(s.where, s.rule))}
        return acc
    return step


def _scan(appliance_reads, m):
    """(matched {rule: (Seen, via, role)}, unrecorded {appliance DN: (text, ...)}) of environment m's rules over the
    appliances read: the first running rule for each record rule (by marker, else by name), and the rest that carry
    m's marker, repeat a matched rule, or allow traffic to m's servers."""
    rules = of_class(m, "ciamFirewallRule")
    return reduce(_claim(m, {rule_name(m, r): rdn_value(r) for r in rules}, {rdn_value(r) for r in rules}),
                  _seen(appliance_reads), ({}, {}))


def _withheld(texts, patterns, what):
    """(texts without secret-looking ones, notices)."""
    bad = [t for t in texts if scan(t, patterns)]
    return tuple(t for t in texts if t not in bad), tuple(f"{what}: a value that looks like secret material "
                                                          "withheld" for _ in bad)


def _environment(d, spec, folders, patterns):
    """(groups, notices, reads) of one environment's appliance folders ({appliance: {path: text}})."""
    m = env_model(d, spec)
    own = {rdn_value(a): a for a in appliances(m, STACK_ROLE)}
    stray = [f"{spec}/{name}: not a network firewall (ciamAppliance, stack role {STACK_ROLE}) {spec} records; "
             "not read" for name in folders if name not in own]
    parsed = {name: read_running(files) for name, files in folders.items() if name in own}
    reads = tuple((own[name], run) for name, (run, _) in parsed.items() if run is not None)
    notices = (*stray, *(f"{spec}/{name}/{n}" for name, (_, ns) in parsed.items() for n in ns),
               *(f"{spec}/{name}: running configuration version {run.version}" for name, (run, _) in parsed.items()
                 if run is not None and run.version),
               *(f"{spec}/{name}: nothing read for it" for name in own if name not in folders))
    if not reads:
        return (), notices, ()
    matched, unrecorded = _scan(reads, m)
    by_cn = {rdn_value(r): r for r in of_class(m, "ciamFirewallRule")}
    read = {cn: _facts(m, by_cn[cn], s.run, s.rule, via, role, s.where, s.expected)
            for cn, (s, via, role) in matched.items()}
    facts = {cn: _withheld(f, patterns, f"{spec}: {cn}") for cn, (_, f) in read.items()}
    states = {cn: "disabled" if s.rule.disabled else "committed" if s.kind == "panorama" else "deployed"
              for cn, (s, _, _) in matched.items()}
    resources = tuple(resource("firewall", s.rule.uuid or s.rule.name, read[cn][0], name=cn)
                      for cn, (s, _, _) in matched.items())
    placed, placed_notices = environment_groups(d, spec, resources)
    missing = [r for cn, r in by_cn.items() if cn not in matched and within(r.dn, m.dn)]
    held = {a.dn: _withheld(unrecorded.get(a.dn, ()), patterns, f"{spec}: {rdn_value(a)}")
            for a, _ in reads if within(a.dn, m.dn)}
    groups = (*((dn, tuple(observed_rule(e, states[rdn_value(e)], facts[rdn_value(e)][0]) for e in entries))
                for dn, entries in placed),
              *((r.dn, (observed_rule(r, "missing", ()),)) for r in missing),
              *((a.dn, (observed_appliance(a, held[a.dn][0]),)) for a, _ in reads if a.dn in held))
    return groups, (*notices, *(n for n in placed_notices if not n.endswith(_UNREPORTED)),
                    *(n for _, ns in facts.values() for n in ns), *(n for _, ns in held.values() for n in ns),
                    *(f"{spec}: {rdn_value(r)} isn't in the running configuration read (missing)" for r in missing),
                    *(f"{spec}: {n} rule(s) the record doesn't hold on {rdn_value(get(d, dn))}"
                      for dn, (texts, _) in held.items() for n in (len(texts),) if n)), reads


def management_host(address):
    """The host name an appliance's management address or a URL names, lower case (no scheme, port or path)."""
    return (address or "").split("://")[-1].split("/")[0].rsplit(":", 1)[0].lower()


def allowlist_place(path):
    """(host, scope, kind, name) a panos ciamAllowlistRef's path (after panos:) names, or None when it isn't
    <host>/<scope>/<address|address-group|rule>/<name>."""
    parts = path.split("/")
    if len(parts) < 4 or parts[-2] not in ("address", "address-group", "rule"):
        return None
    return parts[0].lower(), "/".join(parts[1:-2]), parts[-2], parts[-1]


def _held_by(run, scope, kind, name, direction):
    """((cidr, ...), (unresolved, ...)) an allowlist's object holds, or None when the read doesn't hold it."""
    if kind == "rule":
        rule = next((x for (s, _), rs in run.rules.items() if s == scope for x in rs if x.name == name), None)
        if rule is None:
            return None
        return resolve_addresses(run, scope, rule.sources if direction == "partner-ingress" else rule.destinations)
    table = run.scopes.get(scope)
    if table is None or name not in (table.addresses if kind == "address" else table.groups):
        return None
    return resolve_addresses(run, scope, (name,))


def _allowlist(xa, path, reads):
    """(entry or None, notices) of one external allowlist whose object a read may hold."""
    place = allowlist_place(path)
    if place is None:
        return None, (f"external allowlist {rdn_value(xa)}: ciamAllowlistRef panos:{path} isn't "
                      "panos:<host>/<scope>/<address|address-group|rule>/<name>; not read",)
    held = next((h for a, run in reads if management_host(one(a, "ciamManagementAddress")) == place[0]
                 for h in (_held_by(run, *place[1:], one(xa, "ciamAllowlistDirection")),) if h is not None), None)
    if held is None:
        return None, ()
    cidrs, unresolved = held
    return recorded_allowlist(xa, cidrs), tuple(f"external allowlist {rdn_value(xa)}: {u} not resolved; not "
                                                "recorded" for u in unresolved)


def _allowlists(d, reads):
    """(groups, notices): each external allowlist a read holds the object of (each appliance read once)."""
    once = tuple({a.dn: (a, run) for a, run in reads}.values())
    found = [(xa, _allowlist(xa, path, once)) for xa, path in allowlist_refs(d, ADAPTER)]
    return (tuple((xa.dn, (e,)) for xa, (e, _) in found if e is not None),
            tuple(n for _, (_, ns) in found for n in ns))


def _folders(files):
    """({spec: {appliance: {path within its folder: text}}}, stray paths): the core's folders, two levels down."""
    specs = sorted({"/".join(p.split("/")[:2]) for p in files if p.count("/") >= 3})
    return ({spec: by_folder(inside) for spec, inside in folders(files, specs).items()},
            tuple(p for p in sorted(files) if p.count("/") < 3))


def read_running_config(files, d, patterns, at=None):
    """Imported: each <cloud>/<env>/<appliance>/ folder's running configuration read against environment <cloud>/<env>
    of record d: its firewall rules (read into the rule, and observed), its appliances' unrecorded rules, and the
    external allowlists the files hold."""
    folders, stray = _folders(files)
    known = {spec: f for spec, f in folders.items() if get(d, env_dn(spec)) is not None}
    done = {spec: _environment(d, spec, f, patterns) for spec, f in known.items()}
    lists, list_notices = _allowlists(d, tuple(r for _, _, reads in done.values() for r in reads))
    return Imported(containers=(), groups=(*(g for groups, _, _ in done.values() for g in groups), *lists),
                    notices=(*(n for _, ns, _ in done.values() for n in ns), *list_notices,
                             *(f"{spec}: no such environment in the record; not read" for spec in folders
                               if spec not in known),
                             *(f"{p}: put each appliance's files under <cloud>/<env>/<appliance>/; not read"
                               for p in stray),
                             *(("no files found (<cloud>/<env>/<appliance>/running-config.xml or api/)",)
                               if not folders and not stray else ())))


IMPORTER = Importer("running-config", "A Panorama's or PAN-OS firewall's running configuration (an explicit "
                    "running-config snapshot, or the XML API's action=show answers `opsdir collect` saves): its "
                    "security rules against the record's firewall rules, read-only", read_running_config)

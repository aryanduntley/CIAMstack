"""Importers of DS-lineage servers' own files, registered by each product of the lineage. Pure.

  config      each server's config.ldif -> an observed snapshot of it (ou=observed), dated when the import runs,
              added only when the configuration differs from the server's latest snapshot (importing it again
              changes nothing); each archived-configs/config-<YYYYMMDDhhmmss>Z(.gz) -> a snapshot of the
              configuration in effect until then (the server archives config.ldif before each change made online),
              dated by its name
  declared    one server's config.ldif -> the declared configuration (ou=declared), each branch it has made exactly
              what the server runs; attributes the importer doesn't own (owners, what a policy is for, ...) are
              kept. For a record that doesn't declare its configuration yet; review it with --dry-run first.
  access-log  the servers' JSON access logs -> the directory's consumers (ou=consumers; see access_log.py)

For config and declared, an export holds a copy of each server's config/ directory in a folder named by the
server's hostname, or by its record name when no other environment has a server of that name; a config.ldif at the
top of the export is placed by the server ID its global configuration records (setup --serverId). For access-log, the
servers' logs/ directories, in any layout.
"""
import re

from opsdir.core.contract import Imported, Importer
from opsdir.core.directory import get, make_entry, norm_dn, rdn_value
from opsdir.core.environment import server_location, server_named
from opsdir.domains.directory.drift import latest_snapshots
from opsdir.domains.directory.naming import CONFIG, CONSUMERS, DECLARED, DIRECTORY_SERVER_ROLE, OBSERVED
from .access_log import read_access_logs
from .observe import OWNED, config_entries, server_id

ARCHIVED = re.compile(r"(?:^|/)archived-configs/config-(\d{14})Z(?:\.ldif)?$")
BRANCHES = ("backends", "password-policies", "connection-handlers", "log-publishers")


def _ou(dn):
    return make_entry(dn, ("top", "organizationalUnit"), {"ou": (dn.split(",", 1)[0].split("=", 1)[1],)})


def _stamp(at):
    return at.strftime("%Y%m%d%H%M%SZ")


# ------------------------------------------------------------------ which server a folder is
def _server_named(d, name):
    """(server entry, None), or (None, why not) for a folder name or server ID."""
    return server_named(d, name, (DIRECTORY_SERVER_ROLE,), "directory server")


def _folders(files):
    """{folder: {path inside it: text}}: one folder per server, or '' when the export is one server's config/."""
    if "config.ldif" in files:
        return {"": files}
    tops = sorted({p.split("/", 1)[0] for p in files if "/" in p})
    return {t: {p.split("/", 1)[1]: text for p, text in files.items() if p.startswith(t + "/")} for t in tops}


def _config_file(inside):
    found = sorted((p for p in inside if p.rsplit("/", 1)[-1] == "config.ldif"), key=lambda p: (p.count("/"), p))
    return inside[found[0]] if found else None


def _placed(d, folder, inside):
    """(server, None) or (None, why not) for one folder of the export."""
    if folder:
        return _server_named(d, folder)
    sid = server_id(_config_file(inside) or "")
    if not sid:
        return None, ("config.ldif: its global configuration records no server ID; put each server's config/ "
                      "directory in a folder named by the server's hostname; not imported")
    return _server_named(d, sid)


# ------------------------------------------------------------------ snapshots
def _snap_name(server, stamp):
    cloud_env = server_location(server).replace("/", "-")
    return f"{cloud_env}-{rdn_value(server)}-{stamp}"


def _snapshot(product, d, server, stamp, text, description):
    """(scope, entries, notices) of one snapshot of a server's configuration."""
    name = _snap_name(server, stamp)
    dn = f"snap={name},{OBSERVED}"
    head = make_entry(dn, ("top", "ciamSnapshot"), {"snap": (name,), "ciamServerRef": (server.dn,),
                                                    "ciamCapturedAt": (stamp,), "description": (description,)})
    entries, notices = config_entries(product, d, text, dn, f"{server_location(server)} {rdn_value(server)}")
    return dn, (head, *entries), notices


def _content(entries, base):
    """What a snapshot holds, apart from its own entry: {DN relative to the snapshot: (classes, attributes)}."""
    b = norm_dn(base)
    return {e.norm[: -len(b) - 1]: (frozenset(e.classes), {k: tuple(sorted(v)) for k, v in e.attrs.items()})
            for e in entries if e.norm != b}


def _unchanged(d, server, scope, entries):
    """The server's latest snapshot, when it holds exactly what this one would."""
    latest = {norm_dn(srv): snap for srv, snap in latest_snapshots(d).items()}.get(server.norm)
    if latest is None:
        return None
    held = tuple(e for n, e in d.entries.items() if n == latest.norm or n.endswith("," + latest.norm))
    return latest if _content(held, latest.dn) == _content(entries, scope) else None


def _current(product, d, server, text, at):
    """(groups, notices) for a server's config.ldif."""
    if at is None:
        return (), (f"{rdn_value(server)}: no import time given, so config.ldif can't be dated; not imported",)
    scope, entries, notices = _snapshot(product, d, server, _stamp(at), text, "config.ldif, imported")
    same = _unchanged(d, server, scope, entries)
    if same is not None:
        return (), (*notices, f"{server_location(server)} {rdn_value(server)}: configuration unchanged since snapshot "
                              f"{rdn_value(same)}; no new snapshot")
    return ((scope, entries),), notices


def _archives(product, d, server, inside):
    """(groups, notices) for a server's archived configurations."""
    found = tuple((m.group(1) + "Z", inside[p]) for p in sorted(inside) for m in (ARCHIVED.search(p),) if m)
    made = tuple(_snapshot(product, d, server, stamp, text,
                           f"archived by the server at {stamp}: the configuration in effect until then")
                 for stamp, text in found)
    return tuple((scope, entries) for scope, entries, _ in made), tuple(n for _, _, ns in made for n in ns)


def _ignored(folder, inside):
    other = [p for p in inside if p.rsplit("/", 1)[-1] != "config.ldif" and not ARCHIVED.search(p)]
    return (f"{folder or 'export'}: {len(other)} other file(s) not read (only config.ldif and archived-configs/)",) \
        if other else ()


def _server_snapshots(product, d, folder, inside, at):
    server, problem = _placed(d, folder, inside)
    if server is None:
        return (), (problem,)
    text = _config_file(inside)
    current = _current(product, d, server, text, at) if text is not None else ((), ())
    archived = _archives(product, d, server, inside)
    return (*current[0], *archived[0]), (*current[1], *archived[1], *_ignored(folder, inside))


def snapshot_reader(product):
    """read(files, d, patterns, at) for the config importer of a DS-lineage product."""
    def read(files, d, patterns, at=None):
        results = tuple(_server_snapshots(product, d, folder, inside, at) for folder, inside in _folders(files).items())
        return Imported(containers=(_ou(CONFIG), _ou(OBSERVED)),
                        groups=tuple(g for groups, _ in results for g in groups),
                        notices=(*(n for _, ns in results for n in ns),
                                 *(("no server folders found: put each server's config/ directory in a folder named "
                                    "by the server's hostname",) if not _folders(files) else ())))
    return read


# ------------------------------------------------------------------ the declared configuration
def _kept(d, e):
    """e, keeping what the record's entry at its DN holds that the importer doesn't own."""
    held = get(d, e.dn)
    if held is None:
        return e
    owned = next((attrs for oc, attrs in OWNED.items() if oc in e.classes), ())
    return make_entry(e.dn, e.classes, {**{k: v for k, v in held.attrs.items() if k not in owned}, **e.attrs})


def declared_reader(product):
    """read(files, d, patterns, at) for the declared importer of a DS-lineage product."""
    def read(files, d, patterns, at=None):
        configs = sorted(p for p in files if p.rsplit("/", 1)[-1] == "config.ldif")
        if len(configs) != 1:
            return Imported((), (), (f"the declared configuration comes from one server's config.ldif; the export "
                                     f"holds {len(configs)}{': ' + ', '.join(configs) if configs else ''}; "
                                     f"nothing imported",))
        entries, notices = config_entries(product, d, files[configs[0]], DECLARED, configs[0])
        merged = tuple(_kept(d, e) for e in entries)
        scopes = tuple(f"ou={b},{DECLARED}" for b in BRANCHES)
        groups = tuple((s, tuple(e for e in merged if e.norm == norm_dn(s) or e.norm.endswith("," + norm_dn(s))))
                       for s in scopes)
        return Imported(containers=(_ou(CONFIG), _ou(DECLARED)), groups=tuple(g for g in groups if g[1]),
                        notices=notices)
    return read


def access_log_reader(files, d, patterns, at=None):
    """read(files, d, patterns, at) for the access-log importer: each consumer found its own group."""
    entries, notices = read_access_logs(files, d, patterns, at)
    return Imported(containers=(_ou(CONSUMERS),), groups=tuple((e.dn, (e,)) for e in entries), notices=notices)


def importers(product):
    """The importers every product of the lineage registers."""
    return (Importer("config", f"{product.name} servers' configuration (a copy of each server's config/ directory: "
                               "config.ldif, archived-configs/) as observed snapshots", snapshot_reader(product)),
            Importer("declared", f"one {product.name} server's config.ldif as the declared configuration",
                     declared_reader(product)),
            Importer("access-log", f"{product.name} servers' JSON access logs (logs/ldap-access.audit.json and its "
                                   "rotated files) as the directory's consumers", access_log_reader))

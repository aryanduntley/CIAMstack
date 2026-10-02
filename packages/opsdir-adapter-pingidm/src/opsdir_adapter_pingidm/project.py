"""IDM project import: an IDM project directory (its conf/ files) read into the record. Pure.

  conf/managed.json                  -> managed objects (pingidmManagedObject), in file order
  conf/provisioner.openicf-*.json    -> connectors (pingidmConnector): a host that is a service name in the record
                                        becomes that binding's role (rendered per environment); the bind account is
                                        matched to a directory consumer record; credentials are withheld
  conf/sync.json                     -> mappings (pingidmMapping), in file order
  conf/schedule-*.json               -> schedules (pingidmSchedule)
  any other conf/ file (JSON, properties) -> a captured config file (its settings held one by one)
  script/, ui/ and other code        -> named in a notice: code is recorded as a bundle, not held
  anything else                      -> named in a notice (not IDM configuration)

The importer owns what it reads; what the record adds to its entries (a connector's credential role, owners) is kept.
"""

from types import MappingProxyType

from opsdir.core.contract import Imported, Importer
from opsdir.core.directory import get, make_entry, one, ou_entry
from opsdir.core.environment import published_role
from opsdir.core.formats import JAVA_PROPERTIES, JSON
from opsdir.core.jsondata import canonical, rendered_in_place, without_secrets
from opsdir.core.naming import rdn_safe
from opsdir.core.sources import json_document
from opsdir.domains.configuration.naming import CONFIG_FILES
from opsdir.domains.configuration.record import captured_file
from opsdir.domains.directory.consumers import consumer_by_bind_dn
from .naming import CONNECTORS, MANAGED, MAPPINGS, PINGIDM, SCHEDULES, SERVER_ROLES, named

CONNECTOR_PREFIX, SCHEDULE_PREFIX = "conf/provisioner.openicf-", "conf/schedule-"
STRUCTURED = ("conf/managed.json", "conf/sync.json")
CAPTURED_FORMATS = MappingProxyType({".json": JSON, ".properties": JAVA_PROPERTIES})
CODE_DIRS = ("script/", "ui/", "bundle/", "connectors/")     # an IDM project's code and packages
CODE_EXTENSIONS = (".js", ".groovy", ".py", ".sh", ".jar")


def _sealed(value):
    """Secret material whole: IDM's encrypted values ({"$crypto": ...}), and what opsdir renders in their place, so
    a rendered file imports back unchanged."""
    return (isinstance(value, dict) and "$crypto" in value) or rendered_in_place(value)


def _settings(data, patterns, drop):
    settings, held = without_secrets({k: v for k, v in data.items() if k not in ("_id", *drop)}, patterns,
                                     sealed=_sealed)
    return settings, held


def _json_entry(dn, classes, owned, existing):
    """The entry: what the import owns, over what the record already adds to it (owners, a credential role)."""
    kept = {k: v for k, v in (existing.attrs.items() if existing else ()) if k not in owned}
    attrs = {**kept, **{k: tuple(v) if isinstance(v, (list, tuple)) else (v,) for k, v in owned.items()
                        if v not in (None, "", [], ())}}
    return make_entry(dn, ("top", *classes), attrs)


# ------------------------------------------------------------------ managed objects, mappings, schedules
def _managed(d, n, obj, patterns):
    name = obj.get("name")
    config, held = _settings(obj, patterns, ("name", "schema"))
    dn = named(MANAGED, name)
    return dn, _json_entry(dn, ("ciamObject", "pingidmManagedObject"), {
        "cn": name, "pingidmPosition": str(n), "pingidmSchema": canonical(obj["schema"]) if "schema" in obj else None,
        "pingidmConfig": canonical(config) if config else None, "pingidmWithheld": list(held)}, get(d, dn))


def _mapping(d, n, m, patterns):
    name = m.get("name")
    config, held = _settings(m, patterns, ("name", "source", "target"))
    dn = named(MAPPINGS, name)
    return dn, _json_entry(dn, ("ciamObject", "pingidmMapping"), {
        "cn": name, "pingidmPosition": str(n), "pingidmSource": m.get("source"), "pingidmTarget": m.get("target"),
        "pingidmConfig": canonical(config) if config else None, "pingidmWithheld": list(held)}, get(d, dn))


def _schedule(d, name, data, patterns):
    config, held = _settings(data, patterns, ("enabled",))
    dn = named(SCHEDULES, name)
    return dn, _json_entry(dn, ("ciamObject", "pingidmSchedule"), {
        "cn": name, "pingidmEnabled": "FALSE" if data.get("enabled") is False else "TRUE",
        "pingidmConfig": canonical(config) if config else None, "pingidmWithheld": list(held)}, get(d, dn))


# ------------------------------------------------------------------ connectors
def _connector(d, name, data, patterns):
    props = data.get("configurationProperties") or {}
    host = props.get("host") or ""
    role = host[len("UNBOUND:"):] if host.startswith("UNBOUND:") else published_role(d, host)
    consumer = consumer_by_bind_dn(d, props.get("principal"))
    stored = {**data, "configurationProperties": {k: v for k, v in props.items() if not (role and k == "host")}}
    config, held = _settings(stored, patterns, ("name", "connectorRef"))
    ref = data.get("connectorRef") or {}
    dn = named(CONNECTORS, name)
    existing = get(d, dn)
    entry = _json_entry(dn, ("ciamObject", "pingidmConnector"), {
        "cn": name, "pingidmConnectorName": ref.get("connectorName") or "unknown",
        "pingidmBundle": ref.get("bundleName"), "pingidmBundleVersion": ref.get("bundleVersion"),
        **({"pingidmTargetRole": role} if role else {}),
        **({"pingidmConsumer": consumer.dn} if consumer else {}),
        "pingidmConfig": canonical(config), "pingidmWithheld": list(held)}, existing)
    notices = (*((f"connector {name}: its credentials are withheld; set pingidmCredentialRole to the secret role "
                  "that holds them",) if held and not one(entry, "pingidmCredentialRole") else ()),
               *((f"connector {name}: no host that is a service name in the record, so it reaches the same place "
                  "from every environment",) if not one(entry, "pingidmTargetRole") else ()))
    return dn, entry, notices


# ------------------------------------------------------------------ composing
def _captured(path, text, patterns):
    fmt = next((f for ext, f in CAPTURED_FORMATS.items() if path.endswith(ext)), None)
    if fmt is None or not rdn_safe("idm." + path.replace("/", ".")):
        return None, (f"not imported (a format IDM config isn't captured in): {path}",)
    dn, entries, notices = captured_file(fmt, "idm", "pingidm", path, text, patterns, SERVER_ROLES[0])
    return (dn, entries), notices


def _structured(d, files, patterns):
    """((scope, (entry,)), notices) for managed objects, connectors, mappings and schedules."""
    managed = (json_document(files.get("conf/managed.json", "")) or {}).get("objects") or []
    mappings = (json_document(files.get("conf/sync.json", "")) or {}).get("mappings") or []
    connectors = tuple(_connector(d, p[len(CONNECTOR_PREFIX):-5], json_document(t) or {}, patterns)
                       for p, t in sorted(files.items()) if p.startswith(CONNECTOR_PREFIX) and p.endswith(".json"))
    parts = (*(_managed(d, n, o, patterns) for n, o in enumerate(managed) if rdn_safe(o.get("name") or "")),
             *(_mapping(d, n, m, patterns) for n, m in enumerate(mappings) if rdn_safe(m.get("name") or "")),
             *(_schedule(d, p[len(SCHEDULE_PREFIX):-5], json_document(t) or {}, patterns)
               for p, t in sorted(files.items()) if p.startswith(SCHEDULE_PREFIX) and p.endswith(".json")),
             *((dn, entry) for dn, entry, _ in connectors))
    return tuple((dn, (entry,)) for dn, entry in parts), tuple(n for _, _, ns in connectors for n in ns)


def _is_structured(path):
    return path in STRUCTURED or path.startswith(CONNECTOR_PREFIX) or path.startswith(SCHEDULE_PREFIX)


def read_project(files, d, patterns, at=None):
    """Imported from an IDM project directory."""
    groups, notices = _structured(d, files, patterns)
    other = sorted(p for p in files if p.startswith("conf/") and not _is_structured(p))
    captured = tuple(_captured(p, files[p], patterns) for p in other)
    code = sorted(p for p in files if p.startswith(CODE_DIRS) or p.endswith(CODE_EXTENSIONS))
    other_files = sorted(p for p in files if not p.startswith("conf/") and p not in code)
    return Imported(
        containers=tuple(ou_entry(dn) for dn in (PINGIDM, MANAGED, CONNECTORS, MAPPINGS, SCHEDULES, CONFIG_FILES)),
        groups=(*groups, *(g for g, _ in captured if g)),
        notices=(*notices, *(n for _, ns in captured for n in ns),
                 *(f"code, not config (record it as a bundle with `opsdir bundle`): {p}" for p in code),
                 *(f"not IDM configuration, not imported: {p}" for p in other_files)))


IDM_PROJECT = Importer("project", "an IDM project directory (its conf/ files)", read_project)

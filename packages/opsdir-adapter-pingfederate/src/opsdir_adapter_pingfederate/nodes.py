"""PingFederate nodes: each node's own files read into the record, and the cluster's discovery rendered per environment.
Pure.

The importer `pingfederate/node-files` takes one folder per node, named by the server's hostname (or its record name),
holding what the node has under its install root:

  bin/run.properties                    -> the server gains auxiliary class pingfedNode: its operational mode
                                           (pingfedOperationalMode), node tags, the ports it listens on
                                           (pingfedListener: runtime=9031, admin=9999, cluster=7600, ...) and every
                                           other setting (pingfedConfig; secrets withheld)
  bin/jgroups.properties                -> the JGroups discovery protocol the node uses (pingfedDiscovery), checked
  (server/default/conf/tcp.xml)            against its environment's discovery binding; an upgraded install's tcp.xml
                                           element when jgroups.properties names none
  server/default/conf/META-INF/         -> which kind of store backs OAuth clients, persistent grants and sessions
    hivemodule.xml                         (pingfedSettings cn=storage)

Discovery differs per environment (an S3 bucket on AWS, DNS where the platform publishes the members, the members
listed), so it is a binding whose protocol is chosen per environment: see discovery.py.
"""
from types import MappingProxyType
import xml.etree.ElementTree as ET

from opsdir.core.contract import Imported, Importer
from opsdir.core.directory import get, make_entry, merged_attrs, one, ou_entry, rdn_value, subtree
from opsdir.core.environment import env_model, one_role, server_named
from opsdir.core.interchange.properties import decode, split
from opsdir.core.jsondata import canonical
from opsdir.core.sources import by_folder
from .discovery import (CHOICES, JGROUPS_PROPERTIES, PROTOCOLS, RENDERED, TCP_XML, binding_protocol, node_protocol,
                        where)
from .naming import DISCOVERY_ROLE, SERVER_ROLES, SETTINGS, STORAGE

from .withheld import withheld_settings

RUN_PROPERTIES = "bin/run.properties"
HIVEMODULE = "server/default/conf/META-INF/hivemodule.xml"
MODES = ("CLUSTERED_CONSOLE", "CLUSTERED_ENGINE", "STANDALONE")
# run.properties ports, by what the node listens for
LISTENERS = MappingProxyType({"pf.http.port": "runtime-http", "pf.https.port": "runtime",
                              "pf.secondary.https.port": "runtime-secondary", "pf.admin.https.port": "admin",
                              "pf.cluster.bind.port": "cluster",
                              "pf.cluster.failure.detection.bind.port": "cluster-failure-detection"})
# hivemodule.xml service points -> what they keep (verify against the target version)
STORAGE_POINTS = MappingProxyType({"ClientManager": "clients", "AccessGrantManager": "grants",
                                   "SessionStorageManager": "sessions"})
NODE_OWNED = ("pingfedOperationalMode", "pingfedNodeTags", "pingfedListener", "pingfedDiscovery", "pingfedConfig",
              "pingfedWithheld")


# ------------------------------------------------------------------ reading the files
def properties(text):
    """{key: value} of a Java properties text."""
    return {p[0]: decode(p[1]) for p in split(text) if isinstance(p, tuple)}


def _xml(text):
    try:
        return ET.fromstring(text)
    except ET.ParseError:
        return None


def _local(tag):
    return tag.rsplit("}", 1)[-1].rsplit(".", 1)[-1]


def storage_kind(implementation):
    """The kind of store an implementation class keeps its data in, from its name."""
    name = implementation.rsplit(".", 1)[-1].lower()
    return next((kind for marks, kind in ((("jdbc",), "JDBC"), (("ldap",), "LDAP"), (("xmlfile", "xml"), "XML file"),
                                          (("memory",), "memory"), (("generic", "plugin"), "custom"))
                 if any(m in name for m in marks)), "unknown")


def storage(text):
    """{what: {"implementation", "storage"}} for the service points of a hivemodule.xml that keep clients, grants and
    sessions."""
    root = _xml(text)
    points = (e for e in root.iter() if _local(e.tag) == "service-point") if root is not None else ()
    found = ((STORAGE_POINTS.get(p.get("id")), next((c.get("class") for c in p.iter() if c.get("class")), None))
             for p in points)
    return {what: {"implementation": impl, "storage": storage_kind(impl)} for what, impl in found if what and impl}


def _env_of(d, server):
    return env_model(d, ",".join(server.dn.split(",")[1:]))


# ------------------------------------------------------------------ import
def node_entries(d, server, files, patterns):
    """(entries for the server's subtree, notices): the server with what its run.properties and tcp.xml say."""
    host = one(server, "ciamHostname") or rdn_value(server)
    props = properties(files[RUN_PROPERTIES]) if RUN_PROPERTIES in files else {}
    mode = props.get("pf.operational.mode")
    ports = [f"{what}={props[k]}" for k, what in LISTENERS.items() if (props.get(k) or "").isdigit()]
    tags = [t.strip() for t in (props.get("node.tags") or "").split(",") if t.strip()]
    config, held = withheld_settings({k: v for k, v in props.items()
                                      if k not in ("pf.operational.mode", "node.tags", *LISTENERS)}, patterns)
    protocol = node_protocol(files)
    owned = {"pingfedOperationalMode": (mode if mode in MODES else None,), "pingfedNodeTags": tuple(tags),
             "pingfedListener": tuple(ports), "pingfedDiscovery": (protocol,),
             "pingfedConfig": (canonical(config) if props else None,), "pingfedWithheld": held}
    node = make_entry(server.dn, tuple(dict.fromkeys((*server.classes, "pingfedNode"))),
                      merged_attrs(server, owned, NODE_OWNED))
    binding = one_role(_env_of(d, server), DISCOVERY_ROLE)
    known, bound = PROTOCOLS.get(protocol), binding_protocol(binding) if binding is not None else None
    notices = (*((f"node {host}: pf.operational.mode {mode!r} is none of {', '.join(MODES)}; not recorded",)
                 if mode and mode not in MODES else ()),
               *((f"node {host}: neither jgroups.properties nor tcp.xml names a discovery protocol",)
                 if (JGROUPS_PROPERTIES in files or TCP_XML in files) and protocol is None else ()),
               *((f"node {host}: discovers its cluster with {protocol}, which PingFederate's clustering doesn't "
                  f"know",) if protocol and known is None else ()),
               *((f"node {host}: discovers its cluster with {protocol}, {known.about}; choose one of "
                  f"{', '.join(CHOICES)} for its environment",) if known and known.support != RENDERED else ()),
               *((f"node {host}: discovers its cluster with {protocol}, but its environment binds no {DISCOVERY_ROLE} "
                  f"role: bind it, with pingfedDiscoveryProtocol {protocol}",)
                 if protocol and binding is None else ()),
               *((f"node {host}: discovers its cluster with {protocol}, but its environment's {DISCOVERY_ROLE} binding "
                  f"uses {bound.name if bound else 'no protocol'} ({where(binding)})",)
                 if protocol and binding is not None and (bound is None or bound.name != protocol) else ()),
               *((f"node {host}: its secrets are withheld; set pingfedCredentialRole to the secret role that "
                  "holds them",)
                 if held and not one(node, "pingfedCredentialRole") else ()))
    return (node, *(e for e in subtree(d, server.dn) if e.norm != server.norm)), notices


def storage_entry(d, kept):
    """The storage settings entry: which store backs clients, grants and sessions."""
    owned = {"cn": ("storage",), "pingfedConfig": (canonical(kept),)}
    return make_entry(STORAGE, ("top", "ciamObject", "pingfedSettings"),
                      merged_attrs(get(d, STORAGE), owned, ("cn", "pingfedConfig")))


def read_node_files(files, d, patterns, at=None):
    """Imported: each PingFederate node's run.properties, tcp.xml and hivemodule.xml."""
    folders = by_folder(files)
    placed = [(f, *server_named(d, f, SERVER_ROLES, "PingFederate server")) for f in folders]
    nodes = [(s, node_entries(d, s, folders[f], patterns)) for f, s, _ in placed if s is not None]
    stores = [(f, storage(folders[f][HIVEMODULE])) for f in folders if HIVEMODULE in folders[f]]
    kept = next((st for _, st in stores if st), None)
    return Imported(
        containers=(ou_entry(SETTINGS),),
        groups=(*((s.dn, entries) for s, (entries, _) in nodes),
                *(((STORAGE, (storage_entry(d, kept),)),) if kept else ())),
        notices=(*(why for _, s, why in placed if s is None), *(n for _, (_, ns) in nodes for n in ns),
                 *((f"hivemodule.xml differs between nodes ({', '.join(f for f, st in stores if st)}); recorded "
                    f"the first",) if len({canonical(st) for _, st in stores if st}) > 1 else ()),
                 *(("no node folders (one folder per node, named by its hostname, holding bin/run.properties, "
                    "bin/jgroups.properties, server/default/conf/tcp.xml, "
                    "server/default/conf/META-INF/hivemodule.xml)",)
                   if not folders else ())))


NODE_FILES = Importer("node-files", "PingFederate nodes' own files (one folder per node, named by its hostname: "
                                    "bin/run.properties, bin/jgroups.properties, server/default/conf/tcp.xml, "
                                    "META-INF/hivemodule.xml)",
                      read_node_files)

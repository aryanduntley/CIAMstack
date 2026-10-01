"""PingFederate nodes: each node's own files read into the record, and the cluster's discovery rendered per environment.
Pure.

The importer `pingfederate/node-files` takes one folder per node, named by the server's hostname (or its record name),
holding what the node has under its install root:

  bin/run.properties                    -> the server gains auxiliary class pingfedNode: its operational mode
                                           (pingfedOperationalMode), node tags, the ports it listens on
                                           (pingfedListener: runtime=9031, admin=9999, cluster=7600, ...) and every
                                           other setting (pingfedConfig; secrets withheld)
  server/default/conf/tcp.xml           -> the JGroups discovery protocol the node uses (pingfedDiscovery), checked
                                           against its environment's discovery binding
  server/default/conf/META-INF/         -> which kind of store backs OAuth clients, persistent grants and sessions
    hivemodule.xml                         (pingfedSettings cn=storage)

Discovery differs per cloud (S3 on AWS, a blob container on Azure, DNS where the platform publishes the members), so
it is a binding: the environment binds role pf-cluster-discovery to a storage location (s3://bucket,
azblob://account/container) or a service name, and pingfederate/cluster/discovery.xml renders the matching protocol
element, the one each node's tcp.xml takes in place of TCPPING.
"""
import xml.etree.ElementTree as ET
from xml.sax.saxutils import quoteattr

from opsdir.core.contract import Imported, Importer
from opsdir.core.directory import get, make_entry, one, rdn_value, subtree
from opsdir.core.environment import env_model, one_role, secret_placeholder, server_named
from opsdir.core.interchange.properties import decode, split
from opsdir.core.jsondata import canonical
from .naming import DISCOVERY_KEY_ROLE, DISCOVERY_ROLE, SERVER_ROLES, STORAGE
from .objects import merged_attrs
from .withheld import withheld_settings

RUN_PROPERTIES, TCP_XML = "bin/run.properties", "server/default/conf/tcp.xml"
HIVEMODULE = "server/default/conf/META-INF/hivemodule.xml"
MODES = ("CLUSTERED_CONSOLE", "CLUSTERED_ENGINE", "STANDALONE")
# run.properties ports, by what the node listens for
LISTENERS = {"pf.http.port": "runtime-http", "pf.https.port": "runtime", "pf.secondary.https.port": "runtime-secondary",
             "pf.admin.https.port": "admin", "pf.cluster.bind.port": "cluster",
             "pf.cluster.failure.detection.bind.port": "cluster-failure-detection"}
# JGroups discovery protocols (the element's last name part) -> the kind of place the members are found in
PROTOCOLS = {"TCPPING": "static", "NATIVE_S3_PING": "s3", "S3_PING": "s3", "AZURE_PING": "azure-blob",
             "DNS_PING": "dns", "JDBC_PING": "jdbc", "FILE_PING": "file", "KUBE_PING": "kubernetes"}
# hivemodule.xml service points -> what they keep (verify against the target version)
STORAGE_POINTS = {"ClientManager": "clients", "AccessGrantManager": "grants", "SessionStorageManager": "sessions"}
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


def discovery_protocol(text):
    """The JGroups discovery protocol a tcp.xml uses (TCPPING, NATIVE_S3_PING, ...), or None."""
    root = _xml(text)
    return next((_local(e.tag) for e in root.iter() if _local(e.tag) in PROTOCOLS), None) if root is not None else None


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


# ------------------------------------------------------------------ the environment's discovery
def binding_kind(b):
    """The kind of place a discovery binding names: s3, azure-blob or dns (None when it names none of them)."""
    ref = one(b, "ciamStorageRef") or ""
    return {"s3": "s3", "azblob": "azure-blob"}.get(ref.split("://", 1)[0]) if ref else \
        ("dns" if one(b, "ciamFqdn") else None)


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
    protocol = discovery_protocol(files[TCP_XML]) if TCP_XML in files else None
    owned = {"pingfedOperationalMode": (mode if mode in MODES else None,), "pingfedNodeTags": tuple(tags),
             "pingfedListener": tuple(ports), "pingfedDiscovery": (protocol,),
             "pingfedConfig": (canonical(config) if props else None,), "pingfedWithheld": held}
    node = make_entry(server.dn, tuple(dict.fromkeys((*server.classes, "pingfedNode"))),
                      merged_attrs(server, owned, NODE_OWNED))
    binding = one_role(_env_of(d, server), DISCOVERY_ROLE)
    kind, bound = PROTOCOLS.get(protocol), binding_kind(binding) if binding is not None else None
    notices = (*((f"node {host}: pf.operational.mode {mode!r} is none of {', '.join(MODES)}; not recorded",)
                 if mode and mode not in MODES else ()),
               *((f"node {host}: tcp.xml names no discovery protocol PingFederate's clustering uses",)
                 if TCP_XML in files and protocol is None else ()),
               *((f"node {host}: lists its cluster's members by hand (TCPPING): their hostnames change when servers "
                  f"are replaced or moved; consider the cloud's discovery or DNS_PING",) if kind == "static" else ()),
               *((f"node {host}: discovers its cluster with {protocol}, but its environment binds no {DISCOVERY_ROLE} "
                  f"role: record where (s3://bucket, azblob://account/container, or a DNS service name)",)
                 if kind not in (None, "static") and binding is None else ()),
               *((f"node {host}: discovers its cluster with {protocol}, but its environment's {DISCOVERY_ROLE} binding "
                  f"is {bound or 'neither storage nor a service name'}",)
                 if kind not in (None, "static") and binding is not None and bound != kind else ()),
               *((f"node {host}: its secrets are withheld; set pingfedCredentialRole to the secret role that holds them",)
                 if held and not one(node, "pingfedCredentialRole") else ()))
    return (node, *(e for e in subtree(d, server.dn) if e.norm != server.norm)), notices


def _folders(files):
    tops = sorted({p.split("/", 1)[0] for p in files if "/" in p})
    return {t: {p.split("/", 1)[1]: text for p, text in files.items() if p.startswith(t + "/")} for t in tops}


def storage_entry(d, kept):
    """The storage settings entry: which store backs clients, grants and sessions."""
    owned = {"cn": ("storage",), "pingfedConfig": (canonical(kept),)}
    return make_entry(STORAGE, ("top", "ciamObject", "pingfedSettings"),
                      merged_attrs(get(d, STORAGE), owned, ("cn", "pingfedConfig")))


def read_node_files(files, d, patterns, at=None):
    """Imported: each PingFederate node's run.properties, tcp.xml and hivemodule.xml."""
    folders = _folders(files)
    placed = [(f, *server_named(d, f, SERVER_ROLES, "PingFederate server")) for f in folders]
    nodes = [(s, node_entries(d, s, folders[f], patterns)) for f, s, _ in placed if s is not None]
    stores = [(f, storage(folders[f][HIVEMODULE])) for f in folders if HIVEMODULE in folders[f]]
    kept = next((st for _, st in stores if st), None)
    return Imported(
        containers=(make_entry(STORAGE.split(",", 1)[1], ("top", "organizationalUnit"), {"ou": ("settings",)}),),
        groups=(*((s.dn, entries) for s, (entries, _) in nodes),
                *(((STORAGE, (storage_entry(d, kept),)),) if kept else ())),
        notices=(*(why for _, s, why in placed if s is None), *(n for _, (_, ns) in nodes for n in ns),
                 *((f"hivemodule.xml differs between nodes ({', '.join(f for f, st in stores if st)}); recorded "
                    f"the first",) if len({canonical(st) for _, st in stores if st}) > 1 else ()),
                 *(("no node folders (one folder per node, named by its hostname, holding bin/run.properties, "
                    "server/default/conf/tcp.xml, server/default/conf/META-INF/hivemodule.xml)",)
                   if not folders else ())))


NODE_FILES = Importer("node-files", "PingFederate nodes' own files (one folder per node, named by its hostname: "
                                    "bin/run.properties, server/default/conf/tcp.xml, META-INF/hivemodule.xml)",
                      read_node_files)


# ------------------------------------------------------------------ render
def discovery_element(m):
    """The discovery protocol element for environment m's nodes' tcp.xml, from its pf-cluster-discovery binding."""
    b = one_role(m, DISCOVERY_ROLE)
    kind = binding_kind(b) if b is not None else None
    if kind == "s3":
        bucket, _, prefix = one(b, "ciamStorageRef").split("://", 1)[1].partition("/")
        return (f"<org.jgroups.aws.s3.NATIVE_S3_PING region_name={quoteattr(one(m.cloud, 'ciamRegion') or '')} "
                f"bucket_name={quoteattr(bucket)} bucket_prefix={quoteattr(prefix or 'pingfederate')}/>")
    if kind == "azure-blob":
        account, _, container = one(b, "ciamStorageRef").split("://", 1)[1].partition("/")
        return (f"<azure.AZURE_PING storage_account_name={quoteattr(account)} "
                f"storage_access_key={quoteattr(secret_placeholder(m, DISCOVERY_KEY_ROLE))} "
                f"container={quoteattr(container or 'pingfederate')}/>")
    if kind == "dns":
        return f"<dns.DNS_PING dns_query={quoteattr(one(b, 'ciamFqdn'))} dns_record_type=\"A\"/>"
    return f"<!-- UNBOUND:{DISCOVERY_ROLE}: where this environment's nodes find each other -->"


def clustered(m):
    """Environment m's PingFederate nodes that run in a cluster."""
    return tuple(s for s in m.servers if one(s, "pingfedOperationalMode", "").startswith("CLUSTERED"))


def discovery_file(m):
    """{pingfederate/cluster/discovery.xml: text} when environment m binds a discovery or has clustered nodes."""
    if one_role(m, DISCOVERY_ROLE) is None and not clustered(m):
        return {}
    return {"pingfederate/cluster/discovery.xml":
            f"<!-- PingFederate cluster discovery for {m.label}: the protocol element each node's "
            f"server/default/conf/tcp.xml takes in place of TCPPING -->\n{discovery_element(m)}\n"}

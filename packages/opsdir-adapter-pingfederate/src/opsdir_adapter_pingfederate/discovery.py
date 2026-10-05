"""PingFederate cluster discovery: which JGroups discovery protocol an environment's nodes find each other with, held as
data and rendered per environment. Pure.

Since PingFederate 11.0 each node's bin/jgroups.properties names the protocol (pf.cluster.discovery.protocol) and its
parameters (pf.cluster.<PROTOCOL>.<name>); server/default/conf/tcp.xml holds ${DISCOVERY_TAG} where the protocol
element used to be (an upgraded install may still carry the element itself).

The environment binds role pf-cluster-discovery. The binding states its protocol (pingfedDiscoveryProtocol, on a
pingfedClusterDiscovery binding), or the protocol follows from what the binding names: an s3:// storage reference is
NATIVE_S3_PING, a DNS name DNS_PING. TCPPING (the members listed by hand) is only ever stated; its hosts are the
environment's clustered nodes, so they follow the record when servers are replaced or moved.

PROTOCOLS holds every protocol the adapter knows, one row each: whether PingFederate documents it and the adapter
renders it, what the binding must name, and how its jgroups.properties lines are written. A new protocol is a new row;
the values pingfedDiscoveryProtocol accepts are the rendered rows.
"""
from types import MappingProxyType
from typing import Callable, NamedTuple, Optional
import xml.etree.ElementTree as ET

from opsdir.core.changeset import delete_entry, new_entry
from opsdir.core.directory import is_a, one, rdn_value, values
from opsdir.core.environment import one_role
from opsdir.core.findings import Fix, Input, Option, bindings_container
from opsdir.core.interchange.ldif import LdifRecord
from opsdir.core.interchange.properties import decode, encode, split
from .naming import DISCOVERY_ROLE

JGROUPS_PROPERTIES, TCP_XML = "bin/jgroups.properties", "server/default/conf/tcp.xml"
PROTOCOL_KEY = "pf.cluster.discovery.protocol"
CLUSTER_PORT = "7600"            # run.properties pf.cluster.bind.port when a node records none
RENDERED, DOCUMENTED, UNSUPPORTED = "rendered", "documented", "unsupported"

# One discovery protocol: its name as PingFederate and JGroups spell it; RENDERED (documented by Ping, written by this
# adapter), DOCUMENTED (documented by Ping, not written yet) or UNSUPPORTED (not in PingFederate's documentation);
# what its binding must name (storage, dns or nothing); its parameter lines (environment model, binding) -> ((name,
# value), ...); and what to say about it.
Protocol = NamedTuple("Protocol", [("name", str), ("support", str), ("needs", Optional[str]),
                                   ("parameters", Optional[Callable]), ("about", str)])


# ------------------------------------------------------------------ parameters per protocol
def clustered(m):
    """Environment m's PingFederate nodes that run in a cluster."""
    return tuple(s for s in m.servers if one(s, "pingfedOperationalMode", "").startswith("CLUSTERED"))


def _cluster_port(server):
    return next((v.split("=", 1)[1] for v in server.attrs.get("pingfedListener", ()) if v.startswith("cluster=")),
                CLUSTER_PORT)


def _tcpping(m, b):
    hosts = sorted(f"{one(s, 'ciamHostname')}[{_cluster_port(s)}]" for s in clustered(m) if one(s, "ciamHostname"))
    return (("initial_hosts", ",".join(hosts)), ("port_range", "0"))


def _native_s3(m, b):
    bucket = one(b, "ciamStorageRef").split("://", 1)[1].split("/", 1)[0]
    return (("region_name", one(m.cloud, "ciamRegion") or ""), ("bucket_name", bucket),
            ("remove_all_data_on_view_change", "true"), ("write_data_on_find", "true"))


def _dns(m, b):
    return (("dns_query", one(b, "ciamFqdn")),)


PROTOCOLS = MappingProxyType({p.name: p for p in (
    Protocol("TCPPING", RENDERED, None, _tcpping,
             "static: the members are listed, here the environment's clustered nodes"),
    Protocol("NATIVE_S3_PING", RENDERED, "s3", _native_s3, "members found in an S3 bucket (s3://bucket)"),
    Protocol("DNS_PING", RENDERED, "dns", _dns,
             "members found by a DNS query (A records; Ping's recommendation on Kubernetes)"),
    Protocol("AWS_PING", DOCUMENTED, None, None, "members found by EC2 tags; documented by Ping, not rendered here"),
    Protocol("SWIFT_PING", DOCUMENTED, None, None, "members found in OpenStack Swift; documented by Ping, not "
                                                   "rendered here"),
    Protocol("S3_PING", UNSUPPORTED, None, None, "deprecated by Ping in favour of NATIVE_S3_PING"),
    Protocol("AZURE_PING", UNSUPPORTED, None, None, "a community JGroups extension (jgroups-azure) PingFederate "
                                                    "doesn't document"),
    Protocol("KUBE_PING", UNSUPPORTED, None, None, "not in PingFederate's documentation; Ping recommends DNS_PING "
                                                   "on Kubernetes"),
    Protocol("JDBC_PING", UNSUPPORTED, None, None, "not in PingFederate's documentation"),
    Protocol("FILE_PING", UNSUPPORTED, None, None, "not in PingFederate's documentation"),
)})
CHOICES = tuple(n for n, p in PROTOCOLS.items() if p.support == RENDERED)   # what pingfedDiscoveryProtocol accepts
# what a binding names -> the protocol it implies when it states none (an azblob:// container implies AZURE_PING)
IMPLIED = MappingProxyType({"s3": "NATIVE_S3_PING", "azblob": "AZURE_PING"})


# ------------------------------------------------------------------ the environment's choice
def binding_protocol(b):
    """The Protocol a pf-cluster-discovery binding uses: the one it states, else the one what it names implies (an
    s3:// reference, a DNS name); None when it states none and names nothing that implies one."""
    stated = one(b, "pingfedDiscoveryProtocol")
    if stated:
        return PROTOCOLS.get(stated)
    ref = one(b, "ciamStorageRef") or ""
    implied = IMPLIED.get(ref.split("://", 1)[0]) if ref else ("DNS_PING" if one(b, "ciamFqdn") else None)
    return PROTOCOLS.get(implied) if implied else None


def lacks(protocol, b):
    """What a binding lacks for its protocol (an s3:// reference, a DNS name), or None."""
    has = {"s3": (one(b, "ciamStorageRef") or "").startswith("s3://"), "dns": bool(one(b, "ciamFqdn"))}
    return {"s3": "an s3://bucket storage reference", "dns": "a DNS name (ciamFqdn)"}[protocol.needs] \
        if protocol.needs and not has[protocol.needs] else None


def where(b):
    """What a discovery binding names, for messages."""
    return one(b, "ciamStorageRef") or one(b, "ciamFqdn") or "the clustered nodes"


# ------------------------------------------------------------------ fixes
_NEEDS = MappingProxyType({   # what a protocol's binding needs -> (attribute, the Input giving it)
    "s3": ("ciamStorageRef", Input("ciamStorageRef", "the S3 bucket the nodes find each other in", (),
                                   ("s3://pf-cluster-discovery",), r"s3://[a-z0-9][a-z0-9.-]{1,61}[a-z0-9](/\S*)?")),
    "dns": ("ciamFqdn", Input("ciamFqdn", "the DNS name whose A records are the nodes (a headless service on "
                                          "Kubernetes)", (), ("pingfederate-cluster.ciam.svc.cluster.local",)))})


def _attrs(protocol):
    needed = _NEEDS.get(protocol.needs)
    return {"pingfedDiscoveryProtocol": (protocol.name,), **({needed[0]: (needed[1],)} if needed else {})}


def _records(m, b, protocol):
    """The records binding environment m's discovery with protocol: a new binding when it has none, the binding's
    protocol and what it needs set on a pingfedClusterDiscovery, else (a binding of another class, an object store) the
    binding replaced by one, under its name, its owners kept."""
    if b is not None and is_a(b, "pingfedClusterDiscovery"):
        stale = [a for a, _ in _NEEDS.values() if a in b.attrs and a not in _attrs(protocol)]
        return (LdifRecord(b.dn, "modify", {}, (*(("replace", a, v) for a, v in _attrs(protocol).items()),
                                                 *(("delete", a, ()) for a in stale))),)
    cn = rdn_value(b) if b is not None else "pf-discovery"
    owners = {"ciamOwner": values(b, "ciamOwner")} if b is not None and values(b, "ciamOwner") else {}
    return (*bindings_container(m.d, m.dn), *((delete_entry(b),) if b is not None else ()),
            new_entry(f"cn={cn},ou=bindings,{m.dn}", ("top", "pingfedClusterDiscovery"),
                      {"cn": (cn,), "ciamBindingRole": (DISCOVERY_ROLE,), **owners, **_attrs(protocol),
                       "description": (f"PingFederate cluster discovery ({protocol.name})",)}))


def discovery_fix(m, b, protocols):
    """The Fix binding environment m's PingFederate cluster discovery (b: its pf-cluster-discovery binding, or None)
    with one of protocols (names): an option each when there are several, the values a protocol needs (the bucket,
    the DNS name) as inputs; None when protocols is empty."""
    rendered = tuple(PROTOCOLS[n] for n in protocols if n in PROTOCOLS and PROTOCOLS[n].support == RENDERED)
    if not rendered:
        return None
    key, title = f"discovery:{m.label}", f"Bind PingFederate's cluster discovery in {m.label}"
    manual = (f"Put the lines of {m.label}'s pingfederate/cluster/jgroups.properties in each node's "
              "bin/jgroups.properties, and create what the binding names (the bucket and the nodes' access to it, "
              "the DNS records) if it isn't there.",)
    if len(rendered) == 1:
        return Fix(key, "PingFederate", f"{title}: {rendered[0].name}", _records(m, b, rendered[0]), manual, ())
    return Fix(key, "PingFederate", title, (), manual, (), tuple(
        Option(p.name, f"{p.name}: {p.about}", _records(m, b, p), ()) for p in rendered))


# ------------------------------------------------------------------ what a node uses
def _local(tag):
    return tag.rsplit("}", 1)[-1].rsplit(".", 1)[-1]


def _tcp_xml_protocol(text):
    try:
        root = ET.fromstring(text)
    except ET.ParseError:
        return None
    return next((_local(e.tag) for e in root.iter() if _local(e.tag) in PROTOCOLS), None)


def node_protocol(files):
    """The discovery protocol a node's files name: bin/jgroups.properties' pf.cluster.discovery.protocol, else the
    protocol element of a tcp.xml that still carries one (an upgraded install); None when neither says."""
    props = {p[0]: decode(p[1]) for p in split(files.get(JGROUPS_PROPERTIES, "")) if isinstance(p, tuple)}
    named = (props.get(PROTOCOL_KEY) or "").strip()
    return named or (_tcp_xml_protocol(files[TCP_XML]) if TCP_XML in files else None)


# ------------------------------------------------------------------ render
def _lines(m):
    b = one_role(m, DISCOVERY_ROLE)
    protocol = binding_protocol(b) if b is not None else None
    if b is None:
        return (f"# UNBOUND:{DISCOVERY_ROLE}: where this environment's nodes find each other; bind the role and choose "
                f"pingfedDiscoveryProtocol ({', '.join(CHOICES)})",)
    if protocol is None or protocol.support != RENDERED:
        why = (f"{protocol.name} is {protocol.about}" if protocol
               else "the binding states no known protocol and names nothing that implies one")
        return (f"# UNSUPPORTED:{DISCOVERY_ROLE}: {why}; choose pingfedDiscoveryProtocol ({', '.join(CHOICES)})",)
    lack = lacks(protocol, b)
    if lack:
        return (f"# INCOMPLETE:{DISCOVERY_ROLE}: {protocol.name} needs {lack} on the binding",)
    return (f"{PROTOCOL_KEY}={protocol.name}",
            *(f"pf.cluster.{protocol.name}.{k}={encode(v, '')}" for k, v in protocol.parameters(m, b)))


def discovery_file(m):
    """{pingfederate/cluster/jgroups.properties: text} when environment m binds a discovery or has clustered nodes:
    the discovery lines of each node's bin/jgroups.properties."""
    if one_role(m, DISCOVERY_ROLE) is None and not clustered(m):
        return {}
    return {"pingfederate/cluster/jgroups.properties":
            f"# PingFederate cluster discovery for {m.label}: the discovery lines of each node's bin/jgroups.properties "
            "(server/default/conf/tcp.xml holds ${DISCOVERY_TAG})\n" + "\n".join(_lines(m)) + "\n"}

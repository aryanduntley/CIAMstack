"""The importer `pingfederate/cluster`: an environment's cluster discovery file read into its pf-cluster-discovery
binding. Pure.

The file is what the adapter renders as pingfederate/cluster/jgroups.properties (the discovery lines of each node's
bin/jgroups.properties), one per environment, in that environment's <cloud>/<env>/ folder:

  pf.cluster.discovery.protocol         -> the protocol the binding uses: kept when the binding already implies or
                                           states it, else stated (pingfedDiscoveryProtocol on a pingfedClusterDiscovery
                                           binding, which replaces a binding of another class under its name)
  pf.cluster.NATIVE_S3_PING.bucket_name -> the binding's ciamStorageRef (s3://<bucket>), kept when it names that bucket
  pf.cluster.DNS_PING.dns_query         -> the binding's ciamFqdn

Every other setting follows from the rest of the record (the region from the cloud, TCPPING's hosts and ports from the
environment's clustered nodes, the flags the adapter always writes), so it is compared with what the record renders and
a difference is a notice, never a change. The nodes themselves are the node-files importer's (nodes.py).
"""
from types import MappingProxyType
from typing import Callable, NamedTuple

from opsdir.core.contract import Imported, Importer
from opsdir.core.directory import make_entry, norm_dn, ou_entry
from opsdir.core.environment import env_model, environment_at, one_role
from .discovery import PROTOCOL_KEY, PROTOCOLS, RENDERED, binding_protocol, discovery_entry, lacks
from .naming import DISCOVERY_ROLE
from .nodes import properties

FILE_NAME = "jgroups.properties"

# What the file gives of what a protocol's binding needs: the binding attribute, the protocol's parameter, and the
# attribute's value from the parameter's.
Given = NamedTuple("Given", [("attribute", str), ("parameter", str), ("value", Callable)])
GIVEN = MappingProxyType({"s3": Given("ciamStorageRef", "bucket_name", lambda v: f"s3://{v}"),
                          "dns": Given("ciamFqdn", "dns_query", lambda v: v)})


def _says(m, b, protocol, params):
    """Whether binding b already says what the file does: its protocol, and the parameter it gives rendered as given."""
    given = GIVEN.get(protocol.needs)
    return binding_protocol(b) is protocol and not lacks(protocol, b) and \
        (given is None or dict(protocol.parameters(m, b)).get(given.parameter) == params.get(given.parameter))


def bound_entry(m, b, protocol, params):
    """The pf-cluster-discovery binding environment m has after reading a file naming protocol with params: b itself
    when it already says so; b with only what the file gives changed when that still implies the protocol; else a
    pingfedClusterDiscovery binding stating it (discovery.discovery_entry)."""
    given = GIVEN.get(protocol.needs)
    attrs = {given.attribute: (given.value(params[given.parameter]),)} if given else {}
    if b is not None and _says(m, b, protocol, params):
        return b
    changed = make_entry(b.dn, b.classes, {**b.attrs, **attrs}) if b is not None else None
    if changed is not None and binding_protocol(changed) is protocol:
        return changed
    return discovery_entry(m, b, protocol, {"pingfedDiscoveryProtocol": (protocol.name,), **attrs})


def _compared(m, entry, protocol, params, path):
    expected = {k: str(v) for k, v in protocol.parameters(m, entry)}
    key = f"pf.cluster.{protocol.name}."
    return tuple(
        f"{path}: {key}{k}={params[k]} is no setting the record holds; not read" if k not in expected else
        f"{path}: no {key}{k}; the record renders {expected[k]}" if k not in params else
        f"{path}: {key}{k} is {params[k]}, the record renders {expected[k]}; not read"
        for k in sorted({*expected, *params}) if params.get(k) != expected.get(k))


def environment_binding(d, env, path, text):
    """(the binding entry to record, or None when nothing changes, notices) of one environment's discovery file."""
    m = env_model(d, env)
    settings = properties(text)
    name = (settings.get(PROTOCOL_KEY) or "").strip()
    protocol = PROTOCOLS.get(name)
    if protocol is None or protocol.support != RENDERED:
        why = (f"names no discovery protocol ({PROTOCOL_KEY})" if not name else
               f"discovers with {name}, which PingFederate's clustering doesn't know" if protocol is None else
               f"discovers with {name}, {protocol.about}")
        return None, (f"{path}: {why}; the binding is left as it is",)
    key = f"pf.cluster.{name}."
    params = {k[len(key):]: v for k, v in settings.items() if k.startswith(key)}
    others = tuple(f"{path}: {k} isn't a setting of {name}; not read" for k in settings
                   if k != PROTOCOL_KEY and not k.startswith(key))
    given = GIVEN.get(protocol.needs)
    if given is not None and not params.get(given.parameter):
        return None, (*others, f"{path}: {name} needs {key}{given.parameter}; the binding is left as it is")
    b = one_role(m, DISCOVERY_ROLE)
    entry = bound_entry(m, b, protocol, params)
    if entry is b:
        return None, (*others, *_compared(m, entry, protocol, params, path))
    if not entry.norm.endswith("," + norm_dn(m.dn)):
        return None, (*others, f"{path}: the {DISCOVERY_ROLE} binding {b.dn} is inherited and doesn't say {name} "
                               f"as the file does; bind the role in {m.label} itself")
    return entry, (*others, *_compared(m, entry, protocol, params, path))


def read_cluster_files(files, d, patterns, at=None):
    """Imported: each environment's discovery file (<cloud>/<env>/.../jgroups.properties) read into its binding."""
    named = sorted(p for p in files if p.rsplit("/", 1)[-1] == FILE_NAME)
    placed = [(p, environment_at(d, p)) for p in named]
    firsts = {env: p for p, env in reversed(placed) if env}
    read = [environment_binding(d, env, p, files[p]) for env, p in sorted(firsts.items())]
    entries = tuple(e for e, _ in read if e is not None)
    return Imported(
        containers=tuple(ou_entry(dn) for dn in dict.fromkeys(e.dn.split(",", 1)[1] for e in entries)),
        groups=tuple((e.dn, (e,)) for e in entries),
        notices=(*(n for _, ns in read for n in ns),
                 *(f"{p}: not under <cloud>/<env>/ of an environment the record holds; not read"
                   for p, env in placed if not env),
                 *(f"{p}: {firsts[env]} is read for its environment; not read" for p, env in placed
                   if env and firsts[env] != p),
                 *(f"{p}: not a {FILE_NAME}; not read" for p in sorted(files) if p not in named),
                 *((f"no {FILE_NAME} (one per environment, in its <cloud>/<env>/ folder)",) if not named else ())))


CLUSTER = Importer("cluster", "PingFederate cluster discovery as the adapter renders it (pingfederate/cluster/"
                              "jgroups.properties: the discovery lines of each node's bin/jgroups.properties), one per "
                              "environment in its <cloud>/<env>/ folder, read into its pf-cluster-discovery binding",
                   read_cluster_files)

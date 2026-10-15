"""The ping-devops kit reads the DNS name its values pass PingFederate's nodes (DNS_QUERY_LOCATION) with its own copy of
PingFederate's protocol rule (it doesn't import the product adapter); PingFederate's binding_protocol is the source of
truth. The two agree on every environment's cluster-discovery binding in the showcase, before and after the approved
changes, and on the other shapes a binding takes, so neither can drift silently."""
import pytest

from opsdir.connectors.registry import environment, environment_specs
from opsdir.core.directory import make_entry
from opsdir.core.environment import one_role
from opsdir_adapter_ping_devops.discovery import recorded_query as kit_query
from opsdir_adapter_pingfederate.discovery import recorded_query as product_query
from opsdir_adapter_pingfederate.naming import DISCOVERY_ROLE

# the shapes a discovery binding takes: (classes, attributes)
SHAPES = ((("top", "pingfedClusterDiscovery"), {"pingfedDiscoveryProtocol": ("DNS_PING",), "ciamFqdn": ("pf.test",)}),
          (("top", "pingfedClusterDiscovery"), {"pingfedDiscoveryProtocol": ("DNS_PING",)}),
          (("top", "pingfedClusterDiscovery"), {"pingfedDiscoveryProtocol": ("TCPPING",), "ciamFqdn": ("pf.test",)}),
          (("top", "pingfedClusterDiscovery"), {"pingfedDiscoveryProtocol": ("NATIVE_S3_PING",),
                                                "ciamStorageRef": ("s3://pf-cluster",)}),
          (("top", "pingfedClusterDiscovery"), {"pingfedDiscoveryProtocol": ("KUBE_PING",), "ciamFqdn": ("pf.test",)}),
          (("top", "pingfedClusterDiscovery"), {"ciamFqdn": ("pf.test",)}),
          (("top", "ciamObjectStore"), {"ciamStorageRef": ("s3://pf-cluster",)}),
          (("top", "ciamObjectStore"), {"ciamStorageRef": ("azblob://pf/cluster",), "ciamFqdn": ("pf.test",)}),
          (("top", "ciamObjectStore"), {"ciamStorageRef": ("gs://pf/cluster",), "ciamFqdn": ("pf.test",)}),
          (("top", "pingfedClusterDiscovery"), {}))


def _models(estate):
    return tuple(environment(d, spec)[0] for d in estate.values() for spec in environment_specs(d))


def test_the_kit_and_pingfederate_read_the_showcases_bindings_alike(estate):
    models = _models(estate)
    bound = [m for m in models if one_role(m, DISCOVERY_ROLE) is not None]
    assert bound                                        # the showcase binds PingFederate's discovery somewhere
    assert all(kit_query(m) == product_query(m) for m in models), [m.label for m in models
                                                                   if kit_query(m) != product_query(m)]


@pytest.mark.parametrize("classes, attrs", SHAPES)
def test_the_kit_and_pingfederate_read_every_shape_of_binding_alike(estate, classes, attrs):
    m = next(m for m in _models(estate) if one_role(m, DISCOVERY_ROLE) is not None)
    b = one_role(m, DISCOVERY_ROLE)
    shaped = make_entry(b.dn, classes, {"cn": b.attrs["cn"], "ciamBindingRole": (DISCOVERY_ROLE,), **attrs})
    other = m._replace(bindings=tuple(shaped if x.dn == b.dn else x for x in m.bindings))
    assert kit_query(other) == product_query(other)

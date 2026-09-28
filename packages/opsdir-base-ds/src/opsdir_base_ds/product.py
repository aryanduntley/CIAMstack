"""What distinguishes one product of the DS lineage (OpenDJ → ForgeRock DS → PingDS) from another, as data the shared
renderers read. Everything else the lineage has in common (dsconfig, the ACI syntax, replication) is in this base."""
from typing import Mapping, NamedTuple

from opsdir.core.directory import one

DsProduct = NamedTuple("DsProduct", [("name", str),                # as servers record it in ciamProductVersion
                                     ("root_dn", str),             # directory administrator's bind DN
                                     ("dsconfig_apply", tuple),    # comment lines: how to apply the batch file
                                     ("handler_names", Mapping)])  # connection handler record name → product name


def handler_name(product, record_name):
    """The product's name for a connection handler recorded under a neutral name (LDAP, LDAPS, HTTPS, ...)."""
    return product.handler_names.get(record_name, record_name)


def runs(product, m):
    """Whether any server of the environment runs this product (its ciamProductVersion starts with the name)."""
    return any(one(s, "ciamProductVersion", "").startswith(product.name) for s in m.servers)

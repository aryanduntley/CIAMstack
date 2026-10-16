"""What distinguishes one product of the DS lineage (OpenDJ → ForgeRock DS → PingDS) from another, as data the shared
renderers read. Everything else the lineage has in common (dsconfig, the ACI syntax, replication) is in this base."""
from collections import namedtuple

from opsdir.domains.compute.workloads import runs_product

# name: as servers record it in ciamProductVersion; root_dn: the directory administrator's bind DN; dsconfig_apply:
# comment lines saying how to apply the batch file; handler_names: connection handler record name → product name;
# builtin_policies: password policies every server already has; shipped_arcs: the vendor OID arcs whose schema
# definitions the product's servers ship (the lineage's own vendors'), left out of the schema the record renders
# for them (default none).
DsProduct = namedtuple("DsProduct", ("name", "root_dn", "dsconfig_apply", "handler_names", "builtin_policies",
                                     "shipped_arcs"), defaults=((),))


def handler_name(product, record_name):
    """The product's name for a connection handler recorded under a neutral name (LDAP, LDAPS, HTTPS, ...)."""
    return product.handler_names.get(record_name, record_name)


def shipped_arc(product, oid):
    """The product's shipped vendor arc (DsProduct.shipped_arcs) an OID lies under, or None."""
    return next((a for a in product.shipped_arcs if oid and (oid == a or oid.startswith(a + "."))), None)


def runs(product, m):
    """Whether the environment runs this product (a ciamProductVersion starting with its name), on servers or on
    Kubernetes."""
    return runs_product(m, product.name)

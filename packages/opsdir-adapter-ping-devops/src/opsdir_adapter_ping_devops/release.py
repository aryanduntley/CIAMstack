"""The ping-devops chart release this adapter renders for, as read in its source: the pinned chart, the products it
deploys for the record's roles, and what PingFederate's image reads from Secrets. Data, and lookups on it. Pure.

ping-devops is Ping Identity's Helm chart for its DevOps images (PingFederate, PingDirectory, PingAccess, ...). This
adapter renders its PingFederate admin and engine; ForgeOps (opsdir-adapter-forgeops) deploys PingAM, PingIDM, PingDS
and PingGateway.
"""
from collections import namedtuple

CHART = "ping-devops"
VERSION = "0.16.0"
APP_VERSION = "2609"                    # the chart's default image tag
REPOSITORY = "https://helm.pingidentity.com/"
SOURCE = f"https://github.com/pingidentity/helm-charts/releases/download/{CHART}-{VERSION}/{CHART}-{VERSION}.tgz"
SOURCE_SHA256 = "9fac7be41a22f25fc34ad81577ed49fec762c805011510d9d634c44cdd1a0872"   # the repository index's digest
RELEASE = "pingfederate"                # the Helm release name the values' install command uses

# One product the chart deploys. name: its values key and workload name (the release's name is prepended); role:
# the server role a workload runs it as; containers: the record's container names whose image it runs
# (ciamContainerImage, first found wins).
Product = namedtuple("Product", ("name", "role", "containers"))
PRODUCTS = (
    Product("pingfederate-admin", "pf-admin", ("pingfederate-admin", "pingfederate")),
    Product("pingfederate-engine", "pf-engine", ("pingfederate-engine", "pingfederate")),
)
_BY_ROLE = {p.role: p for p in PRODUCTS}

# What the chart's PingFederate pods listen on (its services' containerPort), per server role: (role, port, purpose,
# peers) as contract.Listener's. The admin console for the operators and the engines' wait for it, the runtime for
# clients, the cluster ports (JGroups bind and failure detection) between the admin console and the engines.
POD_PORTS = (("pf-admin", 9999, "admin console and API", ("admin",)),
             ("pf-admin", 7600, "cluster", ("peers", "pf-engine")),
             ("pf-admin", 7700, "cluster failure detection", ("peers", "pf-engine")),
             ("pf-engine", 9031, "runtime", ("clients",)),
             ("pf-engine", 7600, "cluster", ("peers", "pf-admin")),
             ("pf-engine", 7700, "cluster failure detection", ("peers", "pf-admin")))

# What PingFederate's image reads. Each key a workload's Secret records (ciamWorkloadSecret <secret>/<key> <- <role>) is
# set as the environment variable of its name, except the keys here, mounted as files at these paths (the chart's
# own example mounts the license there).
FILE_KEYS = (("pingfederate.lic", "/opt/in/instance/server/default/conf/pingfederate.lic"),)
LICENSE_KEY = "pingfederate.lic"
DEVOPS_KEYS = ("PING_IDENTITY_DEVOPS_USER", "PING_IDENTITY_DEVOPS_KEY")    # a license from Ping's license server
ADMIN_PASSWORD = "PING_IDENTITY_PASSWORD"   # the image's default is published
EULA = "PING_IDENTITY_ACCEPT_EULA"          # the image starts only with YES (the organization accepts the terms)


def product_of(role):
    """The chart product a server role runs as, or None."""
    return _BY_ROLE.get(role)


def file_path(key):
    """The path a Secret key is mounted at, or None for a key set as an environment variable."""
    return dict(FILE_KEYS).get(key)

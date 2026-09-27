"""The parts of the stack and which of them apply to an environment. The only module that lists them.

Adding a product, cloud provider or secret store = writing its adapter package and adding it here.
Which adapters apply to an environment is decided by each adapter from directory data (provider of the
cloud, products on the servers), never by a default.
"""
from pathlib import Path

from ..adapters.aws.adapter import ADAPTER as AWS
from ..adapters.azure.adapter import ADAPTER as AZURE
from ..adapters.hashicorp_vault.adapter import ADAPTER as HASHICORP_VAULT
from ..adapters.pingds.adapter import ADAPTER as PINGDS
from ..adapters.pingfederate.adapter import ADAPTER as PINGFEDERATE
from ..core.contract import Services
from ..core.environment import env_model, with_required_roles
from ..core.standard import CORE
from ..domains.directory.domain import DOMAIN as DIRECTORY
from ..domains.federation.domain import DOMAIN as FEDERATION
from ..domains.governance.domain import DOMAIN as GOVERNANCE
from ..domains.infrastructure.domain import DOMAIN as INFRASTRUCTURE
from ..domains.pki.domain import DOMAIN as PKI

DOMAINS = (INFRASTRUCTURE, DIRECTORY, FEDERATION, PKI, GOVERNANCE)
ADAPTERS = (AWS, AZURE, PINGDS, PINGFEDERATE, HASHICORP_VAULT)    # providers first: their files lead a render

STORE_SQL = Path(__file__).resolve().parent.parent / "store" / "sql"
CONNECTOR_SQL = (Path(__file__).resolve().parent / "sql" / "connectors.sql",)


def sql_files():
    """Every SQL file, in load order: the store, each domain's views, then cross-domain views."""
    return (*sorted(STORE_SQL.glob("*.sql")), *(f for domain in DOMAINS for f in domain.sql), *CONNECTOR_SQL)


def schema_fragments():
    """Every schema fragment: core first, then each domain's."""
    return (CORE, *(domain.schema for domain in DOMAINS))


def applicable(m):
    return tuple(a for a in ADAPTERS if a.applies(m))


def required_roles(adapters):
    """Roles an environment must bind: every domain's, then each applicable adapter's (first mention wins)."""
    return tuple(dict.fromkeys(r for part in (*DOMAINS, *adapters) for r in part.required_roles))


def environment(d, spec):
    """(EnvModel with its required roles resolved, the adapters that apply to it)."""
    m = env_model(d, spec)
    adapters = applicable(m)
    return with_required_roles(m, required_roles(adapters)), adapters


def ref_schemes():
    """Every secret/key/storage reference scheme some adapter owns (the store accepts only these in ref-uri values)."""
    return tuple(dict.fromkeys(s for a in ADAPTERS for s in a.ref_schemes))


def secret_command(uri):
    """Shell command resolving a secret reference, from the adapter that owns its scheme."""
    scheme, rest = uri.split("://", 1)
    resolvers = {s: resolve for a in ADAPTERS for s, resolve in a.secret_schemes.items()}
    if scheme not in resolvers:
        raise SystemExit(f"no resolver for secret scheme {scheme}")
    return resolvers[scheme](rest)


SERVICES = Services(secret_command=secret_command)

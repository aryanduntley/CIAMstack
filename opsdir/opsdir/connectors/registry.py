"""The parts of the stack and which of them apply to an environment.

Domains and adapters are discovered, never imported by name: every installed distribution registers them under the
entry-point groups `opsdir.domains` and `opsdir.adapters` (the core registers its built-in domains the same way).
Installing an adapter package is all it takes to add a product, cloud provider or secret store. Which adapters apply
to an environment is decided by each adapter from directory data (provider of the cloud, products on the servers),
never by a default.
"""
from functools import partial
from importlib.metadata import entry_points
from pathlib import Path

from ..core.contract import Adapter, Domain, Services
from ..core.directory import get, rdn_value, subtree
from ..core.environment import env_model, with_required_roles
from ..core.naming import branch
from ..core.standard import CORE, schema_ldif
from ..store.migrations import DEFINITIONS as STORE_DEFINITIONS, read_migrations
from .stack import declared_adapters, missing_adapters

DOMAIN_GROUP = "opsdir.domains"
ADAPTER_GROUP = "opsdir.adapters"
KIND_ORDER = ("provider", "product", "secret-store")     # providers first: their files lead a render
ENVIRONMENTS = branch("environments")
CONNECTOR_SQL = (Path(__file__).resolve().parent / "sql" / "connectors.sql",)


# ------------------------------------------------------------------ discovery
def registered(group, record, loaded):
    """The records registered in an entry-point group, from its (entry-point name, object, version) triples;
    refused unless each object is a `record` and every record name is unique."""
    wrong = [name for name, obj, _ in loaded if not isinstance(obj, record)]
    if wrong:
        raise SystemExit(f"{group}: not a {record.__name__} record: {', '.join(wrong)}")
    names = [obj.name for _, obj, _ in loaded]
    repeated = sorted({n for n in names if names.count(n) > 1})
    if repeated:
        raise SystemExit(f"{group}: registered more than once: {', '.join(repeated)}")
    return tuple(obj for _, obj, _ in loaded)


def versions(loaded):
    """{record name: version of the distribution that registered it}."""
    return {obj.name: version for _, obj, version in loaded}


def ordered_domains(domains):
    """Domains in the order they run and report (Domain.order, then name)."""
    return tuple(sorted(domains, key=lambda d: (d.order, d.name)))


def ordered_adapters(adapters):
    """Adapters by kind (providers, products, secret stores), then name."""
    unknown = [a.name for a in adapters if a.kind not in KIND_ORDER]
    if unknown:
        raise SystemExit(f"adapters of unknown kind: {', '.join(unknown)} (kinds: {', '.join(KIND_ORDER)})")
    return tuple(sorted(adapters, key=lambda a: (KIND_ORDER.index(a.kind), a.name)))


def discover(group):
    """Effect: (entry-point name, loaded object, distribution version) for every registration in a group."""
    return tuple((ep.name, ep.load(), ep.dist.version if ep.dist else None) for ep in entry_points(group=group))


DOMAINS = ordered_domains(registered(DOMAIN_GROUP, Domain, discover(DOMAIN_GROUP)))
_ADAPTERS_FOUND = discover(ADAPTER_GROUP)
ADAPTERS = ordered_adapters(registered(ADAPTER_GROUP, Adapter, _ADAPTERS_FOUND))
ADAPTER_VERSIONS = versions(_ADAPTERS_FOUND)
if not DOMAINS:
    raise SystemExit("no opsdir domains are registered: install the package (pip install -e opsdir)")


# ------------------------------------------------------------------ what the registered parts add up to
def definition_files():
    """Every SQL definition (views, report functions), in apply order: the store's, each domain's, then the
    cross-domain views. Migrations (tables, rules) are the store's own."""
    return (*sorted(STORE_DEFINITIONS.glob("*.sql")), *(f for domain in DOMAINS for f in domain.sql), *CONNECTOR_SQL)


def schema_fragments():
    """Every schema fragment: core first, then each domain's."""
    return (CORE, *(domain.schema for domain in DOMAINS))


def vocabulary(domains=DOMAINS, adapters=ADAPTERS):
    """(attribute, value, owner) for every `vocab` value a registered domain or adapter defines."""
    return tuple(dict.fromkeys((attr, value, part.name) for part in (*domains, *adapters)
                               for attr, values in part.vocabulary.items() for value in values))


def store_parts():
    """Effect (reads the migration files): what `init` and `upgrade` build the store from: (migrations, definition
    files, schema text composed from the registered fragments, reference schemes, vocabulary)."""
    return read_migrations(), definition_files(), schema_ldif(schema_fragments()), ref_schemes(), vocabulary()


def applicable(m, installed=ADAPTERS):
    """The installed adapters that render an environment: its declared stack's, else inferred from its data.
    Refuses an environment whose stack declares adapters that are not installed."""
    missing = missing_adapters(m, installed)
    if missing:
        raise SystemExit(f"{m.label} declares adapters that are not installed: "
                         f"{', '.join(c.adapter for c in missing)} (run `opsdir check`)")
    return declared_adapters(m, installed)


def required_roles(adapters, domains=DOMAINS):
    """Roles an environment must bind: every domain's, then each applicable adapter's (first mention wins)."""
    return tuple(dict.fromkeys(r for part in (*domains, *adapters) for r in part.required_roles))


def environment_specs(d):
    """Every environment in the directory as a cloud/env spec, in DN order."""
    return tuple(f"{rdn_value(get(d, e.dn.split(',', 1)[1]))}/{rdn_value(e)}"
                 for e in subtree(d, ENVIRONMENTS, "ciamEnvironment"))


def environment(d, spec, installed=ADAPTERS):
    """(EnvModel with its required roles resolved, the installed adapters that apply to it)."""
    m = env_model(d, spec)
    adapters = applicable(m, installed)
    return with_required_roles(m, required_roles(adapters)), adapters


def ref_schemes(installed=ADAPTERS):
    """Every secret/key/storage reference scheme some adapter owns (the store accepts only these in ref-uri values)."""
    return tuple(dict.fromkeys(s for a in installed for s in a.ref_schemes))


def secret_command(uri, installed=ADAPTERS):
    """Shell command resolving a secret reference, from the adapter that owns its scheme."""
    scheme, rest = uri.split("://", 1)
    resolvers = {s: resolve for a in installed for s, resolve in a.secret_schemes.items()}
    if scheme not in resolvers:
        raise SystemExit(f"no resolver for secret scheme {scheme}")
    return resolvers[scheme](rest)


def services(installed=ADAPTERS):
    """What connectors provide to adapters while rendering, resolved against the installed adapters."""
    return Services(secret_command=partial(secret_command, installed=installed))

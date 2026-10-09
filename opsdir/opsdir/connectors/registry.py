"""The parts of the stack and which of them apply to an environment.

Domains, adapters and file formats are discovered, never imported by name: every installed distribution registers them
under the entry-point groups `opsdir.domains`, `opsdir.adapters` and `opsdir.formats` (the core registers its
built-in domains and the standard formats the same way).
Installing an adapter package is all it takes to add a product, cloud provider or secret store. Which adapters apply
to an environment is decided by each adapter from directory data (provider of the cloud, products on the servers),
never by a default.
"""
from functools import partial
from importlib.metadata import entry_points
from pathlib import Path

from ..core.contract import Adapter, Domain, Format, SecretPattern, Services
from ..core.directory import get, rdn_value, subtree
from ..core.environment import env_model, with_required_roles
from ..core.inventory import imports
from ..core.naming import branch
from ..core.secrets import CORE_OWNER, CORE_PATTERNS, dialect_problems
from ..core.standard import CORE
from ..store.migrations import DEFINITIONS as STORE_DEFINITIONS, read_migrations
from . import schema
from .stack import declared_adapters, missing_adapters

DOMAIN_GROUP = "opsdir.domains"
ADAPTER_GROUP = "opsdir.adapters"
FORMAT_GROUP = "opsdir.formats"
FORMAT_ATTRIBUTE = "ciamFormat"                          # its values are the registered formats' names
KIND_ORDER = ("provider", "platform", "product", "host", "delivery", "secret-store", "compliance")   # providers first: their files lead a render
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
    """Adapters by kind (providers, products, secret stores), then name. Refused: an adapter of a kind not known, or
    one declaring a prerequisite fetched with an importer it doesn't have."""
    unknown = [a.name for a in adapters if a.kind not in KIND_ORDER]
    if unknown:
        raise SystemExit(f"adapters of unknown kind: {', '.join(unknown)} (kinds: {', '.join(KIND_ORDER)})")
    unfetched = [f"{a.name} ({p.name}: {p.importer})" for a in adapters for p in a.prerequisites
                 if p.importer not in {i.name for i in a.importers}]
    if unfetched:
        raise SystemExit(f"prerequisites naming an importer their adapter doesn't have: {', '.join(unfetched)}")
    return tuple(sorted(adapters, key=lambda a: (KIND_ORDER.index(a.kind), a.name)))


def discover(group):
    """Effect: (entry-point name, loaded object, distribution version) for every registration in a group."""
    return tuple((ep.name, ep.load(), ep.dist.version if ep.dist else None) for ep in entry_points(group=group))


DOMAINS = ordered_domains(registered(DOMAIN_GROUP, Domain, discover(DOMAIN_GROUP)))
_ADAPTERS_FOUND = discover(ADAPTER_GROUP)
ADAPTERS = ordered_adapters(registered(ADAPTER_GROUP, Adapter, _ADAPTERS_FOUND))
ADAPTER_VERSIONS = versions(_ADAPTERS_FOUND)
FORMATS = tuple(sorted(registered(FORMAT_GROUP, Format, discover(FORMAT_GROUP)), key=lambda f: f.name))
if not DOMAINS:
    raise SystemExit("no opsdir domains are registered: install the package (pip install -e opsdir)")


# ------------------------------------------------------------------ what the registered parts add up to
def definition_files():
    """Every SQL definition (views, report functions), in apply order: the store's, each domain's, then the
    cross-domain views. Migrations (tables, rules) are the store's own."""
    return (*sorted(STORE_DEFINITIONS.glob("*.sql")), *(f for domain in DOMAINS for f in domain.sql), *CONNECTOR_SQL)


def core_fragments(domains=DOMAINS):
    """The core's schema fragment, then each domain's: what the published schema file holds."""
    return (CORE, *(domain.schema for domain in domains))


def schema_fragments(domains=DOMAINS, adapters=ADAPTERS):
    """Every schema fragment the store is built from: the core's and the domains', then each installed adapter's
    (a package that adds definitions numbers them under its own OID arc)."""
    return (*core_fragments(domains), *(a.schema for a in adapters if a.schema))


def vocabulary(domains=DOMAINS, adapters=ADAPTERS, formats=FORMATS):
    """(attribute, value, owner) for every `vocab` value a registered domain or adapter defines, and each registered
    format's name (the values of ciamFormat)."""
    return tuple(dict.fromkeys(
        [(attr, value, part.name) for part in (*domains, *adapters) for attr, values in part.vocabulary.items()
         for value in values]
        + [(FORMAT_ATTRIBUTE, f.name, f"format {f.name}") for f in formats]))


def secret_patterns(installed=ADAPTERS):
    """(name, pattern, owner, description) for every form of secret material the store refuses: the core's generic
    ones, then each installed adapter's. Refuses patterns the store can't evaluate or names registered twice."""
    owned = (*((p, CORE_OWNER) for p in CORE_PATTERNS), *((p, a.name) for a in installed for p in a.secret_patterns))
    wrong = dialect_problems(tuple(p for p, _ in owned))
    if wrong:
        raise SystemExit("secret patterns the store can't use: " + "; ".join(wrong))
    return tuple((p.name, p.pattern, owner, p.description) for p, owner in owned)


def pattern_records(installed=ADAPTERS):
    """The secret patterns as SecretPattern records (what capture and importers withhold values with)."""
    return tuple(SecretPattern(name, pattern, description) for name, pattern, _, description in secret_patterns(installed))


def format_named(name, formats=FORMATS):
    """The registered format of that name, or None."""
    return next((f for f in formats if f.name == name), None)


def schema_sync(installed=ADAPTERS):
    """How a write that changes custom definitions re-syncs the store's schema, for the installed adapters."""
    return schema.schema_sync(schema_fragments(adapters=installed))


def store_parts(installed=ADAPTERS):
    """Effect (reads the migration files): what `init` and `upgrade` build the store from: (migrations, definition
    files, the schema (a function of the connection: code-owned fragments composed with the record's custom
    definitions), reference schemes, vocabulary, secret patterns)."""
    return (read_migrations(), definition_files(), partial(schema.store_schema, fragments=schema_fragments(adapters=installed)),
            ref_schemes(installed), vocabulary(adapters=installed), secret_patterns(installed))


def applicable(m, installed=ADAPTERS):
    """The installed adapters that render an environment: its declared stack's, else inferred from its data.
    Refuses an environment whose stack declares adapters that are not installed."""
    missing = missing_adapters(m, installed)
    if missing:
        raise SystemExit(f"{m.label} declares adapters that are not installed: "
                         f"{', '.join(c.adapter for c in missing)} (run `opsdir check`)")
    return declared_adapters(m, installed)


def import_table(domains=DOMAINS):
    """How the domains read cloud resources into the record (core.inventory.Imports): what an import's snapshot
    carries."""
    return imports(domains)


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


def listeners_of(m, installed=ADAPTERS):
    """The ports the installed adapters' products listen on in environment m."""
    return tuple(lst for a in installed if a.listeners for lst in a.listeners(m))


def workload_identity_of(m, binding, installed=ADAPTERS):
    """The K8sIdentity of an identity binding from the first installed adapter that applies to m and declares workload
    identity (its cloud's provider adapter), or None."""
    hook = next((a.workload_identity for a in installed if a.workload_identity and a.applies and a.applies(m)), None)
    return hook(m, binding) if hook else None


def routes_of(m, installed=ADAPTERS):
    """The HTTP routes the installed adapters' deployment kits serve through a cluster gateway in environment m."""
    return tuple(r for a in installed if a.routes for r in a.routes(m))


def gateway_plug_of(m, gateway, service, installed=ADAPTERS):
    """The GatewayPlug of a cluster gateway binding whose data-plane Service is service ((name, ports)) from the first
    installed adapter that applies to m and declares a gateway plug (its cloud's provider adapter), or None."""
    hook = next((a.gateway_plug for a in installed if a.gateway_plug and a.applies and a.applies(m)), None)
    return hook(m, gateway, service) if hook else None


def secret_delivery_of(scheme, installed=ADAPTERS):
    """The SecretDelivery of the installed adapter owning a ref-uri scheme, or None."""
    return next((a.secret_delivery[scheme] for a in installed if a.secret_delivery and scheme in a.secret_delivery),
                None)


def services(installed=ADAPTERS):
    """What connectors provide to adapters while rendering, resolved against the installed adapters."""
    return Services(secret_command=partial(secret_command, installed=installed),
                    endpoints=tuple(e for a in installed for e in a.endpoints),
                    listeners=partial(listeners_of, installed=installed),
                    workload_identity=partial(workload_identity_of, installed=installed),
                    secret_delivery=partial(secret_delivery_of, installed=installed),
                    routes=partial(routes_of, installed=installed),
                    gateway_plug=partial(gateway_plug_of, installed=installed))

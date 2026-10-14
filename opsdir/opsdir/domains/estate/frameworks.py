"""Compliance frameworks: what a provider offers an organization to assess its resources against (a framework, at a
revision, made of controls). They are fetched from the provider (the cloud adapters' framework importers, run with the
provider's own commands) into the framework catalog: one ciamFrameworkCatalog per provider and organization under
ou=frameworks, a ciamProviderFramework per framework the provider lists (its full name, revision, name as shown, how it
can be enforced, and the framework or baseline it answers by the neutral id a posture service names, as its adapter
maps it), and the ciamProviderControl entries of the frameworks a posture service names (a deployment lists every
control, with the parameters it requires). The renderers deploy a posture service's frameworks from it; one not
fetched stays a request. Which organization an environment's cloud belongs to is its adapter's to say
(organization_of). Pure."""
import json
from collections import namedtuple

from ...core.contract import Imported
from ...core.directory import children, get, make_entry, merged_attrs, ou_entry, subtree, values
from ...core.environment import env_model
from ...core.naming import branch
from .naming import FRAMEWORKS
from .security import security_services

CATALOG = "ciamFrameworkCatalog"
FRAMEWORK = "ciamProviderFramework"
CONTROL = "ciamProviderControl"
# One framework as a provider lists it: its id (the provider's: builtin-nist-800-53-r5), full name, revision, name as
# shown, enforcement modes (naming.ENFORCEMENT_MODES), the neutral framework and baseline ids it answers (its adapter's
# mapping) and its controls (ControlRows).
FrameworkRow = namedtuple("FrameworkRow", ("id", "name", "revision", "title", "modes", "standards", "baselines",
                                           "controls"), defaults=(None, (), (), (), ()))
# One control of a framework: its id, full name, revision, enforcement modes and the parameters it requires
# ((name, default or None), ...).
ControlRow = namedtuple("ControlRow", ("id", "name", "revision", "modes", "parameters"), defaults=((), ()))
FRAMEWORK_OWNED = ("cn", "ciamProviderRef", "ciamRevision", "ciamFrameworkName", "ciamEnforcementMode",
                   "ciamComplianceStandard", "ciamSecurityBaseline")
CONTROL_OWNED = ("cn", "ciamProviderRef", "ciamRevision", "ciamEnforcementMode", "ciamControlParameter")


def catalog_dn(provider, organization):
    """DN of a provider's framework catalog for one organization."""
    return f"cn={provider}:{organization},{FRAMEWORKS}"


def _models(d):
    return [env_model(d, e.dn) for e in subtree(d, branch("environments"), "ciamEnvironment")]


def assessed(m):
    """(frameworks, baselines) environment m's posture services name."""
    services = security_services(m, "posture")
    return (tuple(sorted({v for s in services for v in values(s, "ciamComplianceStandard")})),
            tuple(sorted({v for s in services for v in values(s, "ciamSecurityBaseline")})))


def wanted_frameworks(d, provider, organization_of):
    """{organization: (frameworks, baselines)} the posture services of a provider's environments name, by the
    organization their cloud belongs to (organization_of(m); environments it gives none for are left out)."""
    named = [(org, assessed(m)) for m in _models(d) if m.provider == provider and any(assessed(m))
             for org in (organization_of(m),) if org]
    return {org: (tuple(sorted({v for o, (f, _) in named if o == org for v in f})),
                  tuple(sorted({v for o, (_, b) in named if o == org for v in b})))
            for org in sorted({o for o, _ in named})}


def frameworks_fetched(d, provider, organization_of):
    """Whether the framework catalog holds every organization whose environments' posture services name frameworks or
    baselines (the provider's framework prerequisite is met; nothing named is met too)."""
    return all(get(d, catalog_dn(provider, org)) is not None for org in wanted_frameworks(d, provider, organization_of))


def provider_framework(d, provider, organization, key):
    """The catalog framework of a provider's organization answering a neutral framework or baseline id, or None."""
    return next((f for f in children(d, catalog_dn(provider, organization), FRAMEWORK)
                 if key in (*values(f, "ciamComplianceStandard"), *values(f, "ciamSecurityBaseline"))), None)


def framework_controls(d, framework):
    """The controls of a catalog framework (none when no posture service named it at import)."""
    return children(d, framework.dn, CONTROL)


def control_parameters(control):
    """The parameters a catalog control requires: ((name, default or None), ...)."""
    return tuple((name, json.loads(default) if sep else None)
                 for name, sep, default in (v.partition("=") for v in values(control, "ciamControlParameter")))


def _parameter(name, default):
    return name if default is None else f"{name}={json.dumps(default, sort_keys=True)}"


def _catalog(d, dn, provider, organization):
    owned = ("cn", "ciamCloudProvider", "ciamOrganizationRef")
    return make_entry(dn, ("top", CATALOG), merged_attrs(get(d, dn), dict(zip(owned, (
        (f"{provider}:{organization}",), (provider,), (organization,)))), owned))


def _framework(d, dn, row, with_controls):
    fdn = f"cn={row.id},{dn}"
    given = dict(zip(FRAMEWORK_OWNED, ((row.id,), (row.name,), (str(row.revision),), (row.title,), row.modes,
                                       row.standards, row.baselines)))
    return (make_entry(fdn, ("top", FRAMEWORK), merged_attrs(get(d, fdn), given, FRAMEWORK_OWNED)),
            *(make_entry(cdn, ("top", CONTROL), merged_attrs(get(d, cdn), dict(zip(CONTROL_OWNED, (
                (c.id,), (c.name,), (str(c.revision),), c.modes, tuple(_parameter(*p) for p in c.parameters)))),
                CONTROL_OWNED))
              for c in (row.controls if with_controls else ()) for cdn in (f"cn={c.id},{fdn}",)))


def _answers(row, named):
    frameworks, baselines = named
    return bool(set(row.standards) & set(frameworks) or set(row.baselines) & set(baselines))


def _notice(provider, org, rows, named):
    if not rows:
        return (f"{provider} organization {org}: lists no framework; its catalog left as it is",)
    kept = [r.id for r in rows if _answers(r, named)]
    missing = [k for k in named[0] if not any(k in r.standards for r in rows)]
    return (f"{provider} organization {org}: {len(rows)} frameworks"
            + (f", the controls of {', '.join(kept)} kept" if kept else ""),
            *((f"{provider} organization {org}: no framework listed answers {', '.join(missing)} (not offered, or "
               "listed under another name)",) if missing else ()))


def framework_import(d, provider, catalogs, organization_of):
    """Imported: the framework catalogs a provider's lists give, {organization: (FrameworkRow, ...)}: every framework
    listed, with its controls when a posture service of that organization names a framework or baseline it answers. A
    list with no framework leaves its catalog as it is (an empty or wrong export would remove every framework)."""
    wanted = wanted_frameworks(d, provider, organization_of)
    return Imported(
        containers=(ou_entry(FRAMEWORKS),),
        groups=tuple((dn, (_catalog(d, dn, provider, org),
                           *(x for r in rows for x in _framework(d, dn, r, _answers(r, wanted.get(org, ((), ())))))))
                     for org, rows in sorted(catalogs.items()) if rows for dn in (catalog_dn(provider, org),)),
        notices=tuple(n for org, rows in sorted(catalogs.items())
                      for n in _notice(provider, org, rows, wanted.get(org, ((), ())))))

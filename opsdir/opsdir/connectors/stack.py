"""Declared stacks against the installed adapters: which adapters render an environment, and `opsdir check`.

An environment's stack (entries under ou=stack) says which adapter fills each role. When it declares one, exactly
those adapters render it; otherwise they are inferred from the data (each adapter's `applies`). A declaration-only
adapter (`applies` is None: a generic adapter for a standard, which every compliant server would match) is never
inferred; it renders only where a stack declares it. A connector: it joins the directory's declarations with what
the registry discovered. Every function here is pure.
"""
from ..core.environment import EnvModel, product_roles, with_product_roles
from ..core.naming import env_label
from ..core.versions import in_range, product_version
from ..domains.compute.workloads import version_holders

STATUS_HEADERS = ("environment", "role", "adapter", "status")


def matches_data(a, m):
    """Whether an adapter's `applies` matches the environment's data (never, for a declaration-only adapter)."""
    return a.applies is not None and a.applies(m)


def _with_roles(m, adapters):
    """m carrying the adapters' product roles, unless it already carries some (registry.environment's) or isn't an
    EnvModel (a caller's stand-in)."""
    return with_product_roles(m, product_roles(adapters)) if isinstance(m, EnvModel) and not m.product_roles else m


def declared_adapters(m, adapters):
    """The adapters that render an environment: its declared stack's (in registry order), or those whose `applies`
    matches its data when it declares none (with the adapters' product roles: a kit finds its products by them)."""
    m = _with_roles(m, adapters)
    if not m.stack:
        return tuple(a for a in adapters if matches_data(a, m))
    names = {c.adapter for c in m.stack}
    return tuple(a for a in adapters if a.name in names)


def missing_adapters(m, adapters):
    """Declared stack components whose adapter is not installed."""
    installed = {a.name for a in adapters}
    return tuple(c for c in m.stack if c.adapter not in installed)




def _component_status(m, c, by_name, versions):
    """(status text, is a problem) for one declared component."""
    a = by_name.get(c.adapter)
    if a is None:
        return f"NOT INSTALLED{f'; get it from {c.source}' if c.source else ''}", True
    v = versions.get(c.adapter) or "unknown"
    if c.versions and not in_range(v, c.versions):
        return f"installed {v}, but the stack accepts {c.versions}", True
    if a.kind != "secret-store" and a.applies is not None and not a.applies(m):
        return f"installed {v}, but the environment's data doesn't match it (provider or products)", True
    names = tuple(t[0] for t in a.render_targets)
    targets, wrong = ", ".join(names), ", ".join(t for t in c.targets if t not in names)
    if wrong:
        return (f"installed {v}, but it has no render target {wrong} "
                f"({f'it renders: {targets}' if targets else 'it has none to choose'})"), True
    chosen = f"; renders {', '.join(c.targets)}" if c.targets else ""
    return f"ok (installed {v}{chosen})", False


def unsupported_products(m, adapters):
    """(what, adapter, product version, range) for every server, and every workload on Kubernetes, running a product
    one of the adapters renders at a version outside the range the adapter declares (compute.version_holders)."""
    return tuple((what, a, version, versions) for what, version in version_holders(m) for a in adapters
                 for product, versions in a.products
                 if product_version(version)[0] == product and not in_range(product_version(version)[1], versions))


def _product_rows(m, adapters):
    return tuple((m.label, "-", a.name, f"{what} runs {version}; {a.name} supports {versions}")
                 for what, a, version, versions in unsupported_products(m, adapters))


def _overlay_rows(m):
    bases = [env_label(e.dn) for e in m.lineage[1:]]
    through = f" (itself an overlay of {', '.join(bases[1:])})" if len(bases) > 1 else ""
    return ((m.label, "-", "-", f"overlay of {bases[0]}{through}: inherits the bindings, stack, required roles and "
             "overrides it doesn't set itself"),) if bases else ()


def _host_file_rows(m, adapters, files):
    """A row naming the files the adapters render for environment m's servers (HostFiles: agents' configuration) when
    no adapter rendering it places them: they reach no server. A warning, not a problem: the files are rendered, and
    an operator may place them another way."""
    if not files or any(a.places_host_files for a in declared_adapters(m, adapters)):
        return ()
    paths, roles = sorted({f.path for f in files}), sorted({f.server_role for f in files})
    return ((m.label, "-", "-", f"{len(files)} files rendered for the servers of {', '.join(roles)} "
             f"({', '.join(paths)}) that no adapter in its stack places: declare one that places host files "
             "(configuration management), or place them another way"),)


def stack_rows(m, adapters, versions, host_files=()):
    """(rows, problem count) describing one environment's stack against the installed adapters (name -> version),
    servers whose product versions the adapters rendering them don't support, the environments it is an overlay of,
    and the files rendered for its servers (host_files: the HostFiles its adapters render) nothing places."""
    rows, problems = _stack_rows(m, adapters, versions)
    return (*_overlay_rows(m), *rows, *_host_file_rows(m, adapters, host_files)), problems


def _stack_rows(m, adapters, versions):
    m = _with_roles(m, adapters)
    products = _product_rows(m, declared_adapters(m, adapters))
    if not m.stack:
        inferred = ", ".join(a.name for a in declared_adapters(m, adapters)) or "none"
        return ((m.label, "-", "-", f"no stack declared; adapters inferred from the data: {inferred}"), *products), \
            len(products)
    by_name = {a.name: a for a in adapters}
    declared = [(c, *_component_status(m, c, by_name, versions)) for c in m.stack]
    names = {c.adapter for c in m.stack}
    undeclared = [a for a in adapters if a.kind != "secret-store" and matches_data(a, m) and a.name not in names]
    rows = ([(m.label, c.role, c.adapter, status) for c, status, _ in declared]
            + [(m.label, "-", a.name, "applies to the environment's data but is not in its stack") for a in undeclared])
    return (*rows, *products), sum(problem for _, _, problem in declared) + len(undeclared) + len(products)


def note_rows(m, notes):
    """Stack check rows of environment m's render blockers and actions (core.notes RenderNotes): each with its owners;
    the rest is in its render's NOTES.md."""
    return tuple((m.label, "-", "-", f"render {n.severity}: {n.subject}: {n.text} [{', '.join(n.owners) or 'NO OWNER'}]"
                  f" (opsdir render {m.label}: NOTES.md)") for n in notes if n.severity in ("blocker", "action"))

"""Declared stacks against the installed adapters: which adapters render an environment, and `opsdir check`.

An environment's stack (entries under ou=stack) says which adapter fills each role. When it declares one, exactly
those adapters render it; otherwise they are inferred from the data (each adapter's `applies`). A connector: it
joins the directory's declarations with what the registry discovered. Every function here is pure.
"""
from packaging.specifiers import InvalidSpecifier, SpecifierSet

STATUS_HEADERS = ("environment", "role", "adapter", "status")


def declared_adapters(m, adapters):
    """The adapters that render an environment: its declared stack's (in registry order), or those whose `applies`
    matches its data when it declares none."""
    if not m.stack:
        return tuple(a for a in adapters if a.applies(m))
    names = {c.adapter for c in m.stack}
    return tuple(a for a in adapters if a.name in names)


def missing_adapters(m, adapters):
    """Declared stack components whose adapter is not installed."""
    installed = {a.name for a in adapters}
    return tuple(c for c in m.stack if c.adapter not in installed)


def _in_range(version, versions):
    try:
        return SpecifierSet(versions).contains(version, prereleases=True)
    except InvalidSpecifier:
        return False


def _component_status(m, c, by_name, versions):
    """(status text, is a problem) for one declared component."""
    a = by_name.get(c.adapter)
    if a is None:
        return f"NOT INSTALLED{f'; get it from {c.source}' if c.source else ''}", True
    v = versions.get(c.adapter) or "unknown"
    if c.versions and not _in_range(v, c.versions):
        return f"installed {v}, but the stack accepts {c.versions}", True
    if a.kind != "secret-store" and not a.applies(m):
        return f"installed {v}, but the environment's data doesn't match it (provider or products)", True
    return f"ok (installed {v})", False


def stack_rows(m, adapters, versions):
    """(rows, problem count) describing one environment's stack against the installed adapters (name -> version)."""
    if not m.stack:
        inferred = ", ".join(a.name for a in declared_adapters(m, adapters)) or "none"
        return ((m.label, "-", "-", f"no stack declared; adapters inferred from the data: {inferred}"),), 0
    by_name = {a.name: a for a in adapters}
    declared = [(c, *_component_status(m, c, by_name, versions)) for c in m.stack]
    names = {c.adapter for c in m.stack}
    undeclared = [a for a in adapters if a.kind != "secret-store" and a.applies(m) and a.name not in names]
    rows = ([(m.label, c.role, c.adapter, status) for c, status, _ in declared]
            + [(m.label, "-", a.name, "applies to the environment's data but is not in its stack") for a in undeclared])
    return tuple(rows), sum(problem for _, _, problem in declared) + len(undeclared)

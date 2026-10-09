"""Render a complete, working configuration set for one environment: the applicable adapters' outputs, each in a
format the adapter declares and some installed package registers, the captured config files the environment
receives, plus the MANIFEST (R10)."""
from ..core.environment import as_seen
from ..core.formats import format_of
from ..core.manifest import manifest
from .capture import rendered_config
from .registry import ADAPTERS, FORMATS, environment, services


def chosen_targets(adapters, wanted=None):
    """{adapter name: the render targets chosen} for the adapters that declare targets: those wanted ({adapter: (names,
    ...)}), by default an adapter's targets not marked only-when-asked; refused for an adapter that declares none here
    or a target it doesn't declare, naming those it does."""
    wanted = wanted or {}
    declared = {a.name: tuple(t[0] for t in a.render_targets) for a in adapters if a.render_targets}
    defaults = {a.name: tuple(t[0] for t in a.render_targets if len(t) < 3 or t[2]) for a in adapters
                if a.render_targets}
    unknown = sorted(name for name in wanted if name not in declared)
    if unknown:
        raise SystemExit(f"no render targets to choose for {', '.join(unknown)} here (adapters with targets: "
                         f"{', '.join(sorted(declared)) or 'none'})")
    wrong = sorted(f"{name}={t} (it renders: {', '.join(declared[name])})" for name, ts in wanted.items()
                   for t in ts if t not in declared[name])
    if wrong:
        raise SystemExit(f"unknown render targets: {', '.join(wrong)}")
    return {name: tuple(t for t in names if t in wanted.get(name, defaults[name])) for name, names in declared.items()}


def _env_files(a, m, found, targets):
    return a.render_env(m, found, targets[a.name]) if a.name in targets else a.render_env(m, found)


def render_parts(d, spec, installed=ADAPTERS, wanted=None):
    """(EnvModel as the environment sees the record (its overrides applied), applicable adapters,
    environment-neutral files, environment-specific files, the render targets chosen); wanted: {adapter: (target,
    ...)} (default: every target)."""
    shared, adapters = environment(d, spec, installed)
    m = as_seen(shared)
    if not any(a.kind == "provider" for a in adapters):
        raise SystemExit(f"no renderer for provider {m.provider}")
    targets = chosen_targets(adapters, wanted)
    neutral = {p: text for a in adapters if a.render_neutral for p, text in a.render_neutral(m.d).items()}
    found = services(installed)
    specific = {p: text for a in adapters if a.render_env for p, text in _env_files(a, m, found, targets).items()}
    return m, adapters, neutral, specific, targets


def _declared(adapters, path):
    """(adapter, format name) of the first applicable adapter that declares a format for the path."""
    return next(((a, name) for a in adapters for name in (format_of(path, a.formats),) if name), (None, None))


def file_formats(adapters, paths, formats=FORMATS):
    """{path: format name} for every rendered file; refused when no adapter declares a file's format, or the format it
    declares is not registered (the file would be in a language nothing describes)."""
    registered = {f.name for f in formats}
    found = {p: _declared(adapters, p) for p in paths}
    undeclared = sorted(p for p, (a, _) in found.items() if a is None)
    if undeclared:
        raise SystemExit(f"no adapter declares the format of: {', '.join(undeclared)}")
    unknown = sorted(f"{p} ({name}, declared by {a.name})" for p, (a, name) in found.items() if name not in registered)
    if unknown:
        raise SystemExit(f"rendered files are in formats no installed package registers: {', '.join(unknown)}")
    return {p: name for p, (_, name) in found.items()}


def assemble(m, adapters, neutral, specific, targets=None):
    """The environment's files: the adapters' outputs, the captured config files it receives, and the MANIFEST (with
    the render targets chosen)."""
    config = rendered_config(m.d, m)
    clash = sorted(set(config.files) & {*neutral, *specific})
    if clash:
        raise SystemExit(f"captured files and rendered files share paths: {', '.join(clash)}")
    formats = {**file_formats(adapters, (*neutral, *specific)), **config.formats}
    return {**neutral, **specific, **config.files,
            "MANIFEST.json": manifest(m, neutral, specific, formats, config.files, config.scopes, config.not_rendered,
                                      targets)}


def render_env(d, spec, installed=ADAPTERS, wanted=None):
    m, adapters, neutral, specific, targets = render_parts(d, spec, installed, wanted)
    return m, assemble(m, adapters, neutral, specific, targets)

"""Render a complete, working configuration set for one environment: the applicable adapters' outputs, each in a
format the adapter declares and some installed package registers, the captured config files the environment
receives, plus the MANIFEST (R10)."""
from ..core.environment import as_seen
from ..core.formats import format_of
from ..core.manifest import manifest
from .capture import rendered_config
from .registry import ADAPTERS, FORMATS, environment, services


def render_parts(d, spec, installed=ADAPTERS):
    """(EnvModel as the environment sees the record (its overrides applied), applicable adapters,
    environment-neutral files, environment-specific files)."""
    shared, adapters = environment(d, spec, installed)
    m = as_seen(shared)
    if not any(a.kind == "provider" for a in adapters):
        raise SystemExit(f"no renderer for provider {m.provider}")
    neutral = {p: text for a in adapters if a.render_neutral for p, text in a.render_neutral(m.d).items()}
    specific = {p: text for a in adapters if a.render_env for p, text in a.render_env(m, services(installed)).items()}
    return m, adapters, neutral, specific


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


def assemble(m, adapters, neutral, specific):
    """The environment's files: the adapters' outputs, the captured config files it receives, and the MANIFEST."""
    config = rendered_config(m.d, m)
    clash = sorted(set(config.files) & {*neutral, *specific})
    if clash:
        raise SystemExit(f"captured files and rendered files share paths: {', '.join(clash)}")
    formats = {**file_formats(adapters, (*neutral, *specific)), **config.formats}
    return {**neutral, **specific, **config.files,
            "MANIFEST.json": manifest(m, neutral, specific, formats, config.files, config.scopes, config.not_rendered)}


def render_env(d, spec, installed=ADAPTERS):
    m, adapters, neutral, specific = render_parts(d, spec, installed)
    return m, assemble(m, adapters, neutral, specific)

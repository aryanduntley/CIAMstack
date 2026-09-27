"""Render a complete, working configuration set for one environment: the applicable adapters' outputs
plus the MANIFEST (R10)."""
from ..core.manifest import manifest
from .registry import SERVICES, environment


def render_parts(d, spec):
    """(EnvModel, applicable adapters, environment-neutral files, environment-specific files)."""
    m, adapters = environment(d, spec)
    if not any(a.kind == "provider" for a in adapters):
        raise SystemExit(f"no renderer for provider {m.provider}")
    neutral = {p: text for a in adapters if a.render_neutral for p, text in a.render_neutral(d).items()}
    specific = {p: text for a in adapters if a.render_env for p, text in a.render_env(m, SERVICES).items()}
    return m, adapters, neutral, specific


def assemble(m, neutral, specific):
    return {**neutral, **specific, "MANIFEST.json": manifest(m, neutral, specific)}


def render_env(d, spec):
    m, _, neutral, specific = render_parts(d, spec)
    return m, assemble(m, neutral, specific)

"""Render a complete, working configuration set for one environment from the operations directory."""
import hashlib
import json

from . import ds, pingfed, terraform_aws, terraform_azure
from .model import EnvModel

PROVIDERS = {"aws": terraform_aws, "azure": terraform_azure}


def render_env(d, spec):
    m = EnvModel(d, spec)
    if m.provider not in PROVIDERS:
        raise SystemExit(f"no renderer for provider {m.provider}")
    neutral = {**ds.render_neutral(d), **pingfed.render_neutral(d)}
    specific = {**PROVIDERS[m.provider].render(m), **ds.setup_scripts(m)}
    manifest = {
        "environment": m.dn, "provider": m.provider, "unbound_roles": m.unbound,
        "files": {p: {"scope": "environment-neutral" if p in neutral else "environment-specific",
                      "sha256": hashlib.sha256(c.encode()).hexdigest()}
                  for p, c in sorted({**neutral, **specific}.items())},
    }
    return m, {**neutral, **specific, "MANIFEST.json": json.dumps(manifest, indent=2) + "\n"}

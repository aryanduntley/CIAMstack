"""The captured product configuration files an environment's servers receive (Services.deployable_config: rebuilt
with its bindings, with their target role and deploy path) as Jinja templates the host-config playbook writes to each
role's servers: the file's own text kept verbatim in raw blocks, each secret placeholder (${secret:<ref-uri>}) a lookup
read at run time on the controller (output.secret_lookup). A file isn't deployed, and is named with why, when a
placeholder can't be read (no scheme, or one no installed adapter resolves) or its target role has no servers here.
Pure."""
import re

from opsdir.core.directory import one
from .names import ROOT
from .output import secret_lookup

PLACEHOLDER = re.compile(r"\$\{secret:([^}]+)\}")
TEMPLATES = f"{ROOT}/templates"


def _raw(text):
    return "{% raw %}" + text + "{% endraw %}" if text else ""


def template(m, services, text):
    """(template, unreadable): a rendered file's text as a Jinja template (verbatim in raw blocks, secret
    placeholders as lookups), and the placeholders' references that can't be read (the template is None then)."""
    parts = PLACEHOLDER.split(text)        # text, ref, text, ref, ..., text
    lookups = {p: secret_lookup(m, services, p) for p in parts[1::2]}
    unreadable = tuple(dict.fromkeys(p for p, expr in lookups.items() if expr is None))
    return (None if unreadable else
            "".join(_raw(p) if i % 2 == 0 else lookups[p] for i, p in enumerate(parts))), unreadable


def config_templates(m, services):
    """({path under ansible/templates/: template text}, {role: [{src, dest}]}, [not deployed: why]) of the files m's
    servers receive."""
    served = {one(s, "ciamServerRole") for s in m.servers}
    found = [(role, dest, repo, *template(m, services, text))
             for role, dest, repo, text in services.deployable_config(m)]
    deployed = [(role, dest, repo, t) for role, dest, repo, t, _ in found if t is not None and role in served]
    not_deployed = [f"{dest}: " + (f"secret references it can't read: {', '.join(bad)}" if bad
                                   else f"role {role} has no servers here")
                    for role, dest, _, t, bad in found if t is None or role not in served]
    return ({f"{TEMPLATES}/{repo}.j2": t for _, _, repo, t in deployed},
            {role: [{"src": f"{repo}.j2", "dest": dest} for r, dest, repo, _ in deployed if r == role]
             for role in dict.fromkeys(r for r, *_ in deployed)},
            not_deployed)

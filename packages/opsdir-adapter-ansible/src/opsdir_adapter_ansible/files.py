"""The captured product configuration files an environment's servers receive (Services.deployable_config: rebuilt
with its bindings, with their target role and deploy path) as Jinja templates the host-config playbook writes to each
role's servers: the file's own text kept verbatim in raw blocks, each secret placeholder (${secret:<ref-uri>}) a lookup
read at run time on the controller (Services.ansible_lookup). Pure."""
import re

from opsdir.core.interchange import jinja
from .names import ROOT

PLACEHOLDER = re.compile(r"\$\{secret:([^}]+)\}")
TEMPLATES = f"{ROOT}/templates"


def _raw(text):
    return "{% raw %}" + text + "{% endraw %}" if text else ""


def template(m, services, text):
    """A rendered file's text as a Jinja template: verbatim in raw blocks, secret placeholders as lookups."""
    parts = PLACEHOLDER.split(text)        # text, ref, text, ref, ..., text
    return "".join(_raw(p) if i % 2 == 0 else jinja.expression(services.ansible_lookup(m, p))
                   for i, p in enumerate(parts))


def config_templates(m, services):
    """{path under ansible/templates/: template text} and {role: [{src, dest}]} of the files m's servers receive."""
    found = services.deployable_config(m)
    return ({f"{TEMPLATES}/{repo}.j2": template(m, services, text) for _, _, repo, text in found},
            {role: [{"src": f"{repo}.j2", "dest": dest} for r, dest, repo, _ in found if r == role]
             for role in dict.fromkeys(r for r, *_ in found)})

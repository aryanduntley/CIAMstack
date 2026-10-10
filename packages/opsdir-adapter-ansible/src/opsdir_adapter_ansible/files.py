"""The captured product configuration files an environment's servers receive (Services.deployable_config: rebuilt
with its bindings, with their target role and deploy path) as Jinja templates the host-config playbook writes to each
role's servers: the file's own text kept verbatim in raw blocks, each secret placeholder (${secret:<ref-uri>}) a lookup
read at run time on the controller (output.secret_lookup). A file isn't deployed, and is named with why, when a
placeholder can't be read (no scheme, or one no installed adapter resolves) or its target role has no servers here.
The files other adapters render for the servers (Services.host_files: agents' configuration) become templates the
same way, under host-files/<role>/ (host-files/<role>/<first server>/ for a file only some of the role's servers
receive: those a file is for don't overlap with another file's at the same path), each with the command that makes
what reads it take it up and, when it isn't for all of them, the host names of the servers that receive it. Pure."""
import re

from opsdir.core.directory import one, rdn_value
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


def _not_deployed(dest, role, bad):
    return f"{dest}: " + (f"secret references it can't read: {', '.join(bad)}" if bad
                          else f"role {role} has no servers here")


def config_templates(m, services):
    """({path under ansible/templates/: template text}, {role: [{src, dest}]}, [not deployed: why]) of the files m's
    servers receive."""
    served = {one(s, "ciamServerRole") for s in m.servers}
    found = [(role, dest, repo, *template(m, services, text))
             for role, dest, repo, text in services.deployable_config(m)]
    deployed = [(role, dest, repo, t) for role, dest, repo, t, _ in found if t is not None and role in served]
    return ({f"{TEMPLATES}/{repo}.j2": t for _, _, repo, t in deployed},
            {role: [{"src": f"{repo}.j2", "dest": dest} for r, dest, repo, _ in deployed if r == role]
             for role in dict.fromkeys(r for r, *_ in deployed)},
            [_not_deployed(dest, role, bad) for role, dest, _, t, bad in found if t is None or role not in served])


def _host_repo(f):
    return "/".join(("host-files", f.server_role, *f.hosts[:1], f.path.lstrip("/")))


def host_file_templates(m, services):
    """({path under ansible/templates/: template text}, {role: [{src, dest, mode[, reload][, hosts]}]}, [not deployed:
    why]) of the files the adapters rendering m render for its servers (Services.host_files)."""
    served = {one(s, "ciamServerRole") for s in m.servers}
    hostname = {rdn_value(s): one(s, "ciamHostname") for s in m.servers}
    found = [(f, _host_repo(f), *template(m, services, f.text)) for f in services.host_files(m)]
    deployed = [(f, repo, t) for f, repo, t, _ in found if t is not None and f.server_role in served]
    return ({f"{TEMPLATES}/{repo}.j2": t for _, repo, t in deployed},
            {role: [{"src": f"{repo}.j2", "dest": f.path, "mode": f.mode,
                     **({"reload": list(f.reload)} if f.reload else {}),
                     **({"hosts": [hostname[h] for h in f.hosts if h in hostname]} if f.hosts else {})}
                    for f, repo, _ in deployed if f.server_role == role]
             for role in dict.fromkeys(f.server_role for f, *_ in deployed)},
            [_not_deployed(f.path, f.server_role, bad) for f, _, t, bad in found
             if t is None or f.server_role not in served])

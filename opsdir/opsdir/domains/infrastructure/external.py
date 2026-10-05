"""Systems the platform reaches but doesn't run (a database, a corporate directory): each environment records its host
as a ciamExternalHost binding of a role, so a product that reaches one names the role and each environment renders its
own host (core.environment.published_role is how importers turn the host into the role). Pure.
"""
import re

from ...core.changeset import new_entry
from ...core.findings import Fix, Input, bindings_container

ROLE_PATTERN = r"[a-z0-9]([a-z0-9-]*[a-z0-9])?"


def _cn(host):
    return "ext-" + re.sub(r"[^a-z0-9-]+", "-", host.lower()).strip("-")


def external_host_fix(m, host, what, key, importer, port=None):
    """The Fix recording host (and port, when the product's setting names one the role must carry) as environment m's
    host of an external system's role (the role an input: never guessed), so that importing the product again
    (importer) names the role in place of the host."""
    hint = re.sub(r"[^a-z0-9-]+", "-", host.lower().split(".", 1)[0]).strip("-")
    cn = _cn(host)
    return Fix(key, "Hosts", f"Record `{host}`, which {what} reaches, as {m.label}'s host of a role",
               (*bindings_container(m.d, m.dn),
                new_entry(f"cn={cn},ou=bindings,{m.dn}", ("top", "ciamExternalHost"), {
                    "cn": (cn,), "ciamFqdn": (host,), **({"ciamPort": (str(port),)} if port else {}),
                    "ciamBindingRole": (Input("role", "the role of the system it reaches", (), (hint,),
                                              ROLE_PATTERN),)})),
               (f"Import the product again ({importer}): {what} then names the role in place of the host.",
                "Bind the role in every other environment with the host it reaches there (the plan's binding fix "
                "offers it once the role is recorded)."),
               ("A system that is the same from every environment gets the same host in each: the fix only names it, "
                "so a move can't miss it.",))

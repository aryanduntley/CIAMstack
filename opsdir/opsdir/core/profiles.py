"""Product profiles: a product's files as a deployment kit consumes them, in the product's own instance tree (a ForgeOps
config profile, a Ping server profile) rather than opsdir's render layout. A product adapter declares which of its
rendered files (and its captured files under files/) belong to its product's instance and where (ProductProfile); the
render hands every product's tree to the kit adapters (Adapter.render_profiles), which place it in their kit's layout.

A profile carries no secret: where a product's render writes a secret reference (${secret:<ref-uri>}), the kit writes
its product's own runtime substitution of a token named by the secret's role (slot_token: &{opsdir.pf.grants.password}
for IDM, PingGateway and Amster; slot_env for an environment variable a Ping server profile substitutes), and delivers
the role's Kubernetes Secret key into that variable. UNBOUND:<role> and ${withheld} stay as they are (the planner
names them). Pure."""
import re
from collections import namedtuple

from .directory import one, values

# A product's profile: its name (the kit asks for it by this) and ((rendered path prefix, instance path prefix), ...):
# a rendered file whose path starts with the first is the product's file at the second plus the rest of its path.
ProductProfile = namedtuple("ProductProfile", ("product", "paths"))
_SECRET = re.compile(r"\$\{secret:([^}]+)\}")
# what every slot's environment variable starts with (slot_env): a kit delivers the Secret keys of that name
SLOT_PREFIX = "OPSDIR_"


def profile_tree(profile, files):
    """{instance path: text} of a product's files among the rendered ones (the first prefix matching wins)."""
    return {instance + path[len(rendered):]: text for path, text in sorted(files.items())
            for rendered, instance in (next(((r, i) for r, i in profile.paths if path.startswith(r)), (None, None)),)
            if rendered is not None}


def slot_token(role):
    """The configuration token a role's secret fills: opsdir.<role, its dashes as dots> (PingIDM, PingGateway and
    Amster read &{token} from the environment variable slot_env names)."""
    return "opsdir." + re.sub(r"[^a-z0-9]+", ".", role.lower()).strip(".")


def slot_env(role):
    """The environment variable holding a role's secret at run time: the token upper-cased, dots as underscores
    (OPSDIR_PF_GRANTS_PASSWORD), as the products map environment variables to tokens."""
    return slot_token(role).upper().replace(".", "_")


def secret_role(m, uri):
    """The role of environment m's binding whose reference a ${secret:<uri>} names, or None."""
    return next((one(b, "ciamBindingRole") for b in m.bindings if uri in values(b, "ciamRefUri")), None)


def slotted(m, text, expression):
    """(text with each ${secret:<uri>} replaced by expression(role) of the role binding it, the roles used in order,
    the references no binding of environment m names (left as they are))."""
    found = [(match.group(1), secret_role(m, match.group(1))) for match in _SECRET.finditer(text)]
    roles = {uri: role for uri, role in found if role}
    return (_SECRET.sub(lambda match: expression(roles[match.group(1)]) if match.group(1) in roles
                        else match.group(0), text),
            tuple(dict.fromkeys(role for _, role in found if role)),
            tuple(dict.fromkeys(uri for uri, role in found if not role)))

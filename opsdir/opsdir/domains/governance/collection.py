"""Collection sources: where `opsdir collect` reads an environment for an importer that needs more than the operator's
own cloud login (ciamCollectionSource, a binding: the operator's opt-in). A source names its importer, and either the
object or URL it reads (ciamSourceRef: a Terraform state object, an admin endpoint) or the servers of a role on a port
(ciamTargetRole, ciamPort: https on each server's host name); the role of the binding holding its credential's
reference (ciamCredentialRole, with the account it signs in as: ciamLoginName, and how it is sent: ciamCredentialScheme)
and of the certificate its endpoint is trusted by (ciamCaRole). The references are resolved when collecting and
never stored. Pure."""
from typing import NamedTuple

from ...core.directory import one, rdn_value, values
from ...core.environment import of_class, role_named, servers_with_role
from ..pki.credentials import role_uses

SOURCE = "ciamCollectionSource"
# A collection source resolved against its environment: the binding's name, the importer, the locations it reads (the
# source ref, or https://<host>:<port> per server of its role), the credential reference and login name, the trust
# anchor's reference (each None when the source names none or the environment binds no such role), problems, and how
# the credential is sent (ciamCredentialScheme: basic, the default, bearer, token or api-key).
Source = NamedTuple("Source", [("name", str), ("importer", str), ("locations", tuple), ("credential", object),
                               ("login", object), ("ca", object), ("problems", tuple), ("scheme", str)])


def _ref(m, s, attr):
    b = role_named(m, s, attr)
    return one(b, "ciamRefUri") if b is not None else None


def _locations(m, s):
    ref = one(s, "ciamSourceRef")
    if ref:
        return (ref,)
    ports = values(s, "ciamPort")
    return tuple(f"https://{one(x, 'ciamHostname')}:{port}" for x in servers_with_role(m, one(s, "ciamTargetRole"))
                 for port in ports[:1] if one(x, "ciamHostname"))


def resolve_source(m, s):
    """The Source collection source binding s of environment m resolves to."""
    cred_role, ca_role = one(s, "ciamCredentialRole"), one(s, "ciamCaRole")
    credential, ca, where = _ref(m, s, "ciamCredentialRole"), _ref(m, s, "ciamCaRole"), _locations(m, s)
    problems = (*(("no location: ciamSourceRef, or ciamTargetRole and ciamPort naming servers with host names",)
                  if not where else ()),
                *((f"role `{cred_role}` (its credential) isn't bound in {m.label}",) if cred_role and not credential
                  else ()),
                *((f"role `{ca_role}` (its trust anchor) isn't bound in {m.label}",) if ca_role and not ca else ()))
    return Source(rdn_value(s), one(s, "ciamImporter"), where, credential, one(s, "ciamLoginName"), ca,
                  tuple(f"collection source `{rdn_value(s)}`: {p}" for p in problems),
                  one(s, "ciamCredentialScheme") or "basic")


def declared_adapters(m):
    """The adapters (by name) environment m's collection sources name: collecting opts in to them, whether or not
    they apply to the environment otherwise (a declaration-only adapter such as the generic LDAP one)."""
    return tuple(dict.fromkeys((one(s, "ciamImporter") or "").split("/", 1)[0] for s in of_class(m, SOURCE)
                               if one(s, "ciamImporter")))


def collection_sources(m, importer):
    """The Sources environment m declares for an importer ('adapter/importer')."""
    return tuple(resolve_source(m, s) for s in of_class(m, SOURCE) if one(s, "ciamImporter") == importer)


def readable_sources(m, importer, schemes=None):
    """Environment m's collection sources for an importer that can be read: each has a location and no problems
    and, when schemes are given, sends its credential in one of them (the ones the system is read with)."""
    return tuple(s for s in collection_sources(m, importer)
                 if s.locations and not s.problems and (schemes is None or s.scheme in schemes))


def readable_source(m, importer, schemes=None):
    """Environment m's first collection source for an importer that can be read (readable_sources); None when none
    can."""
    return next(iter(readable_sources(m, importer, schemes)), None)


def source_problems(m, importer):
    """Why environment m's collection sources for an importer can't be read (an unbound credential or trust anchor,
    no location), every source's."""
    return tuple(p for s in collection_sources(m, importer) for p in s.problems)


def scheme_problems(m, importer, schemes, takes):
    """Why an importer's collection sources can't be read: their own problems, and a credential scheme the system
    isn't read with (takes: what it is read with, in words)."""
    return tuple(p for s in collection_sources(m, importer) for p in (
        *s.problems, *((f"collection source `{s.name}`: credential scheme `{s.scheme}`: {takes}",)
                       if s.scheme not in schemes else ())))


def collection_roles(m):
    """(RoleUse, ...) of environment m's collection sources' credential roles (ciamCredentialRole)."""
    return role_uses(of_class(m, "ciamCollectionSource"), "ciamCredentialRole", "collection source")

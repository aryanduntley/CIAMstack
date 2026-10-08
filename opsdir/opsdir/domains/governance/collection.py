"""Collection sources: where `opsdir collect` reads an environment for an importer that needs more than the operator's
own cloud login (ciamCollectionSource, a binding: the operator's opt-in). A source names its importer, and either the
object or URL it reads (ciamSourceRef: a Terraform state object, an admin endpoint) or the servers of a role on a port
(ciamTargetRole, ciamPort: https on each server's host name); the role of the binding holding its credential's
reference (ciamCredentialRole, with the account it signs in as: ciamLoginName) and of the certificate its endpoint is
trusted by (ciamCaRole). The references are resolved when collecting and never stored. Pure."""
from typing import NamedTuple

from ...core.directory import one, rdn_value, values
from ...core.environment import of_class, one_role, servers_with_role

SOURCE = "ciamCollectionSource"
# A collection source resolved against its environment: the binding's name, the importer, the locations it reads (the
# source ref, or https://<host>:<port> per server of its role), the credential reference and login name, the trust
# anchor's reference (each None when the source names none or the environment binds no such role) and problems.
Source = NamedTuple("Source", [("name", str), ("importer", str), ("locations", tuple), ("credential", object),
                               ("login", object), ("ca", object), ("problems", tuple)])


def _ref(m, role):
    b = one_role(m, role) if role else None
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
    credential, ca, where = _ref(m, cred_role), _ref(m, ca_role), _locations(m, s)
    problems = (*(("no location: ciamSourceRef, or ciamTargetRole and ciamPort naming servers with host names",)
                  if not where else ()),
                *((f"role `{cred_role}` (its credential) isn't bound in {m.label}",) if cred_role and not credential
                  else ()),
                *((f"role `{ca_role}` (its trust anchor) isn't bound in {m.label}",) if ca_role and not ca else ()))
    return Source(rdn_value(s), one(s, "ciamImporter"), where, credential, one(s, "ciamLoginName"), ca,
                  tuple(f"collection source `{rdn_value(s)}`: {p}" for p in problems))


def declared_adapters(m):
    """The adapters (by name) environment m's collection sources name: collecting opts in to them, whether or not
    they apply to the environment otherwise (a declaration-only adapter such as the generic LDAP one)."""
    return tuple(dict.fromkeys((one(s, "ciamImporter") or "").split("/", 1)[0] for s in of_class(m, SOURCE)
                               if one(s, "ciamImporter")))


def collection_sources(m, importer):
    """The Sources environment m declares for an importer ('adapter/importer')."""
    return tuple(resolve_source(m, s) for s in of_class(m, SOURCE) if one(s, "ciamImporter") == importer)

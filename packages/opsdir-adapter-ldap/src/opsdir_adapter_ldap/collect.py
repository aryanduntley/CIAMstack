"""The data profile's collector (`opsdir collect`, core.contract Collector): what ldap/data-profile reads, from the
directory over LDAP, values-free. Pure: the core runs the search.

Where to read is the environment's collection source for ldap/data-profile (ciamCollectionSource: ciamSourceRef
ldaps://<host>:<port>/<base DN>, preferably a replica; the bind DN in ciamLoginName, the role of the binding referencing
its password in ciamCredentialRole: a read-only account with read, search and compare on the user branch). The search
is OpenLDAP's ldapsearch over LDAPS (simple bind, the password only on its standard input: -y reads /dev/stdin, the
exact bytes), paged (pr=1000), all user and operational attributes, unwrapped; its output streams straight through the
profiler the front end gives (options profile: `opsdir data-profile` for the environment, dated when collecting), so
the user data is never held whole, written or kept: the export is the profile's counts only. The CA certificate the
server is checked against is the operator's PEM file, given when collecting (--ldap-ca PATH, LDAPTLS_CACERT)."""
from urllib.parse import unquote, urlparse

from opsdir.core.contract import Collector, Command
from opsdir.core.directory import rdn_value
from opsdir.domains.governance.collection import collection_sources

IMPORTER = "ldap/data-profile"


def _parts(location):
    parsed = urlparse(location)
    return parsed.hostname, parsed.port or 636, unquote(parsed.path.lstrip("/"))


def profile_steps(d, m, done, options):
    """The paged search of the first collection source's user branch, profiled as it streams."""
    profile = options.get("profile")
    s = next((x for x in collection_sources(m, IMPORTER) if x.locations and x.credential and x.login
              and not x.problems), None)
    if s is None or profile is None:
        return ()
    host, port, base = _parts(s.locations[0])
    if not host or not base:
        return ()
    ca = options.get("ldap_ca")
    return ((f"data-profile-{rdn_value(m.env)}.json",
             Command(("ldapsearch", "-H", f"ldaps://{host}:{port}", "-x", "-D", s.login, "-y", "/dev/stdin",
                      "-b", base, "-E", "pr=1000/noprompt", "-o", "ldif-wrap=no", "(objectClass=*)", "*", "+"),
                     (s.credential,), lambda r: r[s.credential], env=(("LDAPTLS_CACERT", ca),) if ca else (),
                     digest=profile)),)


def problems(d, m, options):
    """Why the directory can't be profiled: a source's problems, no bind DN, credential or base DN."""
    return tuple(p for s in collection_sources(m, IMPORTER) for p in (
        *s.problems,
        *((f"collection source `{s.name}`: no bind DN (ciamLoginName)",) if not s.login else ()),
        *((f"collection source `{s.name}`: no credential (ciamCredentialRole)",) if not s.credential and not s.problems
          else ()),
        *((f"collection source `{s.name}`: ciamSourceRef must be ldaps://<host>:<port>/<base DN>",)
          if s.locations and not (_parts(s.locations[0])[0] and _parts(s.locations[0])[2]) else ())))


COLLECTORS = (Collector("data-profile", "environment", profile_steps, problems=problems),)

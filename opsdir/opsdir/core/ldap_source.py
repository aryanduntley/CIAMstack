"""What collectors reading a directory over LDAPS with OpenLDAP's ldapsearch share (core.contract Collector): the
collection source's location, ldaps://<host>:<port>/<base DN> (ciamSourceRef, port 636 by default), with its bind DN
(ciamLoginName) and the role of the binding referencing its password (ciamCredentialRole); the search, a simple bind
whose password reaches ldapsearch only on its standard input (-y /dev/stdin reads the exact bytes); and the run-time
option naming the CA certificate the server is checked against (--ldap-ca PATH, given to ldapsearch as
LDAPTLS_CACERT; never stored). Declared here once for every adapter collecting this way
(connectors.registry.collect_options refuses two different declarations of one flag). Pure: sources are the
collection sources domains.governance.collection resolves."""
from urllib.parse import unquote, urlparse

from .contract import CollectOption, Command

LDAPS_PORT = 636
# The collect option ldapsearch_command reads (ldap_ca).
LDAP_CA = CollectOption("--ldap-ca", "PATH", "CA certificate (PEM) the LDAP server is checked against", 50)


def ldaps_parts(location):
    """(host, port, base DN) of an ldaps://<host>:<port>/<base DN> location: port 636 when it names none, the base DN
    percent-decoded; host None and base '' when the URL lacks them."""
    parsed = urlparse(location)
    return parsed.hostname, parsed.port or LDAPS_PORT, unquote(parsed.path.lstrip("/"))


def _named(s):
    host, _, base = ldaps_parts(s.locations[0])
    return bool(host and base)


def ldaps_source(sources):
    """The first collection source ldapsearch can read: a location naming a host and base DN, a bind DN and a
    credential, and no problems; None when there is none."""
    return next((s for s in sources if s.locations and s.credential and s.login and not s.problems and _named(s)),
                None)


def ldaps_source_problems(sources):
    """Why the sources can't be read over LDAPS: each one's problems, no bind DN, no credential, or a location
    that isn't ldaps://<host>:<port>/<base DN>."""
    return tuple(p for s in sources for p in (
        *s.problems,
        *((f"collection source `{s.name}`: no bind DN (ciamLoginName)",) if not s.login else ()),
        *((f"collection source `{s.name}`: no credential (ciamCredentialRole)",) if not s.credential and not s.problems
          else ()),
        *((f"collection source `{s.name}`: ciamSourceRef must be ldaps://<host>:<port>/<base DN>",)
          if s.locations and not _named(s) else ())))


def ldapsearch_command(source, base, args, options, digest=None):
    """The Command searching source's server from base with ldapsearch's further args (scope, controls, filter,
    attributes), a simple bind as its bind DN with the password on standard input, the operator's CA certificate
    (options ldap_ca) when given; digest as Command's."""
    host, port, _ = ldaps_parts(source.locations[0])
    ca = options.get("ldap_ca")
    return Command(("ldapsearch", "-H", f"ldaps://{host}:{port}", "-x", "-D", source.login, "-y", "/dev/stdin",
                    "-b", base, *args),
                   (source.credential,), lambda r: r[source.credential], env=(("LDAPTLS_CACERT", ca),) if ca else (),
                   digest=digest)

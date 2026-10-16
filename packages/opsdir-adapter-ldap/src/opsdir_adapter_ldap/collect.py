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
from opsdir.core.contract import Collector
from opsdir.core.directory import rdn_value
from opsdir.core.ldap_source import LDAP_CA, ldaps_parts, ldaps_source, ldaps_source_problems, ldapsearch_command
from opsdir.domains.governance.collection import collection_sources

IMPORTER = "ldap/data-profile"


def profile_steps(d, m, done, options):
    """The paged search of the first collection source's user branch, profiled as it streams."""
    profile = options.get("profile")
    s = ldaps_source(collection_sources(m, IMPORTER))
    if s is None or profile is None:
        return ()
    return ((f"data-profile-{rdn_value(m.env)}.json",
             ldapsearch_command(s, ldaps_parts(s.locations[0])[2],
                                ("-E", "pr=1000/noprompt", "-o", "ldif-wrap=no", "(objectClass=*)", "*", "+"), options,
                                digest=profile)),)


def problems(d, m, options):
    """Why the directory can't be profiled: a source's problems, no bind DN, credential or base DN."""
    return ldaps_source_problems(collection_sources(m, IMPORTER))


# ldapsearch_command reads core.ldap_source's LDAP_CA option (ldap_ca).
COLLECTORS = (Collector("data-profile", "environment", profile_steps, problems=problems, options=(LDAP_CA,)),)

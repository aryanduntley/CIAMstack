"""PingFederate collector (`opsdir collect`, core.contract Collector): the Admin API bulk export pingfederate/bulk
reads, read-only. Pure: the core makes the request.

Where to read is the environment's collection source for pingfederate/bulk (ciamCollectionSource: the admin node's
URL https://<host>:9999, or the servers of its role on a port; the first location only, the admin node), with the
credential its ciamCredentialRole binding references (resolved when collecting, never stored) sent as HTTP Basic for
its ciamLoginName, or, when its ciamCredentialScheme is bearer, as Authorization: Bearer (an OAuth access token or a
signed JWT minted outside opsdir, for an Admin API whose pf.admin.api.authentication accepts OAuth2 or, from 12.2,
JWT), and the CA certificate its ciamCaRole binding references as the trust anchor: GET
/pf-admin-api/v1/bulk/export with X-XSRF-Header: PingFederate. The bulk export needs all four administrative roles,
whichever way the caller signs in. The export holds sensitive values encrypted (the
importer withholds them); only resource types the Admin API supports are in it."""
from opsdir.core.contract import Collector, Request
from opsdir.domains.governance.collection import collection_sources

IMPORTER = "pingfederate/bulk"
XSRF = (("X-XSRF-Header", "PingFederate"),)
SCHEMES = ("basic", "bearer")       # how the Admin API takes the credential (native/LDAP/RADIUS; OAuth2/JWT)


def _credential(s):
    return (s.scheme, s.credential, s.login) if s.credential else None


def bulk_steps(d, m, done, options):
    """The bulk export request of each collection source (its first location)."""
    return tuple((f"bulk-export-{s.name}.json",
                  Request(f"{s.locations[0].rstrip('/')}/pf-admin-api/v1/bulk/export", XSRF, _credential(s), s.ca))
                 for s in collection_sources(m, IMPORTER) if s.locations and not s.problems and s.scheme in SCHEMES)


def source_problems(d, m, options):
    """Why the collection sources can't be read (an unbound credential or trust anchor, no location, a credential
    scheme the Admin API doesn't take)."""
    return tuple(p for s in collection_sources(m, IMPORTER) for p in (*s.problems, *_scheme_problem(s)))


def _scheme_problem(s):
    return (f"collection source `{s.name}`: credential scheme `{s.scheme}`: PingFederate's Admin API takes "
            f"{' or '.join(SCHEMES)}",) if s.scheme not in SCHEMES else ()


COLLECTORS = (Collector("bulk", "environment", bulk_steps, problems=source_problems),)

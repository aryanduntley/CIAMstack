"""PingFederate collector (`opsdir collect`, core.contract Collector): the Admin API bulk export pingfederate/bulk
reads, read-only. Pure: the core makes the request.

Where to read is the environment's collection source for pingfederate/bulk (ciamCollectionSource: the admin node's
URL https://<host>:9999, or the servers of its role on a port; the first location only, the admin node), with the
credential its ciamCredentialRole binding references (resolved when collecting, never stored) sent as HTTP Basic for
its ciamLoginName, and the CA certificate its ciamCaRole binding references as the trust anchor: GET
/pf-admin-api/v1/bulk/export with X-XSRF-Header: PingFederate. The export holds sensitive values encrypted (the
importer withholds them); only resource types the Admin API supports are in it."""
from opsdir.core.contract import Collector, Request
from opsdir.domains.governance.collection import collection_sources

IMPORTER = "pingfederate/bulk"
XSRF = (("X-XSRF-Header", "PingFederate"),)


def bulk_steps(d, m, done, options):
    """The bulk export request of each collection source (its first location)."""
    return tuple((f"bulk-export-{s.name}.json",
                  Request(f"{s.locations[0].rstrip('/')}/pf-admin-api/v1/bulk/export", XSRF,
                          ("basic", s.credential, s.login) if s.credential else None, s.ca))
                 for s in collection_sources(m, IMPORTER) if s.locations and not s.problems)


def source_problems(d, m, options):
    """Why the collection sources can't be read (an unbound credential or trust anchor, no location)."""
    return tuple(p for s in collection_sources(m, IMPORTER) for p in s.problems)


COLLECTORS = (Collector("bulk", "environment", bulk_steps, problems=source_problems),)

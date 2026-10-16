"""The revocation collector (`opsdir collect x509/revocation`, core.contract Collector, estate scope): one observing
GET (core Request with observe) per endpoint the observation plans (plan.py), whatever each answers (a CRL, an OCSP
response, an error status, nothing) kept as an observation in the export; an unreachable endpoint is what it records,
never a failed collection. Read-only and anonymous: CRLs and OCSP responders are public; no credential is resolved;
https endpoints are trusted by the system's store. Run it from where the relying parties sit (their network decides
what they reach). Pure: the core makes the requests."""
from opsdir.core.contract import Collector, Request

from .plan import plan


def revocation_steps(d, m, done, options):
    """((export path, observing Request), ...) of every endpoint the observation plans to fetch."""
    return tuple((p.path, Request(p.url, observe=True)) for p in plan(d) if p.url is not None)


COLLECTORS = (Collector("revocation", "estate", revocation_steps),)

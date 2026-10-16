"""The revocation importer (x509/revocation): what each recorded CA's endpoints answered, as the collector's export
holds it (<CA name>/<endpoint name>.json, observations), checked against the CA certificates the record holds
(verify.py) and recorded under ou=revocation-observations (core domains.pki.revocation), which it replaces whole:
per CA an observation (made when its first endpoint was observed; complete when every endpoint the observation
plans was in the export), per endpoint its answer.

An answer is unreachable (the collector got none: why), an HTTP error (its status), unreadable (no body, or one that
isn't a CRL or an OCSP response), or answered: a CRL's update times, numbers and signature check, an OCSP response's
status, the certificate's status and serial, update times and signature check. An endpoint the observation doesn't
fetch (plan.py: not http(s), its URL still holding the CA's variables, nothing to ask an OCSP responder about) is
recorded as not observed, with why. Pure: reading the export and the record, never the network."""
from opsdir.core.contract import Importer, Imported
from opsdir.core.directory import gtime, one, ou_entry, rdn_value
from opsdir.core.observation import read_observation
from opsdir.domains.pki.naming import OBSERVATIONS
from opsdir.domains.pki.revocation import (HTTP_ERROR, NOT_OBSERVED, UNREACHABLE, UNREADABLE,
                                           endpoint_observation_entry, observation_entry, observations_group)

from .plan import plan, signing_certificates
from .verify import crl_facts, ocsp_facts

NOT_EXPORTED = "not in the export"


def answer_facts(kind, observation, cas, serial=None):
    """The facts of one observed endpoint's answer (an Observation), checked against cas ((record entry,
    x509.Certificate), ...): unreachable, http-error or unreadable with why, else the CRL's or OCSP response's facts;
    an OCSP responder's always say which serial it was asked about."""
    asked = {"ciamSerialNumber": serial} if kind == "ocsp" else {}
    if observation.error is not None or observation.status is None:
        return {**asked, "ciamEndpointAnswer": UNREACHABLE,
                "ciamInventoryProblem": (observation.error or "no answer",)}
    if not 200 <= observation.status < 300:
        return {**asked, "ciamEndpointAnswer": HTTP_ERROR, "ciamInventoryProblem": (f"HTTP {observation.status}",)}
    if not observation.body:
        return {**asked, "ciamEndpointAnswer": UNREADABLE, "ciamInventoryProblem": ("an empty answer",)}
    facts = ocsp_facts(observation.body, cas, serial) if kind == "ocsp" else crl_facts(observation.body, cas)
    return {**asked, **facts}


def _endpoint(d, p, files, cas):
    """(at or None, facts, missing from the export) of one Planned endpoint."""
    kind = one(p.endpoint, "ciamRevocationKind")
    if p.url is None:
        return None, {"ciamEndpointAnswer": NOT_OBSERVED, "ciamInventoryProblem": (p.why_not,)}, False
    if p.path not in files:
        return None, {"ciamEndpointAnswer": NOT_OBSERVED, "ciamInventoryProblem": (NOT_EXPORTED,),
                      **({"ciamSerialNumber": p.serial} if kind == "ocsp" else {})}, True
    observation, problem = read_observation(files[p.path])
    if observation is None:
        return None, {"ciamEndpointAnswer": UNREADABLE, "ciamInventoryProblem": (f"{p.path}: {problem}",)}, False
    return gtime(observation.at), answer_facts(kind, observation, cas, p.serial), False


def _authority(d, authority, planned, files, fallback):
    """(entries, notices) of one CA's observation."""
    cas = signing_certificates(d, authority)
    read = tuple((p, *_endpoint(d, p, files, cas)) for p in planned)
    seen = sorted(at for _, at, _, _ in read if at is not None)
    at = seen[0] if seen else fallback
    name = rdn_value(authority)
    if at is None:
        return (), (f"{name}: nothing observed and no --at: its observation isn't recorded",)
    missing = tuple(rdn_value(p.endpoint) for p, _, _, gone in read if gone)
    head = observation_entry(d, name, at, "incomplete" if missing else "complete",
                             (f"not in the export: {', '.join(missing)}",) if missing else ())
    return (head, *(endpoint_observation_entry(d, name, rdn_value(p.endpoint), one(p.endpoint, "ciamRevocationKind"),
                                               one(p.endpoint, "ciamEndpointUrl"), when or at, facts)
                    for p, when, facts, _ in read)), ()


def read_revocation(files, d, patterns, at=None):
    """Imported: ou=revocation-observations made what the export says each recorded CA's endpoints answered (every
    CA with a CRL, delta CRL or OCSP endpoint observed or not); files the observation didn't plan are left out with a
    notice."""
    planned = plan(d)
    fallback = gtime(at) if at is not None else None
    cas = tuple(dict.fromkeys(p.authority.norm for p in planned))
    by_ca = {n: tuple(p for p in planned if p.authority.norm == n) for n in cas}
    done = tuple(_authority(d, ps[0].authority, ps, files, fallback) for ps in by_ca.values())
    expected = {p.path for p in planned}
    observed = sum(1 for p in planned if p.path in files)
    return Imported(containers=(ou_entry(OBSERVATIONS),),
                    groups=(observations_group(d, tuple(e for entries, _ in done for e in entries)),),
                    notices=(f"revocation: {observed} of {len(planned)} endpoint(s) of {len(by_ca)} CA(s) observed",
                             *(n for _, notices in done for n in notices),
                             *(f"{p}: no recorded CA endpoint of that name: left out" for p in sorted(files)
                               if p not in expected)))


REVOCATION_IMPORTER = Importer("revocation", "What each recorded CA's CRL, delta CRL and OCSP endpoints answered "
                                             "(<CA name>/<endpoint>.json, as `opsdir collect` writes them), checked "
                                             "against the CA certificates the record holds", read_revocation)

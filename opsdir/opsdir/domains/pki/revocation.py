"""Revocation endpoints observed: what each certification authority's CRL distribution points, delta CRLs and OCSP
responders answered when last observed, judged for the CA's owners. Pure functions of a snapshot; the network fetch is
an operator-run collection and the signature checks are its importer's (an adapter's), never done here.

An observation (ciamRevocationObservation under ou=revocation-observations, cn: the CA's name) is when the CA's
endpoints were last observed and whether every one was; each endpoint's answer is its child
(ciamEndpointObservation, cn: the endpoint's, with the URL observed): whether it answered (ciamEndpointAnswer), the
thisUpdate and nextUpdate of what it served, a CRL's numbers (ciamCrlNumber, a delta CRL's ciamBaseCrlNumber),
whether the CA the record holds signed it (ciamSignatureCheck, through ciamSignedBy) and what an OCSP responder said
of the certificate it was asked about (ciamOcspStatus, ciamSerialNumber). Observations are never written onto the
endpoints themselves (ou=certificate-authorities): a CA's importer owns those.

An endpoint is observable when its URL is http(s) and its variables were all filled; an OCSP responder is asked
about one certificate the CA issued (probe_serial: a record certificate's, else the newest one its inventory holds
unrevoked). The planner judges each observed CA's endpoints (check_revocation_endpoints): one that couldn't be
reached, answered an error or something unreadable, served what the CA's certificate doesn't verify (or the record
holds none to check with), served what had expired or was within the margin of its nextUpdate when observed
(revocation-freshness-margin-hours: by then the CA should have published the next), a CRL without nextUpdate, a
delta CRL building on a newer CRL than the distribution points serve, an OCSP answer the CA's inventory contradicts
or a responder not knowing the certificate, and an endpoint the last observation missed: each an action for the
CA's owners."""
import datetime as dt
import urllib.parse

from ...core.directory import (children, date_of, follow_all, get, gtime_at, make_entry, merged_attrs, one, ou_entry,
                               rdn_value, values)
from ...core.findings import findings, owner_label
from ...core.settings import setting_value
from .chain import ca_certificates
from .issued import (AREA, TEMPLATE_KEPT, authorities, authority_of, cert_inventories, common_name, endpoints,
                     find_issued, is_revoked, issued_of, serial_key)
from .naming import CERTIFICATES, OBSERVATIONS, observation_dn
from .settings import REVOCATION_MARGIN_HOURS

OBSERVATION_CLASS, ENDPOINT_OBSERVATION_CLASS = "ciamRevocationObservation", "ciamEndpointObservation"
OBSERVATION_ATTRS = ("cn", "ciamInventoryAt", "ciamInventoryState", "ciamInventoryProblem")
# what an importer records of an endpoint's answer (None: not known)
FACTS = ("ciamEndpointAnswer", "ciamThisUpdate", "ciamNextUpdate", "ciamCrlNumber", "ciamBaseCrlNumber",
         "ciamSignatureCheck", "ciamSignedBy", "ciamOcspStatus", "ciamSerialNumber", "ciamInventoryProblem")
ENDPOINT_OBSERVATION_ATTRS = ("cn", "ciamRevocationKind", "ciamEndpointUrl", "ciamInventoryAt", *FACTS)
OBSERVED_KINDS = ("crl", "delta-crl", "ocsp")   # the endpoint kinds observed (CA issuers aren't)
ANSWERED, HTTP_ERROR, UNREACHABLE, UNREADABLE, NOT_OBSERVED = (
    "answered", "http-error", "unreachable", "unreadable", "not-observed")
VALID, INVALID, OTHER_ISSUER, UNAUTHORIZED, NO_CA_CERTIFICATE, UNSUPPORTED = (
    "valid", "invalid", "other-issuer", "unauthorized-responder", "no-ca-certificate", "unsupported")
GOOD, REVOKED, UNKNOWN = "good", "revoked", "unknown"
SAFE_PATH = "/%:@!$&'()*+,;=~"                  # what a URL's path keeps as it is (escapes already made stay)


# ------------------------------------------------------------------ what an importer writes
def _observed(d, dn, oc, owned, names):
    return make_entry(dn, ("top", "ciamObject", oc), merged_attrs(get(d, dn), owned, names))


def observation_entry(d, authority, at, state, problems=()):
    """The observation of the revocation endpoints of the CA named authority: made at `at` (GeneralizedTime),
    complete or incomplete (an endpoint not observed), with why."""
    owned = {"cn": (authority,), "ciamInventoryAt": (at,), "ciamInventoryState": (state,),
             "ciamInventoryProblem": tuple(dict.fromkeys(problems))}
    return _observed(d, observation_dn(authority), OBSERVATION_CLASS, owned, OBSERVATION_ATTRS)


def endpoint_observation_entry(d, authority, endpoint, kind, url, at, facts):
    """What the endpoint named endpoint (crl-1) of the CA named authority answered when observed at `at`
    (GeneralizedTime) at url: facts {attribute of FACTS: value, or a tuple of values for ciamInventoryProblem; None:
    not known}."""
    told = {k: (tuple(dict.fromkeys(v)) if isinstance(v, tuple) else (v,)) for k, v in facts.items() if k in FACTS}
    owned = {"cn": (endpoint,), "ciamRevocationKind": (kind,), "ciamEndpointUrl": (url,), "ciamInventoryAt": (at,),
             **told}
    return _observed(d, f"cn={endpoint},{observation_dn(authority)}", ENDPOINT_OBSERVATION_CLASS, owned,
                     ENDPOINT_OBSERVATION_ATTRS)


def observations_group(d, entries):
    """An Imported group: ou=revocation-observations made exactly these entries (an observation per CA, its
    endpoints' answers as children, parents first; the container kept)."""
    return OBSERVATIONS, (get(d, OBSERVATIONS) or ou_entry(OBSERVATIONS),
                          *sorted(entries, key=lambda e: (e.norm.count(","), e.norm)))


# ------------------------------------------------------------------ what to observe
def observable_url(endpoint):
    """(the URL to GET, None) of a revocation endpoint, its path percent-encoded where the CA wrote spaces; (None,
    why) when it can't be observed: its URL still holds the CA's variables, or isn't http(s)."""
    url = one(endpoint, "ciamEndpointUrl") or ""
    if (one(endpoint, "description") or "").startswith(TEMPLATE_KEPT):
        return None, "its URL still holds the CA's variables"
    parts = urllib.parse.urlsplit(url)
    if parts.scheme.lower() not in ("http", "https") or not parts.netloc:
        return None, f"not an http(s) URL ({parts.scheme or 'no scheme'})"
    return urllib.parse.urlunsplit(parts._replace(path=urllib.parse.quote(parts.path, safe=SAFE_PATH))), None


def authority_certificates(d, authority):
    """The CA's own certificates the record holds: its ciamCaCertificate, else the CA certificates whose subject's
    common name is its name (an AD CS CA's certificate is named after the CA)."""
    own = tuple(c for c in follow_all(d, authority, "ciamCaCertificate") if c is not None)
    return own or tuple(c for c in ca_certificates(d)
                        if (common_name(one(c, "ciamSubject")) or "").lower() == rdn_value(authority).lower())


def probe_serial(d, authority):
    """(serial, which certificate it is) an OCSP responder of the CA is asked about: a record certificate the CA
    issued (its serial, else the one its inventory found for it), else the newest certificate the CA's inventory holds
    unrevoked; (None, why) when there is none."""
    cas = authorities(d)
    inventory = cert_inventories(d).get(rdn_value(authority).lower())
    rows = issued_of(d, inventory) if inventory is not None else ()
    for cert in children(d, CERTIFICATES, "ciamCertificate"):
        found = find_issued(cert, rows, rows) if rows else None
        issuer = authority_of(d, cert, cas) if found is None else authority
        serial = one(cert, "ciamSerialNumber") or (one(found, "ciamSerialNumber") if found is not None else None)
        if issuer is not None and issuer.norm == authority.norm and serial:
            return serial, f"record certificate `{rdn_value(cert)}`"
    unrevoked = tuple(r for r in rows if not is_revoked(r) and one(r, "ciamSerialNumber"))
    if unrevoked:
        newest = max(unrevoked, key=lambda r: one(r, "ciamNotBefore") or "")
        return one(newest, "ciamSerialNumber"), f"request {rdn_value(newest)} of the CA's inventory"
    return None, "no certificate it issued is recorded or inventoried: nothing to ask the responder about"


# ------------------------------------------------------------------ reading the record
def observations(d):
    """{CA name, lowercase: the observation of its revocation endpoints} of every observation the record holds."""
    return {rdn_value(e).lower(): e for e in children(d, OBSERVATIONS, OBSERVATION_CLASS)}


def endpoint_observations(d, observation):
    """{endpoint name, lowercase: what it answered} of one CA's observation."""
    return {rdn_value(e).lower(): e for e in children(d, observation.dn, ENDPOINT_OBSERVATION_CLASS)}


def observation_for(d, endpoint, seen):
    """What an endpoint answered when its CA's endpoints were last observed (seen: endpoint_observations), or None:
    not observed, or observed at another URL (it changed since)."""
    found = seen.get(rdn_value(endpoint).lower())
    return found if found is not None and one(found, "ciamEndpointUrl") == one(endpoint, "ciamEndpointUrl") else None


# ------------------------------------------------------------------ judging
def _at(e, attr):
    v = one(e, attr)
    return gtime_at(v) if v else None


def _when(t):
    return t.strftime("%Y-%m-%d %H:%MZ")


def _answer_problems(obs):
    answer, detail = one(obs, "ciamEndpointAnswer"), "; ".join(values(obs, "ciamInventoryProblem"))
    said = f" ({detail})" if detail else ""
    return {HTTP_ERROR: (("http-error", f"it answered an error{said}"),),
            UNREACHABLE: (("unreachable", f"it couldn't be reached{said}"),),
            UNREADABLE: (("unreadable", f"what it served isn't a CRL or an OCSP response{said}"),)}.get(answer, ())


def _signature_problems(d, obs):
    check = one(obs, "ciamSignatureCheck")
    return {INVALID: (("bad signature", "its signature doesn't verify with the key of the CA certificate the record "
                                        "holds: it isn't the CA's, or the record's certificate is wrong"),),
            OTHER_ISSUER: (("other issuer", "it was issued by another CA than the one the record holds for it"),),
            UNAUTHORIZED: (("unauthorized responder", "it was signed by a responder certificate the CA didn't "
                                                      "authorize (issued by it for OCSP signing)"),),
            NO_CA_CERTIFICATE: (("no CA certificate", "the record holds none of the CA's certificates to check its "
                                                      "signature with: record it (ciamCaCertificate)"),)}.get(check, ())


def _freshness_problems(obs, margin):
    at, nxt = _at(obs, "ciamInventoryAt"), _at(obs, "ciamNextUpdate")
    kind = one(obs, "ciamRevocationKind")
    if one(obs, "ciamEndpointAnswer") != ANSWERED or one(obs, "ciamThisUpdate") is None:
        return ()
    if nxt is None:
        return ((("no nextUpdate", "the CRL gives no nextUpdate (RFC 5280 requires one; Windows reads such a CRL as "
                                   "final, never expiring)"),) if kind != "ocsp" else ())
    if at > nxt:
        return (("expired", f"what it served had expired when observed (nextUpdate {_when(nxt)})"),)
    if nxt - at < margin:
        return (("stale", f"what it served was stale when observed: its nextUpdate ({_when(nxt)}) was less than "
                          f"{int(margin.total_seconds() // 3600)} hours away, by when the CA should have published "
                          "the next"),)
    return ()


def _delta_problems(obs, published):
    base = one(obs, "ciamBaseCrlNumber")
    if one(obs, "ciamRevocationKind") != "delta-crl" or base is None or not published or int(base) <= max(published):
        return ()
    return (("delta ahead", f"it builds on CRL number {base}, but the CA's CRL distribution points serve number "
                            f"{max(published)}: relying parties can't combine them"),)


def _ocsp_problems(obs, rows):
    status, serial = one(obs, "ciamOcspStatus"), one(obs, "ciamSerialNumber")
    if one(obs, "ciamRevocationKind") != "ocsp" or status is None:
        return ()
    if status not in (GOOD, REVOKED, UNKNOWN):
        return (("refused", f"the responder refused the request for serial {serial} ({status})"),)
    if status == UNKNOWN:
        return (("unknown", f"the responder doesn't know serial {serial}, a certificate the CA issued"),)
    row = next((r for r in rows if serial and serial_key(one(r, "ciamSerialNumber")) == serial_key(serial)), None)
    at, effective = _at(obs, "ciamInventoryAt"), _at(row, "ciamRevokedAt") if row is not None else None
    if status == GOOD and row is not None and is_revoked(row) and (effective is None or effective <= at):
        return (("contradicts inventory", f"the responder says serial {serial} is good, but the CA's inventory has "
                                          f"it revoked ({one(row, 'ciamRevocationReason')})"),)
    if status == REVOKED and row is not None and not is_revoked(row):
        return (("contradicts inventory", f"the responder says serial {serial} is revoked, but the CA's inventory "
                                          "holds it as issued"),)
    return ()


def endpoint_problems(d, obs, margin, published=(), rows=()):
    """((short label, text), ...) of what is wrong with what an endpoint answered when observed: margin the
    freshness margin (timedelta), published the CRL numbers the CA's distribution points served, rows its inventory's
    certificates."""
    return (*_answer_problems(obs), *_signature_problems(d, obs), *_freshness_problems(obs, margin),
            *_delta_problems(obs, published), *_ocsp_problems(obs, rows))


def _published(seen):
    return tuple(int(n) for o in seen.values() if one(o, "ciamRevocationKind") == "crl"
                 for n in (one(o, "ciamCrlNumber"),) if n is not None and n.isdigit())


def _rows(d, authority):
    inventory = cert_inventories(d).get(rdn_value(authority).lower())
    return issued_of(d, inventory) if inventory is not None else ()


def judged(d, authority, observation, margin):
    """((endpoint, its observation or None, ((label, text), ...)), ...) for each of a CA's observed kinds of
    endpoint: an observable one its last observation missed is a problem."""
    seen = endpoint_observations(d, observation)
    published, rows = _published(seen), _rows(d, authority)
    def problems(e, obs):
        if obs is None:
            return ((("not observed", "it wasn't observed (added or changed since the CA's last observation, "
                                      f"{_when(_at(observation, 'ciamInventoryAt'))}): observe it again"),)
                    if observable_url(e)[0] else ())
        return endpoint_problems(d, obs, margin, published, rows)
    return tuple((e, obs, problems(e, obs)) for e in endpoints(d, authority)
                 if one(e, "ciamRevocationKind") in OBSERVED_KINDS for obs in (observation_for(d, e, seen),))


def _action(d, authority, endpoint, obs, problems):
    when = f", observed {_when(_at(obs, 'ciamInventoryAt'))}" if obs is not None else ""
    return (AREA, f"Revocation endpoint `{rdn_value(endpoint)}` of certification authority `{rdn_value(authority)}` "
                  f"({one(endpoint, 'ciamEndpointUrl')}{when}): {'; '.join(t for _, t in problems)}. Relying parties "
                  "checking revocation there fail or skip the check: fix what it serves.",
            owner_label(d, authority), None)


def check_revocation_endpoints(ctx):
    """The observed CAs' revocation endpoints (nothing when the record holds no observation): each endpoint with a
    problem (endpoint_problems, or missed by its CA's last observation) an action for the CA's owners; endpoints
    answering as they should are counted."""
    seen = observations(ctx.d)
    if not seen:
        return findings()
    margin = dt.timedelta(hours=setting_value(ctx.d, REVOCATION_MARGIN_HOURS))
    done = tuple((a, row) for a in authorities(ctx.d) if rdn_value(a).lower() in seen
                 for row in judged(ctx.d, a, seen[rdn_value(a).lower()], margin))
    fine = sum(1 for _, (_, obs, problems) in done if obs is not None and not problems
               and one(obs, "ciamEndpointAnswer") == ANSWERED and one(obs, "ciamSignatureCheck") == VALID)
    return findings(actions=[_action(ctx.d, a, e, obs, problems) for a, (e, obs, problems) in done if problems],
                    ok=[f"{fine} revocation endpoint(s) answered current and signed by their CA when observed."]
                    if fine else [])


# ------------------------------------------------------------------ the report
REVOCATION_HEADERS = ("authority", "endpoint", "kind", "url", "observed", "answer", "this update", "next update",
                      "crl number", "signature", "ocsp", "state", "detail", "owner")


def _state(obs, problems, as_of):
    labels = [label for label, _ in problems]
    nxt = date_of(obs, "ciamNextUpdate") if obs is not None else None
    outdated = ["outdated"] if nxt is not None and nxt < as_of else []
    if obs is not None and one(obs, "ciamEndpointAnswer") == NOT_OBSERVED:
        return "; ".join(["not observed", *labels])
    return ", ".join([*labels, *outdated]) or ("ok" if obs is not None else "")


def revocation_rows(d, dn, as_of):
    """One row per observed kind of revocation endpoint of every CA: its URL, when it was observed and what it
    answered (this and next update, CRL number or the base a delta builds on, signature check, an OCSP responder's
    status for the serial it was asked about), what is wrong (or ok; outdated: its nextUpdate is before as_of, observe
    it again), the observation's detail (why not observed, the HTTP status, the responder certificate) and the CA's
    owners; dn unused (the report covers the estate)."""
    margin = dt.timedelta(hours=setting_value(d, REVOCATION_MARGIN_HOURS))
    seen = observations(d)
    def row(a, e, obs, problems):
        said = (lambda x: one(obs, x, "")) if obs is not None else (lambda x: "")      # noqa: E731
        number = said("ciamCrlNumber") or (f"base {said('ciamBaseCrlNumber')}" if said("ciamBaseCrlNumber") else "")
        ocsp = f"{said('ciamOcspStatus')} {said('ciamSerialNumber')}".strip() if said("ciamOcspStatus") else ""
        return (rdn_value(a), rdn_value(e), one(e, "ciamRevocationKind"), one(e, "ciamEndpointUrl"),
                said("ciamInventoryAt"), said("ciamEndpointAnswer"), said("ciamThisUpdate"), said("ciamNextUpdate"),
                number, said("ciamSignatureCheck"), ocsp, _state(obs, problems, as_of),
                "; ".join(values(obs, "ciamInventoryProblem")) if obs is not None else "", owner_label(d, a))
    return [row(a, e, obs, problems) for a in authorities(d)
            for e, obs, problems in (judged(d, a, seen[rdn_value(a).lower()], margin) if rdn_value(a).lower() in seen
                                     else tuple((e, None, ()) for e in endpoints(d, a)
                                                if one(e, "ciamRevocationKind") in OBSERVED_KINDS))]

"""Revocation endpoints observed (domains/pki/revocation): which endpoints can be observed, which certificate an OCSP
responder is asked about, what the planner makes of each answer (unreachable, error, unreadable, wrongly signed, no
CA certificate, expired, stale within the margin, no nextUpdate, a delta ahead of its base, OCSP answers the CA's
inventory contradicts, endpoints the last observation missed) and the revocation-endpoints report."""
import datetime as dt

from opsdir.core.contract import Imported, PlanContext
from opsdir.core.directory import gtime, ou_entry
from opsdir.core.environment import env_model
from opsdir.core.interchange.ldif import parse
from opsdir.domains.pki.domain import DOMAIN
from opsdir.domains.pki.inventory import inventory_group
from opsdir.domains.pki.issued import (AUTHORITIES, authority_entry, authorities, cert_inventory_entry, endpoint_entry,
                                       issued_entry)
from opsdir.domains.pki.naming import ISSUED, OBSERVATIONS
from opsdir.domains.pki.revocation import (REVOCATION_HEADERS, check_revocation_endpoints, endpoint_observation_entry,
                                           endpoint_problems, observable_url, observation_entry, observations_group,
                                           probe_serial, revocation_rows)
import mini_estate
from support import after_import

AS_OF = dt.date(2026, 10, 1)
CA = "Example Issuing CA"
OWNERS = "ou=owners,dc=ciam-ops"
SEEN = dt.datetime(2026, 9, 30, 12, 0, tzinfo=dt.timezone.utc)
URLS = {"crl": "http://pki.example.test/CertEnroll/Example Issuing CA.crl",
        "delta-crl": "http://pki.example.test/CertEnroll/Example Issuing CA+.crl",
        "ocsp": "http://ocsp.example.test/ocsp"}


def _t(at):
    return gtime(at)


def _base(*records):
    head = (f"dn: {OWNERS}\nchangetype: add\nobjectClass: top\nobjectClass: organizationalUnit\nou: owners\n",
            f"dn: cn=pki-team,{OWNERS}\nchangetype: add\nobjectClass: top\nobjectClass: ciamParty\ncn: pki-team\n"
            "ciamOwnerKind: team\n",
            "dn: ou=certificates,dc=ciam-ops\nchangetype: add\nobjectClass: top\nobjectClass: organizationalUnit\n"
            "ou: certificates\n",
            "dn: cn=issuing-ca,ou=certificates,dc=ciam-ops\nchangetype: add\nobjectClass: top\n"
            "objectClass: ciamCertificate\ncn: issuing-ca\nciamFingerprint: AA:BB\nciamNotAfter: 20300101000000Z\n"
            f"ciamCertPurpose: ca\nciamSubject: CN={CA}\nciamIssuer: CN=Example Root CA\n")
    return mini_estate.directory(tuple(parse("\n".join((*head, *records)))))


def _cert(cn, fp, serial=None):
    return (f"dn: cn={cn},ou=certificates,dc=ciam-ops\nchangetype: add\nobjectClass: top\n"
            f"objectClass: ciamCertificate\ncn: {cn}\nciamFingerprint: {fp}\nciamNotAfter: 20270630000000Z\n"
            f"ciamCertPurpose: tls-server\nciamSubject: CN={cn}.example.test\nciamIssuer: CN={CA}\n"
            + (f"ciamSerialNumber: {serial}\n" if serial else ""))


def _authority(d, kinds=("crl", "delta-crl", "ocsp"), rows=(), owned=True):
    ca = authority_entry(d, CA, f"PKI1\\{CA}")
    if owned:
        ca = ca._replace(attrs={**ca.attrs, "ciamOwner": (f"cn=pki-team,{OWNERS}",)})
    groups = [inventory_group(ca, tuple(endpoint_entry(d, CA, k, 1, URLS[k]) for k in kinds))]
    if rows:
        groups.append(inventory_group(cert_inventory_entry(d, CA, _t(SEEN), "complete"),
                                      tuple(issued_entry(d, CA, r, facts) for r, facts in rows)))
    return after_import(d, Imported((ou_entry(AUTHORITIES), ou_entry(ISSUED)), tuple(groups), ()))


def _observed(d, answers, url=None):
    """answers: {kind: facts}; each observed at SEEN."""
    entries = (observation_entry(d, CA, _t(SEEN), "complete"),
               *(endpoint_observation_entry(d, CA, f"{k}-1", k, url or URLS[k], _t(SEEN), facts)
                 for k, facts in answers.items()))
    return after_import(d, Imported((ou_entry(OBSERVATIONS),), (observations_group(d, entries),), ()))


def _plan(d):
    return check_revocation_endpoints(PlanContext(d, env_model(d, "alpha/prod"), env_model(d, "beta/prod"), None,
                                                  AS_OF, {}, {}, ()))


def _good(kind, hours=72, **more):
    return {"ciamEndpointAnswer": "answered", "ciamThisUpdate": _t(SEEN - dt.timedelta(days=1)),
            "ciamNextUpdate": _t(SEEN + dt.timedelta(hours=hours)), "ciamSignatureCheck": "valid",
            "ciamSignedBy": "cn=issuing-ca,ou=certificates,dc=ciam-ops",
            **({"ciamCrlNumber": "41"} if kind == "crl" else {}), **more}


def test_only_http_endpoints_with_every_variable_filled_are_observed():
    d = _base()
    e = endpoint_entry(d, CA, "crl", 1, "http://pki.example.test/CertEnroll/Example Issuing CA.crl")
    assert observable_url(e) == ("http://pki.example.test/CertEnroll/Example%20Issuing%20CA.crl", None)
    plus = endpoint_entry(d, CA, "delta-crl", 1, "https://pki.example.test/Example%20CA+.crl")
    assert observable_url(plus) == ("https://pki.example.test/Example%20CA+.crl", None)       # escapes kept
    ldap = endpoint_entry(d, CA, "crl", 2, "ldap:///CN=Example,CN=CDP,CN=Public Key Services")
    assert observable_url(ldap) == (None, "not an http(s) URL (ldap)")
    kept = endpoint_entry(d, CA, "crl", 3, "http://pki.example.test/%3%8%9.crl", template="http://x/%3%8%9.crl")
    assert observable_url(kept) == (None, "its URL still holds the CA's variables")


def test_ocsp_is_asked_about_a_record_certificate_else_the_newest_unrevoked_one():
    rows = (("7", {"ciamSerialNumber": "0a07", "ciamFingerprint": "77:77", "ciamNotBefore": "20260101000000Z"}),
            ("8", {"ciamSerialNumber": "0a08", "ciamFingerprint": "88:88", "ciamNotBefore": "20260301000000Z"}),
            ("9", {"ciamSerialNumber": "0a09", "ciamNotBefore": "20260401000000Z", "ciamRevocationReason": "superseded",
                   "ciamRevokedAt": "20260501000000Z"}))
    d = _authority(_base(_cert("web", "77:77")), rows=rows)
    a = authorities(d)[0]
    assert probe_serial(d, a) == ("0a07", "record certificate `web`")              # found by fingerprint
    d = _authority(_base(_cert("web", "12:34", serial="0b01")), rows=rows)
    assert probe_serial(d, authorities(d)[0]) == ("0b01", "record certificate `web`")     # its own serial
    d = _authority(_base(), rows=rows)
    assert probe_serial(d, authorities(d)[0]) == ("0a08", "request 8 of the CA's inventory")   # 9 is revoked
    d = _authority(_base())
    assert probe_serial(d, authorities(d)[0])[0] is None


def test_silent_without_observations_and_current_signed_answers_are_counted():
    d = _authority(_base())
    assert _plan(d).actions == () and _plan(d).ok == ()
    d = _observed(d, {"crl": _good("crl"), "delta-crl": _good("delta-crl", ciamBaseCrlNumber="41"),
                      "ocsp": _good("ocsp", ciamOcspStatus="good", ciamSerialNumber="0a07")})
    assert _plan(d).actions == ()
    assert _plan(d).ok == ("3 revocation endpoint(s) answered current and signed by their CA when observed.",)


def test_each_problem_is_an_action_for_the_cas_owners():
    rows = (("7", {"ciamSerialNumber": "0a07", "ciamRevocationReason": "keyCompromise",
                   "ciamRevokedAt": "20260901000000Z"}),)
    d = _authority(_base(), rows=rows)
    d = _observed(d, {"crl": {"ciamEndpointAnswer": "answered", "ciamThisUpdate": _t(SEEN),
                              "ciamNextUpdate": _t(SEEN + dt.timedelta(hours=5)), "ciamCrlNumber": "41",
                              "ciamSignatureCheck": "invalid"},
                      "delta-crl": _good("delta-crl", ciamBaseCrlNumber="45"),
                      "ocsp": _good("ocsp", ciamOcspStatus="good", ciamSerialNumber="0A07")})
    actions = {a[1].split("`")[1]: a for a in _plan(d).actions}
    assert set(actions) == {"crl-1", "delta-crl-1", "ocsp-1"}
    assert all(a[0] == "Certificate" and a[2] == "pki-team" for a in actions.values())
    crl = actions["crl-1"][1]
    assert "doesn't verify with the key of the CA certificate" in crl and "was stale when observed" in crl
    assert "less than 12 hours away" in crl and "(http://pki.example.test/CertEnroll/Example Issuing CA.crl" in crl
    assert "builds on CRL number 45, but the CA's CRL distribution points serve number 41" in actions["delta-crl-1"][1]
    assert "says serial 0A07 is good, but the CA's inventory has it revoked (keyCompromise)" in actions["ocsp-1"][1]


def test_answers_freshness_and_ocsp_statuses_are_judged_one_by_one():
    d = _base()
    margin = dt.timedelta(hours=12)
    def labels(kind, facts, rows=()):
        obs = endpoint_observation_entry(d, CA, f"{kind}-1", kind, URLS[kind], _t(SEEN), facts)
        return [label for label, _ in endpoint_problems(d, obs, margin, (41,), rows)]
    assert labels("crl", {"ciamEndpointAnswer": "unreachable", "ciamInventoryProblem": ("URLError: timed out",)}) \
        == ["unreachable"]
    assert labels("crl", {"ciamEndpointAnswer": "http-error", "ciamInventoryProblem": ("HTTP 404 Not Found",)}) \
        == ["http-error"]
    assert labels("crl", {"ciamEndpointAnswer": "unreadable"}) == ["unreadable"]
    assert labels("crl", {"ciamEndpointAnswer": "not-observed"}) == []
    assert labels("crl", _good("crl", hours=-1)) == ["expired"]
    assert labels("crl", _good("crl", ciamNextUpdate=None)) == ["no nextUpdate"]
    assert labels("ocsp", _good("ocsp", ciamNextUpdate=None, ciamOcspStatus="good")) == []    # RFC 6960 allows it
    assert labels("crl", _good("crl", ciamSignatureCheck="no-ca-certificate")) == ["no CA certificate"]
    assert labels("crl", _good("crl", ciamSignatureCheck="other-issuer")) == ["other issuer"]
    assert labels("crl", _good("crl", ciamSignatureCheck="unsupported")) == []
    assert labels("ocsp", _good("ocsp", ciamSignatureCheck="unauthorized-responder", ciamOcspStatus="good")) \
        == ["unauthorized responder"]
    assert labels("ocsp", _good("ocsp", ciamOcspStatus="unknown", ciamSerialNumber="0a07")) == ["unknown"]
    assert labels("ocsp", {"ciamEndpointAnswer": "answered", "ciamOcspStatus": "unauthorized"}) == ["refused"]
    issued = issued_entry(d, CA, "7", {"ciamSerialNumber": "0a07"})
    assert labels("ocsp", _good("ocsp", ciamOcspStatus="revoked", ciamSerialNumber="a07"), (issued,)) \
        == ["contradicts inventory"]
    assert labels("delta-crl", _good("delta-crl", ciamBaseCrlNumber="41")) == []


def test_an_endpoint_the_last_observation_missed_is_an_action():
    d = _authority(_base())
    d = _observed(d, {"crl": _good("crl")})                       # the delta and OCSP weren't observed
    missed = sorted(a[1].split("`")[1] for a in _plan(d).actions)
    assert missed == ["delta-crl-1", "ocsp-1"]
    assert "wasn't observed (added or changed since the CA's last observation, 2026-09-30 12:00Z)" in \
        _plan(d).actions[0][1]
    d = _observed(_authority(_base()), {"crl": _good("crl")}, url="http://old.example.test/ca.crl")
    assert "crl-1" in {a[1].split("`")[1] for a in _plan(d).actions}       # observed at another URL: changed since


def test_unowned_cas_get_no_owner_and_the_report_lists_every_endpoint():
    d = _authority(_base(), owned=False)
    d = _observed(d, {"crl": _good("crl", hours=-30), "delta-crl": {"ciamEndpointAnswer": "not-observed",
                                                                     "ciamInventoryProblem": ("why not",)}})
    assert {a[2] for a in _plan(d).actions} == {"**NO OWNER**"}
    rows = {r[1]: dict(zip(REVOCATION_HEADERS, r)) for r in revocation_rows(d, None, AS_OF)}
    assert set(rows) == {"crl-1", "delta-crl-1", "ocsp-1"}
    assert rows["crl-1"]["state"] == "expired, outdated" and rows["crl-1"]["crl number"] == "41"
    assert rows["delta-crl-1"]["state"] == "not observed" and rows["delta-crl-1"]["answer"] == "not-observed"
    assert rows["delta-crl-1"]["detail"] == "why not" and rows["crl-1"]["detail"] == ""
    assert rows["ocsp-1"]["state"] == "not observed" and rows["ocsp-1"]["observed"] == ""
    assert "revocation-endpoints" in DOMAIN.reports and DOMAIN.reports["revocation-endpoints"].dated
    assert check_revocation_endpoints in DOMAIN.checks


def test_the_schema_holds_the_observations():
    names = {c.name: c for c in DOMAIN.schema.classes}
    assert (names["ciamRevocationObservation"].number, names["ciamEndpointObservation"].number) == (180, 181)
    attrs = {a.name: a.number for a in DOMAIN.schema.attributes}
    assert [attrs[n] for n in ("ciamEndpointAnswer", "ciamOcspStatus")] == [818, 825]
    assert {a for a, n in attrs.items() if 818 <= n <= 825} <= set(names["ciamEndpointObservation"].may)

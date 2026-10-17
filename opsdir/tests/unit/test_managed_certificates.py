"""Certificate managers' inventories reconciled with the record's certificates (domains/pki/managed): how a record
certificate is found (fingerprint, thumbprint of its PEM, serial with issuer, subject and validity), each state kept
apart (managed, renewed, revoked, disabled, in error, not managed: never missing), unrecorded certificates judged only
for the host names the record holds, the planner's findings (issued.py's not repeated) and the report."""
import base64
import datetime as dt
import hashlib

from opsdir.core.contract import Imported, PlanContext
from opsdir.core.directory import get, gtime, one, ou_entry
from opsdir.core.environment import env_model
from opsdir.core.interchange.ldif import parse
from opsdir.domains.pki.domain import DOMAIN
from opsdir.domains.pki.inventory import inventory_group
from opsdir.domains.pki.issued import REVOKED, cert_inventory_entry, issued_entry, authority_entry
from opsdir.domains.pki.managed import (AREA, DISABLED, IN_ERROR, MANAGED_HEADERS, MANAGED_STATE, NOT_MANAGED,
                                        RENEWED, UNRECORDED, check_managed_certificates, covers, managed_entry,
                                        managed_inventory_entry, managed_rows, reconcile_managed, record_names)
from opsdir.domains.pki.naming import AUTHORITIES, ISSUED, MANAGED, managed_inventory_dn
from opsdir.domains.pki.pem import pem_fingerprint, pem_thumbprint
import mini_estate
from support import after_import

AS_OF = dt.date(2026, 10, 1)
AT = gtime(dt.datetime(2026, 9, 30, 12, 0))
SOURCE = "venafi-prod"
FP = "AB:" * 31 + "CD"
OWNERS = "ou=owners,dc=ciam-ops"
DER = b"0\x03\x02\x01\x01"                     # any bytes do for the digest
PEM = ("-----BEGIN CERTIFICATE-----\n" + base64.b64encode(DER).decode() + "\n-----END CERTIFICATE-----\n")


def _t(day):
    return f"{day.replace('-', '')}000000Z"


def _cert(cn, fp=FP, issuer="CN=Public CA R11", extra=""):
    return (f"dn: cn={cn},ou=certificates,dc=ciam-ops\nchangetype: add\nobjectClass: top\n"
            f"objectClass: ciamCertificate\ncn: {cn}\nciamFingerprint: {fp}\nciamNotAfter: {_t('2027-06-30')}\n"
            f"ciamNotBefore: {_t('2026-06-30')}\nciamCertPurpose: tls-server\nciamSubject: CN={cn}.example.test\n"
            f"ciamSubjectAltName: {cn}.example.test\nciamIssuer: {issuer}\nciamOwner: cn=platform,{OWNERS}\n{extra}")


def _base(*records):
    head = (f"dn: {OWNERS}\nchangetype: add\nobjectClass: top\nobjectClass: organizationalUnit\nou: owners\n",
            *(f"dn: cn={t},{OWNERS}\nchangetype: add\nobjectClass: top\nobjectClass: ciamParty\ncn: {t}\n"
              "ciamOwnerKind: team\n" for t in ("platform", "web-team")),
            "dn: ou=certificates,dc=ciam-ops\nchangetype: add\nobjectClass: top\nobjectClass: organizationalUnit\n"
            "ou: certificates\n")
    return mini_estate.directory(tuple(parse("\n".join((*head, *records)))))


def _row(key, subject, fp=None, sha1=None, serial=None, issuer="CN=Public CA R11", nb="2026-06-30", na="2027-06-30",
         names=None, management="provisioned", problems=(), revoked=None, state=None, installed=()):
    return key, {"ciamFingerprint": fp, "ciamThumbprint": sha1, "ciamSerialNumber": serial, "ciamSubject": subject,
                 "ciamIssuer": issuer, "ciamNotBefore": _t(nb), "ciamNotAfter": _t(na),
                 "ciamCertificateName": names if names is not None else (subject.split("=", 1)[1],),
                 "ciamManagerPath": f"\\VED\\Policy\\Example\\{key}", "ciamManagement": management,
                 "ciamManagerContact": ("local:{1234}",), "ciamInstalledAt": installed, "ciamManagerProblem": problems,
                 "ciamRevokedAt": _t(revoked) if revoked else None,
                 "ciamRevocationReason": "unspecified" if revoked else None, "ciamObjectState": state}


def _imported(d, rows=(), state="complete", problems=()):
    inv = inventory_group(managed_inventory_entry(d, SOURCE, AT, state, problems, ("\\VED\\Policy\\Example",),
                                                  "https://tpp.example.test/vedsdk"),
                          tuple(managed_entry(d, SOURCE, k, f) for k, f in rows))
    return after_import(d, Imported((ou_entry(MANAGED),), (inv,), ()))


def _states(d):
    return {r.cert.attrs["cn"][0]: r.state for r in reconcile_managed(d, AS_OF)}


def _plan(d):
    ctx = PlanContext(d, env_model(d, "alpha/prod"), env_model(d, "beta/prod"), None, AS_OF, {}, {}, ())
    return check_managed_certificates(ctx)


def test_the_inventory_is_written_as_given():
    d = _imported(_base(), (_row("g1", "CN=a.example.test", names=("a.example.test", "*.a.example.test")),))
    inv = get(d, managed_inventory_dn(SOURCE))
    assert one(inv, "ciamInventoryPrefix") == "\\VED\\Policy\\Example"
    assert one(inv, "ciamProviderRef") == "https://tpp.example.test/vedsdk"
    row = get(d, f"cn=g1,{managed_inventory_dn(SOURCE)}")
    assert row.attrs["ciamCertificateName"] == ("a.example.test", "*.a.example.test")
    assert "ciamInstalledAt" not in row.attrs and "ciamRevokedAt" not in row.attrs


def test_each_state_is_kept_apart_and_absence_is_never_missing():
    held_pem = f"ciamCertificatePem:: {base64.b64encode(PEM.encode()).decode()}\n"
    d = _base(_cert("by-fp"), _cert("by-sha1", fp="11:22", extra=held_pem),
              _cert("by-serial", fp="33:44", extra="ciamSerialNumber: 0A:1B\n"),
              _cert("by-validity", fp="55:66"), _cert("revoked", fp="77:88"), _cert("renewed", fp="99:00"),
              _cert("disabled", fp="AA:00"), _cert("failing", fp="BB:00"), _cert("elsewhere", fp="CC:00"))
    d = _imported(d, (_row("g1", "CN=by-fp.example.test", fp=FP),
                      _row("g2", "CN=x", sha1=pem_thumbprint(PEM)),
                      _row("g3", "CN=y", serial="0a1b"),
                      _row("g4", "CN=by-validity.example.test"),
                      _row("g5", "CN=z", fp="77:88", revoked="2026-09-01"),
                      _row("g6", "CN=renewed.example.test", nb="2026-09-01", na="2027-09-01"),
                      _row("g7", "CN=w", fp="AA:00", state="disabled"),
                      _row("g8", "CN=v", fp="BB:00", problems=("Access denied by the CA",))))
    assert _states(d) == {"by-fp": MANAGED_STATE, "by-sha1": MANAGED_STATE, "by-serial": MANAGED_STATE,
                          "by-validity": MANAGED_STATE, "revoked": REVOKED, "renewed": RENEWED, "disabled": DISABLED,
                          "failing": IN_ERROR, "elsewhere": NOT_MANAGED}
    # a complete inventory still says nothing of a certificate it doesn't hold
    assert _states(_imported(_base(_cert("only")), state="complete")) == {"only": NOT_MANAGED}


def test_a_serial_matches_only_with_the_same_issuer():
    d = _base(_cert("tls", fp="01:01", extra="ciamSerialNumber: 0A\n"))
    assert _states(_imported(d, (_row("g", "CN=other", serial="0a", issuer="CN=Other CA"),))) == {"tls": NOT_MANAGED}
    # a self-signed certificate's issuer is its subject
    own = _base(_cert("own", fp="02:02", issuer="self-signed", extra="ciamSerialNumber: 0B\n"))
    rows = (_row("g", "CN=own.example.test", serial="0b", issuer="CN=own.example.test"),)
    assert _states(_imported(own, rows)) == {"own": MANAGED_STATE}


def test_hashes_and_names():
    assert pem_thumbprint(PEM) == ":".join(f"{b:02X}" for b in hashlib.sha1(DER).digest())
    assert pem_fingerprint(PEM).replace(":", "") == hashlib.sha256(DER).hexdigest().upper()
    assert covers("*.example.test", "login.example.test") and covers("Login.Example.Test.", "login.example.test")
    assert not covers("*.example.test", "example.test") and not covers("*.example.test", "a.b.example.test")
    assert not covers("", "x.example.test")


def test_nothing_without_an_inventory():
    d = _base(_cert("tls"))
    f = _plan(d)
    assert not f.blockers and not f.actions and not f.ok
    assert reconcile_managed(d, AS_OF) == () and managed_rows(d, None, AS_OF) == []


def test_the_planner_blocks_on_a_revoked_certificate_in_use_and_acts_on_the_rest():
    use = ("dn: cn=sso,ou=identity-services,dc=ciam-ops\nchangetype: modify\nadd: ciamUsesCertificate\n"
           "ciamUsesCertificate: cn={},ou=certificates,dc=ciam-ops\n-\n")
    d = _base(_cert("revoked", fp="77:88"), _cert("renewed", fp="99:00"), _cert("failing", fp="BB:00"),
              _cert("disabled", fp="AA:00"), _cert("idle", fp="DD:00"), _cert("quiet", fp="EE:00"),
              use.format("revoked"), use.format("disabled"))
    d = _imported(d, (_row("g5", "CN=z", fp="77:88", revoked="2026-09-01"),
                      _row("g6", "CN=renewed.example.test", nb="2026-09-01", na="2027-09-01"),
                      _row("g7", "CN=w", fp="AA:00", state="disabled"),
                      _row("g8", "CN=v", fp="BB:00", problems=("renewal failed: CA unreachable",)),
                      _row("g9", "CN=u", fp="DD:00", state="disabled"),
                      _row("g0", "CN=t", fp="EE:00")))
    f = _plan(d)
    assert [(a, o) for a, _, o in f.blockers] == [(AREA, "platform")]
    assert "Certificate `revoked` was revoked, as venafi-prod reports (`\\VED\\Policy\\Example\\g5`: unspecified, " \
           "2026-09-01), but the record still uses it (used by sso)" in f.blockers[0][1]
    texts = sorted(t for _, t, _, _ in f.actions)
    assert len(texts) == 3
    assert texts[0].startswith("Certificate `disabled`'s management is disabled in venafi-prod")
    assert texts[1] == ("Certificate `failing`: venafi-prod reports a problem with it (`\\VED\\Policy\\Example\\g8`): "
                        "renewal failed: CA unreachable. Have it fixed in venafi-prod, or renew it another way before "
                        "it expires (2027-06-30).")
    assert texts[2].startswith("Certificate `renewed` was renewed by venafi-prod: it holds a newer certificate for "
                               "the same subject (`\\VED\\Policy\\Example\\g6`, valid until 2027-09-01)")
    assert {a[3] for a in f.actions} == {dt.date(2027, 6, 30)}
    assert list(f.ok) == ["1 certificate(s) of the record managed by a certificate manager with nothing wrong "
                          "reported."]


def test_what_a_cas_inventory_says_is_not_said_again():
    d = _base(_cert("tls", fp="77:88", issuer="CN=Example CA"))
    d = after_import(d, Imported((ou_entry(AUTHORITIES), ou_entry(ISSUED)), (
        inventory_group(authority_entry(d, "Example CA"), ()),
        inventory_group(cert_inventory_entry(d, "Example CA", AT, "complete"),
                        (issued_entry(d, "Example CA", 1, {"ciamFingerprint": "77:88", "ciamSubject": "CN=tls",
                                                           "ciamRevocationReason": "keyCompromise",
                                                           "ciamRevokedAt": _t("2026-09-01")}),))), ()))
    d = _imported(d, (_row("g5", "CN=tls.example.test", fp="77:88", issuer="CN=Example CA", revoked="2026-09-01"),))
    f = _plan(d)
    assert not f.blockers and not f.actions


def test_unrecorded_certificates_only_for_names_the_record_holds():
    d = _base(_cert("sso"))
    names = record_names(d)
    assert set(names) == {"sso.example.test"}
    d = _imported(d, (_row("g1", "CN=sso.example.test", fp=FP),
                      _row("g2", "CN=stray", names=("*.example.test",), issuer="CN=Other CA", na="2027-01-31"),
                      _row("g3", "CN=elsewhere.test", names=("elsewhere.test",)),
                      _row("g4", "CN=old", names=("sso.example.test",), na="2026-01-01")))
    f = _plan(d)
    assert [(t, o, due) for _, t, o, due in f.actions] == [
        ("venafi-prod holds 1 certificate(s) in service for names the record holds, of which the record has none: "
         "`\\VED\\Policy\\Example\\g2` for sso.example.test (until 2027-01-31). Record the ones in use "
         "(ou=certificates), or have them removed.", "platform", dt.date(2027, 1, 31))]
    rows = managed_rows(d, None, AS_OF)
    assert [(r[0], r[2], r[7]) for r in rows] == [("sso", "\\VED\\Policy\\Example\\g1", MANAGED_STATE),
                                                  ("", "\\VED\\Policy\\Example\\g2", UNRECORDED),
                                                  ("", "\\VED\\Policy\\Example\\g3", UNRECORDED)]
    assert rows[1][8:] == ("platform", "*.example.test; the record's sso.example.test")
    assert rows[2][8:] == ("", "elsewhere.test")
    assert len(rows[0]) == len(MANAGED_HEADERS) and rows[0][3:5] == ("provisioned", "local:{1234}")


def test_an_incomplete_or_refused_inventory_is_an_action():
    d = _base(_cert("tls", fp="01:01"))
    inc = _plan(_imported(d, state="incomplete", problems=("120 of 300 certificates listed",)))
    assert [t for _, t, _, _ in inc.actions] == [
        "Certificate manager inventory `venafi-prod` of 2026-09-30 is incomplete (120 of 300 certificates listed): "
        "renewals and certificates the record lacks may be missing from the comparison. Collect it again completely."]
    den = _plan(_imported(d, state="denied", problems=("HTTP 403: grant View and Read",)))
    assert den.actions[0][1].startswith("Certificate manager inventory `venafi-prod` was refused (HTTP 403: grant "
                                        "View and Read)")
    assert den.actions[0][2] == "**NO OWNER**"


def test_the_report_and_check_are_the_domains():
    assert DOMAIN.reports["managed-certificates"].dated
    assert check_managed_certificates in DOMAIN.checks

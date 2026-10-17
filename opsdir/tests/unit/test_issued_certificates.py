"""Certification authorities' issued-certificate inventories reconciled with the record's certificates
(domains/pki/issued): how a record certificate's CA is found, each state kept apart (present, revoked, revocation
scheduled, superseded, confirmed missing, inventory incomplete, refused, not inventoried), untracked active
certificates judged only for the templates the record cares about, what a CA that isn't active means for what
it issued, the planner's findings and the two reports."""
import datetime as dt

from opsdir.core.contract import Imported, PlanContext
from opsdir.core.directory import get, gtime, one, ou_entry
from opsdir.core.environment import env_model
from opsdir.core.interchange.ldif import parse
from opsdir.domains.pki.domain import DOMAIN
from opsdir.domains.pki.inventory import INACCESSIBLE, INCOMPLETE, MISSING, NOT_INVENTORIED, PRESENT
from opsdir.domains.pki.issued import (AREA, REVOKED, SCHEDULED, SUPERSEDED, UNTRACKED, authority_entry,
                                       authority_rows, ca_templates_groups, cert_inventory_entry,
                                       check_issued_certificates, endpoint_entry, is_ca_scoped, issued_entry,
                                       issued_rows, reconciled, revocation_reason, template_entry, templates_group)
from opsdir.domains.pki.inventory import inventory_group
from opsdir.domains.pki.naming import AUTHORITIES, ISSUED, authority_dn, template_dn
import mini_estate
from support import after_import

AS_OF = dt.date(2026, 10, 1)
AT = gtime(dt.datetime(2026, 9, 30, 12, 0))
CA = "Example Issuing CA"
FP = "AB:" * 31 + "CD"
OWNERS = "ou=owners,dc=ciam-ops"


def _t(day):
    return f"{day.replace('-', '')}000000Z"


def _cert(cn, issuer=f"CN={CA}", fp=FP, extra=""):
    return (f"dn: cn={cn},ou=certificates,dc=ciam-ops\nchangetype: add\nobjectClass: top\n"
            f"objectClass: ciamCertificate\ncn: {cn}\nciamFingerprint: {fp}\nciamNotAfter: {_t('2027-06-30')}\n"
            f"ciamNotBefore: {_t('2026-06-30')}\n"
            f"ciamCertPurpose: tls-server\nciamSubject: CN={cn}.example.test\nciamIssuer: {issuer}\n"
            f"ciamOwner: cn=platform,{OWNERS}\n{extra}")


def _base(*records):
    head = (f"dn: {OWNERS}\nchangetype: add\nobjectClass: top\nobjectClass: organizationalUnit\nou: owners\n",
            *(f"dn: cn={t},{OWNERS}\nchangetype: add\nobjectClass: top\nobjectClass: ciamParty\ncn: {t}\n"
              "ciamOwnerKind: team\n" for t in ("platform", "pki-team")),
            "dn: ou=certificates,dc=ciam-ops\nchangetype: add\nobjectClass: top\nobjectClass: organizationalUnit\n"
            "ou: certificates\n")
    return mini_estate.directory(tuple(parse("\n".join((*head, *records)))))


def _row(request, subject, template="WebServer", fp=None, serial=None, nb="2026-06-30", na="2027-06-30",
         reason=None, revoked=None):
    return request, {"ciamFingerprint": fp, "ciamSerialNumber": serial, "ciamSubject": subject,
                     "ciamNotBefore": _t(nb), "ciamNotAfter": _t(na), "ciamTemplateName": template,
                     "ciamRequester": "CORP\\svc-web", "ciamRevocationReason": reason,
                     "ciamRevokedAt": _t(revoked) if revoked else None}


def _imported(d, rows=(), state="complete", kinds=("crl", "ocsp"), templates=(), facts=None):
    ca = inventory_group(authority_entry(d, CA, f"PKI1\\{CA}", ("WebServer",), facts),
                         tuple(endpoint_entry(d, CA, k, 1, f"http://pki.example.test/{k}") for k in kinds))
    inv = inventory_group(cert_inventory_entry(d, CA, AT, state, ("RPC denied",) if state == "denied" else ()),
                          tuple(issued_entry(d, CA, r, facts) for r, facts in rows))
    groups = (ca, inv, *((templates_group(d, tuple(template_entry(d, n) for n in templates)),) if templates else ()))
    return after_import(d, Imported((ou_entry(AUTHORITIES), ou_entry(ISSUED)), groups, ()))


def _states(d):
    return {r.cert.attrs["cn"][0]: r.state for r in reconciled(d, AS_OF)}


def _plan(d):
    ctx = PlanContext(d, env_model(d, "alpha/prod"), env_model(d, "beta/prod"), None, AS_OF, {}, {}, ())
    return check_issued_certificates(ctx)


def test_each_state_is_kept_apart():
    d = _base(_cert("by-fp"), _cert("by-serial", fp="11:22", extra="ciamSerialNumber: 00:0a:1b\n"),
              _cert("by-validity", fp="33:44"), _cert("revoked", fp="55:66"), _cert("scheduled", fp="77:88"),
              _cert("renewed", fp="99:00"), _cert("missing", fp="12:34"), _cert("public", issuer="CN=Public CA R1",
                                                                                 fp="56:78"))
    d = _imported(d, (_row(1, "CN=other", fp=FP), _row(2, "CN=x", serial="0A1B"),
                      _row(3, "CN=by-validity.example.test"), _row(4, "CN=r", fp="55:66", reason="superseded",
                                                                    revoked="2026-09-01"),
                      _row(5, "CN=s", fp="77:88", reason="keyCompromise", revoked="2026-12-01"),
                      _row(6, "CN=renewed.example.test", fp="99:00"),
                      _row(7, "CN=renewed.example.test", nb="2026-09-01", na="2027-09-01")))
    assert _states(d) == {"by-fp": PRESENT, "by-serial": PRESENT, "by-validity": PRESENT, "revoked": REVOKED,
                          "scheduled": SCHEDULED, "renewed": SUPERSEDED, "missing": MISSING}


def test_an_unconfirmable_certificate_says_why():
    d = _base(_cert("one"))
    assert _states(_imported(d, state="incomplete")) == {"one": INCOMPLETE}
    assert _states(_imported(d, state="denied")) == {"one": INACCESSIBLE}
    other = _imported(_base(_cert("two", issuer="CN=Elsewhere CA", fp="01:02")))
    held = after_import(other, Imported((ou_entry(AUTHORITIES),),
                                        (inventory_group(authority_entry(other, "Elsewhere CA"), ()),), ()))
    assert _states(held) == {"two": NOT_INVENTORIED}


def test_the_ca_is_found_by_issued_by_then_subject():
    root = _cert("issuing-ca", issuer="CN=Root", fp="EE:EE").replace("CN=issuing-ca.example.test",
                                                                    "CN=Renamed Issuing CA, O=Example")
    ca = (f"dn: {AUTHORITIES}\nchangetype: add\nobjectClass: top\nobjectClass: organizationalUnit\n"
          "ou: certificate-authorities\n",
          f"dn: {authority_dn(CA)}\nchangetype: add\nobjectClass: top\nobjectClass: ciamCertAuthority\ncn: {CA}\n"
          "ciamCaCertificate: cn=issuing-ca,ou=certificates,dc=ciam-ops\n")
    d = _imported(_base(root, _cert("leaf", issuer="CN=Renamed Issuing CA,O=Example", fp="0F:0F"),
                        _cert("linked", issuer="CN=Someone", fp="0E:0E",
                              extra="ciamIssuedBy: cn=issuing-ca,ou=certificates,dc=ciam-ops\n"), *ca))
    assert get(d, authority_dn(CA)).attrs["ciamCaCertificate"] == ("cn=issuing-ca,ou=certificates,dc=ciam-ops",)
    # the CA's own certificate isn't one it issued; the other two are its, and confirmed missing
    assert _states(d) == {"leaf": MISSING, "linked": MISSING}


def test_the_planner_blocks_on_a_revoked_certificate_in_use():
    d = _base(_cert("tls", fp="55:66"), "dn: cn=sso,ou=identity-services,dc=ciam-ops\nchangetype: modify\n"
              "add: ciamUsesCertificate\nciamUsesCertificate: cn=tls,ou=certificates,dc=ciam-ops\n-\n")
    f = _plan(_imported(d, (_row(4, "CN=r", fp="55:66", reason=revocation_reason(4), revoked="2026-09-01"),)))
    assert [(a, o) for a, _, o in f.blockers] == [(AREA, "platform")]
    assert "revoked by Example Issuing CA (request 4: superseded, effective 2026-09-01)" in f.blockers[0][1]
    assert "used by sso" in f.blockers[0][1]


def test_untracked_certificates_only_for_templates_the_record_cares_about():
    d = _base(_cert("tls"))
    rows = (_row(1, "CN=tls", fp=FP), _row(2, "CN=hand.example.test", na="2026-10-10"),
            _row(3, "CN=user", template="User"), _row(4, "CN=old", na="2026-01-01"))
    f = _plan(_imported(d, rows, templates=("WebServer", "User")))
    texts = [t for _, t, _, _ in f.actions]
    assert len(texts) == 1 and "issued 1 active certificate(s) from template `WebServer`" in texts[0]
    assert "request 2 CN=hand.example.test (until 2026-10-10)" in texts[0]
    assert f.actions[0][2] == "**NO OWNER**" and f.actions[0][3] == dt.date(2026, 10, 10)
    owned = _imported(d, rows, templates=("WebServer", "User"))
    owned = after_import(owned, Imported((), (templates_group(owned, (
        template_entry(owned, "WebServer"),
        template_entry(owned, "User")._replace(attrs={"cn": ("User",), "ciamRenewalOwner": (f"cn=pki-team,{OWNERS}",)}),
    )),), ()))
    acts = _plan(owned).actions
    assert [(a[2], "template `User`" in a[1]) for a in acts] == [("**NO OWNER**", False), ("pki-team", True)]
    rows_out = issued_rows(owned, None, AS_OF)
    assert [(r[0], r[2], r[7]) for r in rows_out] == [("tls", "1", PRESENT), ("", "2", UNTRACKED),
                                                      ("", "3", UNTRACKED)]
    assert rows_out[2][8] == "pki-team"


def test_an_inventoried_ca_without_revocation_checking_is_an_action():
    f = _plan(_imported(_base(_cert("tls")), (_row(1, "CN=tls", fp=FP),), kinds=("ca-issuers",)))
    assert [t for _, t, _, _ in f.actions] == [
        "Certification authority `Example Issuing CA` publishes no CRL distribution point or OCSP responder in the "
        "certificates it issues: nothing can check their revocation. Publish one, or record why not."]
    assert list(f.ok) == ["1 certificate(s) of the record found current at their CA."]


def test_nothing_without_an_inventory():
    f = _plan(_base(_cert("tls")))
    assert not f.blockers and not f.actions and not f.ok


def test_reports():
    d = _imported(_base(_cert("tls")), (_row(1, "CN=tls", fp=FP),))
    assert authority_rows(d) == [(CA, f"PKI1\\{CA}", "", "", "", "", "WebServer",
                                  "crl http://pki.example.test/crl; ocsp http://pki.example.test/ocsp",
                                  "2026-09-30 complete", "")]
    assert {"certificate-authorities", "issued-certificates"} <= set(DOMAIN.reports)
    assert DOMAIN.reports["issued-certificates"].dated


def test_reason_codes():
    assert [revocation_reason(c) for c in (0, 4, 7, 10, -1, 4294967295)] == [
        "unspecified", "superseded", "7", "aACompromise", "-1", "4294967295"]


def test_a_directorys_templates_keep_each_cas_own_and_a_ca_replaces_only_its_own():
    d = _imported(_base(), templates=("WebServer",))
    own = (template_entry(d, f"{CA}/web", authority=CA), template_entry(d, f"{CA}/client", authority=CA))
    d = after_import(d, Imported((), ca_templates_groups(d, CA, own), ()))
    assert one(get(d, template_dn(f"{CA}/web")), "ciamTemplateAuthority") == authority_dn(CA)
    assert is_ca_scoped(get(d, template_dn(f"{CA}/web"))) and not is_ca_scoped(get(d, template_dn("WebServer")))
    d = after_import(d, Imported((), (templates_group(d, (template_entry(d, "UserAuth"),)),), ()))
    assert get(d, template_dn("WebServer")) is None and get(d, template_dn("UserAuth")) is not None
    assert get(d, template_dn(f"{CA}/web")) is not None and get(d, template_dn(f"{CA}/client")) is not None
    d = after_import(d, Imported((), ca_templates_groups(d, CA, own[:1]), ()))
    assert get(d, template_dn(f"{CA}/client")) is None
    assert get(d, template_dn(f"{CA}/web")) is not None and get(d, template_dn("UserAuth")) is not None
    other = after_import(d, Imported((), ca_templates_groups(d, "Other CA", ()), ()))
    assert get(other, template_dn(f"{CA}/web")) is not None


# ------------------------------------------------------------------ a CA that isn't active
ROOT = "Example Root CA"
ALPHA_SVC, BETA_SVC = (f"cn=svc-sso,ou=bindings,env=prod,cloud={c},ou=environments,dc=ciam-ops" for c in ("alpha",
                                                                                                           "beta"))
DELETED = {"ciamCaType": "subordinate", "ciamCaState": "deleted", "ciamCaRestorableUntil": _t("2026-10-20")}


def _uses(svc, cert="tls"):
    return (f"dn: {svc}\nchangetype: modify\nadd: ciamTlsCertificate\n"
            f"ciamTlsCertificate: cn={cert},ou=certificates,dc=ciam-ops\n-\n")


def _with_root(d, state):
    root = inventory_group(authority_entry(d, ROOT, None, (), {"ciamCaType": "root", "ciamCaState": state}), ())
    return after_import(d, Imported((ou_entry(AUTHORITIES),), (root,), ()))


def test_a_certificate_of_a_deleted_ca_the_target_relies_on_blocks():
    d = _base(_cert("tls"), _uses(BETA_SVC))
    f = _plan(_imported(d, (_row(1, "CN=tls", fp=FP),), facts=DELETED))
    assert [(a, o) for a, _, o in f.blockers] == [(AREA, "platform")]
    text = f.blockers[0][1]
    assert text.startswith(f"Certificate `tls` comes from {CA}, which was deleted (restorable until 2026-10-20): it "
                           "issues nothing and no longer publishes its CRL (http://pki.example.test/crl)")
    assert "beta/prod relies on it (svc-sso)" in text
    assert text.endswith(f"Reissue it from an active CA and record it, or have {CA}'s owner (none recorded: record "
                         "the CA's ciamOwner) restore the CA before 2026-10-20.")
    assert list(f.ok) == ["1 certificate(s) of the record found current at their CA."]


def test_one_only_the_source_uses_is_an_action_due_when_the_ca_can_no_longer_be_restored():
    d = _base(_cert("tls"), _uses(ALPHA_SVC))
    f = _plan(_imported(d, (_row(1, "CN=tls", fp=FP),), facts=DELETED))
    assert not f.blockers
    [(area, text, owner, due)] = f.actions
    assert (area, owner, due) == (AREA, "platform", dt.date(2026, 10, 20))
    assert "; used by svc-sso. Reissue it" in text
    # without a restorable-until, it is due when the certificate expires
    f = _plan(_imported(d, (_row(1, "CN=tls", fp=FP),), facts={"ciamCaState": "deleted"}))
    assert f.actions[0][3] == dt.date(2027, 6, 30) and "until when it can be restored is unrecorded" in f.actions[0][1]


def test_a_ca_above_it_that_isnt_active_is_named():
    d = _imported(_base(_cert("tls")), (_row(1, "CN=tls", fp=FP),),
                  facts={"ciamCaType": "subordinate", "ciamCaState": "active", "ciamParentAuthority": ROOT})
    [(_, text, _, due)] = _plan(_with_root(d, "disabled")).actions
    assert text.startswith(f"Certificate `tls` comes from {CA}, below {ROOT}, which is disabled: it issues nothing; "
                           "nothing recorded uses it.")
    assert text.endswith(f"or have {ROOT}'s owner (none recorded: record the CA's ciamOwner) re-enable the CA.")
    assert due == dt.date(2027, 6, 30)
    assert not _plan(_with_root(d, "active")).actions


def test_silent_for_a_ca_reporting_no_state_and_for_revoked_or_expired_certificates():
    d = _base(_cert("tls"), _cert("gone", fp="55:66"),
              _cert("old", fp="77:88").replace(_t("2027-06-30"), _t("2026-09-01")), _uses(BETA_SVC))
    rows = (_row(1, "CN=tls", fp=FP), _row(2, "CN=gone", fp="55:66", reason="keyCompromise", revoked="2026-09-01"),
            _row(3, "CN=old", fp="77:88", na="2026-09-01"))
    assert not _plan(_imported(d, rows)).blockers
    f = _plan(_imported(d, rows, facts={"ciamCaState": "expired"}))
    assert [t.split(" comes from ")[0] for _, t, _ in f.blockers] == ["Certificate `tls`"]
    assert "has expired: it issues nothing, and what chains to it no longer validates" in f.blockers[0][1]
    assert not any("comes from" in t for _, t, _, _ in f.actions)


def test_untracked_certificates_of_a_ca_that_isnt_active_say_so():
    d = _base(_cert("tls"))
    rows = (_row(1, "CN=tls", fp=FP), _row(2, "CN=hand.example.test", na="2026-12-01"))
    acts = [a for a in _plan(_imported(d, rows, facts=DELETED)).actions if "active certificate(s)" in a[1]]
    [(_, text, owner, due)] = acts
    assert text.endswith(f"They come from {CA}, which was deleted (restorable until 2026-10-20): it issues nothing "
                         "and no longer publishes its CRL (http://pki.example.test/crl), so whatever checks "
                         "revocation refuses what chains to it once its last CRL lapses. Reissue the ones in use from "
                         f"an active CA and record them, or have {CA}'s owner (none recorded: record the CA's "
                         "ciamOwner) restore the CA before 2026-10-20.")
    assert (owner, due) == ("**NO OWNER**", dt.date(2026, 10, 20))


def test_the_authorities_report_says_until_when_a_deleted_ca_is_restorable():
    d = _imported(_base(), facts=DELETED)
    assert authority_rows(d)[0][2] == "subordinate deleted (restorable until 2026-10-20)"

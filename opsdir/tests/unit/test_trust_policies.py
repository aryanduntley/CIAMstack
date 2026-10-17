"""Partner trust (domains/pki/trust): trust bundles as imported, trust policies' anchors reviewed against the bundles
they follow (approve or decline, anchors a bundle dropped), bundle integrity and age, anchor expiry, policy gaps, and
the two reports."""
import datetime as dt

from opsdir.core.contract import Imported, PlanContext
from opsdir.core.directory import get, gtime, one, ou_entry, values
from opsdir.core.interchange.ldif import parse
from opsdir.domains.pki.domain import DOMAIN
from opsdir.domains.pki.naming import TRUST_BUNDLES, trust_bundle_dn
from opsdir.domains.pki.trust import (FAILED, UNANCHORED, VERIFIED, bundle_entry, bundle_group, bundle_rows,
                                      check_trust, member_entry, policy_rows)
import mini_estate
from support import after_import, applied

AS_OF = dt.date(2026, 10, 17)
AT = gtime(dt.datetime(2026, 10, 1, 12, 0))
OWNERS = "ou=owners,dc=ciam-ops"
POLICY = "cn=cac-users,ou=trust-policies,dc=ciam-ops"
FP = {n: ":".join([f"{i:02X}"] * 32) for i, n in enumerate(("Root A", "Root B", "Issuing A1", "Old Root"), 1)}


def _base(policy=""):
    head = (f"dn: {OWNERS}\nchangetype: add\nobjectClass: top\nobjectClass: organizationalUnit\nou: owners\n",
            f"dn: cn=pki-team,{OWNERS}\nchangetype: add\nobjectClass: top\nobjectClass: ciamParty\ncn: pki-team\n"
            "ciamOwnerKind: team\n",
            *(f"dn: ou={o},dc=ciam-ops\nchangetype: add\nobjectClass: top\nobjectClass: organizationalUnit\nou: {o}\n"
              for o in ("certificates", "trust-policies")),
            policy)
    return mini_estate.directory(tuple(parse("\n".join(r for r in head if r))))


def _policy(extra=""):
    return (f"dn: {POLICY}\nchangetype: add\nobjectClass: top\nobjectClass: ciamTrustPolicy\ncn: cac-users\n"
            f"ciamTrustPurpose: client-auth\nciamTrustBundleRef: {trust_bundle_dn('dod')}\n"
            f"ciamOwner: cn=pki-team,{OWNERS}\n{extra}")


def _member(name, issuer=None, not_after="20410614000000Z"):
    return name, {"ciamFingerprint": FP[name], "ciamNotAfter": not_after, "ciamNotBefore": "20200101000000Z",
                  "ciamSubject": f"CN={name},O=Example", "ciamIssuer": f"CN={issuer or name},O=Example",
                  "ciamCaType": "subordinate" if issuer else "root", "ciamSerialNumber": "01",
                  "ciamCertificatePem": "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n",
                  "ciamCertPolicyOid": ("2.16.840.1.101.2.1.11.39",) if issuer else None,
                  "ciamBundleGroup": issuer or name}


def _with_bundle(d, members, state=VERIFIED, at=AT, problems=None):
    b = bundle_entry(d, "dod", at, state, {"ciamTrustBundleRelease": "5.14", "ciamBundleSource": "dod.zip",
                                           "ciamSignerAnchor": FP["Root A"], "ciamInventoryProblem": problems})
    return after_import(d, Imported((ou_entry(TRUST_BUNDLES),),
                                    (bundle_group(b, [member_entry(d, b, n, f) for n, f in members]),), ()))


def _check(d):
    return check_trust(PlanContext(d, None, None, None, AS_OF, {}, {}, ()))


def _approve(d, f, name):
    fix = next(x for x in f.fixes if f"root `{name}`" in x.title)
    return applied(d, next(o for o in fix.options if o.key == "approve").records)


def test_trust_is_wired_into_the_pki_domain():
    assert check_trust in DOMAIN.checks
    assert {"trust-bundles", "trust-policies"} <= set(DOMAIN.reports)


def test_nothing_is_said_without_a_trust_policy():
    d = _with_bundle(_base(), [_member("Root A")], state=FAILED)
    assert _check(d) == check_trust(PlanContext(_base(), None, None, None, AS_OF, {}, {}, ()))
    assert not _check(d).blockers and not _check(d).actions


def test_a_bundle_import_replaces_its_members_and_keeps_what_the_record_adds():
    d = _with_bundle(_base(), [_member("Root A"), _member("Issuing A1", "Root A")])
    assert {one(e, "cn") for e in d.entries.values() if "ciamBundleCertificate" in e.classes} == {"Root A",
                                                                                                    "Issuing A1"}
    d = _with_bundle(d, [_member("Root A")])
    assert get(d, f"cn=Issuing A1,{trust_bundle_dn('dod')}") is None
    assert one(get(d, trust_bundle_dn("dod")), "ciamTrustBundleRelease") == "5.14"


def test_new_roots_are_proposed_for_review_and_approval_records_the_anchor():
    d = _with_bundle(_base(_policy()), [_member("Root A"), _member("Root B"), _member("Issuing A1", "Root A")])
    f = _check(d)
    proposed = [x.title for x in f.fixes]
    assert len(proposed) == 2 and all("root `Root " in t for t in proposed)     # roots only, not the issuing CA
    assert any("has no anchors" in a[1] for a in f.actions)
    d = _approve(d, f, "Root A")
    anchor = get(d, "cn=Root A,ou=certificates,dc=ciam-ops")
    assert one(anchor, "ciamCertPurpose") == "ca" and one(anchor, "ciamFingerprint") == FP["Root A"]
    assert values(anchor, "ciamOwner") == (f"cn=pki-team,{OWNERS}",)
    assert anchor.dn in values(get(d, POLICY), "ciamTrustAnchor")
    assert [x.title for x in _check(d).fixes] == [proposed[1]]


def test_a_declined_root_is_not_proposed_again():
    d = _with_bundle(_base(_policy()), [_member("Root A"), _member("Old Root")])
    fix = next(x for x in _check(d).fixes if "Old Root" in x.title)
    d = applied(d, next(o for o in fix.options if o.key == "decline").records)
    assert FP["Old Root"] in values(get(d, POLICY), "ciamDeclinedAnchor")
    assert all("Old Root" not in x.title for x in _check(d).fixes)


def test_an_anchor_no_followed_bundle_holds_is_flagged_with_its_removal():
    d = _with_bundle(_base(_policy()), [_member("Root A"), _member("Root B")])
    d = _approve(d, _check(d), "Root B")
    d = _with_bundle(d, [_member("Root A")])
    f = _check(d)
    assert any("`Root B`, which none of the bundles" in a[1] for a in f.actions)
    removal = next(x for x in f.fixes if x.key.startswith("trust-anchor-dropped:"))
    assert values(get(applied(d, removal.records), POLICY), "ciamTrustAnchor") == ()


def test_a_failed_bundle_blocks_and_proposes_nothing():
    d = _with_bundle(_base(_policy()), [_member("Root A")], state=FAILED,
                     problems=("dod.der.p7b's SHA-256 differs from the manifest's",))
    f = _check(d)
    assert len(f.blockers) == 1 and "failed its integrity check: dod.der.p7b" in f.blockers[0][1]
    assert not f.fixes


def test_an_unanchored_bundle_asks_for_the_signer_root_then_for_a_new_import():
    d = _with_bundle(_base(_policy()), [_member("Root A")], state=UNANCHORED)
    assert any("confirm that fingerprint" in a[1] for a in _check(d).actions)
    d = _approve(d, _check(d), "Root A")
    assert any("now holds: import the bundle again" in a[1] for a in _check(d).actions)


def test_a_stale_bundle_and_an_expiring_anchor_are_actions():
    d = _with_bundle(_base(_policy()), [_member("Root A", not_after="20291230184641Z")],
                     at=gtime(dt.datetime(2026, 5, 1)))
    d = _approve(d, _check(d), "Root A")
    texts = [a[1] for a in _check(d).actions]
    assert any("last imported 2026-05-01, more than 90 days ago" in t for t in texts)
    expiring = next(a for a in _check(d).actions if a[1].startswith("Anchor `Root A` expires 2029-12-30"))
    assert expiring[3] == dt.date(2029, 12, 30)


def test_policy_gaps_name_what_a_client_auth_policy_leaves_open():
    d = _with_bundle(_base(_policy("ciamRevocationMode: ocsp-then-crl\nciamRevocationFailure: cached\n")),
                     [_member("Root A")])
    texts = [a[1] for a in _check(d).actions]
    assert any("sets no certificate policies, extended key usages or an identity mapping" in t for t in texts)
    assert any("without saying how old" in t for t in texts)
    assert not any("doesn't check revocation" in t for t in texts)
    tight = _policy("ciamAllowedPolicyOid: 2.16.840.1.101.2.1.11.39\nciamRequiredEku: 1.3.6.1.5.5.7.3.2\n"
                    "ciamIdentityMapping: san-upn\nciamRevocationMode: ocsp\nciamRevocationFailure: reject\n")
    d = _with_bundle(_base(tight), [_member("Root A")])
    d = _approve(d, _check(d), "Root A")
    assert not [a for a in _check(d).actions if "Trust policy `cac-users` (client-auth)" in a[1]]


def test_reports_list_bundles_and_policies():
    d = _with_bundle(_base(_policy("ciamRevocationMode: ocsp\nciamRevocationFailure: cached\n"
                                   "ciamRevocationCacheHours: 24\nciamAcceptedByRole: gateway\n")),
                     [_member("Root A"), _member("Issuing A1", "Root A")])
    d = _approve(d, _check(d), "Root A")
    assert bundle_rows(d) == [("dod", "5.14", "2026-10-01", VERIFIED, FP["Root A"], "2", "Root A (2041-06-14)", "")]
    row = policy_rows(d)[0]
    assert row[:4] == ("cac-users", "client-auth", "Root A (2041-06-14)", "dod")
    assert row[7:] == ("ocsp on failure cached (24 h)", "gateway", "pki-team")


# ------------------------------------------------------------------ consumers (milestone 122, task 576)
def test_the_bundle_holds_the_anchors_then_the_subordinates_chaining_to_them():
    from opsdir.domains.pki.trust import bundle_certificates, policy_bundle
    issuing = ("Issuing A1", {**_member("Issuing A1", "Root A")[1], "ciamCertificatePem":
                              "-----BEGIN CERTIFICATE-----\nMIIC\n-----END CERTIFICATE-----\n"})
    d = _with_bundle(_base(_policy()), [_member("Root A"), _member("Root B"), issuing])
    d = _approve(d, _check(d), "Root A")
    policy = get(d, POLICY)
    assert [one(c, "cn") for c in bundle_certificates(d, policy)] == ["Root A", "Issuing A1"]   # not Root B's
    assert policy_bundle(d, policy).count("-----BEGIN CERTIFICATE-----") == 2


def test_each_anchor_has_its_own_chain_for_consumers_taking_chains():
    from opsdir.domains.pki.trust import anchor_chains
    d = _with_bundle(_base(_policy()), [_member("Root A"), _member("Root B"), _member("Issuing A1", "Root A")])
    d = _approve(d, _check(d), "Root A")
    d = _approve(d, _check(d), "Root B")
    chains = [(one(a, "cn"), [one(c, "cn") for c in subs]) for a, subs in anchor_chains(d, get(d, POLICY))]
    assert chains == [("Root A", ["Issuing A1"]), ("Root B", [])]


def test_an_edge_policy_needs_a_service_name_in_front_of_its_roles():
    from network_fixtures import ALPHA, entry, model
    from opsdir.domains.pki.trust import accepting_services
    tree = ("dn: ou=trust-policies,dc=ciam-ops\nobjectClass: top\nobjectClass: organizationalUnit\n"
            "ou: trust-policies\n",
            f"dn: {POLICY}\nobjectClass: top\nobjectClass: ciamObject\nobjectClass: ciamTrustPolicy\ncn: cac-users\n"
            "ciamTrustPurpose: client-auth\nciamTrustEnforcedAt: edge\nciamAcceptedByRole: ds\n"
            "ciamRevocationMode: ocsp\nciamRevocationFailure: reject\n")
    d, alpha, beta = model(tree=tree)
    texts = [a[1] for a in check_trust(PlanContext(d, alpha, beta, None, AS_OF, {}, {}, ())).actions]
    assert any("checked at the edge, but alpha/prod has no service name in front of `ds`" in t for t in texts)
    svc = entry(ALPHA, "ldaps", "ciamServiceName", ciamBindingRole="ldaps", ciamFqdn="ldaps.example.test",
                ciamTargetRole="ds", ciamPort="636")
    d, alpha, beta = model(alpha=(svc,), tree=tree)
    assert [one(s, "cn") for s in accepting_services(alpha, get(d, POLICY))] == ["ldaps"]
    texts = [a[1] for a in check_trust(PlanContext(d, alpha, beta, None, AS_OF, {}, {}, ())).actions]
    assert not any("alpha/prod has no service name" in t for t in texts)

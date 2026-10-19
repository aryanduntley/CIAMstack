"""Cross-certificates (domains/pki/cross, task 129b): recorded as facts of the graph (issuer -> subject, role, policy
mappings, validity), never trust; which CAs a trust policy's anchors reach through them (the cross-certificates
report), the planner's actions for a CA reached only through cross-certificates, for those expired or expiring within
the certificate expiry margin and for one also held as a record certificate; a cross-certificate recognised by name
(certified_root); and what a certificate says of itself written onto its entry (pem.with_pem_facts)."""
import datetime as dt

from opsdir.core.contract import Imported, PlanContext
from opsdir.core.directory import get, one, ou_entry, values
from opsdir.core.interchange.ldif import parse
from opsdir.domains.pki.cross import (CROSS_HEADERS, certified_root, check_cross_certificates, cross_certificates,
                                      cross_entry, cross_name, cross_rows, reachable)
from opsdir.domains.pki.domain import DOMAIN
from opsdir.domains.pki.naming import CERTIFICATES, CROSS_CERTIFICATES, cross_certificate_dn
from opsdir.domains.pki.pem import PEM_BASICS, PEM_FACTS, with_pem_facts
from opsdir.domains.pki.settings import EXPIRY_MARGIN_DAYS
import mini_estate
from support import after_import

AS_OF = dt.date(2026, 10, 19)
OWNERS = "ou=owners,dc=ciam-ops"
POLICY = "cn=eca-users,ou=trust-policies,dc=ciam-ops"
# the synthetic PKIs: our anchor's root, a bridge, and a partner PKI's root the bridge certifies
ROOT, BRIDGE, PARTNER = "CN=Example Root CA,O=Example", "CN=Example Bridge CA,O=Bridge", "CN=Partner Root CA,O=Partner"


def _cert(cn, subject, issuer, purpose="ca", not_after="20400101000000Z", fp="AA"):
    return (f"dn: cn={cn},{CERTIFICATES}\nchangetype: add\nobjectClass: top\nobjectClass: ciamCertificate\ncn: {cn}\n"
            f"ciamFingerprint: {':'.join([fp] * 32)}\nciamNotAfter: {not_after}\nciamCertPurpose: {purpose}\n"
            f"ciamSubject: {subject}\nciamIssuer: {issuer}\n")


def _base(anchors=("example-root",), extra=()):
    head = (f"dn: {OWNERS}\nchangetype: add\nobjectClass: top\nobjectClass: organizationalUnit\nou: owners\n",
            f"dn: cn=pki-team,{OWNERS}\nchangetype: add\nobjectClass: top\nobjectClass: ciamParty\ncn: pki-team\n"
            "ciamOwnerKind: team\n",
            *(f"dn: ou={o},dc=ciam-ops\nchangetype: add\nobjectClass: top\nobjectClass: organizationalUnit\nou: {o}\n"
              for o in ("certificates", "trust-policies")),
            _cert("example-root", ROOT, ROOT, fp="01"), _cert("partner-root", PARTNER, PARTNER, fp="02"),
            _cert("partner-user", "CN=Jane Doe,O=Partner", PARTNER, purpose="client-auth", fp="03"),
            f"dn: {POLICY}\nchangetype: add\nobjectClass: top\nobjectClass: ciamTrustPolicy\ncn: eca-users\n"
            f"ciamTrustPurpose: client-auth\nciamOwner: cn=pki-team,{OWNERS}\n"
            + "".join(f"ciamTrustAnchor: cn={a},{CERTIFICATES}\n" for a in anchors),
            *extra)
    return mini_estate.directory(tuple(parse("\n".join(head))))


# (name, issuer, subject, not after, role, policy mappings)
CROSSES = (("bridge by root", ROOT, BRIDGE, "20290601000000Z", "member-to-bridge", ()),
           ("partner by bridge", BRIDGE, PARTNER, "20281231000000Z", "bridge-to-member",
            ("2.16.840.1.101.3.2.1.3.13=2.16.840.1.101.2.1.11.39",)))


def _with_crosses(d, crosses=CROSSES):
    entries = tuple(cross_entry(d, n, {"ciamIssuer": i, "ciamSubject": s, "ciamNotAfter": end,
                                       "ciamPolicyMapping": maps})
                    for n, i, s, end, _, maps in crosses)
    roles = {cross_certificate_dn(n): r for n, _, _, _, r, _ in crosses}
    entries = tuple(e._replace(attrs={**e.attrs, "ciamCrossRole": (roles[e.dn],)}) for e in entries)
    return after_import(d, Imported((ou_entry(CROSS_CERTIFICATES),), tuple((e.dn, (e,)) for e in entries), ()))


def _check(d, cutover=None, as_of=AS_OF):
    return check_cross_certificates(PlanContext(d, None, None, cutover, as_of, {}, {}, ()))


def test_wired_into_the_pki_domain():
    assert check_cross_certificates in DOMAIN.checks and "cross-certificates" in DOMAIN.reports
    assert DOMAIN.reports["cross-certificates"].headers == CROSS_HEADERS


def test_nothing_is_said_without_a_cross_certificate():
    d = _base()
    assert _check(d) == check_cross_certificates(PlanContext(mini_estate.directory(), None, None, None, AS_OF, {}, {},
                                                             ()))
    assert not _check(d).actions and cross_rows(d) == []


def test_a_cross_certificate_entry_keeps_what_the_record_adds():
    d = _with_crosses(_base())
    x = get(d, cross_certificate_dn("partner by bridge"))
    assert [rdn for rdn in (one(e, "cn") for e in cross_certificates(d))] == ["bridge by root", "partner by bridge"]
    again = cross_entry(d, "partner by bridge", {"ciamIssuer": BRIDGE, "ciamSubject": PARTNER,
                                                 "ciamNotAfter": "20311231000000Z"})
    assert one(again, "ciamCrossRole") == "bridge-to-member" and one(again, "ciamNotAfter") == "20311231000000Z"
    assert values(again, "ciamPolicyMapping") == () and values(x, "ciamPolicyMapping") == CROSSES[1][5]


def test_the_ca_an_anchor_reaches_through_cross_certificates():
    d = _with_crosses(_base())
    anchor = get(d, f"cn=example-root,{CERTIFICATES}")
    reached = reachable(d, anchor)
    assert [(r.ca, [one(x, "cn") for x in r.path]) for r in reached] == [
        (BRIDGE, ["bridge by root"]), (PARTNER, ["bridge by root", "partner by bridge"])]
    assert reachable(d, get(d, f"cn=partner-root,{CERTIFICATES}")) == ()     # cross-certificates run issuer -> subject


def test_the_cross_certificates_report_lists_the_graph():
    d = _with_crosses(_base(), (*CROSSES, ("orphan by nobody", "CN=Elsewhere CA", "CN=Other CA", "20300101000000Z",
                                           "peer", ())))
    rows = cross_rows(d)
    assert all(len(r) == len(CROSS_HEADERS) for r in rows)
    assert rows[0] == ("example-root", BRIDGE, "bridge by root (member-to-bridge)", "1", "2029-06-01", "", "eca-users",
                       "cross-certificate only")
    assert rows[1][:5] == ("example-root", PARTNER,
                           "bridge by root (member-to-bridge) -> partner by bridge (bridge-to-member)", "2",
                           "2028-12-31")
    assert rows[1][5] == CROSSES[1][5][0]
    assert rows[2] == ("", "CN=Other CA", "orphan by nobody (peer)", "1", "2030-01-01", "", "",
                       "not reached from an anchor")
    direct = cross_rows(_with_crosses(_base(anchors=("example-root", "partner-root"))))
    assert [r[7] for r in direct if r[0] == "example-root"] == ["cross-certificate only", "anchor"]


def test_a_ca_reached_only_through_cross_certificates_is_an_action_not_a_blocker():
    f = _check(_with_crosses(_base()))
    reach = [a for a in f.actions if "reachable only through" in a[1]]
    assert not f.blockers and len(reach) == 2
    partner = next(a for a in reach if f"CA `{PARTNER}`" in a[1])
    assert "bridge by root (member-to-bridge) -> partner by bridge (bridge-to-member)" in partner[1]
    assert "policy mappings 2.16.840.1.101.3.2.1.3.13=2.16.840.1.101.2.1.11.39" in partner[1]
    assert "partner-user" in partner[1] and partner[2] == "pki-team"
    approved = _check(_with_crosses(_base(anchors=("example-root", "partner-root"))))
    assert [a for a in approved.actions if f"CA `{PARTNER}`" in a[1] and "reachable only" in a[1]] == []


def test_expired_and_expiring_cross_certificates_are_actions():
    margin = DOMAIN.settings[DOMAIN.settings.index(EXPIRY_MARGIN_DAYS)].default
    soon = AS_OF + dt.timedelta(days=margin - 1)
    d = _with_crosses(_base(), ((CROSSES[0][0], ROOT, BRIDGE, "20260101000000Z", "member-to-bridge", ()),
                                (CROSSES[1][0], BRIDGE, PARTNER, soon.strftime("%Y%m%d000000Z"), "bridge-to-member",
                                 ()),
                                ("later by root", ROOT, "CN=Later CA", "20400101000000Z", "peer", ())))
    expiry = [a for a in _check(d).actions if a[1].startswith("Cross-certificate")]
    assert len(expiry) == 2
    assert "expired 2026-01-01" in expiry[0][1] and "`example-root` (eca-users)" in expiry[0][1]
    assert f"expires {soon} ({margin - 1} days)" in expiry[1][1] and expiry[1][3] == soon
    assert all(a[2] == "pki-team" for a in expiry)
    late = [a for a in _check(d, cutover=dt.date(2040, 1, 1)).actions if a[1].startswith("Cross-certificate")]
    assert len(late) == 3


def test_a_cross_certificate_also_held_as_a_record_certificate_is_an_action():
    d = _with_crosses(_base(extra=(_cert("bridge-cross", BRIDGE, ROOT, fp="09"),)))
    x = get(d, cross_certificate_dn("bridge by root"))
    x = x._replace(attrs={**x.attrs, "ciamFingerprint": (":".join(["09"] * 32),)})
    d = after_import(d, Imported((), ((x.dn, (x,)),), ()))
    held = [a for a in _check(d).actions if "also recorded as certificate `bridge-cross`" in a[1]]
    assert len(held) == 1


def test_a_cross_certificate_is_recognised_by_the_root_it_certifies():
    d = _base()
    assert one(certified_root(d, PARTNER, BRIDGE, True), "cn") == "partner-root"
    assert certified_root(d, PARTNER, BRIDGE, False) is None            # not a CA certificate
    assert certified_root(d, PARTNER, PARTNER, True) is None            # the root itself
    assert certified_root(d, "CN=Issuing CA", ROOT, True) is None        # an ordinary subordinate
    assert cross_name(d, PARTNER, BRIDGE, "AB") == "Partner Root CA by Example Bridge CA"
    d = _with_crosses(d, (("Partner Root CA by Example Bridge CA", BRIDGE, PARTNER, "20300101000000Z", "peer", ()),))
    assert cross_name(d, PARTNER, BRIDGE, "AB") == "Partner Root CA by Example Bridge CA"     # recorded by hand
    x = get(d, cross_certificate_dn("Partner Root CA by Example Bridge CA"))
    d = after_import(d, Imported((), ((x.dn, (x._replace(attrs={**x.attrs, "ciamFingerprint": ("CD",)}),)),), ()))
    assert cross_name(d, PARTNER, BRIDGE, "AB") == "Partner Root CA by Example Bridge CA AB"
    assert cross_name(d, PARTNER, BRIDGE, "CD") == "Partner Root CA by Example Bridge CA"


def test_what_a_certificate_says_of_itself_replaces_its_facts_and_fills_missing_basics():
    c = get(_base(), f"cn=partner-user,{CERTIFICATES}")
    c = c._replace(attrs={**c.attrs, "ciamSanEmail": ("old@partner.test",)})
    facts = {"ciamSanUpn": ("jane.doe@partner.test",), "ciamIsCa": ("FALSE",), "ciamSubject": ("CN=Other",),
             "ciamSerialNumber": ("0a",), "ciamSanEmail": ()}
    e = with_pem_facts(c, facts)
    assert values(e, "ciamSanUpn") == ("jane.doe@partner.test",) and one(e, "ciamIsCa") == "FALSE"
    assert values(e, "ciamSanEmail") == ()                              # the certificate is the source
    assert one(e, "ciamSubject") == "CN=Jane Doe,O=Partner" and one(e, "ciamSerialNumber") == "0a"
    assert one(e, "ciamCertPurpose") == "client-auth" and set(PEM_FACTS).isdisjoint(PEM_BASICS)

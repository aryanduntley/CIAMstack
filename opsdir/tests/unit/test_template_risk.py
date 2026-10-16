"""Certificate template risk (domains/pki/templates): a template letting the requester name the subject of
authenticating certificates with no approval or authorized signature is an action when a broad group may enroll or
who may isn't known, owned by its renewal owner, else its CAs' owners; restricted and unpublished ones are counted;
anything else (server authentication only, approval, a signature, the subject from the directory) is never judged;
the template's rights are recorded by the importers' entry builder."""
import datetime as dt

from opsdir.core.contract import Imported, PlanContext
from opsdir.core.directory import get, ou_entry
from opsdir.core.environment import env_model
from opsdir.core.interchange.ldif import parse
from opsdir.domains.pki.domain import DOMAIN
from opsdir.domains.pki.inventory import inventory_group
from opsdir.domains.pki.issued import authority_entry, template_entry, templates_group
from opsdir.domains.pki.naming import AUTHORITIES, TEMPLATES, template_dn
from opsdir.domains.pki.templates import (BROAD, RESTRICTED, UNKNOWN, UNPUBLISHED, authenticates,
                                          check_template_risk, template_risk)
import mini_estate
from support import after_import

AS_OF = dt.date(2026, 10, 1)
OWNERS = "ou=owners,dc=ciam-ops"
CLIENT, SERVER, ANY = "1.3.6.1.5.5.7.3.2", "1.3.6.1.5.5.7.3.1", "2.5.29.37.0"
USERS = "S-1-5-21-1-2-3-513 (Domain Users)"


def _rights(subject=True, approval=False, signatures=0, scope=BROAD, enrollees=(USERS,)):
    return {"ciamSubjectFromRequest": subject, "ciamApprovalRequired": approval, "ciamRequiredSignatures": signatures,
            "ciamTemplateVersion": 2, "ciamEnrollee": enrollees, "ciamEnrollmentScope": scope}


def _record(templates, published=None, renewal=None):
    """The record with these templates ((name, usages, rights)), a CA issuing from published (None: listing none)
    owned by the PKI team, and a renewal owner on each template when renewal names one."""
    head = "\n".join((f"dn: {OWNERS}\nchangetype: add\nobjectClass: top\nobjectClass: organizationalUnit\nou: owners\n",
                      *(f"dn: cn={t},{OWNERS}\nchangetype: add\nobjectClass: top\nobjectClass: ciamParty\ncn: {t}\n"
                        "ciamOwnerKind: team\n" for t in ("platform", "pki-team"))))
    d = mini_estate.directory(tuple(parse(head)))
    entries = tuple(template_entry(d, n, None, None, None, usages, rights) for n, usages, rights in templates)
    ca = authority_entry(d, "Issuing CA", "PKI1\\Issuing CA", published or ())
    ca = ca._replace(attrs={**ca.attrs, "ciamOwner": (f"cn=pki-team,{OWNERS}",)})
    d = after_import(d, Imported((ou_entry(AUTHORITIES), ou_entry(TEMPLATES)),
                                 (templates_group(d, entries), inventory_group(ca, ())), ()))
    if renewal:
        d = after_import(d, Imported((), (templates_group(d, tuple(
            t._replace(attrs={**t.attrs, "ciamRenewalOwner": (f"cn={renewal},{OWNERS}",)})
            for t in (get(d, template_dn(n)) for n, _, _ in templates))),), ()))
    return d


def _plan(d):
    return check_template_risk(PlanContext(d, env_model(d, "alpha/prod"), env_model(d, "beta/prod"), None, AS_OF,
                                           {}, {}, ()))


def test_the_rights_are_recorded():
    d = _record((("Web", (CLIENT,), _rights()),))
    t = get(d, template_dn("Web")).attrs
    assert (t["ciamSubjectFromRequest"], t["ciamApprovalRequired"], t["ciamRequiredSignatures"]) == (
        ("TRUE",), ("FALSE",), ("0",))
    assert t["ciamEnrollee"] == (USERS,) and t["ciamEnrollmentScope"] == ("broad",)
    assert t["ciamTemplateVersion"] == ("2",)


def test_states():
    d = _record((("Broad", (CLIENT,), _rights()), ("Any", (ANY,), _rights(scope=RESTRICTED)),
                 ("NoUsage", (), _rights(scope=None)), ("Server", (SERVER,), _rights()),
                 ("Approved", (CLIENT,), _rights(approval=True)), ("Signed", (CLIENT,), _rights(signatures=1)),
                 ("Directory", (CLIENT,), _rights(subject=False)), ("Unread", (CLIENT,), _rights(subject=None))))
    states = {n: template_risk(d, get(d, template_dn(n))) for n in ("Broad", "Any", "NoUsage", "Server", "Approved",
                                                                   "Signed", "Directory", "Unread")}
    assert states == {"Broad": BROAD, "Any": RESTRICTED, "NoUsage": UNKNOWN, "Server": None, "Approved": None,
                      "Signed": None, "Directory": None, "Unread": None}
    assert authenticates(()) and authenticates((SERVER, CLIENT)) and not authenticates((SERVER,))


def test_broad_and_unknown_enrollment_are_actions_owned_by_the_renewal_owner():
    d = _record((("Broad", (CLIENT,), _rights()), ("Unknown", (CLIENT,), _rights(scope=UNKNOWN, enrollees=())),
                 ("Narrow", (CLIENT,), _rights(scope=RESTRICTED))), published=("Broad", "unknown", "Narrow"),
                renewal="platform")
    f = _plan(d)
    assert [a[2] for a in f.actions] == ["platform", "platform"] and not f.blockers
    broad, unknown = (a[1] for a in f.actions)
    assert "`Broad`" in broad and USERS in broad and "client authentication" in broad and "ESC1" in broad
    assert "Issuing CA issues from it" in broad
    assert "`Unknown`" in unknown and "Who may enroll from it is unknown" in unknown
    assert f.ok == ("1 certificate template(s) letting the requester name the subject of authenticating certificates "
                    "let only named accounts enroll.",)
    assert check_template_risk in DOMAIN.checks


def test_owner_falls_back_to_the_issuing_cas_and_publication():
    f = _plan(_record((("Broad", (CLIENT,), _rights()),), published=("Broad",)))
    assert [a[2] for a in f.actions] == ["pki-team"]
    f = _plan(_record((("Broad", (CLIENT,), _rights()),)))
    assert [a[2] for a in f.actions] == ["**NO OWNER**"]
    assert "whether a CA issues from it is unknown" in f.actions[0][1]
    f = _plan(_record((("Broad", (CLIENT,), _rights()),), published=("Other",)))
    assert f.actions == () and f.ok == ("1 certificate template(s) letting the requester name the subject of "
                                        "authenticating certificates are issued by no recorded CA.",)
    assert template_risk(_record((("Broad", (CLIENT,), _rights()),), published=("Other",)),
                         get(_record((("Broad", (CLIENT,), _rights()),)), template_dn("Broad"))) == UNPUBLISHED

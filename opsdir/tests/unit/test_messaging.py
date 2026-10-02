"""The messaging domain: external services (the names they allow, the roles they use), mail senders and the sending
identities each environment delivers their mail from, event streams and what carries them; their reports, the
planner's findings, and sending identities and streams as bindings a cloud reads."""
import datetime as dt

from opsdir.core.contract import PlanContext
from opsdir.core.directory import one
from opsdir.core.environment import env_model
from opsdir.core.findings import findings
from opsdir.core.interchange.ldif import parse
from opsdir.core.inventory import environment_groups, resource
from opsdir.domains.messaging.naming import (EVENT_STREAMS, EXTERNAL_SERVICES, MAIL_SENDERS, sender_dn, service_dn,
                                            stream_dn)
from opsdir.domains.messaging.services import check_services, covered, sender_rows, service_rows
from opsdir.domains.messaging.streams import check_streams, stream_rows
import mini_estate
from support import REGISTRY, build_directory

ALPHA = "env=prod,cloud=alpha,ou=environments,dc=ciam-ops"
BETA = "env=prod,cloud=beta,ou=environments,dc=ciam-ops"
OPS = "cn=ops,ou=owners,dc=ciam-ops"


def _ou(dn, ou):
    return f"dn: {dn}\nobjectClass: top\nobjectClass: organizationalUnit\nou: {ou}\n"


def _binding(env, cn, oc, role, extra):
    return (f"dn: cn={cn},ou=bindings,{env}\nobjectClass: top\nobjectClass: {oc}\ncn: {cn}\nciamBindingRole: {role}\n"
            f"{extra}")


RECORDS = "\n".join((
    "dn: ou=owners,dc=ciam-ops\nobjectClass: top\nobjectClass: organizationalUnit\nou: owners\n",
    f"dn: {OPS}\nobjectClass: top\nobjectClass: ciamParty\ncn: ops\nciamOwnerKind: team\n",
    _binding(ALPHA, "svc-login", "ciamServiceName", "login-service",
             "ciamFqdn: login.alpha.example.test\nciamTargetRole: web\nciamPort: 443\n"),
    _binding(BETA, "svc-login", "ciamServiceName", "login-service",
             "ciamFqdn: login.beta.example.net\nciamTargetRole: web\nciamPort: 443\n"),
    _binding(ALPHA, "mail-id", "ciamSendingIdentity", "mail-sending",
             "ciamSenderDomain: example.test\nciamProviderRef: ses-1\nciamDkimVerified: TRUE\n"
             "ciamSpfAuthorized: TRUE\nciamDmarcPolicy: reject\n"),
    _binding(BETA, "mail-id", "ciamSendingIdentity", "mail-sending",
             "ciamSenderDomain: example.test\nciamProviderRef: acs-1\nciamDkimVerified: FALSE\n"
             "ciamSpfAuthorized: TRUE\nciamDmarcPolicy: none\n"),
    _binding(ALPHA, "audit-bus", "ciamStreamBinding", "audit-events", "ciamProviderRef: bus-1\nciamStreamKind: bus\n"),
    _ou(EXTERNAL_SERVICES, "external-services"),
    f"dn: {service_dn('captcha')}\nobjectClass: top\nobjectClass: ciamObject\nobjectClass: ciamExternalService\n"
    "cn: captcha\nciamServiceKind: captcha\nciamVendor: Example CAPTCHA\nciamAllowedDomain: example.test\n"
    "ciamReachedFrom: web\nciamUsesRole: captcha-secret\n",
    f"dn: {service_dn('relay')}\nobjectClass: top\nobjectClass: ciamObject\nobjectClass: ciamExternalService\n"
    f"cn: relay\nciamServiceKind: smtp-relay\nciamEndpointHost: smtp.example.test\nciamPort: 587\nciamOwner: {OPS}\n",
    _ou(MAIL_SENDERS, "mail-senders"),
    f"dn: {sender_dn('noreply')}\nobjectClass: top\nobjectClass: ciamObject\nobjectClass: ciamMailSender\n"
    f"cn: noreply\nciamSenderAddress: noreply@example.test\nciamSentBy: {service_dn('relay')}\n"
    "ciamSendingRole: mail-sending\nciamMessagePurpose: password-reset\n",
    _ou(EVENT_STREAMS, "event-streams"),
    f"dn: {stream_dn('audit')}\nobjectClass: top\nobjectClass: ciamObject\nobjectClass: ciamEventStream\ncn: audit\n"
    "ciamStreamKind: bus\nciamEventType: sign-in\nciamPublishedBy: web\nciamStreamRole: audit-events\n"
    "ciamConsumedBy: siem\n",
    f"dn: {stream_dn('crm')}\nobjectClass: top\nobjectClass: ciamObject\nobjectClass: ciamEventStream\ncn: crm\n"
    "ciamStreamKind: queue\nciamEventType: registration\nciamStreamRole: crm-queue\n"))


def directory(extra=""):
    return build_directory(REGISTRY, tuple(parse(mini_estate.LDIF + "\n" + RECORDS + "\n" + extra)))


def context(d, src="alpha/prod", dst="beta/prod"):
    return PlanContext(d, env_model(d, src), env_model(d, dst), None, dt.date(2026, 10, 1), {}, {}, ())


def test_the_reports():
    d = directory()
    assert service_rows(d) == [
        ("captcha", "captcha", "Example CAPTCHA", "", "web", "example.test", "captcha-secret", ""),
        ("relay", "smtp-relay", "", "smtp.example.test:587", "", "", "", "")]
    assert sender_rows(d) == [("noreply", "noreply@example.test", "example.test", "relay", "mail-sending",
                               "password-reset", "")]
    assert stream_rows(d) == [("audit", "bus", "sign-in", "web", "audit-events", "siem"),
                              ("crm", "queue", "registration", "", "crm-queue", "")]


def test_allowed_domains_cover_names_under_them():
    assert covered("login.example.test", ("example.test",)) and covered("a.b.example.test", ("*.example.test",))
    assert not covered("login.example.testing", ("example.test",)) and not covered("example.net", ("example.test",))


def test_the_planner_names_what_breaks_at_cutover():
    f = check_services(context(directory()))
    assert [t for _, t, _ in f.blockers] == [
        "External service `captcha` allows example.test; beta/prod's names for the roles that use it aren't among "
        "them: login.beta.example.net. Add them at the vendor before cutover.",
        "External service `captcha` uses role `captcha-secret`, which neither alpha/prod nor beta/prod binds: record "
        "where each environment keeps it.",
        "Sender `noreply`: beta/prod's sending identity for example.test isn't DKIM-verified: mail it sends lands in "
        "spam (password resets included). Publish the DNS records before cutover."]
    assert [t for _, t, _, _ in f.actions] == [
        "External service `captcha` has no owner: a vendor account nobody owns lapses unnoticed. Name who owns it.",
        "Sender `noreply`: beta/prod's DMARC policy for example.test is none, weaker than alpha/prod's reject.",
        "Sender `noreply` records no bounce or complaint handling: undeliverable reset mail goes unnoticed. Record "
        "where bounces go."]


def test_streams_need_a_carrier_and_a_reader():
    f = check_streams(context(directory()))
    assert [t for _, t, _ in f.blockers] == [
        "Event stream `crm` is carried by role `crm-queue`, which neither alpha/prod nor beta/prod binds: record each "
        "environment's queue or bus."]
    assert [t for _, t, _, _ in f.actions] == [
        "Event stream `crm` records nobody who reads it: events nobody consumes after a move go unnoticed. Record its "
        "consumers."]


def test_nothing_is_asked_of_a_record_without_them():
    d = build_directory(REGISTRY, tuple(parse(mini_estate.LDIF)))
    assert check_services(context(d)) == check_streams(context(d)) == findings()


def test_sending_identities_and_streams_are_bindings_a_cloud_reads():
    groups, notices = environment_groups(directory(), "beta/prod", (
        resource("sending", "acs-2", {"ciamSenderDomain": "mail.example.test", "ciamDkimVerified": "TRUE"},
                 name="acs-mail", role="mail-sending-2"),
        resource("stream", "sb-1", {"ciamStreamKind": "queue"}, name="crm-queue", role="crm-queue"),
        resource("stream", "sb-untagged", name="untagged")))
    placed = {dn: e for dn, (e,) in groups}
    acs, queue = placed[f"cn=acs-mail,ou=bindings,{BETA}"], placed[f"cn=crm-queue,ou=bindings,{BETA}"]
    assert (acs.classes, one(acs, "ciamSenderDomain")) == (("top", "ciamSendingIdentity"), "mail.example.test")
    assert (queue.classes, one(queue, "ciamProviderRef")) == (("top", "ciamStreamBinding"), "sb-1")
    assert any("untagged" in n for n in notices)


def test_spf_and_dmarc_from_txt_records():
    from opsdir.domains.messaging.dns import dmarc_policy, spf_authorizes
    assert spf_authorizes(('"v=spf1 include:amazonses.com" " ~all"', "google-site-verification=x"), "amazonses.com") \
        == "TRUE"
    assert spf_authorizes(("v=spf1 include:_spf.example.net -all",), "amazonses.com") == "FALSE"
    assert spf_authorizes(("not spf",), "amazonses.com") is None
    assert dmarc_policy(("v=DMARC1; p=quarantine; rua=mailto:d@example.test",)) == "quarantine"
    assert dmarc_policy(("v=DMARC1; sp=reject",)) is None and dmarc_policy(()) is None

"""Messaging fixture data (78-messaging): what the platform depends on outside itself and what it tells others. The
SES SMTP relay and the reCAPTCHA service PingFederate uses (the import fills in what PingFederate says; the record
adds owners and the domains reCAPTCHA allows), the address reset mail comes from, and the identity audit stream the
security team's SIEM reads. Each environment's sending identity and the bus that carries the stream are bindings
(infrastructure: SOURCE / TARGET)."""
from .common import R, owner, spec

FILE = "78-messaging"
SERVICES, SENDERS, STREAMS = f"ou=external-services,{R}", f"ou=mail-senders,{R}", f"ou=event-streams,{R}"
RELAY = "email-smtp.us-east-1.amazonaws.com"


def _ou(dn, name):
    return spec(FILE, dn, ["top", "organizationalUnit"], ou=name)


def entries():
    return (_ou(SERVICES, "external-services"),
            spec(FILE, f"cn={RELAY},{SERVICES}", ["top", "ciamObject", "ciamExternalService"], cn=RELAY,
                 ciamServiceKind="smtp-relay", ciamVendor="Amazon SES", ciamEndpointHost=RELAY, ciamPort=587,
                 ciamOwner=owner("ciam-platform")),
            spec(FILE, f"cn=captcha-recaptcha,{SERVICES}", ["top", "ciamObject", "ciamExternalService"],
                 cn="captcha-recaptcha", ciamServiceKind="captcha",
                 ciamAllowedDomain=["sso.example-aero.test", "login.example-aero.test"],
                 ciamOwner=owner("ciam-platform")),
            _ou(SENDERS, "mail-senders"),
            spec(FILE, f"cn=noreply@example-aero.test,{SENDERS}", ["top", "ciamObject", "ciamMailSender"],
                 cn="noreply@example-aero.test", ciamSenderAddress="noreply@example-aero.test",
                 ciamSendingRole="mail-sending", ciamMessagePurpose=["password-reset", "registration"],
                 ciamBounceHandling="bounce and complaint notifications to the ciam-mail-events topic; suppression "
                                    "list on", ciamOwner=owner("ciam-platform")),
            _ou(STREAMS, "event-streams"),
            spec(FILE, f"cn=identity-audit,{STREAMS}", ["top", "ciamObject", "ciamEventStream"], cn="identity-audit",
                 ciamStreamKind="bus", ciamEventType=["sign-in", "sign-in-failure", "password-change", "registration"],
                 ciamPublishedBy=["pf-engine", "am"], ciamStreamRole="audit-events",
                 ciamConsumedBy="SIEM (security operations)", ciamOwner=owner("ciam-platform")))

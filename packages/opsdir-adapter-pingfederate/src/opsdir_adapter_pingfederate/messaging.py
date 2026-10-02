"""PingFederate's notification publishers and CAPTCHA providers read into the core messaging domain's neutral entries.
Pure. The plugin instances themselves are PingFederate's (opsdir_adapter_pingfederate.plugins); what they say about
the services outside the platform becomes the record's view of them, which the planner checks:

  SMTP notification publisher   -> an external service of kind smtp-relay (its email server and port), found by its
                                   host, and a mail sender for its From address (sent by that service), found by its
                                   address
  CAPTCHA provider              -> an external service of kind captcha (its vendor, from the plugin type), named
                                   captcha-<instance id>
Both are reached from PingFederate's engines, and use the credential role the instance names
(pingfedCredentialRole): its secrets are withheld from the plugin and never reach these entries. What the record adds
(allowed domains, owners, a sender's sending role and bounce handling) is kept on import.
"""
from opsdir.core.directory import children, get, make_entry, merged_attrs, one, rdn_value
from opsdir.core.naming import rdn_safe
from opsdir.domains.messaging.naming import EXTERNAL_SERVICES, MAIL_SENDERS, sender_dn, service_dn
from .naming import SERVER_ROLES, named
from .plugins import KINDS, settings_fields

SERVICE_OWNED = ("cn", "ciamServiceKind", "ciamVendor", "ciamEndpointHost", "ciamPort", "ciamReachedFrom",
                 "ciamUsesRole")
SENDER_OWNED = ("cn", "ciamSenderAddress", "ciamSenderDomain", "ciamSentBy")
# CAPTCHA vendors by a word in the plugin type
CAPTCHA_VENDORS = (("recaptcha", "Google reCAPTCHA"), ("hcaptcha", "hCaptcha"), ("turnstile", "Cloudflare Turnstile"))


def field(item, name):
    """A plugin instance's settings field value by name, or None."""
    return next((f.get("value") for f in settings_fields(item) if f.get("name") == name and f.get("value")), None)


def is_smtp(item):
    return "smtp" in ((item.get("pluginDescriptorRef") or {}).get("id") or "").lower()


def captcha_vendor(item):
    kind = ((item.get("pluginDescriptorRef") or {}).get("id") or "").lower()
    return next((v for word, v in CAPTCHA_VENDORS if word in kind), (item.get("pluginDescriptorRef") or {}).get("id"))


def _credential_role(d, kind, pid):
    held = get(d, named(KINDS[kind].base, pid))
    return one(held, "pingfedCredentialRole") if held else None


def _held(d, base, oc, attr, value):
    return next((e for e in children(d, base, oc) if value and (one(e, attr) or "").lower() == value.lower()), None)


def _entry(d, dn, classes, owned, names):
    return make_entry(dn, ("top", "ciamObject", *classes), merged_attrs(get(d, dn), owned, names))


def relay_entries(d, item):
    """(entries, notices) of an SMTP notification publisher: its relay and the sender of its From address."""
    pid, host, port, address = item.get("id"), field(item, "Email Server"), field(item, "SMTP Port"), \
        field(item, "From Address")
    if not host:
        return (), (f"notification publisher {pid}: no Email Server; no relay recorded",)
    held = _held(d, EXTERNAL_SERVICES, "ciamExternalService", "ciamEndpointHost", host)
    dn = held.dn if held else service_dn(host.lower())
    role = _credential_role(d, "notification-publisher", pid)
    relay = _entry(d, dn, ("ciamExternalService",), {
        "cn": (rdn_value(held) if held else host.lower(),), "ciamServiceKind": ("smtp-relay",),
        "ciamEndpointHost": (host.lower(),), "ciamPort": (str(port) if port else None,),
        "ciamReachedFrom": (SERVER_ROLES[0],), "ciamUsesRole": (role,)},
        tuple(n for n in SERVICE_OWNED if n != "ciamVendor"))
    if not address or "@" not in address:
        return (relay,), (f"notification publisher {pid}: no From Address; no sender recorded",)
    sender = _held(d, MAIL_SENDERS, "ciamMailSender", "ciamSenderAddress", address)
    sdn = sender.dn if sender else sender_dn(address.lower())
    return (relay, _entry(d, sdn, ("ciamMailSender",), {
        "cn": (rdn_value(sender) if sender else address.lower(),), "ciamSenderAddress": (address,),
        "ciamSenderDomain": (address.rsplit("@", 1)[1].lower(),), "ciamSentBy": (relay.dn,)}, SENDER_OWNED)), ()


def captcha_entries(d, item):
    """(entries, notices) of a CAPTCHA provider: the CAPTCHA service it is."""
    pid = item.get("id")
    role = _credential_role(d, "captcha-provider", pid)
    return (_entry(d, service_dn(f"captcha-{pid}"), ("ciamExternalService",), {
        "cn": (f"captcha-{pid}",), "ciamServiceKind": ("captcha",), "ciamVendor": (captcha_vendor(item),),
        "ciamReachedFrom": (SERVER_ROLES[0],), "ciamUsesRole": (role,)},
        tuple(n for n in SERVICE_OWNED if n not in ("ciamEndpointHost", "ciamPort"))),), ()


def messaging_groups(d, found):
    """(groups, notices): the external services and mail senders the export's publishers and CAPTCHA providers
    are, each its own group."""
    parts = [*(relay_entries(d, i) for i in found.get("notification-publisher", ()) if is_smtp(i)
               and rdn_safe(i.get("id") or "")),
             *(captcha_entries(d, i) for i in found.get("captcha-provider", ()) if rdn_safe(f"captcha-{i.get('id')}"))]
    entries = {e.dn: e for es, _ in parts for e in es}
    return tuple((dn, (e,)) for dn, e in entries.items()), tuple(n for _, ns in parts for n in ns)

"""PingFederate's notification publishers and CAPTCHA providers: plugin instances of their own (secrets withheld,
rendered back per environment), read into the core messaging domain as an SMTP relay and the sender of its From
address, and a CAPTCHA service; their secrets never reach those entries; what the record adds to them is kept; a
re-import changes nothing."""
import json

from opsdir.connectors.importing import preview_import
from opsdir.connectors.registry import core_fragments
from opsdir.core.directory import get, one, values
from opsdir.core.environment import env_model
from opsdir.core.interchange.ldif import parse
from opsdir.core.standard import registry_ldif
from opsdir.domains.messaging.naming import sender_dn, service_dn
from opsdir_adapter_pingfederate.adapter import ADAPTER
from opsdir_adapter_pingfederate.naming import CAPTCHA_PROVIDERS, NOTIFICATION_PUBLISHERS, named
from opsdir_adapter_pingfederate.render import render_env
from opsdir_adapter_pingfederate.schema import FRAGMENT
import mini_estate
from support import build_directory

REGISTRY = registry_ldif((*core_fragments(), FRAGMENT))
SMTP = {"id": "smtp", "name": "SMTP", "pluginDescriptorRef": {"id": "com.pingidentity.email.SmtpNotificationPlugin"},
        "configuration": {"fields": [
            {"name": "From Address", "value": "noreply@example.test"},
            {"name": "Email Server", "value": "email-smtp.region-1.example.cloud"},
            {"name": "SMTP Port", "value": "587"}, {"name": "Username", "value": "AKIAEXAMPLE"},
            {"name": "Password", "encryptedValue": "eyJ..not-a-real-value"}]}}
CAPTCHA = {"id": "recaptcha", "name": "reCAPTCHA",
           "pluginDescriptorRef": {"id": "com.pingidentity.captcha.recaptchav3.ReCaptchaV3Plugin"},
           "configuration": {"fields": [{"name": "Site Key", "value": "6Lc-public-site-key"},
                                        {"name": "Secret Key", "encryptedValue": "eyJ..also-not-real"}]}}
FILES = {"data.json": json.dumps({"operations": [
    {"operationType": "SAVE", "resourceType": "/notificationPublishers", "items": [SMTP]},
    {"operationType": "SAVE", "resourceType": "/captchaProviders", "items": [CAPTCHA]}]})}
RECORD_ADDS = tuple(parse(
    f"dn: {service_dn('captcha-recaptcha')}\nchangetype: modify\nadd: ciamAllowedDomain\n"
    "ciamAllowedDomain: example.test\n-\n\n"
    f"dn: {named(NOTIFICATION_PUBLISHERS, 'smtp')}\nchangetype: modify\nadd: pingfedCredentialRole\n"
    "pingfedCredentialRole: smtp-credentials\n-\n"))


def imported(changes=()):
    base = build_directory(REGISTRY, tuple(parse(mini_estate.LDIF)), changes)
    found, notices = preview_import(base, "pingfederate/bulk", FILES, (ADAPTER,))
    return build_directory(REGISTRY, tuple(parse(mini_estate.LDIF)), (*changes, *found)), found, notices


def test_plugins_of_their_own_with_secrets_withheld():
    d, _, notices = imported()
    smtp, captcha = get(d, named(NOTIFICATION_PUBLISHERS, "smtp")), get(d, named(CAPTCHA_PROVIDERS, "recaptcha"))
    assert (one(smtp, "pingfedPluginKind"), one(captcha, "pingfedPluginKind")) == \
        ("notification-publisher", "captcha-provider")
    assert values(smtp, "pingfedWithheld") == ("/configuration/fields/4/value",)
    files = render_env(env_model(d, "alpha/prod"), None)
    assert {"pingfederate/notification-publishers.json", "pingfederate/captcha-providers.json"} <= set(files)
    assert not any("held as is" in n and "notificationPublishers" in n for n in notices)


def test_the_relay_its_sender_and_the_captcha_service():
    d, _, _ = imported()
    relay = get(d, service_dn("email-smtp.region-1.example.cloud"))
    assert (one(relay, "ciamServiceKind"), one(relay, "ciamEndpointHost"), one(relay, "ciamPort"),
            one(relay, "ciamReachedFrom")) == ("smtp-relay", "email-smtp.region-1.example.cloud", "587", "pf-engine")
    sender = get(d, sender_dn("noreply@example.test"))
    assert (one(sender, "ciamSenderAddress"), one(sender, "ciamSenderDomain"), one(sender, "ciamSentBy")) == \
        ("noreply@example.test", "example.test", relay.dn)
    captcha = get(d, service_dn("captcha-recaptcha"))
    assert (one(captcha, "ciamServiceKind"), one(captcha, "ciamVendor")) == ("captcha", "Google reCAPTCHA")


def test_secrets_never_reach_the_messaging_entries():
    _, changes, _ = imported()
    assert "not-a-real-value" not in repr(changes) and "also-not-real" not in repr(changes)


def test_what_the_record_adds_is_kept_and_the_credential_role_carried():
    _, first, _ = imported()
    again, changes, _ = imported((*first, *RECORD_ADDS))
    relay = get(again, service_dn("email-smtp.region-1.example.cloud"))
    captcha = get(again, service_dn("captcha-recaptcha"))
    assert values(captcha, "ciamAllowedDomain") == ("example.test",)
    assert values(relay, "ciamUsesRole") == ("smtp-credentials",)          # from the publisher's credential role
    _, unchanged, _ = imported((*first, *RECORD_ADDS, *changes))
    assert not unchanged

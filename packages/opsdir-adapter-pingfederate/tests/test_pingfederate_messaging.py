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
from opsdir_adapter_pingfederate.admin_api import OUTPUT as REQUESTS, rendered_bodies
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
    bodies = rendered_bodies(render_env(env_model(d, "alpha/prod"), None)[REQUESTS])
    assert {"/notificationPublishers", "/captchaProviders"} <= set(bodies)
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


RELAY = service_dn("email-smtp.region-1.example.cloud")
ALPHA = "env=prod,cloud=alpha,ou=environments,dc=ciam-ops"
OAUTH_SMTP = {**SMTP, "configuration": {"fields": [
    *(f for f in SMTP["configuration"]["fields"] if f["name"] not in ("Username", "Password")),
    {"name": "Authentication Method", "value": "OAuth 2.0 Bearer Token"},
    {"name": "OAuth Authentication Method", "value": "Client Credentials"},
    {"name": "OAuth Token Endpoint", "value": "https://login.example.cloud/oauth2/v2.0/token"},
    {"name": "OAuth Scope", "value": "https://outlook.office365.com/.default"},
    {"name": "Client ID", "value": "pf-mailer"}, {"name": "Client Secret", "encryptedValue": "eyJ..not-real-either"}]}}


def _smtp_body(d, env="alpha/prod"):
    (body,) = rendered_bodies(render_env(env_model(d, env), None)[REQUESTS])["/notificationPublishers"]
    return {f["name"]: f.get("value") for f in body["configuration"]["fields"]}


def test_a_13_1_publisher_signing_in_with_oauth_is_recorded_on_its_relay():
    files = {"data.json": json.dumps({"operations": [
        {"operationType": "SAVE", "resourceType": "/notificationPublishers", "items": [OAUTH_SMTP]}]})}
    base = build_directory(REGISTRY, tuple(parse(mini_estate.LDIF)))
    found, _ = preview_import(base, "pingfederate/bulk", files, (ADAPTER,))
    relay = get(build_directory(REGISTRY, tuple(parse(mini_estate.LDIF)), found), RELAY)
    assert (one(relay, "ciamSmtpAuth"), one(relay, "ciamTokenEndpoint"), one(relay, "ciamClientId"),
            values(relay, "ciamScope")) == ("oauth-client-credentials", "https://login.example.cloud/oauth2/v2.0/token",
                                            "pf-mailer", ("https://outlook.office365.com/.default",))
    assert "not-real-either" not in repr(found)


def test_a_relay_moved_to_oauth_renders_the_publishers_sign_in_from_13_1_and_the_planner_names_older_targets():
    _, first, _ = imported()
    assert one(get(imported(first)[0], RELAY), "ciamSmtpAuth") == "basic"          # a password before 13.1
    to_oauth = tuple(parse(f"dn: {RELAY}\nchangetype: modify\nreplace: ciamSmtpAuth\n"
                           "ciamSmtpAuth: oauth-private-key-jwt\n-\nreplace: ciamTokenEndpoint\n"
                           "ciamTokenEndpoint: https://login.example.cloud/token\n-\nreplace: ciamClientId\n"
                           "ciamClientId: pf-mailer\n-\n"))
    record = lambda *changes: build_directory(REGISTRY, tuple(parse(mini_estate.LDIF)), changes)   # noqa: E731
    d = record(*first, *to_oauth)                                                   # changed, not imported again
    fields = _smtp_body(d)                                                           # no version: the newest
    assert (fields["Authentication Method"], fields["OAuth Authentication Method"], fields["OAuth Token Endpoint"],
            fields["Client ID"]) == ("OAuth 2.0 Bearer Token", "Private Key JWT", "https://login.example.cloud/token",
                                     "pf-mailer")
    pf12 = tuple(parse(f"dn: cn=pf-1,{ALPHA}\nchangetype: add\nobjectClass: top\nobjectClass: ciamServer\ncn: pf-1\n"
                       f"ciamServerRole: pf-engine\nciamHostname: pf-1.example.test\n"
                       f"ciamSubnet: cn=net,ou=bindings,{ALPHA}\nciamProductVersion: PingFederate 12.3.8\n"))
    old = record(*first, *to_oauth, *pf12)
    assert "Authentication Method" not in _smtp_body(old)                           # as held: a password
    import datetime as dt
    from opsdir.core.contract import PlanContext
    from opsdir_adapter_pingfederate.checks import check_smtp_auth
    ctx = PlanContext(old, env_model(old, "beta/prod"), env_model(old, "alpha/prod"), None, dt.date(2026, 10, 1),
                      {}, {}, ())
    (action,) = [t for _, t, _, _ in check_smtp_auth(ctx).actions]
    assert action.startswith("Notification publisher `smtp` sends through `email-smtp.region-1.example.cloud`, which "
                             "the record signs in to with OAuth (oauth-private-key-jwt), but alpha/prod runs "
                             "PingFederate 12.3.8")


def _plan(d, dst="alpha/prod"):
    import datetime as dt
    from opsdir.core.contract import PlanContext
    return PlanContext(d, env_model(d, "beta/prod"), env_model(d, dst), None, dt.date(2026, 10, 1), {}, {}, ())


def _record(*changes):
    return build_directory(REGISTRY, tuple(parse(mini_estate.LDIF)), changes)


def test_the_credential_role_fix_also_gives_the_service_the_role():
    from opsdir_adapter_pingfederate.checks import check_references
    _, first, _ = imported()
    d = _record(*first, *mini_estate.credential_changes(alpha={}, beta={}))     # alpha binds a secret: signing-key
    fixes = {f.key: f for f in check_references(_plan(d)).fixes}
    for key, service in (("credential-role:notification-publishers/smtp", RELAY),
                         ("credential-role:captcha-providers/recaptcha", service_dn("captcha-recaptcha"))):
        (option,) = fixes[key].options
        assert [(r.dn, r.mods) for r in option.records if "external-services" in r.dn] == \
            [(service, (("replace", "ciamUsesRole", ("signing-key",)),))]


def test_a_credential_role_set_after_the_import_is_named_on_its_service_and_fixed():
    from opsdir_adapter_pingfederate.checks import check_service_roles
    _, first, _ = imported()
    roles = tuple(parse(f"dn: {named(NOTIFICATION_PUBLISHERS, 'smtp')}\nchangetype: modify\n"
                        "replace: pingfedCredentialRole\npingfedCredentialRole: smtp-credentials\n-\n\n"
                        f"dn: {named(CAPTCHA_PROVIDERS, 'recaptcha')}\nchangetype: modify\n"
                        "replace: pingfedCredentialRole\npingfedCredentialRole: captcha-credentials\n-\n"))
    found = check_service_roles(_plan(_record(*first, *roles)))                 # set by a change, not imported again
    assert [t.split(":")[0] for _, t, _, _ in found.actions] == \
        ["`email-smtp.region-1.example.cloud` records credential role none, but notification publisher `smtp`, "
         "which stands for it, takes its credentials from `smtp-credentials`",
         "`captcha-recaptcha` records credential role none, but CAPTCHA provider `recaptcha`, which stands for it, "
         "takes its credentials from `captcha-credentials`"]
    fixed = _record(*first, *roles, *(r for f in found.fixes for r in f.records))
    assert check_service_roles(_plan(fixed)) == check_service_roles(_plan(_record(*first)))
    assert not check_service_roles(_plan(fixed)).actions
    assert values(get(fixed, RELAY), "ciamUsesRole") == ("smtp-credentials",)

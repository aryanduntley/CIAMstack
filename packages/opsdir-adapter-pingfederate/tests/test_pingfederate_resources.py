"""PingFederate resources the adapter doesn't model are held as is: one entry per item (by id; a one-object resource as
'settings'), secrets withheld, rendered per environment in the bulk export's shape, imported back unchanged, removed
when the export no longer has them, and blocked by the planner while their secrets have no credential role."""
import datetime as dt
import json

import pytest

from opsdir.connectors.importing import preview_import
from opsdir.connectors.registry import core_fragments
from opsdir.core.contract import PlanContext
from opsdir.core.directory import get, one, values
from opsdir.core.environment import env_model
from opsdir.core.interchange.ldif import parse
from opsdir.core.standard import registry_ldif
from opsdir_adapter_pingfederate.adapter import ADAPTER
from opsdir_adapter_pingfederate.checks import check_references
from opsdir_adapter_pingfederate.naming import RESOURCES
from opsdir_adapter_pingfederate.render import render_env
from opsdir_adapter_pingfederate.schema import FRAGMENT
import mini_estate
from support import build_directory

REGISTRY = registry_ldif((*core_fragments(), FRAGMENT))
SERVER = {"contactInfo": {"company": "Example"}, "rolesAndProtocols": {"oauthRole": {"enableOauth": True}}}
MAPPINGS = [{"id": "default|jwt", "context": {"type": "DEFAULT"}, "accessTokenManagerRef": {"id": "jwt"}},
            {"id": "client-credentials", "context": {"type": "CLIENT_CREDENTIALS"}}]
SMTP = {"id": "smtp", "name": "SMTP", "pluginDescriptorRef": {"id": "com.pingidentity.email.SmtpNotificationPlugin"},
        "configuration": {"fields": [{"name": "Email Server", "value": "smtp.example.test"},
                                     {"name": "Password", "encryptedValue": "eyJ..not-a-real-value"}]}}


def export(mappings=MAPPINGS):
    ops = (("/serverSettings", [SERVER]), ("/oauth/accessTokenMappings", mappings), ("/notificationPublishers", [SMTP]))
    return {"data.json": json.dumps({"operations": [{"operationType": "SAVE", "resourceType": r, "items": items}
                                                     for r, items in ops]})}


def imported(files=None):
    base = build_directory(REGISTRY, tuple(parse(mini_estate.LDIF)))
    changes, notices = preview_import(base, "pingfederate/bulk", files or export(), (ADAPTER,))
    return build_directory(REGISTRY, tuple(parse(mini_estate.LDIF)), changes), changes, notices


@pytest.fixture(scope="module")
def after():
    d, _, notices = imported()
    return d, notices


def _dn(slug, name):
    return f"cn={name},ou={slug},{RESOURCES}"


def test_each_item_is_held_as_the_admin_api_writes_it(after):
    d, notices = after
    server = get(d, _dn("serverSettings", "settings"))
    assert (one(server, "pingfedResourceType"), json.loads(one(server, "pingfedConfig"))) == ("/serverSettings", SERVER)
    assert get(d, _dn("oauth.accessTokenMappings", "client-credentials")) is not None
    assert "held as is (not modeled): /notificationPublishers (1), /oauth/accessTokenMappings (2), /serverSettings " \
           "(1)" in notices
    assert not any(n.startswith("not read yet") for n in notices)


def test_an_id_that_cant_name_an_entry_is_named_not_held(after):
    d, notices = after
    assert get(d, _dn("oauth.accessTokenMappings", "default|jwt")) is not None      # '|' is fine in an RDN
    _, _, bad = imported(export([{"id": "a,b"}]))
    assert "/oauth/accessTokenMappings: an item named 'a,b' can't name an entry, or another has the name; not held" \
        in bad


def test_secrets_are_withheld_and_rendered_per_environment(after):
    d, notices = after
    smtp = get(d, _dn("notificationPublishers", "smtp"))
    assert values(smtp, "pingfedWithheld") == ("/configuration/fields/1/value",)
    assert "/notificationPublishers smtp: its secrets are withheld; set pingfedCredentialRole to the secret role that " \
           "holds them" in notices
    assert "not-a-real-value" not in json.dumps([dict(e.attrs) for e in d.entries.values()])
    ops = json.loads(render_env(env_model(d, "alpha/prod"), None)["pingfederate/other-resources.json"])["operations"]
    smtp_out = next(op for op in ops if op["resourceType"] == "/notificationPublishers")["items"][0]
    assert smtp_out["configuration"]["fields"][1] == {"name": "Password", "value": "${withheld}"}


def test_what_it_renders_imports_back_unchanged():
    d, _, _ = imported()
    rendered = {"other-resources.json": render_env(env_model(d, "alpha/prod"), None)["pingfederate/other-resources.json"]}
    assert preview_import(d, "pingfederate/bulk", rendered, (ADAPTER,))[0] == ()


def test_an_item_the_export_no_longer_has_is_removed():
    d, first, _ = imported()
    second, _ = preview_import(d, "pingfederate/bulk", export(MAPPINGS[1:]), (ADAPTER,))
    again = build_directory(REGISTRY, tuple(parse(mini_estate.LDIF)), (*first, *second))
    assert get(again, _dn("oauth.accessTokenMappings", "default|jwt")) is None


def test_the_planner_blocks_withheld_secrets_without_a_credential_role():
    d, _, _ = imported()
    f = check_references(PlanContext(d, env_model(d, "alpha/prod"), env_model(d, "beta/prod"), None,
                                     dt.date(2026, 10, 1), {}, {}, ()))
    assert [t for _, t, _ in f.blockers] == [
        "Resource `/notificationPublishers smtp` has withheld credentials but no credential role: nothing says which "
        "secret beta/prod gives it. Set pingfedCredentialRole."]

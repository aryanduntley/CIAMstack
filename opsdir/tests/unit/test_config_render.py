"""Captured config files in each environment's rendered output and in the migration plan (on the mini estate)."""
import datetime as dt
import json
from functools import reduce

from opsdir.connectors.capture import capture_changes
from opsdir.connectors.plan import plan
from opsdir.connectors.render import render_env
from opsdir.core.formats import INI, JAVA_PROPERTIES
from opsdir.core.interchange.ldif import parse
from opsdir.domains.configuration.naming import setting_dn
import mini_estate
from mini_estate import FAKE

ALPHA, BETA = "alpha/prod", "beta/prod"
AS_OF = dt.date(2026, 1, 1)


def captured(*files, links=()):
    """The mini estate with files captured ((fmt, text, name, options), ...) and settings linked ((name, locator,
    role#attribute), ...)."""
    def add(records, spec):
        fmt, text, name, options = spec
        d = mini_estate.directory(records)
        return (*records, *capture_changes(d, fmt, text, name, f"conf/{name}", installed=(FAKE,), **options)[0])
    records = reduce(add, files, ())
    edits = tuple(r for name, locator, source in links for r in parse(
        f"dn: {setting_dn(name, locator)}\nchangetype: modify\nreplace: ciamValueFrom\nciamValueFrom: {source}\n-\n"))
    return mini_estate.directory((*records, *edits))


def manifest(files):
    return json.loads(files["MANIFEST.json"])


def test_captured_files_render_into_each_environment_with_its_bindings():
    d = captured((INI, "[sso]\nhost = sso.example.test\n", "sso.ini", {}),
                 (JAVA_PROPERTIES, "timeout=30\n", "app.properties", {}),
                 links=(("sso.ini", "sso.host", "sso-service#ciamFqdn"),))
    _, files = render_env(d, ALPHA, (FAKE,))
    assert files["files/conf/sso.ini"] == "[sso]\nhost = sso.example.test\n"
    assert files["files/conf/app.properties"] == "timeout=30\n"
    entries = manifest(files)["files"]
    assert entries["files/conf/sso.ini"]["scope"] == "environment-specific"
    assert entries["files/conf/app.properties"] == {**entries["files/conf/app.properties"], "scope":
                                                     "environment-neutral", "format": "java-properties",
                                                     "captured": True}
    assert "captured_not_rendered" not in manifest(files)


def test_a_file_deployed_to_a_role_no_server_runs_is_not_rendered():
    d = captured((JAVA_PROPERTIES, "timeout=30\n", "web.properties", {"role": "web"}))
    _, files = render_env(d, ALPHA, (FAKE,))
    assert not any(p.startswith("files/") for p in files)


def test_a_file_an_environment_cant_render_is_listed_in_its_manifest_and_blocks_the_plan():
    d = captured((JAVA_PROPERTIES, "key.path=/x\n", "keys.properties", {}),
                 links=(("keys.properties", "key.path", "disk-encryption#ciamRefUri"),))
    _, alpha = render_env(d, ALPHA, (FAKE,))
    assert alpha["files/conf/keys.properties"] == "key.path=${secret:fake://keys/alpha}\n"
    _, beta = render_env(d, BETA, (FAKE,))
    assert manifest(beta)["captured_not_rendered"] == [
        {"file": "keys.properties", "why": "key.path: beta/prod binds no disk-encryption"}]
    p = plan(d, ALPHA, BETA, AS_OF, (FAKE,))
    assert ("Config file", "`keys.properties` can't be rendered for beta/prod: key.path: beta/prod binds no "
            "disk-encryption.") in [b[:2] for b in p.blockers]
    assert "Config file `keys.properties` renders for alpha/prod (conf/keys.properties)." in \
        plan(d, BETA, ALPHA, AS_OF, (FAKE,)).ok


def test_a_file_held_only_as_a_reference_is_an_action_in_the_plan():
    d = captured((JAVA_PROPERTIES, "# admin password: Hunter2Hunter2\nx=1\n", "leaky.properties", {}))
    p = plan(d, BETA, ALPHA, AS_OF, (FAKE,))
    (action,) = [a for a in p.actions if a[0] == "Config file"]
    assert action[1].startswith("`leaky.properties` is held only as a reference: deploy it to alpha/prod from "
                                "conf/leaky.properties")

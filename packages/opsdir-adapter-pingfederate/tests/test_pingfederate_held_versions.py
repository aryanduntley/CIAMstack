"""Held settings exported from one PingFederate version, rendered for another: every render (admin-api, Terraform, bulk)
says so through the same diagnostics: one line per source version naming its objects, one per change between the two
versions touching some of them, an older target named as such, objects with no recorded source counted; nothing said
when the versions match."""
import importlib.util
import json
import pathlib
from types import SimpleNamespace

from opsdir.core.directory import get, make_entry
from opsdir_adapter_pingfederate.bulk import OUTPUT as BULK, PROBLEMS, bulk_files
from opsdir_adapter_pingfederate.diagnostics import held_objects
from opsdir_adapter_pingfederate.naming import DATA_STORES
from opsdir_adapter_pingfederate.terraform_target import OUTPUT as TERRAFORM, terraform_files
from opsdir_adapter_pingfederate.versions import VERSION_CHANGES

_SPEC = importlib.util.spec_from_file_location("pf_admin_api_fixtures",
                                               pathlib.Path(__file__).with_name("test_pingfederate_admin_api.py"))
_FX = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(_FX)
NAMES = "batch, customer-portal, default, grants-db, htmlform, mobile, partner-idp, user-directory"


def _problems(version, d=None):
    return _FX._doc(_FX._env(d or _FX._after(), version))["problems"]


def _held(problems):
    return [p for p in problems if "held settings" in p or "no recorded source version" in p or
            p.startswith(("PingFederate >=", "12.1.0 lacks"))]


def test_settings_of_the_version_rendered_for_say_nothing():
    assert _held(_problems("PingFederate 12.1.4")) == []


def test_settings_of_an_older_version_are_named_with_the_changes_touching_them():
    held = _held(_problems("PingFederate 13.1.3"))
    assert held[0] == (f"held settings exported from PingFederate 12.1.4.0, rendered for 13.1.3: 8 objects ({NAMES}): "
                       "nothing is migrated between the versions; review them against the changes named, or upgrade "
                       "a copy of PingFederate 12.1.4.0 and export it again")
    assert any(p.startswith("PingFederate >=13.1.3: the Admin API validates JDBC data stores' driver class and URL: "
                            "grants-db: ") for p in held[1:])


def test_settings_of_a_newer_version_are_named_never_dropped():
    held = _held(_problems("PingFederate 12.1.0"))
    assert held == [f"held settings exported from PingFederate 12.1.4.0, rendered for 12.1.0: 8 objects ({NAMES}), "
                    "an older version: nothing is dropped; its spec refuses what it lacks"]


def test_objects_with_no_recorded_source_are_counted_not_compared():
    d = _FX._after()
    store = get(d, f"cn=grants-db,{DATA_STORES}")
    d = _FX._with(d, make_entry(store.dn, store.classes,
                                {k: v for k, v in store.attrs.items() if k != "pingfedSourceVersion"}))
    held = _held(_problems("PingFederate 12.1.4", d))
    assert held == ["1 objects hold settings with no recorded source version (grants-db): not compared with 12.1.4"]
    assert len(held_objects(_FX._env(d, "PingFederate 12.1.4"))) >= 8


def test_terraform_and_bulk_carry_the_same_problems():
    m = _FX._env(_FX._after(), "PingFederate 13.1.3")
    problems = _FX._doc(m)["problems"]
    main = terraform_files(m)[f"{TERRAFORM}main.tf"]
    assert all(f"# Problem: {p}\n" in main for p in problems)
    files = bulk_files(m)
    assert json.loads(files[PROBLEMS])["problems"] == problems
    assert "problems" not in json.loads(files[BULK])


def _object(name, classes, config, **attrs):
    return make_entry(f"cn={name},ou=pingfederate,dc=ciam-ops", ("top", *classes),
                      {"cn": (name,), "pingfedConfig": (json.dumps(config),), **{k: (v,) for k, v in attrs.items()}})


def test_each_release_change_names_the_objects_holding_what_it_changes():
    objects = (
        _object("atm-plain", ("ciamObject", "pingfedPlugin"), {}, pingfedPluginKind="access-token-manager",
                pingfedPluginType="com.pingidentity.pf.access.token.management.plugins.JwtBearerAccessTokenManagementPlugin"),
        _object("atm-inherits", ("ciamObject", "pingfedPlugin"),
                {"selectionSettings": {"resourceUris": ["https://api"]},
                 "tokenEndpointAttributeContract": {"inherited": True}}, pingfedPluginKind="access-token-manager",
                pingfedPluginType="com.pingidentity.pf.access.token.management.plugins.JwtBearerAccessTokenManagementPlugin"),
        _object("custom", ("ciamObject", "pingfedPlugin"), {}, pingfedPluginKind="idp-adapter",
                pingfedPluginType="com.example.CustomAdapter"),
        _object("mapping", ("ciamObject", "pingfedResource"),
                {"issuanceCriteria": {"conditionalCriteria": [{"condition": "MULTIVALUE_CONTAINS_DN"}]}},
                pingfedResourceType="/oauth/accessTokenMappings"),
        _object("portal", ("ciamIntegration", "pingfedHeldSettings"),
                {"clientAuth": {"type": "PRIVATE_KEY_JWT"}, "persistentGrantIdleTimeout": 30,
                 "outboundProvision": {"channels": [{"channelSource": {"accountManagementSettings": {
                     "flagComparisonValue": "true"}}}]}}),
        _object("partner", ("ciamIntegration", "pingfedHeldSettings"),
                {"oidcProviderSettings": {"jwtSecuredAuthorizationResponseModeType": "QUERY_JWT"},
                 "idpBrowserSso": {"handleFailuresLocally": True}}),
        _object("oauth-auth-server", ("ciamObject", "pingfedSettings"), {"parStatus": "ENABLED"}),
        _object("not-held", ("ciamObject",), {"flagComparisonValue": "x"}),
    )
    d = SimpleNamespace(entries={e.norm: e for e in objects})
    named = [c.touches(d, None, "pf-admin") for c in VERSION_CHANGES if c.touches is not None and c.has != ">=13.1.3"]
    assert sorted(named) == sorted([
        ("mapping",), ("atm-plain",), ("mapping",), ("portal",), ("atm-inherits",), ("portal",), ("custom",),
        ("partner",), ("oauth-auth-server",), ("portal",), ("custom",), ("partner",)])
    assert all(c.touches(d, None, "am") == () for c in VERSION_CHANGES if c.touches is not None)
    disabled = _object("oauth-auth-server", ("ciamObject", "pingfedSettings"), {"parStatus": "DISABLED"})
    (par,) = [c for c in VERSION_CHANGES if "request_uri" in c.change]
    assert par.touches(SimpleNamespace(entries={disabled.norm: disabled}), None, "pf-admin") == ()

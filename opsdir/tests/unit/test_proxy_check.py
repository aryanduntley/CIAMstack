"""The planner's explicit-proxy check: when the target's egress passes a proxy clients must be told about, each
installed product's settings for it are compared with the captured config files the target receives; right values
are in place, missing or other values are actions (an approved change to the file), places the record holds no file
of are actions naming what to set; no explicit proxy, nothing to check."""
import datetime as dt
from types import SimpleNamespace

from opsdir.connectors.proxies import held, proxy_check
from opsdir.connectors.registry import format_named
from opsdir.core.contract import ProxySetting
from opsdir.core.interchange.ldif import parse, write_entry
from opsdir.core.environment import env_model
from opsdir.core.directory import get
from opsdir.domains.configuration.naming import file_dn, setting_rdn
from opsdir.domains.configuration.record import file_entries, rebuild
import mini_estate
import network_fixtures
from network_fixtures import ALPHA, BETA, context, entry
from support import REGISTRY, build_directory

CUTOVER = dt.date(2026, 11, 2)
SQUID = entry(BETA, "squid", "ciamProxy", ciamBindingRole="squid", ciamProxyKind="forward-proxy",
              ciamProxyAddress="proxy.corp.example:3128")
CONFIG = "dn: ou=config-files,dc=ciam-ops\nobjectClass: top\nobjectClass: organizationalUnit\nou: config-files\n"
WEB = "the web tier's conf/app.properties"


def product(m, proxy):
    """A product whose web servers read the proxy from conf/app.properties and an admin setting."""
    return (ProxySetting("web", WEB, "conf/app.properties", "http.proxyHost", proxy.host, "proxy:host"),
            ProxySetting("web", WEB, "conf/app.properties", "http.proxyPort", str(proxy.port), "proxy:port"),
            ProxySetting("web", "its admin console", None, "proxy", f"{proxy.host}:{proxy.port}", "proxy:address"))


ADAPTERS = (SimpleNamespace(proxy_settings=product), SimpleNamespace(proxy_settings=None))


def _plan(beta=(SQUID,), app=None, changes=()):
    files = file_entries(format_named("java-properties"), app, "web.app", "web/conf/app.properties", (),
                         role="web")[0] if app is not None else ()
    d = build_directory(REGISTRY, tuple(parse("\n".join((
        mini_estate.LDIF, CONFIG, *network_fixtures._estate(ALPHA, ()), *network_fixtures._estate(BETA, beta),
        *(write_entry(e.dn, e.classes, dict(e.attrs)) for e in files))))), changes)
    return context(d, env_model(d, "alpha/prod"), env_model(d, "beta/prod"), CUTOVER)


def _texts(f):
    return [a[1] for a in f.actions]


VIA = "beta/prod's outside traffic goes through `squid` (proxy.corp.example:3128)"


def test_no_explicit_proxy_nothing_to_check():
    firewall = entry(BETA, "fw", "ciamProxy", ciamBindingRole="fw", ciamProxyKind="firewall")
    assert proxy_check(ADAPTERS)(_plan(beta=(firewall,))) == proxy_check(ADAPTERS)(_plan(beta=()))
    assert proxy_check(ADAPTERS)(_plan(beta=())).actions == ()


def test_one_action_per_role_naming_every_place_and_what_the_record_can_t_confirm():
    f = proxy_check(ADAPTERS)(_plan())
    assert _texts(f) == [
        f"{VIA}, so `web` must be told: (1) in {WEB}: `http.proxyHost=proxy.corp.example`; `http.proxyPort=3128` (its "
        "file isn't captured, so the record can't confirm it). (2) in its admin console: "
        "`proxy=proxy.corp.example:3128` (the record can't confirm it)."]
    assert {a[3] for a in f.actions} == {CUTOVER}


def test_a_captured_file_missing_or_with_other_values_needs_a_change():
    f = proxy_check(ADAPTERS)(_plan(app="http.proxyPort=8080\nother=1\n"))
    assert _texts(f)[0].startswith(
        f"{VIA}, so `web` must be told: (1) in {WEB}: add `http.proxyHost=proxy.corp.example`; `http.proxyPort` is "
        "`8080`, needs `3128` (`opsdir fix` links them to the proxy binding, so each environment's file names its "
        "own). (2) in its admin console:")


def test_a_captured_file_that_says_so_is_in_place():
    ctx = _plan(app="http.proxyHost=proxy.corp.example\nhttp.proxyPort=3128\n")
    assert held(ctx.d, ctx.dst, "conf/app.properties", "web") == {"http.proxyHost": "proxy.corp.example",
                                                                  "http.proxyPort": "3128"}
    assert held(ctx.d, ctx.dst, "conf/app.properties", "ds") is None          # deployed to web servers only
    f = proxy_check(ADAPTERS)(ctx)
    assert f.ok == (f"{VIA}: `web`'s {WEB} says so.",)
    assert _texts(f) == [f"{VIA}, so `web` must be told: (1) in its admin console: `proxy=proxy.corp.example:3128` "
                         "(the record can't confirm it)."]


def test_the_fix_links_the_shared_file_to_the_proxy_so_each_environment_renders_its_own():
    app = "# app settings\nhttp.proxyPort=8080\nother=1\n"
    (fix,) = proxy_check(ADAPTERS)(_plan(app=app)).fixes
    assert (fix.key, fix.area) == ("egress-proxy:web:conf/app.properties", "Egress proxy")
    assert fix.title == f"Link `http.proxyHost`, `http.proxyPort` in `web`'s {WEB} (web.app) to `squid`'s proxy"
    assert [(r.changetype, r.dn.split(",")[0]) for r in fix.records] == [
        ("add", f"cn={setting_rdn('http.proxyHost')}"), ("modify", "cn=web.app"),
        ("modify", f"cn={setting_rdn('http.proxyPort')}")]
    assert ("replace", "ciamValueFrom", ("squid#proxy:port",)) in fix.records[2].mods
    assert ("delete", "ciamSettingValue", ()) in fix.records[2].mods
    assert fix.manual == ("Deploy the rebuilt web/conf/app.properties to `web`'s servers in beta/prod.",)
    fixed = _plan(app=app, changes=fix.records)
    found = proxy_check(ADAPTERS)(fixed)
    assert found.fixes == () and f"{VIA}: `web`'s {WEB} says so." in found.ok
    f = get(fixed.d, file_dn("web.app"))
    assert rebuild(fixed.d, format_named("java-properties"), f, fixed.dst) == (
        "# app settings\nhttp.proxyPort=3128\nother=1\nhttp.proxyHost=proxy.corp.example\n")
    assert rebuild(fixed.d, format_named("java-properties"), f, fixed.src) == (    # alpha binds no squid: no proxy
        "# app settings\nhttp.proxyPort=\nother=1\nhttp.proxyHost=\n")


def test_a_format_that_can_t_place_a_setting_gets_a_manual_step():
    files = file_entries(format_named("json"), '{"other": 1}\n', "web.app", "web/conf/app.properties", (),
                         role="web")[0]
    d = build_directory(REGISTRY, tuple(parse("\n".join((
        mini_estate.LDIF, CONFIG, *network_fixtures._estate(ALPHA, ()), *network_fixtures._estate(BETA, (SQUID,)),
        *(write_entry(e.dn, e.classes, dict(e.attrs)) for e in files))))))
    (fix,) = proxy_check(ADAPTERS)(context(d, env_model(d, "alpha/prod"), env_model(d, "beta/prod"), CUTOVER)).fixes
    assert fix.records == () and fix.manual[0].startswith("Add `http.proxyHost=proxy.corp.example` to "
                                                          "web/conf/app.properties by hand")

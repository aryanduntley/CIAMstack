"""The SiteMinder agent files (importer agent-files): each server's Web Agent instances read into SiteMinder's branch,
naming their server, linked to the agent identities they act as, their ACO, HCO, trusted host and policy servers; an
Access Gateway's virtual hosts and proxy rules (its one external DOCTYPE stripped, any other declaration refused) as
ordered routes; secrets withheld whole; a server the record no longer holds reported; and SiteMinder's one
projection: ignored extensions and URLs as unprotected resources, a gateway application's backend and published roles,
routes no realm covers as unprotected applications, rewrites as blocking source objects, the routing source object
dropped. A re-import of either the files or the export changes nothing."""
import datetime as dt
from pathlib import Path
from types import MappingProxyType

import pytest

from opsdir.connectors.importing import preview_import
from opsdir.connectors.registry import core_fragments
from opsdir.core.contract import PlanContext
from opsdir.core.directory import children, get, norm_dn, one, values
from opsdir.core.environment import env_model
from opsdir.core.interchange.ldif import parse
from opsdir.core.standard import registry_ldif
from opsdir.domains.governance.source_objects import check_source_objects
from opsdir.domains.webaccess.checks import check_protected_apps
from opsdir_adapter_siteminder.adapter import ADAPTER
from opsdir_adapter_siteminder.agents import dangling, file_concerns
from opsdir_adapter_siteminder.conf import allowed_local, effective, matching, sections, settings
from opsdir_adapter_siteminder.naming import AGENTS, CARRIED, ROUTES, WEB_AGENTS
from opsdir_adapter_siteminder.proxyrules import routes, rules_document
from opsdir_adapter_siteminder.schema import FRAGMENT
import mini_estate
from support import build_directory

HERE = Path(__file__).resolve().parent / "agent-files"
SERVERS_DIR = HERE / "servers"
REGISTRY = registry_ldif((*core_fragments(), FRAGMENT))
AT = dt.datetime(2026, 9, 20, 3, 0, tzinfo=dt.timezone.utc)
ALPHA = "env=prod,cloud=alpha,ou=environments,dc=ciam-ops"
APPS = "ou=protected-applications,dc=ciam-ops"
CREW_WEB, PARTS_GW = f"cn=crew-web-1,{ALPHA}", f"cn=parts-gw-1,{ALPHA}"
CREW_AGENT, PARTS_AGENT = f"cn=crew-agent,{AGENTS}", f"cn=parts-gateway,{AGENTS}"
CREW_APACHE = f"cn=alpha-prod-crew-web-1-crew-apache,{WEB_AGENTS}"
PARTS_HOST = f"cn=alpha-prod-parts-gw-1-parts,{WEB_AGENTS}"
SECRETS = ("crew-host-shared-secret", "local-proxy-password", "gateway-key-passphrase", "parts-host-shared-secret")


def _server(cn, role, version):
    return (f"dn: cn={cn},{ALPHA}\nobjectClass: top\nobjectClass: ciamServer\ncn: {cn}\nciamServerRole: {role}\n"
            f"ciamHostname: {cn}.example.test\nciamSubnet: cn=net,ou=bindings,{ALPHA}\nciamProductVersion: {version}\n")


EXTRA = (
    _server("ps-1", "sm-policy-server", "SiteMinder 12.8.8"),
    _server("crew-web-1", "sm-agent", "SiteMinder Web Agent 12.8.8"),
    _server("parts-gw-1", "sm-access-gateway", "SiteMinder Access Gateway 12.8.8"),
    f"dn: cn=svc-parts,ou=bindings,{ALPHA}\nobjectClass: top\nobjectClass: ciamServiceName\ncn: svc-parts\n"
    "ciamBindingRole: parts-service\nciamFqdn: parts.example.test\nciamTargetRole: sm-access-gateway\nciamPort: 443\n",
    f"dn: cn=parts-app,ou=bindings,{ALPHA}\nobjectClass: top\nobjectClass: ciamExternalHost\ncn: parts-app\n"
    "ciamBindingRole: parts-app\nciamFqdn: parts-app.example.test\n",
)


def _files(base):
    return {str(p.relative_to(base)): p.read_text() for p in sorted(base.rglob("*")) if p.is_file()}


def _record(changes=()):
    return build_directory(REGISTRY, tuple(parse("\n".join((mini_estate.LDIF, *EXTRA)))), changes)


def _import(d, spec, files):
    changes, notices = preview_import(d, spec, files, (ADAPTER,), at=AT)
    return changes, notices


def _export():
    return {"policy-store.xml": (HERE / "policy-store.xml").read_text()}


@pytest.fixture(scope="module")
def exported():
    xps, _ = _import(_record(), "siteminder/xps", _export())
    return xps


@pytest.fixture(scope="module")
def after(exported):
    files, notices = _import(_record(exported), "siteminder/agent-files", _files(SERVERS_DIR))
    return _record((*exported, *files)), notices, files


def test_files_read_as_settings_and_sections():
    assert settings('# c\nA="1"\nB=2\nA="3"\n') == (("A", "1"), ("B", "2"), ("A", "3"))
    root = sections((SERVERS_DIR / "parts-gw-1.example.test" / "server.conf").read_text())
    assert [s.name for s in root.children] == ["Server", "SSL", "ServiceDispatcher", "VirtualHostDefaults",
                                               "VirtualHost"]
    assert root.children[4].children[0].settings == (
        ("sminitfile", "/opt/ca/secure-proxy/proxy-engine/conf/partsagent/WebAgent.conf"),)
    wanted = "proxy-engine/conf/partsagent/WebAgent.conf"
    assert matching(("a/WebAgent.conf", wanted), "C:\\CA\\proxy-engine\\conf\\partsagent\\WebAgent.conf") == wanted
    central = (("IgnoreUrl", "/a"), ("AllowLocalConfig", "IgnoreUrl"))
    assert effective(central, (("IgnoreUrl", "/b"), ("CookieDomain", "x")), allowed_local(central)) == (
        ("AllowLocalConfig", "IgnoreUrl"), ("IgnoreUrl", "/b"))
    assert effective((), (("IgnoreUrl", "/b"),), allowed_local(())) == ()           # no ACO says yes: none


def test_proxy_rules_become_ordered_routes():
    root, why = rules_document((SERVERS_DIR / "parts-gw-1.example.test/proxy-engine/conf/proxyrules.xml").read_text())
    assert why is None
    found, notices = routes(root)
    assert [(r.conditions, r.action, r.target) for r in found] == [
        (("host equals parts.example.test", "uri beginswith /parts"), "forward", "http://parts-app.example.test:8080$0"),
        (("host equals parts.example.test", "uri beginswith /legacy"), "forward",
         "http://legacy-app.example.test:8080/old$1"),
        (("host equals parts.example.test", "uri beginswith /search", "query contains q="), "forward",
         "http://search.example.test$0"),
        (("host equals parts.example.test", "uri beginswith /search"), "redirect", "https://parts.example.test/parts/"),
        (("host equals parts.example.test",), "forward", "https://www-app.example.test$0"),
        ((), "redirect", "https://www.example.test/")]
    assert found[4].filter == "com.example.HeaderFilter" and notices == ()
    regex = ('<nete:proxyrules xmlns:nete="urn:x"><nete:xprcond type="uri"><nete:xpr><nete:rule>^/docs/(.*)'
             '</nete:rule><nete:result>http://docs:8080/$1</nete:result></nete:xpr><nete:xpr-default>http://www$0'
             '</nete:xpr-default></nete:xprcond></nete:proxyrules>')
    assert [(r.conditions, r.target) for r in routes(rules_document(regex)[0])[0]] == [
        (("uri regex ^/docs/(.*)",), "http://docs:8080/$1"), ((), "http://www$0")]


@pytest.mark.parametrize("head, accepted", [
    ('<!DOCTYPE nete:proxyrules SYSTEM "file:/opt/dtd/proxyrules.dtd">', True),
    ('<!DOCTYPE nete:proxyrules PUBLIC "-//CA//proxyrules" "proxyrules.dtd">', True),
    ('<!DOCTYPE nete:proxyrules SYSTEM "x.dtd" [<!ENTITY e "boom">]>', False),        # an internal subset
    ('<!DOCTYPE nete:proxyrules SYSTEM "a.dtd"><!DOCTYPE nete:proxyrules SYSTEM "b.dtd">', False),
    ('<!DOCTYPE other SYSTEM "x.dtd">', False),
    ('<!ENTITY e SYSTEM "file:///etc/passwd">', False)])
def test_only_one_external_proxy_rules_doctype_is_stripped(head, accepted):
    text = f'<?xml version="1.0"?>\n{head}\n<nete:proxyrules xmlns:nete="urn:x"><nete:forward>http://a$0' \
           '</nete:forward></nete:proxyrules>'
    root, why = rules_document(text)
    assert (root is not None) == accepted and (why is None) == accepted
    if not accepted:
        assert "refused" in why or "not XML" in why


def test_web_agent_instances_name_their_servers_and_what_their_files_name(after):
    d, notices, _ = after
    crew = get(d, CREW_APACHE)
    assert one(crew, "smServer") == CREW_WEB and children(d, CREW_WEB) == ()      # nothing below the server
    assert (one(crew, "smEnabled"), values(crew, "smActsAs"), one(crew, "smAgentConfig"), one(crew, "smHostConfig"),
            one(crew, "smTrustedHost"), values(crew, "smPolicyServer")) == (
        "TRUE", (CREW_AGENT,), f"cn=aco-crew-aco,{CARRIED}", f"cn=hco-default-hco,{CARRIED}",
        f"cn=trusted-host-crew-web-1,{CARRIED}", (f"cn=ps-1,{ALPHA}",))
    assert any("crew-web-1/crew-apache: its policy server 10.9.9.9 isn't a server of role sm-policy-server" in n
               for n in notices)
    assert any("crew-web-1/crew-apache: LocalConfig.conf sets CookieDomain, DefaultPassword, which ACO crew-aco "
               "doesn't allow local configuration of" in n for n in notices)
    parts = get(d, PARTS_HOST)
    assert (values(parts, "smActsAs"), values(parts, "smVirtualHost"), one(parts, "smTrustedHost")) == (
        (PARTS_AGENT,), ("parts.example.test",), f"cn=trusted-host-parts-gw-1,{CARRIED}")
    assert values(parts, "smPolicyServer") == ()          # 10.0.1.5 isn't ps-1's address


def test_secrets_are_withheld_whole_and_their_presence_recorded(after):
    d, notices, changes = after
    text = repr(changes)
    assert not any(s in text for s in SECRETS)
    crew = get(d, CREW_APACHE)
    assert values(crew, "smWithheld") == (
        "SmHost.conf: sharedsecret: the shared secret an agent or trusted host signs its requests with; re-provision "
        "in the target",
        "LocalConfig.conf: DefaultPassword: the password of the account an IIS agent proxies requests as "
        "(DefaultUserName); re-provision in the target")
    assert "sharedsecrettime" in one(crew, "smConfig")              # a time, not a secret
    parts = get(d, PARTS_HOST)
    assert any(w.startswith("server.conf: ClientPassPhrase:") for w in values(parts, "smWithheld"))
    assert any(n.startswith("4 sensitive setting(s) withheld, never stored") for n in notices)


def test_gateway_routes_are_stored_in_order(after):
    d, _, _ = after
    found = sorted(children(d, ROUTES, "smRoute"), key=lambda r: int(one(r, "ciamOrder")))
    assert {one(r, "smServer") for r in found} == {PARTS_GW}
    assert [(one(r, "cn"), one(r, "smRouteAction"), one(r, "smRouteTarget")) for r in found][:2] == [
        ("alpha-prod-parts-gw-1-route-1", "forward", "http://parts-app.example.test:8080$0"),
        ("alpha-prod-parts-gw-1-route-2", "forward", "http://legacy-app.example.test:8080/old$1")]
    assert values(found[0], "smCondition") == ("host equals parts.example.test", "uri beginswith /parts")
    assert len(found) == 6 and '"filter"' in one(found[4], "smConfig")


def test_ignored_extensions_and_urls_become_unprotected_resources(exported, after):
    before = _record(exported)                               # the ACO alone: its IgnoreUrl /crew/health
    crew = f"cn=portal-crew,{APPS}"
    assert {one(r, "cn"): (values(r, "ciamPathPattern"), one(r, "ciamAccessMode"))
            for r in children(before, crew, "ciamPathResource")} == {
        "crew-pages": (("/*",), "standard"), "ignored-ext-gif": (("/*.gif",), "unprotected"),
        "ignored-ext-css": (("/*.css",), "unprotected"), "ignored-url-crew-health": (("/health",), "unprotected")}
    d, _, _ = after                                          # its LocalConfig.conf may set IgnoreUrl: /crew/status
    found = {one(r, "cn"): r for r in children(d, crew, "ciamPathResource")}
    assert set(found) == {"crew-pages", "ignored-ext-gif", "ignored-ext-css", "ignored-url-crew-status"}
    status = found["ignored-url-crew-status"]
    assert (values(status, "ciamPathPattern"), one(status, "ciamMatchKind"), one(status, "ciamProjectedFrom")) == (
        ("/status",), "wildcard", CREW_AGENT)


def test_a_gateway_application_takes_its_backend_and_names_from_its_routes(after):
    d, notices, _ = after
    parts = get(d, f"cn=portal-parts,{APPS}")
    assert (one(parts, "ciamBackendRole"), one(parts, "ciamBackendPort"), one(parts, "ciamBackendTls"),
            values(parts, "ciamPublishedAs"), one(parts, "ciamEnforcedByRole")) == (
        "parts-app", "8080", "FALSE", ("parts-service",), "sm-access-gateway")


def test_routes_no_realm_covers_become_unprotected_applications(after):
    d, notices, _ = after
    legacy = get(d, f"cn=parts-gateway-route-2,{APPS}")
    assert (one(legacy, "ciamBasePath"), one(legacy, "ciamSignOn"), one(legacy, "ciamEnforcedByRole"),
            one(legacy, "ciamBackendPort"), one(legacy, "ciamProjectedFrom")) == (
        "/legacy", "none", "sm-access-gateway", "8080", f"cn=alpha-prod-parts-gw-1-route-2,{ROUTES}")
    (all_,) = children(d, legacy.dn, "ciamPathResource")
    assert (values(all_, "ciamPathPattern"), one(all_, "ciamAccessMode")) == (("/*",), "unprotected")
    rest = get(d, f"cn=parts-gateway-route-5,{APPS}")
    assert (one(rest, "ciamBasePath"), one(rest, "ciamBackendTls"), one(rest, "ciamBackendPort")) == (
        "/", "TRUE", "443")
    assert get(d, f"cn=parts-gateway-route-1,{APPS}") is None              # the parts realm covers it
    assert any("route parts-gw-1/route-3" in n and "can't place" in n for n in notices)
    assert any("route parts-gw-1/route-6" in n and "redirects to https://www.example.test/" in n for n in notices)
    assert "protected application parts-gateway-route-2: its backend host legacy-app.example.test isn't in the " \
           "record (a service name, an external host or a server): record its role" in notices


def test_a_route_sending_another_path_is_a_blocking_rewrite(after):
    d, _, _ = after
    rewrite = get(d, f"cn=rewrite-parts-gateway-route-2,{CARRIED}")
    assert (one(rewrite, "ciamHandling"), one(rewrite, "ciamBlocking"), values(rewrite, "ciamConcerns"),
            one(rewrite, "ciamTargetRole")) == ("rebuild", "TRUE", (f"cn=parts-gateway-route-2,{APPS}",),
                                                 "sm-access-gateway")
    assert "Path /legacy -> /old" in values(rewrite, "ciamSourceFact")


def test_source_objects_concern_the_servers_and_routing_is_dropped(exported, after):
    assert get(_record(exported), f"cn=routing-parts-gateway,{CARRIED}") is not None
    d, notices, _ = after
    assert get(d, f"cn=routing-parts-gateway,{CARRIED}") is None
    assert values(get(d, f"cn=hco-default-hco,{CARRIED}"), "ciamConcerns") == (CREW_WEB, PARTS_GW)
    assert values(get(d, f"cn=aco-crew-aco,{CARRIED}"), "ciamConcerns") == (CREW_WEB,)
    assert values(get(d, f"cn=trusted-host-crew-web-1,{CARRIED}"), "ciamConcerns") == (CREW_WEB,)
    assert any(n.startswith("trusted host old-web: no server's SmHost.conf in the record names it") for n in notices)


def test_a_re_import_of_the_files_or_the_export_changes_nothing(after):
    d, _, _ = after
    assert _import(d, "siteminder/agent-files", _files(SERVERS_DIR))[0] == ()
    assert _import(d, "siteminder/xps", _export())[0] == ()


def test_a_server_the_record_no_longer_holds_is_reported_not_linked(after):
    d, _, _ = after
    gone = d._replace(entries=MappingProxyType({k: e for k, e in d.entries.items() if k != norm_dn(CREW_WEB)}))
    assert dangling(gone) == (f"alpha-prod-crew-web-1-crew-apache: its server {CREW_WEB} isn't in the record: import "
                              "that server's files again under its new name, or remove the entry",)
    assert values(get(gone, f"cn=hco-default-hco,{CARRIED}"), "ciamConcerns") == (CREW_WEB, PARTS_GW)   # as recorded
    assert file_concerns(gone, f"cn=hco-default-hco,{CARRIED}") == (PARTS_GW,)


def test_folders_that_are_no_siteminder_server_are_named():
    d = _record()
    _, notices = _import(d, "siteminder/agent-files", {"nobody.example.test/WebAgent.conf": 'EnableWebAgent="YES"\n'})
    assert notices[0].startswith("nobody.example.test: no SiteMinder agent or Access Gateway server in the record")
    assert _import(d, "siteminder/agent-files", {"WebAgent.conf": ""})[1][0].startswith("no server folders")


def _ctx(d):
    return PlanContext(d, env_model(d, "alpha/prod"), env_model(d, "beta/prod"), dt.date(2026, 11, 1),
                       dt.date(2026, 10, 1), {}, {}, ())


def test_a_target_without_the_gateway_is_blocked_by_the_core_checks(after):
    d, _, _ = after
    apps = [b[1].split("`")[1] for b in check_protected_apps(_ctx(d)).blockers]
    assert {"portal-parts", "parts-gateway-route-2", "parts-gateway-route-5"} <= set(apps)
    blockers = check_source_objects(_ctx(d)).blockers
    assert any("rewrite-parts-gateway-route-2" in b[1] for b in blockers)
    assert not any("routing-parts-gateway" in b[1] for b in blockers)

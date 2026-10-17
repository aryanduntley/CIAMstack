"""Per-firewall delivery (milestone 106): a Panorama's device-group hierarchy (ancestors' rules and objects), the
device group's firewalls with the policy pushed to each and its hit counts, read into managed firewalls and rule
observations; the rule's state as their rollup; what the core's check says of them; API answers lacking a part make
the read incomplete; names in xpaths can't break out; the collector's later steps."""
import datetime as dt
from urllib.parse import parse_qs, urlparse

from opsdir.core.contract import PlanContext
from opsdir.core.directory import get, one, values
from opsdir.core.environment import env_model, of_class
from opsdir.domains.infrastructure.running import check_firewall_running, firewall_running_rows
from opsdir_adapter_panos.collect import running_steps
from opsdir_adapter_panos.importer import read_running_config
from opsdir_adapter_panos.rules import marker, rule_name
from opsdir_adapter_panos.running import literal, read_running, xpath
from edge_samples import appliance
from network_fixtures import ALPHA, entry, model, rule
from support import after_import

SERVERS = tuple(entry(ALPHA, n, "ciamServer", ciamServerRole="app", ciamHostname=f"{n}.example.test",
                      ciamPrivateIp=ip, ciamSubnet=f"cn=subnet-ds,ou=bindings,{ALPHA}")
                for n, ip in (("app-1", "10.1.1.21"), ("app-2", "10.1.1.22")))
RULES = (rule(ALPHA, "fw-app", "10.1.2.0/24", "8443", "app"), rule(ALPHA, "fw-admin", "10.9.0.0/28", "22", "app"),
         rule(ALPHA, "fw-gone", "10.8.0.0/16", "4444", "app"))
PANO = appliance("pano", "network-firewall", "pano.example.test", "DG")
SPEC = "alpha/prod"


def _model(*extra):
    return model(alpha=(*SERVERS, *RULES, *PANO, *extra))


def _answer(holder, body):
    return f'<response status="success" code="19"><result count="1"><{holder}>{body}</{holder}></result></response>'


def _source():
    return (entry(ALPHA, "panos-read", "ciamCollectionSource", ciamBindingRole="panos-read",
                  ciamImporter="panos/running-config", ciamSourceRef="https://pano.example.test",
                  ciamCredentialRole="pano-api-key", ciamCredentialScheme="api-key"),
            entry(ALPHA, "pano-api-key", "ciamSecretRef", ciamBindingRole="pano-api-key",
                  ciamRefUri="vault://secret/ciam/pano-api"))

NOW = dt.datetime(2026, 10, 17, tzinfo=dt.timezone.utc)
OBJECT_FAMILIES = ("address", "address-group", "service", "service-group")


def _epoch(days_ago):
    return str(int((NOW - dt.timedelta(days=days_ago)).timestamp()))


def _rule(m, r, extra=""):
    return (f'<entry name="{rule_name(m, r)}"><source><member>parent-net</member></source><destination>'
            "<member>10.1.1.21</member><member>10.1.1.22</member></destination><service><member>svc</member>"
            f"</service><action>allow</action>{extra}<description>{marker(m)} {one(r, 'cn')} -> role app"
            "</description></entry>")


def _config(m, pushed_to=("S1", "S2"), disabled_on=(), hits=None, hierarchy=True, drop=None):
    """API answers of Panorama 'pano' (device group DG under Parent) with the environment's rules in DG's
    pre-rulebase, their objects in Parent, and the policy pushed to the firewalls pushed_to."""
    held = of_class(m, "ciamFirewallRule")
    rules = "".join(_rule(m, r) for r in held if one(r, "cn") != "fw-gone")
    empty = '<response status="success" code="7"><result/></response>'
    parent_objects = {"address": '<entry name="parent-net"><ip-netmask>10.1.2.0/24</ip-netmask></entry>',
                      "service": '<entry name="svc"><protocol><tcp><port>8443</port></tcp></protocol></entry>'}
    files = {
        "api/device-group/DG/pre-rulebase.xml": _answer("rules", rules),
        "api/device-group/DG/devices.xml": _answer("devices", '<entry name="S1"><vsys><entry name="vsys1"/></vsys>'
                                                   '</entry><entry name="S2"/>'),
        **{f"api/device-group/Parent/{f}.xml": _answer(f, parent_objects[f]) if f in parent_objects else empty
           for f in ("pre-rulebase", "post-rulebase", *OBJECT_FAMILIES)},
        **{f"api/{scope}/{f}.xml": empty for scope in ("device-group/DG", "shared")
           for f in ("pre-rulebase", "post-rulebase", *OBJECT_FAMILIES)
           if f"api/{scope}/{f}.xml" not in ("api/device-group/DG/pre-rulebase.xml",)},
        "api/op/devices.xml": _answer("devices", '<entry name="S1"><hostname>fw-a</hostname><connected>yes</connected>'
                                      '<sw-version>11.2.15</sw-version><ha><state>active</state><peer><serial>S2'
                                      '</serial></peer></ha><vsys><entry name="vsys1"><shared-policy-status>In Sync'
                                      '</shared-policy-status></entry></vsys></entry><entry name="S2"><hostname>fw-b'
                                      '</hostname><connected>no</connected><sw-version>11.2.15</sw-version></entry>'),
        **({"api/op/dg-hierarchy.xml": '<response status="success"><result><dg-hierarchy><dg name="Parent">'
                                       '<dg name="DG"/></dg></dg-hierarchy></result></response>'} if hierarchy else {})}
    for serial in pushed_to:
        pushed = "".join(_rule(m, r, "<disabled>yes</disabled>" if serial in disabled_on else "")
                         for r in held if one(r, "cn") == "fw-app" or serial == "S1")
        files[f"api/firewall/{serial}/vsys1/pre-rulebase.xml"] = _answer("rules", pushed)
        files[f"api/firewall/{serial}/vsys1/post-rulebase.xml"] = empty
        counts = (hits or {}).get(serial, {})
        files[f"api/firewall/{serial}/vsys1/hit-count.xml"] = (
            '<response status="success"><result><rule-hit-count><vsys><entry name="vsys1"><rule-base><entry '
            'name="security"><rules>' + "".join(
                f'<entry name="{rule_name(m, r)}"><hit-count>{n}</hit-count><last-hit-timestamp>'
                f'{_epoch(1) if n else 0}</last-hit-timestamp><rule-creation-timestamp>{_epoch(age)}'
                "</rule-creation-timestamp><last-reset-timestamp>0</last-reset-timestamp></entry>"
                for r in held for n, age in (counts.get(one(r, "cn"), (0, 200)),)) +
            "</rules></entry></rule-base></entry></vsys></rule-hit-count></result></response>")
    if drop:
        files.pop(drop)
    return {f"{SPEC}/pano/{p}": t for p, t in files.items()}


def _imported(files):
    d, m, _ = _model()
    return after_import(d, read_running_config(files, d, ())), m


def _check(d):
    m = env_model(d, SPEC)
    return check_firewall_running(PlanContext(d, m, m, None, NOW.date(), {}, {}, ()))


def test_ancestors_resolve_objects_and_every_firewall_running_a_rule_rolls_up_to_deployed():
    d, m = _imported(_config(_model()[1]))
    app = get(d, f"cn=fw-app,ou=bindings,{m.dn}")
    assert one(app, "ciamRunningState") == "deployed"
    assert values(app, "ciamSourceCidr") == ("10.1.2.0/24",) and not values(app, "ciamRunningFact")   # Parent's
    s1 = get(d, f"cn=S1,{get(d, f'cn=pano,ou=bindings,{m.dn}').dn}")
    assert (one(s1, "ciamDeviceName"), one(s1, "ciamDeviceConnected"), one(s1, "ciamHaState"),
            one(s1, "ciamPolicySync"), values(s1, "ciamDeviceContext")) == (
        "fw-a", "TRUE", "active, peer S2", "In Sync", ("vsys1",))
    obs = get(d, f"cn=fw-app/vsys1,{s1.dn}")
    assert one(obs, "ciamRunningState") == "deployed" and one(obs, "ciamHitCount") == "0"


def test_a_rule_some_firewalls_dont_run_is_partial_and_named():
    d, m = _imported(_config(_model()[1]))
    admin = get(d, f"cn=fw-admin,ou=bindings,{m.dn}")                 # pushed to S1 only
    assert one(admin, "ciamRunningState") == "partial"
    texts = [a[1] for a in _check(d).actions]
    assert any("`fw-admin` in alpha/prod runs on 1 of the 2 firewalls" in t and "missing on S2/vsys1" in t
               for t in texts)
    assert any("`S2` (fw-b behind `pano`, alpha/prod) isn't connected to its manager" in t for t in texts)


def test_a_rule_disabled_on_every_firewall_rolls_up_to_disabled():
    d, m = _imported(_config(_model()[1], pushed_to=("S1",), disabled_on=("S1",)))
    assert one(get(d, f"cn=fw-app,ou=bindings,{m.dn}"), "ciamRunningState") == "disabled"


def test_a_rule_no_firewall_hit_for_the_window_is_an_action_and_a_used_or_young_one_isnt():
    d, _ = _imported(_config(_model()[1], hits={"S1": {"fw-app": (12, 200)}, "S2": {"fw-app": (0, 200)}}))
    texts = [a[1] for a in _check(d).actions]
    assert not any("`fw-app`" in t and "no hits" in t for t in texts)
    assert any("`fw-admin` in alpha/prod has no hits on any of the 1 firewall(s) running it since" in t for t in texts)
    d, _ = _imported(_config(_model()[1], hits={"S1": {"fw-admin": (0, 30)}}))
    assert not any("`fw-admin`" in a[1] and "no hits" in a[1] for a in _check(d).actions)


def test_the_report_lists_firewalls_and_observations():
    d, _ = _imported(_config(_model()[1], hits={"S1": {"fw-app": (12, 200)}}))
    rows = {r[1]: r for r in firewall_running_rows(d)}
    assert rows["pano/S1"][2:4] == ("firewall", "fw-a, connected, In Sync, 11.2.15, active, peer S2, vsys1")
    assert rows["fw-app @ S1/vsys1"][2] == "deployed" and rows["fw-app @ S1/vsys1"][3].startswith("hits 12, since ")


def test_answers_lacking_an_expected_part_read_nothing():
    d, m, _ = _model()
    imported = read_running_config(_config(m, drop="api/device-group/Parent/address.xml"), d, ())
    assert not imported.groups
    assert any("api/device-group/Parent/address.xml: not in the answers" in n for n in imported.notices)


def test_without_the_hierarchy_ancestors_arent_read_and_older_exports_still_read():
    d, m = _imported(_config(_model()[1], hierarchy=False))
    app = get(d, f"cn=fw-app,ou=bindings,{m.dn}")
    assert any(f.startswith("source parent-net") for f in values(app, "ciamRunningFact"))
    run, _ = read_running({"api/device-group/DG/pre-rulebase.xml": _answer("rules", "")})
    assert run.parents is None and run.devices == {} and run.pushed == {}


def test_names_in_xpaths_are_literals():
    assert literal("DG") == "'DG'" and literal("it's") == '"it\'s"'
    assert literal("a'b\"c") == "concat('a', \"'\", 'b\"c')"
    assert xpath("device-group/x']|//*['", "address").count("\"x']|//*['\"") == 1


def test_the_collector_reads_ancestors_and_each_firewall_once_their_names_are_known():
    d, m, _ = _model(*_source())
    first = dict(running_steps(d, m, {}, {}))
    done = {p: "" for p in first}
    done[f"{SPEC}/pano/api/op/dg-hierarchy.xml"] = ('<response status="success"><result><dg-hierarchy><dg '
                                                    'name="Parent"><dg name="DG"/></dg></dg-hierarchy></result>'
                                                    "</response>")
    done[f"{SPEC}/pano/api/device-group/DG/devices.xml"] = _answer("devices", '<entry name="S1"/>')
    later = dict(running_steps(d, m, done, {}))
    assert f"{SPEC}/pano/api/device-group/Parent/address.xml" in later
    pushed = later[f"{SPEC}/pano/api/firewall/S1/vsys1/pre-rulebase.xml"]
    q = parse_qs(urlparse(pushed.url).query)
    assert (q["type"], q["action"], q["target"]) == (["config"], ["show"], ["S1"])
    assert q["xpath"] == ["/config/panorama/vsys/entry[@name='vsys1']/pre-rulebase/security/rules"]
    hits = parse_qs(urlparse(later[f"{SPEC}/pano/api/firewall/S1/vsys1/hit-count.xml"].url).query)
    assert hits["type"] == ["op"] and hits["target"] == ["S1"] and "<rule-hit-count>" in hits["cmd"][0]
    assert not any("commit" in r.url or "action=set" in r.url or "action=edit" in r.url for r in later.values())

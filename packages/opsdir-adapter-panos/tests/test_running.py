"""The read-back (milestone 6.2c): a Panorama's or firewall's running configuration, as a snapshot or the XML API's
action=show answers, read against the record's firewall rules: what matches by marker or name, what is read into the
rule (a difference is a conflict), what is observed (state, facts), what the appliance runs that the record doesn't,
the external allowlists it holds; the collector's read-only requests; the render's round trip."""
from urllib.parse import parse_qs, urlparse

from opsdir.connectors import importing
from opsdir.connectors.registry import ADAPTERS, services
from opsdir.connectors.roundtrip import read_back
from opsdir_adapter_panos.collect import KEY_HEADER, SCHEME, running_steps, source_problems
from opsdir_adapter_panos.importer import read_running_config
from opsdir_adapter_panos.readback import running_config
from opsdir_adapter_panos.render import render
from opsdir_adapter_panos.rules import objects
from opsdir_adapter_panos.running import read_running, resolve_addresses, resolve_services, xpath
from edge_samples import appliance
from network_fixtures import ALPHA, entry, model, rule

SERVERS = tuple(entry(ALPHA, n, "ciamServer", ciamServerRole="app", ciamHostname=f"{n}.example.test",
                      ciamPrivateIp=ip, ciamSubnet=f"cn=subnet-ds,ou=bindings,{ALPHA}")
                for n, ip in (("app-1", "10.1.1.21"), ("app-2", "10.1.1.22")))
RULES = (rule(ALPHA, "fw-app", "10.1.2.0/24", "8443", "app"), rule(ALPHA, "fw-admin", "10.9.0.0/28", "22", "app"),
         rule(ALPHA, "fw-gone", "10.8.0.0/16", "4444", "app"))
PANO = appliance("pano", "network-firewall", "pano.example.test", "DG")
SPEC = "alpha/prod"


def _model(*extra, tree=()):
    return model(alpha=(*SERVERS, *RULES, *PANO, *extra), tree=tree)


def _pushed(m):
    """What a push of environment m's render leaves on a Panorama's device group DG: {path: text}."""
    return {f"{SPEC}/pano/running-config.xml": running_config({"ciam_panos_device_group": "DG"}, objects(m))}


def _plan(d, files):
    return importing.import_plan(d, "panos/running-config", files)


def _changed(plan):
    return {c.dn.split(",", 1)[0][3:]: {a: v for _, a, v in c.mods} for c in plan.changes if c.changetype == "modify"}


# ------------------------------------------------------------------ reading the running configuration
def _members(tag, names):
    return f"<{tag}>{''.join(f'<member>{n}</member>' for n in names)}</{tag}>"


def _rule_xml(name, sources, destinations, services_, description, extra=""):
    return (f'<entry name="{name}" uuid="u-{name}">{_members("source", sources)}'
            f"{_members('destination', destinations)}{_members('service', services_)}<action>allow</action>{extra}"
            f"<description>{description}</description></entry>")


OBJECTS = ('<address><entry name="net-a"><ip-netmask>10.1.2.0/24</ip-netmask></entry>'
           '<entry name="host-b"><ip-netmask>10.1.1.21</ip-netmask></entry>'
           '<entry name="range-c"><ip-range>10.1.3.1-10.1.3.9</ip-range></entry>'
           '<entry name="name-d"><fqdn>d.example.test</fqdn></entry></address>'
           '<address-group><entry name="grp"><static><member>net-a</member><member>inner</member></static></entry>'
           '<entry name="inner"><static><member>host-b</member><member>10.7.0.0/16</member></static></entry>'
           '<entry name="loop"><static><member>loop</member></static></entry>'
           '<entry name="dyn"><dynamic><filter>\'app\'</filter></dynamic></entry></address-group>'
           '<service><entry name="https"><protocol><tcp><port>443,8443</port></tcp></protocol></entry>'
           '<entry name="dns"><protocol><udp><port>53</port></udp></protocol></entry>'
           '<entry name="high"><protocol><tcp><port>1000-2000</port></tcp></protocol></entry></service>'
           '<service-group><entry name="svcs"><members><member>https</member><member>dns</member></members></entry>'
           '</service-group>')
SHARED = '<shared><address><entry name="shared-e"><ip-netmask>192.0.2.0/24</ip-netmask></entry></address></shared>'


def _snapshot(rules="", post="", shared=SHARED):
    return (f"<config version=\"11.1.0\">{shared}<devices><entry name=\"localhost.localdomain\"><device-group>"
            f"<entry name=\"DG\"><pre-rulebase><security><rules>{rules}</rules></security></pre-rulebase>"
            f"<post-rulebase><security><rules>{post}</rules></security></post-rulebase>{OBJECTS}</entry>"
            "</device-group></entry></devices></config>")


def _answer(holder, body):
    return f'<response status="success" code="19"><result count="1"><{holder}>{body}</{holder}></result></response>'


def test_a_snapshot_and_the_api_answers_read_the_same():
    rules = _rule_xml("r1", ("grp",), ("host-b",), ("https",), "x")
    snap, notices = read_running({"running-config.xml": _snapshot(rules)})
    parts = {tag: OBJECTS.split(f"<{tag}>", 1)[1].split(f"</{tag}>", 1)[0]
             for tag in ("address", "address-group", "service", "service-group")}
    api, api_notices = read_running({
        "api/device-group/DG/pre-rulebase.xml": _answer("rules", rules),
        "api/device-group/DG/post-rulebase.xml": '<response status="success" code="7"><result/></response>',
        **{f"api/device-group/DG/{tag}.xml": _answer(tag, body) for tag, body in parts.items()},
        "api/shared/address.xml": _answer("address", SHARED.split("<address>")[1].split("</address>")[0])})
    assert (notices, api_notices) == ((), ())
    assert snap.scopes == api.scopes and snap.rules == api.rules and snap.version == "11.1.0"
    (r,) = snap.rules[("device-group/DG", "pre-rulebase")]
    assert (r.name, r.uuid, r.sources, r.destinations, r.services, r.action, r.disabled, r.log_end) == (
        "r1", "u-r1", ("grp",), ("host-b",), ("https",), "allow", False, None)


def test_what_isnt_running_evidence_is_refused():
    assert read_running({"running-config.xml": '<!DOCTYPE x [<!ENTITY a "b">]><config/>'})[0] is None
    assert read_running({"running-config.xml": "<response/>"})[0] is None              # not a <config> document
    failed, notices = read_running({"api/device-group/DG/address.xml": _answer("address", ""),
                                    "api/device-group/DG/pre-rulebase.xml":
                                        '<response status="error"><msg>no</msg></response>'})
    assert failed is None and any("incomplete" in n for n in notices)                 # never half a read
    assert read_running({"api/somewhere/else.xml": _answer("rules", "")})[0] is None
    assert read_running({})[0] is None


def test_addresses_resolve_through_objects_groups_and_shared_and_the_rest_is_named():
    run, _ = read_running({"running-config.xml": _snapshot()})
    scope = "device-group/DG"
    assert resolve_addresses(run, scope, ("grp", "10.5.5.5", "shared-e")) == (
        ("10.1.1.21/32", "10.1.2.0/24", "10.5.5.5/32", "10.7.0.0/16", "192.0.2.0/24"), ())
    assert resolve_addresses(run, scope, ("any",)) == (("0.0.0.0/0", "::/0"), ())
    cidrs, named = resolve_addresses(run, scope, ("range-c", "name-d", "dyn", "loop", "nowhere"))
    assert cidrs == () and named == ("range-c (ip-range 10.1.3.1-10.1.3.9)", "name-d (fqdn d.example.test)",
                                     "dyn (dynamic group 'app')", "loop (group cycle)", "nowhere (not in the export)")


def test_services_resolve_to_protocol_and_port_and_the_rest_is_named():
    run, _ = read_running({"running-config.xml": _snapshot()})
    scope = "device-group/DG"
    assert resolve_services(run, scope, ("svcs",)) == ((("tcp", "443"), ("tcp", "8443"), ("udp", "53")), ())
    assert resolve_services(run, scope, ("application-default", "high", "service-https")) == (
        (), ("application-default", "high (tcp/1000-2000)",
             "service-https (not in the export: predefined or another scope's)"))


# ------------------------------------------------------------------ the read-back against the record
def test_what_a_push_leaves_running_reads_back_as_committed_and_nothing_else():
    d, m, _ = _model()
    plan = _plan(d, _pushed(m))
    assert plan.conflicts == ()
    assert _changed(plan) == {cn: {"ciamRunningState": ("committed",)} for cn in ("fw-app", "fw-admin", "fw-gone")}


def _drifted(m):
    """The push with drift: fw-admin's source widened, fw-app's logging off and a third destination, fw-gone gone,
    an unmarked allow to app-1, a marked rule the record lacks, another environment's rule, a name-matched rule with
    its description edited moved to the post-rulebase... as a snapshot."""
    found = objects(m)
    rules = {r["rule_name"]: r for r in found["rules"]}
    app, admin = rules["opsdir-alpha-prod-fw-app"], rules["opsdir-alpha-prod-fw-admin"]
    pre = "".join((
        _rule_xml(app["rule_name"], app["source_ip"], (*app["destination_ip"], "10.1.1.99"), app["service"],
                  app["description"], "<log-end>no</log-end><negate-source>yes</negate-source>"),
        _rule_xml("vendor-tmp", ("192.0.2.0/24",), ("opsdir-alpha-prod-app-1",), ("opsdir-tcp-8443",), "vendor"),
        _rule_xml("opsdir-alpha-prod-fw-old", ("10.1.2.0/24",), ("opsdir-alpha-prod-app-2",), ("opsdir-tcp-8443",),
                  "opsdir alpha/prod: fw-old -&gt; role app"),
        _rule_xml("opsdir-beta-prod-fw-app", ("10.1.2.0/24",), ("10.1.1.21",), ("opsdir-tcp-8443",),
                  "opsdir beta/prod: fw-app -&gt; role app"),
        _rule_xml("corp-unrelated", ("any",), ("10.200.0.0/16",), ("any",), "not ours")))
    post = _rule_xml(admin["rule_name"], ("wide",), admin["destination_ip"], admin["service"], "edited by hand",
                     "<disabled>yes</disabled>")
    objs = "".join(f'<entry name="{a["name"]}"><ip-netmask>{a["value"]}</ip-netmask></entry>'
                   for a in found["addresses"]) + '<entry name="wide"><ip-netmask>10.9.0.0/24</ip-netmask></entry>'
    svcs = "".join(f'<entry name="{s["name"]}"><protocol><tcp><port>{s["destination_port"]}</port></tcp></protocol>'
                   "</entry>" for s in found["services"])
    return (f'<config><devices><entry name="localhost.localdomain"><device-group><entry name="DG">'
            f"<pre-rulebase><security><rules>{pre}</rules></security></pre-rulebase>"
            f"<post-rulebase><security><rules>{post}</rules></security></post-rulebase>"
            f"<address>{objs}</address><service>{svcs}</service></entry></device-group></entry></devices></config>")


def test_drift_is_read_into_the_rule_observed_and_named_on_the_appliance():
    d, m, _ = _model()
    plan = _plan(d, {f"{SPEC}/pano/running-config.xml": _drifted(m)})
    changed = _changed(plan)
    assert [(c.key.split(",", 1)[0], c.held, c.live) for c in plan.conflicts] == [
        ("cn=fw-admin", ("10.9.0.0/28",), ("10.9.0.0/24",))]                           # out of band: take or keep
    assert changed["fw-admin"]["ciamRunningState"] == ("disabled",)
    assert changed["fw-admin"]["ciamRunningFact"] == ("description edited by hand", "rulebase device-group/DG "
                                                      "post-rulebase")                  # matched by its name
    assert changed["fw-app"] == {"ciamRunningState": ("committed",), "ciamRunningFact": (
        "destination 10.1.1.21/32, 10.1.1.22/32, 10.1.1.99/32", "log-end no", "negate-source yes")}
    assert changed["fw-gone"] == {"ciamRunningState": ("missing",)}
    (unrecorded,) = changed["pano"].values()
    assert unrecorded == ("device-group/DG pre-rulebase opsdir-alpha-prod-fw-old: 10.1.2.0/24 -> "
                          "opsdir-alpha-prod-app-2 opsdir-tcp-8443",
                          "device-group/DG pre-rulebase vendor-tmp: 192.0.2.0/24 -> opsdir-alpha-prod-app-1 "
                          "opsdir-tcp-8443")                         # not beta's rule, not the unrelated one
    assert any("fw-gone isn't in the running configuration read (missing)" in n for n in plan.notices)


def test_a_firewall_deploys_and_a_source_it_cant_resolve_leaves_the_record_as_it_is():
    d, m, _ = _model(*appliance("fw-1", "network-firewall", "fw-1.example.test", "vsys2"))
    found = objects(m)
    rules = "".join(_rule_xml(r["rule_name"], ("dyn-src",) if "fw-app" in r["rule_name"] else r["source_ip"],
                              r["destination_ip"], r["service"], r["description"]) for r in found["rules"])
    objs = "".join(f'<entry name="{a["name"]}"><ip-netmask>{a["value"]}</ip-netmask></entry>'
                   for a in found["addresses"])
    svcs = "".join(f'<entry name="{s["name"]}"><protocol><tcp><port>{s["destination_port"]}</port></tcp></protocol>'
                   "</entry>" for s in found["services"])
    text = (f'<config><devices><entry name="localhost.localdomain"><vsys><entry name="vsys2"><rulebase><security>'
            f"<rules>{rules}</rules></security></rulebase><address>{objs}</address>"
            f'<address-group><entry name="dyn-src"><dynamic><filter>x</filter></dynamic></entry></address-group>'
            f"<service>{svcs}</service></entry></vsys></entry></devices></config>")
    plan = _plan(d, {f"{SPEC}/fw-1/running-config.xml": text})
    changed = _changed(plan)
    assert plan.conflicts == () and {cn: c["ciamRunningState"] for cn, c in changed.items()} == {
        "fw-app": ("deployed",), "fw-admin": ("deployed",), "fw-gone": ("deployed",)}
    assert changed["fw-app"]["ciamRunningFact"] == ("source dyn-src (dynamic group x)",)
    assert any("pano: nothing read for it" in n for n in plan.notices)


def test_an_external_allowlist_records_what_the_object_it_names_holds():
    ref = "panos:pano.example.test/shared/address-group/partner-in"
    tree = (f"dn: cn=partner-in,ou=external-allowlists,dc=ciam-ops\nobjectClass: top\nobjectClass: "
            f"ciamExternalAllowlist\ncn: partner-in\nciamManagedBy: cn=platform-team,ou=owners,dc=ciam-ops\n"
            f"ciamRefersToRole: egress\nciamRecordedCidr: 198.51.100.1/32\nciamAllowlistDirection: partner-ingress\n"
            f"ciamAllowlistRef: {ref}\n",)
    d, m, _ = _model(tree=tree)
    shared = ('<shared><address><entry name="ours"><ip-netmask>203.0.113.5</ip-netmask></entry></address>'
              '<address-group><entry name="partner-in"><static><member>ours</member><member>dyn</member></static>'
              '</entry><entry name="dyn"><dynamic><filter>x</filter></dynamic></entry></address-group></shared>')
    text = _pushed(m)[f"{SPEC}/pano/running-config.xml"].replace("<config>", f"<config>{shared}")
    plan = _plan(d, {f"{SPEC}/pano/running-config.xml": text})
    assert _changed(plan)["partner-in"] == {"ciamRecordedCidr": ("203.0.113.5/32",)}
    assert [c.key for c in plan.conflicts] == ["cn=partner-in,ou=external-allowlists,dc=ciam-ops|ciamRecordedCidr"]
    assert any("dyn (dynamic group x) not resolved" in n for n in plan.notices)


def test_files_outside_the_layout_or_for_unknown_places_are_named_not_read():
    d, m, _ = _model()
    imported = read_running_config({"stray.xml": "<config/>", "alpha/prod/nobody/running-config.xml": "<config/>",
                                    "nowhere/prod/pano/running-config.xml": "<config/>"}, d, ())
    assert imported.groups == ()
    assert {n.split(":")[0] for n in imported.notices} >= {"stray.xml", "alpha/prod/nobody", "nowhere/prod"}


# ------------------------------------------------------------------ the collector and the round trip
def _source(scheme=SCHEME, url="https://pano.example.test"):
    return (entry(ALPHA, "panos-read", "ciamCollectionSource", ciamBindingRole="panos-read",
                  ciamImporter="panos/running-config", ciamSourceRef=url, ciamCredentialRole="pano-api-key",
                  ciamCredentialScheme=scheme),
            entry(ALPHA, "pano-api-key", "ciamSecretRef", ciamBindingRole="pano-api-key",
                  ciamRefUri="vault://secret/ciam/pano-api"))


def test_the_collector_reads_the_running_configuration_only_with_the_key_in_a_header():
    d, m, _ = _model(*_source())
    steps = running_steps(d, m, {}, {})
    paths = [p for p, _ in steps]
    assert paths[0] == f"{SPEC}/pano/api/device-group/DG/pre-rulebase.xml" and len(paths) == 12      # DG + shared
    for path, req in steps:
        query = parse_qs(urlparse(req.url).query)
        scope, family = path.split("/api/", 1)[1].removesuffix(".xml").rsplit("/", 1)
        assert (query["type"], query["action"], query["xpath"]) == (["config"], ["show"], [xpath(scope, family)])
        assert "commit" not in req.url and "key=" not in req.url
    assert steps[0][1].credential == (SCHEME, "vault://secret/ciam/pano-api", None, KEY_HEADER)
    assert source_problems(d, m, {}) == ()


def test_the_collector_names_why_it_cant_read():
    d, m, _ = _model(*_source(scheme="basic", url="https://elsewhere.example.test"))
    assert running_steps(d, m, {}, {}) == ()
    problems = source_problems(d, m, {})
    assert any("credential scheme `basic`" in p for p in problems) and any("elsewhere" in p for p in problems)


def test_the_render_reads_back_through_the_importer_unchanged_but_for_what_a_read_observes():
    d, m, _ = _model()
    panos = next(a for a in ADAPTERS if a.name == "panos")
    (trip,) = read_back(m.d, panos, render(m, services()), environment=SPEC)
    assert trip.files == (f"{SPEC}/pano/running-config.xml",) and trip.drift == ()
    assert {c.dn.split(",", 1)[0]: c.mods for c in trip.changes} == {
        f"cn={cn}": (("replace", "ciamRunningState", ("committed",)),) for cn in ("fw-app", "fw-admin", "fw-gone")}

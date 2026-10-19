"""Detections product adapters declare (ProductDetection) and the alert rules adopting them: a declaration as record
values and back, what keeps one from being offered, the planner's offer of a rule a person approves, a changed
declaration taken or kept by choice, a gone one removed, the record's rule as renderers render it with the mapping for
the versions an environment runs, and the declarations (fixed, and derived from the record) reaching the check and
the render services."""
import datetime as dt
import re

from opsdir.connectors.fixes import chosen
from opsdir.connectors.observability import detection_check
from opsdir.connectors.registry import detections_of, services
from opsdir.core.contract import Adapter, DetectionMapping, PlanContext, ProductDetection, declared_detections
from opsdir.core.directory import one
from opsdir.core.environment import env_model
from opsdir.core.findings import Input, findings
from opsdir.core.interchange.ldif import LdifRecord, parse
from opsdir.domains.observability import detections as x
from opsdir.domains.observability.naming import ALERT_RULES, DECLARED_DETECTION, DURATION, SELECTOR_TERM
import mini_estate
from support import REGISTRY, applied, build_directory

BETA = "env=prod,cloud=beta,ou=environments,dc=ciam-ops"
OPS = "cn=ops,ou=owners,dc=ciam-ops"
RULE = f"cn=idp-adapter-brute-force,{ALERT_RULES}"
BASE = (
    "dn: ou=owners,dc=ciam-ops\nobjectClass: top\nobjectClass: organizationalUnit\nou: owners\n",
    f"dn: {OPS}\nobjectClass: top\nobjectClass: ciamParty\ncn: ops\nciamOwnerKind: team\n",
    f"dn: {ALERT_RULES}\nobjectClass: top\nobjectClass: organizationalUnit\nou: alert-rules\n",
    f"dn: cn=lag,{ALERT_RULES}\nobjectClass: top\nobjectClass: ciamObject\nobjectClass: ciamAlertRule\ncn: lag\n"
    "ciamSignal: replication-delay\nciamAlertRole: alerts-page\n")
SERVER = (f"dn: cn=web-1,{BETA}\nobjectClass: top\nobjectClass: ciamServer\ncn: web-1\nciamServerRole: web\n"
          f"ciamHostname: web-1.example.test\nciamSubnet: cn=net,ou=bindings,{BETA}\nciamProductVersion: IdP 8.1.2\n")
FIELDS = (("subject", "principal"), ("realm", "realm"), ("outcome", "result"), ("action", "eventName"))
SAID = (("outcome", "failure", ("FAILED",)), ("action", "login", ("LOGIN-COMPLETED",)))


def _record(*extra):
    return build_directory(REGISTRY, tuple(parse(mini_estate.LDIF + "\n" + "\n".join((*BASE, *extra)))))


def _plan(d, check):
    return check(PlanContext(d, env_model(d, "alpha/prod"), env_model(d, "beta/prod"), None, dt.date(2026, 10, 1),
                             {}, {}, ()))


def _detection(**changes):
    return ProductDetection(
        id="brute-force", title="Brute force", description="Repeated failed sign-ins for one subject",
        products=(("idp", ">=8"),), server_role="web", log_source="authentication",
        mappings=(DetectionMapping("idp", ">=8,<9", FIELDS, SAID),
                  DetectionMapping("idp", ">=9", (("subject", "user.id"), *FIELDS[1:]), SAID)),
        selector=(("action", ("login",)), ("outcome", ("failure",))), group_by=("subject", "realm"), distinct=None,
        threshold=10, window_seconds=300, window_kind="sliding", tactics=("credential-access",),
        techniques=("T1110",), severity="sev2", prerequisites=("the authentication audit topic is logged",),
        evidence=("https://docs.example.test/audit",), validation="documented")._replace(**changes)


def _declared(*dets, installed=None):
    pairs = tuple(("idp-adapter", det) for det in dets)
    return lambda ctx: x.check_detections(ctx, pairs, {"idp-adapter": dets} if installed is None else installed)


def _with(d, *records):
    return applied(d, records)


def _adopted():
    d = _record()
    fix = _plan(d, _declared(_detection())).fixes[0]
    return _with(d, *chosen(fix, None, {"ciamAlertRole": ("alerts-page",), "ciamOwner": (OPS,)}).records)


def _rule(d):
    return d.entries[RULE.lower()]


def _tuned(d, attr, *vals):
    return _with(d, LdifRecord(RULE, "modify", {}, (("replace", attr, vals),)))


def test_a_declaration_reads_as_record_values_and_back():
    det = _detection()
    assert x.declared_attrs(det) == {
        "ciamSignal": ("brute-force",), "ciamTargetRole": ("web",),
        "ciamDetectionSelector": ("action=login", "outcome=failure"), "ciamGroupBy": ("subject", "realm"),
        "ciamDistinctField": (), "ciamComparison": ("ge",), "ciamThreshold": ("10",),
        "ciamEvaluationPeriod": ("5m",), "ciamWindowKind": ("sliding",), "ciamSeverity": ("sev2",),
        "ciamAttackTactic": ("credential-access",), "ciamAttackTechnique": ("T1110",)}
    assert x.digest(det) == x.digest(_detection(description="said otherwise")) != x.digest(_detection(threshold=20))
    assert len(x.digest(det)) == 16
    assert [x.window_text(s) for s in (300, 90, 3600, 86400, 7200)] == ["5m", "90s", "1h", "1d", "2h"]
    assert [x.duration_seconds(t) for t in ("5m", "90s", "1h", "2d", "five")] == [300, 90, 3600, 172800, None]
    assert x.parse_selector(("action=login|admin-login", "outcome=failure")) == (
        ("action", ("login", "admin-login")), ("outcome", ("failure",)))
    every = x.declared_attrs(_detection(threshold=None, window_seconds=None, window_kind=None, group_by=()))
    assert (every["ciamComparison"], every["ciamThreshold"], every["ciamEvaluationPeriod"]) == ((), (), ())
    assert x.declared((("a", det), ("b", det)), "b:brute-force") is det and x.declared((), "a:brute-force") is None


def test_a_declaration_that_does_not_hold_together_says_why():
    assert x.detection_problems("idp-adapter", _detection()) == ()
    bad = _detection(id="Brute Force", selector=(("outcome", ("lost",)), ("host", ("x",))), group_by=("subject",),
                     distinct="source-ip", window_kind="rolling", tactics=("defense-evasion",),
                     techniques=("T9999",), severity="high", validation="guessed", evidence=("http://x.test",),
                     mappings=(DetectionMapping("other", None, (("subject", "user"),), ()),))
    canonical = ("(subject, source-ip, realm, outcome, action, actor, object, step, step-outcome; outcome "
                 "success|failure; action login|admin-login|config-change|key-change|login-step)")
    assert x.detection_problems("idp-adapter", bad) == (
        "reference `idp-adapter:Brute Force` isn't <adapter>:<id> in lower case",
        f"selector value `outcome=lost` isn't canonical {canonical}",
        f"selector value `host=x` isn't canonical {canonical}",
        "window kind 'rolling', not sliding or fixed",
        "mapping of other, which it doesn't name among its products",
        "mapping of other names no field for `outcome`", "mapping of other names no field for `host`",
        "mapping of other names no field for `source-ip`", "mapping of other doesn't say what `outcome=lost` is",
        "ATT&CK tactic `defense-evasion` isn't one of the current ATT&CK's",
        "ATT&CK technique `T9999` isn't in the current ATT&CK", "severity 'high', not one of sev1, sev2, sev3, sev4",
        "validation 'guessed', not one of unverified, documented, lab-verified, live-verified",
        "no https evidence (the documentation it rests on)")
    assert x.detection_problems("a", _detection(threshold=None, distinct="subject")) == (
        "no threshold but a window", "no threshold but a window kind", "no threshold but a grouping",
        "no threshold but a distinct field")
    f = _plan(_record(), _declared(bad))
    assert f.fixes == () and f.actions[0][1].startswith(
        "idp-adapter declares detection `Brute Force`, which can't be offered as an alert rule: reference")


def test_a_declaration_no_rule_adopts_is_offered_as_a_rule_a_person_approves():
    d = _record()
    f = _plan(d, _declared(_detection()))
    assert f.actions == (
        ("Alert", "idp-adapter declares detection `brute-force` (Brute force; idp >=8; documented only: not yet seen "
         "firing in a lab or on a live system); no alert rule adopts it, so no SIEM runs it. Adopt it (the fix "
         "records alert rule `idp-adapter-brute-force`, its channel's role given) or leave it.", "**NO OWNER**",
         None),)
    fix, = f.fixes
    assert (fix.key, fix.title, fix.manual) == (
        "detection:idp-adapter:brute-force",
        "Record alert rule `idp-adapter-brute-force` adopting idp-adapter's detection `brute-force` (Brute force)",
        ("Make sure: the authentication audit topic is logged",))
    assert fix.risks == ("The detection is documented only: not yet seen firing in a lab or on a live system: it may "
                         "miss or over-count until its events are checked against the product's",)
    record, = fix.records
    assert record.dn == RULE and record.attrs["ciamDeclaredDetection"] == ("idp-adapter:brute-force",)
    role, = record.attrs["ciamAlertRole"]
    assert isinstance(role, Input) and (role.key, role.default, role.example) == ("ciamAlertRole", (), ("alerts-page",))
    assert record.attrs["ciamOwner"][0].key == "ciamOwner"
    patterns = {"ciamDetectionSelector": SELECTOR_TERM, "ciamDeclaredDetection": DECLARED_DETECTION,
                "ciamDeclarationDigest": "^[0-9a-f]{16}$", "ciamEvaluationPeriod": DURATION}
    assert all(re.fullmatch(p, v) for a, p in patterns.items() for v in record.attrs[a])
    adopted = _adopted()
    assert (one(_rule(adopted), "ciamThreshold"), one(_rule(adopted), "ciamWindowKind"),
            one(_rule(adopted), "ciamOwner"), one(_rule(adopted), "description")) == (
        "10", "sliding", OPS, "Brute force: Repeated failed sign-ins for one subject")
    assert _plan(adopted, _declared(_detection())) == findings(ok=[
        "Every detection the target's products declare (1) is adopted, and the alert rules adopting one (1) hold "
        "what their declarations say now."])
    # tuned by a person while the declaration stayed: left alone; nothing declared and nothing adopted: silent
    assert _plan(_tuned(adopted, "ciamThreshold", "15"), _declared(_detection())).actions == ()
    assert _plan(d, _declared()) == findings()


def test_a_changed_declaration_is_taken_or_kept_by_choice_and_a_gone_one_removed():
    tuned = _tuned(_adopted(), "ciamThreshold", "15")
    changed = _detection(threshold=20, techniques=("T1110", "T1110.001"))
    f = _plan(tuned, _declared(changed))
    assert [t for _, t, _, _ in f.actions] == [
        "Alert rule `idp-adapter-brute-force` adopted idp-adapter's detection `brute-force`, whose declaration "
        "changed since: the rule differs from it in ciamThreshold 15 -> 20, ciamAttackTechnique T1110 -> "
        "T1110|T1110.001. Take the declaration's values, or keep the rule's (values a person tuned) and record the "
        "declaration as seen."]
    fix, = f.fixes
    assert [o.key for o in fix.options] == ["take", "keep"] and fix.records == ()
    assert chosen(fix, "take").records[0].mods == (
        ("replace", "ciamThreshold", ("20",)), ("replace", "ciamAttackTechnique", ("T1110", "T1110.001")),
        ("replace", "ciamDeclarationDigest", (x.digest(changed),)))
    for option, threshold in (("take", "20"), ("keep", "15")):
        after = _with(tuned, *chosen(fix, option).records)
        assert one(_rule(after), "ciamThreshold") == threshold
        assert _plan(after, _declared(changed)).actions == ()
    # changed to what a person had already tuned: only the digest to record
    same = _plan(_tuned(_adopted(), "ciamThreshold", "20"), _declared(_detection(threshold=20)))
    assert same.fixes[0].options == () and [m[1] for m in same.fixes[0].records[0].mods] == ["ciamDeclarationDigest"]
    # the declaration is gone, or its adapter isn't installed
    gone = _plan(_adopted(), _declared(_detection(id="other")))
    assert [k.key for k in gone.fixes] == ["detection:idp-adapter:other", "detection-remove:idp-adapter-brute-force"]
    assert gone.fixes[1].records[0].changetype == "delete"
    lost = _plan(_adopted(), _declared(installed={}))
    assert [t for _, t, _, _ in lost.actions] == [
        "Alert rule `idp-adapter-brute-force` adopted detection `idp-adapter:brute-force`, but adapter `idp-adapter` "
        "isn't installed: nothing maps its fields to the product's log. Install it, or remove the rule."]


def test_the_record_rule_is_what_renderers_render_with_the_mapping_for_the_versions_run():
    rule = _rule(_adopted())

    def tuned(**attrs):
        return rule._replace(attrs={**rule.attrs, **attrs})
    det, why = x.recorded(tuned(ciamThreshold=("15",), ciamComparison=("gt",), ciamGroupBy=("subject",)),
                          _detection())
    assert why is None and (det.threshold, det.group_by, det.window_seconds, det.window_kind, det.mappings) == (
        16, ("subject",), 300, "sliding", _detection().mappings)
    assert x.recorded(tuned(ciamComparison=("lt",)), _detection()) == (None, (
        "its condition `lt 10` isn't a count of events reached (ciamComparison ge or gt, a whole ciamThreshold "
        "without a unit)"))
    assert x.recorded(tuned(ciamEvaluationPeriod=()), _detection())[1] == (
        "it counts events but records no window (ciamEvaluationPeriod)")
    newest = x.mapping_for(env_model(_record(), "beta/prod"), _detection())
    assert (newest.versions, x.product_field(newest, "subject"), x.product_field(newest, "source-ip")) == (
        ">=9", "user.id", None)
    assert x.product_values(newest, "outcome", "failure") == ("FAILED",)
    assert x.product_values(newest, "realm", "alpha") == ("alpha",)
    assert x.mapping_for(env_model(_record(SERVER), "beta/prod"), _detection()).versions == ">=8,<9"
    assert x.mapping_for(env_model(_record(SERVER), "beta/prod"), _detection(mappings=())) is None


def test_the_target_adapters_declarations_reach_the_check_and_the_renderers():
    idp = Adapter(name="idp-adapter", kind="product", applies=lambda m: True, required_roles=(), render_neutral=None,
                  render_env=None, checks=(), ref_schemes=(), secret_schemes={}, renders=None, neutral_label=None,
                  vocabulary={}, schema=None, formats=(), products=(), secret_patterns=(), importers=(),
                  profile_terms=None, access=None, detections=(_detection(),))
    other = idp._replace(name="other", applies=lambda m: False, detections=(_detection(id="spray"),))
    assert "detections" in Adapter._fields and Adapter(*idp[:19]).detections == ()     # defaults to none
    d = _record()
    assert [f.key for f in _plan(d, detection_check((idp,), (idp, other))).fixes] == [
        "detection:idp-adapter:brute-force"]
    unstacked = env_model(d, "alpha/prod")._replace(stack=())
    assert detections_of(unstacked, (idp, other)) == (("idp-adapter", _detection()),)
    assert services((idp, other)).detections(unstacked) == (("idp-adapter", _detection()),)


def test_an_unverified_declaration_says_so_in_its_offer_and_its_render_note():
    det = _detection(validation="unverified")
    assert x.detection_problems("idp-adapter", det) == ()
    f = _plan(_record(), _declared(det))
    said = ("unverified: it rests partly on what the product's documentation doesn't establish, and hasn't been seen "
            "firing in a lab or on a live system")
    assert said in f.actions[0][1] and f.fixes[0].risks == (
        f"The detection is {said}: it may miss or over-count until its events are checked against the product's",)
    adopted = _adopted()
    m = env_model(adopted, "beta/prod")
    note, = x.native_notes(m, (x.NativeRule(_rule(adopted), det, det.mappings[1], None),), (), "SIEM")
    assert note.severity == "note" and "declaration that is unverified (it rests partly" in note.text


def test_detections_an_adapter_derives_from_the_record_reach_the_check_and_the_renderers():
    derived = _detection(id="mfa-bypass.login", selector=(("action", ("login-step",)), ("step", ("n1",)),
                                                          ("step-outcome", ("skip",))),
                         group_by=(), threshold=None, window_seconds=None, window_kind=None, validation="unverified",
                         mappings=(DetectionMapping("idp", None, (("step", "entries[].info.nodeId"),
                                                                  ("step-outcome", "entries[].info.nodeOutcome"),
                                                                  ("action", "eventName")),
                                                    (("action", "login-step", ("NODE-COMPLETED",)),)),))
    idp = Adapter(name="idp-adapter", kind="product", applies=lambda m: True, required_roles=(), render_neutral=None,
                  render_env=None, checks=(), ref_schemes=(), secret_schemes={}, renders=None, neutral_label=None,
                  vocabulary={}, schema=None, formats=(), products=(), secret_patterns=(), importers=(),
                  profile_terms=None, access=None, detections=(_detection(),),
                  record_detections=lambda d: (derived,))
    assert Adapter(*idp[:19]).record_detections is None and declared_detections(Adapter(*idp[:19]), _record()) == ()
    assert x.detection_problems("idp-adapter", derived) == ()
    d = _record()
    assert declared_detections(idp, d) == (_detection(), derived)
    assert [f.key for f in _plan(d, detection_check((idp,), (idp,))).fixes] == [
        "detection:idp-adapter:brute-force", "detection:idp-adapter:mfa-bypass.login"]
    unstacked = env_model(d, "alpha/prod")._replace(stack=())
    assert detections_of(unstacked, (idp,)) == (("idp-adapter", _detection()), ("idp-adapter", derived))
    assert services((idp,)).detections(unstacked) == detections_of(unstacked, (idp,))
    # a rule adopting a derived declaration the record no longer gives is offered for removal
    adopted = _with(d, *chosen(_plan(d, detection_check((idp,), (idp,))).fixes[1], None,
                               {"ciamAlertRole": ("alerts-page",), "ciamOwner": (OPS,)}).records)
    gone = idp._replace(record_detections=lambda d: ())
    assert "detection-remove:idp-adapter-mfa-bypass.login" in [
        f.key for f in _plan(adopted, detection_check((gone,), (gone,))).fixes]


def test_a_rule_on_a_field_inside_a_list_is_refused_where_the_siem_doesnt_search_lists():
    listed = _detection(mappings=(DetectionMapping("idp", None, (("subject", "principal[]"), *FIELDS[1:]), SAID),))
    channel = (f"dn: cn=page,ou=bindings,{BETA}\nobjectClass: top\nobjectClass: ciamAlertChannel\ncn: page\n"
               "ciamBindingRole: alerts-page\nciamChannelKind: email\nciamProviderRef: soc@example.test\n")
    d = _with(_record(channel), *chosen(_plan(_record(channel), _declared(listed)).fixes[0], None,
                                        {"ciamAlertRole": ("alerts-page",), "ciamOwner": (OPS,)}).records)
    m = env_model(d, "beta/prod")
    (refused,) = x.native_rules(m, (("idp-adapter", listed),))
    assert refused.why == ("the product's fields principal[] sit inside a list ([]), which this SIEM's render doesn't "
                           "search inside yet")
    (taken,) = x.native_rules(m, (("idp-adapter", listed),), lists=True)
    assert taken.why is None and x.product_field(taken.mapping, "subject") == "principal[]"

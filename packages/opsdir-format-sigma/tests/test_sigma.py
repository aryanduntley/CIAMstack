"""The Sigma export: an alert rule adopting a declared detection as a Sigma 2.1.0 base rule (the product's field names
and values for the version the environment runs) and a correlation rule (event_count or value_count, group-by,
timespan, gte), checked against the specification's documented attributes; the rules it leaves out with a note (fixed
windows, no mapping for the versions run, a condition that isn't a count); the render and its notes; the registry
installing it."""
import re
import uuid
from types import SimpleNamespace

import pytest
import yaml

from opsdir.connectors.registry import ADAPTERS
from opsdir.core.contract import DetectionMapping, ProductDetection
from opsdir.core.environment import env_model
from opsdir.core.interchange.ldif import parse
from opsdir.domains.observability.detections import declared_attrs, declared_ref, digest
from opsdir.domains.observability.naming import ALERT_RULES
from opsdir_format_sigma.adapter import ADAPTER
from opsdir_format_sigma.sigma import rule_id, sigma_exports, sigma_notes
import mini_estate
from support import REGISTRY, build_directory

BETA = "env=prod,cloud=beta,ou=environments,dc=ciam-ops"
FIELDS = (("subject", "principal"), ("realm", "realm"), ("outcome", "result"), ("action", "eventName"),
          ("source-ip", "client.ip"))
SAID = (("outcome", "failure", ("FAILED",)), ("action", "login", ("LOGIN-COMPLETED", "LOGIN-FAILED")))
SERVER = (f"dn: cn=web-1,{BETA}\nobjectClass: top\nobjectClass: ciamServer\ncn: web-1\nciamServerRole: web\n"
          f"ciamHostname: web-1.example.test\nciamSubnet: cn=net,ou=bindings,{BETA}\nciamProductVersion: IdP 8.1.2\n")

# What the Sigma 2.1.0 specification documents (sigma-rules-specification.md, sigma-correlation-rules-
# specification.md, their JSON schemas; checked 2026-10-18): the top-level attributes, status and level values,
# correlation types, the timespan form, condition operators and the ATT&CK tag forms (sigma-appendix-tags.md)
RULE_KEYS = {"title", "id", "name", "related", "taxonomy", "status", "description", "license", "references", "author",
             "date", "modified", "logsource", "detection", "fields", "falsepositives", "level", "tags", "scope"}
CORRELATION_KEYS = {"title", "id", "name", "status", "description", "author", "references", "date", "modified",
                    "taxonomy", "falsepositives", "level", "generate", "correlation", "tags"}
STATUSES = {"stable", "test", "experimental", "deprecated", "unsupported"}
LEVELS = {"informational", "low", "medium", "high", "critical"}
TYPES = {"event_count", "value_count", "temporal", "temporal_ordered", "value_sum", "value_avg", "value_percentile"}
OPERATORS = {"gt", "gte", "lt", "lte", "eq", "neq"}
TAG = re.compile(r"attack\.(t[0-9]{4}(\.[0-9]{3})?|[a-z]+(-[a-z]+)*)")


def _detection(**changes):
    return ProductDetection(
        id="brute-force", title="Brute force", description="Repeated failed sign-ins for one subject",
        products=(("idp", ">=8"),), server_role="web", log_source="authentication",
        mappings=(DetectionMapping("idp", ">=8,<9", FIELDS, SAID),
                  DetectionMapping("idp", ">=9", (("subject", "user.id"), *FIELDS[1:]), SAID)),
        selector=(("action", ("login",)), ("outcome", ("failure",))), group_by=("subject", "realm"), distinct=None,
        threshold=10, window_seconds=300, window_kind="sliding", tactics=("credential-access",),
        techniques=("T1110", "T1110.001"), severity="sev2", prerequisites=("the authentication audit topic is logged",),
        evidence=("https://docs.example.test/audit",), validation="documented")._replace(**changes)


SPRAY = _detection(id="password-spray", title="Password spray", group_by=("source-ip",), distinct="subject",
                   threshold=20, window_seconds=3600, techniques=("T1110.003",), validation="lab-verified")


def _rule(det, **tuned):
    attrs = {**{k: v for k, v in declared_attrs(det).items() if v}, "ciamAlertRole": ("alerts-page",),
             "ciamDeclaredDetection": (declared_ref("idp-adapter", det),), "ciamDeclarationDigest": (digest(det),),
             **tuned}
    return (f"dn: cn=idp-adapter-{det.id},{ALERT_RULES}\nobjectClass: top\nobjectClass: ciamObject\n"
            f"objectClass: ciamAlertRule\ncn: idp-adapter-{det.id}\n"
            + "".join(f"{k}: {v}\n" for k, vs in attrs.items() for v in vs))


def _env(*extra):
    d = build_directory(REGISTRY, tuple(parse(mini_estate.LDIF + "\n" + "\n".join((
        f"dn: {ALERT_RULES}\nobjectClass: top\nobjectClass: organizationalUnit\nou: alert-rules\n", *extra)))))
    return env_model(d, "beta/prod")


def _pairs(*dets):
    return tuple(("idp-adapter", det) for det in dets)


def _shape(doc):
    """Problems with a Sigma document against the specification's documented attributes ([] when it holds)."""
    correlated = "correlation" in doc
    allowed, required = (CORRELATION_KEYS, {"title", "correlation"}) if correlated else (
        RULE_KEYS, {"title", "logsource", "detection"})
    c = doc.get("correlation", {})
    return [*(f"unknown {k}" for k in set(doc) - allowed), *(f"missing {k}" for k in required - set(doc)),
            *(["status"] if doc.get("status") not in STATUSES else []),
            *(["level"] if doc.get("level") not in LEVELS else []),
            *(["id"] if str(uuid.UUID(doc["id"])) != doc["id"] else []),
            *(["tags"] if not all(TAG.fullmatch(t) for t in doc.get("tags", ())) else []),
            *(["condition"] if not correlated and "condition" not in doc["detection"] else []),
            *(["logsource"] if not correlated and set(doc["logsource"]) - {"category", "product", "service",
                                                                         "definition"} else []),
            *(["type"] if correlated and c["type"] not in TYPES else []),
            *(["timespan"] if correlated and not re.fullmatch(r"[0-9]+[smhd]", c["timespan"]) else []),
            *(["operator"] if correlated and set(c["condition"]) - OPERATORS - {"field"} else []),
            *(["value field"] if correlated and c["type"] == "value_count" and "field" not in c["condition"] else [])]


def _docs(m, *dets):
    files = ADAPTER.render_env(m, SimpleNamespace(detections=lambda _: _pairs(*dets)))
    return {p: list(yaml.safe_load_all(text)) for p, text in files.items()}, files


def test_a_counting_rule_is_a_base_rule_and_a_correlation_in_the_product_s_field_names():
    docs, files = _docs(_env(_rule(_detection())), _detection())
    base, correlation = docs["sigma/idp-adapter-brute-force.yml"]
    assert files["sigma/idp-adapter-brute-force.yml"].startswith("# Generated by opsdir from " + BETA)
    assert _shape(base) == [] and _shape(correlation) == []
    assert base == {
        "title": "Brute force", "id": rule_id("idp-adapter-brute-force-events"),
        "name": "idp-adapter-brute-force-events", "status": "experimental",
        "description": "Repeated failed sign-ins for one subject (opsdir alert rule idp-adapter-brute-force, adopting "
                       "idp-adapter:brute-force)",
        "references": ["https://docs.example.test/audit"], "author": "opsdir",
        "logsource": {"product": "idp", "service": "authentication",
                      "definition": "idp >=9, its authentication log; requires: the authentication audit topic is "
                                    "logged"},
        "detection": {"selection": {"eventName": ["LOGIN-COMPLETED", "LOGIN-FAILED"], "result": "FAILED"},
                      "condition": "selection"},
        "fields": ["user.id", "realm"], "level": "high",
        "tags": ["attack.credential-access", "attack.t1110", "attack.t1110.001"]}
    assert correlation["name"] == "idp-adapter-brute-force" and correlation["id"] == rule_id("idp-adapter-brute-force")
    assert correlation["correlation"] == {"type": "event_count", "rules": ["idp-adapter-brute-force-events"],
                                          "group-by": ["user.id", "realm"], "timespan": "5m",
                                          "condition": {"gte": 10}}
    assert rule_id("x") == rule_id("x") != rule_id("y") and uuid.UUID(rule_id("x")).version == 5


def test_a_distinct_count_is_a_value_count_and_the_version_run_picks_the_mapping():
    m = _env(SERVER, _rule(SPRAY, ciamThreshold=("25",)))
    docs, _ = _docs(m, SPRAY)
    base, correlation = docs["sigma/idp-adapter-password-spray.yml"]
    assert (base["status"], base["fields"], base["logsource"]["definition"].split(", its")[0]) == (
        "test", ["client.ip", "principal"], "idp >=8,<9")
    assert correlation["correlation"] == {"type": "value_count", "rules": ["idp-adapter-password-spray-events"],
                                          "group-by": ["client.ip"], "timespan": "1h",
                                          "condition": {"gte": 25, "field": "principal"}}
    assert _shape(correlation) == []


def test_every_event_is_a_base_rule_alone():
    single = _detection(id="admin-change", threshold=None, window_seconds=None, window_kind=None, group_by=())
    docs, _ = _docs(_env(_rule(single)), single)
    base, = docs["sigma/idp-adapter-admin-change.yml"]
    assert _shape(base) == [] and base["name"] == "idp-adapter-admin-change-events"


def test_what_sigma_cannot_say_as_recorded_is_left_out_with_a_note():
    fixed = _detection(id="fixed", window_kind="fixed")
    unmapped = _detection(id="unmapped", mappings=(DetectionMapping("idp", ">=7,<8", FIELDS, SAID),))
    lt = _detection(id="lt")
    m = _env(_rule(fixed), _rule(unmapped), _rule(lt, ciamComparison=("lt",)), _rule(_detection(id="elsewhere")),
             _rule(_detection(), ciamGroupBy=("actor",)))
    pairs = _pairs(fixed, unmapped, lt, _detection())
    assert [(r.dn.split(",")[0], why) for r, docs, why, _ in sigma_exports(m, pairs)] == [
        ("cn=idp-adapter-brute-force", "the product's mapping names no field for actor"),
        ("cn=idp-adapter-fixed", "it counts in fixed (clock-aligned) windows, and a Sigma correlation's timespan isn't "
                                 "bound to clock boundaries"),
        ("cn=idp-adapter-lt", "its condition `lt 10` isn't a count of events reached (ciamComparison ge or gt, a "
                              "whole ciamThreshold without a unit)"),
        ("cn=idp-adapter-unmapped", "idp-adapter:unmapped maps no version of its product beta/prod records for role "
                                    "web (>=7,<8)")]
    notes = sigma_notes(m, pairs)
    assert [(n.severity, n.subject) for n in notes] == [("action", f"alert rule idp-adapter-{x}")
                                                        for x in ("brute-force", "fixed", "lt", "unmapped")]
    assert notes[1].how == ("Render it natively with the SIEM's adapter, or make the window sliding (ciamWindowKind) "
                            "if that is what is meant",)
    assert ADAPTER.render_env(m, SimpleNamespace(detections=lambda _: pairs)) == {}


def test_the_render_notes_say_what_a_converter_needs_and_the_registry_installs_it():
    m = _env(_rule(_detection()))
    notes = ADAPTER.notes(m, SimpleNamespace(detections=lambda _: _pairs(_detection())))
    assert [(n.severity, n.subject) for n in notes] == [("note", "alert rule idp-adapter-brute-force"),
                                                        ("note", "Sigma rules")]
    assert notes[1].how[0].startswith("Whoever converts them (the SIEM team) gives the converter a pipeline")
    assert ADAPTER.notes(m, SimpleNamespace(detections=lambda _: ())) == ()
    sigma = next(a for a in ADAPTERS if a.name == "sigma")
    assert (sigma.applies, sigma.formats) == (None, (("sigma/*.yml", "yaml"),))


@pytest.mark.parametrize("severity,level", [("sev1", "critical"), ("sev3", "medium"), ("sev4", "low")])
def test_severity_is_the_sigma_level(severity, level):
    det = _detection(severity=severity, validation="live-verified")
    docs, _ = _docs(_env(_rule(det)), det)
    assert {d["level"] for d in docs["sigma/idp-adapter-brute-force.yml"]} == {level}
    assert {d["status"] for d in docs["sigma/idp-adapter-brute-force.yml"]} == {"stable"}

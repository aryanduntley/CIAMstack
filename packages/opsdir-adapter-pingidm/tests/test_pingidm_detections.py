"""PingIDM's declared detections: each can be offered as an alert rule, reads an audit topic the adapter declares, and
holds only for the versions whose audit guide establishes its fields (failures by result alone, config events in both
spellings the guides give)."""
from fnmatch import fnmatch

from opsdir.core.versions import holds
from opsdir.domains.observability.detections import detection_problems, product_field, product_values
from opsdir_adapter_pingidm.adapter import ADAPTER


def _det(name):
    return next(d for d in ADAPTER.detections if d.id == name)


def _mapping(det, recorded):
    return next((mp for mp in det.mappings if holds(mp.versions, (recorded,))), None)


def test_every_declaration_can_be_offered_as_an_alert_rule():
    assert [d.id for d in ADAPTER.detections] == ["brute-force", "password-spray", "config-change"]
    assert all(detection_problems(ADAPTER.name, d) == () for d in ADAPTER.detections)


def test_each_reads_an_audit_topic_the_adapter_declares_for_its_products():
    named = {p for p, _ in ADAPTER.products}
    for det in ADAPTER.detections:
        assert any(s.server_role == det.server_role and fnmatch(f"audit/{det.log_source}.audit.json", s.path)
                   for s in ADAPTER.logs)
        assert {p for p, _ in det.products} <= named and {mp.product for mp in det.mappings} <= named


def test_failures_are_counted_by_result_per_principal_or_per_source_address():
    brute, spray = _det("brute-force"), _det("password-spray")
    mp = _mapping(spray, "PingIDM 8.1.2")
    assert brute.selector == spray.selector == (("outcome", ("failure",)),)
    assert product_values(mp, "outcome", "failure") == ("FAILED",)
    assert (product_field(mp, "subject"), product_field(mp, "source-ip")) == ("principal", "context.ipAddress")
    assert (spray.group_by, spray.distinct, spray.threshold, spray.window_seconds) == (("source-ip",), "subject", 10,
                                                                                       600)
    assert _mapping(brute, "PingIDM 7.0.2") is None and _mapping(brute, "ForgeRock IDM 7.1.0") is not None
    assert _mapping(brute, "") is not None  # a role recording no version runs the newest release


def test_a_config_change_names_who_changed_what_in_either_spelling():
    det = _det("config-change")
    mp = _mapping(det, "PingIDM 8.1.2")
    assert product_values(mp, "action", "config-change") == ("config", "CONFIG")
    assert (product_field(mp, "actor"), product_field(mp, "object")) == ("userId", "objectId")
    assert _mapping(det, "PingIDM 7.1.0") is None

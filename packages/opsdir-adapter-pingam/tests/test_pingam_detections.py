"""PingAM's declared detections: each can be offered as an alert rule, reads an audit topic the adapter declares, and
maps a failed sign-in to the events each version's audit reference names (chains on 7.x only)."""
from fnmatch import fnmatch

from opsdir.core.versions import holds
from opsdir.domains.observability.detections import detection_problems, product_field, product_values
from opsdir_adapter_pingam.adapter import ADAPTER


def _det(name):
    return next(d for d in ADAPTER.detections if d.id == name)


def _mapping(det, recorded):
    return next(mp for mp in det.mappings if holds(mp.versions, (recorded,)))


def test_every_declaration_can_be_offered_as_an_alert_rule():
    assert [d.id for d in ADAPTER.detections] == ["brute-force", "config-change"]
    assert all(detection_problems(ADAPTER.name, d) == () for d in ADAPTER.detections)


def test_each_reads_an_audit_topic_the_adapter_declares_for_its_products():
    named = {p for p, _ in ADAPTER.products}
    for det in ADAPTER.detections:
        assert any(s.server_role == det.server_role and fnmatch(f"var/audit/{det.log_source}.audit.json", s.path)
                   for s in ADAPTER.logs)
        assert {p for p, _ in det.products} <= named and {mp.product for mp in det.mappings} <= named


def test_a_failed_sign_in_is_a_completed_journey_or_on_7x_chain_ending_failed():
    det = _det("brute-force")
    old, new = _mapping(det, "PingAM 7.5.1"), _mapping(det, "PingAM 8.1.1")
    assert product_values(old, "action", "login") == ("AM-TREE-LOGIN-COMPLETED", "AM-LOGIN-COMPLETED")
    assert product_values(new, "action", "login") == ("AM-TREE-LOGIN-COMPLETED",)
    assert _mapping(det, "") == new         # a role recording no version runs the newest release
    assert {product_values(mp, "outcome", "failure") for mp in det.mappings} == {("FAILED",)}
    assert (product_field(new, "subject"), product_field(new, "realm")) == ("principal", "realm")
    assert (det.group_by, det.threshold, det.window_seconds, det.window_kind) == (("subject", "realm"), 10, 300,
                                                                                  "sliding")


def test_a_config_change_is_every_config_event_with_who_made_it_left_to_the_access_topic():
    det = _det("config-change")
    mp = _mapping(det, "PingAM 8.1.1")
    assert product_values(mp, "action", "config-change") == ("AM-CONFIG-CHANGE",)
    assert product_field(mp, "object") == "objectId" and product_field(mp, "actor") is None
    assert det.threshold is None and any("transactionId" in p for p in det.prerequisites)

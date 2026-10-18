"""PingDS's declared detections: each can be offered as an alert rule, reads the LDAP access log the adapter declares,
and counts binds with invalid credentials (BIND, result code 49) only."""
from fnmatch import fnmatch

from opsdir.core.versions import holds
from opsdir.domains.observability.detections import detection_problems, product_field, product_values
from opsdir_adapter_pingds.adapter import ADAPTER


def _mapping(det, recorded):
    return next((mp for mp in det.mappings if holds(mp.versions, (recorded,))), None)


def test_every_declaration_can_be_offered_as_an_alert_rule():
    assert [d.id for d in ADAPTER.detections] == ["brute-force", "password-spray"]
    assert all(detection_problems(ADAPTER.name, d) == () for d in ADAPTER.detections)


def test_each_reads_the_ldap_access_log_for_the_adapters_products():
    named = {p for p, _ in ADAPTER.products}
    for det in ADAPTER.detections:
        assert any(s.server_role == det.server_role and fnmatch(f"logs/{det.log_source}.audit.json", s.path)
                   for s in ADAPTER.logs)
        assert {p for p, _ in det.products} <= named and {mp.product for mp in det.mappings} <= named


def test_a_failed_bind_is_a_bind_with_invalid_credentials():
    for det in ADAPTER.detections:
        mp = _mapping(det, "PingDS 8.1.2")
        assert product_values(mp, "action", "login") == ("BIND",)
        assert product_values(mp, "outcome", "failure") == ("49",)
        assert (product_field(mp, "action"), product_field(mp, "outcome")) == ("request.operation",
                                                                              "response.statusCode")
        assert (product_field(mp, "subject"), product_field(mp, "source-ip")) == ("request.dn", "client.ip")
        assert _mapping(det, "PingDS 7.1.0") is None and _mapping(det, "") is mp


def test_brute_force_counts_per_bind_dn_and_spray_distinct_bind_dns_per_address():
    brute, spray = ADAPTER.detections
    assert (brute.group_by, brute.distinct, brute.threshold, brute.window_seconds) == (("subject",), None, 10, 300)
    assert (spray.group_by, spray.distinct, spray.threshold, spray.window_seconds) == (("source-ip",), "subject", 10,
                                                                                       600)

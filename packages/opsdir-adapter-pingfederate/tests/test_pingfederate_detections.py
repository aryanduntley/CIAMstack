"""PingFederate's declared detections: each can be offered as an alert rule, reads the engines' security audit log the
adapter declares, counts failed IdP adapter attempts (AUTHN_ATTEMPT), and says what the guide leaves to confirm (the
status values, the field names a SIEM sees)."""
from opsdir.core.versions import holds
from opsdir.domains.observability.detections import detection_problems, product_field, product_values
from opsdir_adapter_pingfederate.adapter import ADAPTER


def test_every_declaration_can_be_offered_as_an_alert_rule():
    assert [d.id for d in ADAPTER.detections] == ["brute-force", "password-spray"]
    assert all(detection_problems(ADAPTER.name, d) == () for d in ADAPTER.detections)


def test_each_reads_the_engines_security_audit_log_for_the_adapters_products():
    named = {p for p, _ in ADAPTER.products}
    for det in ADAPTER.detections:
        assert det.server_role == "pf-engine"
        assert any(s.server_role == det.server_role and s.path == f"pingfederate/log/{det.log_source}.log"
                   for s in ADAPTER.logs)
        assert {p for p, _ in det.products} <= named and {mp.product for mp in det.mappings} <= named


def test_a_failed_attempt_is_an_authn_attempt_whose_status_is_left_to_confirm():
    for det in ADAPTER.detections:
        (mp,) = det.mappings
        assert product_values(mp, "action", "login") == ("AUTHN_ATTEMPT",)
        assert (product_field(mp, "outcome"), product_values(mp, "outcome", "failure")) == ("status", ("failure",))
        assert (product_field(mp, "subject"), product_field(mp, "source-ip")) == ("subject", "ip")
        assert holds(mp.versions, ("PingFederate 11.3.4",)) and holds(mp.versions, ("",))
        assert det.validation == "documented"
        assert any("status values" in p for p in det.prerequisites)
        assert any("pipe-separated" in p for p in det.prerequisites)

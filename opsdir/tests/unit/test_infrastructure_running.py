"""Firewall rules as a firewall manager runs them, read back (core infrastructure.running): the observed attributes an
importer sets (state, facts, unrecorded rules, an allowlist's recorded addresses), the planner's check and the
firewall-running report. Vendor-neutral."""
import re

from opsdir.core.directory import get, values
from opsdir.domains.infrastructure.naming import ACCESS_FACTS, OWNED_FACTS, RUNNING_FACT
from opsdir.domains.infrastructure.running import (allowlist_refs, check_firewall_running, firewall_running_rows,
                                                   observed_appliance, observed_rule, recorded_allowlist,
                                                   running_facts)
from network_fixtures import ALPHA, BETA, context, entry, model

RULE = f"cn=fw-app,ou=bindings,{ALPHA}"


def _rule(cn, state=None, facts=()):
    return entry(ALPHA, cn, "ciamFirewallRule", ciamBindingRole=cn, ciamSourceCidr="10.1.2.0/24", ciamPort="443",
                 ciamTargetRole="web", **({"ciamRunningState": state} if state else {}),
                 **({"ciamRunningFact": tuple(facts)} if facts else {}))


FIREWALL = entry(ALPHA, "pano", "ciamAppliance", ciamBindingRole="appliance-pano", ciamStackRole="network-firewall",
                 ciamManagementAddress="pano.example.test",
                 ciamUnrecordedRule="device-group/DG pre-rulebase vendor: 192.0.2.0/24 -> app-1 tcp-443")
ALLOWLIST = ("dn: cn=partner-in,ou=external-allowlists,dc=ciam-ops\nobjectClass: top\nobjectClass: "
             "ciamExternalAllowlist\ncn: partner-in\nciamManagedBy: cn=platform-team,ou=owners,dc=ciam-ops\n"
             "ciamRefersToRole: egress\nciamRecordedCidr: 198.51.100.1/32\nciamAllowlistDirection: partner-ingress\n"
             "ciamAllowlistRef: panos:pano.example.test/shared/address-group/partner-in\n")


def test_observed_values_replace_what_was_observed_and_none_removes_them():
    d, m, _ = model(alpha=(_rule("fw-app", "committed", ("log-end no",)),))
    fw = get(d, RULE)
    seen = observed_rule(fw, "disabled", ("schedule nights", "action deny", "action deny"))
    assert (values(seen, "ciamRunningState"), values(seen, "ciamRunningFact")) == (("disabled",),
                                                                                    ("action deny", "schedule nights"))
    cleared = observed_rule(fw, None, ())
    assert "ciamRunningState" not in cleared.attrs and "ciamRunningFact" not in cleared.attrs
    assert values(cleared, "ciamSourceCidr") == ("10.1.2.0/24",)                     # the rest kept
    assert running_facts(seen) == (("action deny",), ("schedule nights",))


def test_the_fact_pattern_takes_only_the_keys_the_check_knows():
    for key in (*OWNED_FACTS, *ACCESS_FACTS):
        assert re.match(RUNNING_FACT, f"{key} something")
    assert not re.match(RUNNING_FACT, "zone outside") and not re.match(RUNNING_FACT, "action")


def test_an_appliance_and_an_allowlist_record_what_a_read_saw():
    d, _, _ = model(alpha=(FIREWALL,), tree=(ALLOWLIST,))
    a = get(d, f"cn=pano,ou=bindings,{ALPHA}")
    assert "ciamUnrecordedRule" not in observed_appliance(a, ()).attrs
    ((xa, path),) = allowlist_refs(d, "panos")
    assert path == "pano.example.test/shared/address-group/partner-in" and allowlist_refs(d, "other") == ()
    assert values(recorded_allowlist(xa, ("203.0.113.5/32",)), "ciamRecordedCidr") == ("203.0.113.5/32",)


def _check(alpha=(), beta=()):
    d, a, b = model(alpha=alpha, beta=beta)
    return check_firewall_running(context(d, a, b))


def test_nothing_read_back_is_nothing_to_report():
    assert _check(alpha=(_rule("fw-app"),)) == check_firewall_running(context(*model()))


def test_each_rule_read_back_is_an_action_for_who_can_act_on_it():
    found = _check(alpha=(_rule("fw-gone", "missing"), _rule("fw-off", "disabled"),
                          _rule("fw-drift", "committed", ("action deny", "log-end no")),
                          _rule("fw-limited", "committed", ("negate-source yes",)), _rule("fw-ok", "committed"),
                          FIREWALL))
    texts = [text for _, text, _, _ in found.actions]
    assert len(texts) == 5
    assert any("`fw-gone` in alpha/prod isn't in its firewall's running configuration" in t for t in texts)
    assert any("`fw-off` in alpha/prod is disabled" in t for t in texts)
    assert any("`fw-drift` in alpha/prod runs `action deny`, `log-end no`" in t and "next push restores" in t
               for t in texts)
    assert any("`fw-limited` in alpha/prod admits less than the record says: `negate-source yes`" in t for t in texts)
    assert any("`pano` (alpha/prod's network firewall) runs a rule the record doesn't hold: device-group/DG" in t
               for t in texts)
    assert found.ok == ("3 of alpha/prod's firewall rule(s) are committed on their firewall manager as the record "
                        "says; their delivery to the firewalls isn't confirmed by that read.",)


def test_both_environments_are_read_and_the_same_one_once():
    found = _check(alpha=(_rule("fw-gone", "missing"),),
                   beta=(entry(BETA, "fw-b", "ciamFirewallRule", ciamBindingRole="fw-b", ciamSourceCidr="10.0.0.0/8",
                               ciamPort="443", ciamTargetRole="web", ciamRunningState="missing"),))
    assert sorted(text.split(" isn't")[0] for _, text, _, _ in found.actions) == ["`fw-b` in beta/prod",
                                                                                  "`fw-gone` in alpha/prod"]
    d, a, _ = model(alpha=(_rule("fw-gone", "missing"),))
    assert len(check_firewall_running(context(d, a, a)).actions) == 1


def test_the_report_lists_rules_read_back_then_unrecorded_ones():
    d, _, _ = model(alpha=(_rule("fw-app", "committed", ("log-end no",)), _rule("fw-new"), FIREWALL))
    assert firewall_running_rows(d) == [
        ("alpha/prod", "fw-app", "committed", "log-end no", ""),
        ("alpha/prod", "pano", "unrecorded", "device-group/DG pre-rulebase vendor: 192.0.2.0/24 -> app-1 tcp-443", "")]
    assert firewall_running_rows(d, BETA) == []

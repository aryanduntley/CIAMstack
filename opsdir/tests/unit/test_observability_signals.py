"""What evaluates an alert rule in an environment (the metric its cloud runs, else a product's Prometheus signal),
thresholds read in the signal's unit, the PromQL a rule becomes, and the planner's action for a rule the target
delivers but nothing there evaluates."""
import datetime as dt
from decimal import Decimal

from opsdir.core.contract import Adapter, PlanContext, Signal
from opsdir.core.directory import get
from opsdir.core.environment import env_model
from opsdir.core.interchange.ldif import parse
from opsdir.core.inventory import duration_seconds
from opsdir.connectors.observability import signal_check
from opsdir.domains.observability.naming import ALERT_RULES
from opsdir.domains.observability.signals import (convert, evaluation, number_text, parse_threshold, promql,
                                                  threshold_in)
import mini_estate
from support import REGISTRY, build_directory

ALPHA = "env=prod,cloud=alpha,ou=environments,dc=ciam-ops"
BETA = "env=prod,cloud=beta,ou=environments,dc=ciam-ops"
LAG = f"cn=replication-lag,{ALERT_RULES}"
DELAY = Signal("replication-delay", "web", "max by (instance) (lag_seconds)", "s", "replication delay")


def _binding(env, cn, oc, role, extra=""):
    return (f"dn: cn={cn},ou=bindings,{env}\nobjectClass: top\nobjectClass: {oc}\ncn: {cn}\nciamBindingRole: {role}\n"
            f"{extra}")


BASE = (
    _binding(ALPHA, "page", "ciamAlertChannel", "alerts-page", "ciamChannelKind: topic\nciamProviderRef: sns-1\n"),
    _binding(BETA, "page", "ciamAlertChannel", "alerts-page",
             "ciamChannelKind: action-group\nciamProviderRef: ag-1\n"),
    f"dn: {ALERT_RULES}\nobjectClass: top\nobjectClass: organizationalUnit\nou: alert-rules\n",
    f"dn: {LAG}\nobjectClass: top\nobjectClass: ciamObject\nobjectClass: ciamAlertRule\ncn: replication-lag\n"
    "ciamSignal: replication-delay\nciamTargetRole: web\nciamComparison: gt\nciamThreshold: 5000 ms\n"
    "ciamEvaluationPeriod: 5m\nciamAlertRole: alerts-page\n",
    # delivered nowhere: the observability domain's blocker, not this check's
    f"dn: cn=ticket,{ALERT_RULES}\nobjectClass: top\nobjectClass: ciamObject\nobjectClass: ciamAlertRule\n"
    "cn: ticket\nciamSignal: disk-free\nciamAlertRole: alerts-ticket\n",
)
ALARM = _binding(BETA, "lag", "ciamAlarmBinding", "alarm-replication-lag",
                 "ciamProviderRef: alarm-1\nciamRealizes: replication-lag\nciamMetric: CIAM/DS ReplicationDelay\n")


def _record(*extra):
    return build_directory(REGISTRY, tuple(parse(mini_estate.LDIF + "\n" + "\n".join((*BASE, *extra)))))


def _plan(d, adapters):
    return signal_check(adapters)(PlanContext(d, env_model(d, "alpha/prod"), env_model(d, "beta/prod"), None,
                                              dt.date(2026, 10, 1), {}, {}, ()))


def _adapter(*signals):
    return Adapter(name="product", kind="product", applies=None, required_roles=(), render_neutral=None,
                   render_env=None, checks=(), ref_schemes=(), secret_schemes={}, renders=None, neutral_label=None,
                   vocabulary={}, schema=None, formats=(), products=(), secret_patterns=(), importers=(),
                   profile_terms=None, access=None, signals=signals)


def test_thresholds_are_read_with_their_unit():
    assert parse_threshold("5000 ms") == (Decimal(5000), "ms")
    assert parse_threshold("90%") == (Decimal(90), "%")
    assert parse_threshold("50 /min") == (Decimal(50), "/min")
    assert parse_threshold("0.5") == (Decimal("0.5"), None)
    assert parse_threshold("lots") is None and parse_threshold(None) is None


def test_thresholds_convert_within_a_kind_only():
    assert convert(Decimal(5000), "ms", "s") == Decimal(5)
    assert convert(Decimal(10), "GB", "bytes") == Decimal(10) ** 10
    assert convert(Decimal(90), "%", "ratio") == Decimal("0.9")
    assert number_text(convert(Decimal(50), "/min", "/s")) == "0.833333"
    assert convert(Decimal(5), None, "s") == Decimal(5)
    assert convert(Decimal(5), "ms", "bytes") is None
    assert convert(Decimal(5), "furlongs", "s") is None


def test_a_rule_becomes_promql_in_the_signals_unit():
    d = _record()
    rule = get(d, LAG)
    assert threshold_in(rule, "s") == "5"
    assert promql(rule, DELAY) == ("(max by (instance) (lag_seconds)) > 5", None)
    expr, why = promql(rule, DELAY._replace(unit="bytes"))
    assert expr is None and why == ("alert rule replication-lag's threshold '5000 ms' can't be read in "
                                    "replication-delay's unit (bytes)")


def test_the_clouds_metric_wins_over_a_product_signal():
    d = _record(ALARM)
    e = evaluation(env_model(d, "beta/prod"), (DELAY,), get(d, LAG))
    assert e.alarm is not None and e.signal is DELAY and e.missing is None
    e = evaluation(env_model(d, "alpha/prod"), (), get(d, LAG))
    assert (e.alarm, e.signal) == (None, None)
    assert e.missing == ("no alarm in alpha/prod realizes it with a recorded metric (ciamMetric), and no product "
                         "declares signal `replication-delay` for role `web`")


def test_a_rule_the_target_delivers_but_cant_evaluate_is_an_action():
    f = _plan(_record(), ())
    assert [t for _, t, _, _ in f.actions] == [
        "Alert rule `replication-lag` can't be evaluated in beta/prod: no alarm in beta/prod realizes it with a "
        "recorded metric (ciamMetric), and no product declares signal `replication-delay` for role `web`. Record the "
        "metric the alarm realizing it evaluates there (ciamMetric), or install a product adapter that declares the "
        "signal."]
    assert _plan(_record(), (_adapter(DELAY),)).actions == ()
    assert _plan(_record(ALARM), ()).actions == ()


def test_durations_read_back_in_seconds():
    assert [duration_seconds(t) for t in ("30s", "5m", "2h", "1d", "5", "m", None)] == [30, 300, 7200, 86400, None,
                                                                                        None, None]


def test_the_products_declare_only_documented_signals():
    from opsdir_adapter_pingam.adapter import ADAPTER as AM
    from opsdir_adapter_pingds.adapter import ADAPTER as DS
    from opsdir_adapter_pingidm.adapter import ADAPTER as IDM
    from opsdir_adapter_pingfederate.adapter import ADAPTER as PF
    assert {(s.signal, s.server_role, s.unit) for s in DS.signals} == {
        ("replication-delay", "ds", "s"), ("disk-free", "ds", "bytes"), ("heap-used", "ds", "bytes"),
        ("ldap-errors", "ds", "/s")}
    assert [(s.signal, s.server_role) for s in AM.signals] == [("login-failures", "am")]
    assert [(s.signal, s.server_role) for s in IDM.signals] == [("heap-used", "idm")]
    assert PF.signals == ()                 # PingFederate serves heartbeat statistics, no Prometheus endpoint

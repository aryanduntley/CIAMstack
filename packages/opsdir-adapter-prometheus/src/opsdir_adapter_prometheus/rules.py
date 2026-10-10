"""The alerting rules Prometheus evaluates for an environment: each alert rule of the record on a server role the
environment runs, whose signal a product rendering it declares as Prometheus metrics (core.contract.Signal), as one
alerting rule (domains/observability/signals.promql: the signal's expression compared with the threshold in its
unit), held for the rule's evaluation period. Grouped by the role of the channel that delivers them (ciamAlertRole):
Alertmanager routes them by their labels (severity, team, ciam_rule, environment), which stays the operators'. A rule
on a role the environment doesn't run isn't its concern; one no product here declares the signal of, or whose
threshold can't be read in the signal's unit, is named, not rendered. Pure."""
from opsdir.core.directory import follow_all, one, rdn_value
from opsdir.domains.compute.workloads import runs_here
from opsdir.domains.observability.alerts import alert_rules
from opsdir.domains.observability.signals import product_signal, promql

GROUP_PREFIX = "ciam-"


def _runbook(d, r):
    """The rule's first runbook as its link (ciamDocUrl), else its name and title, or None."""
    book = next(iter(follow_all(d, r, "ciamRunbookRef")), None)
    if book is None:
        return None
    return one(book, "ciamDocUrl") or f"{rdn_value(book)}: {one(book, 'ciamTitle')}"


def _alert(m, r, signal, expr):
    owners = [rdn_value(o) for o in follow_all(m.d, r, "ciamOwner")]
    labels = {"severity": one(r, "ciamSeverity"), "team": owners[0] if owners else None, "ciam_rule": rdn_value(r),
              "environment": m.label}
    runbook = _runbook(m.d, r)
    condition = " ".join(p for p in (one(r, "ciamComparison"), one(r, "ciamThreshold")) if p)
    annotations = {"summary": f"{signal.description}: {condition} on {signal.server_role}",
                   **({"runbook": runbook} if runbook else {})}
    period = one(r, "ciamEvaluationPeriod")
    return {"alert": rdn_value(r), "expr": expr, **({"for": period} if period else {}),
            "labels": {k: v for k, v in labels.items() if v}, "annotations": annotations}


def _skipped(m, r, signals):
    """(alert, None) of a rule rendered here, (None, why not) of one named instead, or (None, None) of a rule on a
    role environment m doesn't run."""
    role = one(r, "ciamTargetRole")
    if role and not runs_here(m, role):
        return None, None
    signal = product_signal(signals, r)
    if signal is None:
        return None, (f"alert rule {rdn_value(r)}: no product rendering {m.label} declares signal "
                      f"`{one(r, 'ciamSignal')}`" + (f" for role `{role}`" if role else " (it names no role)"))
    expr, why = promql(r, signal)
    return (_alert(m, r, signal, expr), None) if expr else (None, why)


def rule_set(m, signals):
    """(rule groups as Prometheus reads them, (why each rule not rendered, ...)) of environment m, given the Signals
    of the adapters rendering it."""
    done = [(one(r, "ciamAlertRole"), *_skipped(m, r, signals)) for r in alert_rules(m.d)]
    roles = tuple(dict.fromkeys(role for role, alert, _ in done if alert))
    groups = [{"name": f"{GROUP_PREFIX}{role}", "rules": [a for g, a, _ in done if a and g == role]} for role in roles]
    return groups, tuple(why for _, _, why in done if why)

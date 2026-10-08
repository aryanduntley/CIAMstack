"""Budgets: what an environment may spend each period (ciamBudget: an amount in a currency, monthly, quarterly or
annually) and at which shares of it, spent or forecast, the channel of its ciamAlertRole is alerted; the cloud's
ciamBillingAccountRef says where billing is managed, which is where budgets live when that isn't the account itself
(AWS GovCloud's associated standard account; a Google Cloud billing account). The report, and the planner's check: a
target without a budget while the source has one is an action (its spending would go unwatched); a target budget
alerting a role it doesn't bind is a blocker (its alerts would reach no one). Pure."""
from ...core.directory import get, one, rdn_value, subtree, values
from ...core.environment import env_model, of_class, one_role
from ...core.findings import findings, responsible
from ...core.naming import branch
from .naming import DEFAULT_CURRENCY

AREA = "Budgets"
BUDGET = "ciamBudget"
BUDGET_HEADERS = ("environment", "budget", "amount", "period", "alert at (spent)", "alert at (forecast)", "alerts to",
                  "kept by")


def budgets(m):
    """Environment m's budgets."""
    return of_class(m, BUDGET)


def budget_role(resource, roles):
    """The binding role of a budget a cloud reports (ImportKind role): budget."""
    return "budget"


def budget_channel(m, b):
    """The binding of environment m a budget alerts (its ciamAlertRole), or None."""
    role = one(b, "ciamAlertRole")
    return one_role(m, role) if role else None


def currency(b):
    """A budget's currency (USD when it names none)."""
    return one(b, "ciamCurrency") or DEFAULT_CURRENCY


def thresholds(b, attr):
    """A budget's alert thresholds of one kind (ciamActualThreshold, ciamForecastThreshold), percents, ascending."""
    return tuple(sorted(int(v) for v in values(b, attr)))


def check_budgets(ctx):
    """A target without a budget while the source has one (an action); a target budget whose alerts go to a role it
    doesn't bind (a blocker). Nothing when neither environment records a budget."""
    src, dst = budgets(ctx.src), budgets(ctx.dst)
    if not src and not dst:
        return findings()
    owner = responsible(ctx.d, ctx.dst.env)
    unbound = [(AREA, f"Budget `{rdn_value(b)}` in {ctx.dst.label} alerts role `{one(b, 'ciamAlertRole')}`, which "
                      f"{ctx.dst.label} doesn't bind: its alerts reach no one. Record the channel.",
                responsible(ctx.d, b, ctx.dst.env))
               for b in dst if one(b, "ciamAlertRole") and budget_channel(ctx.dst, b) is None]
    missing = [(AREA, f"{ctx.src.label} has a budget ({', '.join(f'{rdn_value(b)}: {_amount(b)}' for b in src)}) and "
                      f"{ctx.dst.label} none: its spending would go unwatched. Record the target's (ciamBudget).",
                owner, ctx.cutover)] if src and not dst else []
    return findings(blockers=unbound, actions=missing,
                    ok=() if unbound or missing or not dst else
                    (f"Budgets recorded in {ctx.dst.label}: {', '.join(_amount(b) for b in dst)}.",))


def _amount(b):
    return f"{one(b, 'ciamBudgetAmount')} {currency(b)} {one(b, 'ciamBudgetPeriod') or 'monthly'}"


def _keeper(m, b):
    ref = one(b, "ciamManagedBy")
    keeper = get(m.d, ref) if ref else None
    return rdn_value(keeper) if keeper is not None else "platform"


def _percents(b, attr):
    return ", ".join(f"{p}%" for p in thresholds(b, attr))


def budget_rows(d, dn=None):
    """One row per budget of every environment: its amount and currency, period, alert thresholds (spent, forecast),
    the role its alerts go to and who keeps it (the platform team unless ciamManagedBy names someone)."""
    models = [env_model(d, e.dn) for e in subtree(d, branch("environments"), "ciamEnvironment")]
    return [(m.label, rdn_value(b), f"{one(b, 'ciamBudgetAmount')} {currency(b)}", one(b, "ciamBudgetPeriod") or
             "monthly", _percents(b, "ciamActualThreshold"), _percents(b, "ciamForecastThreshold"),
             one(b, "ciamAlertRole", ""), _keeper(m, b))
            for m in models for b in budgets(m)]

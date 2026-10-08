"""Quotas and budgets (core estate). Quotas: a target whose limits aren't fetched, or whose provider doesn't list a
quota it needs, gives an action; a limit below what its environments need together is an action the operator decides
(request the need, a value of their own, or deny), a request short of the need or not yet granted an action, a denial
a blocker; a need the source records and the target doesn't, an action; the import keeps only what is needed. Budgets:
a target without the source's budget gives an action, a budget alerting a role the target doesn't bind a blocker; the
reports."""
from opsdir.connectors.fixes import chosen
from opsdir.core.findings import findings
from opsdir.domains.estate.budgets import budget_rows, check_budgets
from opsdir.domains.estate.quotas import (QuotaRow, check_quotas, needed, quota_import, quota_rows, wanted_quotas)
from network_fixtures import ALPHA, BETA, context, entry, model

QUOTAS = "ou=quotas,dc=ciam-ops"
CATALOG = f"cn=fakecloud:111:region-1,{QUOTAS}"


def catalog(**limits):
    """The quota catalog of fakecloud's account 111 in region-1: {quota id: (value, kind)}."""
    return (f"dn: {QUOTAS}\nobjectClass: top\nobjectClass: organizationalUnit\nou: quotas\n",
            f"dn: {CATALOG}\nobjectClass: top\nobjectClass: ciamQuotaCatalog\ncn: fakecloud:111:region-1\n"
            "ciamCloudProvider: fakecloud\nciamAccountRef: 111\nciamRegion: region-1\n",
            *(f"dn: cn={q},{CATALOG}\nobjectClass: top\nobjectClass: ciamQuotaLimit\ncn: {q}\nciamQuotaValue: {v}\n"
              f"ciamQuotaKind: {k}\n" for q, (v, k) in limits.items()))


def need(env, cn, kind, n, **more):
    return entry(env, cn, "ciamQuotaNeed", ciamBindingRole=cn, ciamQuotaKind=kind, ciamQuotaNeeded=str(n), **more)


def _ctx(alpha=(), beta=(), tree=()):
    d, a, b = model(alpha=alpha, beta=beta, tree=tree)
    return context(d, a, b, cutover="2026-12-01")


def test_nothing_when_neither_environment_needs_a_quota():
    assert check_quotas(_ctx()) == findings()


def test_limits_not_fetched_is_an_action_naming_the_fetch():
    f = check_quotas(_ctx(beta=(need(BETA, "cpus", "vcpus", 16),)))
    assert f.blockers == () and [(a[1], a[3]) for a in f.actions] == [
        ("beta/prod's quota limits (fakecloud account (not recorded) in region-1) aren't fetched: fetch them (`opsdir "
         "import fakecloud/quotas --run`) so its needs (vcpus) are checked.", "2026-12-01")]


def test_a_limit_below_need_waits_for_the_operators_decision():
    ctx = _ctx(beta=(need(BETA, "cpus", "vcpus", 10), need(BETA, "more-cpus", "vcpus", 6)),
               tree=catalog(CPUS=(8, "vcpus")))
    f = check_quotas(ctx)
    assert needed(ctx.dst, "vcpus") == 16
    assert f.blockers == () and [a[1] for a in f.actions] == [
        "`vcpus` on fakecloud account (not recorded) in region-1 is limited to 8 and its environments need 16: decide "
        "whether to raise it (request the need, a value of your own, or deny)."]
    fix, = f.fixes
    assert [o.key for o in fix.options] == ["approve", "amount", "deny"]
    approve = chosen(fix, "approve").records[0]
    assert approve.dn == f"cn=cpus,ou=bindings,{BETA}" and approve.mods == (
        ("replace", "ciamQuotaDecision", ("request",)), ("replace", "ciamQuotaRequested", ("16",)))
    assert chosen(fix, "amount", {"ciamQuotaRequested": ("20",)}).records[0].mods[1] == \
        ("replace", "ciamQuotaRequested", ("20",))
    assert chosen(fix, "deny").records[0].mods == (("replace", "ciamQuotaDecision", ("deny",)),)


def test_decisions_deny_blocks_short_and_pending_requests_are_actions():
    tree = catalog(CPUS=(8, "vcpus"))
    f = check_quotas(_ctx(beta=(need(BETA, "cpus", "vcpus", 16, ciamQuotaDecision="deny"),), tree=tree))
    assert f.actions == () and f.fixes == () and [b[1] for b in f.blockers] == [
        "`vcpus` on fakecloud account (not recorded) in region-1 is limited to 8 and its environments need 16; raising "
        "it was denied (ciamQuotaDecision): the move stops until the need is lowered or the decision changes."]
    f = check_quotas(_ctx(beta=(need(BETA, "cpus", "vcpus", 16, ciamQuotaDecision="request",
                                    ciamQuotaRequested="12"),), tree=tree))
    assert f.blockers == () and f.actions[0][1].endswith("12 was requested: still 4 short. Request at least 16.")
    f = check_quotas(_ctx(beta=(need(BETA, "cpus", "vcpus", 16, ciamQuotaDecision="request"),), tree=tree))
    assert f.actions[0][1].endswith("16 is requested (rendered where the cloud takes requests): fetch the quotas "
                                    "again once the provider grants it.")


def test_enough_unlisted_and_unrecorded():
    tree = catalog(CPUS=(64, "vcpus"))
    f = check_quotas(_ctx(beta=(need(BETA, "cpus", "vcpus", 16),), tree=tree))
    assert f.actions == () and f.ok == ("beta/prod's quota limits cover what its environments need: vcpus.",)
    f = check_quotas(_ctx(alpha=(need(ALPHA, "lbs", "load-balancers", 2),),
                          beta=(need(BETA, "cpus", "vcpus", 16), need(BETA, "ips", "public-ips", 4)), tree=tree))
    assert [a[1] for a in f.actions] == [
        "The provider's quota list for fakecloud account (not recorded) in region-1 has no `public-ips` quota, which "
        "beta/prod needs 4 of: confirm the limit with the provider (some are raised only through a support case).",
        "alpha/prod needs `load-balancers` of its provider's limits and beta/prod records no such need: record the "
        "target's (ciamQuotaNeed) so its limits are checked."]


def test_quota_import_keeps_what_the_environments_need():
    d, _, _ = model(alpha=(need(ALPHA, "cpus", "vcpus", 4),),
                    beta=(entry(BETA, "family", "ciamQuotaNeed", ciamBindingRole="family", ciamQuotaNeeded="8",
                                ciamProviderRef="standardDSv5Family"),))
    assert wanted_quotas(d, "fakecloud") == (("vcpus",), ("standardDSv5Family",))
    imported = quota_import(d, "fakecloud", {
        ("111", "region-1"): (QuotaRow("CPUS", 32, "CPUs", 3, "vcpus"), QuotaRow("standardDSv5Family", 10),
                              QuotaRow("DISKS", 100)),
        ("111", "region-2"): (QuotaRow("DISKS", 100),)})
    (dn, entries), = imported.groups
    assert dn == CATALOG and [(e.dn.split(",")[0], dict(e.attrs).get("ciamQuotaValue")) for e in entries] == [
        ("cn=fakecloud:111:region-1", None), ("cn=CPUS", ("32",)), ("cn=standardDSv5Family", ("10",))]
    assert imported.notices == (
        "fakecloud account 111 in region-1: 2 of the quotas the environments need",
        "fakecloud account 111 in region-2: none of the quotas the environments need is listed; its catalog left as "
        "it is")


def test_quota_report():
    d, _, _ = model(beta=(need(BETA, "cpus", "vcpus", 16, ciamQuotaDecision="request"),),
                    tree=catalog(CPUS=(8, "vcpus")))
    assert quota_rows(d) == [("beta/prod", "vcpus", "16", "16", "8", "", "request", "", "requested")]
    d, _, _ = model(beta=(need(BETA, "cpus", "vcpus", 16, ciamQuotaDecision="request", ciamQuotaRequested="12"),),
                    tree=catalog(CPUS=(8, "vcpus")))
    assert quota_rows(d)[0][-1] == "short"


CHANNEL = "cost-alerts"


def budget(env, cn="monthly", **more):
    return entry(env, cn, "ciamBudget", ciamBindingRole="budget", ciamBudgetAmount="5000",
                 ciamActualThreshold=("80", "100"), ciamForecastThreshold="100", ciamAlertRole=CHANNEL, **more)


def channel(env):
    return entry(env, CHANNEL, "ciamAlertChannel", ciamBindingRole=CHANNEL, ciamChannelKind="topic")


def test_budgets_missing_in_the_target_and_alerting_no_one():
    assert check_budgets(_ctx()) == findings()
    f = check_budgets(_ctx(alpha=(budget(ALPHA), channel(ALPHA))))
    assert f.blockers == () and [(a[1], a[3]) for a in f.actions] == [
        ("alpha/prod has a budget (monthly: 5000 USD monthly) and beta/prod none: its spending would go unwatched. "
         "Record the target's (ciamBudget).", "2026-12-01")]
    f = check_budgets(_ctx(alpha=(budget(ALPHA), channel(ALPHA)), beta=(budget(BETA, ciamCurrency="EUR"),)))
    assert f.actions == () and [b[1] for b in f.blockers] == [
        "Budget `monthly` in beta/prod alerts role `cost-alerts`, which beta/prod doesn't bind: its alerts reach no "
        "one. Record the channel."]
    f = check_budgets(_ctx(beta=(budget(BETA, ciamBudgetPeriod="quarterly"), channel(BETA))))
    assert f.ok == ("Budgets recorded in beta/prod: 5000 USD quarterly.",)


def test_budget_report():
    d, _, _ = model(beta=(budget(BETA, ciamCurrency="EUR"), channel(BETA)))
    assert budget_rows(d) == [("beta/prod", "monthly", "5000 EUR", "monthly", "80%, 100%", "100%", CHANNEL,
                               "platform")]

"""Data discovery (core estate): a target running none while the source does, leaving a store unexamined the source
examines and the target binds, or not looking for one of the source's own data types gives actions, blockers where the
target holds controlled data; examining less often and keeping findings or results the source sends on give actions; a
target service sending findings or results to a role it doesn't bind blocks; the data-discovery report."""
from opsdir.core.directory import make_entry
from opsdir.core.findings import findings
from opsdir.domains.estate.discovery import (check_discovery, custom_identifiers, discovery_role, discovery_rows,
                                             discovery_services, rescan_days, scanned_roles)
from network_fixtures import ALPHA, BETA, context, entry, model

CUI, EMPLOYEE = "cui-marking: CUI//[A-Z-]+", "employee-id: EA[0-9]{6}"


def discovery(env, cn="discovery", scans=("ds-backups",), identifiers=(CUI, EMPLOYEE), days="7", **more):
    return entry(env, cn, "ciamDataDiscovery", ciamBindingRole="data-discovery", ciamScansRole=tuple(scans),
                 **({"ciamCustomIdentifier": tuple(identifiers)} if identifiers else {}),
                 **({"ciamRescanDays": days} if days else {}), **more)


def stores(env):
    return (entry(env, "backups", "ciamObjectStore", ciamBindingRole="ds-backups", ciamStorageRef="s3://backups"),
            entry(env, "exports", "ciamObjectStore", ciamBindingRole="idm-exports", ciamStorageRef="s3://exports"),
            entry(env, "audit", "ciamObjectStore", ciamBindingRole="audit-archive", ciamStorageRef="s3://audit"),
            entry(env, "security-alerts", "ciamAlertChannel", ciamBindingRole="security-alerts",
                  ciamChannelKind="topic"))


def _ctx(alpha=(), beta=(), restricted=False, levels=()):
    d, a, b = model(alpha=alpha, beta=beta)
    extra = {**({"ciamDataClassification": ("restricted",)} if restricted else {}),
             **({"ciamRequiredAuthorization": tuple(levels)} if levels else {})}
    if extra:
        b = b._replace(env=make_entry(b.env.dn, (*b.env.classes, "ciamEnvironmentPlacement"),
                                      {**b.env.attrs, **extra}))
    return context(d, a, b, cutover="2026-12-01"), d


def test_nothing_when_neither_environment_records_one():
    ctx, _ = _ctx()
    assert check_discovery(ctx) == findings()


def test_a_target_running_none_is_an_action_and_a_blocker_where_it_holds_controlled_data():
    src = (discovery(ALPHA, scans=("ds-backups", "idm-exports")), *stores(ALPHA))
    ctx, _ = _ctx(alpha=src, beta=stores(BETA))
    text = ("alpha/prod runs data discovery (discovery, over ds-backups, idm-exports) and beta/prod runs none: where "
            "the target's sensitive data lies would go unknown (NIST SP 800-53 CM-12). Record the target's.")
    assert [a[1] for a in check_discovery(ctx).actions] == [text] and check_discovery(ctx).blockers == ()
    held, _ = _ctx(alpha=src, beta=stores(BETA), levels=("fedramp-moderate",))
    assert [b[1] for b in check_discovery(held).blockers] == [
        text + " beta/prod holds controlled data (held to fedramp-moderate): this blocks the move."]
    restricted, _ = _ctx(alpha=src, beta=stores(BETA), restricted=True)
    assert check_discovery(restricted).blockers[0][1].endswith("(classified restricted): this blocks the move.")


def test_a_store_left_unexamined_and_an_own_data_type_not_looked_for():
    ctx, _ = _ctx(alpha=(discovery(ALPHA, scans=("ds-backups", "idm-exports", "not-in-beta")), *stores(ALPHA)),
                  beta=(discovery(BETA, identifiers=(CUI,)), *stores(BETA)))
    assert [a[1] for a in check_discovery(ctx).actions] == [
        "alpha/prod examines `idm-exports` for sensitive data and beta/prod's data discovery doesn't: add it to the "
        "target's.",
        "alpha/prod looks for its own data type `employee-id` (EA[0-9]{6}) and beta/prod doesn't: add the identifier "
        "to the target's data discovery, or that data won't be found."]       # not-in-beta: beta doesn't bind it


def test_examining_less_often_is_an_action_and_keeping_findings_or_results_a_gap():
    src = discovery(ALPHA, days="1", ciamFindingsRole="security-alerts", ciamResultsRole="audit-archive")
    ctx, _ = _ctx(alpha=(src, *stores(ALPHA)), beta=(discovery(BETA, days="7"), *stores(BETA)),
                  levels=("fedramp-moderate",))
    f = check_discovery(ctx)
    held = " beta/prod holds controlled data (held to fedramp-moderate): this blocks the move."
    assert [a[1] for a in f.actions] == [
        "alpha/prod examines its stores every 1 days and beta/prod every 7: sensitive data written in between goes "
        "unknown longer; examine the target's as often."]
    assert [b[1] for b in f.blockers] == [
        "alpha/prod's data discovery sends its findings on and beta/prod's keeps them in the service: send them where "
        "someone acts on them." + held,
        "alpha/prod's data discovery keeps its detailed results (where sensitive data was found) and beta/prod's "
        "doesn't: keep the target's." + held]


def test_findings_or_results_to_a_role_the_target_doesnt_bind_block():
    ctx, _ = _ctx(beta=(discovery(BETA, ciamFindingsRole="nowhere", ciamResultsRole="audit-archive"), *stores(BETA)))
    assert [b[1] for b in check_discovery(ctx).blockers] == [
        "Data discovery `discovery` in beta/prod sends its findings to role `nowhere`, which beta/prod doesn't bind: "
        "they reach no one. Record where they go."]


def test_a_matching_target_is_in_place():
    ctx, _ = _ctx(alpha=(discovery(ALPHA), *stores(ALPHA)), beta=(discovery(BETA), *stores(BETA)))
    assert check_discovery(ctx) == findings(ok=("Data discovery recorded in beta/prod: discovery.",))


def test_helpers_and_report():
    ctx, d = _ctx(alpha=(discovery(ALPHA, ciamFindingsRole="security-alerts"),
                         discovery(ALPHA, cn="daily", scans=("ds-backups", "x"), days="1"), *stores(ALPHA)),
                  beta=(discovery(BETA, cn="dspm", days=None, identifiers=()), *stores(BETA)))
    src, dst = discovery_services(ctx.src), discovery_services(ctx.dst)
    assert custom_identifiers(src[0]) == (("cui-marking", "CUI//[A-Z-]+"), ("employee-id", "EA[0-9]{6}"))
    assert scanned_roles(src) == ("ds-backups", "x") and rescan_days(src) == 1 and rescan_days(dst) is None
    assert discovery_role(None, ()) == "data-discovery"
    assert discovery_rows(d) == [
        ("alpha/prod", "daily", "ds-backups, x", "cui-marking, employee-id", "1", "", "", "platform"),
        ("alpha/prod", "discovery", "ds-backups", "cui-marking, employee-id", "7", "security-alerts", "", "platform"),
        ("beta/prod", "dspm", "ds-backups", "", "", "", "", "platform")]

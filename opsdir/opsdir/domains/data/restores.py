"""Restore tests: the record of each restore someone did (ciamRestoreTest under ou=restore-tests): when, in which
environment, whose data and from what, what it proved (the disk restored and mounted, or the application's data
restored and verified to work), how it went and how long it took. The restore-tests report, and the planner check
holding both environments to them for every role the source protects (a backup nobody has restored shows nothing): in
the source, a role never restore-tested, last failed, or tested too long ago is an action; in the target, a failed
latest test is a blocker, and no passed application-level test before cutover (or an overdue one) an action. Tests
are due every restore-test-interval-days (an estate setting) unless a plan protecting the role says otherwise. Pure."""
import datetime as dt

from ...core.directory import children, date_of, norm_dn, one, rdn_of, rdn_value, values
from ...core.findings import findings, merge_findings, owner_label, responsible
from ...core.naming import env_label
from ...core.settings import setting_value
from .backups import holds_role, protected_roles
from .naming import RESTORE_TESTS
from .settings import RESTORE_TEST_DAYS

TEST = "ciamRestoreTest"
AREA = "Restore tests"
RESTORE_HEADERS = ("tested on", "environment", "restored", "from", "level", "result", "minutes", "runbook", "owner")


def restore_tests(d):
    """Every restore-test record, newest first."""
    return tuple(sorted(children(d, RESTORE_TESTS, TEST),
                        key=lambda t: (date_of(t, "ciamTestedOn") or dt.date.min, rdn_value(t)), reverse=True))


def tests_of(d, env_dn, role):
    """The restore tests of a role in an environment (its DN), newest first."""
    env = norm_dn(env_dn)
    return tuple(t for t in restore_tests(d) if norm_dn(one(t, "ciamTestEnvironment") or "") == env
                 and one(t, "ciamRestoredRole") == role)


def restore_interval(d, m, role):
    """Days within which a role's restores must be tested in environment m: the shortest a plan protecting it there
    says (ciamRestoreTestDays), else the estate setting."""
    own = [int(one(p, "ciamRestoreTestDays")) for p in protected_roles(m).get(role, ())
           if one(p, "ciamRestoreTestDays")]
    return min(own) if own else setting_value(d, RESTORE_TEST_DAYS)


def restore_rows(d, dn=None):
    """One row per restore test, newest first."""
    return [(str(date_of(t, "ciamTestedOn") or ""), env_label(one(t, "ciamTestEnvironment")),
             one(t, "ciamRestoredRole"), one(t, "ciamRestoredFromRole") or "", one(t, "ciamRestoreLevel"),
             one(t, "ciamTestResult"), one(t, "ciamRestoreMinutes") or "",
             ", ".join(rdn_of(r) for r in values(t, "ciamRunbookRef")),
             owner_label(d, t) if values(t, "ciamOwner") else "")
            for t in restore_tests(d)]


# ------------------------------------------------------------------ check
def _passed(tests, level=None):
    return [t for t in tests if one(t, "ciamTestResult") == "passed"
            and (level is None or one(t, "ciamRestoreLevel") == level)]


def _overdue(ctx, t, every):
    return (ctx.as_of - date_of(t, "ciamTestedOn")).days > every


def _owner(ctx, m, role):
    return responsible(ctx.d, *protected_roles(m).get(role, ()), m.env)


def _source(ctx, role):
    """The source's restore tests of a role: none, the latest failed, or the last passed one too old."""
    tests, every, owner = tests_of(ctx.d, ctx.src.dn, role), restore_interval(ctx.d, ctx.src, role), \
        _owner(ctx, ctx.src, role)
    passed = _passed(tests)
    if not tests:
        text = (f"Role `{role}` is backed up in {ctx.src.label} but no restore of it has been tested: nothing shows "
                "its backups can be restored.")
    elif one(tests[0], "ciamTestResult") == "failed":
        text = (f"The latest restore test of `{role}` in {ctx.src.label} ({date_of(tests[0], 'ciamTestedOn')}) "
                "failed: its backups may not restore.")
    elif not passed:
        text = f"No restore test of `{role}` in {ctx.src.label} has passed: nothing shows its backups can be restored."
    elif _overdue(ctx, passed[0], every):
        text = (f"`{role}` was last restore-tested in {ctx.src.label} on {date_of(passed[0], 'ciamTestedOn')}; tests "
                f"are due every {every} days.")
    else:
        return findings()
    return findings(actions=[(AREA, text, owner, ctx.cutover)])


def _target(ctx, role):
    """The target's restore tests of a role the source protects: the latest failed (a blocker), no passed
    application-level test, or an overdue one."""
    tests, every, owner = tests_of(ctx.d, ctx.dst.dn, role), restore_interval(ctx.d, ctx.dst, role), \
        _owner(ctx, ctx.dst, role)
    if tests and one(tests[0], "ciamTestResult") == "failed":
        return findings(blockers=[(AREA, f"The latest restore test of `{role}` in {ctx.dst.label} "
                                         f"({date_of(tests[0], 'ciamTestedOn')}) failed: nothing shows its data can be "
                                         "recovered there.", owner)])
    verified = _passed(tests, "application")
    if not verified:
        return findings(actions=[(AREA, f"Before cutover, restore `{role}`'s data in {ctx.dst.label} from its backups "
                                        "and verify the application works with it, then record the test: nothing "
                                        f"shows {ctx.dst.label} can recover it (a disk mounted isn't enough).", owner,
                                  ctx.cutover)])
    if _overdue(ctx, verified[0], every):
        return findings(actions=[(AREA, f"`{role}`'s last application-level restore test in {ctx.dst.label} was on "
                                        f"{date_of(verified[0], 'ciamTestedOn')}; tests are due every {every} days: "
                                        "test again before cutover.", owner, ctx.cutover)])
    return findings()


def check_restores(ctx):
    """Every role the source protects (a backup plan, a snapshot policy): restore-tested in the source, and in the
    target where it binds the role or runs its servers."""
    roles = sorted(protected_roles(ctx.src))
    parts = merge_findings([*(_source(ctx, role) for role in roles),
                            *(_target(ctx, role) for role in roles if holds_role(ctx.dst, role))])
    if roles and not (parts.blockers or parts.actions):
        return parts._replace(ok=(*parts.ok, f"{len(roles)} protected role(s) restore-tested in {ctx.src.label} and "
                                             f"{ctx.dst.label}."))
    return parts

"""Fixes that wait for something to happen first: pinning firewall priorities needs an import of the environment's
rules taken after their last change, since a slot free in the record may be taken by a live rule the record lacks.
Until then the fix is offered but can't be proposed or applied, and says what it waits for."""
import datetime as dt

from opsdir.cli import _fix_lines
from opsdir.connectors.fixes import unmet
from opsdir.domains.governance.imports import run_records
from opsdir.domains.infrastructure.firewall import priority_check
from network_fixtures import ALPHA, BETA, context, model, rule

CHECK = priority_check(100, 10, 4096)
AT = dt.datetime(2026, 9, 20, 3, 0, tzinfo=dt.timezone.utc)
CHANGE = (f"dn: cn=CHG-1,ou=changes,dc=ciam-ops\nobjectClass: top\nobjectClass: ciamChange\ncn: CHG-1\n"
          "ciamTitle: import\nciamChangeStatus: approved\n",)


def _pinned(env, cn, prio=None):
    return rule(env, cn, "10.0.0.0/24", "1636", "ds") + (f"ciamRulePriority: {prio}\n" if prio else "")


def _found(beta, changes=()):
    d, alpha, b = model(beta=beta, tree=CHANGE, changes=changes)
    return d, CHECK(context(d, alpha, b))


def test_unpinned_rules_are_an_action_with_the_fix_pinning_the_render_s_slots():
    d, found = _found((_pinned(BETA, "fw-a", 100), _pinned(BETA, "fw-b"), _pinned(BETA, "fw-c")))
    (action,) = found.actions
    assert action[1] == ("2 firewall rule(s) in beta/prod have no pinned priority (`fw-b` 110, `fw-c` 120): the "
                         "render assigns free slots that a live rule the record lacks may already hold. Import "
                         "beta/prod's rules, then pin them.")
    (fix,) = found.fixes
    assert (fix.key, [r.mods for r in fix.records]) == ("priorities:beta/prod", [
        (("replace", "ciamRulePriority", ("110",)),), (("replace", "ciamRulePriority", ("120",)),)])
    (req,) = fix.requires
    assert req.entries == tuple(f"cn={c},ou=bindings,{BETA}" for c in ("fw-a", "fw-b", "fw-c"))
    assert "First (propose and apply wait for it):" in _fix_lines(fix)
    assert _found((_pinned(BETA, "fw-a", 100),))[1].actions == ()


def test_the_fix_waits_for_an_import_taken_after_the_rules_last_changed():
    rules = (_pinned(BETA, "fw-a", 100), _pinned(BETA, "fw-b"))
    d, found = _found(rules)
    (fix,) = found.fixes
    never = unmet(fix, d, lambda dns, excluded: None)
    assert never == ("beta/prod's firewall rules as they run, so the slots are free there too: import what it "
                     "changes first (no import has read it back)",)
    runs = run_records(d, "cloud/inventory", (f"ou=bindings,{BETA}",), AT, "CHG-1")
    d, found = _found(rules, runs)
    seen = []

    def changed(at):
        return lambda dns, excluded: seen.append(excluded) or at
    assert unmet(fix, d, changed(None)) == ()                              # nothing changed since the record began
    assert unmet(fix, d, changed(AT - dt.timedelta(hours=1))) == ()        # changed before the export was taken
    (later,) = unmet(fix, d, changed(AT + dt.timedelta(days=1)))
    assert later.endswith("import it again first (cloud/inventory last read it from an export of 20260920030000Z, "
                          "before the record changed there on 2026-09-21 03:00 UTC)")
    assert seen[0] == ("CHG-1",)                                           # the import's own change doesn't count


def test_an_import_of_another_environment_doesn_t_count():
    rules = (_pinned(BETA, "fw-a", 100), _pinned(BETA, "fw-b"))
    d, _ = _found(rules)
    runs = run_records(d, "cloud/inventory", (f"ou=bindings,{ALPHA}",), AT, "CHG-1")
    d, found = _found(rules, runs)
    assert "no import has read it back" in unmet(found.fixes[0], d, lambda dns, excluded: None)[0]

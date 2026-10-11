"""In-range upgrades during a migration (milestone 86, decision 2375): the planner names each server role's version
jump, blocks a target the adapter can't render, names a downgrade, and lists the changes the adapter declares between
the two versions that touch what the record holds."""
import datetime as dt

from opsdir.connectors.upgrades import crossing, jumps, upgrade_check
from opsdir.core.contract import PlanContext, VersionChange
from opsdir.core.environment import env_model
from opsdir.core.interchange.ldif import parse
from opsdir.core.versions import crossed, in_any
import mini_estate
from support import REGISTRY, build_directory

ALPHA = "env=prod,cloud=alpha,ou=environments,dc=ciam-ops"
BETA = "env=prod,cloud=beta,ou=environments,dc=ciam-ops"


def _server(env, cn, role, version):
    return (f"dn: cn={cn},{env}\nobjectClass: top\nobjectClass: ciamServer\ncn: {cn}\nciamServerRole: {role}\n"
            f"ciamHostname: {cn}.example.test\nciamSubnet: cn=net,ou=bindings,{env}\n"
            + (f"ciamProductVersion: {version}\n" if version else ""))


def context(src, dst):
    """A plan context from alpha/prod's servers (src: ((name, role, version), ...)) to beta/prod's (dst)."""
    records = (*(_server(ALPHA, *s) for s in src), *(_server(BETA, *s) for s in dst))
    d = build_directory(REGISTRY, tuple(parse(mini_estate.LDIF + "\n" + "\n".join(records))))
    return PlanContext(d, env_model(d, "alpha/prod"), env_model(d, "beta/prod"), dt.date(2026, 12, 1),
                       dt.date(2026, 10, 1), {}, {}, ())


CHANGES = (
    VersionChange(">=8.0", "auth chains removed", "captured chain files", "blocker", "Rebuild them as journeys.",
                  lambda d, m, role: ("chain-ldap",) if role == "am" else ()),
    VersionChange(">=8.0", "embedded store removed", "the role's servers", "action", "Use an external store."),
    VersionChange(">=8.1", "node versions", "journey nodes", "info", "Nothing to do.", lambda d, m, role: ()),
    VersionChange((">=7.5.3,<8", ">=8.0.2"), "pool template", "data sources", "action", "Re-render.",
                  lambda d, m, role: ("repo.jdbc",)),
)
AM = mini_estate.FAKE._replace(name="am", products=(("PingAM", ">=7,<9"), ("ForgeRock AM", ">=7,<8")),
                               version_changes=CHANGES)


def texts(f):
    return ([t for _, t, _ in f.blockers], [t for _, t, _, _ in f.actions], list(f.ok))


def test_a_change_lies_between_two_versions_when_the_older_lacks_it_and_the_newer_has_it():
    assert crossed(">=8.0", "7.5.1", "8.1.1") and not crossed(">=8.0", "8.0.1", "8.1.1")
    assert in_any("7.5.3", (">=7.5.3,<8", ">=8.0.2")) and not in_any("8.0.1", (">=7.5.3,<8", ">=8.0.2"))
    assert crossed((">=7.5.3,<8", ">=8.0.2"), "7.5.1", "8.1.1") and not crossed((">=7.5.3,<8", ">=8.0.2"),
                                                                                "7.5.3", "8.1.1")


def test_an_upgrade_names_its_jump_and_the_changes_that_touch_the_record():
    ctx = context((("am-1", "am", "ForgeRock AM 7.5.1"), ("am-2", "am", "PingAM 7.5.2")),
                  (("am-b1", "am", "PingAM 8.1.1"),))
    assert [(a.name, roles, s, t) for a, roles, s, t in jumps(ctx.src, ctx.dst, (AM,))] == [
        ("am", ("am",), "ForgeRock AM 7.5.1", "PingAM 8.1.1")]
    blockers, actions, ok = texts(upgrade_check((AM,), (AM,))(ctx))
    assert blockers == ["`am` in beta/prod: auth chains removed. Affects captured chain files; the record holds "
                        "`chain-ldap`. Rebuild them as journeys."]
    assert actions == ["`am` in beta/prod: embedded store removed. Affects the role's servers. Use an external store.",
                       "`am` in beta/prod: pool template. Affects data sources; the record holds `repo.jdbc`. "
                       "Re-render."]
    assert ok == ["`am` in beta/prod: ForgeRock AM 7.5.1 → PingAM 8.1.1, an upgrade within the versions am supports "
                  "(PingAM >=7,<9, ForgeRock AM >=7,<8); 4 changes am declares lie between them; 3 apply to this "
                  "record (named below)."]
    assert {a[3] for a in upgrade_check((AM,), (AM,))(ctx).actions} == {dt.date(2026, 12, 1)}


def test_changes_that_touch_nothing_in_the_record_are_counted_not_listed():
    ctx = context((("am-1", "am", "PingAM 8.0.1"),), (("am-b1", "am", "PingAM 8.1.1"),))
    listed, between = crossing(ctx.d, ctx.dst, AM, ("am",), "8.0.1", "8.1.1")
    assert (listed, between) == (((CHANGES[3], ("repo.jdbc",)),), 2)


def test_a_target_outside_the_adapters_range_blocks_and_a_source_outside_it_is_an_action():
    ctx = context((("am-1", "am", "PingAM 6.5.0"),), (("am-b1", "am", "PingAM 9.0.0"),))
    blockers, actions, _ = texts(upgrade_check((AM,), (AM,))(ctx))
    assert blockers[0] == ("`am` in beta/prod would run PingAM 9.0.0, outside the versions am supports (PingAM "
                           ">=7,<9, ForgeRock AM >=7,<8): it can't render or read it. Record a version in its range, "
                           "or install an adapter that supports it.")
    assert actions[0].startswith("`am` in alpha/prod runs PingAM 6.5.0, outside the versions am supports")


def test_a_downgrade_is_an_action_naming_what_the_target_loses():
    ctx = context((("am-1", "am", "PingAM 8.1.1"),), (("am-b1", "am", "PingAM 7.5.2"),))
    blockers, actions, ok = texts(upgrade_check((AM,), (AM,))(ctx))
    assert blockers == [] and actions == [
        "`am` in beta/prod: PingAM 8.1.1 → PingAM 7.5.2 is a downgrade. What a newer release wrote may not load in an "
        "older one: build the target from the record and test it before the cutover, or record a version at or above "
        "PingAM 8.1.1."]
    assert ok == ["`am` in beta/prod loses, at PingAM 7.5.2: auth chains removed. Affects captured chain files.",
                  "`am` in beta/prod loses, at PingAM 7.5.2: embedded store removed. Affects the role's servers.",
                  "`am` in beta/prod loses, at PingAM 7.5.2: pool template. Affects data sources."]


def test_same_versions_and_roles_only_one_side_runs_say_nothing():
    same = context((("am-1", "am", "PingAM 8.1.1"),), (("am-b1", "am", "PingAM 8.1.1"),))
    new = context((("ig-1", "ig", "PingGateway 2024.11.0"),), (("am-b1", "am", "PingAM 8.1.1"),))
    assert upgrade_check((AM,), (AM,))(same) == upgrade_check((AM,), (AM,))(new) == upgrade_check((AM,), (AM,))(
        context((), ()))
    assert texts(upgrade_check((AM,), (AM,))(same)) == ([], [], [])


def test_roles_making_the_same_jump_are_named_together_and_an_adapter_without_changes_says_so():
    pf = mini_estate.FAKE._replace(name="pf", products=(("PingFederate", ">=11,<14"),))
    ctx = context((("pfa-1", "pf-admin", "PingFederate 12.1.4"), ("pfe-1", "pf-engine", "PingFederate 12.1.4")),
                  (("pfa-b1", "pf-admin", "PingFederate 13.1.3"), ("pfe-b1", "pf-engine", "PingFederate 13.1.3")))
    _, actions, _ = texts(upgrade_check((pf,), (pf,))(ctx))
    assert actions == ["`pf-admin`, `pf-engine` in beta/prod: PingFederate 12.1.4 → PingFederate 13.1.3, an upgrade "
                       "pf declares no version changes for: test it separately from the move."]

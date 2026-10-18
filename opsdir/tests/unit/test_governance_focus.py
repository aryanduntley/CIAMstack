"""'My area', pure (domains.governance.focus): reports narrowed by their owner or keeper column, plan findings by
their owner, and a person's open items."""
from opsdir.core.directory import make_directory
from opsdir.core.interchange.ldif import parse
from opsdir.connectors.application import OWNERS, ApplicationView, Section, my_view
from opsdir.core.changeset import new_entry, set_values
from opsdir.core.directory import get
from opsdir.core.findings import Fix, Option
from opsdir.domains.governance.focus import (NO_COLUMN, entry_teams, focus_findings, focus_fixes, focus_rows,
                                             kept_by, open_items)

RECORD = """dn: ou=changes,dc=ciam-ops
objectClass: organizationalUnit
ou: changes

dn: cn=CHG-1,ou=changes,dc=ciam-ops
objectClass: ciamChange
cn: CHG-1
ciamTitle: Bob's proposal
ciamChangeStatus: proposed
ciamAuthor: bob

dn: cn=CHG-2,ou=changes,dc=ciam-ops
objectClass: ciamChange
cn: CHG-2
ciamTitle: Alice's approved change
ciamChangeStatus: approved
ciamAuthor: alice

dn: cn=CHG-3,ou=changes,dc=ciam-ops
objectClass: ciamChange
cn: CHG-3
ciamTitle: Alice's done change
ciamChangeStatus: applied
ciamAuthor: alice

dn: cn=q1,ou=unknowns,dc=ciam-ops
objectClass: ciamUnknown
cn: q1
ciamQuestion: Which CA signs the partner certificates?
ciamOwner: cn=platform,ou=owners,dc=ciam-ops

dn: cn=q2,ou=unknowns,dc=ciam-ops
objectClass: ciamUnknown
cn: q2
ciamQuestion: Answered already
ciamOwner: cn=platform,ou=owners,dc=ciam-ops
ciamAnswer: Ours

dn: cn=q3,ou=unknowns,dc=ciam-ops
objectClass: ciamUnknown
cn: q3
ciamQuestion: The network team's
ciamOwner: cn=network,ou=owners,dc=ciam-ops

dn: env=prod,cloud=aws,ou=environments,dc=ciam-ops
objectClass: ciamEnvironment
env: prod
ciamOwner: cn=platform,ou=owners,dc=ciam-ops

dn: cn=lb,ou=bindings,env=prod,cloud=aws,ou=environments,dc=ciam-ops
objectClass: ciamBinding
cn: lb

dn: cn=fw,ou=bindings,env=prod,cloud=aws,ou=environments,dc=ciam-ops
objectClass: ciamBinding
cn: fw
ciamManagedBy: cn=network,ou=owners,dc=ciam-ops

dn: cn=svc,ou=services,dc=ciam-ops
objectClass: ciamServiceName
cn: svc
"""


def directory():
    rows = [(r.dn, tuple(r.attrs.get("objectClass", ())), {k: v for k, v in r.attrs.items() if k != "objectClass"})
            for r in parse(RECORD)]
    return make_directory((), {}, rows)


def test_a_report_is_narrowed_by_its_owner_column():
    rows = (("job-a", "platform"), ("job-b", "network, platform"), ("job-c", "network"), ("job-d", "**NO OWNER**"))
    assert focus_rows(("job", "owner"), rows, ("platform",)) == (rows[:2], None)
    assert focus_rows(("job", "kind"), rows, ("platform",)) == (rows, NO_COLUMN)


def test_plan_findings_by_their_owner():
    blockers = (("Network", "Open 636", "network"), ("Directory", "Rotate", "Platform"),
                ("X", "Nobody", "**NO OWNER**"))
    assert focus_findings(blockers, ("platform",)) == (blockers[1],)


def test_open_items():
    sections = dict(open_items(directory(), "alice", ("platform",)))
    assert sections["changes waiting for someone else's approval"] == ("CHG-1  proposed  Bob's proposal",)
    assert sections["your changes not yet applied"] == ("CHG-2  approved  Alice's approved change",)
    assert sections["open unknowns of platform"] == ("q1  Which CA signs the partner certificates?",)


PLATFORM, NETWORK = "cn=platform,ou=owners,dc=ciam-ops", "cn=network,ou=owners,dc=ciam-ops"
LB, FW = "cn=lb,ou=bindings,env=prod,cloud=aws,ou=environments,dc=ciam-ops", \
    "cn=fw,ou=bindings,env=prod,cloud=aws,ou=environments,dc=ciam-ops"


def test_an_entrys_teams_are_its_own_else_its_environments():
    d = directory()
    assert entry_teams(d, LB) == {PLATFORM}                                    # the environment's
    assert entry_teams(d, FW) == {NETWORK}                                     # its own keeper, not the environment's
    assert entry_teams(d, "cn=svc,ou=services,dc=ciam-ops") == frozenset()     # outside any environment, unowned
    new = "cn=new,ou=bindings,env=prod,cloud=aws,ou=environments,dc=ciam-ops"
    assert entry_teams(d, new) == {PLATFORM}                                   # not there yet: where it goes
    assert entry_teams(d, new, {"ciamOwner": (NETWORK,)}) == {NETWORK}          # an add record's own owners
    assert kept_by(d, LB, ("Platform",)) and not kept_by(d, LB, ("network",))


def test_fixes_narrowed_by_the_entries_they_change():
    d = directory()
    lb, fw = get(d, LB), get(d, FW)
    platform = Fix("binding:lb", "Binding", "Bind lb", (set_values(lb, "description", ("x",)),), (), ())
    network = Fix("fw:open", "Network", "Open", (set_values(fw, "description", ("y",)),), (), ())
    choice = Fix("fw:pick", "Network", "Pick", (), (), (),
                 (Option("a", "A", (set_values(fw, "description", ("a",)),), ()),))
    added = Fix("svc:add", "Names", "Add", (new_entry("cn=s2,ou=services,dc=ciam-ops", ("ciamServiceName",),
                                                      {"cn": ("s2",), "ciamOwner": (PLATFORM,)}),), (), ())
    manual = Fix("party:confirm", "Parties", "Confirm by hand", (), ("ask them",), ())
    found = (platform, network, choice, added, manual)
    assert focus_fixes(d, found, ("platform",)) == (platform, added)
    assert focus_fixes(d, found, ("network",)) == (network, choice)


def test_the_application_view_narrowed_to_my_teams():
    d = directory()
    row = ("aws/prod", "ciamBinding", "lb", "", "", LB)
    theirs = ("aws/prod", "ciamBinding", "fw", "", "", FW)
    view = ApplicationView("cn=app", "app", ("cn=app",), (), None,
                           (Section("network", (row, theirs)),
                            Section(OWNERS, (("", "team", "network", "owns 1: fw", "", NETWORK),
                                             ("", "team", "platform", "owns 1: lb", "", PLATFORM)))))
    mine = my_view(d, view, ("platform",))
    assert mine.sections[0].rows == (row,)
    assert [r[2] for r in mine.sections[1].rows] == ["platform"]

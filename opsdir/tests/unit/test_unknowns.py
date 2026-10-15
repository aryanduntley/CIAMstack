"""The unknowns register: questions the record can't answer yet, each owned by the party who must answer it. The
planner counts the ones that concern the source or the target: open and blocking, a blocker; open, an action dated by
when the answer is needed (else the cutover); answered, in place. The report lists every question with its status."""
import datetime as dt

from opsdir.core.contract import PlanContext
from opsdir.core.environment import env_model
from opsdir.core.interchange.ldif import parse
from opsdir.domains.governance.domain import DOMAIN
from opsdir.domains.governance.unknowns import AREA, check_unknowns, concerned, unknown_rows
import mini_estate
from support import REGISTRY, build_directory

ALPHA = "env=prod,cloud=alpha,ou=environments,dc=ciam-ops"
BETA = "env=prod,cloud=beta,ou=environments,dc=ciam-ops"
ELSEWHERE = "env=lab,cloud=gamma,ou=environments,dc=ciam-ops"
TEAM = "cn=ops,ou=owners,dc=ciam-ops"
AS_OF, CUTOVER = dt.date(2026, 10, 1), dt.date(2026, 11, 1)


def _unknown(cn, question, **attrs):
    return (f"dn: cn={cn},ou=unknowns,dc=ciam-ops\nobjectClass: top\nobjectClass: ciamObject\n"
            f"objectClass: ciamUnknown\ncn: {cn}\nciamQuestion: {question}\nciamOwner: {TEAM}\n"
            + "".join(f"{k}: {v}\n" for k, vs in attrs.items() for v in (vs if isinstance(vs, tuple) else (vs,))))


RECORD = (
    "dn: ou=owners,dc=ciam-ops\nobjectClass: top\nobjectClass: organizationalUnit\nou: owners\n",
    f"dn: {TEAM}\nobjectClass: top\nobjectClass: ciamParty\ncn: ops\nciamOwnerKind: team\n",
    "dn: ou=unknowns,dc=ciam-ops\nobjectClass: top\nobjectClass: organizationalUnit\nou: unknowns\n",
    _unknown("q-partner", "Does the partner accept the new signing certificate?", ciamBlocking="TRUE",
             ciamConcerns=BETA),
    _unknown("q-ttl", "Who lowers the zone's TTLs?", ciamNeededBy="20260920000000Z"),
    _unknown("q-hsm", "Which HSM partition does the target use?", ciamConcerns=f"cn=sso,ou=bindings,{BETA}"),
    _unknown("q-lab", "Is the lab kept?", ciamBlocking="TRUE", ciamConcerns=ELSEWHERE),
    _unknown("q-shared", "Who owns the shared claim map?", ciamConcerns="cn=claims,ou=integrations,dc=ciam-ops",
             ciamNeededBy="20261020000000Z"),
    _unknown("q-dns", "Which DNS team keeps the zone?", ciamConcerns=ALPHA, ciamAnswer="Corporate DNS",
             ciamAnsweredAt="20260915000000Z"),
)


def _plan(cutover=CUTOVER):
    d = build_directory(REGISTRY, tuple(parse("\n".join((mini_estate.LDIF, *RECORD)))))
    return d, check_unknowns(PlanContext(d, env_model(d, "alpha/prod"), env_model(d, "beta/prod"), cutover, AS_OF,
                                         {}, {}, ()))


def test_the_governance_domain_checks_and_reports_unknowns():
    assert check_unknowns in DOMAIN.checks and "unknowns" in DOMAIN.reports


def test_an_open_blocking_question_blocks_the_move():
    _, found = _plan()
    assert found.blockers == ((AREA, "Open question `q-partner` (beta/prod): Does the partner accept the new "
                                     "signing certificate? ops must answer it (ciamAnswer, ciamAnsweredAt) before the "
                                     "move: the plan can't be READY until then.", "ops"),)     # q-lab concerns neither


def test_open_questions_are_actions_dated_by_when_the_answer_is_needed_else_the_cutover():
    _, found = _plan()
    actions = {a[1].split("`")[1]: a for a in found.actions}
    assert sorted(actions) == ["q-hsm", "q-shared", "q-ttl"]
    assert actions["q-ttl"] == (AREA, "Open question `q-ttl` (the estate): Who lowers the zone's TTLs? ops to answer "
                                      "it (ciamAnswer, ciamAnsweredAt) by **2026-09-20** (**already late**).", "ops",
                                dt.date(2026, 9, 20))
    assert actions["q-hsm"][1].startswith("Open question `q-hsm` (`sso` in beta/prod):")
    assert actions["q-hsm"][3] == CUTOVER and "already late" not in actions["q-hsm"][1]
    assert actions["q-shared"][3] == dt.date(2026, 10, 20)       # an entry the environments share: every plan
    _, undated = _plan(cutover=None)
    assert {a[1].split("`")[1]: a[3] for a in undated.actions}["q-hsm"] is None
    assert "ciamAnsweredAt)." in {a[1].split("`")[1]: a[1] for a in undated.actions}["q-hsm"]


def test_an_answered_question_is_in_place():
    _, found = _plan()
    assert found.ok == ("Question `q-dns` answered 2026-09-15 by ops: Corporate DNS",)


def test_the_report_lists_every_question_with_its_status():
    d, _ = _plan()
    rows = {r[0]: r for r in unknown_rows(d, None, AS_OF)}
    assert sorted(rows) == ["q-dns", "q-hsm", "q-lab", "q-partner", "q-shared", "q-ttl"]
    assert rows["q-ttl"] == ("q-ttl", "Who lowers the zone's TTLs?", "ops", "no", "the estate", "", "2026-09-20",
                             "overdue", "", "")
    assert rows["q-dns"][7:] == ("answered", "Corporate DNS", "2026-09-15")
    assert rows["q-partner"][3:5] == ("yes", "beta/prod") and rows["q-shared"][4] == "claims"
    assert rows["q-lab"][7] == "open" and concerned(next(u for u in d.entries.values()
                                                         if u.dn.startswith("cn=q-lab,"))) == "gamma/lab"

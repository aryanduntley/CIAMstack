"""Findings handed to their owning teams as work-ticket drafts (connectors.handoff), pure: one draft per team and
installed ITSM add-on that drafts, the README saying how to file them, what is missing and what no team owns."""
import datetime as dt
from types import SimpleNamespace

from opsdir.core.contract import Adapter, TicketDraft
from opsdir.core.directory import make_directory
from opsdir.connectors.handoff import handoff_files, request_lines, ticket_requests

AS_OF = dt.date(2026, 10, 18)
D = make_directory((), {}, [("cn=Platform,ou=owners,dc=ciam-ops", ("ciamParty",), {"cn": ("Platform",)})])
PLAN = SimpleNamespace(
    src=SimpleNamespace(label="aws/prod"), dst=SimpleNamespace(label="azure/prod"), as_of=AS_OF,
    blockers=(("Network", "Open 636 to the directory", "network"),),
    actions=(("Certificates", "Renew the signing certificate", "platform", dt.date(2026, 11, 1)),
             ("Allowlist", "Ask the partner to add 10.0.0.0/24", "network, Platform", dt.date(2026, 10, 25)),
             ("Secrets", "Nobody's reference", "**NO OWNER**", None)))


def drafting(d, r):
    if r.team == "network":
        return TicketDraft(None, "json", (), ("acme-groups has no queue for network: opsdir setting acme-groups ...",))
    return TicketDraft('{"title": "%s"}' % r.title, "json", ("POST /api/tickets", "curl ... --data-binary @FILE"), ())


ITSM = Adapter(name="acme", kind="itsm", applies=None, required_roles=(), render_neutral=None, render_env=None,
               checks=(), ref_schemes=(), secret_schemes={}, renders=None, neutral_label=None, vocabulary={},
               schema=None, formats=(), products=(), secret_patterns=(), importers=(), profile_terms=None,
               access=None, ticket_draft=drafting)
READ_ONLY = ITSM._replace(name="other", ticket_draft=None)


def test_one_request_per_owning_team():
    requests, unowned = ticket_requests(D, PLAN)
    assert [(r.team, r.team_dn, len(r.items), r.do_by) for r in requests] == [
        ("network", "cn=network,ou=owners,dc=ciam-ops", 2, dt.date(2026, 10, 25)),
        ("Platform", "cn=Platform,ou=owners,dc=ciam-ops", 2, dt.date(2026, 10, 25))]
    assert requests[1].title == "CIAM: 2 findings for Platform (aws/prod to azure/prod)"
    assert unowned == (("action", "Secrets", "Nobody's reference", None),)
    mine, none = ticket_requests(D, PLAN, ("PLATFORM",))
    assert [r.team for r in mine] == ["Platform"] and none == ()


def test_request_lines_put_the_earliest_do_by_first():
    r = ticket_requests(D, PLAN, ("platform",))[0][0]
    assert request_lines(r)[2:4] == ("- [action] Allowlist: Ask the partner to add 10.0.0.0/24 (do by 2026-10-25)",
                                     "- [action] Certificates: Renew the signing certificate (do by 2026-11-01)")


def test_drafts_and_readme():
    files = handoff_files(D, PLAN, (ITSM, READ_ONLY))
    assert sorted(files) == ["tickets/README.md", "tickets/acme/Platform.json"]
    readme = files["tickets/README.md"]
    assert "- `acme/Platform.json`: Platform, 2 findings, earliest do-by 2026-10-25" in readme
    assert "- **not complete for network**: acme-groups has no queue for network" in readme
    assert "    curl ... --data-binary @FILE" in readme
    assert "## other" not in readme                                   # an add-on that drafts nothing isn't listed
    assert "- [action] Secrets: Nobody's reference" in readme


def test_a_problem_every_team_has_is_said_once():
    site = "acme-site isn't set: opsdir setting acme-site <url> --change <id>"
    unset = ITSM._replace(ticket_draft=lambda d, r: TicketDraft(None, "json", (), (site, f"no queue for {r.team}")))
    readme = handoff_files(D, PLAN, (unset,))["tickets/README.md"]
    assert readme.count(site) == 1 and f"- **not complete for any team**: {site}" in readme
    assert "- **not complete for network**: no queue for network" in readme


def test_without_a_drafting_add_on_nothing_is_drafted():
    files = handoff_files(D, PLAN, (READ_ONLY,))
    assert list(files) == ["tickets/README.md"]
    assert "No installed ITSM add-on drafts work tickets" in files["tickets/README.md"]

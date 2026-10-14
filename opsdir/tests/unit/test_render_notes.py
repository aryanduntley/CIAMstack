"""Render notes (core.notes, flow 43): an adapter's notes are located at their comments in the rendered files and get
their owners (the entry's, else the environment's); every other NOTE comment is listed to review; the render writes
NOTES.md and NOTES.json beside the MANIFEST, and NOTES.json reads back as the same notes."""
import json

import pytest

from opsdir.connectors.render import render_env
from opsdir.core.environment import env_model
from opsdir.core.interchange.ldif import parse
from opsdir.core.notes import (collected, located, note, note_comment, notes_markdown, parsed, scanned, summary,
                               with_owners)
import mini_estate
from mini_estate import FAKE
from support import REGISTRY, build_directory

ALPHA = "alpha/prod"
ENV = "env=prod,cloud=alpha,ou=environments,dc=ciam-ops"
SVC = f"cn=svc-sso,ou=bindings,{ENV}"
OWNERS = ("dn: ou=owners,dc=ciam-ops\nobjectClass: top\nobjectClass: organizationalUnit\nou: owners\n\n"
          "dn: cn=web-team,ou=owners,dc=ciam-ops\nobjectClass: top\nobjectClass: ciamParty\ncn: web-team\n\n"
          "dn: cn=platform,ou=owners,dc=ciam-ops\nobjectClass: top\nobjectClass: ciamParty\ncn: platform\n")
CHECK = note("Monitoring", "blocker", "canary sso-alive", "not rendered: the cloud runs no checks here",
             ("Run the probe from inside the boundary", "Or alert on the product's own logs"), entry=SVC,
             scope="project ciam-prod")
GRANT = note("Network", "action", "subnet subnet-a", "delegate it to the checks' environment", ("Delegate it",))


@pytest.fixture(scope="module")
def d():
    owned = (mini_estate.LDIF
             .replace("ciamExposure: internet\n", "ciamExposure: internet\nciamOwner: cn=web-team,ou=owners,"
                                                  "dc=ciam-ops\n", 1))
    owned = owned.replace(f"dn: {ENV}\n", f"dn: {ENV}\nciamOwner: cn=platform,ou=owners,dc=ciam-ops\n", 1)
    return build_directory(REGISTRY, tuple(parse(OWNERS + "\n" + owned)))


FILES = {"terraform/main.tf": f'resource "x" "y" {{}}\n\n# {note_comment(CHECK)}\n# NOTE: guardduty: one region only\n',
         "bicep/main.bicep": f"// {note_comment(CHECK)}\n",
         "config/agent.yaml": "a: 1\n  # NOTE: the agent replaces the servers' own\n"}


def test_a_note_is_written_as_its_comment_and_its_severity_is_checked():
    assert note_comment(CHECK) == "NOTE: canary sso-alive: not rendered: the cloud runs no checks here"
    with pytest.raises(ValueError, match="blocker, action, note"):
        note("Monitoring", "urgent", "x", "y")


def test_notes_are_located_at_every_comment_of_theirs_and_other_comments_are_to_review():
    (check, grant) = located((CHECK, GRANT), FILES)
    assert check.places == (("bicep/main.bicep", 1), ("terraform/main.tf", 3)) and grant.places == ()
    review = scanned(FILES, (check,))
    assert [(n.severity, n.text, n.places) for n in review] == [
        (None, "the agent replaces the servers' own", (("config/agent.yaml", 2),)),
        (None, "guardduty: one region only", (("terraform/main.tf", 4),))]


def test_owners_are_the_entrys_else_the_environments(d):
    m = env_model(d, ALPHA)
    check, grant = with_owners(d, m.env, (CHECK, GRANT))
    assert check.owners == ("web-team",) and grant.owners == ("platform",)


def test_collected_orders_by_severity_and_reads_back_from_its_json(d):
    m = env_model(d, ALPHA)
    notes = collected(m, (GRANT, CHECK), FILES)
    assert [n.severity for n in notes] == ["blocker", "action", None, None]
    assert summary(notes) == "1 blocker, 1 action, 0 notes, 2 to review" and summary(()) == "nothing to handle"
    text = notes_markdown(m, notes)
    assert "# Render notes: alpha/prod" in text and "**1 blocker, 1 action, 0 notes, 2 to review**" in text
    assert ("### canary sso-alive (Monitoring)\n\n- **What:** not rendered: the cloud runs no checks here\n"
            "- **Where:** bicep/main.bicep:1, terraform/main.tf:3; project ciam-prod\n- **Who:** web-team\n"
            "- **How:**\n  1. Run the probe from inside the boundary\n"
            "  2. Or alert on the product's own logs\n") in text
    assert "- **Where:** not written in any file\n- **Who:** platform\n- **How:** Delegate it\n" in text
    assert "| terraform/main.tf:4 | guardduty: one region only | platform |" in text


def test_a_render_writes_its_notes_beside_the_manifest(d):
    noted = FAKE._replace(render_env=lambda m, s: {"fake/env.txt": f"# {note_comment(CHECK)}\n# NOTE: loose\n"},
                          notes=lambda m, s: (CHECK,))
    _, files = render_env(d, ALPHA, (noted,))
    (check, loose) = parsed(files["NOTES.json"])
    assert check._replace(owners=(), places=()) == CHECK and check.places == (("fake/env.txt", 1),)
    assert loose.severity is None and loose.places == (("fake/env.txt", 2),)
    assert json.loads(files["NOTES.json"])["counts"] == {"blocker": 1, "action": 0, "note": 0, "to_review": 1}
    assert files["NOTES.md"].startswith("<!--") and "## To review" in files["NOTES.md"]


def test_a_render_with_nothing_to_handle_says_so(d):
    _, files = render_env(d, ALPHA, (FAKE,))
    assert json.loads(files["NOTES.json"])["notes"] == [] and "**nothing to handle**" in files["NOTES.md"]


def test_a_plan_raises_the_targets_blockers_and_actions_and_counts_what_is_left_to_review(d):
    from opsdir.core.notes import notes_findings
    m = env_model(d, ALPHA)
    f = notes_findings(m, collected(m, (GRANT, CHECK), FILES), "platform")
    ((area, text, owner),) = f.blockers
    assert (area, owner) == ("Monitoring", "web-team")
    assert text == ("alpha/prod: canary sso-alive: not rendered: the cloud runs no checks here (render: "
                    "bicep/main.bicep:1, terraform/main.tf:3; project ciam-prod). How: 1) Run the probe from inside "
                    "the boundary 2) Or alert on the product's own logs")
    assert [(a, o) for a, _, o, _ in f.actions] == [("Network", "platform"), ("Render", "platform")]
    assert f.actions[1][1] == "alpha/prod's render holds 2 NOTE comments not yet classified: review them (its " \
                              "NOTES.md, To review)."


def test_canaries_no_adapter_renders_are_notes_of_their_own():
    from opsdir.core.contract import Endpoint
    from opsdir.domains.observability.canaries import unrun_notes
    from opsdir.domains.observability.naming import CANARIES
    from network_fixtures import BETA as NET_BETA, entry, model
    tree = (f"dn: {CANARIES}\nobjectClass: top\nobjectClass: organizationalUnit\nou: canaries\n",
            entry(CANARIES, "sso-alive", "ciamCanary", ciamCheckedService="sso", ciamCanaryFlow="health")
            .replace("objectClass: ciamCanary", "objectClass: ciamObject\nobjectClass: ciamCanary"))
    svc = entry(NET_BETA, "svc-sso", "ciamServiceName", ciamBindingRole="sso", ciamFqdn="sso.example.test",
                ciamTargetRole="web", ciamExposure="internet")
    _, _, beta = model(beta=(svc,), tree=tree)
    endpoints = (Endpoint("health", "/pf/heartbeat.ping", "web"),)
    (n,) = unrun_notes(beta, (FAKE,), endpoints, ("cloud-a", "cloud-b"))
    assert (n.subject, n.severity) == ("canary sso-alive", "action")          # it feeds no alert rule
    assert n.text.startswith("not rendered: no adapter in ")
    assert "renders synthetic checks (its provider: fake" in n.text
    assert n.how[0].startswith("Declare an adapter that renders synthetic checks in the environment's stack "
                               "(installed: cloud-a, cloud-b)")
    assert unrun_notes(beta, (FAKE._replace(renders_synthetic_checks=True),), endpoints) == ()


def test_check_lists_each_environments_render_blockers_and_actions(d):
    from opsdir.connectors.stack import note_rows
    m = env_model(d, ALPHA)
    rows = note_rows(m, with_owners(d, m.env, (CHECK, GRANT, note("Monitoring", "note", "x", "fyi"))))
    assert [r[3].split(":")[0] for r in rows] == ["render blocker", "render action"]
    assert rows[0][3].endswith("[web-team] (opsdir render alpha/prod: NOTES.md)")

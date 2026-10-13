"""Who keeps an environment's entries and whether the default render gives that keeper a root (decisions 1860, 2732):
the party ciamManagedBy names, else the landing zone's owner for what is the landing zone's, else the stack; a keeper
is rooted when its party takes generated infrastructure, or when the landing zone has no party to ask. Also: request
drafts ask every topic a check raises, none dropped."""
from types import SimpleNamespace

import pytest

from opsdir.connectors.plan import _landing_draft
from opsdir.core.directory import get
from opsdir.domains.governance.keepers import LANDING_ZONE, keeper, keeper_folder, landing_zone_keeper, takes_generated
from opsdir.domains.network.plumbing import keepers
from network_fixtures import ALPHA, entry, model

LZ_TEAM = "cn=lz-team,ou=owners,dc=ciam-ops"
DBA_TEAM = "cn=DBA Team,ou=owners,dc=ciam-ops"
NET_TEAM = "cn=net-team,ou=owners,dc=ciam-ops"


def _owners(lz_takes=None, net_takes="TRUE"):
    def party(dn, cn, takes):
        return (f"dn: {dn}\nobjectClass: top\nobjectClass: ciamParty\ncn: {cn}\nciamOwnerKind: team\n"
                + (f"ciamTakesGeneratedInfra: {takes}\n" if takes else ""))
    return ("dn: ou=owners,dc=ciam-ops\nobjectClass: top\nobjectClass: organizationalUnit\nou: owners\n",
            party(LZ_TEAM, "lz-team", lz_takes), party(NET_TEAM, "net-team", net_takes),
            party(DBA_TEAM, "DBA Team", None))


GUARDRAIL = entry(ALPHA, "fence", "ciamGuardrail", ciamBindingRole="fence", ciamDenies="public-storage",
                  ciamOwner=LZ_TEAM)
DB_OWN = entry(ALPHA, "db-own", "ciamDatabase", ciamBindingRole="db-own", ciamDbEngine="postgres")
DB_DBA = entry(ALPHA, "db-dba", "ciamDatabase", ciamBindingRole="db-dba", ciamDbEngine="postgres",
               ciamManagedBy=DBA_TEAM)
DB_LZ = entry(ALPHA, "db-lz", "ciamDatabase", ciamBindingRole="db-lz", ciamDbEngine="postgres", ciamManagedBy=LZ_TEAM)
DB_GONE = entry(ALPHA, "db-gone", "ciamDatabase", ciamBindingRole="db-gone", ciamDbEngine="postgres",
                ciamManagedBy="cn=gone,ou=owners,dc=ciam-ops")
TABLE = entry(ALPHA, "rt-ds", "ciamRouteTable", ciamBindingRole="rt-ds", ciamRoute="0.0.0.0/0 nat egress",
              ciamSubnetRole="subnet-ds")
EGRESS_NET = entry(ALPHA, "egress", "ciamEgress", ciamBindingRole="egress", ciamCidr="203.0.113.10/32",
                   ciamManagedBy=NET_TEAM)


def _alpha(*records, **owners):
    return model(alpha=records, tree=_owners(**owners))[1]


def _of(m, cn):
    return next(b for b in m.bindings if b.dn.startswith(f"cn={cn},"))


def test_the_stack_keeps_what_names_no_one_and_isn_t_the_landing_zone_s():
    m = _alpha(GUARDRAIL, DB_OWN)
    assert keeper(m, _of(m, "db-own")) is None


def test_a_named_party_keeps_it_in_its_own_folder_and_is_asked_unless_it_takes_generated_infrastructure():
    m = _alpha(GUARDRAIL, DB_DBA, EGRESS_NET)
    dba, net = keeper(m, _of(m, "db-dba")), keeper(m, _of(m, "egress"))
    assert (dba.name, dba.folder, dba.party.dn, dba.takes) == ("DBA Team", f"{LANDING_ZONE}/dba-team", DBA_TEAM, False)
    assert (net.name, net.folder, net.takes) == ("net-team", f"{LANDING_ZONE}/net-team", True)


def test_the_landing_zone_s_party_named_by_ciammanagedby_is_the_landing_zone_s_keeper():
    m = _alpha(GUARDRAIL, DB_LZ, lz_takes="TRUE")
    assert keeper(m, _of(m, "db-lz")) == landing_zone_keeper(m)
    assert (landing_zone_keeper(m).folder, landing_zone_keeper(m).takes) == (LANDING_ZONE, True)


def test_the_landing_zone_is_rooted_when_its_party_takes_it_or_no_party_is_recorded_to_ask():
    assert landing_zone_keeper(_alpha(GUARDRAIL, lz_takes="TRUE")).takes
    assert not landing_zone_keeper(_alpha(GUARDRAIL)).takes
    assert not landing_zone_keeper(_alpha(GUARDRAIL, lz_takes="FALSE")).takes
    nobody = landing_zone_keeper(_alpha())
    assert nobody.party is None and nobody.takes


def test_what_is_the_landing_zone_s_by_nature_falls_to_its_keeper():
    m = _alpha(GUARDRAIL, TABLE, lz_takes="TRUE")
    assert keeper(m, _of(m, "rt-ds")) is None
    assert keeper(m, _of(m, "rt-ds"), landing_zone=True) == landing_zone_keeper(m)


def test_a_party_the_record_has_no_entry_for_is_named_by_its_dn_and_never_rooted():
    m = _alpha(GUARDRAIL, DB_GONE)
    gone = keeper(m, _of(m, "db-gone"))
    assert (gone.name, gone.folder, gone.party, gone.takes) == (
        "cn=gone,ou=owners,dc=ciam-ops", f"{LANDING_ZONE}/gone", None, False)
    assert not takes_generated(None)


def test_keeper_folders_are_slugs_of_the_party_s_name():
    assert keeper_folder("cn=Network & Security,ou=owners,dc=ciam-ops") == f"{LANDING_ZONE}/network-security"
    assert keeper_folder("cn=***,ou=owners,dc=ciam-ops") == f"{LANDING_ZONE}/keeper"


def test_plumbing_keepers_carry_whether_they_take_their_root():
    lz, net = keepers(_alpha(GUARDRAIL, TABLE, EGRESS_NET))
    assert (lz.folder, lz.takes, net.folder, net.takes) == (LANDING_ZONE, False, f"{LANDING_ZONE}/net-team", True)


def test_a_request_asks_every_topic_raised_even_ones_no_draft_wording_describes():
    p = SimpleNamespace(dst=SimpleNamespace(label="hq/prod"), cutover="2026-12-01")
    mgr = get(_alpha().d, NET_TEAM)
    asks = [(None, "a load balancer for `login.example.test`", "on-prem", None), (None, "a widget", "widgets", None)]
    draft = "\n".join(_landing_draft(p, mgr, asks, "the platform", "The platform team"))
    assert "Subject: On-prem changes needed for hq/prod before 2026-12-01" in draft
    assert "set up the following at the sites you keep:" in draft and "- a load balancer for" in draft
    assert "Also, in what you keep:" in draft and "- a widget" in draft


def test_a_scope_places_its_entries_in_its_root_and_names_what_it_writes():
    from opsdir.core.environment import Scope
    from opsdir.domains.governance.keepers import SLICE, check_scope, in_scope, placement, scope_folder, scope_title
    m = _alpha(GUARDRAIL, DB_DBA, DB_OWN)
    dba = m._replace(scope=Scope("keeper", (DBA_TEAM,)))
    assert placement(dba)(_of(m, "db-dba").dn) == f"{LANDING_ZONE}/dba-team"     # its root, though it takes none
    assert placement(dba)(_of(m, "db-own").dn) is None and in_scope(dba, f"{LANDING_ZONE}/dba-team")
    assert not in_scope(dba, "terraform") and scope_title(dba) == "what DBA Team keeps"
    sliced = m._replace(scope=Scope("class", ("ciamDatabase",)))
    assert {placement(sliced)(_of(m, cn).dn) for cn in ("db-dba", "db-own")} == {SLICE}
    assert scope_folder(m) is None and in_scope(m, "terraform")
    with pytest.raises(SystemExit, match="no party"):
        check_scope(m._replace(scope=Scope("keeper", ("cn=gone,ou=owners,dc=ciam-ops",))))
    with pytest.raises(SystemExit, match="binds no"):
        check_scope(m._replace(scope=Scope("bindings", ("cn=x,ou=bindings,dc=ciam-ops",))))


def test_the_manifest_records_a_requested_render_s_scope_and_requester():
    import json
    from opsdir.core.environment import Scope
    from opsdir.core.manifest import manifest
    m = _alpha()._replace(scope=Scope("class", ("ciamDatabase",)))
    found = json.loads(manifest(m, {}, {}, {}, requester="alice"))
    assert found["scope"] == {"kind": "class", "value": ["ciamDatabase"]} and found["requester"] == "alice"
    assert "scope" not in json.loads(manifest(_alpha(), {}, {}, {}))


def test_the_cli_reads_one_scope():
    from opsdir.cli import render_scope
    from opsdir.core.environment import ENVIRONMENT, Scope
    assert render_scope(None, [], []) == ENVIRONMENT
    assert render_scope("dba", [], []) == Scope("keeper", ("cn=dba,ou=owners,dc=ciam-ops",))
    assert render_scope(None, ["ciamDatabase"], []) == Scope("class", ("ciamDatabase",))
    with pytest.raises(SystemExit, match="one of"):
        render_scope("dba", ["ciamDatabase"], [])


# ------------------------------------------------------------------ organization-wide parts (5.7b, decision 2777)
ORG_SVC = entry(ALPHA, "detector", "ciamSecurityService", ciamBindingRole="detector",
                ciamSecurityKind="threat-detection", ciamAuditScope="organization")
OWN_SVC = entry(ALPHA, "scanner", "ciamSecurityService", ciamBindingRole="scanner",
                ciamSecurityKind="vulnerability-scanning", ciamAuditScope="account")
NET_SVC = entry(ALPHA, "posture", "ciamSecurityService", ciamBindingRole="posture", ciamSecurityKind="posture",
                ciamAuditScope="organization", ciamManagedBy=NET_TEAM)


def test_an_entry_s_organization_part_is_kept_with_the_landing_zone_and_its_own_part_where_the_entry_goes():
    from opsdir.domains.governance.keepers import (keeper_of_origin, organization_origin, organization_wide,
                                                   origin_entry, placement)
    m = _alpha(GUARDRAIL, ORG_SVC, OWN_SVC, NET_SVC, lz_takes="TRUE")
    detector, scanner, posture = (_of(m, cn) for cn in ("detector", "scanner", "posture"))
    assert organization_wide(detector) and not organization_wide(scanner)
    assert origin_entry(organization_origin(detector.dn)) == detector.dn and origin_entry(detector.dn) == detector.dn
    place = placement(m)
    assert place(detector.dn) is None                                      # its findings routing: the stack's
    assert place(organization_origin(detector.dn)) == LANDING_ZONE         # its organization part
    assert place(organization_origin(posture.dn)) == f"{LANDING_ZONE}/net-team"   # ciamManagedBy wins
    assert keeper_of_origin(m, organization_origin("cn=gone,dc=x")) is None


def test_an_asked_keeper_s_organization_part_is_named_as_organization_wide_and_scopes_follow_the_entry():
    from opsdir.core.environment import Scope
    from opsdir.domains.governance.keepers import NAMED, asked_lines, organization_line, organization_origin, placement
    m = _alpha(GUARDRAIL, ORG_SVC)                                         # lz-team takes nothing: asked
    detector = _of(m, "detector")
    assert placement(m)(organization_origin(detector.dn)) == NAMED + "lz-team"
    (line,) = asked_lines(m, {NAMED + "lz-team": ((organization_origin(detector.dn), "aws_x.y"),)})
    assert line.startswith("detector (organization-wide): kept by lz-team, not rendered here (aws_x.y)")
    assert organization_line(m, detector) == "detector: organization-wide: enabled for every account by lz-team " \
                                             "(asked of them)"
    sliced = m._replace(scope=Scope("bindings", (detector.dn,)))
    assert placement(sliced)(organization_origin(detector.dn)) == "terraform/slice"
    taking = _alpha(GUARDRAIL, ORG_SVC, lz_takes="TRUE")
    assert organization_line(taking, _of(taking, "detector")).endswith(f"by lz-team (in their root {LANDING_ZONE})")

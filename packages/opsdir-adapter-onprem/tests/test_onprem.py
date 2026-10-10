"""The on-prem provider: the organization's sites read as the region catalog's onprem regions, and the planner asking
the site's teams for what fronts and connects an on-prem target (unless an add-on in its stack renders it)."""
import datetime as dt
import json

from opsdir.connectors.plan import plan
from opsdir.core.directory import one, rdn_value
from opsdir.core.interchange.ldif import parse
from opsdir.domains.estate.regions import catalog_dn, region_dn
from opsdir_adapter_onprem.adapter import ADAPTER
from opsdir_adapter_onprem.sites import read_sites
import mini_estate
from mini_estate import FAKE
from support import REGISTRY, build_directory

AS_OF = dt.date(2026, 1, 1)
BETA = "env=prod,cloud=beta,ou=environments,dc=ciam-ops"
SITES = [{"code": "hq-dc1", "name": "Headquarters data center 1", "geography": "United States"},
         {"code": "east-dc2", "status": "not-listed"}, {"name": "no code: skipped"}]
OWNER = ("dn: ou=parties,dc=ciam-ops\nobjectClass: top\nobjectClass: organizationalUnit\nou: parties\n",
         "dn: cn=site-infra,ou=parties,dc=ciam-ops\nobjectClass: top\nobjectClass: ciamParty\ncn: site-infra\n"
         "ciamPartyKind: team\n")


def _directory(*records, changes=""):
    onprem = (f"dn: cloud=beta,ou=environments,dc=ciam-ops\nchangetype: modify\nreplace: ciamCloudProvider\n"
              f"ciamCloudProvider: onprem\n-\nreplace: ciamRegion\nciamRegion: hq-dc1\n-\n{changes}\n"
              f"dn: cn=provider,ou=stack,{BETA}\nchangetype: modify\nreplace: ciamAdapter\nciamAdapter: onprem\n-\n")
    renders = (f"dn: cn=fake,ou=stack,{BETA}\nobjectClass: top\nobjectClass: ciamStackComponent\ncn: fake\n"
               "ciamStackRole: directory\nciamAdapter: fake-cloud\nciamAdapterVersion: >=0.1,<1\n"
               "ciamAdapterSource: https://example.test/fake-cloud\n")
    return build_directory(REGISTRY, tuple(parse("\n".join((mini_estate.LDIF, renders, *records)))),
                           tuple(parse(onprem)))


APPLIANCE = FAKE._replace(name="some-appliance", kind="platform", checks=(), render_env=None, render_neutral=None,
                          vocabulary={}, importers=(), schema=None)


def _onprem_findings(d):
    p = plan(d, "alpha/prod", "beta/prod", AS_OF, (FAKE, ADAPTER, APPLIANCE))
    return ([a[1] for a in p.actions if a[0] == "On-prem"],
            [(rdn_value(party), new) for party, items in p.requests for _, new, role, _ in items if role == "on-prem"])


def test_sites_are_the_onprem_regions():
    imported = read_sites({"sites.json": json.dumps(SITES), "notes.txt": "x"}, _directory(), ())
    (scope, entries), = imported.groups
    by_dn = {e.dn: e for e in entries}
    assert scope == catalog_dn("onprem")
    hq = by_dn[region_dn("onprem", "hq-dc1")]
    assert (one(hq, "ciamRegionName"), one(hq, "ciamGeography"), one(hq, "ciamRegionStatus"),
            one(hq, "ciamCloudEnvironment")) == ("Headquarters data center 1", "United States", "available",
                                                 "on-premises")
    assert one(by_dn[region_dn("onprem", "east-dc2")], "ciamRegionStatus") == "not-listed"
    assert "notes.txt: not a sites list (a JSON list of sites); not read" in imported.notices


def test_a_target_with_no_keeper_gets_actions():
    actions, requests = _onprem_findings(_directory())
    assert not requests
    assert actions == [
        "beta/prod: a load balancer for `sso.example.test` on port(s) 443 (internet), in front of role `web` (no web "
        "servers recorded): no one is recorded to keep it (ciamManagedBy, or the site's owner).",
        "beta/prod: DNS record `sso.example.test` answering its load balancer's address: no one is recorded to keep "
        "it (ciamManagedBy, or the site's owner)."]


def test_the_sites_owner_is_asked_unless_an_add_on_renders_it():
    owned = "add: ciamOwner\nciamOwner: cn=site-infra,ou=parties,dc=ciam-ops\n-\n"
    actions, requests = _onprem_findings(_directory(*OWNER, changes=owned))
    assert not actions and requests == [
        ("site-infra", "beta/prod: set up a load balancer for `sso.example.test` on port(s) 443 (internet), in front "
                       "of role `web` (no web servers recorded)."),
        ("site-infra", "beta/prod: set up DNS record `sso.example.test` answering its load balancer's address.")]
    add_on = (f"dn: cn=lb,ou=stack,{BETA}\nobjectClass: top\nobjectClass: ciamStackComponent\ncn: lb\n"
              "ciamStackRole: load-balancer\nciamAdapter: some-appliance\nciamAdapterVersion: >=1\n"
              "ciamAdapterSource: https://example.test/some-appliance\n")
    _, requests = _onprem_findings(_directory(*OWNER, add_on, changes=owned))
    assert requests == [(
        "site-infra", "beta/prod: set up DNS record `sso.example.test` answering its load balancer's address.")]


def test_a_cloud_target_is_not_asked():
    d = build_directory(REGISTRY, tuple(parse(mini_estate.LDIF)))
    p = plan(d, "alpha/prod", "beta/prod", AS_OF, (FAKE, ADAPTER))
    assert not [a for a in p.actions if a[0] == "On-prem"]
    assert not [i for _, items in p.requests for i in items if i[2] == "on-prem"]


def test_a_dns_add_on_still_leaves_the_names_it_cant_write_to_their_keepers():
    owned = "add: ciamOwner\nciamOwner: cn=site-infra,ou=parties,dc=ciam-ops\n-\n"
    add_on = (f"dn: cn=dns,ou=stack,{BETA}\nobjectClass: top\nobjectClass: ciamStackComponent\ncn: dns\n"
              "ciamStackRole: dns\nciamAdapter: some-appliance\nciamAdapterVersion: >=1\n"
              "ciamAdapterSource: https://example.test/some-appliance\n")
    _, requests = _onprem_findings(_directory(*OWNER, add_on, changes=owned))
    assert ("site-infra", "beta/prod: set up DNS record `sso.example.test` (in no DNS zone the environment binds: "
                          "the DNS add-on writes only the zones the platform runs).") in requests

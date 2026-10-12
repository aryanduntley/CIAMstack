"""Every type the Azure renderers write, translated to ARM (5.6 e4): the showcase and the Azure sample (azure_sample:
plumbing with peering, VPNs, a hub connection and NAT prefixes, Front Door before a cluster's gateway, DNS records of
every type in a public and a private zone with Traffic Manager names and forwarders, MySQL, a copied container, a
suppression, an availability test) rendered in eastus2 and Azure Government cover the whole mapping, and each
translates: every resource goes exactly one place, what stays Terraform says why, and the computed forms (a Front Door
route waiting for its origins, its custom domains, the Key Vault secret its certificate is, a web test's hidden-link
tag, long TXT values, Traffic Manager's global profile) come out as ARM takes them."""
import pytest

from opsdir.connectors.registry import ADAPTERS, environment_specs, services
from opsdir.connectors.render import render_parts
from opsdir_adapter_azure.arm_render import UNPLACED
from opsdir_adapter_azure.arm_types import DATA, KEPT, NO_NATIVE, TYPES, arm_translation
from opsdir_adapter_azure.terraform import WHAT, render_files
from opsdir_format_arm.template import ResourceId
from opsdir_format_terraform.hcl import TfBlock
from opsdir_format_terraform.translate import address, root_items, roots
import azure_sample

REGIONS = ("eastus2", "usgovvirginia")
# data sources that are checks (lifecycle conditions): the Terraform root beside the templates keeps them
CHECKS = {"azurerm_key_vault_secrets"}
LOOKUPS = ("data", "ephemeral")      # what the data table answers for (an ephemeral secret: a secure parameter)


@pytest.fixture(scope="module")
def sample():
    """{region: ((name, model, Terraform files, translation), ...)}."""
    return {r: tuple((n, m, files, arm_translation(m, files, WHAT)) for n, m, files in azure_sample.renders(r))
            for r in REGIONS}


def _types(files, kind):
    return {b.labels[0] for root in roots(files).values() for b in root_items(root)
            if isinstance(b, TfBlock) and b.kind == kind}


def _by_name(sample, region, name):
    return next(x for x in sample[region] if x[0] == name)


def _resources(t, type_):
    return [r for tpl in t.templates.values() for r in tpl.resources if r.type == type_ and not r.existing]


def test_the_showcase_and_the_sample_render_every_type_the_table_knows(sample, estate):
    found = services(ADAPTERS)
    showcase = tuple(render_files(render_parts(d, spec)[0], found) for d in estate.values()
                     for spec in environment_specs(d)
                     if any(a.name == "azure" for a in render_parts(d, spec)[1]))
    rendered = (*showcase, *(files for xs in sample.values() for _, _, files, _ in xs))
    resources = set().union(*(_types(f, "resource") for f in rendered))
    data = set().union(*(_types(f, kind) for f in rendered for kind in LOOKUPS))
    known = set(TYPES) | set(KEPT) | NO_NATIVE
    assert resources - known == set()
    assert known <= resources
    assert data - set(DATA) <= CHECKS and set(DATA) <= data


def test_every_terraform_resource_goes_exactly_one_place(sample):
    for region, xs in sample.items():
        for name, _, files, t in xs:
            for directory, root in roots(files).items():
                blocks = tuple(b for b in root_items(root) if isinstance(b, TfBlock))
                placed = {address(b) for b in blocks if b.kind == "resource" or
                          (b.kind == "data" and any(k == "lifecycle" for k, _ in b.body))}
                assert set(t.placements[directory]) == placed, (region, name, directory)


def test_what_stays_terraform_says_why(sample):
    places = {a: p for _, _, _, t in sample["eastus2"] for ps in t.placements.values() for a, p in ps.items()}
    assert "virtual WAN hub" in places["azurerm_virtual_hub_connection.hub"].detail
    rule = next(p for a, p in places.items() if a.startswith("azurerm_private_dns_resolver_forwarding_rule."))
    assert rule.kind == "terraform" and "forwarding ruleset" in rule.detail
    copy = next(p for a, p in places.items() if a.startswith("azurerm_storage_object_replication."))
    assert copy.kind == "terraform" and "destination" in copy.detail
    assert places["azurerm_firewall_policy_rule_collection_group.fw_sites"].detail == UNPLACED
    for a in ("azurerm_virtual_network_peering.peer", "azurerm_local_network_gateway.vpn_b",
              "azurerm_virtual_network_gateway_connection.vpn_b", "azurerm_mysql_flexible_server.db_sess",
              "azurerm_application_insights_standard_web_test.sso_alive"):
        assert places[a].kind == "template", a
    assert places["azurerm_cdn_frontdoor_custom_domain_association.svc_login"].kind == "merged"
    assert places["azurerm_nat_gateway_public_ip_prefix_association.egress_0"].detail == "azurerm_nat_gateway.egress"
    assert "landing zone's subnet" in places["azurerm_subnet_nat_gateway_association.egress_subnet_ds"].detail


def test_a_front_door_route_waits_for_its_origins_with_its_domain_once(sample):
    for region in REGIONS:
        _, _, _, t = _by_name(sample, region, "gateway")
        route = _resources(t, "Microsoft.Cdn/profiles/afdEndpoints/routes")[0]
        origin = _resources(t, "Microsoft.Cdn/profiles/originGroups/origins")[0]
        domain = _resources(t, "Microsoft.Cdn/profiles/customDomains")[0]
        assert origin.symbol in route.depends_on
        assert route.properties["customDomains"] == [{"id": ResourceId(domain.symbol)}]   # the association's too
        assert route.properties["linkToDefaultDomain"] == "Disabled" and route.properties["httpsRedirect"] == "Enabled"
        secret = _resources(t, "Microsoft.Cdn/profiles/secrets")[0]
        source = secret.properties["parameters"]["secretSource"]["id"]
        assert source.parts[-1] == "/secrets/sso-tls"                  # the Key Vault secret, by its ARM id
        profile = _resources(t, "Microsoft.Cdn/profiles")[0]
        assert profile.fields["location"] == "global"


def test_a_web_test_is_tied_to_its_component_and_long_txt_values_are_split(sample):
    for region in REGIONS:
        _, _, _, t = _by_name(sample, region, "services")
        test = _resources(t, "Microsoft.Insights/webtests")[0]
        link = next(k for k in test.fields["tags"] if not isinstance(k, str))
        assert link.parts[0] == "hidden-link:" and test.fields["tags"][link] == "Resource"
        assert test.fields["tags"]["Realizes"] == "sso-alive" and test.fields["kind"] == "standard"
        locations = [x["Id"] for x in test.properties["Locations"]]
        assert all(x.startswith("usgov") for x in locations) == azure_sample.government(region)
        _, _, _, dns = _by_name(sample, region, "dns")
        txt = next(r for r in _resources(dns, "Microsoft.Network/dnsZones/TXT") if r.name == "_long")
        value = txt.properties["TXTRecords"][0]["value"]
        assert [len(x) for x in value] == [255, 47] and "".join(value) == "v=" + "x" * 300
        profile = _resources(dns, "Microsoft.Network/trafficmanagerprofiles")[0]
        assert profile.fields["location"] == "global"

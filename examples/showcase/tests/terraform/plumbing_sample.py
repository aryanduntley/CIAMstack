"""Every kind of network plumbing in one environment, with provider refs shaped as each cloud writes them, rendered by
that cloud's landing zone: what `terraform validate` checks beyond the showcase (which has no route tables, ACLs, VPNs,
peering or flow logs). The landing zone's owner keeps most of it; a network team keeps a VPN, a private endpoint and
an egress firewall in its own root."""
import pathlib

from opsdir_adapter_aws.landing import render_landing as aws
from opsdir_adapter_azure.landing import render_landing as azure
from opsdir_adapter_gcp.landing import render_landing as gcp
from opsdir.core.environment import env_model
from opsdir.core.interchange.ldif import parse
import mini_estate
import network_fixtures
from network_fixtures import ALPHA, BETA, entry
from support import REGISTRY, build_directory

TEAM = "cn=net-team,ou=owners,dc=ciam-ops"
OWNERS = ("dn: ou=owners,dc=ciam-ops\nobjectClass: top\nobjectClass: organizationalUnit\nou: owners\n",
          f"dn: {TEAM}\nobjectClass: top\nobjectClass: ciamParty\ncn: net-team\nciamOwnerKind: team\n")
SUB = "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups"
HOST = "projects/example-net"
# cloud: (renderer, {placeholder: its provider ref there}); a network ref may carry more of the network's attributes
CLOUDS = {
    "aws": (aws, {"NET": "vpc-0a1b2c3d4e5f67890", "SUBNET": "subnet-0{}", "NAT": "nat-0123456789abcdef0",
                  "POLICY": "arn:aws:network-firewall:us-east-1:111122223333:firewall-policy/hub",
                  "LOGS": "arn:aws:logs:us-east-1:111122223333:log-group:flow"}),
    "azure": (azure, {"NET": "vnet-ciam-prod\nciamResourceGroup: rg-ciam-prod", "SUBNET": "vnet-ciam-prod/snet-{}",
                      "NAT": "natgw-ciam-prod",
                      "POLICY": f"{SUB}/rg-hub/providers/Microsoft.Network/firewallPolicies/fwp-hub",
                      "LOGS": f"{SUB}/rg-logs/providers/Microsoft.Storage/storageAccounts/stflowlogs"}),
    "gcp": (gcp, {"NET": f"{HOST}/global/networks/ciam-a",
                  "SUBNET": f"{HOST}/regions/us-central1/subnetworks/ciam-{{}}",
                  "NAT": "example-ciam/us-central1/ciam-router/ciam-nat",
                  "POLICY": f"{HOST}/global/firewallPolicies/hub",
                  "LOGS": "projects/example-ciam/locations/global/buckets/flow"}),
}


def _link(cn, kind, **attrs):
    return entry(ALPHA, cn, "ciamInterconnect", ciamBindingRole=cn, ciamInterconnectKind=cn, ciamLinkKind=kind,
                 ciamPeerEnvironment=BETA, ciamSourceCidr="10.9.0.0/16", **attrs)


RECORDS = (
    entry(ALPHA, "egress", "ciamEgress", ciamBindingRole="egress", ciamCidr="203.0.113.10/31", ciamProviderRef="NAT",
          ciamNatAllocation="static"),
    entry(ALPHA, "fw", "ciamProxy", ciamBindingRole="fw", ciamProxyKind="firewall", ciamProxyAddress="10.1.9.4:3128",
          ciamAllowedDestination=("a.example.test", "*.b.example.test", "c.example.test:587")),
    entry(ALPHA, "rt-ds", "ciamRouteTable", ciamBindingRole="rt-ds", ciamSubnetRole="subnet-ds",
          ciamProviderRef="rtb-1",
          ciamRoute=("0.0.0.0/0 nat egress", "10.7.0.0/16 firewall fw", "10.8.0.0/16 transit", "10.6.0.0/16 vpn vpn-a",
                     "10.5.0.0/16 appliance 10.1.9.5", "::/0 egress-only eigw-1", "10.4.0.0/16 none for ds")),
    entry(ALPHA, "rt-main", "ciamRouteTable", ciamBindingRole="rt-main", ciamRoute="0.0.0.0/0 internet",
          ciamMainTable="TRUE"),
    entry(ALPHA, "acl", "ciamNetworkAcl", ciamBindingRole="acl", ciamSubnetRole="subnet-ds", ciamProviderRef="acl-1",
          ciamAclRule=("100 allow in tcp 636 10.0.0.0/8", "200 allow out tcp 1024-65535 10.0.0.0/8",
                       "300 deny in all all 0.0.0.0/0", "400 allow in icmp all 10.0.0.0/8")),
    _link("vpn-a", "vpn", ciamPeerGateway="198.51.100.1", ciamPeerAsn="65010", ciamLocalAsn="64512",
          ciamAcceptedCidr="192.168.0.0/16", ciamAdvertisedCidr="10.1.0.0/16"),
    _link("vpn-b", "vpn", ciamPeerGateway="198.51.100.2", ciamAcceptedCidr="192.168.0.0/16", ciamManagedBy=TEAM),
    _link("tgw", "transit"), _link("hub", "hub"), _link("peer", "peering"),
    entry(ALPHA, "logs", "ciamLogDestination", ciamBindingRole="logs", ciamDestinationKind="log-group",
          ciamProviderRef="LOGS"),
    entry(ALPHA, "fl", "ciamFlowLog", ciamBindingRole="fl", ciamFlowScope="network", ciamLogDestinationRole="logs",
          ciamRetentionDays="90"),
    entry(ALPHA, "fl-sub", "ciamFlowLog", ciamBindingRole="fl-sub", ciamFlowScope="subnet",
          ciamSubnetRole=("subnet-ds", "subnet-web"), ciamLogDestinationRole="logs"),
    entry(ALPHA, "pe-hub", "ciamPrivateEndpoint", ciamBindingRole="pe-hub", ciamPrivateService="secrets",
          ciamPrivateEndpointKind="interface", ciamSubnetRole="subnet-ds", ciamManagedBy=TEAM),
    entry(ALPHA, "fw-hub", "ciamProxy", ciamBindingRole="fw-hub", ciamProxyKind="firewall", ciamManagedBy=TEAM,
          ciamProviderRef="POLICY", ciamAllowedDestination=("a.example.test", "c.example.test:587")),
)


def _model(refs):
    """The alpha environment with the plumbing, its network, subnets and plumbing refs shaped as one cloud writes."""
    def with_refs(text):
        subnet = refs["SUBNET"]
        return (text.replace("ciamCidr: 10.1.1.0/24", f"ciamCidr: 10.1.1.0/24\nciamProviderRef: {subnet.format('ds')}")
                .replace("ciamCidr: 10.1.2.0/24", f"ciamCidr: 10.1.2.0/24\nciamProviderRef: {subnet.format('web')}")
                .replace("ciamProviderRef: NAT", f"ciamProviderRef: {refs['NAT']}")
                .replace("ciamProviderRef: POLICY", f"ciamProviderRef: {refs['POLICY']}")
                .replace("ciamProviderRef: LOGS", f"ciamProviderRef: {refs['LOGS']}"))
    alpha = tuple(with_refs(r) for r in network_fixtures._estate(ALPHA, RECORDS))
    net = mini_estate.LDIF.replace("ciamCidr: 10.1.0.0/16",                 # the first network is alpha's
                                   f"ciamCidr: 10.1.0.0/16\nciamProviderRef: {refs['NET']}", 1)
    d = build_directory(REGISTRY, tuple(parse("\n".join((net, *OWNERS, *alpha)))))
    return env_model(d, "alpha/prod")


def write_samples(root):
    """Write each cloud's landing-zone roots for the sample under root/<cloud>/; the root."""
    for cloud, (render, refs) in CLOUDS.items():
        for path, text in render(_model(refs)).items():
            out = pathlib.Path(root) / cloud / path
            out.parent.mkdir(parents=True, exist_ok=True)
            out.write_text(text)
    return root

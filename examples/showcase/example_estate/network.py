"""Network depth fixture data, per environment (NETWORK below, used by infrastructure: SOURCE / TARGET / STANDBY): the
private endpoints the platform reaches its secrets by, the endpoint service that exposes LDAPS to the supplier portal's
network, the egress firewall and the sites it lets the servers reach, and the standby's firewall model. Each is
(object class, cn, binding role, attributes), rendered by the cloud adapters into the stack's own Terraform.

  source   AWS: an interface endpoint to Secrets Manager (private DNS), an endpoint service on the LDAPS load balancer
           the supplier portal's account connects to, and an AWS Network Firewall the stack keeps, whose domain
           allowlist it renders
  target   Azure: a private endpoint to the Key Vault (the hub's privatelink zone), a Private Link Service on the LDAPS
           load balancer, the hub's Azure Firewall, which the network team keeps, and the hub's forward proxy (an
           explicit proxy: the products must be told about it)
  standby  Google Cloud: the network firewall policy model (secure tags), a Private Service Connect endpoint for
           Google's APIs, and the stack's own egress rules in the policy

The plumbing under them: each environment's route table (the servers' subnets out through the NAT gateway, the hub
firewall, the default internet gateway) and flow log (to the ops log destination), and the source's network ACL on
the directory subnet (anything from the VPC, LDAPS and replies from anywhere).

Planted for the planner to find:
  - the supplier portal connects to LDAPS through the source's endpoint service; the target's Private Link Service has
    another name (not recorded yet) and allows the portal's Azure subscription, not its AWS account: the portal must
    create an endpoint to it and be accepted before cutover
  - the hub firewall in the target doesn't allow the mail relay the platform sends through
  - the target's outside traffic goes through the hub's forward proxy, but the products' configuration doesn't say
    so: PingFederate's captured run.properties lacks the proxy keys (a fix links them to the proxy binding), and the
    other products' places are named
  - the target's route table and flow log are the network team's to build (none exists yet): requests to them; its
    route sends internet traffic straight to the NAT gateway, around the hub firewall whose domain rules the stack
    relies on; its flow log keeps 14 days where the source keeps 30 (a fix carries the source's over); the source's
    network ACL has no counterpart in the target (Azure has none: the target's NSGs do its work)
"""
from .common import owner

SUPPLIER = "cn=supplier-portal-svc,ou=consumers,dc=ciam-ops"
SITES = ("email-smtp.us-east-1.amazonaws.com:587", "metadata.skyline-air.test", "sso.harbor-mro.test",
         "ocsp.example-ca.test:80", "crl.example-ca.test:80")
NETWORK_TEAM = owner("network-security")
HUB_DNS = ("/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-hub-dns/providers/"
           "Microsoft.Network/privateDnsZones/privatelink.vaultcore.azure.net")
AZ_NET = "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-ciam-prod/providers/Microsoft.Network"
STANDBY_POLICY = "projects/example-aero-net/global/firewallPolicies/ciam-prod-fw-policy"
HUB_FIREWALL = ("/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-hub-net/providers/"
                "Microsoft.Network/firewallPolicies/fwp-hub")
SERVER_SUBNETS = ["subnet-ds", "subnet-pf", "subnet-am", "subnet-idm", "subnet-ig"]
DS_ACL = ["100 allow in all all 10.20.0.0/16", "110 allow in tcp 1636 0.0.0.0/0",
          "120 allow in tcp 1024-65535 0.0.0.0/0", "100 allow out all all 0.0.0.0/0"]
NETWORK = {
    "source": (
        ("ciamRouteTable", "rt-private", "routes-private",
         {"ciamRoute": ["0.0.0.0/0 nat pf-egress"], "ciamSubnetRole": SERVER_SUBNETS, "ciamMainTable": "FALSE",
          "ciamOwner": NETWORK_TEAM, "ciamProviderRef": "rtb-0a1b2c3d4e5f60021"}),
        ("ciamNetworkAcl", "acl-ds", "acl-ds",
         {"ciamAclRule": DS_ACL, "ciamSubnetRole": "subnet-ds", "ciamOwner": NETWORK_TEAM,
          "ciamProviderRef": "acl-0a1b2c3d4e5f60031"}),
        ("ciamFlowLog", "flow-vpc", "flow-logs",
         {"ciamFlowScope": "network", "ciamLogDestinationRole": "ops-logs", "ciamRetentionDays": "30",
          "ciamOwner": NETWORK_TEAM, "ciamProviderRef": "fl-0a1b2c3d4e5f60041"}),
        ("ciamPrivateEndpoint", "pe-secrets", "private-secrets",
         {"ciamPrivateService": "secrets", "ciamPrivateEndpointKind": "interface",
          "ciamReachesRole": ["pf-admin-password", "pf-signing-key", "ds-root-password"],
          "ciamSubnetRole": ["subnet-ds", "subnet-pf"], "ciamPrivateDns": "TRUE", "ciamOwner": NETWORK_TEAM,
          "ciamProviderRef": "vpce-0a1b2c3d4e5f60011"}),
        ("ciamEndpointService", "ldaps-link", "ldaps-endpoint-service",
         {"ciamServiceRole": "ds-ldaps-service",
          "ciamServiceAlias": "com.amazonaws.vpce.us-east-1.vpce-svc-0a1b2c3d4e5f67890",
          "ciamAllowedPrincipal": "arn:aws:iam::444455556666:root", "ciamAllowsConsumer": SUPPLIER,
          "ciamAcceptanceRequired": "TRUE", "ciamOwner": NETWORK_TEAM, "ciamProviderRef": "vpce-svc-0a1b2c3d4e5f67890"}),
        ("ciamProxy", "egress-firewall", "egress-firewall",
         {"ciamProxyKind": "firewall", "ciamAllowedDestination": list(SITES), "ciamOwner": NETWORK_TEAM,
          "ciamProviderRef": "arn:aws:network-firewall:us-east-1:111122223333:firewall-policy/ciam-prod-egress"}),
    ),
    "target": (
        ("ciamRouteTable", "rt-private", "routes-private",
         {"ciamRoute": ["0.0.0.0/0 nat pf-egress"], "ciamSubnetRole": SERVER_SUBNETS,
          "ciamManagedBy": NETWORK_TEAM[0], "ciamOwner": NETWORK_TEAM}),
        ("ciamFlowLog", "flow-vnet", "flow-logs",
         {"ciamFlowScope": "network", "ciamLogDestinationRole": "ops-logs", "ciamRetentionDays": "14",
          "ciamManagedBy": NETWORK_TEAM[0], "ciamOwner": NETWORK_TEAM}),
        ("ciamPrivateEndpoint", "pe-secrets", "private-secrets",
         {"ciamPrivateService": "secrets", "ciamPrivateEndpointKind": "interface",
          "ciamReachesRole": ["pf-admin-password", "pf-signing-key", "ds-root-password"],
          "ciamSubnetRole": "subnet-pf", "ciamFrontendIp": "10.60.2.50", "ciamPrivateDns": "TRUE",
          "ciamDnsZone": "privatelink.vaultcore.azure.net", "ciamDnsZoneRef": HUB_DNS, "ciamOwner": NETWORK_TEAM,
          "ciamProviderRef": f"{AZ_NET}/privateEndpoints/pe-ciam-prod-pe-secrets"}),
        ("ciamEndpointService", "ldaps-link", "ldaps-endpoint-service",
         {"ciamServiceRole": "ds-ldaps-service", "ciamAllowedPrincipal": "55555555-6666-7777-8888-999999999999",
          "ciamVisibleTo": "55555555-6666-7777-8888-999999999999", "ciamAllowsConsumer": SUPPLIER,
          "ciamAcceptanceRequired": "TRUE", "ciamSubnetRole": "subnet-ds", "ciamOwner": NETWORK_TEAM,
          "ciamProviderRef": f"{AZ_NET}/privateLinkServices/pls-ciam-prod-ldaps-link"}),
        ("ciamProxy", "egress-firewall", "egress-firewall",
         {"ciamProxyKind": "firewall", "ciamAllowedDestination": list(SITES[1:]), "ciamProviderRef": HUB_FIREWALL,
          "ciamManagedBy": NETWORK_TEAM[0], "ciamOwner": NETWORK_TEAM}),
        ("ciamProxy", "hub-proxy", "egress-proxy",
         {"ciamProxyKind": "forward-proxy", "ciamProxyAddress": "proxy.hub.example-aero.test:3128",
          "ciamAllowedDestination": list(SITES), "ciamManagedBy": NETWORK_TEAM[0], "ciamOwner": NETWORK_TEAM}),
    ),
    "standby": (
        ("ciamRouteTable", "routes", "routes-private",
         {"ciamRoute": ["0.0.0.0/0 internet"], "ciamOwner": NETWORK_TEAM}),
        ("ciamFlowLog", "flow-subnets", "flow-logs",
         {"ciamFlowScope": "subnet", "ciamSubnetRole": SERVER_SUBNETS, "ciamLogDestinationRole": "ops-logs",
          "ciamRetentionDays": "30", "ciamOwner": NETWORK_TEAM}),
        ("ciamFirewallPolicy", "fw-policy", "firewall-policy",
         {"ciamPolicyScope": "network", "ciamPolicyOrder": "policy-first", "ciamOwner": NETWORK_TEAM,
          "ciamProviderRef": STANDBY_POLICY}),
        ("ciamPrivateEndpoint", "psc-apis", "private-apis",
         {"ciamPrivateService": "apis", "ciamPrivateEndpointKind": "all-apis", "ciamFrontendIp": "10.70.255.5",
          "ciamPrivateDns": "TRUE", "ciamOwner": NETWORK_TEAM,
          "ciamProviderRef": "projects/example-aero-net/global/forwardingRules/pscapis"}),
        ("ciamProxy", "egress-firewall", "egress-firewall",
         {"ciamProxyKind": "firewall", "ciamAllowedDestination": list(SITES), "ciamOwner": NETWORK_TEAM,
          "ciamProviderRef": STANDBY_POLICY}),      # its egress rules are in the network policy
    ),
}

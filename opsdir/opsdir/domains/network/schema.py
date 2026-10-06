"""Network domain schema: how the platform's networks carry its traffic beyond the basics (networks, subnets, inbound
firewall rules, egress addresses, interconnects, which stay in infrastructure). The outside sites the platform must
reach are intent, the same in every environment. How each environment gets there is a binding: route tables,
stateless network ACLs, private endpoints to the services it uses, endpoint services that expose its services to other
networks, the proxy or firewall its egress passes, its time source, its flow logs and its firewall policies; and the
depth of its interconnects and egress (added to the infrastructure classes)."""
from ...core.standard import AttributeDef, ClassDef, enum_type, fragment
from .naming import (ACL_RULE, DESTINATION, FIREWALL_MODELS, FLOW_SCOPES, LINK_KINDS, NAT_ALLOCATION, POLICY_ORDER,
                     POLICY_SCOPES, PORT_RANGE, PRIVATE_ENDPOINT_KINDS, PRIVATE_SERVICES, PROXY_ADDRESS, PROXY_KINDS,
                     ROUTE, SITE_KINDS, TIME_KINDS)

ATTRIBUTES = (
    # ------------------------------------------------------------------ intent: outside sites
    AttributeDef(408, 'ciamDestination', 'string', 'intent', True,
                 "An outside site the platform must reach: a host name or '*.' and a domain, with a port when not 443",
                 (("X-PATTERN", DESTINATION),)),
    AttributeDef(409, 'ciamSiteKind', enum_type(SITE_KINDS), 'intent', True,
                 "What the site serves: a partner's metadata, signing keys (JWKS), certificate status (OCSP, CRL), "
                 'an MFA or messaging vendor, vendor updates, a directory'),
    AttributeDef(410, 'ciamNeededByRole', 'string', 'intent', False, 'A server role that must reach it'),
    # ------------------------------------------------------------------ bindings: routes and ACLs
    AttributeDef(385, 'ciamSubnetRole', 'string', 'binding', False, 'Binding role of a subnet this applies to'),
    AttributeDef(386, 'ciamRoute', 'string', 'binding', False,
                 "A route: '<destination> <target kind> [<target>] [for <server roles>]', the target the binding "
                 "role of what realizes it (0.0.0.0/0 nat pf-egress; 10.20.0.0/16 vpn link-source)",
                 (("X-PATTERN", ROUTE),)),
    AttributeDef(387, 'ciamMainTable', 'bool', 'binding', True,
                 "Whether this is the network's main route table: subnets no other table names use it"),
    AttributeDef(388, 'ciamAclRule', 'string', 'binding', False,
                 "A stateless network ACL rule, evaluated in number order: '<number> <allow|deny> <in|out> "
                 "<protocol> <port|from-to|all> <cidr>' (100 allow in tcp 636 10.20.0.0/16)",
                 (("X-PATTERN", ACL_RULE),)),
    AttributeDef(389, 'ciamEphemeralPorts', 'string', 'binding', True,
                 "Port range the clients' return traffic uses (from-to; 1024-65535 when not stated)",
                 (("X-PATTERN", PORT_RANGE),)),
    # ------------------------------------------------------------------ bindings: private endpoints, endpoint services
    AttributeDef(390, 'ciamPrivateService', enum_type(PRIVATE_SERVICES), 'binding', True,
                 'What a private endpoint reaches: the secret store, keys, object storage, a database, logs, '
                 "messaging, a registry, the provider's APIs"),
    AttributeDef(391, 'ciamPrivateEndpointKind', enum_type(PRIVATE_ENDPOINT_KINDS), 'binding', True,
                 "How: an endpoint the routes point at (gateway), an address in a subnet (interface), one address for "
                 "all of the provider's APIs, the provider's service networks reached by peering, or a subnet setting"),
    AttributeDef(392, 'ciamReachesRole', 'string', 'binding', False,
                 'Binding role of what it reaches (a secret, key or object store binding)'),
    AttributeDef(393, 'ciamPrivateDns', 'bool', 'binding', True,
                 "Whether the service's usual name resolves to the private endpoint inside the network"),
    AttributeDef(394, 'ciamServiceAlias', 'string', 'binding', True,
                 'The name other networks connect to an endpoint service by (service name, alias, attachment); it '
                 'changes with the environment, so every consumer reconnects'),
    AttributeDef(395, 'ciamAllowedPrincipal', 'string', 'binding', False,
                 'An account, subscription or project allowed to connect (or approved automatically)'),
    AttributeDef(396, 'ciamAcceptanceRequired', 'bool', 'binding', True,
                 'Whether each new connection waits for the operators to accept it'),
    AttributeDef(397, 'ciamVisibleTo', 'string', 'binding', False,
                 'An account, subscription or project that may discover the service (none recorded: anyone who '
                 'knows its name)'),
    # ------------------------------------------------------------------ bindings: interconnect depth
    AttributeDef(398, 'ciamLinkKind', enum_type(LINK_KINDS), 'binding', True,
                 'What an interconnect is: network peering, a transit hub attachment, a site-to-site VPN, a dedicated '
                 'circuit, a managed hub connection'),
    AttributeDef(399, 'ciamPeerGateway', 'ip', 'binding', False,
                 "Address of the other end (a VPN peer's gateway, a tunnel's outside address)"),
    AttributeDef(400, 'ciamLocalAsn', 'int', 'binding', True, 'BGP autonomous system number on this side'),
    AttributeDef(401, 'ciamPeerAsn', 'int', 'binding', True, 'BGP autonomous system number of the peer'),
    AttributeDef(402, 'ciamAdvertisedCidr', 'cidr', 'binding', False, 'A range this side advertises over the link'),
    AttributeDef(403, 'ciamAcceptedCidr', 'cidr', 'binding', False, 'A range this side accepts from the peer'),
    AttributeDef(404, 'ciamPeerAccepted', 'bool', 'binding', True,
                 'Whether the other side has accepted or configured its half (peering is two-sided)'),
    # ------------------------------------------------------------------ bindings: egress control, time, flow logs
    AttributeDef(405, 'ciamProxyKind', enum_type(PROXY_KINDS), 'binding', True,
                 'What controls egress to named sites: a cloud firewall with domain rules, a managed web proxy, a '
                 'forward proxy the platform runs, a proxy service run by someone else'),
    AttributeDef(406, 'ciamProxyAddress', 'string', 'binding', True,
                 'Where clients send traffic to an explicit proxy (host:port)', (("X-PATTERN", PROXY_ADDRESS),)),
    AttributeDef(407, 'ciamAllowedDestination', 'string', 'binding', False,
                 'A site the proxy or firewall lets traffic out to (host, or * and a domain)',
                 (("X-PATTERN", DESTINATION),)),
    AttributeDef(411, 'ciamTimeServer', 'string', 'binding', False,
                 "A time server the servers synchronize with (host or address; 'ptp:<device>' for a host clock)"),
    AttributeDef(412, 'ciamTimeKind', enum_type(TIME_KINDS), 'binding', True,
                 "Where time comes from: the provider's own service, NTP servers, the host's clock (PTP), servers the "
                 'organization runs'),
    AttributeDef(413, 'ciamFlowScope', enum_type(FLOW_SCOPES), 'binding', True,
                 'What a flow log records: a whole network, subnets, interfaces, a transit attachment, a security '
                 'group'),
    # ------------------------------------------------------------------ bindings: firewall model and policies
    AttributeDef(414, 'ciamFirewallModel', enum_type(FIREWALL_MODELS), 'binding', True,
                 "How the network's firewall rules are kept: as rules on the network (the default) or in a policy "
                 'attached to it, targeting servers by governed tags'),
    AttributeDef(420, 'ciamOpenWithinNetwork', 'bool', 'binding', True,
                 "Whether the network admits traffic between its own addresses unless a rule denies it (some "
                 "providers' default rules do)"),
    AttributeDef(415, 'ciamPolicyScope', enum_type(POLICY_SCOPES), 'binding', True,
                 'Whether a firewall policy is attached to the network or above it (an organization or folder; read, '
                 'never rendered)'),
    AttributeDef(416, 'ciamPolicyOrder', enum_type(POLICY_ORDER), 'binding', True,
                 "Which the network evaluates first: its rules or its policy"),
    AttributeDef(417, 'ciamPolicyRole', 'string', 'binding', True,
                 'Binding role of the firewall policy a rule belongs to'),
    AttributeDef(418, 'ciamNatAllocation', enum_type(NAT_ALLOCATION), 'binding', True,
                 'Whether egress addresses are fixed (static) or picked by the provider (automatic: nothing a partner '
                 'can allowlist)'),
    AttributeDef(419, 'ciamTagKeyRef', 'string', 'binding', True,
                 'Provider reference of the tag key a firewall policy targets servers by'),
)
CLASSES = (
    ClassDef(82, 'ciamEgressDestination', 'ciamObject', 'STRUCTURAL', ('cn', 'ciamDestination', 'ciamSiteKind'),
             ('ciamNeededByRole', 'ciamPort'),
             'An outside site the platform must reach (partner metadata, signing keys, certificate status, vendors)'),
    ClassDef(83, 'ciamRouteTable', 'ciamBinding', 'STRUCTURAL', ('ciamRoute',),
             ('ciamSubnetRole', 'ciamMainTable', 'ciamManagedBy'),
             'Routes, and the subnets that use them'),
    ClassDef(84, 'ciamNetworkAcl', 'ciamBinding', 'STRUCTURAL', ('ciamAclRule',),
             ('ciamSubnetRole', 'ciamEphemeralPorts', 'ciamManagedBy'),
             'A stateless network ACL on subnets: rules both ways, in number order'),
    ClassDef(85, 'ciamPrivateEndpoint', 'ciamBinding', 'STRUCTURAL', ('ciamPrivateService',),
             ('ciamPrivateEndpointKind', 'ciamReachesRole', 'ciamSubnetRole', 'ciamFrontendIp', 'ciamCidr',
              'ciamDnsZone', 'ciamDnsZoneRef', 'ciamPrivateDns', 'ciamManagedBy'),
             'A private way to a service the platform uses, so its traffic stays off the internet'),
    ClassDef(86, 'ciamEndpointService', 'ciamBinding', 'STRUCTURAL', ('ciamServiceRole',),
             ('ciamServiceAlias', 'ciamAllowedPrincipal', 'ciamAllowsConsumer', 'ciamAcceptanceRequired',
              'ciamVisibleTo', 'ciamSubnetRole'),
             'A service name exposed privately to other networks or accounts, and who may connect'),
    ClassDef(87, 'ciamProxy', 'ciamBinding', 'STRUCTURAL', ('ciamProxyKind',),
             ('ciamProxyAddress', 'ciamAllowedDestination', 'ciamManagedBy'),
             'What egress to named sites passes, and the sites it allows'),
    ClassDef(88, 'ciamTimeSource', 'ciamBinding', 'STRUCTURAL', ('ciamTimeServer',),
             ('ciamTimeKind',),
             "Where the servers get their time (clock skew breaks SAML and replication)"),
    ClassDef(89, 'ciamFlowLog', 'ciamBinding', 'STRUCTURAL', ('ciamFlowScope',),
             ('ciamSubnetRole', 'ciamLogDestinationRole', 'ciamRetentionDays', 'ciamManagedBy'),
             'A flow log: what it records, where it goes, how long it is kept'),
    ClassDef(90, 'ciamFirewallPolicy', 'ciamBinding', 'STRUCTURAL', ('ciamPolicyScope',),
             ('ciamPolicyOrder', 'ciamTagKeyRef', 'ciamManagedBy'),
             'A firewall policy attached to the network or above it; rules name it by its role'),
)

FRAGMENT = fragment(ATTRIBUTES, CLASSES)

"""Edge domain schema: how traffic reaches the platform and what protects it. Traffic and protection policies and
header contracts are intent, the same in every environment: a policy names the binding roles of the service names it
applies to, so one policy means each environment's own load balancer, WAF and CDN in front of them. What realizes them
is a binding per environment: DNS zones, records and forwarders, the WAF, CDN, DDoS protection, gateways and proxies,
and what each actually runs (read back as facts in the policies' terms)."""
from ...core.standard import AttributeDef, ClassDef, enum_type, fragment
from .naming import (BACKEND_VALIDATION, DDOS_TIERS, EDGE_FACT, EDGE_KINDS, ENDPOINT_PATH, FORWARD_DIRECTIONS,
                     GEO_RULE, HEADER_KINDS, HEADER_NAME, HEALTH_PROTOCOLS, IP_RULE, RATE_LIMIT, RECORD_TYPES,
                     ROUTING_POLICIES, STICKINESS, TLS_MODES, TLS_PROFILES, TLS_VERSIONS, WAF_CATEGORIES, WAF_EXCLUSION,
                     WAF_MODES, ZONE_VISIBILITY)

_SECONDS = (("X-MIN", "1"),)

ATTRIBUTES = (
    # ------------------------------------------------------------------ intent: traffic
    AttributeDef(342, 'ciamServiceRole', 'string', 'intent', False,
                 'Binding role of a service name this applies to (each environment binds its own)'),
    AttributeDef(343, 'ciamTlsMode', enum_type(TLS_MODES), 'intent', True,
                 'How the load balancer handles TLS: passthrough to the servers (layer 4), or terminate at the edge '
                 'and send on in clear (terminate) or encrypted again (reencrypt); only layer 7 can inspect requests'),
    AttributeDef(344, 'ciamTlsMinVersion', enum_type(TLS_VERSIONS), 'intent', True,
                 'Lowest TLS version the edge accepts from clients'),
    AttributeDef(345, 'ciamTlsProfile', enum_type(TLS_PROFILES), 'intent', True,
                 'Cipher profile the edge offers (modern, intermediate, compatible); each cloud renders its nearest '
                 'named policy'),
    AttributeDef(346, 'ciamBackendValidation', enum_type(BACKEND_VALIDATION), 'intent', True,
                 "What the edge checks of the servers' certificates when it re-encrypts: nothing, a trusted root, or "
                 'a trusted root and the name'),
    AttributeDef(347, 'ciamHealthProtocol', enum_type(HEALTH_PROTOCOLS), 'intent', True,
                 'How the load balancer checks a server is healthy'),
    AttributeDef(348, 'ciamHealthPath', 'string', 'intent', True,
                 "Path of an HTTP health check, when not the product's declared health endpoint",
                 (("X-PATTERN", "^/[^ ]*$"),)),
    AttributeDef(349, 'ciamHealthIntervalSeconds', 'int', 'intent', True, 'Seconds between health checks', _SECONDS),
    AttributeDef(350, 'ciamHealthyThreshold', 'int', 'intent', True,
                 'Consecutive passed checks before a server takes traffic', _SECONDS),
    AttributeDef(351, 'ciamUnhealthyThreshold', 'int', 'intent', True,
                 'Consecutive failed checks before a server stops taking traffic', _SECONDS),
    AttributeDef(352, 'ciamStickiness', enum_type(STICKINESS), 'intent', True,
                 'Whether a client keeps reaching the same server: no, by source address, or by a cookie'),
    AttributeDef(353, 'ciamStickinessSeconds', 'int', 'intent', True, 'How long stickiness lasts', _SECONDS),
    AttributeDef(354, 'ciamIdleTimeoutSeconds', 'int', 'intent', True,
                 'Seconds an idle connection is kept open', _SECONDS),
    AttributeDef(355, 'ciamDrainSeconds', 'int', 'intent', True,
                 'Seconds a server leaving the pool keeps its open connections'),
    AttributeDef(364, 'ciamEndpointPath', 'string', 'intent', False,
                 "Where an endpoint lives on these services when not where its product declares it: '<kind> <path>' "
                 '(token /oauth/token)',
                 (("X-PATTERN", ENDPOINT_PATH),)),
    # ------------------------------------------------------------------ intent: protection
    AttributeDef(356, 'ciamWafMode', enum_type(WAF_MODES), 'intent', True,
                 'Whether the web application firewall only counts what its rules match (detect) or blocks it'),
    AttributeDef(357, 'ciamWafCategory', enum_type(WAF_CATEGORIES), 'intent', False,
                 'A category of managed rules the web application firewall applies'),
    AttributeDef(358, 'ciamRateLimit', 'string', 'intent', False,
                 "A rate limit on an endpoint kind: '<kind> <requests>/<seconds>s per <ip|header:Name>' "
                 '(token 100/300s per ip)',
                 (("X-PATTERN", RATE_LIMIT),)),
    AttributeDef(359, 'ciamIpRule', 'string', 'intent', False,
                 "Addresses always allowed or refused: 'allow|deny <cidr>'", (("X-PATTERN", IP_RULE),)),
    AttributeDef(360, 'ciamGeoRule', 'string', 'intent', False,
                 "Countries allowed or refused: 'allow|deny <ISO 3166 codes>'", (("X-PATTERN", GEO_RULE),)),
    AttributeDef(361, 'ciamWafExclusion', 'string', 'intent', False,
                 "A field a managed rule category must not inspect on an endpoint kind (SAML posts, token requests "
                 "trip generic rules): '<category> on <kind> <body|query|header|cookie>:<name>'",
                 (("X-PATTERN", WAF_EXCLUSION),)),
    AttributeDef(362, 'ciamDdosTier', enum_type(DDOS_TIERS), 'intent', True,
                 "DDoS protection beyond the provider's standard: network-advanced (the addresses), "
                 'application-advanced (layer 7 too)'),
    AttributeDef(363, 'ciamCdn', 'bool', 'intent', True,
                 'Whether a CDN serves these service names (sign-in, token and password endpoints are never cached)'),
    # ------------------------------------------------------------------ intent: header contracts
    AttributeDef(365, 'ciamHeaderName', 'string', 'contract', True,
                 'HTTP header an application or product trusts. Must stay the same across migrations',
                 (("X-PATTERN", HEADER_NAME),)),
    AttributeDef(366, 'ciamHeaderKind', enum_type(HEADER_KINDS), 'intent', True,
                 "What a header carries: who the user is (header-based sign-on), the client's address, the scheme "
                 'or host the client used'),
    AttributeDef(367, 'ciamSetByRole', 'string', 'intent', True,
                 "Who sets a header: a server role (a gateway, a proxy) or a service name's binding role (its "
                 'load balancer)'),
    AttributeDef(368, 'ciamTrustedByRole', 'string', 'intent', False, 'A server role that trusts a header'),
    AttributeDef(369, 'ciamTrustedByConsumer', 'dn', 'intent', False, 'A consumer that trusts a header'),
    AttributeDef(370, 'ciamHeaderValue', 'string', 'intent', True,
                 "What a header's value comes from (claim sub, attribute uid, the client's address)"),
    AttributeDef(371, 'ciamStripsInbound', 'bool', 'intent', True,
                 'Whether the setter removes the header from incoming requests, so a client cannot supply it'),
    # ------------------------------------------------------------------ bindings: DNS
    AttributeDef(372, 'ciamZoneVisibility', enum_type(ZONE_VISIBILITY), 'binding', True,
                 'Whether a DNS zone answers the internet or only the networks linked to it'),
    AttributeDef(373, 'ciamRecordName', 'fqdn', 'binding', True, 'Name of a DNS record'),
    AttributeDef(374, 'ciamRecordType', enum_type(RECORD_TYPES), 'binding', True, 'Type of a DNS record'),
    AttributeDef(375, 'ciamRecordValue', 'string', 'binding', False, 'A value a DNS record answers with'),
    AttributeDef(376, 'ciamTtlSeconds', 'int', 'binding', True,
                 'How long resolvers may cache a DNS answer, in seconds (lowered before a cutover)', (("X-MIN", "0"),)),
    AttributeDef(377, 'ciamRoutingPolicy', enum_type(ROUTING_POLICIES), 'binding', True,
                 'How a DNS name chooses among answers: one answer, the primary or secondary of a health-checked '
                 'failover pair, or a weighted share'),
    AttributeDef(378, 'ciamRoutingWeight', 'int', 'binding', True, 'Share of answers a weighted record gets',
                 (("X-MIN", "0"),)),
    AttributeDef(379, 'ciamForwardDomain', 'fqdn', 'binding', False,
                 'A domain whose queries are forwarded to other resolvers (a conditional forwarder)'),
    AttributeDef(380, 'ciamForwardTarget', 'ip', 'binding', False, 'A resolver queries are forwarded to'),
    AttributeDef(381, 'ciamForwardDirection', enum_type(FORWARD_DIRECTIONS), 'binding', True,
                 "outbound: the environment's queries for the domains go to the targets; inbound: other networks' "
                 'queries come in to the environment'),
    AttributeDef(592, 'ciamResolverHost', 'ip', 'binding', False,
                 "A DNS server on the environment's own machines that does the forwarding, instead of the platform's "
                 "managed resolver; the network's DNS settings point at it"),
    # ------------------------------------------------------------------ bindings: what the edge runs
    AttributeDef(382, 'ciamEdgeKind', enum_type(EDGE_KINDS), 'binding', True,
                 'What an edge service is: a web application firewall, a CDN, DDoS protection, an API gateway, a '
                 'reverse proxy'),
    AttributeDef(383, 'ciamEdgeFact', 'string', 'observed', False,
                 "What the edge runs, read back in the policies' terms: '<key> <value>' (tls-min 1.2, waf-category "
                 'core-rules, rate-limit token 100/300s per ip, health https /pf/heartbeat.ping)',
                 (("X-PATTERN", EDGE_FACT),)),
    AttributeDef(384, 'ciamEdgeSetting', 'string', 'observed', False,
                 "A setting the edge runs that the policies' terms can't express, in the provider's own terms"),
)
CLASSES = (
    ClassDef(74, 'ciamTrafficPolicy', 'ciamObject', 'STRUCTURAL', ('cn', 'ciamServiceRole', 'ciamTlsMode'),
             ('ciamTlsMinVersion', 'ciamTlsProfile', 'ciamBackendValidation', 'ciamHealthProtocol', 'ciamHealthPath',
              'ciamHealthIntervalSeconds', 'ciamHealthyThreshold', 'ciamUnhealthyThreshold', 'ciamStickiness',
              'ciamStickinessSeconds', 'ciamIdleTimeoutSeconds', 'ciamDrainSeconds', 'ciamEndpointPath'),
             "How traffic reaches the servers behind service names: TLS handling and level, health checks, "
             'stickiness, timeouts'),
    ClassDef(75, 'ciamProtectionPolicy', 'ciamObject', 'STRUCTURAL', ('cn', 'ciamServiceRole'),
             ('ciamWafMode', 'ciamWafCategory', 'ciamRateLimit', 'ciamIpRule', 'ciamGeoRule', 'ciamWafExclusion',
              'ciamDdosTier', 'ciamCdn', 'ciamEndpointPath'),
             'What protects service names: web application firewall rules and rate limits, address and country '
             'rules, DDoS protection, a CDN'),
    ClassDef(76, 'ciamHeaderContract', 'ciamObject', 'STRUCTURAL',
             ('cn', 'ciamHeaderName', 'ciamHeaderKind', 'ciamSetByRole'),
             ('ciamTrustedByRole', 'ciamTrustedByConsumer', 'ciamHeaderValue', 'ciamStripsInbound'),
             'A header someone sets and applications or products trust: header-based sign-on, the client address '
             'behind a proxy'),
    ClassDef(77, 'ciamDnsZoneBinding', 'ciamBinding', 'STRUCTURAL', ('ciamDnsZone', 'ciamZoneVisibility'),
             ('ciamProviderRef', 'ciamManagedBy'),
             'A DNS zone the environment publishes in, and who runs it when not the platform'),
    ClassDef(78, 'ciamDnsRecord', 'ciamBinding', 'STRUCTURAL', ('ciamRecordName', 'ciamRecordType'),
             ('ciamRecordValue', 'ciamTtlSeconds', 'ciamRoutingPolicy', 'ciamRoutingWeight', 'ciamDnsZone',
              'ciamProviderRef'),
             'A DNS record beyond the service names (verification, mail, delegation), with its TTL and routing'),
    ClassDef(79, 'ciamDnsForwarder', 'ciamBinding', 'STRUCTURAL', ('ciamForwardDomain', 'ciamForwardTarget'),
             ('ciamForwardDirection', 'ciamProviderRef', 'ciamResolverHost'),
             'A conditional forwarder or resolver rule: the domains it forwards and the resolvers it forwards to'),
    ClassDef(80, 'ciamEdgeService', 'ciamBinding', 'STRUCTURAL', ('ciamEdgeKind',),
             ('ciamServiceRole', 'ciamProviderRef', 'ciamEdgeFact', 'ciamEdgeSetting'),
             'A web application firewall, CDN, DDoS protection, API gateway or reverse proxy in front of service '
             'names, and what it runs'),
)

FRAGMENT = fragment(ATTRIBUTES, CLASSES)

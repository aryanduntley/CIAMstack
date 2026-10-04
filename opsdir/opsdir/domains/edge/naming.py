"""Edge domain vocabulary: where traffic and protection policies and header contracts live, the neutral terms a policy
is written in (TLS modes, versions and profiles, health checks, stickiness, WAF categories, the kinds of endpoint a
product declares), and the kinds of DNS records, routing, forwarders and edge services an environment binds."""
from ...core.naming import branch

EDGE_POLICIES = branch("edge-policies")
HEADER_CONTRACTS = branch("header-contracts")

# How a service's load balancer handles TLS: passed through to the servers (layer 4), or terminated at the edge
# (layer 7), then sent on in clear (terminate) or encrypted again (reencrypt). Only layer 7 can inspect requests.
TLS_MODES = ("passthrough", "terminate", "reencrypt")
LAYER7 = ("terminate", "reencrypt")
TLS_VERSIONS = ("1.2", "1.3")
# Cipher profile, after Mozilla's server-side TLS levels; each cloud maps (version, profile) to its nearest policy
TLS_PROFILES = ("modern", "intermediate", "compatible")
BACKEND_VALIDATION = ("none", "trusted-roots", "san-match")   # what the edge checks of the servers' certificates
HEALTH_PROTOCOLS = ("tcp", "http", "https")
STICKINESS = ("none", "source-ip", "cookie")

WAF_MODES = ("detect", "block")
WAF_CATEGORIES = ("core-rules", "known-bad-inputs", "ip-reputation", "bot-control", "account-takeover",
                  "account-creation-fraud")
# What an endpoint a product declares is for; renderers aim rate limits, exclusions, health checks and cache bypasses
# at them, and the planner asks for protection of the sensitive ones on public services.
ENDPOINT_KINDS = ("login", "token", "password-reset", "registration", "saml-post", "health")
SENSITIVE = ("login", "token", "password-reset", "registration")
DDOS_TIERS = ("standard", "network-advanced", "application-advanced")

_KINDS = "|".join(ENDPOINT_KINDS)
RATE_LIMIT = f"^({_KINDS}) [0-9]+/[0-9]+s per (ip|header:[A-Za-z0-9-]+)$"          # token 100/300s per ip
IP_RULE = "^(allow|deny) [0-9A-Fa-f:.]+/[0-9]+$"                                    # deny 203.0.113.0/24
GEO_RULE = "^(allow|deny) [A-Z]{2}( [A-Z]{2})*$"                                    # deny KP IR
WAF_EXCLUSION = (f"^({'|'.join(WAF_CATEGORIES)}) on ({_KINDS}) "                    # core-rules on saml-post
                 "(body|query|header|cookie):[A-Za-z0-9_.-]+$")                     # body:SAMLResponse
ENDPOINT_PATH = f"^({_KINDS}) /[^ ]*$"                                              # token /as/token.oauth2

HEADER_KINDS = ("identity", "client-ip", "forwarded-proto", "forwarded-host", "other")
HEADER_NAME = "^[A-Za-z0-9][A-Za-z0-9_-]*$"

ZONE_VISIBILITY = ("public", "private")
RECORD_TYPES = ("A", "AAAA", "CNAME", "TXT", "MX", "SRV", "CAA", "NS")
ROUTING_POLICIES = ("simple", "failover-primary", "failover-secondary", "weighted")
FORWARD_DIRECTIONS = ("outbound", "inbound")
EDGE_KINDS = ("waf", "cdn", "ddos", "api-gateway", "reverse-proxy")

# What an environment runs at its edge, read back by the cloud importers in the policies' own terms ('<key> <value>'),
# so the planner compares it with the intent and with the other environment without knowing any cloud.
FACT_KEYS = ("tls-mode", "tls-min", "tls-profile", "backend-validation", "health", "stickiness", "idle-timeout",
             "drain", "waf-mode", "waf-category", "rate-limit", "ip-rule", "geo-rule", "ddos", "cdn")
EDGE_FACT = f"^({'|'.join(FACT_KEYS)}) [^ ].*$"

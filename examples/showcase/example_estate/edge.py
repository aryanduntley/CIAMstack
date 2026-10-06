"""Edge fixture data (85-edge): how traffic reaches the platform and what protects it. The intent is the same in every
environment: the sign-on services (PingFederate's sso and PingAM's login) terminate TLS at the edge and re-encrypt to
their servers behind a web application firewall with rate limits on sign-in and tokens, DDoS protection and a SAML
exclusion; LDAPS passes through. Two header contracts: the client's address the sign-on load balancers pass on, and
the partner user the gateway puts in a header for the partner portal. What realizes them is a binding per environment
(EDGE below, used by infrastructure: SOURCE / TARGET / STANDBY): the DNS zones, the AD forwarder, the SSO certificate in
each cloud's store, the subnets the target's and the standby's load balancers need; and what the source's load
balancers run today, read back as facts (SERVICE_ATTRS).

Planted for the planner to find:
  - the public zone is on the corporate DNS team's Infoblox with 3600 s TTLs: lowering them is dated before cutover,
    and the team gets a drafted request to repoint the names
  - PingFederate's self-service password reset has no rate limit (the policy limits sign-in and tokens only)
  - the gateway's source load balancer keeps clients on one server by source address, which no policy states
  - the partner user header isn't stripped from incoming requests: a client can send it
  - sso and login move from TLS passthrough to termination: PingFederate and PingAM must trust the client address
    header from the target's load balancers
  - the source forwards the AD domain to the domain controllers; the target has no forwarder (approved change CHG-2015
    adds it)
"""
from .common import R, cert, ou, owner, spec

FILE = "85-edge"
POLICIES, HEADERS = f"ou=edge-policies,{R}", f"ou=header-contracts,{R}"
SIGN_ON = ("pf-sso-service", "am-service")
# cn, description, attributes
TRAFFIC = (
    ("sign-on-edge", "Sign-on terminates TLS at the edge (the firewall inspects it) and re-encrypts to the servers",
     {"ciamServiceRole": list(SIGN_ON), "ciamTlsMode": "reencrypt", "ciamTlsMinVersion": "1.2",
      "ciamTlsProfile": "intermediate", "ciamStickiness": "cookie", "ciamStickinessSeconds": 3600}),
    ("ldaps-passthrough", "LDAPS passes through to the directory servers, which present its certificate",
     {"ciamServiceRole": "ds-ldaps-service", "ciamTlsMode": "passthrough"}),
)
PROTECTION = (
    # planted: no password-reset rate limit (PingFederate serves /ext/pwdreset/*)
    ("sign-on-protection", "What protects sign-on: managed rules, bots, sign-in and token rate limits",
     {"ciamServiceRole": list(SIGN_ON), "ciamWafMode": "block",
      "ciamWafCategory": ["core-rules", "known-bad-inputs", "bot-control"],
      "ciamRateLimit": ["login 300/300s per ip", "token 600/300s per ip"],
      "ciamWafExclusion": "core-rules on saml-post body:SAMLResponse", "ciamDdosTier": "network-advanced"}),
)
CONTRACTS = (
    ("client-address-sso", "The client's address PingFederate uses for risk and audit",
     {"ciamHeaderName": "X-Forwarded-For", "ciamHeaderKind": "client-ip", "ciamSetByRole": "pf-sso-service",
      "ciamTrustedByRole": "pf-engine", "ciamHeaderValue": "the client's address", "ciamStripsInbound": "TRUE"}),
    ("client-address-login", "The client's address PingAM uses for its journeys' risk nodes",
     {"ciamHeaderName": "X-Forwarded-For", "ciamHeaderKind": "client-ip", "ciamSetByRole": "am-service",
      "ciamTrustedByRole": "am", "ciamHeaderValue": "the client's address", "ciamStripsInbound": "TRUE"}),
    # planted: not stripped from incoming requests
    ("partner-user", "The partner portal trusts the gateway's header for who the partner user is",
     {"ciamHeaderName": "X-Partner-User", "ciamHeaderKind": "identity", "ciamSetByRole": "ig",
      "ciamTrustedByRole": "partner-portal", "ciamHeaderValue": "claim sub"}),
)


def entries():
    return (ou(FILE, "edge-policies"),
            *(spec(FILE, f"cn={cn},{POLICIES}", ["top", "ciamObject", "ciamTrafficPolicy"], cn=cn, description=desc,
                   ciamOwner=owner("ciam-platform"), **attrs) for cn, desc, attrs in TRAFFIC),
            *(spec(FILE, f"cn={cn},{POLICIES}", ["top", "ciamObject", "ciamProtectionPolicy"], cn=cn,
                   description=desc, ciamOwner=owner("ciam-platform"), **attrs) for cn, desc, attrs in PROTECTION),
            ou(FILE, "header-contracts"),
            *(spec(FILE, f"cn={cn},{HEADERS}", ["top", "ciamObject", "ciamHeaderContract"], cn=cn, description=desc,
                   ciamOwner=owner("ciam-platform"), **attrs) for cn, desc, attrs in CONTRACTS))


# ------------------------------------------------------------------ each environment's edge bindings
PUBLIC_ZONE = ("ciamDnsZoneBinding", "zone-public", "zone-example-aero.test",
               {"ciamDnsZone": "example-aero.test", "ciamZoneVisibility": "public",
                "ciamManagedBy": owner("corporate-dns")[0],
                "description": "The company's public zone, on the corporate DNS team's Infoblox"})
AD = ("corp.example-aero.internal", ["10.40.0.53", "10.40.0.54"])        # the domain controllers' DNS


def _forwarder(ref):
    return ("ciamDnsForwarder", "fwd-corp-ad", "forwarder-corp.example-aero.internal",
            {"ciamForwardDomain": AD[0], "ciamForwardTarget": AD[1], "ciamForwardDirection": "outbound",
             "ciamProviderRef": ref})


def _certificate(ref):
    return ("ciamCertificateRef", "cert-sso-tls", "sso-tls-certificate",
            {"ciamRefUri": ref, "ciamHoldsCertificate": cert("sso-tls-2026")[0]})


def _private_zone(zone, ref):
    return ("ciamDnsZoneBinding", "zone-private", "private-zone",
            {"ciamDnsZone": zone, "ciamZoneVisibility": "private", "ciamProviderRef": ref,
             "description": "Where the LDAPS name is published, for the platform's networks"})


EDGE = {
    "source": (PUBLIC_ZONE, _private_zone("id.example-aero.test", "Z0EXAMPLE1PRIVATE"),
               _forwarder("rslvr-rr-0a1b2c3d4e5f60001"),
               _certificate("aws-acm://arn:aws:acm:us-east-1:111122223333:certificate/"
                            "7f3e9d21-0000-4000-8000-0000000000a1")),
    # planted: no AD forwarder (CHG-2015 adds it)
    "target": (PUBLIC_ZONE, _private_zone("id.cloud.example-aero.test", "id.cloud.example-aero.test"),
               _certificate("azkv-cert://kv-ciam-prod/sso-tls-2026"),
               ("ciamSubnetBinding", "snet-edge", "subnet-edge",
                {"ciamProviderRef": "vnet-ciam-prod/snet-appgw", "ciamCidr": "10.60.250.0/24",
                 "description": "The Application Gateways' own subnet"})),
    "standby": (_forwarder("projects/example-aero-ciam-standby/managedZones/fwd-corp-ad"),
                _certificate("gcp-cert://projects/example-aero-ciam-standby/locations/us-central1/certificates/"
                             "sso-tls-2026"),
                ("ciamSubnetBinding", "subnet-edge", "subnet-edge",
                 {"ciamProviderRef": "projects/example-aero-net/regions/us-central1/subnetworks/ciam-standby-proxy",
                  "ciamCidr": "10.70.250.0/23", "description": "The proxy-only subnet the load balancers run in"})),
}
# What the source's service names answer with and run today (its load balancers read back): the corporate DNS team's
# TTLs, and passthrough everywhere
SERVICE_ATTRS = {
    "source": {"svc-ldaps": {"ciamTtlSeconds": 60, "ciamEdgeFact": "tls-mode passthrough"},
               **{cn: {"ciamTtlSeconds": 3600, "ciamEdgeFact": "tls-mode passthrough"}
                  for cn in ("svc-sso", "svc-login")},
               # planted: the gateway's load balancer sticks by source address, which no policy states
               "svc-apps": {"ciamTtlSeconds": 3600, "ciamEdgeFact": ["tls-mode passthrough", "stickiness source-ip"]}},
    "target": {}, "standby": {},
}


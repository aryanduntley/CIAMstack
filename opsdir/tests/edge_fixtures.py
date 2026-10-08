"""Edge specs and the few entries a cloud's edge renderer reads, for the cloud adapters' edge tests: a service name, its
servers, subnets and firewall rules in one environment, and an EdgeSpec with every policy field set (each test replaces
what it is about)."""
from types import SimpleNamespace

from opsdir.core.directory import make_entry
from opsdir.core.environment import env_model
from opsdir.core.interchange.ldif import parse
from opsdir.domains.edge.resolve import EdgeSpec, Exclusion, Health, RateLimit
import mini_estate
from support import BARE, REGISTRY, build_directory

ENV = "env=prod,cloud=c,ou=environments,dc=ciam-ops"
BASE = EdgeSpec(
    role="pf-sso-service", mode="reencrypt", layer7=True, tls_min="1.2", tls_profile="intermediate",
    backend_validation="none", health=Health("https", "/pf/heartbeat.ping", 10, 2, 3), stickiness="cookie",
    stickiness_seconds=3600, idle_timeout=120, drain=30, waf_mode="block", categories=("core-rules",),
    rate_limits=(RateLimit("token", 100, 300, "ip", ("/as/token.oauth2",)),),
    ip_rules=(("deny", "203.0.113.0/24"),), geo_rules=(("deny", ("KP",)),),
    exclusions=(Exclusion("core-rules", "saml-post", "body", "SAMLResponse", ("/idp/SSO.saml2",)),),
    ddos="standard", cdn=False, endpoints={"login": ("/as/authorization.oauth2",)}, certificate=None, traffic=None,
    protection=None)


def spec(**changes):
    """The base spec with some fields replaced."""
    return BASE._replace(**changes)


def _binding(cn, oc, role, **attrs):
    return make_entry(f"cn={cn},ou=bindings,{ENV}", ("top", oc),
                      {"ciamBindingRole": [role], **{k: list(v) if isinstance(v, tuple) else [v]
                                                      for k, v in attrs.items()}})


def service(ip="198.51.100.20", **attrs):
    return _binding("sso", "ciamServiceName", "pf-sso-service", ciamFqdn="sso.example.test", ciamPort="443",
                    ciamTargetRole="pf-engine", ciamFrontendIp=ip, **attrs)


def subnet(cn, role, cidr):
    return _binding(cn, "ciamSubnetBinding", role, ciamCidr=cidr)


def firewall(cn, cidrs, ports, target="pf-engine"):
    return _binding(cn, "ciamFirewallRule", cn, ciamSourceCidr=tuple(cidrs), ciamPort=tuple(ports),
                    ciamTargetRole=target)


def server(name, ip, role="pf-engine"):
    return make_entry(f"cn={name},{ENV}", ("top", "ciamServer"), {"ciamServerRole": [role], "ciamPrivateIp": [ip]})


def environment(*bindings):
    """The parts of an environment model the edge renderers read (an empty record: no tag policy)."""
    return SimpleNamespace(d=BARE, env=make_entry(ENV, ("top", "ciamEnvironment"), {"env": ["prod"]}), label="c/prod",
                           bindings=tuple(bindings))


# ------------------------------------------------------------------ DNS: two environments of the mini estate
ALPHA = "env=prod,cloud=alpha,ou=environments,dc=ciam-ops"
BETA = "env=prod,cloud=beta,ou=environments,dc=ciam-ops"
PARTY = "cn=dns-team,ou=owners,dc=ciam-ops"


def _ldif(env, cn, oc, role, **attrs):
    lines = "".join(f"{k}: {v}\n" for k, vs in attrs.items() for v in (vs if isinstance(vs, tuple) else (vs,)))
    return (f"dn: cn={cn},ou=bindings,{env}\nobjectClass: top\nobjectClass: {oc}\ncn: {cn}\n"
            f"ciamBindingRole: {role}\n{lines}")


def _svc(env, cn, fqdn, ip, **attrs):
    return _ldif(env, cn, "ciamServiceName", cn, ciamFqdn=fqdn, ciamPort="443", ciamTargetRole="web",
                 ciamFrontendIp=ip, ciamDnsZone="example.test", **attrs)


DNS_RECORDS = (
    "dn: ou=owners,dc=ciam-ops\nobjectClass: top\nobjectClass: organizationalUnit\nou: owners\n",
    f"dn: {PARTY}\nobjectClass: top\nobjectClass: ciamParty\ncn: dns-team\nciamOwnerKind: team\n",
    *(_ldif(env, "zone-public", "ciamDnsZoneBinding", "public-zone", ciamDnsZone="example.test",
            ciamZoneVisibility="public", ciamProviderRef=ref)
      for env, ref in ((ALPHA, "Z1ALPHA"), (BETA, "zone-beta"))),
    _ldif(ALPHA, "zone-partner", "ciamDnsZoneBinding", "partner-zone", ciamDnsZone="partner.example",
          ciamZoneVisibility="public", ciamManagedBy=PARTY),
    _ldif(ALPHA, "zone-corp", "ciamDnsZoneBinding", "corp-zone", ciamDnsZone="corp.example.test",
          ciamZoneVisibility="private", ciamProviderRef="Z2CORP"),
    _svc(ALPHA, "svc-login", "login.example.test", "198.51.100.10", ciamRoutingPolicy="failover-primary",
         ciamTtlSeconds="60", ciamDnsZoneRef="Z1ALPHA"),
    _svc(BETA, "svc-login", "login.example.test", "198.51.100.20", ciamRoutingPolicy="failover-secondary"),
    _svc(ALPHA, "svc-api", "api.example.test", "198.51.100.11", ciamRoutingPolicy="weighted",
         ciamRoutingWeight="3", ciamDnsZoneRef="Z1ALPHA"),
    _svc(BETA, "svc-api", "api.example.test", "198.51.100.21", ciamRoutingPolicy="weighted", ciamRoutingWeight="1"),
    _svc(ALPHA, "svc-portal", "portal.partner.example", "198.51.100.12"),
    *(_ldif(ALPHA, cn, "ciamDnsRecord", cn, ciamRecordName=name, ciamRecordType=rtype, ciamRecordValue=value,
            **attrs) for cn, name, rtype, value, attrs in (
          ("txt-verify", "_verify.example.test", "TXT", "token=abc", {"ciamTtlSeconds": "120"}),
          ("mx-mail", "example.test", "MX", ("10 mail1.example.test", "20 mail2.example.test"), {}),
          ("caa", "example.test", "CAA", '0 issue "letsencrypt.org"', {}),
          ("cname-www", "www.example.test", "CNAME", "login.example.test", {}),
          ("srv-ldap", "_ldap._tcp.corp.example.test", "SRV", "0 5 636 ldap.corp.example.test", {}),
          ("txt-partner", "_verify.partner.example", "TXT", "token=xyz", {}),
          ("txt-nowhere", "_verify.elsewhere.test", "TXT", "token=0", {}))),
    _ldif(ALPHA, "fwd-ad", "ciamDnsForwarder", "ad-forwarder", ciamForwardDomain=("ad.corp.example", "corp.example"),
          ciamForwardTarget=("10.9.0.2", "10.9.0.3")),
    _ldif(ALPHA, "fwd-in", "ciamDnsForwarder", "inbound", ciamForwardDomain="example.internal",
          ciamForwardTarget="10.1.0.53", ciamForwardDirection="inbound"),
    _ldif(BETA, "fwd-legacy", "ciamDnsForwarder", "legacy-forwarder", ciamForwardDomain="legacy.example",
          ciamForwardTarget="10.9.1.2", ciamResolverHost=("10.2.0.4", "10.2.0.5")),
)


def dns_estate():
    """(directory, alpha model, beta model) of the mini estate with the DNS records above."""
    d = build_directory(REGISTRY, tuple(parse(mini_estate.LDIF + "\n" + "\n".join(DNS_RECORDS))))
    return d, env_model(d, "alpha/prod"), env_model(d, "beta/prod")


def binding(m, cn):
    """Environment m's binding named cn."""
    return next(b for b in m.bindings if b.dn.startswith(f"cn={cn},"))

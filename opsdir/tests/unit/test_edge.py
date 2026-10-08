"""The edge domain: traffic and protection policies and header contracts as intent; DNS zones, records and forwarders
and what each environment's edge runs as bindings; their reports, and the planner's findings when a policy can't be
rendered as stated, the source runs what the intent doesn't state, a changing name's TTL isn't lowered in time, a zone
someone else runs needs the change, a forwarder, record or private zone is missing, a header's setter is gone or a
client can spoof it, a move to a TLS-terminating load balancer hides client addresses, or a public service's sensitive
endpoints have no rate limit."""
import datetime as dt
import re

from opsdir.connectors.edge import edge_check, endpoints
from opsdir.connectors.plan import plan, request_drafts
from opsdir.core.contract import Endpoint, PlanContext
from opsdir.core.environment import env_model
from opsdir.core.interchange.ldif import parse
from opsdir.domains.edge.dns import check_dns, dns_rows, lower_by
from opsdir.domains.edge.headers import check_headers, header_rows
from opsdir.domains.edge.naming import EDGE_FACT, EDGE_POLICIES, HEADER_CONTRACTS, RATE_LIMIT, WAF_EXCLUSION
from opsdir.domains.edge.policies import check_policies, intended_facts, policy_for, policy_rows
from opsdir.domains.edge.running import check_running, edge_service_rows, missing, observed_facts, unstated
from opsdir.domains.edge.records import (answers, forwarders, hosted_notes, is_hosted, parts, records_in, routing, run_by,
                                        ttl)
from opsdir.domains.edge.resolve import (Exclusion, Health, RateLimit, certificate_ref, declared_endpoints, inspected,
                                         path_regex, service_edge)
from opsdir.domains.edge.schema import ATTRIBUTES
import mini_estate
from edge_fixtures import PARTY, binding as fixture_binding, dns_estate
from support import REGISTRY, build_directory

ALPHA = "env=prod,cloud=alpha,ou=environments,dc=ciam-ops"
BETA = "env=prod,cloud=beta,ou=environments,dc=ciam-ops"
OPS, DNS_TEAM = "cn=ops,ou=owners,dc=ciam-ops", "cn=dns-team,ou=owners,dc=ciam-ops"
AS_OF, CUTOVER = dt.date(2026, 10, 1), dt.date(2026, 11, 1)


def _ou(dn, ou):
    return f"dn: {dn}\nobjectClass: top\nobjectClass: organizationalUnit\nou: {ou}\n"


def _entry(dn, oc, attrs):
    return f"dn: {dn}\nobjectClass: top\nobjectClass: ciamObject\nobjectClass: {oc}\n" + "".join(
        f"{k}: {v}\n" for k, vs in attrs.items() for v in (vs if isinstance(vs, tuple) else (vs,)))


def _binding(env, cn, oc, role, **attrs):
    return _entry(f"cn={cn},ou=bindings,{env}", oc, {"cn": cn, "ciamBindingRole": role, **attrs})


def _policy(cn, oc, **attrs):
    return _entry(f"cn={cn},{EDGE_POLICIES}", oc, {"cn": cn, **attrs})


def _service(env, cn, role, fqdn, ip, **attrs):
    return _binding(env, cn, "ciamServiceName", role, ciamFqdn=fqdn, ciamPort="443", ciamTargetRole="web",
                    ciamFrontendIp=ip, **attrs)


BASE = (
    _ou("ou=owners,dc=ciam-ops", "owners"),
    f"dn: {OPS}\nobjectClass: top\nobjectClass: ciamParty\ncn: ops\nciamOwnerKind: team\n",
    f"dn: {DNS_TEAM}\nobjectClass: top\nobjectClass: ciamParty\ncn: dns-team\nciamOwnerKind: team\n"
    "mail: dns@example.test\n",
    _ou(EDGE_POLICIES, "edge-policies"),
    _policy("sso-edge", "ciamTrafficPolicy", ciamServiceRole=("sso-service", "login-service"), ciamTlsMode="terminate",
            ciamTlsMinVersion="1.2", ciamTlsProfile="intermediate", ciamHealthProtocol="https",
            ciamHealthPath="/pf/heartbeat.ping", ciamStickiness="cookie", ciamStickinessSeconds="3600"),
    _policy("sso-edge-old", "ciamTrafficPolicy", ciamServiceRole="sso-service", ciamTlsMode="passthrough"),
    _policy("ldaps", "ciamTrafficPolicy", ciamServiceRole="ldaps-service", ciamTlsMode="passthrough"),
    _policy("sso-protect", "ciamProtectionPolicy", ciamServiceRole=("sso-service", "login-service"),
            ciamWafMode="block", ciamWafCategory=("core-rules", "known-bad-inputs"),
            ciamRateLimit="login 300/300s per ip", ciamWafExclusion="core-rules on saml-post body:SAMLResponse",
            ciamDdosTier="network-advanced", ciamEndpointPath="token /oauth/token", ciamOwner=OPS),
    _policy("ldaps-protect", "ciamProtectionPolicy", ciamServiceRole="ldaps-service",
            ciamRateLimit="login 10/60s per ip"),
    _ou(HEADER_CONTRACTS, "header-contracts"),
    _entry(f"cn=remote-user,{HEADER_CONTRACTS}", "ciamHeaderContract",
           {"cn": "remote-user", "ciamHeaderName": "X_Remote_User", "ciamHeaderKind": "identity",
            "ciamSetByRole": "gw", "ciamTrustedByRole": "app", "ciamHeaderValue": "claim sub"}),
    _entry(f"cn=client-ip,{HEADER_CONTRACTS}", "ciamHeaderContract",
           {"cn": "client-ip", "ciamHeaderName": "X-Forwarded-For", "ciamHeaderKind": "client-ip",
            "ciamSetByRole": "login-service", "ciamTrustedByRole": "web", "ciamStripsInbound": "TRUE"}),
    _entry(f"cn=proto,{HEADER_CONTRACTS}", "ciamHeaderContract",
           {"cn": "proto", "ciamHeaderName": "X-Forwarded-Proto", "ciamHeaderKind": "forwarded-proto",
            "ciamSetByRole": "ldaps-service"}),
    # alpha (the source): what its edge runs was read back
    _service(ALPHA, "svc-login", "login-service", "login.example.test", "198.51.100.10", ciamTtlSeconds="3600",
             ciamEdgeFact=("tls-mode passthrough", "tls-min 1.3", "tls-profile compatible", "health tcp")),
    _service(ALPHA, "svc-ldaps", "ldaps-service", "ldap.example.test", "10.1.0.10"),
    _binding(ALPHA, "waf-1", "ciamEdgeService", "waf", ciamEdgeKind="waf", ciamServiceRole="login-service",
             ciamProviderRef="arn:aws:wafv2:r:1:regional/webacl/ciam/1",
             ciamEdgeFact=("waf-category core-rules", "waf-category bot-control", "rate-limit login 300/300s per ip"),
             ciamEdgeSetting="AWSManagedRulesBotControlRuleSet inspection COMMON"),
    _binding(ALPHA, "zone-public", "ciamDnsZoneBinding", "public-zone", ciamDnsZone="example.test",
             ciamZoneVisibility="public", ciamProviderRef="Z123"),
    _binding(ALPHA, "zone-corp", "ciamDnsZoneBinding", "corp-zone", ciamDnsZone="corp.example.test",
             ciamZoneVisibility="private"),
    _binding(ALPHA, "fwd-ad", "ciamDnsForwarder", "ad-forwarder", ciamForwardDomain="ad.corp.example",
             ciamForwardTarget=("10.9.0.2", "10.9.0.3"), ciamForwardDirection="outbound"),
    _binding(ALPHA, "txt-verify", "ciamDnsRecord", "verify-record", ciamRecordName="_verify.example.test",
             ciamRecordType="TXT", ciamRecordValue="token=abc", ciamTtlSeconds="300"),
    _binding(ALPHA, "a-legacy", "ciamDnsRecord", "legacy-record", ciamRecordName="legacy.example.test",
             ciamRecordType="A", ciamRecordValue="198.51.100.5", ciamTtlSeconds="120"),
    _binding(ALPHA, "subnet-gw", "ciamSubnetBinding", "subnet-gw", ciamCidr="10.1.9.0/24"),
    f"dn: cn=gw-1,{ALPHA}\nobjectClass: top\nobjectClass: ciamServer\ncn: gw-1\nciamServerRole: gw\n"
    f"ciamHostname: gw-1.alpha.example.test\nciamSubnet: cn=subnet-gw,ou=bindings,{ALPHA}\n",
    # beta (the target)
    _service(BETA, "svc-login", "login-service", "login.example.test", "198.51.100.20",
             ciamEdgeFact=("tls-mode terminate", "tls-min 1.3")),
    _service(BETA, "svc-ldaps", "ldaps-service", "ldap.example.test", "10.2.0.10"),
    _binding(BETA, "zone-public", "ciamDnsZoneBinding", "public-zone", ciamDnsZone="example.test",
             ciamZoneVisibility="public", ciamManagedBy=DNS_TEAM),
    _binding(BETA, "a-legacy", "ciamDnsRecord", "legacy-record", ciamRecordName="legacy.example.test",
             ciamRecordType="A", ciamRecordValue="198.51.100.6"),
    # beta binds these roles differently: another domain, another name, another zone
    _binding(BETA, "fwd-ad", "ciamDnsForwarder", "ad-forwarder", ciamForwardDomain="ad.other.example",
             ciamForwardTarget="10.8.0.2"),
    _binding(BETA, "txt-verify", "ciamDnsRecord", "verify-record", ciamRecordName="_verify2.example.test",
             ciamRecordType="TXT", ciamRecordValue="token=def"),
    _binding(BETA, "zone-corp", "ciamDnsZoneBinding", "corp-zone", ciamDnsZone="corp2.example.test",
             ciamZoneVisibility="private"),
)


def _record(*extra):
    return build_directory(REGISTRY, tuple(parse(mini_estate.LDIF + "\n" + "\n".join((*BASE, *extra)))))


def _ctx(d, cutover=CUTOVER):
    return PlanContext(d, env_model(d, "alpha/prod"), env_model(d, "beta/prod"), cutover, AS_OF, {}, {}, ())


def _texts(rows):
    return [r[1] for r in rows]


def test_the_policy_terms_are_patterns_the_store_enforces():
    rules = {a.name: dict(a.rules) for a in ATTRIBUTES}
    assert rules["ciamRateLimit"]["X-PATTERN"] == RATE_LIMIT and rules["ciamEdgeFact"]["X-PATTERN"] == EDGE_FACT
    assert re.fullmatch(RATE_LIMIT, "token 100/300s per ip") and re.fullmatch(RATE_LIMIT, "login 5/60s per header:X-Key")
    assert not re.fullmatch(RATE_LIMIT, "admin 5/60s per ip") and not re.fullmatch(RATE_LIMIT, "token 100 per ip")
    assert re.fullmatch(WAF_EXCLUSION, "core-rules on saml-post body:SAMLResponse")
    assert not re.fullmatch(WAF_EXCLUSION, "core-rules on saml-post SAMLResponse")
    assert re.fullmatch(EDGE_FACT, "rate-limit token 100/300s per ip") and not re.fullmatch(EDGE_FACT, "colour blue")


def test_a_services_policies_as_facts_and_the_policies_report():
    d = _record()
    t, p = policy_for(d, "ciamTrafficPolicy", "login-service"), policy_for(d, "ciamProtectionPolicy", "login-service")
    assert intended_facts(t, p) == {
        "tls-mode terminate", "tls-min 1.2", "tls-profile intermediate", "health https /pf/heartbeat.ping",
        "stickiness cookie 3600", "waf-mode block", "waf-category core-rules", "waf-category known-bad-inputs",
        "rate-limit login 300/300s per ip", "ddos network-advanced"}
    rows = {r[0]: r for r in policy_rows(d)}
    assert rows["login-service"] == ("login-service", "sso-edge", "terminate ≥1.2 intermediate", "",
                                     "https /pf/heartbeat.ping", "cookie 3600", "sso-protect",
                                     "block core-rules, known-bad-inputs", "login 300/300s per ip", "network-advanced",
                                     "")
    assert rows["sso-service"][1] == "sso-edge"            # the first by name applies


def test_policies_that_cant_be_rendered_as_stated_are_actions():
    found = check_policies(_ctx(_record()))
    assert _texts(found.actions) == [
        "Protection policy `ldaps-protect` asks for request inspection (firewall rules, rate limits, address or "
        "country rules) on `ldaps-service`, whose TLS passes through to the servers and which no CDN fronts: "
        "terminate TLS at its load balancer (a traffic policy with tls mode terminate or reencrypt), or put a CDN in "
        "front.",
        "Service role `sso-service` has several traffic policies (sso-edge, sso-edge-old); `sso-edge` applies: keep "
        "one."]


def test_what_runs_against_what_the_intent_asks():
    intended = frozenset({"tls-min 1.2", "tls-mode terminate", "waf-category core-rules", "ddos network-advanced"})
    assert unstated(intended, frozenset({"tls-min 1.3", "tls-mode passthrough", "waf-category bot-control",
                                         "ddos standard", "cdn on"})) == (
        ("cdn on", None), ("tls-min 1.3", "1.2"), ("waf-category bot-control", None))
    assert unstated(frozenset(), frozenset({"tls-mode passthrough", "ddos standard", "health tcp"})) == ()
    assert unstated(frozenset(), frozenset({"tls-mode terminate"})) == (("tls-mode terminate", None),)
    assert missing(intended, frozenset({"tls-min 1.3", "tls-mode passthrough"})) == (
        "ddos network-advanced", "tls-mode terminate", "waf-category core-rules")


def test_what_the_source_runs_that_the_intent_doesnt_state_and_what_the_target_lacks():
    d = _record()
    ctx = _ctx(d)
    assert observed_facts(ctx.src, "login-service") >= {"tls-min 1.3", "waf-category bot-control"}   # LB and WAF
    found = check_running(ctx)
    t, p = policy_for(d, "ciamTrafficPolicy", "login-service"), policy_for(d, "ciamProtectionPolicy", "login-service")
    lacking = sorted(intended_facts(t, p) - {"tls-mode terminate", "tls-min 1.2"})   # beta runs these (1.3 ≥ 1.2)
    assert _texts(found.actions) == [
        "alpha/prod runs `tls-min 1.3` in front of `login-service`, which is stronger than the intent's `tls-min 1.2`: "
        "beta/prod is rendered from the intent and wouldn't. State it in a policy, or accept dropping it.",
        "alpha/prod runs `waf-category bot-control` in front of `login-service`, which no policy states: beta/prod is "
        "rendered from the intent and wouldn't. State it in a policy, or accept dropping it.",
        *(f"beta/prod doesn't run `{f}` in front of `login-service`, which the intent asks: render and apply its edge "
          "again, or find what changed it." for f in lacking)]
    assert {a[3] for a in found.actions} == {CUTOVER} and found.actions[0][2] == "ops"
    rows = edge_service_rows(d)
    assert [r[:4] for r in rows] == [("alpha/prod", "svc-login", "load-balancer", "login-service"),
                                     ("alpha/prod", "waf-1", "waf", "login-service"),
                                     ("beta/prod", "svc-login", "load-balancer", "login-service")]
    assert rows[1][4].endswith("AWSManagedRulesBotControlRuleSet inspection COMMON")


def test_changing_names_ttls_zones_others_run_and_what_the_target_lacks():
    found = check_dns(_ctx(_record()))
    assert [(a[1], a[2], a[3]) for a in found.actions] == [
        ("`ldap.example.test` changes answer at cutover (10.1.0.10 → 10.2.0.10) and alpha/prod doesn't record its "
         "TTL: make sure it is at most 300 s, or lower it to 60 s, by 2026-10-30.", "**NO OWNER**",
         dt.date(2026, 10, 30)),
        ("dns-team runs zone `example.test`: ask them to point `ldap.example.test` to `10.2.0.10` at cutover (request "
         "drafted).", "**NO OWNER**", CUTOVER),
        ("dns-team runs zone `example.test`: ask them to point `legacy.example.test` to `198.51.100.6` at cutover "
         "(request drafted).", "**NO OWNER**", CUTOVER),
        ("Lower the TTL of `login.example.test` in alpha/prod from 3600 s to 60 s by 2026-10-30, so resolvers pick up "
         "its new answer (198.51.100.20) at cutover; restore it after.", "**NO OWNER**", dt.date(2026, 10, 30)),
        ("dns-team runs zone `example.test`: ask them to point `login.example.test` to `198.51.100.20` at cutover "
         "(request drafted).", "**NO OWNER**", CUTOVER),
        ("alpha/prod forwards queries for `ad.corp.example` to 10.9.0.2, 10.9.0.3 (`fwd-ad`); beta/prod has no "
         "outbound forwarder for it: add one before cutover, or what resolved before won't.", "**NO OWNER**", CUTOVER),
        ("alpha/prod publishes TXT `_verify.example.test`; beta/prod records none: copy it, or record why it isn't "
         "needed.", "**NO OWNER**", CUTOVER),
        ("alpha/prod has private zone `corp.example.test`; beta/prod has none: create it and link it to the target's "
         "networks, or names only it answers won't resolve.", "**NO OWNER**", CUTOVER)]
    assert found.ok == ("`legacy.example.test`'s TTL is 120 s: resolvers pick up the new answer within minutes of "
                        "cutover.",)
    assert [(party.dn, text, topic) for party, _, text, topic, _ in found.requests] == [
        (DNS_TEAM, "In zone `example.test`, point `ldap.example.test` to `10.2.0.10` at cutover (today `10.1.0.10`); "
                   "before that, make sure its TTL is at most 300 s by 2026-10-30.", "dns"),
        (DNS_TEAM, "In zone `example.test`, point `legacy.example.test` to `198.51.100.6` at cutover (today "
                   "`198.51.100.5`).", "dns"),
        (DNS_TEAM, "In zone `example.test`, point `login.example.test` to `198.51.100.20` at cutover (today "
                   "`198.51.100.10`); before that, lower its TTL from 3600 s to 60 s by 2026-10-30.", "dns")]
    assert lower_by(CUTOVER, 172800) == dt.date(2026, 10, 29) and lower_by(None, 60) is None


def test_a_ttl_fix_lowers_it_ahead_of_the_live_record_until_an_import_confirms_it():
    ctx = _ctx(_record())
    fixes = {f.key: f for f in check_dns(ctx).fixes}
    assert sorted(fixes) == ["ttl:ldap.example.test", "ttl:login.example.test"]      # legacy's 120 s is low already
    fix = fixes["ttl:login.example.test"]
    lower, mark = fix.records
    assert lower.mods == (("replace", "ciamTtlSeconds", ("60",)),)
    assert mark.mods == (("add", "ciamVerifyPending", (f"ciamTtlSeconds {ctx.src.provider}",)),)
    lowered = build_directory(REGISTRY, tuple(parse(mini_estate.LDIF + "\n" + "\n".join(BASE))), fix.records)
    texts = _texts(check_dns(_ctx(lowered)).actions)
    assert ("`login.example.test`'s TTL is 60 s in the record, set ahead of the live record: apply alpha/prod's "
            "rendered DNS and import alpha/prod again to confirm it by 2026-10-30.") in texts
    assert "ttl:login.example.test" not in {f.key for f in check_dns(_ctx(lowered)).fixes}


def test_the_dns_report_and_the_zone_keepers_request_draft():
    d = _record()
    rows = dns_rows(d)
    assert rows[0] == ("alpha/prod", "corp.example.test", "zone", "", "", "", "", "private")
    assert ("beta/prod", "example.test", "zone", "", "", "", "", "public / dns-team") in rows
    assert ("alpha/prod", "ad.corp.example", "forward outbound", "10.9.0.2, 10.9.0.3", "", "", "", "") in rows
    assert ("alpha/prod", "login.example.test", "A", "198.51.100.10", "3600", "", "", "") in rows
    draft = request_drafts(plan(d, "alpha/prod", "beta/prod", AS_OF, installed=(mini_estate.FAKE,)))[
        "requests/dns-team.md"]
    assert draft.startswith("To: dns-team <dns@example.test>\nSubject: DNS changes needed for beta/prod\n")
    assert "Please set up the following in the DNS zones you run:" in draft
    assert "- In zone `example.test`, point `login.example.test` to `198.51.100.20` at cutover" in draft


def test_header_setters_spoofing_and_client_addresses_behind_a_terminating_balancer():
    d = _record()
    found = check_headers(_ctx(d))
    assert _texts(found.blockers) == [
        "Header `X_Remote_User` (contract `remote-user`) is set by `gw` servers, which beta/prod doesn't run: `app` "
        "would go without it (header-based sign-on stops)."]
    assert _texts(found.actions) == [
        "Header `X-Forwarded-Proto` (contract `proto`) is set by the load balancer of `ldaps-service`, whose TLS passes "
        "through: a layer 4 load balancer sets no header. Terminate TLS there (a traffic policy), or name the setter "
        "that does.",
        "Clients can send header `X_Remote_User` themselves (contract `remote-user`): `gw` must remove it from incoming "
        "requests, since `app` trusts it.",
        "`login-service` changes from TLS passthrough (alpha/prod) to terminate (beta/prod): set `web` to trust "
        "`X-Forwarded-For` from beta/prod's load balancer before cutover, or they'll see its address for every "
        "client."]
    assert found.ok == ("Header contract `client-ip` kept: `X-Forwarded-For` set by `login-service` in beta/prod.",)
    assert header_rows(d)[0] == ("client-ip", "X-Forwarded-For", "client-ip", "login-service", "web", "", "yes")


def test_a_terminating_balancer_with_no_client_address_contract_asks_for_one():
    d = build_directory(REGISTRY, tuple(parse(mini_estate.LDIF + "\n" + "\n".join(
        b for b in BASE if "cn=client-ip," not in b and "cn=proto," not in b and "cn=remote-user," not in b))))
    (action,) = check_headers(_ctx(d)).actions
    assert action[1].startswith("alpha/prod passes TLS for `login-service` through, so its servers see each client's "
                                "address; beta/prod terminates it (terminate), so they'll see the load balancer's.")


def test_sensitive_endpoints_on_public_services_need_rate_limits():
    product = mini_estate.FAKE._replace(name="fake-product", endpoints=(
        Endpoint("login", "/login", "web"), Endpoint("token", "/token", "web"), Endpoint("health", "/health", "web"),
        Endpoint("token", "/elsewhere", "other")))
    d = _record()
    assert endpoints((product,), "web", policy_for(d, "ciamProtectionPolicy", "login-service")) == {
        "login": ("/login",), "token": ("/oauth/token",), "health": ("/health",)}      # the policy moved token
    found = edge_check((product,), (product,))(_ctx(d))
    assert _texts(found.actions) == [
        "`login.example.test` (`login-service`) answers the internet in alpha/prod and beta/prod; protection policy "
        "`sso-protect` sets no rate limit on token /oauth/token: add one per kind."]
    assert found.actions[0][2] == "ops"
    unprotected = build_directory(REGISTRY, tuple(parse(mini_estate.LDIF + "\n" + "\n".join(
        b for b in BASE if "cn=sso-protect," not in b))))
    (action,) = edge_check((product,), ())(_ctx(unprotected)).actions
    assert action[1] == ("`login.example.test` (`login-service`) answers the internet in alpha/prod and serves "
                         "sensitive endpoints (login /login; token /token) that no protection policy covers: give it "
                         "one with rate limits on them.")              # its traffic policy terminates TLS


def test_a_service_names_edge_as_renderers_need_it():
    d = _record(_binding(BETA, "cert-sso", "ciamCertificateRef", "sso-tls",
                         ciamRefUri="aws-acm://arn:aws:acm:r:1:certificate/abc",
                         ciamHoldsCertificate="cn=sso-tls-2026,ou=certificates,dc=ciam-ops"))
    m = env_model(d, "beta/prod")
    login = next(b for b in m.bindings if b.dn.startswith("cn=svc-login,"))
    product = (Endpoint("login", "/login", "web"), Endpoint("health", "/status", "web"),
               Endpoint("token", "/token", "web"))
    spec = service_edge(m, login, product)
    assert (spec.mode, spec.layer7, spec.tls_min, spec.tls_profile, spec.backend_validation) == \
        ("terminate", True, "1.2", "intermediate", "none")
    assert spec.health == Health("https", "/pf/heartbeat.ping", None, None, None)        # the policy's own path
    assert (spec.stickiness, spec.stickiness_seconds, spec.waf_mode, spec.ddos, spec.cdn) == \
        ("cookie", 3600, "block", "network-advanced", False)
    assert spec.rate_limits == (RateLimit("login", 300, 300, "ip", ("/login",)),)
    assert spec.exclusions == (Exclusion("core-rules", "saml-post", "body", "SAMLResponse", ()),)  # none declared
    assert spec.endpoints["token"] == ("/oauth/token",) and inspected(spec) and spec.certificate is None
    ldaps = next(b for b in m.bindings if b.dn.startswith("cn=svc-ldaps,"))
    assert service_edge(m, ldaps, product).health == Health("tcp", None, None, None, None)
    sso = next(b for b in m.bindings if b.dn.startswith("cn=svc-sso,"))
    assert service_edge(m, sso, product).mode == "terminate"           # the first traffic policy by name
    assert service_edge(m, sso._replace(attrs={**sso.attrs, "ciamBindingRole": ("nothing",)}), product) is None
    held = sso._replace(attrs={**sso.attrs, "ciamTlsCertificate": ("cn=sso-tls-2026,ou=certificates,dc=ciam-ops",)})
    assert certificate_ref(m, held) == "aws-acm://arn:aws:acm:r:1:certificate/abc"


def test_health_defaults_to_the_products_endpoint_and_paths_become_regular_expressions():
    d = _record(_policy("ldaps-terminating", "ciamTrafficPolicy", ciamServiceRole="ldaps-service",
                        ciamTlsMode="reencrypt"))
    m = env_model(d, "beta/prod")
    ldaps = next(b for b in m.bindings if b.dn.startswith("cn=svc-ldaps,"))
    spec = service_edge(m, ldaps, (Endpoint("health", "/status", "web"),))
    assert spec.mode == "passthrough"                                   # `ldaps` is first by name
    assert path_regex("/am/json/realms/*/authenticate") == "^/am/json/realms/[^?#]+/authenticate$"
    assert re.fullmatch(path_regex("/am/json/realms/*/authenticate"), "/am/json/realms/root/realms/a/authenticate")
    assert not re.fullmatch(path_regex("/as/token.oauth2"), "/as/tokenXoauth2")
    assert declared_endpoints((Endpoint("health", "/a", "web"), Endpoint("health", "/b", "web"),
                               Endpoint("login", "/x", "other")), "web") == {"health": ("/a", "/b")}


def test_routed_names_zones_run_by_others_ttls_and_record_parts():
    d, alpha, beta = dns_estate()
    login = fixture_binding(alpha, "svc-login")
    assert [(a.label, a.policy, a.weight) for a in answers(d, "LOGIN.example.test")] == [
        ("alpha/prod", "failover-primary", 1), ("beta/prod", "failover-secondary", 1)]
    assert routing(d, alpha, login)[0] == "failover-primary" and len(routing(d, alpha, login)[1]) == 2
    assert routing(d, beta, fixture_binding(beta, "svc-login")) == ("failover-secondary", ())
    assert routing(d, alpha, fixture_binding(alpha, "svc-portal")) is None
    assert run_by(d, alpha, "portal.partner.example").dn == PARTY and run_by(d, alpha, "login.example.test") is None
    assert run_by(d, beta, "portal.partner.example") is None                     # beta binds no such zone
    assert ttl(login) == 60 and ttl(fixture_binding(beta, "svc-login")) == 300
    assert parts("MX", "10 mail.example.test") == (10, "mail.example.test")
    assert parts("SRV", "0 5 636 ldap.example.test") == (0, 5, 636, "ldap.example.test")
    assert parts("CAA", '0 issue "letsencrypt.org"') == (0, "issue", "letsencrypt.org")
    assert parts("TXT", "a b") == ("a b",)
    assert [r.dn.split(",")[0] for r in records_in(alpha)][:2] == ["cn=srv-ldap", "cn=txt-nowhere"]
    assert [f.dn.split(",")[0] for f in forwarders(alpha)] == ["cn=fwd-ad"]
    assert [f.dn.split(",")[0] for f in forwarders(alpha, "inbound")] == ["cn=fwd-in"]
    assert forwarders(beta, hosted=False) == () and is_hosted(forwarders(beta, hosted=True)[0])
    assert hosted_notes(beta, "virtual machines") == (
        "# Forwarder `fwd-legacy` runs on DNS servers 10.2.0.4, 10.2.0.5 (virtual machines), not the managed resolver: "
        "they forward legacy.example to 10.9.1.2 and everything else to the platform's resolver, and the network's DNS "
        "servers point at them; not managed here",)

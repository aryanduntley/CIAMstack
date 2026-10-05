"""The first assisted fixes the planner's findings offer, each checked by applying its records and planning again:
the finding it resolves is gone. Ports between server roles (exactly the uncovered ranges, on the matching rule or a
new one), a service name's stable name, private DNS, endpoint-service principals and flow-log retention like the
source's; each carries its manual steps and what it could hide."""
from types import SimpleNamespace

from opsdir.connectors.network import network_check
from opsdir.connectors.plan import _check_contracts
from opsdir.core.contract import Listener
from opsdir.core.interchange.ldif import parse
from opsdir.domains.network.checks import check_endpoint_services, check_flow_logs, check_private_endpoints
from network_fixtures import ALPHA, BETA, context, entry, model, rule

LISTENERS = (Listener("ds", 8989, "tcp", "replication", ("peers",)), Listener("ds", 1636, "tcp", "LDAPS", ("web",)))
ADAPTERS = (SimpleNamespace(listeners=lambda m: LISTENERS),)


def _ports(**kw):
    d, alpha, beta = model(**kw)
    return network_check(ADAPTERS, ADAPTERS)(context(d, alpha, beta))


def test_a_ports_gap_admits_exactly_the_uncovered_ranges_on_the_matching_rule_or_a_new_one():
    beta = (rule(BETA, "fw-ldaps", "192.0.2.0/24", "1636", "ds"),)
    found = _ports(beta=beta)
    assert [f.key for f in found.fixes] == ["ports:ds:8989:from-ds", "ports:ds:1636:from-web"]
    repl, ldaps = found.fixes
    assert repl.title == "Admit 10.1.1.0/24 (`ds`) to `ds` on tcp 8989 (replication) in a new rule `fw-ds-to-ds-8989`"
    assert (repl.records[0].changetype, repl.records[0].attrs["ciamSourceCidr"]) == ("add", ("10.1.1.0/24",))
    assert ldaps.records[0].mods == (("add", "ciamSourceCidr", ("10.1.2.0/24",)),)
    assert ldaps.manual == ("Apply beta/prod's rendered firewall rules (the platform's Terraform).",)
    fixed = _ports(beta=beta, changes=(*repl.records, *ldaps.records))
    assert fixed.blockers == () and fixed.fixes == ()


def test_no_ports_fix_in_the_source():
    assert _ports(alpha=(rule(ALPHA, "fw-ldaps", "192.0.2.0/24", "1636", "ds"),),
                  beta=(rule(BETA, "fw-all", ("10.1.1.0/24", "10.1.2.0/24"), ("1636", "8989"), "ds"),)).fixes == ()


RENAMED = tuple(parse(f"dn: cn=svc-sso,ou=bindings,{BETA}\nchangetype: modify\nreplace: ciamFqdn\n"
                      "ciamFqdn: sso.beta.test\n-\n"))


def test_the_contract_fix_binds_the_stable_name():
    assert _check_contracts(context(*model())).fixes == ()                 # same name in both: nothing to fix
    (fix,) = _check_contracts(context(*model(changes=RENAMED))).fixes
    assert (fix.key, fix.title) == ("contract:sso-service",
                                    "Bind the stable name `sso.example.test` for `sso-service` in beta/prod")
    assert [r.mods for r in fix.records] == [(("replace", "ciamFqdn", ("sso.example.test",)),)]
    assert fix.risks[0].startswith("Assumes beta/prod may use `sso.example.test`")
    assert _check_contracts(context(*model(changes=(*RENAMED, *fix.records)))).blockers == ()


def test_parity_fixes_for_private_dns_principals_and_flow_log_retention():
    def pe(env, dns):
        return entry(env, "pe", "ciamPrivateEndpoint", ciamBindingRole="pe", ciamPrivateService="secrets",
                     ciamPrivateDns=dns)

    def es(env, *principals):
        return entry(env, "es", "ciamEndpointService", ciamBindingRole="es", ciamServiceRole="sso-service",
                     ciamAllowedPrincipal=principals, ciamAcceptanceRequired="TRUE")

    def fl(env, days):
        return entry(env, "fl", "ciamFlowLog", ciamBindingRole="fl", ciamFlowScope="network", ciamRetentionDays=days)
    kw = dict(alpha=(pe(ALPHA, "TRUE"), es(ALPHA, "acct-a", "acct-b"), fl(ALPHA, "365")),
              beta=(pe(BETA, "FALSE"), es(BETA, "acct-b"), fl(BETA, "30")))
    d, alpha, beta = model(**kw)
    ctx = context(d, alpha, beta)
    fixes = [x for check in (check_private_endpoints, check_endpoint_services, check_flow_logs)
             for x in check(ctx).fixes]
    assert [f.key for f in fixes] == ["private-dns:pe", "endpoint-principals:es", "flow-log-retention:fl"]
    assert [r.mods for f in fixes for r in f.records] == [
        (("replace", "ciamPrivateDns", ("TRUE",)),), (("add", "ciamAllowedPrincipal", ("acct-a",)),),
        (("replace", "ciamRetentionDays", ("365",)),)]
    assert check_endpoint_services(context(d, alpha, beta._replace(provider="othercloud"))).fixes == ()   # no
    d, alpha, beta = model(changes=tuple(r for f in fixes for r in f.records), **kw)
    ctx = context(d, alpha, beta)
    assert all(check(ctx).fixes == () and check(ctx).actions == ()
               for check in (check_private_endpoints, check_flow_logs))
    assert check_endpoint_services(ctx).fixes == ()

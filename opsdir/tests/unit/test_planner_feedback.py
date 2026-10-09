"""The planner never passes silently: a check that fails becomes a blocker naming it, and data a check needs but
doesn't find (an optional attribute left out) is a finding with an owner, never a skipped check or a crash."""
from types import SimpleNamespace as NS

from opsdir.connectors.plan import run_check
from opsdir.core.directory import make_directory, make_entry
from opsdir.core.findings import findings
from opsdir.domains.federation.checks import check_identity_services
from opsdir.domains.infrastructure.checks import check_allowlists, check_versions

ENV = "env=prod,cloud=x,ou=environments,dc=ciam-ops"


def entry(dn, oc, **attrs):
    return make_entry(dn, ("top", oc), {k: (v,) for k, v in attrs.items()})


def env(label, servers=(), bindings=()):
    return NS(label=label, env=entry(ENV, "ciamEnvironment", env="prod"), servers=tuple(servers),
              bindings=tuple(bindings), d=make_directory((), {}, ()))


def ctx(d=None, src=None, dst=None):
    return NS(d=d or make_directory((), {}, ()), src=src or env("x/prod"), dst=dst or env("y/prod"))


def server(name, version=None):
    return entry(f"cn={name},{ENV}", "ciamServer", cn=name,
                 **({"ciamProductVersion": version} if version else {}))


def failing(c):
    raise KeyError("ciamSomething")


def test_a_check_that_fails_is_a_blocker_that_names_it():
    f = run_check(failing, ctx())
    (area, text, owner), = f.blockers
    assert area == "Planner" and owner == "**NO OWNER**"
    assert text.startswith(f"Check `{__name__}.failing` could not run (KeyError: 'ciamSomething').")


def test_a_check_that_runs_is_passed_through():
    assert run_check(lambda c: findings(ok=["fine"]), ctx()).ok == ("fine",)


def test_servers_without_a_product_version_are_named():
    f = check_versions(ctx(src=env("x/prod", [server("ds-1", "DS 7"), server("ds-2")]),
                           dst=env("y/prod", [server("ds-1", "DS 7")])))
    assert [t for _, t, _, _ in f.actions] == [
        "No product version recorded for x/prod ds-2: whether the move is a re-host or an upgrade can't be told "
        "for them."]
    assert f.ok == ("Same product versions in both environments (DS 7): a re-host, not an upgrade.",)


def test_no_servers_anywhere_is_said_not_passed_as_same_versions():
    assert check_versions(ctx()).ok == ("No servers recorded in either environment: no product versions to compare.",)


def _allowlisting(binding):
    xa = entry("cn=partner-fw,ou=external-allowlists,dc=ciam-ops", "ciamExternalAllowlist", cn="partner-fw",
               ciamRefersToRole="sso-service", ciamManagedBy="cn=partner,ou=owners,dc=ciam-ops",
               ciamRecordedCidr="203.0.113.10/32", ciamAllowlistDirection="partner-ingress")
    party = entry("cn=partner,ou=owners,dc=ciam-ops", "ciamParty", cn="partner")
    d = make_directory((), {}, ((e.dn, e.classes, e.attrs) for e in (xa, party)))
    return check_allowlists(ctx(d, dst=env("y/prod", bindings=[binding])))


def test_an_allowlisted_role_bound_without_an_address_is_a_blocker_not_unbound():
    svc = entry(f"cn=svc-sso,ou=bindings,{ENV}", "ciamServiceName", cn="svc-sso", ciamBindingRole="sso-service",
                ciamFqdn="sso.example.test", ciamPort="443", ciamTargetRole="web")
    (_, text, _), = _allowlisting(svc).blockers
    assert text == ("`partner-fw` refers to role `sso-service`: y/prod binds it (`svc-sso`) but records no address "
                    "for it (ciamFrontendIp or ciamCidr), so what partner must allow is unknown.")


def _identity(**attrs):
    s = entry("cn=sso,ou=identity-services,dc=ciam-ops", "ciamIdentityService", cn="sso", **attrs)
    return check_identity_services(ctx(make_directory((), {}, ((s.dn, s.classes, s.attrs),))))


def test_an_identity_service_without_a_server_role_is_an_action():
    (_, text, _, _), = _identity(ciamBaseUrl="https://sso.example.test").actions
    assert text.startswith("`sso` names no server role (ciamTargetRole), so whether y/prod keeps its published "
                           "address (sso.example.test) can't be checked.")


def test_an_identity_service_with_no_url_host_says_so():
    assert _identity(ciamBaseUrl="urn:example:sso", ciamTargetRole="web").ok == (
        "Identity service `sso` publishes no http(s) URL host: no address to keep.",)

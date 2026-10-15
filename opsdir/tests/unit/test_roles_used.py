"""The binding roles the record's entries use in an environment (Domain roles_used), for the keys report: canaries
checked there, external services reached from roles it runs, jobs that apply there, its appliances' logins, its
collection sources' credentials, its streams' send secrets and its databases' credentials."""
from opsdir.connectors.registry import DOMAINS, roles_used
from opsdir.core.environment import env_model
from opsdir.core.interchange.ldif import parse
import mini_estate

ALPHA = "env=prod,cloud=alpha,ou=environments,dc=ciam-ops"
BETA = "env=prod,cloud=beta,ou=environments,dc=ciam-ops"


def _ou(name):
    return (f"dn: ou={name},dc=ciam-ops\nchangetype: add\nobjectClass: top\nobjectClass: organizationalUnit\n"
            f"ou: {name}\n")


def _entry(dn, oc, **attrs):
    lines = "".join(f"{k}: {v}\n" for k, vs in attrs.items() for v in ((vs,) if isinstance(vs, str) else vs))
    return f"dn: {dn}\nchangetype: add\nobjectClass: top\nobjectClass: {oc}\n{lines}"


RECORDS = tuple(parse("\n".join((
    _ou("canaries"), _ou("external-services"), _ou("jobs"),
    _entry("cn=sso-login,ou=canaries,dc=ciam-ops", "ciamCanary", cn="sso-login", ciamCheckedService="sso-service",
           ciamCanaryFlow="oidc-token", ciamUsesRole="canary-client"),
    _entry("cn=elsewhere,ou=canaries,dc=ciam-ops", "ciamCanary", cn="elsewhere", ciamCheckedService="no-such-service",
           ciamCanaryFlow="oidc-token", ciamUsesRole="unused-secret"),
    _entry("cn=captcha,ou=external-services,dc=ciam-ops", "ciamExternalService", cn="captcha",
           ciamServiceKind="captcha", ciamUsesRole="captcha-secret"),
    _entry("cn=nightly,ou=jobs,dc=ciam-ops", "ciamJob", cn="nightly", ciamJobKind="cron", ciamUsesRole="job-secret",
           ciamInEnvironment=ALPHA),
    _entry(f"cn=bigip,ou=bindings,{ALPHA}", "ciamAppliance", cn="bigip", ciamBindingRole="bigip",
           ciamStackRole="load-balancer", ciamManagementAddress="10.0.0.5", ciamLoginSecretRole="bigip-login"),
    _entry(f"cn=pf-admin,ou=bindings,{ALPHA}", "ciamCollectionSource", cn="pf-admin", ciamBindingRole="pf-admin",
           ciamImporter="pingfederate/bulk", ciamCredentialRole="pf-admin-login"),
    _entry(f"cn=audit-bus,ou=bindings,{ALPHA}", "ciamStreamBinding", cn="audit-bus", ciamBindingRole="audit-bus",
           ciamProviderRef="hub-1", ciamSendSecretRole="hub-send"),
    _entry(f"cn=db,ou=bindings,{ALPHA}", "ciamDatabase", cn="db", ciamBindingRole="db", ciamDbEngine="postgresql",
           ciamDbCredentialRole="db-password")))))


def test_the_roles_the_entries_an_environment_runs_use():
    d = mini_estate.directory(RECORDS)
    assert roles_used(env_model(d, "alpha/prod"), ()) == {
        "bigip-login": ("appliance `bigip`",), "pf-admin-login": ("collection source `pf-admin`",),
        "job-secret": ("job `nightly`",), "captcha-secret": ("external service `captcha`",),
        "hub-send": ("stream `audit-bus`",), "canary-client": ("canary `sso-login`",),
        "db-password": ("database `db`",)}
    beta = roles_used(env_model(d, "beta/prod"), ())
    assert "job-secret" not in beta and "bigip-login" not in beta and "unused-secret" not in beta
    assert {d_.name for d_ in DOMAINS if d_.roles_used} >= {"observability", "messaging", "data", "governance",
                                                             "infrastructure", "automation"}

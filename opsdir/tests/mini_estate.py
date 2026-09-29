"""A minimal estate and a fake provider adapter, so the core is tested without any real adapter or the showcase.

Two environments on the made-up provider `fakecloud`: alpha binds a network and disk encryption; beta binds only a
network, so moving alpha -> beta is blocked and beta -> alpha is ready. Both declare the fake adapter in their stack
and put the same service name in front of the identity service's `web` servers.
"""
from opsdir.core.contract import Adapter
from opsdir.core.findings import findings
from opsdir.core.standard import AttributeDef, ClassDef, fragment
from opsdir.core.interchange.ldif import parse
from support import REGISTRY, build_directory

PROVIDER = "fakecloud"
ADAPTER_NAME = "fake-cloud"
VERSIONS = {ADAPTER_NAME: "0.5"}
FAKE_ARC = "1.3.6.1.4.1.32473.99"       # the fake adapter's own OID arc
# What the fake adapter adds to the schema: a tier any entry may carry through an auxiliary class.
FAKE_SCHEMA = fragment((AttributeDef(1, "fakeTier", "enum:gold|silver", "binding", True, "Service tier"),),
                       (ClassDef(1, "fakeTiered", "top", "AUXILIARY", (), ("fakeTier",), "Carries a service tier"),),
                       FAKE_ARC, ADAPTER_NAME)


def _environment(cloud, disk_encryption):
    env = f"env=prod,cloud={cloud},ou=environments,dc=ciam-ops"
    key = (f"\n\ndn: cn=key-disk,ou=bindings,{env}\nobjectClass: top\nobjectClass: ciamKeyRef\ncn: key-disk\n"
           f"ciamBindingRole: disk-encryption\nciamRefUri: fake://keys/{cloud}") if disk_encryption else ""
    return f"""dn: cloud={cloud},ou=environments,dc=ciam-ops
objectClass: top
objectClass: ciamCloud
cloud: {cloud}
ciamCloudProvider: {PROVIDER}
ciamRegion: region-1

dn: {env}
objectClass: top
objectClass: ciamEnvironment
env: prod

dn: ou=bindings,{env}
objectClass: top
objectClass: organizationalUnit
ou: bindings

dn: cn=net,ou=bindings,{env}
objectClass: top
objectClass: ciamNetwork
cn: net
ciamBindingRole: network
ciamCidr: 10.1.0.0/16{key}

dn: cn=svc-sso,ou=bindings,{env}
objectClass: top
objectClass: ciamServiceName
cn: svc-sso
ciamBindingRole: sso-service
ciamFqdn: sso.example.test
ciamPort: 443
ciamTargetRole: web

dn: ou=stack,{env}
objectClass: top
objectClass: organizationalUnit
ou: stack

dn: cn=provider,ou=stack,{env}
objectClass: top
objectClass: ciamStackComponent
cn: provider
ciamStackRole: provider
ciamAdapter: {ADAPTER_NAME}
ciamAdapterVersion: >=0.1,<1
ciamAdapterSource: https://example.test/{ADAPTER_NAME}
"""


LDIF = f"""dn: dc=ciam-ops
objectClass: top
objectClass: domain
dc: ciam-ops

dn: ou=environments,dc=ciam-ops
objectClass: top
objectClass: organizationalUnit
ou: environments

dn: ou=identity-services,dc=ciam-ops
objectClass: top
objectClass: organizationalUnit
ou: identity-services

dn: cn=sso,ou=identity-services,dc=ciam-ops
objectClass: top
objectClass: ciamIdentityService
cn: sso
ciamBaseUrl: https://sso.example.test
ciamEntityId: urn:example:sso
ciamOidcIssuer: https://SSO.example.test/oauth2
ciamTargetRole: web

{_environment("alpha", disk_encryption=True)}
{_environment("beta", disk_encryption=False)}"""


def directory(change_records=()):
    """The mini estate as a Directory, after change records."""
    return build_directory(REGISTRY, parse(LDIF), change_records)


# ------------------------------------------------------------------ the fake provider adapter
def _applies(m):
    return m.provider == PROVIDER


def _render_neutral(d):
    return {"fake/neutral.txt": "the same in every environment\n"}


def _render_env(m, services):
    return {"fake/env.txt": f"{m.label}: {services.secret_command('fake://secrets/admin')}\n"}


def _check(ctx):
    return findings(ok=[f"fake check ran for {ctx.dst.label}"])


def _resolve(rest):
    return f"fake-cli get {rest}"


FAKE = Adapter(name=ADAPTER_NAME, kind="provider", applies=_applies, required_roles=(),
               render_neutral=_render_neutral, render_env=_render_env, checks=(_check,), ref_schemes=("fake",),
               secret_schemes={"fake": _resolve}, renders="fake files", neutral_label="Fake",
               vocabulary={"ciamCloudProvider": (PROVIDER,)}, schema=FAKE_SCHEMA,
               formats=(("fake/*.txt", "text"),), products=(), secret_patterns=())

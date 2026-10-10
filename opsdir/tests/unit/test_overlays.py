"""Environment overlays and overrides (in memory, on the mini estate): alpha/stage is an overlay of alpha/prod. It
inherits prod's bindings, stack, declared roles and overrides except what it has or drops itself; never its servers.
Overrides change what an environment sees of a shared entry and nothing else."""
import pytest

from opsdir.core.directory import get, one
from opsdir.core.environment import env_model, inherited_from, with_required_roles
from opsdir.core.interchange.ldif import parse
from opsdir.core.overlays import apply_overrides, overridden_in
from opsdir.domains.observability.realized import keeper_of
import mini_estate

PROD = "env=prod,cloud=alpha,ou=environments,dc=ciam-ops"
STAGE = "env=stage,cloud=alpha,ou=environments,dc=ciam-ops"
SSO = "cn=sso,ou=identity-services,dc=ciam-ops"


def add(dn, *classes, **attrs):
    lines = "".join(f"{k}: {v}\n" for k, vals in attrs.items() for v in (vals if isinstance(vals, tuple) else (vals,)))
    return f"dn: {dn}\nchangetype: add\nobjectClass: top\n" + "".join(f"objectClass: {c}\n" for c in classes) + lines


def ou(name, parent):
    return add(f"ou={name},{parent}", "organizationalUnit", ou=name)


def override(env, cn, attr, value, target=SSO):
    return add(f"cn={cn},ou=overrides,{env}", "ciamOverride", cn=cn, ciamOverrides=target,
               ciamOverrideAttribute=attr, ciamOverrideValue=value)


def estate(*records, **stage):
    """The mini estate with alpha/stage, an overlay of alpha/prod (its own attributes in `stage`)."""
    base = (add(STAGE, "ciamEnvironment", env="stage", ciamOverlayOf=PROD, **stage), ou("bindings", STAGE),
            ou("stack", STAGE), ou("overrides", STAGE), ou("overrides", PROD))
    return mini_estate.directory(tuple(parse("\n".join((*base, *records)))))


def roles(m):
    return [(one(b, "ciamBindingRole"), b.dn.split(",", 3)[2]) for b in m.bindings]


def test_an_overlay_inherits_its_bases_bindings_and_stack():
    m = env_model(estate(), "alpha/stage")
    assert roles(m) == [("disk-encryption", "env=prod"), ("network", "env=prod"), ("sso-service", "env=prod")]
    assert [c.adapter for c in m.stack] == [mini_estate.ADAPTER_NAME]
    assert [e.dn for e in m.lineage] == [STAGE, PROD] and m.servers == ()


def test_its_own_binding_replaces_the_bases_for_that_role_and_dropped_roles_are_not_inherited():
    own = add(f"cn=svc-sso,ou=bindings,{STAGE}", "ciamServiceName", cn="svc-sso", ciamBindingRole="sso-service",
              ciamFqdn="sso-stage.example.test", ciamPort="443", ciamTargetRole="web")
    m = env_model(estate(own, ciamDropsRole="disk-encryption"), "alpha/stage")
    assert roles(m) == [("sso-service", "env=stage"), ("network", "env=prod")]


def test_declared_required_roles_are_inherited_and_count_as_unbound_until_bound():
    required = add(f"cn=backup-target,ou=stack,{PROD}", "ciamRequiredRole", cn="backup-target",
                   ciamBindingRole="backup-target", description="Every environment keeps backups")
    m = env_model(estate(required), "alpha/stage", ("network",))
    assert m.declared_roles == ("backup-target",) and m.unbound == ("backup-target",)
    assert with_required_roles(m, ("network", "web-tier")).unbound == ("web-tier", "backup-target")


def test_overrides_apply_to_what_the_environment_sees_and_the_nearest_one_wins():
    d = estate(override(PROD, "tier", "description", "prod value"), override(STAGE, "tier", "description", "stage"),
               override(PROD, "role", "ciamTargetRole", "api"))
    stage, prod = env_model(d, "alpha/stage"), env_model(d, "alpha/prod")
    assert [overridden_in(o) for o in stage.overrides] == ["alpha/stage", "alpha/prod"]
    seen = apply_overrides(d, stage.overrides)
    assert (one(get(seen, SSO), "description"), one(get(seen, SSO), "ciamTargetRole")) == ("stage", "api")
    assert one(get(apply_overrides(d, prod.overrides), SSO), "description") == "prod value"
    assert one(get(d, SSO), "description") is None                  # the shared entry itself is unchanged


def test_an_overlay_cycle_is_refused():
    loop = f"dn: {PROD}\nchangetype: modify\nadd: ciamOverlayOf\nciamOverlayOf: {STAGE}\n-\n"
    with pytest.raises(SystemExit, match="overlay cycle"):
        env_model(estate(loop), "alpha/stage")


def test_an_overlay_of_something_else_or_of_another_provider_is_refused():
    with pytest.raises(SystemExit, match="which is not an environment"):
        env_model(_overlay_of(SSO), "alpha/stage")
    other = ("dn: cloud=beta,ou=environments,dc=ciam-ops\nchangetype: modify\nreplace: ciamCloudProvider\n"
             "ciamCloudProvider: othercloud\n-\n")
    with pytest.raises(SystemExit, match="bindings can't be shared across providers"):
        env_model(_overlay_of("env=prod,cloud=beta,ou=environments,dc=ciam-ops", other), "alpha/stage")


def _overlay_of(base, *records):
    return mini_estate.directory(tuple(parse("\n".join((
        add(STAGE, "ciamEnvironment", env="stage", ciamOverlayOf=base), *records)))))


def test_what_an_overlay_inherits_is_its_bases_to_render():
    own = add(f"cn=svc-sso,ou=bindings,{STAGE}", "ciamServiceName", cn="svc-sso", ciamBindingRole="sso-service",
              ciamFqdn="sso-stage.example.test", ciamPort="443", ciamTargetRole="web")
    m = env_model(estate(own), "alpha/stage")
    by_role = {one(b, "ciamBindingRole"): b for b in m.bindings}
    assert inherited_from(m, by_role["network"]) == "alpha/prod" and inherited_from(m, by_role["sso-service"]) is None
    assert keeper_of(m, by_role["network"]) == "alpha/prod (this environment inherits it)"
    assert keeper_of(m, by_role["sso-service"]) is None and keeper_of(m, None) is None
    assert keeper_of(env_model(estate(own), "alpha/prod"), by_role["network"]) is None

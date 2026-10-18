"""Entries declaring where the platform runs: a cloud (provider, region, partition, account), an environment in it, and
the environment's declared stack (ou=stack: one ciamStackComponent per role, the adapter and the versions it accepts).
What guided onboarding writes from its answers; the store checks them like any entry. Pure."""
from ...core.directory import make_entry
from .naming import ENVIRONMENTS


def cloud_dn(cloud):
    return f"cloud={cloud},{ENVIRONMENTS}"


def environment_dn(cloud, env):
    return f"env={env},{cloud_dn(cloud)}"


def cloud_entry(cloud, provider, region, partition=None, account=None, lifecycle=None):
    """A cloud's entry: its provider and region, the provider's partition (public, usgovernment, ...) and its account
    (an AWS account, Azure subscription, Google Cloud project: ciamCloudAccount) when given."""
    return make_entry(cloud_dn(cloud), ("top", "ciamCloud", *(("ciamCloudAccount",) if account else ())), {
        "cloud": (cloud,), "ciamCloudProvider": (provider,), "ciamRegion": (region,),
        **({"ciamCloudEnvironment": (partition,)} if partition else {}),
        **({"ciamAccountRef": (account,)} if account else {}),
        **({"ciamLifecycle": (lifecycle,)} if lifecycle else {})})


def environment_entry(cloud, env, lifecycle=None):
    """An environment's entry in its cloud, with its lifecycle (active, building, retiring, retired) when given."""
    return make_entry(environment_dn(cloud, env), ("top", "ciamEnvironment"),
                      {"env": (env,), **({"ciamLifecycle": (lifecycle,)} if lifecycle else {})})


def stack_entries(cloud, env, components):
    """The environment's ou=stack and one ciamStackComponent per (role, adapter, versions) (versions: a PEP 440 range,
    or None for any)."""
    base = f"ou=stack,{environment_dn(cloud, env)}"

    def component(role, adapter, versions):
        return make_entry(f"cn={role},{base}", ("top", "ciamStackComponent"), {
            "cn": (role,), "ciamStackRole": (role,), "ciamAdapter": (adapter,),
            **({"ciamAdapterVersion": (versions,)} if versions else {})})
    return (make_entry(base, ("top", "organizationalUnit"), {"ou": ("stack",)}), *(component(*c) for c in components))

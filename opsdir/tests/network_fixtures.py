"""Two environments of the mini estate with servers in subnets (ds-1, ds-2 in subnet-ds; web-1 in subnet-web; all in
zone-a), for
the network domain's tests: each test adds the bindings it is about (as LDIF records) to alpha, beta or the tree."""
import datetime as dt
from types import SimpleNamespace

from opsdir.core.environment import env_model
from opsdir.core.interchange.ldif import parse
import mini_estate
from support import REGISTRY, build_directory

ALPHA = "env=prod,cloud=alpha,ou=environments,dc=ciam-ops"
BETA = "env=prod,cloud=beta,ou=environments,dc=ciam-ops"


def entry(parent, cn, oc, **attrs):
    """An LDIF record cn=<cn> under parent (an environment's ou=bindings, unless a server or given a full parent)."""
    lines = "".join(f"{k}: {v}\n" for k, vs in attrs.items() for v in (vs if isinstance(vs, tuple) else (vs,)))
    where = parent if oc == "ciamServer" or not parent.startswith("env=") else f"ou=bindings,{parent}"
    return f"dn: cn={cn},{where}\nobjectClass: top\nobjectClass: {oc}\ncn: {cn}\n{lines}"


def rule(env, cn, cidrs, port, target):
    return entry(env, cn, "ciamFirewallRule", ciamBindingRole=cn, ciamSourceCidr=cidrs, ciamPort=port,
                 ciamTargetRole=target)


def _estate(env, extra):
    return (entry(env, "subnet-ds", "ciamSubnetBinding", ciamBindingRole="subnet-ds", ciamCidr="10.1.1.0/24"),
            entry(env, "subnet-web", "ciamSubnetBinding", ciamBindingRole="subnet-web", ciamCidr="10.1.2.0/24"),
            *(entry(env, n, "ciamServer", ciamServerRole=r, ciamHostname=f"{n}.example.test",
                    ciamSubnet=f"cn={s},ou=bindings,{env}", ciamZone="zone-a")
              for n, r, s in (("ds-1", "ds", "subnet-ds"), ("ds-2", "ds", "subnet-ds"),
                              ("web-1", "web", "subnet-web"))),
            *extra)


def model(alpha=(), beta=(), tree=(), changes=()):
    """(directory, alpha model, beta model) with the given records added, then the change records applied."""
    d = build_directory(REGISTRY, tuple(parse("\n".join((mini_estate.LDIF, *tree, *_estate(ALPHA, alpha),
                                                         *_estate(BETA, beta))))), tuple(changes))
    return d, env_model(d, "alpha/prod"), env_model(d, "beta/prod")


def context(d, src, dst, cutover=None):
    return SimpleNamespace(d=d, src=src, dst=dst, cutover=cutover, as_of=dt.date(2026, 10, 1))

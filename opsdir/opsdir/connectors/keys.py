"""The `keys` report against what each environment must bind: where it keeps every key and secret
(domains/pki/reports), a credential it doesn't bind being UNBOUND when its domains, the installed adapters that apply
to it or its own declarations require the role (what the planner blocks on), or when an entry it runs uses the role
(the domains' and applying adapters' roles_used: a connector's credential, which the package's own planner check
blocks on), else not used there, naming the installed products that require or would use it."""
from ..core.contract import directory_report
from ..domains.pki.reports import KEYS_HEADERS, Uses, placement_rows
from .registry import ADAPTERS, environment, product_of, roles_used, used_elsewhere


def required_elsewhere(installed, applying):
    """{role: (product, ...)}: the roles the installed adapters that don't apply to an environment require."""
    others = tuple(a for a in installed if a.name not in {x.name for x in applying})
    return {r: tuple(dict.fromkeys(product_of(a) for a in others if r in a.required_roles))
            for a in others for r in a.required_roles}


def keys_report(installed=ADAPTERS):
    """The `keys` report (an environment's DN): where it keeps every credential, resolved with the installed
    adapters."""
    def rows(d, dn, as_of=None):
        m, adapters = environment(d, dn, installed)
        return placement_rows(m, as_of, Uses(required_elsewhere(installed, adapters), roles_used(m, adapters),
                                             used_elsewhere(m, installed, adapters)))
    return directory_report(KEYS_HEADERS, rows, needs_dn=True, dated=True)

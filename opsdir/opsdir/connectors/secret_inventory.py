"""Secret-store inventories against the record's references, with the installed adapters' locators (each secret-store
adapter says where in its store's inventory a reference of its scheme points: Adapter.inventory_locator): the planner
check on the target and the `secret-inventory` report (domains/pki/inventory). A connector: the reconciliation is the
pki domain's; here it only gets the locators. Pure."""
from ..core.contract import directory_report
from ..domains.pki.inventory import INVENTORY_HEADERS, inventory_findings, inventory_rows
from .registry import ADAPTERS


def inventory_locators(installed=ADAPTERS):
    """{scheme: locate} of the installed adapters' inventory locators (an adapter's own scheme, first one wins)."""
    return {s: f for a in reversed(installed) for s, f in (a.inventory_locator or {}).items()}


def secret_inventory_check(installed=ADAPTERS):
    """The planner check reconciling the target's secret references with the inventories the record holds."""
    locators = inventory_locators(installed)

    def check_secret_inventory(ctx):
        return inventory_findings(ctx, locators)
    return check_secret_inventory


def secret_inventory_report(installed=ADAPTERS):
    """The `secret-inventory` report: every placed secret reference's state against its store's inventory, and the
    objects nothing references."""
    locators = inventory_locators(installed)
    return directory_report(INVENTORY_HEADERS, lambda d, dn, as_of: inventory_rows(d, locators, as_of), dated=True)

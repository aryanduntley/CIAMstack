"""Data discovery on Azure as Defender for Cloud's sensitive data discovery: the SensitiveDataDiscovery extension on
the Defender CSPM plan, merged with a posture service's CloudPosture pricing; what Microsoft decides (stores examined,
cadence, own data types in Purview, results, findings) in comments; Azure Government a comment; read back from state."""
from opsdir.core.directory import make_entry
from opsdir_adapter_azure.discovery import discovery_plans, discovery_resources, render_discovery
from opsdir_adapter_azure.security import render_security
from network_fixtures import ALPHA, entry, model

STORES = (entry(ALPHA, "backups", "ciamObjectStore", ciamBindingRole="ds-backups",
                ciamStorageRef="https://eabackups.blob.core.windows.net/backups"),
          entry(ALPHA, "grants", "ciamDatabase", ciamBindingRole="pf-grants-db", ciamDbEngine="postgresql"),
          entry(ALPHA, "audit-sql", "ciamDatabase", ciamBindingRole="audit-db", ciamDbEngine="sqlserver"))


def dspm(days="7", **more):
    return entry(ALPHA, "dspm", "ciamDataDiscovery", ciamBindingRole="data-discovery",
                 ciamScansRole=("ds-backups", "pf-grants-db", "audit-db"),
                 ciamCustomIdentifier=("cui-marking: CUI//[A-Z-]+",), ciamRescanDays=days, **more)


def _alpha(*bindings, gov=False):
    _, alpha, _ = model(alpha=(*STORES, *bindings))
    return alpha._replace(cloud=make_entry(alpha.cloud.dn, alpha.cloud.classes,
                                           {**alpha.cloud.attrs, "ciamCloudEnvironment": ("usgovernment",)})) \
        if gov else alpha


def test_the_extension_is_merged_into_the_cspm_plan():
    alpha = _alpha(dspm(), entry(ALPHA, "cspm", "ciamSecurityService", ciamBindingRole="cspm",
                                 ciamSecurityKind="posture"))
    out = "\n\n".join(render_security(alpha, discovery_plans(alpha)))
    assert out.count('resource_type = "CloudPosture"') == 1 and 'name = "SensitiveDataDiscovery"' in out
    alone = _alpha(dspm())
    assert 'name = "SensitiveDataDiscovery"' in "\n".join(render_security(alone, discovery_plans(alone)))
    assert discovery_plans(_alpha()) == ()


def test_what_microsoft_decides_is_said_in_comments():
    out = "\n".join(render_discovery(_alpha(dspm(days="1", ciamFindingsRole="security-logs",
                                                 ciamResultsRole="ds-backups"))))
    assert ("# dspm: Defender for Cloud's sensitive data discovery (Defender CSPM, SensitiveDataDiscovery) examines "
            "every block blob") in out
    assert "# dspm: pf-grants-db: not a store it examines" in out                # PostgreSQL; SQL Database is
    assert "# dspm: it refreshes object storage within eight days of a change and databases weekly; the record asks " \
           "every 1 days" in out
    assert "# dspm: its own data types (cui-marking: CUI//[A-Z-]+) are Microsoft Purview custom sensitive " \
           "information types" in out
    assert "they reach security-logs through the security services' continuous export" in out
    assert "# dspm: Defender keeps its results itself: ds-backups isn't written to" in out
    assert "Azure Government" not in out and "refreshes" not in "\n".join(render_discovery(_alpha(dspm())))


def test_azure_government_and_someone_elses_discovery_are_comments():
    assert "# Azure Government: Defender for Cloud's support matrix lists Defender CSPM's sensitive data scanning" \
        in "\n".join(render_discovery(_alpha(dspm(), gov=True)))
    held = entry(ALPHA, "org", "ciamDataDiscovery", ciamBindingRole="data-discovery",
                 ciamManagedBy="cn=nobody,dc=ciam-ops")
    assert render_discovery(_alpha(held)) == ("# Data discovery org: kept by cn=nobody,dc=ciam-ops, not rendered here",)


def test_read_back_from_state():
    sub = "/subscriptions/00000000-0000-0000-0000-000000000000"
    pairs = [("azurerm_security_center_subscription_pricing", {
                 "id": f"{sub}/providers/Microsoft.Security/pricings/CloudPosture", "tier": "Standard",
                 "resource_type": "CloudPosture", "extension": [{"name": "SensitiveDataDiscovery"}]}),
             ("azurerm_security_center_subscription_pricing", {
                 "id": f"{sub}/providers/Microsoft.Security/pricings/Arm", "tier": "Standard", "resource_type": "Arm"})]
    (r,) = discovery_resources(pairs)
    assert (r.kind, r.ref, r.name) == ("discovery", f"{sub}/providers/Microsoft.Security/pricings/CloudPosture/"
                                                    "SensitiveDataDiscovery", "defender-sensitive-data")
    assert discovery_resources(pairs[1:]) == ()

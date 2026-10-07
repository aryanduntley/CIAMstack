"""An environment's guardrails as Azure Policy: each neutral denial (ciamDenies) as an assignment of a built-in policy
definition to the subscription, by the definition's ID (display names aren't unique). Pure.

Definitions from the Azure/azure-policy repository (checked 2026-10-02, note 457). audit-log-disable has no built-in:
the nearest, "Do not allow deletion of resource types" on diagnostic settings, blocks deleting them, not changing
them (said in a comment). Not applicable on Azure, and NOTEs: service-account-keys (service principal secrets belong to
Entra ID), metadata-v1, root-use. region-escape (allowed locations) allows the regions the environment may hold
resources in (estate.residency.permitted_regions: its cloud's region and those its residency allows).
"""
from opsdir.core.directory import rdn_value, values
from opsdir.core.environment import of_class
from opsdir.domains.access.naming import DENIALS
from opsdir.domains.estate.residency import permitted_regions
from opsdir_format_terraform.hcl import block, jsonencoded, ref, tf_name

DEFINITIONS = "/providers/Microsoft.Authorization/policyDefinitions/"
DENY = {"effect": {"value": "Deny"}}
NOT_APPLICABLE = {"service-account-keys": "service principal secrets belong to Entra ID, not Azure Policy",
                  "metadata-v1": "Azure's instance metadata has no v1/v2 split", "root-use": "Azure has no root user"}


def _assignment(denial, regions):
    """(definition ID, parameters, comment) assigning the built-in that prevents a neutral denial (regions: those
    region-escape allows), or None."""
    return {
        "region-escape": ("e56962a6-4747-49cd-b67b-bf8b01975c4c", {"listOfAllowedLocations": {"value": list(regions)}},
                          None),
        "public-storage": ("4fa4b6c0-31ca-4c0d-b10d-24b96f62a751", DENY, None),
        "key-deletion": ("0b60c0b2-2dc2-4e1c-b5c9-abbed971de53", DENY, None),
        "audit-log-disable": ("78460a36-508a-49a4-b2b2-2f5ec564f4bb", {"listOfResourceTypesDisallowedForDeletion": {
            "value": ["Microsoft.Insights/diagnosticSettings"]}},
            "blocks deleting diagnostic settings, not changing them: Azure has no built-in for that"),
    }.get(denial)


def denial_of(definition_id):
    """What a policy assignment prevents, by its built-in definition's ID (read back on import), or None."""
    guid = (definition_id or "").rsplit("/", 1)[-1].lower()
    return next((d for d in DENIALS if (_assignment(d, ()) or (None,))[0] == guid), None)


def render_guardrails(m):
    """HCL for environment m's guardrails: an assignment per denial; a NOTE for what Azure has no policy for."""
    def one_denial(g, d):
        found = _assignment(d, permitted_regions(m))
        if found is None:
            return (f"# NOTE: guardrail {rdn_value(g)}: {d}: {NOT_APPLICABLE.get(d, 'Azure has no built-in for it')}",)
        definition, parameters, comment = found
        return (block("resource", ["azurerm_subscription_policy_assignment", tf_name(f"{rdn_value(g)}_{d}")], [
            *((("#", comment),) if comment else ()),
            ("name", f"ciam-{rdn_value(m.env)}-{d}"[:64]), ("policy_definition_id", f"{DEFINITIONS}{definition}"),
            ("subscription_id", ref("data.azurerm_subscription.current.id")),
            ("parameters", jsonencoded(parameters))]),)
    return tuple(x for g in of_class(m, "ciamGuardrail") for d in values(g, "ciamDenies") for x in one_denial(g, d))


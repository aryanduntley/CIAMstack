"""Azure landing zone: what the platform needs from the organization rather than its own Terraform, rendered for
whoever keeps the landing zone (terraform/landing-zone/; the MANIFEST marks it landing-zone, the header names the
owner).

  CI deployers     a user-assigned managed identity per deployer with a federated identity credential trusting its
                   pipeline's tokens (issuer and subject), and its role assignments
  operators        role assignments to the operator's Entra group at the narrowest scopes; eligible (Privileged
                   Identity Management, activated when needed) when the principal's condition says jit
  guardrails       policy assignments preventing what the environment's guardrails deny
  network          the plumbing its owner keeps (opsdir_adapter_azure.plumbing) in network.tf; plumbing another party
                   keeps (ciamManagedBy) goes in that party's own root, terraform/landing-zone/<party>/
Pure.
"""
from opsdir.core.directory import one, rdn_value
from opsdir.core.environment import one_role
from opsdir.core.manifest import header
from opsdir.domains.access.workloads import landing_identities, landing_zone_owner
from opsdir.domains.network.plumbing import LANDING_ZONE, NETWORK_FILE, keepers
from opsdir_format_terraform.format import FORMAT as HCL
from opsdir_format_terraform.hcl import Block, TfFile, distinct, mentions, ref, tf_block, tf_name
from .access import ACCESS
from .guardrails import render_guardrails
from .identities import RG, assignments, federated_credential, managed_identity, notes, role_of, scope, scope_data
from .plumbing import render_plumbing
from .account import provider_block, required_providers, subscription_variable
from .resource_providers import registration_note, resource_providers


def _deployer(m, w):
    """A deployer's managed identity, trusted only for its pipeline's tokens, and its role assignments."""
    n, (issuer, subject) = tf_name(w.identity_role), w.trust
    return (*notes(w), managed_identity(m, w),
            federated_credential(n, f"{w.name}-ci", n, issuer, subject),
            *assignments(w, ref(f"azurerm_user_assigned_identity.{n}.principal_id")))


def _eligible(w):
    """An operator group's eligible (PIM) assignments: activated when needed, for at most a year before renewal."""
    n = tf_name(w.identity_role)
    return tuple(x for permit, b, row in w.grants for role in (role_of(row, b),) for x in (
        tf_block("data", ["azurerm_role_definition", f"{n}_{tf_name(permit)}"], [
            ("name", role), ("scope", ref("data.azurerm_subscription.current.id"))]),
        tf_block("resource", ["azurerm_pim_eligible_role_assignment", f"{n}_{tf_name(permit)}"], [
            ("scope", scope(b)[0]), ("principal_id", w.group),
            ("role_definition_id", ref(f"data.azurerm_role_definition.{n}_{tf_name(permit)}.id")),
            ("justification", f"{w.principal}: {permit}"),
            ("schedule", Block((("expiration", Block((("duration_days", 365),))),)))])))


def _operator(m, w):
    return (*notes(w), *(_eligible(w) if "jit" in w.conditions else assignments(w, w.group)))


def _providers(m, variables, register=(), unknown=()):
    """providers.tf of a landing-zone root: the azurerm provider in the environment's subscription (registering the
    resource providers in register), and the root's inputs."""
    return TfFile(header(m, "Providers and inputs (landing zone)", HCL), (
        *registration_note((), unknown),
        required_providers(),
        provider_block(m, register),
        subscription_variable(m, described=True),
        *variables))


def _identities(m, guardrails):
    """(main.tf blocks, or () when environment m's landing zone grants no identities and no guardrails)."""
    deployers, operators = landing_identities(m, ACCESS)
    fences = tuple(guardrails(m))
    if not (deployers or operators or fences):
        return ()
    subscription = any("jit" in w.conditions for w in operators) or mentions(fences, "policy_assignment")
    return (tf_block("data", ["azurerm_resource_group", "main"], [
                ("name", one(one_role(m, "network"), "ciamResourceGroup"))]),
            *((tf_block("data", ["azurerm_subscription", "current"], []),) if subscription else ()),
            *scope_data(m, (*deployers, *operators), standalone=True),
            *(x for w in deployers for x in _deployer(m, w)), *(x for w in operators for x in _operator(m, w)),
            *fences)


def render_landing(m, guardrails=render_guardrails, plumbing=render_plumbing, platform=()):
    """{path: TfFile} of environment m's landing zone (identities, guardrails, the network plumbing its owner keeps)
    and of each other party's root keeping some of its plumbing, or {} when it needs nothing from anyone. A data
    source main.tf declares isn't declared again in the same root's network.tf. The landing zone's provider registers
    the resource providers every root's resources need: its own, the keepers' and the platform's (platform: the
    platform root's rendered items)."""
    out = _identities(m, guardrails)
    nets = tuple((k, plumbing(m, k)) for k in keepers(m))
    roots = dict.fromkeys((*((LANDING_ZONE,) if out else ()), *(k.folder for k, _ in nets)))
    what = (f"Azure landing zone for the CIAM platform, kept by {landing_zone_owner(m)}: applied by the landing zone, "
            "not by the platform's pipeline")
    main = {f"{LANDING_ZONE}/main.tf": TfFile(header(m, what, HCL), out)} if out else {}
    network = {f"{k.folder}/{NETWORK_FILE}": TfFile(header(
        m, f"Azure network kept by {k.name} for the CIAM platform: applied by them, not by the platform's pipeline",
        HCL), tuple(x for x in (*r.shared, *r.blocks) if k.folder != LANDING_ZONE or x not in out)) for k, r in nets}
    register, unknown = resource_providers((*platform, *(x for f in (*main.values(), *network.values())
                                                         for x in f.items)))
    providers = {f"{f}/providers.tf": _providers(m, distinct(tuple(
        v for k, r in nets if k.folder == f for v in r.variables)),
        *((register, unknown) if f == LANDING_ZONE else ())) for f in roots}
    return {**providers, **main, **network}

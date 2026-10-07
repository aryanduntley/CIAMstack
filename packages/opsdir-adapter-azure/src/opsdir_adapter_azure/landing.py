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
from opsdir_format_terraform.hcl import Block, block, ref, tf_name
from .access import ACCESS
from .guardrails import render_guardrails
from .identities import RG, assignments, managed_identity, notes, role_of, scope, scope_data
from .plumbing import render_plumbing
from .account import subscription_variable

AUDIENCE = "api://AzureADTokenExchange"


def _deployer(m, w):
    """A deployer's managed identity, trusted only for its pipeline's tokens, and its role assignments."""
    n, (issuer, subject) = tf_name(w.identity_role), w.trust
    return (*notes(w), managed_identity(m, w),
            block("resource", ["azurerm_federated_identity_credential", n], [
                ("name", f"{w.name}-ci"), ("resource_group_name", RG),
                ("parent_id", ref(f"azurerm_user_assigned_identity.{n}.id")), ("audience", [AUDIENCE]),
                ("issuer", issuer), ("subject", subject)]),
            *assignments(w, ref(f"azurerm_user_assigned_identity.{n}.principal_id")))


def _eligible(w):
    """An operator group's eligible (PIM) assignments: activated when needed, for at most a year before renewal."""
    n = tf_name(w.identity_role)
    return tuple(x for permit, b, row in w.grants for role in (role_of(row, b),) for x in (
        block("data", ["azurerm_role_definition", f"{n}_{tf_name(permit)}"], [
            ("name", role), ("scope", ref("data.azurerm_subscription.current.id"))]),
        block("resource", ["azurerm_pim_eligible_role_assignment", f"{n}_{tf_name(permit)}"], [
            ("scope", scope(b)[0]), ("principal_id", w.group),
            ("role_definition_id", ref(f"data.azurerm_role_definition.{n}_{tf_name(permit)}.id")),
            ("justification", f"{w.principal}: {permit}"),
            ("schedule", Block((("expiration", Block((("duration_days", 365),))),)))])))


def _operator(m, w):
    return (*notes(w), *(_eligible(w) if "jit" in w.conditions else assignments(w, w.group)))


def _providers(m, variables):
    """providers.tf of a landing-zone root: the azurerm provider in the environment's subscription, and the root's
    inputs."""
    return header(m, "Providers and inputs (landing zone)", HCL) + "\n" + "\n\n".join([
        block("terraform", [], [("required_providers", Block((
            ("azurerm", {"source": "hashicorp/azurerm", "version": "~> 4.0"}),)))]),
        block("provider", ["azurerm"], [("features", Block(())), ("subscription_id", ref("var.subscription_id"))]),
        subscription_variable(m, described=True),
        *variables]) + "\n"


def _identities(m, guardrails):
    """(main.tf blocks, or () when environment m's landing zone grants no identities and no guardrails)."""
    deployers, operators = landing_identities(m, ACCESS)
    fences = tuple(guardrails(m))
    if not (deployers or operators or fences):
        return ()
    subscription = any("jit" in w.conditions for w in operators) or any("policy_assignment" in f for f in fences)
    return (block("data", ["azurerm_resource_group", "main"], [
                ("name", one(one_role(m, "network"), "ciamResourceGroup"))]),
            *((block("data", ["azurerm_subscription", "current"], []),) if subscription else ()),
            *scope_data(m, (*deployers, *operators), standalone=True),
            *(x for w in deployers for x in _deployer(m, w)), *(x for w in operators for x in _operator(m, w)),
            *fences)


def render_landing(m, guardrails=render_guardrails, plumbing=render_plumbing):
    """{path: text} of environment m's landing zone (identities, guardrails, the network plumbing its owner keeps)
    and of each other party's root keeping some of its plumbing, or {} when it needs nothing from anyone. A data
    source main.tf declares isn't declared again in the same root's network.tf."""
    out = _identities(m, guardrails)
    nets = tuple((k, plumbing(m, k)) for k in keepers(m))
    roots = dict.fromkeys((*((LANDING_ZONE,) if out else ()), *(k.folder for k, _ in nets)))
    what = (f"Azure landing zone for the CIAM platform, kept by {landing_zone_owner(m)}: applied by the landing zone, "
            "not by the platform's pipeline")
    main = {f"{LANDING_ZONE}/main.tf": header(m, what, HCL) + "\n" + "\n\n".join(out) + "\n"} if out else {}
    network = {f"{k.folder}/{NETWORK_FILE}": header(
        m, f"Azure network kept by {k.name} for the CIAM platform: applied by them, not by the platform's pipeline",
        HCL) + "\n" + "\n\n".join(x for x in (*r.shared, *r.blocks) if k.folder != LANDING_ZONE or x not in out)
        + "\n" for k, r in nets}
    providers = {f"{f}/providers.tf": _providers(m, tuple(dict.fromkeys(
        v for k, r in nets if k.folder == f for v in r.variables))) for f in roots}
    return {**providers, **main, **network}

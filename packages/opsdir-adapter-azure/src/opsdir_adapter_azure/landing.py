"""Azure landing zone: what the platform needs from the organization rather than its own Terraform, rendered for
whoever keeps the landing zone (terraform/landing-zone/ when its keeper takes generated infrastructure, else named and
asked: governance.keepers; the MANIFEST marks it landing-zone, the header names the owner). Given as render parts the
environment's render places (opsdir_format_terraform.placing).

  CI deployers     a user-assigned managed identity per deployer with a federated identity credential trusting its
                   pipeline's tokens (issuer and subject), and its role assignments
  operators        role assignments to the operator's Entra group at the narrowest scopes; eligible (Privileged
                   Identity Management, activated when needed) when the principal's condition says jit
  guardrails       policy assignments preventing what the environment's guardrails deny
  network          the plumbing its owner keeps (opsdir_adapter_azure.plumbing) in network.tf; plumbing another party
                   keeps (ciamManagedBy) goes in that party's own root, terraform/landing-zone/<party>/
Pure.
"""
import posixpath

from opsdir.core.directory import one
from opsdir.core.environment import one_role
from opsdir.domains.access.workloads import landing_identities, principal_label
from opsdir.domains.governance.keepers import (LANDING, in_scope)
from opsdir.domains.network.plumbing import LANDING_ZONE, NETWORK_FILE, keepers
from opsdir_format_terraform.hcl import Block, TfBlock, comment, from_entry, mentions, ref, tf_block, tf_name
from opsdir_format_terraform.placing import MAIN, PROVIDERS, STACK, keeper_placed, keeper_roots
from .access import ACCESS
from .guardrails import render_guardrails
from .identities import assignments, federated_credential, managed_identity, notes, role_of, scope, scope_data
from .plumbing import render_plumbing
from .account import provider_block, required_providers, subscription_variable
from opsdir.core.notes import note_comment
from .resource_providers import registration_notes, resource_providers

CLOUD = "Azure"               # the cloud as the keepers' roots' headers name it


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
            ("justification", f"{principal_label(w)}: {permit}"),
            ("schedule", Block((("expiration", Block((("duration_days", 365),))),)))])))


def _operator(m, w):
    return (*notes(w), *(_eligible(w) if "jit" in w.conditions else assignments(w, w.group)))


def _identities(m, guardrails):
    """The identities and guardrails environment m's landing zone grants, stamped as the landing zone's
    (governance.keepers.LANDING), or ()."""
    deployers, operators = landing_identities(m, ACCESS)
    fences = tuple(guardrails(m))
    if not (deployers or operators or fences):
        return ()
    subscription = any("jit" in w.conditions for w in operators) or mentions(fences, "policy_assignment")
    return from_entry(LANDING, (
        tf_block("data", ["azurerm_resource_group", "main"], [
            ("name", one(one_role(m, "network"), "ciamResourceGroup"))]),
        *((tf_block("data", ["azurerm_subscription", "current"], []),) if subscription else ()),
        *scope_data(m, (*deployers, *operators), standalone=True),
        *(x for w in deployers for x in _deployer(m, w)), *(x for w in operators for x in _operator(m, w)),
        *fences))


def landing_parts(m, guardrails=render_guardrails, plumbing=render_plumbing):
    """(parts, landing): what environment m's landing zone and the keepers of its plumbing keep, as render parts
    ((file name, items, origin), ...) placed with the rest of the render (opsdir_format_terraform.placing): the
    landing zone's identities and guardrails (main.tf), each keeper's plumbing (network.tf, its inputs in
    providers.tf), each part's loose comments with its origin; landing: the plumbing bindings' DNs (the landing zone's
    by nature, governance.keepers)."""
    found = keepers(m)
    nets = tuple(plumbing(m, k) for k in found)
    parts = ((MAIN, _identities(m, guardrails), LANDING),
             *(x for k, r in zip(found, nets) for x in (
                 (NETWORK_FILE, (*r.shared, *r.blocks), k.bindings[0].dn), (PROVIDERS, r.variables, k.bindings[0].dn))))
    return parts, frozenset(b.dn for k in found for b in k.bindings)


def _azurerm(x):
    return isinstance(x, TfBlock) and x.kind == "provider" and x.labels[0] == "azurerm" and \
        not any(k == "alias" for k, _ in x.body)


def _subscription(x):
    return isinstance(x, TfBlock) and x.kind == "variable" and x.labels[0] == "subscription_id"


def _registered(placed):
    """(namespaces, unknown types) of every placed root's resources (resource_providers)."""
    return resource_providers(tuple(x for files in placed.files.values() for items in files.values() for x in items))


def registrations(m, placed):
    """{root: (RenderNote, ...)} the providers.tf of environment m's placed roots writes: the stack's every namespace
    to register by hand when no landing-zone root does it, the landing zone's the types whose resource provider opsdir
    doesn't know (its provider registers the rest)."""
    register, unknown = _registered(placed)
    return {STACK: () if LANDING_ZONE in placed.files else registration_notes(m, register, unknown),
            LANDING_ZONE: registration_notes(m, (), unknown)}


def placed_notes(m, parts, landing_dns):
    """The render notes of environment m's render parts as placed_roots writes them: placed the same way, each
    in-scope root's providers.tf registrations."""
    placed = keeper_placed(m, parts, landing_dns)
    noted = registrations(m, placed)
    return tuple(n for root, files in placed.files.items() if in_scope(m, root) and PROVIDERS in files
                 for n in noted.get(root, ()))


def _providers(m):
    """providers(placed) of the placement: each root's providers.tf with its registrations' render notes as comments
    (registrations); a keeper's root's azurerm provider registering, in the landing zone's, the resource providers
    every rendered root's resources need, and its subscription input described."""
    def written(placed):
        register, _ = _registered(placed)
        noted = registrations(m, placed)

        def providers(root, items):
            notes = tuple(comment(note_comment(n)) for n in noted.get(root, ()))
            if root == STACK:
                return (*notes, *items)
            return (*notes, *(provider_block(m, register if root == LANDING_ZONE else ()) if _azurerm(x) else
                              subscription_variable(m, described=True) if _subscription(x) else x for x in items))
        return providers
    return written


def placed_roots(m, parts, landing_dns, stack_head):
    """{path: TfFile} of environment m's Terraform roots (opsdir_format_terraform.placing.keeper_roots), each keeper's
    subscription input described. The landing zone's provider registers the resource providers every rendered root's
    resources need (unknown types a render note above it); with no landing-zone root the stack's providers.tf names
    what to register (registrations, render notes' comments)."""
    return keeper_roots(m, parts, landing_dns, stack_head, CLOUD, providers=_providers(m))


def render_landing(m, guardrails=render_guardrails, plumbing=render_plumbing):
    """{path: TfFile} of the keepers' roots environment m's landing zone and plumbing place into (the landing zone's,
    each other party's that takes generated infrastructure), as the environment's render writes them for these roots
    alone, or {}."""
    parts, landing = landing_parts(m, guardrails, plumbing)
    roots = placed_roots(m, ((PROVIDERS, (required_providers(), provider_block(m), subscription_variable(m))), *parts),
                         landing, lambda name: "")
    return {p: f for p, f in roots.items() if posixpath.dirname(p) != STACK}

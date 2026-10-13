"""Google Cloud landing zone: what the platform needs from the organization rather than its own Terraform, rendered for
whoever keeps the landing zone (terraform/landing-zone/ when its keeper takes generated infrastructure, else named and
asked: governance.keepers; the MANIFEST marks it landing-zone, the header names the owner). Given as render parts the
environment's render places (opsdir_format_terraform.placing).

  CI deployers     a workload identity pool, an OIDC provider per issuer accepting only the deployers' subjects
                   (attribute condition), and per deployer a service account its pipeline may act as
                   (roles/iam.workloadIdentityUser for that subject) with its resource-level IAM members
  operators        resource-level IAM members granted to the operator's group (group:<email>)
  guardrails       organization policies on the project preventing what the environment's guardrails deny
  budgets          Cloud Billing budgets on the billing account (opsdir_adapter_gcp.budgets)
  network          the plumbing its owner keeps (opsdir_adapter_gcp.plumbing) in network.tf; plumbing another party
                   keeps (ciamManagedBy) goes in that party's own root, terraform/landing-zone/<party>/
Pure.
"""
import posixpath

from opsdir.core.directory import rdn_value
from opsdir.core.manifest import header
from opsdir.domains.access.workloads import landing_identities
from opsdir.domains.governance.keepers import (LANDING, SLICE, asked_lines, in_scope, named_keeper, placement,
                                             root_keeper, scope_title, source_label)
from opsdir.domains.network.plumbing import LANDING_ZONE, NETWORK_FILE, keepers
from opsdir_format_terraform.format import FORMAT as HCL
from opsdir_format_terraform.hcl import Block, TfBlock, TfFile, blocks_of, comment, from_entry, ref, tf_block, tf_name
from opsdir_format_terraform.placing import MAIN, PROVIDERS, place_roots
from opsdir_format_terraform.translate import ref_address, value_refs
from .boundary import render_workload
from .access import ACCESS
from .guardrails import render_guardrails
from .identities import members, notes, sa_member, service_account
from .plumbing import render_plumbing
from .account import project_variable, provider_block, required_providers
from opsdir.domains.estate.budgets import budgets
from .budgets import BUDGET, billing_account, budget_provider_settings, render_budgets

POOL = "ci"
STACK = "terraform"           # the stack's own root


def _id(text, limit=32):
    """A pool or provider id Google accepts: lowercase letters, digits and hyphens, 4-32 characters."""
    return "".join(c if c.isalnum() else "-" for c in text.lower())[:limit].strip("-")


def _host(issuer):
    return issuer.split("://", 1)[1].rstrip("/")


def _pool(m, deployers):
    """The environment's pool and one provider per issuer, accepting only its deployers' subjects."""
    issuers = dict.fromkeys(w.trust[0] for w in deployers)
    return (tf_block("resource", ["google_iam_workload_identity_pool", POOL], [
                ("workload_identity_pool_id", _id(f"ciam-{rdn_value(m.env)}-ci")),
                ("display_name", f"CIAM {rdn_value(m.env)} CI")]),
            *(tf_block("resource", ["google_iam_workload_identity_pool_provider", tf_name(_host(i))], [
                ("workload_identity_pool_id",
                 ref(f"google_iam_workload_identity_pool.{POOL}.workload_identity_pool_id")),
                ("workload_identity_pool_provider_id", _id(_host(i))),
                ("attribute_mapping", {'"google.subject"': "assertion.sub"}),
                ("attribute_condition", "assertion.sub in [" + ", ".join(
                    f"'{w.trust[1]}'" for w in deployers if w.trust[0] == i) + "]"),
                ("oidc", Block((("issuer_uri", i),)))]) for i in issuers))


def _deployer(w):
    """A deployer's service account, which its pipeline's subject may act as, and its IAM members."""
    n = tf_name(w.identity_role)
    return (*notes(w), service_account(w),
            tf_block("resource", ["google_service_account_iam_member", f"{n}_ci"], [
                ("service_account_id", ref(f"google_service_account.{n}.name")),
                ("role", "roles/iam.workloadIdentityUser"),
                ("member", f"principal://iam.googleapis.com/${{google_iam_workload_identity_pool.{POOL}.name}}"
                           f"/subject/{w.trust[1]}")]),
            *members(w, sa_member(n)))


def _operator(w):
    return (*notes(w), *members(w, f"group:{w.group}"))


def _identities(m, guardrails):
    """The identities and guardrails environment m's landing zone grants, the budgets it keeps on the billing account
    and its Assured Workloads workload, stamped as the landing zone's (governance.keepers.LANDING), or ()."""
    deployers, operators = landing_identities(m, ACCESS)
    fences, costs = tuple(guardrails(m)), render_budgets(m) if billing_account(m) else ()
    workload = render_workload(m)
    if not (deployers or operators or fences or costs or workload):
        return ()
    return from_entry(LANDING, (*(_pool(m, deployers) if deployers else ()),
                                *(x for w in deployers for x in _deployer(w)),
                                *(x for w in operators for x in _operator(w)), *fences, *costs, *workload))


def landing_parts(m, guardrails=render_guardrails, plumbing=render_plumbing):
    """(parts, landing): what environment m's landing zone and the keepers of its plumbing keep, as render parts
    ((file name, items, origin), ...) placed with the rest of the render (opsdir_format_terraform.placing): the
    landing zone's identities, guardrails, budgets and workload (main.tf), each keeper's plumbing (network.tf, its
    inputs in providers.tf), each part's loose comments with its origin; landing: the plumbing bindings' and the
    budgets' DNs (the landing zone's by nature, governance.keepers)."""
    found = keepers(m)
    nets = tuple(plumbing(m, k) for k in found)
    parts = ((MAIN, _identities(m, guardrails), LANDING),
             *(x for k, r in zip(found, nets) for x in (
                 (NETWORK_FILE, (*r.shared, *r.blocks), k.bindings[0].dn), (PROVIDERS, r.variables, k.bindings[0].dn))))
    return parts, frozenset((*(b.dn for k in found for b in k.bindings), *(b.dn for b in budgets(m))))


def keeper_head(m, root, name, keeper):
    """The header of file name in a keeper's root (keeper: who keeps it; root: the landing zone's or another
    party's)."""
    if name == PROVIDERS:
        return header(m, "Providers and inputs (landing zone)", HCL)
    if name == NETWORK_FILE:
        what = (f"Google Cloud network kept by {keeper} for the CIAM platform: applied by them, not by the platform's "
                "pipeline")
    elif root == LANDING_ZONE:
        what = (f"Google Cloud landing zone for the CIAM platform, kept by {keeper}: applied by the landing zone, not "
                "by the platform's pipeline")
    else:
        what = (f"Google Cloud infrastructure kept by {keeper} for the CIAM platform: applied by them, not by the "
                "platform's pipeline")
    return header(m, what, HCL)


def _keeper_providers(m):
    """adjust(root, items) of the placement: a keeper's root takes the Google provider in the environment's project
    without the stack's region input (with the Budget API's quota project in the landing zone's root, which keeps the
    budgets), its project input described."""
    def reads_region(items):
        return any(ref_address(r) == "var.region" for x in items if isinstance(x, TfBlock)
                   and x.kind not in ("variable",) for r in value_refs(x.body))

    def adjust(root, items):
        if root == STACK:
            return items
        settings = budget_provider_settings(m) if blocks_of(items, "resource", BUDGET) else ()
        own = tuple(provider_block(m, ("project", ref("var.project_id")), *settings) if _is(x, "provider", "google")
                    else project_variable(m, described=True) if _is(x, "variable", "project_id") else x for x in items)
        return own if reads_region(own) else tuple(x for x in own if not _is(x, "variable", "region"))
    return adjust


def _is(x, kind, label):
    return isinstance(x, TfBlock) and x.kind == kind and x.labels[0] == label and \
        not any(k == "alias" for k, _ in x.body)


def placed_roots(m, parts, landing_dns, stack_head):
    """{path: TfFile} of environment m's Terraform roots: its render parts placed by who keeps what
    (governance.keepers.placement, opsdir_format_terraform.placing): the stack's root (stack_head(file name): its
    files' headers), each keeper's that takes generated infrastructure (_keeper_providers), and in the stack's main.tf
    a comment for each entry asked of a keeper instead."""
    placed = place_roots(parts, placement(m, landing_dns), STACK, named=named_keeper, adjust=_keeper_providers(m),
                         label=source_label)

    def head(root, name, files):
        if root == STACK:
            return stack_head(name)
        if root == SLICE:
            return header(m, "Providers and inputs (a slice)" if name == PROVIDERS else
                          f"Google Cloud infrastructure for the CIAM platform, {scope_title(m)}: a slice rendered on "
                          "request, applied after the roots it reads", HCL)
        return keeper_head(m, root, name, root_keeper(m, (b.origin for items in files.values() for b in items
                                                          if isinstance(b, TfBlock)), landing_dns))
    notes = tuple(comment(line) for line in asked_lines(m, placed.named))
    return {f"{root}/{name}": TfFile(head(root, name, files),
                                     (*items, *(notes if (root, name) == (STACK, MAIN) else ())))
            for root, files in placed.files.items() if in_scope(m, root) for name, items in files.items()}


def render_landing(m, guardrails=render_guardrails, plumbing=render_plumbing):
    """{path: TfFile} of the keepers' roots environment m's landing zone and plumbing place into (the landing zone's,
    each other party's that takes generated infrastructure), as the environment's render writes them for these roots
    alone, or {}."""
    parts, landing = landing_parts(m, guardrails, plumbing)
    platform = (required_providers(), provider_block(m, ("project", ref("var.project_id"))), project_variable(m))
    roots = placed_roots(m, ((PROVIDERS, platform), *parts), landing, lambda name: "")
    return {p: f for p, f in roots.items() if posixpath.dirname(p) != STACK}

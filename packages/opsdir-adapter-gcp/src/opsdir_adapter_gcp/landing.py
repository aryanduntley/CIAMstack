"""Google Cloud landing zone: what the platform needs from the organization rather than its own Terraform, rendered for
whoever keeps the landing zone (terraform/landing-zone/; the MANIFEST marks it landing-zone, the header names the
owner).

  CI deployers     a workload identity pool, an OIDC provider per issuer accepting only the deployers' subjects
                   (attribute condition), and per deployer a service account its pipeline may act as
                   (roles/iam.workloadIdentityUser for that subject) with its resource-level IAM members
  operators        resource-level IAM members granted to the operator's group (group:<email>)
  guardrails       organization policies on the project preventing what the environment's guardrails deny
  network          the plumbing its owner keeps (opsdir_adapter_gcp.plumbing) in network.tf; plumbing another party
                   keeps (ciamManagedBy) goes in that party's own root, terraform/landing-zone/<party>/
Pure.
"""
from opsdir.core.directory import rdn_value
from opsdir.core.manifest import header
from opsdir.domains.access.workloads import landing_identities, landing_zone_owner
from opsdir.domains.network.plumbing import LANDING_ZONE, NETWORK_FILE, keepers
from opsdir_format_terraform.format import FORMAT as HCL
from opsdir_format_terraform.hcl import Block, block, ref, tf_name
from .access import ACCESS
from .guardrails import render_guardrails
from .identities import members, notes, sa_member, service_account
from .plumbing import render_plumbing
from .account import project_variable, provider_block

POOL = "ci"


def _id(text, limit=32):
    """A pool or provider id Google accepts: lowercase letters, digits and hyphens, 4-32 characters."""
    return "".join(c if c.isalnum() else "-" for c in text.lower())[:limit].strip("-")


def _host(issuer):
    return issuer.split("://", 1)[1].rstrip("/")


def _pool(m, deployers):
    """The environment's pool and one provider per issuer, accepting only its deployers' subjects."""
    issuers = dict.fromkeys(w.trust[0] for w in deployers)
    return (block("resource", ["google_iam_workload_identity_pool", POOL], [
                ("workload_identity_pool_id", _id(f"ciam-{rdn_value(m.env)}-ci")),
                ("display_name", f"CIAM {rdn_value(m.env)} CI")]),
            *(block("resource", ["google_iam_workload_identity_pool_provider", tf_name(_host(i))], [
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
            block("resource", ["google_service_account_iam_member", f"{n}_ci"], [
                ("service_account_id", ref(f"google_service_account.{n}.name")),
                ("role", "roles/iam.workloadIdentityUser"),
                ("member", f"principal://iam.googleapis.com/${{google_iam_workload_identity_pool.{POOL}.name}}"
                           f"/subject/{w.trust[1]}")]),
            *members(w, sa_member(n)))


def _operator(w):
    return (*notes(w), *members(w, f"group:{w.group}"))


def _providers(m, variables):
    """providers.tf of a landing-zone root: the Google provider in the environment's project, and the root's inputs."""
    return header(m, "Providers and inputs (landing zone)", HCL) + "\n" + "\n\n".join([
        block("terraform", [], [("required_providers", Block((
            ("google", {"source": "hashicorp/google", "version": "~> 8.0"}),)))]),
        provider_block(m, ("project", ref("var.project_id"))),
        project_variable(m, described=True),
        *variables]) + "\n"


def _identities(m, guardrails):
    """main.tf text of the identities and guardrails environment m's landing zone grants, or None."""
    deployers, operators = landing_identities(m, ACCESS)
    fences = tuple(guardrails(m))
    if not (deployers or operators or fences):
        return None
    out = (*(_pool(m, deployers) if deployers else ()), *(x for w in deployers for x in _deployer(w)),
           *(x for w in operators for x in _operator(w)), *fences)
    what = (f"Google Cloud landing zone for the CIAM platform, kept by {landing_zone_owner(m)}: applied by the landing "
            "zone, not by the platform's pipeline")
    return header(m, what, HCL) + "\n" + "\n\n".join(out) + "\n"


def render_landing(m, guardrails=render_guardrails, plumbing=render_plumbing):
    """{path: text} of environment m's landing zone (identities, guardrails, the network plumbing its owner keeps)
    and of each other party's root keeping some of its plumbing, or {} when it needs nothing from anyone."""
    main = _identities(m, guardrails)
    nets = tuple((k, plumbing(m, k)) for k in keepers(m))
    roots = dict.fromkeys((*((LANDING_ZONE,) if main else ()), *(k.folder for k, _ in nets)))
    network = {f"{k.folder}/{NETWORK_FILE}": header(
        m, f"Google Cloud network kept by {k.name} for the CIAM platform: applied by them, not by the platform's "
           "pipeline", HCL) + "\n" + "\n\n".join((*r.shared, *r.blocks)) + "\n" for k, r in nets}
    providers = {f"{f}/providers.tf": _providers(m, tuple(dict.fromkeys(
        v for k, r in nets if k.folder == f for v in r.variables))) for f in roots}
    return {**providers, **({f"{LANDING_ZONE}/main.tf": main} if main else {}), **network}

"""AWS landing zone: what the platform needs from the organization rather than its own Terraform, rendered for whoever
keeps the landing zone (terraform/landing-zone/ when its keeper takes generated infrastructure, else named and asked:
governance.keepers; the MANIFEST marks it landing-zone, the header names the owner). Given as render parts the
environment's render places (opsdir_format_terraform.placing), the root's providers being the platform's own less the
account pin (a landing zone's keeper may apply from another account).

  CI deployers     an IAM OIDC provider per issuer and a role each deployer's pipeline assumes with its token
                   (sts:AssumeRoleWithWebIdentity, the audience and the subject pinned), with its least-privilege policy
  operators        an IAM Identity Center permission set per operator principal (its permissions as an inline policy)
                   assigned to the principal's group in the account
  guardrails       service control policies preventing what the environment's guardrails deny
  network          the plumbing its owner keeps (opsdir_adapter_aws.plumbing) in network.tf; plumbing another party
                   keeps (ciamManagedBy) goes in that party's own root, terraform/landing-zone/<party>/
Pure.
"""
import posixpath

from opsdir.core.directory import rdn_value
from opsdir.domains.access.workloads import landing_identities, principal_label
from opsdir.domains.governance.keepers import (LANDING)
from opsdir.domains.network.plumbing import NETWORK_FILE, keepers
from opsdir_format_terraform.hcl import TfBlock, from_entry, jsonencoded, ref, tf_block, tf_name
from opsdir_format_terraform.placing import MAIN, PROVIDERS, STACK, keeper_roots
from .access import ACCESS
from .account import account_id, provider_block, required_providers
from .guardrails import render_guardrails
from .identities import notes, role, statements
from .plumbing import render_plumbing

SSO = "tolist(data.aws_ssoadmin_instances.sso.arns)[0]"
CLOUD = "AWS"                 # the cloud as the keepers' roots' headers name it


def _host(issuer):
    return issuer.split("://", 1)[1].rstrip("/")


def _provider(issuer):
    return tf_block("resource", ["aws_iam_openid_connect_provider", tf_name(_host(issuer))], [
        ("url", issuer), ("client_id_list", ["sts.amazonaws.com"])])


def _deployer(m, w):
    """A deployer's role, trusted only for its pipeline's tokens (audience and subject), and its policy."""
    issuer, subject = w.trust
    host = _host(issuer)
    trust = {"Version": "2012-10-17", "Statement": [{
        "Effect": "Allow", "Action": "sts:AssumeRoleWithWebIdentity",
        "Principal": {"Federated": f"${{aws_iam_openid_connect_provider.{tf_name(host)}.arn}}"},
        "Condition": {"StringEquals": {f"{host}:aud": "sts.amazonaws.com"}, "StringLike": {f"{host}:sub": subject}}}]}
    return (*notes(w), *role(m, w, trust))


def _operator(m, w):
    """An operator's permission set, its permissions inline, assigned to its group in the account."""
    n, found = tf_name(w.identity_role), statements(m, w)
    return (*notes(w),
            tf_block("resource", ["aws_ssoadmin_permission_set", n], [
                ("name", w.name[:32]), ("instance_arn", ref(SSO)), ("session_duration", "PT4H"),
                ("description", f"{principal_label(w)} ({w.identity_role})")]),
            *((tf_block("resource", ["aws_ssoadmin_permission_set_inline_policy", n], [
                ("instance_arn", ref(SSO)), ("permission_set_arn", ref(f"aws_ssoadmin_permission_set.{n}.arn")),
                ("inline_policy", jsonencoded({"Version": "2012-10-17", "Statement": found}))]),) if found else ()),
            tf_block("resource", ["aws_ssoadmin_account_assignment", n], [
                ("instance_arn", ref(SSO)), ("permission_set_arn", ref(f"aws_ssoadmin_permission_set.{n}.arn")),
                ("principal_id", w.group), ("principal_type", "GROUP"),
                ("target_id", ref("var.account_id")), ("target_type", "AWS_ACCOUNT")]))


def _identities(m, guardrails):
    """(items, inputs) of the identities and guardrails environment m's landing zone grants, stamped as the landing
    zone's (governance.keepers.LANDING), or ((), ())."""
    deployers, operators = landing_identities(m, ACCESS)
    fences = tuple(guardrails(m))
    if not (deployers or operators or fences):
        return (), ()
    issuers = dict.fromkeys(w.trust[0] for w in deployers)
    out = (*(_provider(i) for i in issuers), *(x for w in deployers for x in _deployer(m, w)),
           *((tf_block("data", ["aws_ssoadmin_instances", "sso"], []),) if operators else ()),
           *(x for w in operators for x in _operator(m, w)), *fences)
    variables = (*((tf_block("variable", ["account_id"], [("type", ref("string")),
                                                          ("description", f"The account {rdn_value(m.env)} runs in"),
                                                          *((("default", account_id(m)),) if account_id(m) else ())]),)
                   if operators else ()),
                 *((tf_block("variable", ["guardrail_target_id"], [
                     ("type", ref("string")),
                     ("description", "The organizational unit or account the guardrails attach to")]),)
                   if any(isinstance(f, TfBlock) and f.labels[0].startswith("aws_organizations_policy")
                          for f in fences) else ()))
    return from_entry(LANDING, out), variables


def landing_parts(m, guardrails=render_guardrails, plumbing=render_plumbing):
    """(parts, landing): what environment m's landing zone and the keepers of its plumbing keep, as render parts
    ((file name, items, origin), ...) placed with the rest of the render (opsdir_format_terraform.placing): the
    landing zone's identities and guardrails (main.tf, their inputs in providers.tf), each keeper's plumbing
    (network.tf, its inputs in providers.tf), each part's loose comments with its origin; landing: the plumbing
    bindings' DNs (the landing zone's by nature, governance.keepers)."""
    main, inputs = _identities(m, guardrails)
    found = keepers(m)
    nets = tuple(plumbing(m, k) for k in found)
    parts = ((MAIN, main, LANDING), (PROVIDERS, inputs, LANDING),
             *(x for k, r in zip(found, nets) for x in (
                 (NETWORK_FILE, (*r.shared, *r.blocks), k.bindings[0].dn), (PROVIDERS, r.variables, k.bindings[0].dn))))
    return parts, frozenset(b.dn for k in found for b in k.bindings)


def _unpinned(m):
    """adjust(root, items) of the placement: a keeper's root takes the platform's providers less the pin to the
    platform's own account (the keeper may apply from another); the standard account's aliases keep theirs."""
    pin = ("allowed_account_ids", [account_id(m)])
    return lambda root, items: items if root == STACK else tuple(
        x._replace(body=tuple(kv for kv in x.body if kv != pin)) if isinstance(x, TfBlock) and x.kind == "provider"
        else x for x in items)


def placed_roots(m, parts, landing_dns, stack_head):
    """{path: TfFile} of environment m's Terraform roots (opsdir_format_terraform.placing.keeper_roots): a keeper's
    root takes the platform's providers less the pin to its own account (_unpinned)."""
    return keeper_roots(m, parts, landing_dns, stack_head, CLOUD, adjust=_unpinned(m))


def render_landing(m, guardrails=render_guardrails, plumbing=render_plumbing):
    """{path: TfFile} of the keepers' roots environment m's landing zone and plumbing place into (the landing zone's,
    each other party's that takes generated infrastructure), as the environment's render writes them, or {}."""
    parts, landing = landing_parts(m, guardrails, plumbing)
    roots = placed_roots(m, ((PROVIDERS, (required_providers(), provider_block(m))), *parts), landing,
                         lambda name: "")
    return {p: f for p, f in roots.items() if posixpath.dirname(p) != STACK}

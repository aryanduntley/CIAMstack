"""AWS landing zone: what the platform needs from the organization rather than its own Terraform, rendered for whoever
keeps the landing zone (terraform/landing-zone/; the MANIFEST marks it landing-zone, the header names the owner).

  CI deployers     an IAM OIDC provider per issuer and a role each deployer's pipeline assumes with its token
                   (sts:AssumeRoleWithWebIdentity, the audience and the subject pinned), with its least-privilege policy
  operators        an IAM Identity Center permission set per operator principal (its permissions as an inline policy)
                   assigned to the principal's group in the account
  guardrails       service control policies preventing what the environment's guardrails deny
Pure.
"""
from opsdir.core.directory import one, rdn_value
from opsdir.core.manifest import header
from opsdir.domains.access.workloads import landing_identities, landing_zone_owner
from opsdir_format_terraform.format import FORMAT as HCL
from opsdir_format_terraform.hcl import Block, block, jsonencoded, ref, tf_name
from .access import ACCESS
from .guardrails import render_guardrails
from .identities import notes, role, statements

SSO = "tolist(data.aws_ssoadmin_instances.sso.arns)[0]"


def _host(issuer):
    return issuer.split("://", 1)[1].rstrip("/")


def _provider(issuer):
    return block("resource", ["aws_iam_openid_connect_provider", tf_name(_host(issuer))], [
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
            block("resource", ["aws_ssoadmin_permission_set", n], [
                ("name", w.name[:32]), ("instance_arn", ref(SSO)), ("session_duration", "PT4H"),
                ("description", f"{w.principal} ({w.identity_role})")]),
            *((block("resource", ["aws_ssoadmin_permission_set_inline_policy", n], [
                ("instance_arn", ref(SSO)), ("permission_set_arn", ref(f"aws_ssoadmin_permission_set.{n}.arn")),
                ("inline_policy", jsonencoded({"Version": "2012-10-17", "Statement": found}))]),) if found else ()),
            block("resource", ["aws_ssoadmin_account_assignment", n], [
                ("instance_arn", ref(SSO)), ("permission_set_arn", ref(f"aws_ssoadmin_permission_set.{n}.arn")),
                ("principal_id", w.group), ("principal_type", "GROUP"),
                ("target_id", ref("var.account_id")), ("target_type", "AWS_ACCOUNT")]))


def render_landing(m, guardrails=render_guardrails):
    """{path: text} of environment m's landing zone, or {} when it needs nothing from one."""
    deployers, operators = landing_identities(m, ACCESS)
    fences = tuple(guardrails(m))
    if not (deployers or operators or fences):
        return {}
    issuers = dict.fromkeys(w.trust[0] for w in deployers)
    out = (*(_provider(i) for i in issuers), *(x for w in deployers for x in _deployer(m, w)),
           *((block("data", ["aws_ssoadmin_instances", "sso"], []),) if operators else ()),
           *(x for w in operators for x in _operator(m, w)), *fences)
    what = (f"AWS landing zone for the CIAM platform, kept by {landing_zone_owner(m)}: applied by the landing zone, "
            "not by the platform's pipeline")
    main = header(m, what, HCL) + "\n" + "\n\n".join(out) + "\n"
    providers = header(m, "Providers and inputs (landing zone)", HCL) + "\n" + "\n\n".join([
        block("terraform", [], [("required_providers", Block((
            ("aws", {"source": "hashicorp/aws", "version": "~> 5.0"}),)))]),
        block("provider", ["aws"], [("region", one(m.cloud, "ciamRegion"))]),
        *((block("variable", ["account_id"], [("type", ref("string")),
                                               ("description", f"The account {rdn_value(m.env)} runs in")]),)
          if operators else ()),
        *((block("variable", ["guardrail_target_id"], [
            ("type", ref("string")), ("description", "The organizational unit or account the guardrails attach to")]),)
          if any("aws_organizations_policy" in f for f in fences) else ())]) + "\n"
    return {"terraform/landing-zone/providers.tf": providers, "terraform/landing-zone/main.tf": main}

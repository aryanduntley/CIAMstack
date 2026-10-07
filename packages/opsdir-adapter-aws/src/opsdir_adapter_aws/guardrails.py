"""An environment's guardrails as AWS service control policies: each neutral denial (ciamDenies) as SCP statements, one
policy per guardrail attached to the organizational unit or account the landing zone names. Pure.

Statements follow AWS's examples (github.com/aws-samples/service-control-policy-examples, checked 2026-10-02, note
457), without their privileged-role exemptions: add one where the organization keeps such a role. Adapted: the
CloudTrail statement covers every trail (the example names one) and leaves trail creation allowed. IMDSv2 follows the
EC2 User Guide's example. Not rendered: public-storage (AWS's mechanism, the Organizations S3 policy type, needs the
aws provider v6), and any denial AWS has no statement for; each is a NOTE. region-escape allows the regions the
environment may hold resources in (estate.residency.permitted_regions: its cloud's region and those its residency
allows).
"""
from opsdir.core.directory import rdn_value, values
from opsdir.core.environment import of_class
from opsdir.domains.access.naming import DENIALS
from opsdir.domains.estate.residency import permitted_regions
from opsdir_format_terraform.hcl import block, jsonencoded, ref, tf_name


GLOBAL_SERVICES = ("a4b:*", "acm:*", "aws-marketplace-management:*", "aws-marketplace:*", "aws-portal:*", "budgets:*",
                   "ce:*", "chime:*", "cloudfront:*", "config:*", "cur:*", "directconnect:*", "ec2:DescribeRegions",
                   "ec2:DescribeTransitGateways", "ec2:DescribeVpnGateways", "fms:*", "globalaccelerator:*",
                   "health:*", "iam:*", "importexport:*", "kms:*", "mobileanalytics:*", "networkmanager:*",
                   "organizations:*", "pricing:*", "route53:*", "route53domains:*", "route53-recovery-cluster:*",
                   "route53-recovery-control-config:*", "route53-recovery-readiness:*", "s3:GetAccountPublic*",
                   "s3:ListAllMyBuckets", "s3:ListMultiRegionAccessPoints", "s3:PutAccountPublic*", "shield:*",
                   "sts:*", "support:*", "trustedadvisor:*", "waf-regional:*", "waf:*", "wafv2:*", "wellarchitected:*")
NOT_RENDERED = {"public-storage": ("AWS's mechanism is the Organizations S3 policy type (S3_POLICY), which needs the "
                                   "aws provider v6; set it on the organization")}


def _statements(denial, regions):
    """The SCP statements preventing a neutral denial (regions: those region-escape allows), or () when AWS has
    none."""
    deny = {"Effect": "Deny", "Resource": "*"}
    return {
        "region-escape": ({**deny, "Sid": "DenyOutsideRegion", "NotAction": list(GLOBAL_SERVICES),
                           "Condition": {"StringNotEquals": {"aws:RequestedRegion": list(regions)}}},),
        "audit-log-disable": ({**deny, "Sid": "DenyCloudTrailChanges",
                               "Action": ["cloudtrail:DeleteTrail", "cloudtrail:PutEventSelectors",
                                          "cloudtrail:StopLogging", "cloudtrail:UpdateTrail"]},),
        "service-account-keys": ({**deny, "Sid": "DenyAccessKeys", "Action": ["iam:CreateAccessKey"]},),
        "metadata-v1": ({"Sid": "RequireImdsV2", "Effect": "Deny", "Action": "ec2:RunInstances",
                         "Resource": "arn:aws:ec2:*:*:instance/*",
                         "Condition": {"StringNotEquals": {"ec2:MetadataHttpTokens": "required"}}},),
        "root-use": ({**deny, "Sid": "DenyRoot", "NotAction": ["s3:GetBucketPolicy", "s3:PutBucketPolicy",
                                                               "s3:DeleteBucketPolicy"],
                      "Condition": {"ArnLike": {"aws:PrincipalArn": "arn:aws:iam::*:root"}}},),
        "key-deletion": ({**deny, "Sid": "DenyKeyDeletion",
                          "Action": ["kms:ScheduleKeyDeletion", "kms:DeleteAlias", "kms:DeleteCustomKeyStore",
                                     "kms:DeleteImportedKeyMaterial"]},),
    }.get(denial, ())


def denials_of(statements):
    """What a control policy's statements prevent, by the statement ids the renderer gives (read back on import)."""
    sids = {s["Sid"]: d for d in DENIALS for s in _statements(d, ())}
    return tuple(dict.fromkeys(sids[s.get("Sid")] for s in statements if s.get("Sid") in sids))


def render_guardrails(m):
    """HCL for environment m's guardrails: per guardrail an SCP and its attachment; a NOTE for what isn't rendered."""
    def one_guardrail(g):
        n, regions = tf_name(rdn_value(g)), permitted_regions(m)
        denials = values(g, "ciamDenies")
        found = [s for d in denials for s in _statements(d, regions)]
        skipped = [f"# NOTE: guardrail {rdn_value(g)}: {d}: {NOT_RENDERED.get(d, 'AWS has no statement for it')}"
                   for d in denials if not _statements(d, regions)]
        return (*skipped, *((
            block("resource", ["aws_organizations_policy", n], [
                ("name", f"ciam-{rdn_value(m.env)}-{rdn_value(g)}"), ("type", "SERVICE_CONTROL_POLICY"),
                ("description", f"Prevents {', '.join(denials)} ({m.label})"),
                ("content", jsonencoded({"Version": "2012-10-17", "Statement": found}))]),
            block("resource", ["aws_organizations_policy_attachment", n], [
                ("policy_id", ref(f"aws_organizations_policy.{n}.id")),
                ("target_id", ref("var.guardrail_target_id"))])) if found else ()))
    return tuple(x for g in of_class(m, "ciamGuardrail") if values(g, "ciamDenies") for x in one_guardrail(g))

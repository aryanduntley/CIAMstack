"""An environment's guardrails as AWS service control policies: each neutral denial (ciamDenies) as SCP statements, one
policy per guardrail attached to the organizational unit or account the landing zone names. Pure.

Statements follow AWS's examples (github.com/aws-samples/service-control-policy-examples, checked 2026-10-02, note
457), without their privileged-role exemptions: add one where the organization keeps such a role. Adapted: the
CloudTrail statement covers every trail (the example names one) and leaves trail creation allowed. IMDSv2 follows the
EC2 User Guide's example. public-storage is an Organizations S3 policy instead (type S3_POLICY, attached to the same
target: AWS's documented form enabling all four S3 Block Public Access settings for every account it applies to, and
locking them there; research 2909), which applies only once the S3 policy type is enabled on the organization's root:
an action for whoever keeps the organization. Any denial AWS has no statement for is an action too (guardrail_notes,
flow 43), written as its comment. region-escape allows the regions the environment may hold resources in
(estate.residency.permitted_regions: its cloud's region and those its residency allows).

Read back: an S3 policy named after its guardrail's control policy (<name>-s3) is that guardrail's public-storage.
"""
import json

from opsdir.core.directory import rdn_value, values
from opsdir.core.environment import of_class
from opsdir.core.notes import RECORD, note, note_comment
from opsdir.domains.access.naming import DENIALS
from opsdir.domains.estate.residency import permitted_regions
from opsdir_format_terraform.hcl import comment, jsonencoded, ref, tf_block, tf_name


GLOBAL_SERVICES = ("a4b:*", "acm:*", "aws-marketplace-management:*", "aws-marketplace:*", "aws-portal:*", "budgets:*",
                   "ce:*", "chime:*", "cloudfront:*", "config:*", "cur:*", "directconnect:*", "ec2:DescribeRegions",
                   "ec2:DescribeTransitGateways", "ec2:DescribeVpnGateways", "fms:*", "globalaccelerator:*",
                   "health:*", "iam:*", "importexport:*", "kms:*", "mobileanalytics:*", "networkmanager:*",
                   "organizations:*", "pricing:*", "route53:*", "route53domains:*", "route53-recovery-cluster:*",
                   "route53-recovery-control-config:*", "route53-recovery-readiness:*", "s3:GetAccountPublic*",
                   "s3:ListAllMyBuckets", "s3:ListMultiRegionAccessPoints", "s3:PutAccountPublic*", "shield:*",
                   "sts:*", "support:*", "trustedadvisor:*", "waf-regional:*", "waf:*", "wafv2:*", "wellarchitected:*")
# public-storage as an Organizations S3 policy: all four S3 Block Public Access settings for every account it applies to
S3_POLICY = "S3_POLICY"
PUBLIC_STORAGE = {"s3_attributes": {"public_access_block_configuration": {"@@assign": "all"}}}
S3_SUFFIX = "-s3"


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


def blocks_public_access(content):
    """Whether an S3 policy's content (a JSON text or dict) enables all four S3 Block Public Access settings."""
    try:
        doc = json.loads(content) if isinstance(content, str) else content or {}
    except ValueError:
        return False
    found = ((doc.get("s3_attributes") or {}).get("public_access_block_configuration") or {}) \
        if isinstance(doc, dict) else {}
    return isinstance(found, dict) and found.get("@@assign") == "all"


def guardrail_note(m, g, d):
    """The render note of guardrail g's denial d, or None: public-storage, rendered as an S3 policy, an action (the S3
    policy type must be enabled on the organization's root first); a denial AWS has no SCP statement for an action
    (enforce it another way)."""
    if d == "public-storage":
        return note("Guardrails", "action", f"guardrail {rdn_value(g)}", "public-storage: rendered as an Organizations "
                    "S3 policy, which applies only once the S3 policy type is enabled on the organization's root",
                    ("From the management account, enable it once: aws organizations enable-policy-type --root-id "
                     "<root id> --policy-type S3_POLICY (the organization must use all features)",
                     "Then apply the landing zone's guardrails"), g.dn, "the organization")
    if _statements(d, permitted_regions(m)):
        return None
    return note("Guardrails", "action", f"guardrail {rdn_value(g)}", f"{d}: AWS has no statement for it",
                (f"Prevent {d} another way where the guardrail applies (an organization policy of another type, a "
                 "Config rule), or remove it from the guardrail's ciamDenies, " + RECORD,), g.dn, m.label)


def guardrail_notes(m):
    """The render notes of environment m's guardrails (render_guardrails writes their comments)."""
    return tuple(n for g in of_class(m, "ciamGuardrail") for d in values(g, "ciamDenies")
                 for n in (guardrail_note(m, g, d),) if n is not None)


def render_guardrails(m):
    """HCL for environment m's guardrails: per guardrail an SCP and its attachment; a note (guardrail_note) for what
    isn't rendered."""
    def one_guardrail(g):
        n, regions = tf_name(rdn_value(g)), permitted_regions(m)
        denials = values(g, "ciamDenies")
        found = [s for d in denials for s in _statements(d, regions)]
        skipped = [comment(note_comment(x)) for d in denials for x in (guardrail_note(m, g, d),) if x is not None]
        name = f"ciam-{rdn_value(m.env)}-{rdn_value(g)}"
        return (*skipped, *((
            tf_block("resource", ["aws_organizations_policy", n], [
                ("name", name), ("type", "SERVICE_CONTROL_POLICY"),
                ("description", f"Prevents {', '.join(d for d in denials if _statements(d, regions))} ({m.label})"),
                ("content", jsonencoded({"Version": "2012-10-17", "Statement": found}))]),
            tf_block("resource", ["aws_organizations_policy_attachment", n], [
                ("policy_id", ref(f"aws_organizations_policy.{n}.id")),
                ("target_id", ref("var.guardrail_target_id"))])) if found else ()),
            *((tf_block("resource", ["aws_organizations_policy", f"{n}_s3"], [
                ("name", name + S3_SUFFIX), ("type", S3_POLICY),
                ("description", f"Prevents public-storage: S3 Block Public Access for every account ({m.label})"),
                ("content", jsonencoded(PUBLIC_STORAGE))]),
               tf_block("resource", ["aws_organizations_policy_attachment", f"{n}_s3"], [
                   ("policy_id", ref(f"aws_organizations_policy.{n}_s3.id")),
                   ("target_id", ref("var.guardrail_target_id"))])) if "public-storage" in denials else ()))
    return tuple(x for g in of_class(m, "ciamGuardrail") if values(g, "ciamDenies") for x in one_guardrail(g))

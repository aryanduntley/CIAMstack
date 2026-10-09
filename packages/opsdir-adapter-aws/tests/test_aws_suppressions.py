"""Suppressions on AWS: a Security Hub automation rule suppressing the exception's controls and a GuardDuty filter
archiving its finding types, named after the exception, with comments for the expiry, GovCloud and other providers'
refs; read back from Terraform state, merged per name, linked to the exception."""
from opsdir_adapter_aws.suppressions import render_suppressions, suppression_resources
from network_fixtures import ALPHA, entry, model

EXC = "cn=EXC-7,ou=exceptions,dc=ciam-ops"
TREE = ("dn: ou=exceptions,dc=ciam-ops\nobjectClass: top\nobjectClass: organizationalUnit\nou: exceptions\n",
        f"dn: {EXC}\nobjectClass: top\nobjectClass: ciamRiskException\ncn: EXC-7\nciamExceptionKind: false-positive\n"
        "ciamExceptionStatus: approved\nciamAffectedEnvironment: env=prod,cloud=alpha,ou=environments,dc=ciam-ops\n"
        "ciamExpiresAt: 20270331000000Z\n")


def _render(*refs, managed=None):
    s = entry(ALPHA, "exc-EXC-7", "ciamSuppression", ciamBindingRole="suppression-EXC-7", ciamFindingRef=tuple(refs),
              ciamExceptionRef=EXC, **({"ciamManagedBy": managed} if managed else {}))
    _, alpha, _ = model(alpha=(s,), tree=TREE)
    return "\n\n".join(render_suppressions(alpha))


def test_a_suppression_renders_an_automation_rule_and_a_guardduty_filter_named_after_its_exception():
    out = _render("aws:securityhub:IAM.6", "aws:securityhub:S3.1", "aws:guardduty:Recon:EC2/PortProbeUnprotectedPort",
                  "azure:policy:abc")
    assert 'resource "aws_securityhub_automation_rule" "exc_exc_7"' in out
    assert 'rule_name   = "exc-EXC-7"' in out and out.count("compliance_security_control_id {") == 2
    assert 'status = "SUPPRESSED"' in out and 'text       = "exception EXC-7, until 2027-03-31"' in out
    assert "# exc-EXC-7: Security Hub automation rules have no expiry: remove this rule on 2027-03-31" in out
    assert 'data "aws_guardduty_detector" "suppressions"' in out and 'action      = "ARCHIVE"' in out
    assert 'equals = ["Recon:EC2/PortProbeUnprotectedPort"]' in out
    assert out.endswith("# exc-EXC-7: not AWS's (not rendered here): azure:policy:abc")


def test_a_suppression_someone_else_keeps_is_a_comment():
    assert _render("aws:securityhub:IAM.6", managed="cn=sec,ou=owners,dc=ciam-ops") == ""


def test_suppressions_are_read_back_merged_per_name():
    pairs = [("aws_securityhub_automation_rule", {
                "arn": "arn:aws:securityhub:us-east-1:111122223333:automation-rule/a1", "rule_name": "exc-EXC-7",
                "criteria": [{"compliance_security_control_id": [{"comparison": "EQUALS", "value": "IAM.6"}]}],
                "actions": [{"type": "FINDING_FIELDS_UPDATE",
                             "finding_fields_update": [{"workflow": [{"status": "SUPPRESSED"}]}]}]}),
             ("aws_guardduty_filter", {"arn": "arn:aws:guardduty:us-east-1:111122223333:detector/d/filter/exc-EXC-7",
                                       "name": "exc-EXC-7", "action": "ARCHIVE",
                                       "finding_criteria": [{"criterion": [{"field": "type",
                                                                            "equals": ["Recon:X"]}]}]}),
             ("aws_securityhub_automation_rule", {"arn": "arn:other", "rule_name": "raise-severity", "actions": [
                 {"finding_fields_update": [{"severity": [{"label": "CRITICAL"}]}]}]})]
    (found,) = suppression_resources(pairs)
    assert (found.kind, found.ref, found.name) == (
        "suppression", "arn:aws:securityhub:us-east-1:111122223333:automation-rule/a1", "exc-EXC-7")
    assert dict(found.attrs) == {"ciamFindingRef": ("aws:securityhub:IAM.6", "aws:guardduty:Recon:X"),
                                 "ciamExceptionRef": ("EXC-7",)}

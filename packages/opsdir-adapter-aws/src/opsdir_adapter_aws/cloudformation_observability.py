"""The observability CloudFormation stacks declare, normalized to the Terraform attribute names the shared mapping
reads (opsdir_adapter_aws.inventory: log destinations). Properties come resolved. Pure.

  AWS::Logs::LogGroup   -> aws_cloudwatch_log_group (its retention, key)
"""
OBSERVABILITY_TYPES = ("AWS::Logs::LogGroup",)


def _tags(tags):
    return {t.get("Key"): t.get("Value") for t in tags or () if isinstance(t, dict) and t.get("Key")}


def observability_stack_pairs(declared, names):
    """(Terraform resource type, attributes) pairs of observability among a stack's declared resources."""
    return [("aws_cloudwatch_log_group", {
        "arn": (names.get(f"{lid}.Arn") or "").removesuffix(":*") or None, "name": p.get("LogGroupName") or pid,
        "retention_in_days": int(p["RetentionInDays"]) if str(p.get("RetentionInDays", "")).isdigit() else None,
        "kms_key_id": p.get("KmsKeyId"), "tags": _tags(p.get("Tags"))})
        for lid, t, p, _, pid in declared if t == "AWS::Logs::LogGroup"]

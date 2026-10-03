"""The IAM roles and policies AWS renderers share: an identity's least-privilege policy statements from the AWS
permission table (opsdir_adapter_aws.access), the role assumed under a trust policy, and notes for what can't be
granted. The platform's Terraform (workloads, terraform.py) and the landing zone's (deployers, landing.py) use them.
Pure.
"""
import re

from opsdir.core.directory import one
from opsdir.core.environment import one_role
from opsdir_format_terraform.hcl import block, jsonencoded, ref, tf_name
from .access import resources


def _sid(permit):
    return "".join(w.capitalize() for w in re.split(r"[^A-Za-z0-9]+", permit) if w)


EC2_TRUST = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Principal": {"Service": "ec2.amazonaws.com"},
                                                     "Action": "sts:AssumeRole"}]}


def _related(m, permit, b, row):
    """Statements for what a permit also needs on a linked binding (the key that encrypts a secret), only through
    Secrets Manager in the environment's region (kms:ViaService)."""
    linked = [(k, needs) for attr, needs in row.related if one(b, attr)
              for k in (one_role(m, one(b, attr)),) if k is not None]
    if not linked:
        return []
    via = {"StringEquals": {"kms:ViaService": f"secretsmanager.{one(m.cloud, 'ciamRegion')}.amazonaws.com"}}
    return [{"Sid": f"{_sid(permit)}Key", "Effect": "Allow", "Action": [alts[0] for alts in needs],
             "Resource": list(resources(k)), "Condition": via} for k, needs in linked]


def statements(m, w):
    """An identity's least-privilege policy statements: one per permit (the first action of each requirement, on the
    binding's resources), with what its secrets' keys need."""
    return [s for permit, b, row in w.grants
            for s in ({"Sid": _sid(permit), "Effect": "Allow", "Action": [alts[0] for alts in row.needs],
                       "Resource": list(resources(b))}, *_related(m, permit, b, row))]


def notes(w):
    return tuple(f"# NOTE: principal {w.principal}: {note}" for note in w.notes)


def role(m, w, trust):
    """An identity's IAM role assumed under a trust policy, and its least-privilege inline policy."""
    n, found = tf_name(w.identity_role), statements(m, w)
    policy = (block("resource", ["aws_iam_role_policy", n], [
        ("name", f"{w.name}-permissions"), ("role", ref(f"aws_iam_role.{n}.id")),
        ("policy", jsonencoded({"Version": "2012-10-17", "Statement": found}))]),) if found else ()
    return (block("resource", ["aws_iam_role", n], [
                ("name", w.name), ("assume_role_policy", jsonencoded(trust)),
                ("tags", {"Principal": w.principal, "Role": w.identity_role, "ManagedBy": "opsdir"})]),
            *policy)

"""The IAM roles and policies AWS renderers share: an identity's least-privilege policy statements from the AWS
permission table (opsdir_adapter_aws.access), the role assumed under a trust policy, and notes for what can't be
granted. The platform's Terraform (workloads, terraform.py) and the landing zone's (deployers, landing.py) use them.
Pure.
"""
import re

from opsdir.core.directory import one
from opsdir.core.environment import one_role
from opsdir_format_terraform.hcl import Block, block, jsonencoded, ref, tf_name
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


def eks_cluster_name(cluster):
    """The EKS cluster name a cluster binding's provider ref gives (its ARN's last segment, or the name itself)."""
    return (one(cluster, "ciamProviderRef") or "").rsplit("/", 1)[-1]


def _eks(cluster):
    return tf_name(eks_cluster_name(cluster))


def eks_data(identities):
    """The EKS clusters (and their IAM OIDC providers) whose service accounts the identities trust, as data sources:
    the provider is whoever made the cluster's (the issuer is the cluster's)."""
    clusters = {c.dn: c for w in identities for c in (p.cluster for p in w.pods) if c is not None}.values()
    return tuple(x for c in clusters for x in (
        block("data", ["aws_eks_cluster", _eks(c)], [("name", eks_cluster_name(c))]),
        block("data", ["aws_iam_openid_connect_provider", _eks(c)], [
            ("url", ref(f"data.aws_eks_cluster.{_eks(c)}.identity[0].oidc[0].issuer"))])))


def _issuer_key(c, claim):
    return ref(f'join(":", [trimprefix(data.aws_eks_cluster.{_eks(c)}.identity[0].oidc[0].issuer, "https://"), '
               f'"{claim}"])')


def pod_trust(w):
    """(the trust policy document of an identity Kubernetes service accounts assume (IRSA: each cluster's OIDC
    provider for system:serviceaccount:<namespace>:<name>, audience sts.amazonaws.com) plus EC2 when its servers do,
    or None when no service account's cluster is bound; notes for those whose cluster the environment doesn't
    bind)."""
    n = tf_name(w.identity_role)
    clusters = {p.cluster.dn: p.cluster for p in w.pods if p.cluster is not None}.values()
    unbound = tuple(f"# NOTE: principal {w.principal}: service account {p.namespace}/{p.service_account} runs in a "
                    "cluster this environment doesn't bind, so nothing trusts it" for p in w.pods if p.cluster is None)
    if not clusters:
        return None, unbound
    ec2 = (("statement", Block((("actions", ["sts:AssumeRole"]), ("principals", Block((
        ("type", "Service"), ("identifiers", ["ec2.amazonaws.com"]))))))),) if w.servers else ()
    pods = tuple(("statement", Block((
        ("actions", ["sts:AssumeRoleWithWebIdentity"]),
        ("principals", Block((("type", "Federated"),
                              ("identifiers", [ref(f"data.aws_iam_openid_connect_provider.{_eks(c)}.arn")])))),
        ("condition", Block((("test", "StringEquals"), ("variable", _issuer_key(c, "sub")),
                             ("values", [f"system:serviceaccount:{p.namespace}:{p.service_account}"
                                         for p in w.pods if p.cluster is not None and p.cluster.dn == c.dn])))),
        ("condition", Block((("test", "StringEquals"), ("variable", _issuer_key(c, "aud")),
                             ("values", ["sts.amazonaws.com"]))))))) for c in clusters)
    return block("data", ["aws_iam_policy_document", f"{n}_trust"], [*ec2, *pods]), unbound


def role(m, w, trust):
    """An identity's IAM role assumed under a trust policy (a document, or an expression giving one), and its
    least-privilege inline policy."""
    n, found = tf_name(w.identity_role), statements(m, w)
    policy = (block("resource", ["aws_iam_role_policy", n], [
        ("name", f"{w.name}-permissions"), ("role", ref(f"aws_iam_role.{n}.id")),
        ("policy", jsonencoded({"Version": "2012-10-17", "Statement": found}))]),) if found else ()
    return (block("resource", ["aws_iam_role", n], [
                ("name", w.name), ("assume_role_policy", jsonencoded(trust) if isinstance(trust, dict) else trust),
                ("tags", {"Principal": w.principal, "Role": w.identity_role, "ManagedBy": "opsdir"})]),
            *policy)

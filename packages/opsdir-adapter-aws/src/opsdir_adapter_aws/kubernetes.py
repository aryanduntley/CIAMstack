"""AWS for Kubernetes workloads: the IAM role a workload's service account assumes (EKS IAM roles for service accounts,
annotation eks.amazonaws.com/role-arn), and how the External Secrets Operator (provider aws, service SecretsManager)
and the Secrets Store CSI driver (AWS provider) read aws-sm:// references. Pure.

The role's ARN is the identity binding's provider ref when it is one, else built from the role name and the account
the cloud records (ciamAccountRef); without them it is UNBOUND. A reference by ARN names its region; any other is in
the cloud's region (ciamRegion). One SecretStore serves one region.
"""
from opsdir.core.contract import K8sIdentity, SecretDelivery
from opsdir.core.directory import one
from opsdir.core.environment import UNBOUND
from opsdir.core.interchange.yaml_text import dump
from .account import account_id

ROLE_ARN = "eks.amazonaws.com/role-arn"


def role_arn(m, binding):
    """The ARN of the IAM role an identity binding names in environment m, or UNBOUND:<role>-role-arn."""
    ref = one(binding, "ciamProviderRef") or ""
    if ref.startswith("arn:"):
        return ref
    name, account = ref.rsplit("/", 1)[-1], account_id(m)
    return f"arn:aws:iam::{account}:role/{name}" if name and account \
        else f"{UNBOUND}{one(binding, 'ciamBindingRole')}-role-arn"


def workload_identity(m, binding):
    """K8sIdentity: the service account annotation naming the IAM role (IRSA)."""
    return K8sIdentity(annotations=((ROLE_ARN, role_arn(m, binding)),), pod_labels=())


def region_of(rest):
    """The region an aws-sm reference names (its ARN's), or '' (the cloud's)."""
    parts = rest.split(":")
    return parts[3] if rest.startswith("arn:") and len(parts) > 3 else ""


def _region(m, key):
    return key or one(m.cloud, "ciamRegion") or f"{UNBOUND}aws-region"


def eso_provider(m, store, key, service_account, cluster):
    """SecretStore spec.provider: Secrets Manager in the reference's region, as the service account's IAM role."""
    return {"aws": {"service": "SecretsManager", "region": _region(m, key),
                    "auth": {"jwt": {"serviceAccountRef": {"name": service_account}}}}}


def eso_ref(rest):
    """remoteRef: the secret by name or ARN (its whole SecretString)."""
    return {"key": rest}


def csi_parameters(m, store, key, objects, identity):
    """SecretProviderClass parameters for the AWS provider: each secret as a secretsmanager object under its alias."""
    return {"region": _region(m, key), "usePodIdentity": "false",
            "objects": dump([{"objectName": rest, "objectType": "secretsmanager", "objectAlias": name}
                             for name, rest in objects])}


SECRET_DELIVERY = {"aws-sm": SecretDelivery(store_key=region_of, eso_provider=eso_provider, eso_ref=eso_ref,
                                            csi_provider="aws", csi_parameters=csi_parameters)}

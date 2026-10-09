"""Google Cloud for Kubernetes workloads: the Google service account a workload's Kubernetes service account acts as
(GKE Workload Identity Federation, annotation iam.gke.io/gcp-service-account), and how the External Secrets Operator
(provider gcpsm) and the Secrets Store CSI driver (Google provider, provider gcp) read gcp-sm:// references. Pure.

The service account's email is the identity binding's provider ref when it is one, else <name>@<project>.iam.
gserviceaccount.com with the project the cloud records (ciamAccountRef). The SecretStore authenticates as the
workload's service account through the cluster it runs in (its ciamCluster provider ref,
projects/<p>/locations/<l>/clusters/<name>; UNBOUND when the record doesn't hold it). One SecretStore serves one
project and location. GKE's managed Secret Manager add-on uses its own driver and provider name (gke): the upstream
driver and the Google provider are what this renders.
"""
import re

from opsdir.core.contract import K8sIdentity, SecretDelivery
from opsdir.core.directory import one
from opsdir.core.environment import UNBOUND
from opsdir.core.interchange.yaml_text import dump
from .account import project_id

SERVICE_ACCOUNT = "iam.gke.io/gcp-service-account"
_SECRET = re.compile(r"^projects/([^/]+)/(?:locations/([^/]+)/)?secrets/([^/]+)$")
_CLUSTER = re.compile(r"projects/([^/]+)/(?:locations|zones)/([^/]+)/clusters/([^/]+)$")


def service_account_email(m, binding):
    """The email of the Google service account an identity binding names in environment m, or UNBOUND."""
    ref = one(binding, "ciamProviderRef") or ""
    if "@" in ref:
        return ref
    name, project = ref.rsplit("/", 1)[-1], project_id(m)
    return f"{name}@{project}.iam.gserviceaccount.com" if name and project \
        else f"{UNBOUND}{one(binding, 'ciamBindingRole')}-service-account"


def workload_identity(m, binding):
    """K8sIdentity: the Kubernetes service account annotation naming the Google service account."""
    return K8sIdentity(annotations=((SERVICE_ACCOUNT, service_account_email(m, binding)),), pod_labels=())


def store_of(rest):
    """The project (and location, for a regional secret) a gcp-sm reference names: 'p' or 'p/l'."""
    found = _SECRET.match(rest)
    return "/".join(x for x in found.groups()[:2] if x) if found else ""


def cluster_parts(cluster):
    """(project, location, name) of a GKE cluster binding's provider ref (projects/<p>/locations/<l>/clusters/<n>),
    each None when the ref doesn't say."""
    found = _CLUSTER.search(one(cluster, "ciamProviderRef") or "") if cluster is not None else None
    return found.groups() if found else (None, None, None)


def eso_provider(m, store, key, service_account, cluster):
    """SecretStore spec.provider: Secret Manager in the reference's project (and location), as the workload's service
    account through its cluster."""
    project, _, location = key.partition("/")
    cluster_project, cluster_location, cluster_name = cluster_parts(cluster)
    return {"gcpsm": {"projectID": project or project_id(m) or f"{UNBOUND}gcp-project",
                      **({"location": location} if location else {}),
                      "auth": {"workloadIdentity": {
                          "clusterLocation": cluster_location or f"{UNBOUND}gke-cluster-location",
                          "clusterName": cluster_name or f"{UNBOUND}gke-cluster-name",
                          **({"clusterProjectID": cluster_project} if cluster_project and cluster_project != project
                             else {}),
                          "serviceAccountRef": {"name": service_account}}}}}


def eso_ref(rest):
    """remoteRef: the secret's name in its store's project, latest version."""
    found = _SECRET.match(rest)
    return {"key": found.group(3) if found else rest, "version": "latest"}


def csi_parameters(m, store, key, objects, identity):
    """SecretProviderClass parameters for the Google provider: each secret's latest version under its alias."""
    return {"secrets": dump([{"resourceName": f"{rest}/versions/latest", "path": name} for name, rest in objects])}


SECRET_DELIVERY = {"gcp-sm": SecretDelivery(store_key=store_of, eso_provider=eso_provider, eso_ref=eso_ref,
                                            csi_provider="gcp", csi_parameters=csi_parameters)}

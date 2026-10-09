"""The service accounts and IAM members Google Cloud renderers share: resource-level IAM members from the Google Cloud
permission table (opsdir_adapter_gcp.access) on the secret, the key, the bucket, the topic, and log writes on the
project (the narrowest Google Cloud allows), granted to a member (a service account, a group); notes for what can't be
granted. The platform's Terraform (workloads, terraform.py) and the landing zone's (deployers, operator groups,
landing.py) use them. Pure.
"""
import re

from opsdir.core.directory import one
from opsdir_adapter_gcp.names import name_parts
from opsdir_format_terraform.hcl import block, ref, tf_name
from .account import project_id
from .kubernetes import cluster_parts


def project_of(path):
    """The project argument of a resource in a resource name's project, or none."""
    return (("project", path["projects"]),) if "projects" in path else ()


def account(w):
    """A service account id from an identity's name: 6-30 characters, a lowercase letter first, no trailing hyphen."""
    return re.sub(r"[^a-z0-9-]", "-", w.name.lower())[:30].rstrip("-")


def notes(w):
    return tuple(f"# NOTE: principal {w.principal}: {note}" for note in w.notes)


def sa_member(n):
    return f"serviceAccount:${{google_service_account.{n}.email}}"


def member(n, permit, b, role, who):
    """The resource-level IAM member granting a role on a binding's resource to who (a service account, a group)."""
    name = f"{n}_{tf_name(permit)}"
    uri, storage, provider = one(b, "ciamRefUri", ""), one(b, "ciamStorageRef", ""), one(b, "ciamProviderRef", "")
    path = name_parts(uri.split("://", 1)[1] if "://" in uri else provider)
    if uri.startswith("gcp-sm://"):
        regional = "locations" in path
        return block("resource", ["google_secret_manager_regional_secret_iam_member" if regional else
                                  "google_secret_manager_secret_iam_member", name], [
            *project_of(path), *((("location", path["locations"]),) if regional else ()),
            ("secret_id", path.get("secrets")), ("role", role), ("member", who)])
    if uri.startswith("gcp-kms://"):
        return block("resource", ["google_kms_crypto_key_iam_member", name], [
            ("crypto_key_id", uri.split("://", 1)[1]), ("role", role), ("member", who)])
    if storage.startswith("gs://"):
        return block("resource", ["google_storage_bucket_iam_member", name], [
            ("bucket", storage[5:].split("/", 1)[0]), ("role", role), ("member", who)])
    if "topics" in path:
        return block("resource", ["google_pubsub_topic_iam_member", name], [
            *project_of(path), ("topic", path["topics"]), ("role", role), ("member", who)])
    project = re.match(r"^projects/([^/]+)", provider)
    return block("resource", ["google_project_iam_member", name], [
        ("#", "granted on the project: the narrowest scope Google Cloud allows for it"),
        ("project", project.group(1) if project else ref("var.project_id")), ("role", role), ("member", who)])


def members(w, who):
    """An identity's resource-level IAM members, one per permit, granted to who."""
    n = tf_name(w.identity_role)
    return tuple(member(n, permit, b, row.needs[0][0], who) for permit, b, row in w.grants)


def service_account(w):
    return block("resource", ["google_service_account", tf_name(w.identity_role)], [
        ("account_id", account(w)), ("display_name", f"{w.principal} ({w.identity_role})")])


def pod_members(m, w):
    """The Kubernetes service accounts that act as a workload identity (GKE Workload Identity Federation): a
    roles/iam.workloadIdentityUser member serviceAccount:<project>.svc.id.goog[<namespace>/<name>] each, the project
    the cluster's (its provider ref's, else the environment's); notes for those whose cluster isn't bound."""
    n = tf_name(w.identity_role)
    pool = lambda p: f"{cluster_parts(p.cluster)[0] or project_id(m) or ref('var.project_id')}.svc.id.goog"
    return (*(f"# NOTE: principal {w.principal}: service account {p.namespace}/{p.service_account} runs in a cluster "
              "this environment doesn't bind, so nothing trusts it" for p in w.pods if p.cluster is None),
            *(block("resource", ["google_service_account_iam_member",
                                 f"{n}_{tf_name(p.namespace)}_{tf_name(p.service_account)}"], [
                ("service_account_id", ref(f"google_service_account.{n}.name")),
                ("role", "roles/iam.workloadIdentityUser"),
                ("member", f"serviceAccount:{pool(p)}[{p.namespace}/{p.service_account}]")])
              for p in w.pods if p.cluster is not None))


def identity(m, w):
    """A workload principal's service account, the Kubernetes service accounts that act as it, and its
    resource-level IAM members."""
    return (*notes(w), service_account(w), *pod_members(m, w), *members(w, sa_member(tf_name(w.identity_role))))

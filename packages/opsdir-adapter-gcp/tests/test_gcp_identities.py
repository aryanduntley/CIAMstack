"""A workload's identity as Google Cloud Terraform: a service account and resource-level IAM members from the Google
Cloud permission table (a global and a regional secret, a key, a bucket, a topic), log writes on the project, and a
service account id Google accepts."""
from opsdir.core.directory import make_entry
from opsdir.domains.access.workloads import WorkloadIdentity
from opsdir_adapter_gcp.access import PERMISSIONS
from opsdir_adapter_gcp.identities import account as _account, identity as _identity

P = "projects/ciam-prod"


def _binding(cls, role, **attrs):
    return make_entry(f"cn={role},ou=bindings,env=prod", ("top", cls),
                      {"ciamBindingRole": [role], **{k: [v] for k, v in attrs.items()}})


def _row(verb, cls):
    return next(r for r in PERMISSIONS if r.verb == verb and r.binding_class == cls)


GRANTS = (("read-secret pf-admin-password", _binding("ciamSecretRef", "pf-admin-password",
                                                     ciamRefUri=f"gcp-sm://{P}/secrets/pf-admin-password"),
           _row("read-secret", "ciamSecretRef")),
          ("read-secret ds-tls", _binding("ciamSecretRef", "ds-tls",
                                          ciamRefUri=f"gcp-sm://{P}/locations/us-central1/secrets/ds-tls"),
           _row("read-secret", "ciamSecretRef")),
          ("use-key disk-encryption", _binding("ciamKeyRef", "disk-encryption",
                                               ciamRefUri=f"gcp-kms://{P}/locations/us-central1/keyRings/r/"
                                                          "cryptoKeys/k"),
           _row("use-key", "ciamKeyRef")),
          ("write-storage backup-target", _binding("ciamBackupTarget", "backup-target",
                                                   ciamStorageRef="gs://ciam-prod-ds-backups/ds"),
           _row("write-storage", "ciamObjectStore")),
          ("publish-stream audit-events", _binding("ciamStreamBinding", "audit-events", ciamStreamKind="topic",
                                                   ciamProviderRef=f"{P}/topics/ciam-audit"),
           next(r for r in PERMISSIONS if r.verb == "publish-stream")),
          ("write-logs audit-logs", _binding("ciamLogDestination", "audit-logs", ciamDestinationKind="log-group",
                                             ciamProviderRef=f"{P}/locations/global/buckets/ciam-audit"),
           _row("write-logs", "ciamLogDestination")))
W = WorkloadIdentity("pf-engine", "identity-pf-engine", "pf-engine", "ciam-prod-pf-engine", GRANTS, ())


def test_a_service_account_with_resource_level_members():
    out = "\n".join(_identity(None, W))
    member = 'member    = "serviceAccount:${google_service_account.identity_pf_engine.email}"'
    assert 'resource "google_service_account" "identity_pf_engine"' in out and member in out
    assert 'resource "google_secret_manager_secret_iam_member"' in out and 'secret_id = "pf-admin-password"' in out
    assert 'resource "google_secret_manager_regional_secret_iam_member"' in out and 'location  = "us-central1"' in out
    assert f'crypto_key_id = "{P}/locations/us-central1/keyRings/r/cryptoKeys/k"' in out
    assert 'bucket = "ciam-prod-ds-backups"' in out and 'role   = "roles/storage.objectCreator"' in out
    assert 'topic   = "ciam-audit"' in out and 'role    = "roles/pubsub.publisher"' in out
    assert 'resource "google_project_iam_member"' in out and 'project = "ciam-prod"' in out    # log writes


def test_service_account_ids_google_accepts():
    long = W._replace(name="ciam-production-identity-pingfederate-engine")
    assert _account(W) == "ciam-prod-pf-engine" and len(_account(long)) <= 30 and not _account(long).endswith("-")

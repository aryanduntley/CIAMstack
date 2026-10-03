"""Google Cloud IAM read as the record's permissions: a secret by its name or project, a bucket by its IAM name or a
project, project-level log writes, and the roles that grant access or impersonate."""
from types import SimpleNamespace

from opsdir.core.directory import make_entry
from opsdir.domains.access.grants import escalating, grant_of, granted
from opsdir_adapter_gcp.access import ACCESS

P = "projects/ciam-prod"
ENV = SimpleNamespace(bindings=(
    make_entry("cn=secret,ou=bindings,env=prod", ("top", "ciamSecretRef"),
               {"ciamBindingRole": ["pf-admin-password"], "ciamRefUri": [f"gcp-sm://{P}/secrets/pf-admin-password"]}),
    make_entry("cn=backup,ou=bindings,env=prod", ("top", "ciamBackupTarget"),
               {"ciamBindingRole": ["backup-target"], "ciamStorageRef": ["gs://ciam-prod-ds-backups"]}),
    make_entry("cn=audit,ou=bindings,env=prod", ("top", "ciamLogDestination"),
               {"ciamBindingRole": ["audit-logs"], "ciamDestinationKind": ["log-group"],
                "ciamProviderRef": [f"{P}/locations/global/buckets/ciam-audit"]})))


def _granted(permit, *grants):
    return granted(ACCESS, ENV, permit, tuple(grant_of(g) for g in grants))[0]


def test_permissions_through_the_gcp_table():
    assert _granted("read-secret pf-admin-password",
                    f"roles/secretmanager.secretAccessor on {P}/secrets/pf-admin-password")
    assert _granted("read-secret pf-admin-password", f"roles/secretmanager.secretAccessor on {P}")      # the project
    assert not _granted("read-secret pf-admin-password", "roles/secretmanager.secretAccessor on projects/other")
    assert _granted("write-storage backup-target",
                    "roles/storage.objectCreator on projects/_/buckets/ciam-prod-ds-backups")
    assert _granted("write-storage backup-target", f"roles/storage.objectAdmin on {P}")
    assert _granted("write-logs audit-logs", f"roles/logging.logWriter on {P}")          # broad: project-level


def test_roles_that_grant_access_or_impersonate():
    gs = tuple(grant_of(g) for g in (f"roles/editor on {P}", f"roles/iam.serviceAccountUser on {P}",
                                     f"roles/secretmanager.secretAccessor on {P}"))
    assert [g.action for g in escalating(ACCESS, gs)] == ["roles/editor", "roles/iam.serviceAccountUser"]


def test_managing_a_service_name_takes_its_load_balancer_and_zone():
    svc = make_entry("cn=svc-sso,ou=bindings,env=prod", ("top", "ciamServiceName"),
                     {"ciamBindingRole": ["pf-sso-service"], "ciamDnsZoneRef": ["example-aero-public"]})
    env = SimpleNamespace(bindings=(svc,))
    assert granted(ACCESS, env, "manage pf-sso-service", (grant_of(f"roles/compute.loadBalancerAdmin on {P}"),
                                                          grant_of(f"roles/dns.admin on {P}")))[0]
    assert not granted(ACCESS, env, "manage pf-sso-service", (grant_of(f"roles/compute.loadBalancerAdmin on {P}"),))[0]

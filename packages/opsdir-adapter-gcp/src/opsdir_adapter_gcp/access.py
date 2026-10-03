"""Google Cloud IAM as the record's neutral permissions: what each verb on a binding needs (predefined roles, any of a
requirement's alternatives; the first is what the renderer binds), the roles that let a principal raise its own
access, and how Google Cloud names a binding's resource (resource names; a role bound on a parent, a key ring or a
project, covers what is under it). Pure.

Sources: the Secret Manager, Cloud KMS, Cloud Storage, Pub/Sub and Cloud Logging access-control pages and the service
account permissions page (checked 2026-10-02, note 450). Log writes are granted on the project (roles/logging.
logWriter), so they are broad. A bucket's, a load balancer's or a DNS zone's project isn't in the record, so a
project-level grant is taken to cover it. `manage` means a secret's lifecycle, a service name's load balancer and DNS
zone, a managed instance group (the predefined roles are broad). A secret under a customer managed key needs nothing
of the key on the accessor's side: Secret Manager's service agent uses it. After the predefined roles, each requirement
names the IAM permission those roles carry, so a custom role's permissions can meet it and a deny policy denying that
permission denies it. A role bound on a folder or the organization is inherited by the environment's project (its
state was given for this environment), so it covers the environment's resources. Evaluator: Policy Troubleshooter
(gcloud policy-intelligence troubleshoot-policy iam: allow and deny policies) for each requirement's permission, for a
service account or user.
"""
import re

from opsdir.core.contract import AccessModel, Permission
from opsdir.core.directory import is_a, one, rdn_of, rdn_value
from opsdir.core.environment import environment_of
from opsdir.domains.access.evaluations import quoted
from opsdir.domains.access.grants import ALLOWED, DENIED, UNKNOWN, covered

SECRET, KEY, STORAGE, STREAM, LOGS = ("ciamSecretRef", "ciamKeyRef", "ciamBackupTarget", "ciamStreamBinding",
                                      "ciamLogDestination")
SERVICE, COMPUTE = "ciamServiceName", "ciamComputeGroup"
PERMISSIONS = (
    Permission("manage", SECRET, None, (("roles/secretmanager.admin", "secretmanager.secrets.delete"),), False),
    Permission("manage", SERVICE, None, (("roles/compute.loadBalancerAdmin", "compute.forwardingRules.update"),
                                         ("roles/dns.admin", "dns.changes.create")), True),
    Permission("manage", COMPUTE, None, (("roles/compute.instanceAdmin.v1", "compute.instanceGroupManagers.update"),),
               True),
    Permission("read-secret", SECRET, None, (("roles/secretmanager.secretAccessor", "roles/secretmanager.admin",
                                                 "secretmanager.versions.access"),), False),
    Permission("write-secret", SECRET, None, (("roles/secretmanager.secretVersionAdder",
                                               "roles/secretmanager.secretVersionManager",
                                               "roles/secretmanager.admin", "secretmanager.versions.add"),), False),
    Permission("use-key", KEY, None, (("roles/cloudkms.cryptoKeyEncrypterDecrypter", "roles/cloudkms.cryptoOperator",
                                       "cloudkms.cryptoKeyVersions.useToDecrypt"),), False),
    Permission("manage-key", KEY, None, (("roles/cloudkms.admin", "cloudkms.cryptoKeys.update"),), False),
    Permission("read-storage", STORAGE, None, (("roles/storage.objectViewer", "roles/storage.objectUser",
                                                "roles/storage.objectAdmin", "storage.objects.get"),), False),
    Permission("write-storage", STORAGE, None, (("roles/storage.objectCreator", "roles/storage.objectUser",
                                                 "roles/storage.objectAdmin", "storage.objects.create"),), False),
    Permission("publish-stream", STREAM, "topic", (("roles/pubsub.publisher", "roles/pubsub.editor",
                                                   "pubsub.topics.publish"),), False),
    Permission("consume-stream", STREAM, "topic", (("roles/pubsub.subscriber",
                                                   "pubsub.subscriptions.consume"),), False),
    Permission("write-logs", LOGS, None, (("roles/logging.logWriter", "roles/logging.bucketWriter",
                                           "logging.logEntries.create"),), True),
    Permission("read-logs", LOGS, None, (("roles/logging.viewer", "roles/logging.privateLogViewer",
                                          "logging.logEntries.list"),), True),
)
# Roles that let a principal grant access or act as another service account
ESCALATIONS = ("roles/owner", "roles/editor", "roles/iam.serviceAccountUser", "roles/iam.serviceAccountTokenCreator",
               "roles/iam.serviceAccountAdmin", "roles/iam.securityAdmin", "roles/resourcemanager.projectIamAdmin",
               "iam.serviceAccounts.actAs")
_PROJECT = re.compile(r"^projects/[^/]+$")
_ANCESTOR = re.compile(r"^(folders|organizations)/[^/]+$")


def resources(binding):
    """A binding's resource as IAM policies name it, most specific first (regional secrets keep their location)."""
    uri = one(binding, "ciamRefUri", "")
    if uri.startswith(("gcp-sm://", "gcp-kms://")):
        return (uri.split("://", 1)[1],)
    if one(binding, "ciamStorageRef", "").startswith("gs://"):
        return (f"projects/_/buckets/{one(binding, 'ciamStorageRef')[5:].split('/', 1)[0]}",)
    if is_a(binding, "ciamServiceName"):          # as the renderer names its forwarding rule, and its zone
        zone = one(binding, "ciamDnsZoneRef")
        return (f"projects/_/regions/*/forwardingRules/ciam-{rdn_of(environment_of(binding))}-{rdn_value(binding)}",
                *((f"projects/_/managedZones/{zone}",) if zone else ()))
    ref = one(binding, "ciamProviderRef", "")
    return (ref,) if ref.startswith("projects/") else ()


def covers(granted, binding):
    """A resource name covers a binding's when it is it or a parent of it (a key ring, a project); a project covers a
    bucket, whose project the record doesn't hold; a folder or the organization covers the environment's resources
    (inherited)."""
    names = resources(binding)
    return covered(granted, names) or bool(names and _ANCESTOR.match(granted)) or (
        bool(_PROJECT.match(granted)) and any(n.startswith("projects/_/") for n in names))   # project unknown here


# The service a resource name belongs to, for its full resource name (//<service>/<name>)
SERVICES = ((re.compile(r"/secrets/[^/]+$"), "secretmanager.googleapis.com"),
            (re.compile(r"/cryptoKeys/[^/]+$"), "cloudkms.googleapis.com"),
            (re.compile(r"^projects/_/buckets/[^/]+$"), "storage.googleapis.com"),
            (re.compile(r"/topics/[^/]+$"), "pubsub.googleapis.com"),
            (re.compile(r"/locations/[^/]+/buckets/[^/]+$"), "logging.googleapis.com"),
            (re.compile(r"/instanceGroupManagers/[^/]+$"), "compute.googleapis.com"))
VERDICTS = {"CAN_ACCESS": ALLOWED, "CANNOT_ACCESS": DENIED, "UNKNOWN_INFO": UNKNOWN, "UNKNOWN_CONDITIONAL": UNKNOWN}


def full_name(name):
    """A resource name as Policy Troubleshooter takes it (//<service>/<name>), or None for one it can't (a pattern,
    a project the record doesn't hold)."""
    service = next((svc for pattern, svc in SERVICES if pattern.search(name or "")), None)
    if service is None or "*" in name or (name.startswith("projects/_/") and service != "storage.googleapis.com"):
        return None
    return f"//{service}/{name}"


def evaluator(m, identity, binding, row):
    """Policy Troubleshooter's commands for one permission of a service account or user (not a group: it can't
    answer for one): each requirement's IAM permission on the binding's resource (allow and deny policies)."""
    names = resources(binding)
    resource = full_name(names[0]) if names else None
    if resource is None or one(identity, "ciamIdentityKind") == "group":
        return ()
    permissions = [next((a for a in reversed(alts) if not a.startswith("roles/")), None) for alts in row.needs]
    return tuple(quoted("gcloud", "policy-intelligence", "troubleshoot-policy", "iam", resource,
                        f"--principal-email={one(identity, 'ciamProviderRef')}", f"--permission={p}", "--format=json")
                 for p in permissions if p)


def troubleshooter_verdict(doc):
    """allowed, denied or unknown from Policy Troubleshooter's overallAccessState; None when it isn't one."""
    return VERDICTS.get(doc.get("overallAccessState")) if isinstance(doc, dict) else None


ACCESS = AccessModel(permissions=PERMISSIONS, escalations=ESCALATIONS, covers=covers,
                     resource=lambda binding: next(iter(resources(binding)), None), evaluator=evaluator)

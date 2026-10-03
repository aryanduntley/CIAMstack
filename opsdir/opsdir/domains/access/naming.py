"""Access domain vocabulary: where permission sets and principals live, the neutral verbs a permission is made of, and
the kinds of principals, identities, guardrails and access paths."""
from ...core.naming import branch

PERMISSION_SETS = branch("permission-sets")
PRINCIPALS = branch("principals")
# What a permission does to the resource a binding role names; the role's binding (a secret, a key, storage, a stream,
# a log destination, ...) says which resource, and each cloud adapter maps the pair to its own actions or roles.
VERBS = ("read-secret", "write-secret", "use-key", "manage-key", "read-storage", "write-storage", "publish-stream",
         "consume-stream", "write-logs", "read-logs", "manage")
PERMIT = f"^({'|'.join(VERBS)}) [a-z0-9][a-z0-9-]*$"             # read-secret pf-admin-password
PRINCIPAL_KINDS = ("workload", "deployer", "operator", "break-glass", "service")
IDENTITY_KINDS = ("role", "managed-identity", "service-account", "federated", "permission-set", "group", "user",
                  "other")
GUARDRAIL_KINDS = ("service-control", "resource-control", "policy-assignment", "deny-assignment", "org-constraint",
                   "other")
# What a guardrail prevents, named neutrally (ciamDenies); each cloud renders and reads back its own mechanism
DENIALS = ("region-escape", "public-storage", "audit-log-disable", "service-account-keys", "metadata-v1", "root-use",
           "key-deletion")
ACCESS_KINDS = ("workforce-sso", "session", "bastion", "iap", "vpn", "jit-elevation", "other")

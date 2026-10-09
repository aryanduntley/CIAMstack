"""HashiCorp Vault for Kubernetes workloads: how the External Secrets Operator (provider vault) and the Secrets Store
CSI driver (Vault provider) read vault:// references. Pure.

A reference is <mount>/<path> in a key/value engine, read as the field `value` (as `vault kv get -field=value` reads
it). What the reference doesn't say comes from the environment's secret store for the scheme (ciamSecretStore): the
Vault address (ciamStoreEndpoint), the Kubernetes auth role (ciamStoreAuthRole) and mount (ciamStoreAuthMount,
`kubernetes` when not recorded) and the engine version (ciamStoreKvVersion, 2 when not recorded); an address or role
the record doesn't hold is UNBOUND. One SecretStore serves one mount.
"""
from opsdir.core.contract import SecretDelivery
from opsdir.core.directory import one
from opsdir.core.environment import UNBOUND
from opsdir.core.interchange.yaml_text import dump

FIELD = "value"


def mount_of(rest):
    """The key/value mount a vault reference names (its first segment)."""
    return rest.split("/", 1)[0]


def _path(rest):
    return rest.split("/", 1)[1] if "/" in rest else ""


def _store(store, attr, missing):
    return (one(store, attr) if store is not None else None) or missing


def _version(store):
    return _store(store, "ciamStoreKvVersion", "2")


def eso_provider(m, store, key, service_account, cluster):
    """SecretStore spec.provider: the Vault server, the mount and engine version, Kubernetes auth as the workload's
    service account."""
    return {"vault": {"server": _store(store, "ciamStoreEndpoint", f"{UNBOUND}vault-address"), "path": key,
                      "version": f"v{_version(store)}",
                      "auth": {"kubernetes": {"mountPath": _store(store, "ciamStoreAuthMount", "kubernetes"),
                                              "role": _store(store, "ciamStoreAuthRole", f"{UNBOUND}vault-role"),
                                              "serviceAccountRef": {"name": service_account}}}}}


def eso_ref(rest):
    """remoteRef: the path under the mount, its `value` field."""
    return {"key": _path(rest), "property": FIELD}


def secret_path(store, rest):
    """The API path the CSI provider reads: <mount>/data/<path> for a version 2 engine, the reference otherwise."""
    return f"{mount_of(rest)}/data/{_path(rest)}" if _version(store) == "2" else rest


def csi_parameters(m, store, key, objects, identity):
    """SecretProviderClass parameters for the Vault provider: the server, the auth role and mount, each secret's
    `value` field under its alias."""
    return {"vaultAddress": _store(store, "ciamStoreEndpoint", f"{UNBOUND}vault-address"),
            "roleName": _store(store, "ciamStoreAuthRole", f"{UNBOUND}vault-role"),
            "vaultKubernetesMountPath": _store(store, "ciamStoreAuthMount", "kubernetes"),
            "objects": dump([{"objectName": name, "secretPath": secret_path(store, rest), "secretKey": FIELD}
                             for name, rest in objects])}


SECRET_DELIVERY = {"vault": SecretDelivery(store_key=mount_of, eso_provider=eso_provider, eso_ref=eso_ref,
                                           csi_provider="vault", csi_parameters=csi_parameters)}

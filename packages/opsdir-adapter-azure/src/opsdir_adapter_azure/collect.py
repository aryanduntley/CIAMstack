"""Azure collectors (`opsdir collect`, core.contract Collector): the exact Azure CLI calls whose outputs
azure/cli-inventory reads, and the Terraform state azure/terraform-state reads, for one environment, read-only. Pure:
the core runs them.

Every call is `az ... -o json` under the operator's own login. First `az account show`: its id must be the
subscription the cloud records (ciamAccountRef) and its environmentName the cloud's (AzureCloud, or
AzureUSGovernment when ciamCloudEnvironment is usgovernment); else nothing is read. The inventory follows the README's
script, scoped as it is: the environment's resource group (the network binding's ciamResourceGroup, else the
environment's), its virtual network (the network binding's provider ref), its region (the cloud's ciamRegion), the Key
Vaults its azkv:// references name and the storage accounts its azblob:// object stores name; the listings first,
then each listed item's details (record sets per DNS zone, keys per vault, functions per app, Front Door endpoints and
origins, firewall policy rule collection groups, PostgreSQL and MySQL parameters, backup policies and instances,
federated credentials). VPN connections are projected to what the importer reads (their shared keys are never
fetched); Key Vault secrets are listed by name only, never shown.

Terraform state: (a) by default the state blob a collection source names (ciamCollectionSource, importer
azure/terraform-state, ciamSourceRef azblob://<account>/<container>/<blob>, a workspace's blob as named), read with
`az storage blob download --auth-mode login` to standard output: no init, no lock, Storage Blob Data Reader on the
container; (b) with --terraform-dir, `terraform state pull` in that initialized working directory."""
import json

from opsdir.core.contract import Collector, Command
from opsdir.core.directory import one, values
from opsdir.core.environment import of_class, one_role
from opsdir.domains.governance.collection import collection_sources
from .account import subscription_id
from .storage import container_of

ARM = {"public": "https://management.azure.com", "usgovernment": "https://management.usgovcloudapi.net"}
CLOUD_NAMES = {"public": "AzureCloud", "usgovernment": "AzureUSGovernment"}
VPN_PROJECTION = ("[].{id: id, name: name, type: type, connectionType: connectionType, tags: tags, "
                  "localNetworkGateway2: localNetworkGateway2, virtualNetworkGateway1: virtualNetworkGateway1}")


def _az(*args, query=None):
    return Command(("az", *args, *(("--query", query) if query else ()), "-o", "json"))


def _list(done, path):
    """The items an `az ... list` output at path holds."""
    try:
        found = json.loads(done.get(path) or "[]")
    except ValueError:
        return []
    return [i for i in (found if isinstance(found, list) else ()) if isinstance(i, dict)]


def _names(done, path, *fields):
    return tuple(tuple(i.get(f) for f in fields) for i in _list(done, path))


def resource_group(m):
    """The resource group that scopes environment m's inventory: its network binding's, else the environment's."""
    net = one_role(m, "network")
    return (one(net, "ciamResourceGroup") if net is not None else None) or one(m.env, "ciamResourceGroup")


def recorded_vaults(m):
    """The Key Vaults environment m's azkv:// and azkv-key:// references name."""
    return tuple(dict.fromkeys(v.split("://", 1)[1].split("/", 1)[0] for b in m.bindings
                               for v in values(b, "ciamRefUri") if v.startswith(("azkv://", "azkv-key://"))))


def recorded_accounts(m):
    """The storage accounts environment m's object stores name."""
    return tuple(dict.fromkeys(c[0] for s in of_class(m, "ciamObjectStore")
                               for c in (container_of(one(s, "ciamStorageRef")),) if c))


def _arm(m):
    return ARM.get(one(m.cloud, "ciamCloudEnvironment") or "public", ARM["public"])


def _listings(m, rg, vnet):
    g = ("-g", rg)
    sub = subscription_id(m)
    return (
        ("vnets.json", _az("network", "vnet", "list", *g)),
        ("vms.json", _az("vm", "list", "-d", *g)),
        ("nics.json", _az("network", "nic", "list", *g)),
        ("lbs.json", _az("network", "lb", "list", *g)),
        ("public-ips.json", _az("network", "public-ip", "list", *g)),
        ("public-ip-prefixes.json", _az("network", "public-ip", "prefix", "list", *g)),
        ("nsgs.json", _az("network", "nsg", "list", *g)),
        ("nat-gateways.json", _az("network", "nat", "gateway", "list", *g)),
        ("disk-encryption-sets.json", _az("disk-encryption-set", "list", *g)),
        ("dns-zones.json", _az("network", "dns", "zone", "list", *g)),
        ("private-dns-zones.json", _az("network", "private-dns", "zone", "list", *g)),
        *((f"containers-{a}.json", _az("storage", "container-rm", "list", "--storage-account", a, *g))
          for a in recorded_accounts(m)),
        *((p, c) for v in recorded_vaults(m) for p, c in (
            (f"kv-secrets-{v}.json", _az("keyvault", "secret", "list", "--vault-name", v)),
            (f"kv-keys-{v}.json", _az("keyvault", "key", "list", "--vault-name", v)))),
        ("functionapps.json", _az("functionapp", "list", *g)),
        ("gateways.json", _az("network", "application-gateway", "list", *g)),
        ("waf-policies.json", _az("network", "application-gateway", "waf-policy", "list", *g)),
        ("ddos.json", _az("network", "ddos-protection", "list", *g)),
        ("traffic-manager.json", _az("network", "traffic-manager", "profile", "list", *g)),
        ("afd-profiles.json", _az("afd", "profile", "list", *g)),
        ("front-door-waf.json", _az("network", "front-door", "waf-policy", "list", *g)),
        ("forwarding-rulesets.json", _az("dns-resolver", "forwarding-ruleset", "list", *g)),
        ("route-tables.json", _az("network", "route-table", "list", *g)),
        ("private-endpoints.json", _az("network", "private-endpoint", "list", *g)),
        ("private-link-services.json", _az("network", "private-link-service", "list", *g)),
        ("firewalls.json", _az("network", "firewall", "list")),
        ("firewall-policies.json", _az("network", "firewall", "policy", "list")),
        *((("peerings.json", _az("network", "vnet", "peering", "list", *g, "--vnet-name", vnet)),) if vnet else ()),
        ("vpn-connections.json", _az("network", "vpn-connection", "list", *g, query=VPN_PROJECTION)),
        ("local-gateways.json", _az("network", "local-gateway", "list", *g)),
        ("vnet-gateways.json", _az("network", "vnet-gateway", "list", *g)),
        *((("flow-logs.json", _az("network", "watcher", "flow-log", "list", "--location", one(m.cloud, "ciamRegion"))),)
          if one(m.cloud, "ciamRegion") else ()),
        ("activity-log.json", _az("monitor", "diagnostic-settings", "subscription", "list")),
        ("postgres-servers.json", _az("postgres", "flexible-server", "list", *g)),
        ("mysql-servers.json", _az("mysql", "flexible-server", "list", *g)),
        ("disks.json", _az("disk", "list", *g)),
        ("backup-vaults.json", _az("dataprotection", "backup-vault", "list", *g)),
        ("locks.json", _az("lock", "list", *g)),
        ("identities.json", _az("identity", "list")),
        ("role-assignments.json", _az("role", "assignment", "list", "--all", "--include-inherited",
                                      "--include-groups")),
        ("role-definitions.json", _az("role", "definition", "list")),
        *((p, _az("rest", "--method", "get", "--url", f"{_arm(m)}/subscriptions/{sub}/providers/"
                                                       f"Microsoft.Authorization/{api}"))
          for p, api in (("pim-eligible.json", "roleEligibilityScheduleInstances?api-version=2020-10-01"),
                         ("deny-assignments.json", "denyAssignments?api-version=2022-04-01")) if sub),
        ("keyvaults.json", _az("keyvault", "list")),
        ("policy-assignments.json", _az("policy", "assignment", "list")),
        ("bastions.json", _az("network", "bastion", "list")))


def _details(m, rg, done):
    g = ("-g", rg)
    profiles = [n for (n,) in _names(done, "afd-profiles.json", "name")]
    return (
        *((f"dns-{z}.json", _az("network", "dns", "record-set", "list", *g, "-z", z))
          for (z,) in _names(done, "dns-zones.json", "name")),
        *((f"private-dns-{z}.json", _az("network", "private-dns", "record-set", "list", *g, "-z", z))
          for (z,) in _names(done, "private-dns-zones.json", "name")),
        *((p, c) for v in recorded_vaults(m) for (k,) in _names(done, f"kv-keys-{v}.json", "name") for p, c in (
            (f"kv-key-{k}.json", _az("keyvault", "key", "show", "--vault-name", v, "-n", k)),
            (f"kv-rotation-{k}.json", _az("keyvault", "key", "rotation-policy", "show", "--vault-name", v, "-n", k)))),
        *((f"functions-{a}.json", _az("functionapp", "function", "list", *g, "-n", a))
          for (a,) in _names(done, "functionapps.json", "name")),
        *((p, c) for prof in profiles for p, c in (
            (f"afd-{prof}-endpoints.json", _az("afd", "endpoint", "list", *g, "--profile-name", prof)),
            (f"afd-{prof}-security-policies.json", _az("afd", "security-policy", "list", *g, "--profile-name", prof)),
            (f"afd-{prof}-origin-groups.json", _az("afd", "origin-group", "list", *g, "--profile-name", prof)))),
        *((f"afd-{prof}-{og}-origins.json", _az("afd", "origin", "list", *g, "--profile-name", prof,
                                                "--origin-group-name", og))
          for prof in profiles for (og,) in _names(done, f"afd-{prof}-origin-groups.json", "name")),
        *((f"forwarding-rules-{rs}.json", _az("dns-resolver", "forwarding-rule", "list", *g, "--ruleset-name", rs))
          for (rs,) in _names(done, "forwarding-rulesets.json", "name")),
        *((f"pe-zones-{pe}.json", _az("network", "private-endpoint", "dns-zone-group", "list", *g,
                                      "--endpoint-name", pe))
          for (pe,) in _names(done, "private-endpoints.json", "name")),
        *((f"rule-collection-groups-{name}.json", _az("network", "firewall", "policy", "rule-collection-group",
                                                      "list", "-g", group, "--policy-name", name))
          for group, name in _names(done, "firewall-policies.json", "resourceGroup", "name") if group and name),
        *((f"postgres-parameters-{s}.json", _az("postgres", "flexible-server", "parameter", "list", *g,
                                                "--server-name", s))
          for (s,) in _names(done, "postgres-servers.json", "name")),
        *((f"mysql-parameters-{s}.json", _az("mysql", "flexible-server", "parameter", "list", *g, "--server-name", s))
          for (s,) in _names(done, "mysql-servers.json", "name")),
        *((p, c) for (v,) in _names(done, "backup-vaults.json", "name") for p, c in (
            (f"backup-policies-{v}.json", _az("dataprotection", "backup-policy", "list", *g, "--vault-name", v)),
            (f"backup-instances-{v}.json", _az("dataprotection", "backup-instance", "list", *g, "--vault-name", v)))),
        *((f"federated-{name}.json", _az("identity", "federated-credential", "list", "--identity-name", name,
                                         "-g", group))
          for name, group in _names(done, "identities.json", "name", "resourceGroup") if name and group),
        *((f"vault-{kv}.json", _az("keyvault", "show", "-n", kv))
          for (kv,) in _names(done, "keyvaults.json", "name") if kv in recorded_vaults(m)))


def _in_env(m, pairs):
    return tuple((f"{m.label}/{p}", c) for p, c in pairs)


def _local(m, done):
    base = f"{m.label}/"
    return {(p[len(base):] if p.startswith(base) else p): t for p, t in done.items()}


def inventory_steps(d, m, done, options):
    """The cli-inventory calls still to make (core.contract Collector.steps): the listings, then their items."""
    rg = resource_group(m)
    if not rg:
        return ()
    net = one_role(m, "network")
    vnet = one(net, "ciamProviderRef") if net is not None else None
    return _in_env(m, (*_listings(m, rg, vnet), *_details(m, rg, _local(m, done))))


def state_steps(d, m, done, options):
    """The terraform-state calls: `terraform state pull` in --terraform-dir, else each collection source's blob."""
    if options.get("terraform_dir"):
        return ((f"{m.label}/terraform.tfstate",
                 Command(("terraform", f"-chdir={options['terraform_dir']}", "state", "pull"))),)
    return tuple((f"{m.label}/{blob.rsplit('/', 1)[-1] or 'terraform.tfstate'}",
                  Command(("az", "storage", "blob", "download", "--account-name", account, "--container-name",
                           container, "--name", blob, "--auth-mode", "login", "-o", "none")))
                 for s in collection_sources(m, "azure/terraform-state") for loc in s.locations
                 if loc.startswith("azblob://")
                 for account, _, rest in (loc[len("azblob://"):].partition("/"),)
                 for container, _, blob in (rest.partition("/"),) if account and container and blob)


def identity_check(d, m):
    """`az account show`, and whether its id is the subscription the cloud records and its environmentName the
    cloud's (Azure Government when the cloud is in it)."""
    want, cloud = subscription_id(m), CLOUD_NAMES.get(one(m.cloud, "ciamCloudEnvironment") or "public")

    def check(out):
        try:
            seen = json.loads(out or "{}")
        except ValueError:
            seen = {}
        sub, env = seen.get("id"), seen.get("environmentName")
        if not want:
            return "the cloud records no subscription (ciamAccountRef) to check the login against"
        if sub != want:
            return f"signed in to subscription {sub}, the record names {want}"
        return None if env == cloud else f"signed in to cloud {env}, the record's is {cloud} (az cloud set)"
    return Command(("az", "account", "show", "-o", "json")), check


COLLECTORS = (Collector("cli-inventory", "environment", inventory_steps, identity_check),
              Collector("terraform-state", "environment", state_steps, identity_check))

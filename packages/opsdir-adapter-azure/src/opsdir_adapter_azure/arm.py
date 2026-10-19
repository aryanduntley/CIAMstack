"""What ARM templates and Bicep (compiled to ARM JSON) deploy into an environment, read into the record's neutral
resources. Pure.

One folder per deployment under <cloud>/<env>/ (any name; files directly in the environment folder are one
deployment), holding any of, recognized by shape:

  the template                                  $schema …deploymentTemplate.json, or contentVersion + resources:
                                                the repository's azuredeploy.json, `az bicep build --file main.bicep
                                                --stdout`, or `az deployment group export`
  az deployment group show -g RG -n NAME        the deployment: its subscription and resource group (from its ID), the
                                                parameter values it ran with, the resources it produced
  a parameters file                             $schema …deploymentParameters.json: parameter values
  az group show -n RG                           the resource group: its location (resourceGroup().location)

and, anywhere in the environment's folder, the Terraform state of a root kept beside the deployments (*.tfstate: what
an opsdir Bicep/ARM render keeps in Terraform, applied), read with them by the state reader's mapping, so one import
sees the whole environment.

A template's expressions are evaluated where they depend only on what the deployment knows: parameters (the
deployment's, else a parameters file's, else the template's defaults; secure parameters never), variables, concat,
format, resourceId (and the subscription, tenant and extension resource ids), subscription(), resourceGroup() (its
location when the group's `az group show` is given), equals, if, toLower, toUpper, string, replace, split, first, last,
and guid (a stable stand-in of its arguments, not ARM's own GUID: the names it makes, a role assignment's, are never
what the record matches on). reference() of a user-assigned identity gives only its principal, as the symbol
principal:<its ID>, which the identity's own principal is when the template doesn't say it: a grant joins its
user-assigned identity within the deployment (a system-assigned identity's principal stays unknown). Anything else (the
rest of reference, listKeys, uniqueString, copyIndex, …) is counted, and the record keeps its value for what it
computes. Built-in roles are named from the adapter's table of them (arm_types.ROLES), as the Terraform render looks
them up. Each resource (nested child resources included, `existing` references and conditions that evaluate false
excluded, and, when the deployment is given, only those it produced) is given its ARM ID where the deployment puts it
(a resource group's, the subscription's or the tenant's; an extension resource's, its scope, under the resource it
extends: Sentinel's onboarding and analytics rules under their workspace) and flattened into the shape the Azure CLI
prints (properties
merged into the resource, sub-resources given their IDs), so the CLI reader maps it
(opsdir_adapter_azure.cli.items_resources). A Key Vault secret's value is dropped before anything evaluates it.
"""
import json
import re
import uuid
from collections import Counter

from opsdir.core.contract import Importer
from opsdir.core.inventory import layout_import
from opsdir.core.sources import json_document
from .cli import items_pairs, kind_of
from .inventory import PROVIDER, pairs_resources, state_pairs
from .mtls_inventory import with_mtls_notices
from .sentinel import with_sentinel_choices
from .cli_backup import READ as BACKUP_TYPES
from .cli_database import READ as DATABASE_TYPES
from .cli_compute import READ as COMPUTE_TYPES
from .cli_disk import READ as DISK_TYPES
from .cli_edge import READ as EDGE_TYPES
from .cli_iam import READ as IAM_TYPES
from .cli_messaging import READ as MESSAGING_TYPES
from .cli_monitor import READ as MONITOR_TYPES
from .cli_budgets import READ as BUDGET_TYPES
from .cli_security import READ as SECURITY_TYPES
from .cli_storage import READ as STORAGE_TYPES
from .audit import READ as AUDIT_TYPES
from .cli_network import TYPES as NETWORK_TYPES
from .arm_ids import arm_segment
from .arm_types import ROLES

EVALUATED = ("parameters", "variables", "concat", "format", "resourceId", "subscriptionResourceId", "tenantResourceId",
             "extensionResourceId", "subscription", "resourceGroup", "equals", "if", "toLower", "toUpper", "string",
             "replace", "split", "first", "last", "guid")
ACCOUNT_WIDE = ("secret", "key", "storage", "job")
READ_TYPES = ("microsoft.network/virtualnetworks", "microsoft.network/virtualnetworks/subnets",
              "microsoft.compute/virtualmachines", "microsoft.network/networkinterfaces",
              "microsoft.network/loadbalancers", "microsoft.network/publicipaddresses",
              "microsoft.network/publicipprefixes", "microsoft.network/dnszones/a",
              "microsoft.network/privatednszones/a",
              "microsoft.network/networksecuritygroups", "microsoft.network/networksecuritygroups/securityrules",
              "microsoft.network/natgateways", "microsoft.compute/diskencryptionsets",
              "microsoft.storage/storageaccounts/blobservices/containers", "microsoft.keyvault/vaults/secrets",
              "microsoft.keyvault/vaults/keys", "microsoft.web/sites", "microsoft.web/sites/functions",
              *(t.lower() for t in NETWORK_TYPES), *DATABASE_TYPES, *STORAGE_TYPES, *DISK_TYPES,
              *BACKUP_TYPES, *AUDIT_TYPES, *EDGE_TYPES, *IAM_TYPES,
              *MONITOR_TYPES, *SECURITY_TYPES, *BUDGET_TYPES, *COMPUTE_TYPES, *MESSAGING_TYPES)
PLACEHOLDER = ("unknown-subscription", "unknown-group")   # IDs without a deployment: links within it still resolve
SUB_RESOURCES = ("subnets", "ipConfigurations", "frontendIPConfigurations", "backendAddressPools",
                 "loadBalancingRules", "probes", "securityRules", "routes", "privateLinkServiceConnections",
                 "manualPrivateLinkServiceConnections", "privateDnsZoneConfigs", "frontendPorts",
                 "backendHttpSettingsCollection", "httpListeners", "requestRoutingRules", "sslCertificates",
                 "gatewayIPConfigurations", "trustedClientCertificates", "sslProfiles", "rewriteRuleSets")
_UNKNOWN = ("<unknown>",)          # what an expression is when it depends on something the deployment doesn't know
_TOKEN = re.compile(r"\s*(?:(\d+)|'((?:[^']|'')*)'|([A-Za-z_][A-Za-z0-9_]*)|(\S))")
_CALL = re.compile(r"([A-Za-z_][A-Za-z0-9_]*)\s*\(")
_GUIDS = uuid.UUID("2d1f6c0a-6b1e-4a43-9d2e-7c3f1b5a8e90")      # guid()'s stand-in namespace
IDENTITIES = "microsoft.managedidentity/userassignedidentities"
DEPLOYMENTS = "microsoft.resources/deployments"


# ------------------------------------------------------------------ expressions
def _tokens(text):
    """(kind, value) tokens of an ARM expression: num, str, name, or punctuation."""
    groups = [m.groups() for m in _TOKEN.finditer(text)]    # unmatched groups are None ('' is an empty string)
    return tuple(("num", int(n)) if n else ("str", q.replace("''", "'")) if q is not None else
                 ("name", w) if w else ("p", p) for n, q, w, p in groups if (n, q, w, p) != (None,) * 4)


def _call(name, args, ctx):
    if _UNKNOWN in args and name not in ("if",):
        return _UNKNOWN
    if name == "parameters":
        return ctx["parameters"].get(args[0], _UNKNOWN)
    if name == "variables":
        return evaluate(ctx["variables"].get(args[0], _UNKNOWN), ctx) if args[0] in ctx["variables"] else _UNKNOWN
    if name == "concat":
        return [x for a in args for x in a] if args and all(isinstance(a, list) for a in args) else \
            "".join(str(a) for a in args)
    if name == "format":
        return re.sub(r"\{(\d+)(?::[^}]*)?\}", lambda m: str(args[1 + int(m.group(1))]), args[0])
    if name == "resourceId":
        return _resource_id(args, ctx)
    if name == "guid":
        return str(uuid.uuid5(_GUIDS, "-".join(str(a) for a in args)))
    if name == "reference":
        return {"principalId": f"principal:{args[0]}"} \
            if isinstance(args[0], str) and f"/providers/{IDENTITIES}/" in args[0].lower() else _UNKNOWN
    if name in ("subscriptionResourceId", "tenantResourceId", "extensionResourceId"):
        return _scoped_id(name, args, ctx)
    if name == "subscription":
        return {"subscriptionId": ctx["subscription"], "id": f"/subscriptions/{ctx['subscription']}"} \
            if ctx["subscription"] else _UNKNOWN
    if name == "resourceGroup":
        return {"name": ctx["group"], "id": f"/subscriptions/{ctx['subscription']}/resourceGroups/{ctx['group']}",
                **({"location": ctx["location"]} if ctx.get("location") else {})} \
            if ctx["group"] and ctx["subscription"] else _UNKNOWN
    simple = {"equals": lambda a: a[0] == a[1], "toLower": lambda a: str(a[0]).lower(),
              "toUpper": lambda a: str(a[0]).upper(),
              "string": lambda a: a[0] if isinstance(a[0], str) else json.dumps(a[0]),
              "replace": lambda a: str(a[0]).replace(a[1], a[2]), "split": lambda a: str(a[0]).split(a[1]),
              "first": lambda a: a[0][0], "last": lambda a: a[0][-1]}
    if name == "if":
        return _UNKNOWN if args[0] is _UNKNOWN or not isinstance(args[0], bool) else (args[1] if args[0] else args[2])
    return simple[name](args) if name in simple else _UNKNOWN


def _resource_id(args, ctx):
    """resourceId([subscription], [group], type, name…) as an ARM ID."""
    at = next((i for i, a in enumerate(args) if isinstance(a, str) and "/" in a and "." in a.split("/")[0]), None)
    if at is None:
        return _UNKNOWN
    here = (ctx["subscription"] or PLACEHOLDER[0], ctx["group"] or PLACEHOLDER[1])
    sub, group = (here, (here[0], args[0]), (args[0], args[1]))[min(at, 2)]
    return arm_id(sub, group, args[at], [str(n) for n in args[at + 1:]])


def _provider_path(type_, names):
    """providers/<namespace>/<type>/<name>[/<child type>/<child name>…] of a full type and its name segments."""
    namespace, *types = type_.split("/")
    return f"providers/{namespace}/" + "/".join(f"{t}/{n}" for t, n in zip(types, names))


def _scoped_id(name, args, ctx):
    """subscriptionResourceId([subscription], type, name…), tenantResourceId(type, name…) and
    extensionResourceId(resource id, type, name…) as ARM IDs."""
    if name == "extensionResourceId":
        return f"{str(args[0]).rstrip('/')}/{_provider_path(args[1], [str(n) for n in args[2:]])}" \
            if len(args) > 2 else _UNKNOWN
    at = next((i for i, a in enumerate(args) if isinstance(a, str) and "/" in a and "." in a.split("/")[0]), None)
    if at is None:
        return _UNKNOWN
    path = _provider_path(args[at], [str(n) for n in args[at + 1:]])
    if name == "tenantResourceId":
        return f"/{path}"
    sub = args[0] if at == 1 else ctx["subscription"] or PLACEHOLDER[0]
    if str(args[at]).lower() == "microsoft.resources/resourcegroups" and len(args) > at + 1:
        return f"/subscriptions/{sub}/resourceGroups/{args[at + 1]}"           # a group's id has no providers/ part
    return f"/subscriptions/{sub}/{path}"


def _parse(tokens, i, ctx):
    """(value, next index) of the expression starting at tokens[i]."""
    kind, value = tokens[i]
    if kind in ("num", "str"):
        return _postfix(value, tokens, i + 1, ctx)
    if kind == "name" and i + 1 < len(tokens) and tokens[i + 1] == ("p", "("):
        args, j = _args(tokens, i + 2, ctx)
        return _postfix(_call(value, args, ctx), tokens, j, ctx)
    if kind == "name":
        return _postfix({"true": True, "false": False, "null": None}.get(value, _UNKNOWN), tokens, i + 1, ctx)
    return _UNKNOWN, i + 1


def _args(tokens, i, ctx):
    if tokens[i] == ("p", ")"):
        return (), i + 1
    value, j = _parse(tokens, i, ctx)
    if tokens[j] == ("p", ","):
        rest, k = _args(tokens, j + 1, ctx)
        return (value, *rest), k
    return (value,), j + 1


def _postfix(value, tokens, i, ctx):
    """Property access (.name) and indexing ([expr]) after a value."""
    if i < len(tokens) and tokens[i] == ("p", "."):
        name = tokens[i + 1][1]
        return _postfix(value.get(name, _UNKNOWN) if isinstance(value, dict) else _UNKNOWN, tokens, i + 2, ctx)
    if i < len(tokens) and tokens[i] == ("p", "["):
        index, j = _parse(tokens, i + 1, ctx)
        got = (value[index] if isinstance(value, list) and isinstance(index, int) and index < len(value) else
               value.get(index, _UNKNOWN) if isinstance(value, dict) else _UNKNOWN)
        return _postfix(got, tokens, j + 1, ctx)
    return value, i


def evaluate(v, ctx):
    """A template value with its expressions ("[…]") evaluated; _UNKNOWN parts where they can't be."""
    if isinstance(v, list):
        return [evaluate(x, ctx) for x in v]
    if isinstance(v, dict):
        return {k: evaluate(x, ctx) for k, x in v.items()}
    if isinstance(v, str) and v.startswith("[["):
        return v[1:]
    if isinstance(v, str) and v.startswith("[") and v.endswith("]"):
        try:
            return _parse(_tokens(v[1:-1]), 0, ctx)[0]
        except (IndexError, KeyError, TypeError, ValueError, RecursionError):
            return _UNKNOWN
    return v


def _known(v):
    """A value with unknown parts as None (the record keeps what they would have set)."""
    if v is _UNKNOWN:
        return None
    if isinstance(v, list):
        return [_known(x) for x in v]
    return {k: _known(x) for k, x in v.items()} if isinstance(v, dict) else v


def unevaluated(template):
    """Counter of the functions template expressions use that aren't evaluated."""
    def walk(v):
        if isinstance(v, list):
            return sum((walk(x) for x in v), Counter())
        if isinstance(v, dict):
            return sum((walk(x) for x in v.values()), Counter())
        if isinstance(v, str) and v.startswith("[") and not v.startswith("[["):
            return Counter(f for f in _CALL.findall(v) if f not in EVALUATED)
        return Counter()
    return walk(_top(template))


# ------------------------------------------------------------------ resources
def arm_id(subscription, group, type_, names):
    """/subscriptions/<s>/resourceGroups/<g>/providers/<namespace>/<type>/<name>[/<child type>/<child name>…]."""
    namespace, *types = type_.split("/")
    return f"/subscriptions/{subscription}/resourceGroups/{group}/providers/{namespace}/" + \
        "/".join(f"{t}/{n}" for t, n in zip(types, names))


def _id_in(ctx, type_, names):
    """A resource's ARM ID where the deployment puts it: under its resource group; at its subscription, or the tenant,
    for a deployment there; under placeholders without a deployment (links within it still resolve)."""
    if ctx.get("scope") is not None and not ctx["group"]:
        return f"{ctx['scope']}/{_provider_path(type_, names)}"
    return arm_id(ctx["subscription"] or PLACEHOLDER[0], ctx["group"] or PLACEHOLDER[1], type_, names)


def _resource_id_of(r, ctx):
    """An evaluated resource's ARM ID: an extension resource's (its scope evaluated to an ID: Sentinel's onboarding and
    rules on a workspace, a role assignment, a lock) under the resource it extends, as Azure gives it; else _id_in."""
    names = r["name"].split("/")
    scope = r.get("scope")
    return f"{scope.rstrip('/')}/{_provider_path(r['type'], names)}" \
        if isinstance(scope, str) and scope.startswith("/") else _id_in(ctx, r["type"], names)


def _top(template):
    """The template's top-level resources as a list (symbolic-name templates hold them in an object)."""
    given = template.get("resources") or []
    return [r for r in (given.values() if isinstance(given, dict) else given) if isinstance(r, dict)]


def _expand(r, parent=None):
    """An evaluated resource and its nested child resources, each with its full type and name."""
    full = r if parent is None else {**r, "type": f"{parent.get('type')}/{r.get('type')}",
                                     "name": f"{parent.get('name')}/{r.get('name')}"}
    return [full, *(x for c in full.get("resources") or () if isinstance(c, dict) and not c.get("existing")
                    for x in _expand(c, full))]


def _without_secret_values(r, parent_type=""):
    """A resource with the value of every Key Vault secret in it (itself or nested) dropped, before evaluation."""
    type_ = f"{parent_type}/{r.get('type')}" if parent_type else str(r.get("type", ""))
    props = r.get("properties") if isinstance(r.get("properties"), dict) else {}
    secret = type_.lower().endswith("vaults/secrets") or type_.lower() == "microsoft.keyvault/vaults/secrets"
    return {**r, **({"properties": {k: v for k, v in props.items() if k != "value"}} if secret else {}),
            **({"resources": [_without_secret_values(c, type_) for c in r["resources"] if isinstance(c, dict)]}
               if isinstance(r.get("resources"), list) else {})}


def _flatten(item, rid):
    """A resource or sub-resource in the Azure CLI's shape: properties merged in, sub-resources given IDs; a reference
    to one (only its id: an SSL profile's trusted client certificates) kept as it is."""
    merged = {**{k: v for k, v in item.items() if k != "properties"}, **(item.get("properties") or {}), "id": rid}
    return {k: ([_flatten(s, f"{rid}/{k}/{s.get('name')}") if isinstance(s, dict) and set(s) != {"id"} else s
                 for s in v]
                if k in SUB_RESOURCES and isinstance(v, list) else v) for k, v in merged.items()}


def _principal(item):
    """A managed identity with the principal the template doesn't say as reference() gives it (principal:<its ID>)."""
    return {**item, "principalId": item.get("principalId") or f"principal:{item['id']}"} \
        if str(item.get("type", "")).lower() == IDENTITIES else item


def _vault_item(r, rid):
    """Key Vault secrets and keys as the CLI's data-plane objects: name and tags only for a secret (never its value)."""
    vault, name = r["name"].split("/")[0], r["name"].split("/")[-1]
    url = f"https://{vault}.vault.azure.net/{'secrets' if r['type'].lower().endswith('/secrets') else 'keys'}/{name}"
    props = r.get("properties") or {}
    if r["type"].lower().endswith("/secrets"):
        return [{"id": url, "name": name, "tags": r.get("tags") or {}}]
    return [{"kid": url, "name": name, "tags": r.get("tags") or {}, "key": {"kid": url, "kty": props.get("kty")}},
            *([{"id": f"{url}/rotationpolicy", "lifetimeActions": props["rotationPolicy"].get("lifetimeActions") or []}]
              if isinstance(props.get("rotationPolicy"), dict) else [])]


def _parameters(declared, given, base):
    """A deployment's parameter values: given (else declared defaults), secure ones never."""
    secure = {k for k, v in declared.items() if str((v or {}).get("type", "")).lower().startswith("secure")}
    defaults = {k: evaluate((v or {}).get("defaultValue", _UNKNOWN), base) for k, v in declared.items()}
    return {k: _UNKNOWN if k in secure else given.get(k, defaults.get(k, _UNKNOWN)) for k in {*declared, *given}}


def _nested(r, ctx):
    """(template, context) of a nested deployment with its own expression scope (a Bicep module: its template inline,
    its parameters and the subscription and resource group it deploys into evaluated where it is declared), else
    None."""
    props = r.get("properties") if isinstance(r.get("properties"), dict) else {}
    if str(r.get("type", "")).lower() != DEPLOYMENTS or not isinstance(props.get("template"), dict) or \
            (props.get("expressionEvaluationOptions") or {}).get("scope") != "inner":
        return None
    template = props["template"]
    where = {k: _known(evaluate(r[k], ctx)) if k in r else ctx[c] for k, c in (("subscriptionId", "subscription"),
                                                                              ("resourceGroup", "group"))}
    base = {"subscription": where["subscriptionId"] if isinstance(where["subscriptionId"], str) else None,
            "group": where["resourceGroup"] if isinstance(where["resourceGroup"], str) else None, "scope": None,
            "location": None, "variables": template.get("variables") or {}, "parameters": {}}
    given = {k: evaluate((v or {}).get("value", _UNKNOWN), ctx) for k, v in (props.get("parameters") or {}).items()}
    return template, {**base, "parameters": _parameters(template.get("parameters") or {}, given, base)}


def _items(template, ctx, produced):
    """(kind, item) of each resource the deployment declares (and, when known, produced), in the CLI's shape; counts
    of resources not deployed and not produced; Counter of types not read. Without a deployment, disk encryption sets
    are skipped: their ID (a key's ciamProviderRef) would carry placeholders. A nested deployment with its own
    expression scope (a module) is read as its own template where it deploys (_nested)."""
    tops = [r for r in _top(template) if not r.get("existing")]
    nested = [n for r in tops for n in (_nested(r, ctx),) if n]
    inner = [_items(t, c, produced) for t, c in nested]
    own = _own_items([r for r in tops if _nested(r, ctx) is None], ctx, produced)
    return ([*own[0], *(i for x in inner for i in x[0])], own[1] + sum(x[1] for x in inner),
            own[2] + sum(x[2] for x in inner), sum((x[3] for x in inner), own[3]))


def _own_items(tops, ctx, produced):
    """_items of a template's own (not nested) resources."""
    found = [x for r in tops for x in _expand(_known(evaluate(_without_secret_values(r), ctx)))]
    kept = [r for r in found if r.get("condition", True) is not False and isinstance(r.get("name"), str)
            and isinstance(r.get("type"), str) and "None" not in r["name"].split("/")]
    ids = [(r, _resource_id_of(r, ctx)) for r in kept]
    live = [(r, rid) for r, rid in ids if produced is None or rid.lower() in produced]
    read = [(r, rid) for r, rid in live if r["type"].lower() in READ_TYPES
            and (ctx["subscription"] or r["type"].lower() != "microsoft.compute/diskencryptionsets")]
    items = [i for r, rid in read for i in (_vault_item(r, rid) if r["type"].lower().startswith("microsoft.keyvault/")
                                            else [_principal({**_flatten(r, rid), "name": r["name"].split("/")[-1]})])]
    return ([(kind_of(i), i) for i in items if kind_of(i)], len(found) - len(kept), len(ids) - len(live),
            Counter(r["type"] for r, _ in live if r["type"].lower() not in READ_TYPES))


# ------------------------------------------------------------------ a deployment folder
def _documents(texts):
    """({folder: {"template": …, "deployment": …, "parameters": …}}, notices): each folder's documents by shape."""
    def kind(doc):
        if not isinstance(doc, dict):
            return None
        schema = str(doc.get("$schema", "")).lower()
        if "deploymentparameters" in schema:
            return "parameters"
        if "deploymenttemplate" in schema or ("resources" in doc and "contentVersion" in doc):
            return "template"
        if "/deployments/" in str(doc.get("id", "")).lower() and isinstance(doc.get("properties"), dict):
            return "deployment"
        if str(doc.get("type", "")).lower() == "microsoft.resources/resourcegroups":
            return "group"
        return None
    found = [(p.rsplit("/", 1)[0] if "/" in p else "", p, json_document(t)) for p, t in sorted(texts.items())]
    typed = [(f, p, kind(doc), doc) for f, p, doc in found]
    folders = dict.fromkeys(f for f, _, k, _ in typed if k)
    return ({f: {k: doc for f2, _, k, doc in typed if f2 == f and k} for f in folders},
            tuple(f"{p}: not an ARM template, deployment or parameters file; not read"
                  for _, p, k, _ in typed if not k))


def _context(folder):
    """What a deployment's expressions can know: subscription, resource group, parameters, variables."""
    template, deployment = folder["template"], folder.get("deployment") or {}
    rid = deployment.get("id", "")
    given = {**{k: (v or {}).get("value", _UNKNOWN) for k, v in ((folder.get("parameters") or {}).get("parameters")
                                                                  or {}).items()},
             **{k: (v or {}).get("value", _UNKNOWN) for k, v in
                ((deployment.get("properties") or {}).get("parameters") or {}).items()}}
    at = rid.lower().find("/providers/microsoft.resources/deployments/")
    base = {"subscription": arm_segment(rid, "subscriptions"), "group": arm_segment(rid, "resourceGroups"),
            "scope": rid[:at] if at >= 0 else None,
            "location": (folder.get("group") or {}).get("location"),
            "variables": template.get("variables") or {}, "parameters": {}}
    return {**base, "parameters": _parameters(template.get("parameters") or {}, given, base)}


def deployment_outputs(folder):
    """{output name: value} of a deployment folder's template outputs that evaluate (what a deployer passes on)."""
    ctx = _context(folder)
    values = {k: _known(evaluate((o or {}).get("value"), ctx)) for k, o in (folder["template"].get("outputs")
                                                                           or {}).items()}
    return {k: v for k, v in values.items() if v is not None}


def deployment_items(folder, label):
    """((kind, item) pairs, notices) of one deployment folder."""
    ctx = _context(folder)
    outputs = ((folder.get("deployment") or {}).get("properties") or {}).get("outputResources")
    produced = {o.get("id", "").lower() for o in outputs} if outputs is not None else None
    items, excluded, not_produced, types = _items(folder["template"], ctx, produced)
    missing = unevaluated(folder["template"])
    return items, (
        *((f"{label}: no deployment (az deployment group show): subscription and resource group unknown; links "
           f"within the template resolve, disk encryption sets aren't read",) if not ctx["subscription"] else ()),
        *((f"{label}: {', '.join(f'{f} ({n})' for f, n in sorted(missing.items()))} not evaluated; the attributes "
           f"computed with them keep the record's values",) if missing else ()),
        *((f"{label}: {excluded} resource(s) not deployed (condition false, or a name that isn't evaluated)",)
          if excluded else ()),
        *((f"{label}: {not_produced} declared resource(s) the deployment didn't produce",) if not_produced else ()),
        *((f"{label}: resource types not read: {', '.join(f'{t} ({n})' for t, n in sorted(types.items()))}",)
          if types else ()))


def arm_pairs(texts):
    """((Terraform resource type, attributes) pairs, notices) of an environment's deployment folders ({path within the
    folder: text}), with the Terraform state of a root kept beside them (*.tfstate: what a Bicep/ARM render keeps in
    Terraform), read together as one environment."""
    folders, unknown = _documents({p: t for p, t in texts.items() if not p.endswith(".tfstate")})
    states = tuple(state_pairs(t) for p, t in sorted(texts.items()) if p.endswith(".tfstate"))
    read = [deployment_items(docs, f or ".") for f, docs in folders.items() if docs.get("template")]
    item_pairs, scope_notices = items_pairs([i for items, _ in read for i in items])
    roles = [("azurerm_role_definition", {"id": f"/providers/Microsoft.Authorization/roleDefinitions/{g}",
                                          "role_definition_id": g, "name": n}) for n, g in ROLES.items()]
    return ([*item_pairs, *roles, *(p for pairs, _ in states for p in pairs)],
            (*unknown, *(f"{f or '.'}: no template (the template file, `az bicep build` output, or "
                         f"`az deployment group export`); not read"
                         for f, docs in folders.items() if not docs.get("template")),
             *(n for _, ns in read for n in ns), *(n for _, ns in states for n in ns), *scope_notices))


def arm_resources(texts):
    """(resources, notices) of an environment's deployment folders and the Terraform state kept beside them
    (arm_pairs), read by the state reader's mapping."""
    pairs, notices = arm_pairs(texts)
    resources, read_notices = pairs_resources(pairs)
    return resources, (*notices, *read_notices)


def read_arm(files, d, patterns, at=None):
    """Imported: each environment's servers and bindings from its ARM/Bicep deployments under <cloud>/<env>/<name>/,
    with what its edge runs of the record's edge trust policies checked against them (mtls_inventory), and each
    Sentinel analytics rule's choices exactly its source's (sentinel.with_sentinel_choices)."""
    pairs = lambda texts: arm_pairs(texts)[0]  # noqa: E731
    return with_sentinel_choices(with_mtls_notices(layout_import(
        files, d, PROVIDER, "Azure", arm_resources, (".json", ".tfstate"), "ARM deployment",
        "network/azuredeploy.json", summarize=ACCOUNT_WIDE), files, d, (".json", ".tfstate"), pairs),
        files, (".json", ".tfstate"), pairs)


ARM = Importer("arm", "ARM templates and Bicep (compiled to ARM JSON) with their deployments, one folder per "
                      "deployment under <cloud>/<env>/, as the environment's servers and bindings", read_arm)

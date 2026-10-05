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

A template's expressions are evaluated where they depend only on what the deployment knows: parameters (the
deployment's, else a parameters file's, else the template's defaults; secure parameters never), variables, concat,
format, resourceId, subscription(), resourceGroup(), equals, if, toLower, toUpper, string, replace, split, first,
last. Anything else (reference, listKeys, uniqueString, copyIndex, …) is counted, and the record keeps its value for
what it computes. Each resource (nested child resources included, `existing` references and conditions that evaluate
false excluded, and, when the deployment is given, only those it produced) is given its ARM ID and flattened into the
shape the Azure CLI prints (properties merged into the resource, sub-resources given their IDs), so the CLI reader
maps it (opsdir_adapter_azure.cli.items_resources). A Key Vault secret's value is dropped before anything evaluates it.
"""
import json
import re
from collections import Counter

from opsdir.core.contract import Importer
from opsdir.core.inventory import layout_import
from opsdir.core.sources import json_document
from .cli import items_resources, kind_of
from .cli_network import TYPES as NETWORK_TYPES
from .arm_ids import arm_segment
from .inventory import PROVIDER

EVALUATED = ("parameters", "variables", "concat", "format", "resourceId", "subscription", "resourceGroup", "equals",
             "if", "toLower", "toUpper", "string", "replace", "split", "first", "last")
ACCOUNT_WIDE = ("secret", "key", "storage", "job")
READ_TYPES = ("microsoft.network/virtualnetworks", "microsoft.network/virtualnetworks/subnets",
              "microsoft.compute/virtualmachines", "microsoft.network/networkinterfaces",
              "microsoft.network/loadbalancers", "microsoft.network/publicipaddresses",
              "microsoft.network/publicipprefixes", "microsoft.network/dnszones/a", "microsoft.network/privatednszones/a",
              "microsoft.network/networksecuritygroups", "microsoft.network/networksecuritygroups/securityrules",
              "microsoft.network/natgateways", "microsoft.compute/diskencryptionsets",
              "microsoft.storage/storageaccounts/blobservices/containers", "microsoft.keyvault/vaults/secrets",
              "microsoft.keyvault/vaults/keys", "microsoft.web/sites", "microsoft.web/sites/functions",
              *(t.lower() for t in NETWORK_TYPES))
PLACEHOLDER = ("unknown-subscription", "unknown-group")   # IDs without a deployment: links within it still resolve
SUB_RESOURCES = ("subnets", "ipConfigurations", "frontendIPConfigurations", "backendAddressPools",
                 "loadBalancingRules", "probes", "securityRules", "routes", "privateLinkServiceConnections",
                 "manualPrivateLinkServiceConnections", "privateDnsZoneConfigs")
_UNKNOWN = ("<unknown>",)          # what an expression is when it depends on something the deployment doesn't know
_TOKEN = re.compile(r"\s*(?:(\d+)|'((?:[^']|'')*)'|([A-Za-z_][A-Za-z0-9_]*)|(\S))")
_CALL = re.compile(r"([A-Za-z_][A-Za-z0-9_]*)\s*\(")


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
    if name == "subscription":
        return {"subscriptionId": ctx["subscription"], "id": f"/subscriptions/{ctx['subscription']}"} \
            if ctx["subscription"] else _UNKNOWN
    if name == "resourceGroup":
        return {"name": ctx["group"], "id": f"/subscriptions/{ctx['subscription']}/resourceGroups/{ctx['group']}"} \
            if ctx["group"] and ctx["subscription"] else _UNKNOWN
    simple = {"equals": lambda a: a[0] == a[1], "toLower": lambda a: str(a[0]).lower(),
              "toUpper": lambda a: str(a[0]).upper(), "string": lambda a: a[0] if isinstance(a[0], str) else json.dumps(a[0]),
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
    """A resource or sub-resource in the Azure CLI's shape: properties merged in, sub-resources given IDs."""
    merged = {**{k: v for k, v in item.items() if k != "properties"}, **(item.get("properties") or {}), "id": rid}
    return {k: ([_flatten(s, f"{rid}/{k}/{s.get('name')}") if isinstance(s, dict) else s for s in v]
                if k in SUB_RESOURCES and isinstance(v, list) else v) for k, v in merged.items()}


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


def _items(template, ctx, produced):
    """(kind, item) of each resource the deployment declares (and, when known, produced), in the CLI's shape; counts
    of resources not deployed and not produced; Counter of types not read. Without a deployment, disk encryption sets
    are skipped: their ID (a key's ciamProviderRef) would carry placeholders."""
    found = [x for r in _top(template) if not r.get("existing")
             for x in _expand(_known(evaluate(_without_secret_values(r), ctx)))]
    kept = [r for r in found if r.get("condition", True) is not False and isinstance(r.get("name"), str)
            and isinstance(r.get("type"), str) and "None" not in r["name"].split("/")]
    here = (ctx["subscription"] or PLACEHOLDER[0], ctx["group"] or PLACEHOLDER[1])
    ids = [(r, arm_id(*here, r["type"], r["name"].split("/"))) for r in kept]
    live = [(r, rid) for r, rid in ids if produced is None or rid.lower() in produced]
    read = [(r, rid) for r, rid in live if r["type"].lower() in READ_TYPES
            and (ctx["subscription"] or r["type"].lower() != "microsoft.compute/diskencryptionsets")]
    items = [i for r, rid in read for i in (_vault_item(r, rid) if r["type"].lower().startswith("microsoft.keyvault/")
                                            else [{**_flatten(r, rid), "name": r["name"].split("/")[-1]}])]
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
        return None
    found = [(p.rsplit("/", 1)[0] if "/" in p else "", p, json_document(t)) for p, t in sorted(texts.items())]
    typed = [(f, p, kind(doc), doc) for f, p, doc in found]
    folders = dict.fromkeys(f for f, _, k, _ in typed if k)
    return ({f: {k: doc for f2, _, k, doc in typed if f2 == f and k} for f in folders},
            tuple(f"{p}: not an ARM template, deployment or parameters file; not read" for _, p, k, _ in typed if not k))


def _context(folder):
    """What a deployment's expressions can know: subscription, resource group, parameters, variables."""
    template, deployment = folder["template"], folder.get("deployment") or {}
    rid = deployment.get("id", "")
    declared = template.get("parameters") or {}
    secure = {k for k, v in declared.items() if str((v or {}).get("type", "")).lower().startswith("secure")}
    given = {**{k: (v or {}).get("value", _UNKNOWN) for k, v in ((folder.get("parameters") or {}).get("parameters")
                                                                  or {}).items()},
             **{k: (v or {}).get("value", _UNKNOWN) for k, v in
                ((deployment.get("properties") or {}).get("parameters") or {}).items()}}
    base = {"subscription": arm_segment(rid, "subscriptions"), "group": arm_segment(rid, "resourceGroups"),
            "variables": template.get("variables") or {}, "parameters": {}}
    defaults = {k: evaluate((v or {}).get("defaultValue", _UNKNOWN), base) for k, v in declared.items()}
    return {**base, "parameters": {k: _UNKNOWN if k in secure else given.get(k, defaults.get(k, _UNKNOWN))
                                   for k in {*declared, *given}}}


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


def arm_resources(texts):
    """(resources, notices) of an environment's deployment folders ({path within the folder: text})."""
    folders, unknown = _documents(texts)
    read = [deployment_items(docs, f or ".") for f, docs in folders.items() if docs.get("template")]
    resources, notices = items_resources([i for items, _ in read for i in items])
    return resources, (*unknown, *(f"{f or '.'}: no template (the template file, `az bicep build` output, or "
                                   f"`az deployment group export`); not read"
                                   for f, docs in folders.items() if not docs.get("template")),
                       *(n for _, ns in read for n in ns), *notices)


def read_arm(files, d, patterns, at=None):
    """Imported: each environment's servers and bindings from its ARM/Bicep deployments under <cloud>/<env>/<name>/."""
    return layout_import(files, d, PROVIDER, "Azure", arm_resources, ".json", "ARM deployment",
                         "network/azuredeploy.json", summarize=ACCOUNT_WIDE)


ARM = Importer("arm", "ARM templates and Bicep (compiled to ARM JSON) with their deployments, one folder per "
                      "deployment under <cloud>/<env>/, as the environment's servers and bindings", read_arm)

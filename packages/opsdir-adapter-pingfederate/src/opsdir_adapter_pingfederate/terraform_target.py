"""PingFederate's configuration for one environment as Terraform for Ping's pingidentity/pingfederate provider (render
target `terraform`), derived from the same Admin API requests the `admin-api` target renders, so both say the same
thing. Pure, but for the provider schema it loads.

  pingfederate/terraform/versions.tf    the provider, pinned to the release that supports the environment's
                                         PingFederate version (PROVIDERS), and the product version it configures
  pingfederate/terraform/variables.tf   the admin node's address, and one sensitive variable per secret: the secret's
                                         role (its description: the reference the environment binds), never a value
  pingfederate/terraform/main.tf        one resource per request, in the provider's terms: arguments in snake_case
                                         (PingFederate's camelCase), a discriminated object as the provider's variant
                                         (a data store of type LDAP as ldap_data_store), a plugin field holding a
                                         secret among sensitive_fields, map keys (claim names) as they are; each group
                                         of requests depending on the one before it, the Admin API's order

Each resource is converted against the provider's own schema of that release (vendored, trimmed: specs/,
scripts/vendor-provider-schemas.py): what the provider doesn't take is named in a comment on the resource, and a
resource type it has no resource for (some resources held as is) is named at the top of main.tf and left to the
admin-api target. Every argument the provider marks sensitive ends in Terraform state: keep state encrypted. The
admin credentials are the provider's own environment variables (PINGFEDERATE_PROVIDER_USERNAME/PASSWORD, or OAuth),
never in the files.
"""
import functools
import json
import re
from importlib import resources as package_data
from types import MappingProxyType

from opsdir.core.directory import one
from opsdir.domains.governance.collection import collection_sources
from opsdir_format_terraform.hcl import Expr, NestedBlock, data_block, tf_name
from .admin_api import pingfederate_version, requests

OUTPUT = "pingfederate/terraform/"
SOURCE = "pingidentity/pingfederate"
# (lowest, highest PingFederate major.minor, the provider release supporting them), newest first (provider docs)
PROVIDERS = (((12, 2), (13, 1), "1.10.0"), ((11, 3), (13, 0), "1.8.1"))
# Admin API resource type -> (provider resource, the argument its id goes in; None: a settings object)
RESOURCES = MappingProxyType({
    "/keyPairs/signing/import": ("pingfederate_keypairs_signing_key", "key_id"),
    "/keyPairs/sslServer/import": ("pingfederate_keypairs_ssl_server_key", "key_id"),
    "/dataStores": ("pingfederate_data_store", "data_store_id"),
    "/passwordCredentialValidators": ("pingfederate_password_credential_validator", "validator_id"),
    "/notificationPublishers": ("pingfederate_notification_publisher", "publisher_id"),
    "/captchaProviders": ("pingfederate_captcha_provider", "provider_id"),
    "/idp/adapters": ("pingfederate_idp_adapter", "adapter_id"),
    "/authenticationSelectors": ("pingfederate_authentication_selector", "selector_id"),
    "/oauth/accessTokenManagers": ("pingfederate_oauth_access_token_manager", "manager_id"),
    "/authenticationPolicyContracts": ("pingfederate_authentication_policy_contract", "contract_id"),
    "/authenticationPolicies/fragments": ("pingfederate_authentication_policies_fragment", "fragment_id"),
    "/authenticationPolicies/default": ("pingfederate_authentication_policies", None),
    "/oauth/openIdConnect/policies": ("pingfederate_openid_connect_policy", "policy_id"),
    "/oauth/authServerSettings": ("pingfederate_oauth_server_settings", None),
    "/oauth/clients": ("pingfederate_oauth_client", "client_id"),
    "/idp/spConnections": ("pingfederate_idp_sp_connection", "connection_id"),
    "/sp/idpConnections": ("pingfederate_sp_idp_connection", "connection_id"),
    "/serverSettings": ("pingfederate_server_settings", None),
    "/oauth/accessTokenMappings": ("pingfederate_oauth_access_token_mapping", "mapping_id"),
    "/idp/tokenProcessors": ("pingfederate_idp_token_processor", "processor_id")})
WITHHELD = "${withheld}"
READ_ONLY = ("lastModified",)        # what PingFederate reports and ignores on writes: never an argument, never named


def provider_release(version):
    """(the provider release supporting a PingFederate version ('PingFederate 12.1.4'), the product version it
    configures ('12.1')), or (None, None) when no pinned release supports it."""
    found = re.search(r"(\d+)\.(\d+)", version or "")
    at = (int(found.group(1)), int(found.group(2))) if found else None
    release = next((r for low, high, r in PROVIDERS if at and low <= at <= high), None)
    return (release, f"{at[0]}.{at[1]}") if release else (None, None)


@functools.lru_cache(maxsize=None)
def load_provider_schema(release):
    """Effect (reads package data): the trimmed resource schemas of a vendored provider release."""
    text = package_data.files(__package__).joinpath("specs", f"terraform-provider-{release}.json").read_text()
    return json.loads(text)


def snake(name):
    """PingFederate's camelCase as the provider's snake_case: userDN -> user_dn, x509File -> x509_file."""
    first = re.sub(r"(.)([A-Z][a-z]+)", r"\1_\2", name)
    return re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", first).lower()


def _settable(a):
    return a.get("required") or a.get("optional")


def _argument(attrs, key):
    """The provider argument a body key is, by snake_case, else by the same letters (None when there is none)."""
    name = snake(key)
    if name in attrs:
        return name
    plain = name.replace("_", "")
    return next((n for n in attrs if n.replace("_", "") == plain), None)


def _variant(attrs, value):
    """The provider's variant argument for a discriminated object (its type LDAP -> ldap_data_store or ldap), or None."""
    kind = value.get("type") if isinstance(value, dict) and "type" not in attrs else None
    if not isinstance(kind, str):
        return None
    t = kind.lower()
    nested = [n for n in attrs if attrs[n].get("nested")]

    def suffix_shared(n):
        suffix = n[len(t):]
        return any(o != n and o.endswith(suffix) for o in nested)
    found = [n for n in nested if n == t or (n.startswith(t + "_") and suffix_shared(n))]
    return found[0] if len(found) == 1 else None


def _is_secret(v):
    return isinstance(v, str) and (v.startswith("${secret:") or v.startswith("UNBOUND:") or v == WITHHELD)


def _split_secret_fields(value):
    """A plugin configuration's (or table row's) fields with those holding a secret moved to sensitive_fields."""
    fields = value.get("fields") or []
    plain = [f for f in fields if not _is_secret(f.get("value"))]
    secret = [f for f in fields if _is_secret(f.get("value"))]
    return {**{k: v for k, v in value.items() if k != "fields"}, **({"fields": plain} if plain or "fields" in value
                                                                    else {}),
            **({"sensitive_fields": secret} if secret else {})}


def _converted(value, attrs, path, secret):
    """(the arguments of an object for its provider attributes, the paths the provider doesn't take)."""
    variant = _variant(attrs, value)
    if variant:
        inner, dropped = _converted({k: v for k, v in value.items() if k != "type"},
                                    attrs[variant]["nested"]["attributes"], f"{path}.{variant}", secret)
        return {variant: inner}, dropped
    if "sensitive_fields" in attrs and isinstance(value.get("fields"), list):
        value = _split_secret_fields(value)
    pairs = [(k, v, _argument(attrs, k)) for k, v in value.items() if k not in READ_ONLY]
    parts = [(name, _value(v, attrs[name], f"{path}.{name}", secret)) for k, v, name in pairs
             if name and _settable(attrs[name])]
    dropped = tuple(f"{path}.{k}" for k, _, name in pairs if not name)
    return {name: val for name, (val, _) in parts}, (*dropped, *(d for _, (_, ds) in parts for d in ds))


def _value(v, a, path, secret):
    """(an argument's value for its provider attribute, the paths the provider doesn't take below it)."""
    if _is_secret(v):
        return secret(v, path), ()
    nested = a.get("nested")
    if not nested or v is None:
        return v, ()
    attrs, mode = nested["attributes"], nested["mode"]
    if mode == "single":
        return _converted(v, attrs, path, secret)
    if mode == "map":
        done = {k: _converted(x, attrs, f"{path}[{k}]", secret) for k, x in v.items()}
        return {k: val for k, (val, _) in done.items()}, tuple(d for _, ds in done.values() for d in ds)
    done = [_converted(x, attrs, f"{path}[{n}]", secret) for n, x in enumerate(v)]
    return [val for val, _ in done], tuple(d for _, ds in done for d in ds)


def secret_variables(m):
    """{secret placeholder the admin-api target writes: (variable name, description)} of environment m's bound
    secrets: the variable named by the role, described by the reference."""
    return {f"${{secret:{ref}}}": (tf_name(role), f"the secret of role {role} ({ref}), supplied at apply time")
            for b in m.bindings for ref, role in [(one(b, "ciamRefUri"), one(b, "ciamBindingRole"))] if ref and role}


def _secret_name(text, known, resource):
    if text in known:
        return known[text]
    if text.startswith("UNBOUND:"):
        role = text[len("UNBOUND:"):]
        return tf_name(role), f"the secret of role {role}, which this environment doesn't bind yet"
    return f"{resource}_withheld", f"a secret of {resource} no credential role supplies yet (set pingfedCredentialRole)"


def _placeholders(value):
    """The secret placeholders a body holds, each once, in order."""
    if _is_secret(value):
        return (value,)
    items = value.values() if isinstance(value, dict) else value if isinstance(value, list) else ()
    return tuple(dict.fromkeys(p for v in items for p in _placeholders(v)))


def kind_of(request):
    """A Request's resource type: the collection its createWith POST names, else its path."""
    return request.create_with.split(" ", 1)[1] if request.create_with else request.path


def resource(request, schema, known):
    """(provider resource type, its name, its arguments, the paths the provider doesn't take, (variable, description)
    of each secret it uses) of an Admin API Request, or None when the provider has no resource for its type."""
    mapped = RESOURCES.get(kind_of(request))
    if mapped is None or mapped[0] not in schema["resources"]:
        return None
    tf_type, id_arg = mapped
    body = request.body
    rid = body.get("id") or body.get("clientId") or kind_of(request).strip("/").replace("/", "_")
    name = tf_name(rid)
    variables = tuple(_secret_name(t, known, name) for t in _placeholders(body))
    by_text = dict(zip(_placeholders(body), variables))
    attrs = schema["resources"][tf_type]
    implied = "type" not in attrs and _variant(attrs, body) is None      # a type the resource itself says (SP)
    content = {k: v for k, v in body.items() if not (k == "id" and id_arg) and not (k == "type" and implied)}
    args, dropped = _converted(content, attrs, tf_type,
                               lambda text, path: Expr(f"var.{by_text[text][0]}"))
    return tf_type, name, {**({id_arg: rid} if id_arg and id_arg not in args else {}), **args}, dropped, variables


def _tiers(reqs):
    """The requests grouped by resource type, in order: each group depends on the one before it."""
    kinds = tuple(dict.fromkeys(kind_of(r) for r in reqs))
    return tuple((k, tuple(r for r in reqs if kind_of(r) == k)) for k in kinds)


def _with_dependencies(groups):
    """(resource, the addresses of the group before it that made resources) for each resource, in order."""
    made = [g for g in groups if g]
    return tuple((x, tuple(f"{y[0]}.{y[1]}" for y in made[n - 1]) if n else ())
                 for n, group in enumerate(made) for x in group)


def _admin_host(m):
    found = [loc for s in collection_sources(m, "pingfederate/bulk") for loc in s.locations]
    return found[0] if found else None


KEY_PAIRS = ("pingfederate_keypairs_signing_key", "pingfederate_keypairs_ssl_server_key")   # the provider can't import
CREATE_KEY_PAIRS = "pingfederate_create_key_pairs"


def _built(m, reqs, release):
    """(((resource, the addresses it depends on), ...), the resource types the provider has no resource for)."""
    schema, known = load_provider_schema(release), secret_variables(m)
    converted = tuple((kind, tuple(resource(r, schema, known) for r in group)) for kind, group in _tiers(reqs))
    return (_with_dependencies(tuple(tuple(x for x in xs if x) for _, xs in converted)),
            tuple(kind for kind, xs in converted if not all(xs)))


def _resource_block(t, n, args, dropped, before):
    counted = (("count", Expr(f"var.{CREATE_KEY_PAIRS} ? 1 : 0")),) if t in KEY_PAIRS else ()
    return data_block("resource", [t, n], [*counted, *args.items(),
                                           *((("depends_on", [Expr(a) for a in before]),) if before else ())],
                      comments=tuple(f"not taken by the provider: {p}" for p in dropped))


def _files(m, reqs, release, product):
    built, unmanaged = _built(m, reqs, release)
    blocks = tuple(_resource_block(t, n, args, dropped, before) for (t, n, args, dropped, _), before in built)
    variables = tuple(dict.fromkeys(v for (_, _, _, _, used), _ in built for v in used))
    host = _admin_host(m)
    key_pairs = any(t in KEY_PAIRS for (t, *_), _ in built)
    head = "".join(f"# Not managed here (no {SOURCE} {release} resource): {k}; apply its admin-api request\n"
                   for k in unmanaged)
    return {
        f"{OUTPUT}versions.tf": data_block("terraform", [], [("required_providers", NestedBlock((("pingfederate", {
            "source": SOURCE, "version": release}),)))]) + "\n\n" + data_block("provider", ["pingfederate"], [
                ("https_host", Expr("var.pingfederate_https_host")), ("product_version", product)]) + "\n",
        f"{OUTPUT}variables.tf": "\n\n".join((
            data_block("variable", ["pingfederate_https_host"], [
                ("description", "The PingFederate admin node's address (https://host:port)"),
                ("type", Expr("string")), *((("default", host),) if host else ())]),
            *((data_block("variable", [CREATE_KEY_PAIRS], [
                ("description", "Import the key pairs into PingFederate (false where it already holds them: the "
                                "provider can't adopt key pairs)"), ("type", Expr("bool")), ("default", True)]),)
              if key_pairs else ()),
            *(data_block("variable", [var], [("description", description), ("type", Expr("string")),
                                             ("sensitive", True)]) for var, description in variables))) + "\n",
        f"{OUTPUT}main.tf": head + ("\n" if head else "") + "\n\n".join(blocks) + "\n"}


def terraform_import_files(m):
    """{pingfederate/terraform/imports.tf: text}: an import block per resource the terraform target renders for
    environment m, adopting the object an existing PingFederate already holds (its id, a placeholder for a settings
    object); key pairs named instead (the provider can't import them: set pingfederate_create_key_pairs to false)."""
    reqs = requests(m)
    version, _ = pingfederate_version(m)
    release, _ = provider_release(version)
    if not reqs or release is None:
        return {}
    built, _ = _built(m, reqs, release)
    ids = {kind: id_arg for kind, id_arg in RESOURCES.values()}
    blocks = tuple(data_block("import", [], [("to", Expr(f"{t}.{n}")), ("id", args.get(ids[t]) or "id")])
                   for (t, n, args, _, _), _ in built if t not in KEY_PAIRS)
    skipped = tuple(f"{t}.{n}" for (t, n, *_), _ in built if t in KEY_PAIRS)
    note = "".join(f"# {a}: the provider can't import key pairs; where PingFederate already holds it, set "
                   f"{CREATE_KEY_PAIRS} = false\n" for a in skipped)
    return {f"{OUTPUT}imports.tf": note + ("\n" if note else "") + "\n\n".join(blocks) + "\n"}


def terraform_files(m):
    """{pingfederate/terraform/<file>: text}: environment m's PingFederate configuration as Terraform for the provider
    release supporting its version (nothing when the record holds nothing for PingFederate)."""
    reqs = requests(m)
    if not reqs:
        return {}
    version, _ = pingfederate_version(m)
    release, product = provider_release(version)
    if release is None:
        return {f"{OUTPUT}main.tf": f"# Not rendered: no pinned {SOURCE} release supports "
                                    f"{version or 'an unknown PingFederate version'} (supported: 11.3 to 13.1); apply "
                                    "the admin-api requests\n"}
    return _files(m, reqs, release, product)

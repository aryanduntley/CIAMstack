"""PingFederate's configuration for one environment as Admin API requests (render target `admin-api`). Pure, but for
the spec it loads.

Every object the record holds for PingFederate becomes one request, in the order PingFederate needs them (an object
before those that name it), as pingfederate/admin-api/requests.json:

  {"pingFederate": the version the environment's PingFederate servers run, "adminApi": the spec checked against,
   "problems": what the spec refuses (none when it is valid), "requests": [{"method", "path", "createWith", "body"}]}

  key pairs                          /keyPairs/signing/import,         imported from where the environment keeps their
                                     /keyPairs/sslServer/import        key material
                                                                       (opsdir_adapter_pingfederate.keypairs)
  data stores                        /dataStores                       hosts and secrets of this environment
  plugin instances                   /passwordCredentialValidators, /notificationPublishers, /captchaProviders,
                                     /idp/adapters, /authenticationSelectors, /oauth/accessTokenManagers (a parent
                                     instance before those inheriting from it)
  policy contracts, fragments,       /authenticationPolicyContracts, /authenticationPolicies/fragments,
  the default policy                 /authenticationPolicies/default
  OIDC policies, the authorization   /oauth/openIdConnect/policies, /oauth/authServerSettings
  server's settings
  OAuth clients, SP and IdP          /oauth/clients, /idp/spConnections, /sp/idpConnections (the federation domain's
  connections                        integrations PingFederate serves)
  resources held as is               their own resource type's path, last

An object with an id is a PUT to <collection>/<id>, createWith the POST that creates it where it doesn't exist yet (a
PUT answers 404); a settings object is a PUT; a key pair is a POST import, once (an id PingFederate has is refused).
Secrets are never values: `${secret:<reference>}` (the reference its credential role binds in this environment),
`UNBOUND:<role>` or `${withheld}` where nothing supplies one (the planner blocks on both): the operator's pipeline puts
the value in when it applies the requests, which opsdir never does. The body of each request is checked against the
Admin API spec of the environment's PingFederate version (opsdir_adapter_pingfederate.admin_api_spec); a version with
no vendored spec is rendered unchecked and says so.
"""
import json
from typing import NamedTuple

from opsdir.core.directory import children, one, rdn_value
from opsdir.domains.compute.workloads import role_versions
from opsdir.domains.federation.services import identity_services, integrations_served
from .admin_api_spec import load_spec, request_problems, spec_version
from .connections import integration_body
from .datastores import data_store_view
from .generic import held_resources, resource_body
from .keypairs import key_pair_imports
from .naming import CONTRACTS, DATA_STORES, FRAGMENTS, OIDC_POLICIES, SERVER_ROLES
from .oauth import auth_server_body, oidc_policy_body
from .plugins import KINDS, plugin_view
from .policies import contract_body, default_policy_body, fragment_body

OUTPUT = "pingfederate/admin-api/requests.json"
PLUGIN_ORDER = ("validator", "notification-publisher", "captcha-provider", "idp-adapter", "selector",
                "access-token-manager")
INTEGRATION_ORDER = ("oidc-client", "saml2-sp", "saml2-idp")

# One Admin API request: method, path, the POST that creates the object where a PUT finds none (None for settings and
# for objects created by POST alone), and the body.
Request = NamedTuple("Request", [("method", str), ("path", str), ("create_with", object), ("body", dict)])


def object_request(collection, oid, body):
    """The Request of an object of a collection: a PUT to <collection>/<id> creatable by POST <collection>; a POST to
    the collection when it has no id."""
    return Request("PUT", f"{collection}/{oid}", f"POST {collection}", body) if oid else \
        Request("POST", collection, None, body)


def settings_request(path, body):
    """The Request of a settings object (one per PingFederate): a PUT."""
    return Request("PUT", path, None, body)


def pingfederate_version(m):
    """(the PingFederate version environment m runs, the first by server or workload name, or None; the other
    versions it runs). Its servers' and, on Kubernetes, its workload bindings' (compute.role_versions)."""
    versions = tuple(dict.fromkeys(v for _, v in role_versions(m, SERVER_ROLES)))
    return (versions[0], versions[1:]) if versions else (None, ())


def _parents_first(entries, placed=()):
    """Plugin instances with each one after the instance it inherits from."""
    if not entries:
        return ()
    ids = {rdn_value(e) for e in entries}
    ready = tuple(e for e in entries
                  if (one(e, "pingfedParent") or "").split(",", 1)[0][3:] not in ids - set(placed))
    ready = ready or entries[:1]                                # a cycle: PingFederate refuses it; keep the order
    return (*ready, *_parents_first(tuple(e for e in entries if e not in ready), (*placed, *map(rdn_value, ready))))


def requests(m):
    """Environment m's PingFederate configuration as Admin API Requests, in the order PingFederate needs them."""
    d = m.d
    plugins = {kind: _parents_first(children(d, KINDS[kind].base, "pingfedPlugin")) for kind in PLUGIN_ORDER}
    policy = default_policy_body(d)
    server = auth_server_body(m)
    services = identity_services(d, SERVER_ROLES)
    integrations = tuple(i for ptype in INTEGRATION_ORDER for i in integrations_served(d, services, ptype))
    return (*(Request("POST", path, None, body) for path, body in key_pair_imports(m)[0]),
            *(object_request("/dataStores", rdn_value(s), data_store_view(m, s))
              for s in children(d, DATA_STORES, "pingfedDataStore")),
            *(object_request(KINDS[kind].resource, rdn_value(e), plugin_view(m, e))
              for kind in PLUGIN_ORDER for e in plugins[kind]),
            *(object_request("/authenticationPolicyContracts", rdn_value(c), contract_body(c))
              for c in children(d, CONTRACTS, "pingfedPolicyContract")),
            *(object_request("/authenticationPolicies/fragments", rdn_value(f), fragment_body(f))
              for f in children(d, FRAGMENTS, "pingfedAuthPolicy")),
            *((settings_request("/authenticationPolicies/default", policy),) if policy is not None else ()),
            *(object_request("/oauth/openIdConnect/policies", rdn_value(p), oidc_policy_body(p))
              for p in children(d, OIDC_POLICIES, "pingfedOidcPolicy")),
            *((settings_request("/oauth/authServerSettings", server),) if server is not None else ()),
            *(object_request(*integration_body(m, i)) for i in integrations),
            *(_held_request(m, r) for r in held_resources(d)))


def _held_request(m, r):
    body = resource_body(m, r)
    kind, name = one(r, "pingfedResourceType"), rdn_value(r)
    return settings_request(kind, body) if name == "settings" else object_request(kind, body.get("id"), body)


def request_type(request):
    """The resource type a rendered request's body is an item of: the collection it is created in, else its path."""
    create = request.get("createWith")
    return create.split(" ", 1)[1] if isinstance(create, str) and " " in create else request.get("path")


def rendered_bodies(text):
    """{resource type: [bodies]} of a rendered requests document (pingfederate/admin-api/requests.json), in order."""
    doc = json.loads(text)
    reqs = [r for r in doc.get("requests") or () if isinstance(r, dict)]
    return {t: [r.get("body") for r in reqs if request_type(r) == t] for t in dict.fromkeys(map(request_type, reqs))}


def checked(spec, reqs):
    """The problems of the requests against a spec: '<method> <path>: <JSON path>: <what>'."""
    return tuple(f"{r.method} {r.path}: {p}" for r in reqs for p in request_problems(spec, r.method, r.path, r.body))


def admin_api_files(m):
    """{pingfederate/admin-api/requests.json: text}: environment m's requests, checked against its version's spec
    (nothing when the record holds nothing for PingFederate)."""
    reqs = requests(m)
    if not reqs:
        return {}
    version, others = pingfederate_version(m)
    vendored = spec_version(version)
    spec = load_spec(vendored) if vendored else None
    problems = (*((f"servers run other versions too ({', '.join(others)}): checked against {version}",)
                  if others else ()), *key_pair_imports(m)[1],
                *(checked(spec, reqs) if spec else
                  (f"no Admin API spec for {version or 'an unknown version'}: the requests are not checked",)))
    doc = {"pingFederate": version, "adminApi": spec["version"] if spec else None, "problems": list(problems),
           "requests": [{"method": r.method, "path": r.path, **({"createWith": r.create_with} if r.create_with else {}),
                         "body": r.body} for r in reqs]}
    return {OUTPUT: json.dumps(doc, indent=2) + "\n"}

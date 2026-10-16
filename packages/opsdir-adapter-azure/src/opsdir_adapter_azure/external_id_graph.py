"""Microsoft Entra External ID's configuration read from Microsoft Graph into the record: the importer azure/external-id
and its collector (`opsdir collect --adapter azure`, external-id). Pure: the core runs the calls.

The collector signs nothing in. Under the operator's `az login --tenant <tenant ID> --allow-no-subscriptions` it first
checks the login is the external tenant an environment's External ID target records (az account show: tenantId its
ciamProviderRef, environmentName AzureCloud: external tenants exist in public clouds only), then reads every page
(@odata.nextLink) of, with `az rest --method get` against Graph v1.0 (graph.microsoft.com):

  organization                          id, displayName: the tenant read, checked against the binding again
  applications                          id, appId, displayName, identifierUris, web, spa, publicClient ($select)
  servicePrincipals                     id, appId, displayName, preferredSingleSignOnMode, servicePrincipalType
  identity/identityProviders            id, displayName ($select: social providers' client secrets never come)
  identity/authenticationEventsFlows    no $select (Graph documents none there, and the sign-up events are a derived
                                          type's): the projection keeps the allowlist
  .../{flow id}/conditions/applications/includeApplications    appId: the applications each flow signs users in to
  identity/customAuthenticationExtensions   no $select (the claims are a derived type's): projected

Every output passes through project_output (Command.keep) before anything else sees it (the export, the evidence's
hash, --save): an allowlist per output, so credentials (passwordCredentials, keyCredentials, identity providers'
client secrets embedded in flows) and the extensions' endpoints are never kept. Least privilege: the Graph
permissions Application.Read.All, EventListener.Read.All, IdentityProvider.Read.All and
CustomAuthenticationExtension.Read.All.

The importer reads <cloud>/<env>/external-id/*.json (a collection, or the same outputs saved by hand) into the
environment's External ID target whose tenant ID (ciamProviderRef) organization.json names:

  applications + service principals -> integrations (ciamIntegration) of the identity service it realizes: saml2-sp
                                         when the service principal is in SAML mode (entity ID its first identifier
                                         URI, ACS URL its first web redirect URI), else oidc-client (client ID its
                                         appId, redirect URIs its web, SPA and public client ones). Matched by client
                                         ID, then entity ID, then name; what Graph doesn't say (grants, token
                                         authentication, scopes, owners, claims) stays the record's, and a redirect
                                         URI azuread can't register (no host) is kept. A name match whose client ID
                                         differs keeps the record's (Entra assigns client IDs: the application
                                         switches when it moves): a notice. Microsoft's own (b2c-extensions-app) are
                                         skipped; a new one is registered with the identity service (ciamServedBy)
  authentication events flows       -> sign-in flows (ciamSignInFlow) beneath the binding: the integrations they sign
                                         users in to, their methods (email-password, email-otp, sign-up, federated),
                                         upstream providers, collected attributes and the extensions their attribute
                                         collection calls
  custom authentication extensions  -> ciamAuthExtension beneath the binding: its event, the application it
                                         authenticates to its API as, the claims it returns; never its endpoint
  identity providers                -> named in a notice (social and OIDC providers have no protocol type)
The binding's sign-in flows and extensions are made exactly what the tenant reports: one deleted there goes.
"""
import json
import re
from functools import partial, reduce

from opsdir.core.contract import Collector, Command, Imported, Importer
from opsdir.core.directory import children, get, make_entry, one, ou_entry, rdn_value, subtree, values
from opsdir.core.environment import env_dn, of_class
from opsdir.core.secrets import value_findings
from opsdir.core.sources import json_document
from opsdir.domains.federation.managed import is_target, realized_service
from opsdir.domains.federation.naming import INTEGRATIONS
from opsdir.domains.federation.services import integrations
from .external_id import SERVICE, hostless

GRAPH = "https://graph.microsoft.com/v1.0"
FOLDER = "external-id"
# (output, Graph path, $select or None): what the collector reads first, every page of it
READS = (("organization", "organization", "id,displayName"),
         ("applications", "applications", "id,appId,displayName,identifierUris,web,spa,publicClient"),
         ("service-principals", "servicePrincipals",
          "id,appId,displayName,preferredSingleSignOnMode,servicePrincipalType"),
         ("identity-providers", "identity/identityProviders", "id,displayName"),
         ("sign-in-flows", "identity/authenticationEventsFlows", None),
         ("extensions", "identity/customAuthenticationExtensions", None))
FLOW_APPS = "flow-applications"      # the projection of a flow's includeApplications output (flow-<id>-applications)
MICROSOFT_APPS = ("b2c-extensions-app",)            # what Microsoft registers in every tenant (by name prefix)
EMAIL_METHODS = {"EmailPassword-OAUTH": "email-password", "EmailOtpSignup-OAUTH": "email-otp"}
EVENTS = {"onTokenIssuanceStartCustomExtension": "token-issuance-start",
          "onAttributeCollectionStartCustomExtension": "attribute-collection-start",
          "onAttributeCollectionSubmitCustomExtension": "attribute-collection-submit",
          "onOtpSendCustomExtension": "otp-send", "onPasswordSubmitCustomExtension": "password-submit"}
_PAGE = re.compile(r"^(.*)-([0-9]+)$")


# ------------------------------------------------------------------ the allowlist
def _uris(x):
    return {"redirectUris": [u for u in (x or {}).get("redirectUris") or () if isinstance(u, str)]}


def _ids(items, *keys):
    return [{k: i.get(k) for k in keys if i.get(k) is not None} for i in items or () if isinstance(i, dict)]


def _handler(event):
    """An attribute collection event's handler: the id of the extension it calls only."""
    ext = ((event or {}).get("handler") or {}).get("customExtension") or {}
    return {"handler": {"customExtension": {"id": ext.get("id")}}} if ext.get("id") else {}


PROJECTIONS = {
    "organization": lambda o: {k: o.get(k) for k in ("id", "displayName")},
    "applications": lambda a: {**{k: a.get(k) for k in ("id", "appId", "displayName")},
                               "identifierUris": [u for u in a.get("identifierUris") or () if isinstance(u, str)],
                               **{k: _uris(a.get(k)) for k in ("web", "spa", "publicClient")}},
    "service-principals": lambda s: {k: s.get(k) for k in ("id", "appId", "displayName", "preferredSingleSignOnMode",
                                                           "servicePrincipalType")},
    "identity-providers": lambda p: {k: p.get(k) for k in ("@odata.type", "id", "displayName")},
    "sign-in-flows": lambda f: {
        **{k: f.get(k) for k in ("@odata.type", "id", "displayName", "description")},
        "onInteractiveAuthFlowStart": {"isSignUpAllowed": (f.get("onInteractiveAuthFlowStart") or {}).get(
            "isSignUpAllowed")},
        "onAuthenticationMethodLoadStart": {"identityProviders": _ids(
            (f.get("onAuthenticationMethodLoadStart") or {}).get("identityProviders"), "id", "displayName")},
        "onAttributeCollection": {"attributes": _ids((f.get("onAttributeCollection") or {}).get("attributes"),
                                                     "id", "displayName")},
        "onAttributeCollectionStart": _handler(f.get("onAttributeCollectionStart")),
        "onAttributeCollectionSubmit": _handler(f.get("onAttributeCollectionSubmit"))},
    "extensions": lambda x: {
        **{k: x.get(k) for k in ("@odata.type", "id", "displayName", "description")},
        "authenticationConfiguration": {"resourceId": (x.get("authenticationConfiguration") or {}).get("resourceId")},
        "claimsForTokenConfiguration": _ids(x.get("claimsForTokenConfiguration"), "claimIdInApiResponse")},
    FLOW_APPS: lambda a: {"appId": a.get("appId")},
}


def output_kind(name):
    """The projection an output file is kept by: its read's name (pages: <name>-<n>), a flow's applications'."""
    stem = _PAGE.sub(r"\1", name) if _PAGE.match(name) and _PAGE.sub(r"\1", name) in PROJECTIONS else name
    return FLOW_APPS if stem.startswith("flow-") and stem.endswith("-applications") else stem


def project(kind, doc):
    """A Graph list output ({"value": [...], "@odata.nextLink"}) kept to the allowlist of its kind: only the fields
    the importer reads, and the next page's link."""
    keep = PROJECTIONS[kind]
    found = doc if isinstance(doc, dict) else {}
    link = found.get("@odata.nextLink")
    return {"value": [keep(x) for x in found.get("value") or () if isinstance(x, dict)],
            **({"@odata.nextLink": link} if isinstance(link, str) else {})}


def project_output(kind, out):
    """Command.keep of a Graph read: its output text kept to the allowlist (project), as JSON text; an output that
    isn't JSON keeps nothing."""
    return json.dumps(project(kind, json_document(out) or {}), indent=1)


# ------------------------------------------------------------------ collector
def graph_target(m):
    """Environment m's External ID targets whose tenant ID (ciamProviderRef) is recorded: what the collector reads."""
    return tuple(b for b in of_class(m, "ciamManagedIdentity") if one(b, "ciamManagedService") == SERVICE
                 and is_target(b) and one(b, "ciamProviderRef"))


def graph_problems(d, m, options):
    """Why environment m's external tenant can't be collected: none recorded, or more than one (one login each)."""
    found = graph_target(m)
    if not found:
        return (f"{m.label} has no Entra External ID target recording its tenant ID (ciamProviderRef)",)
    if len(found) > 1:
        return (f"{m.label} has {len(found)} external tenants ({', '.join(rdn_value(b) for b in found)}): one login "
                "reads one tenant",)
    return None


def _get(url, kind):
    return Command(("az", "rest", "--method", "get", "--url", url, "-o", "json"),
                   keep=partial(project_output, kind))


def _next_pages(base, done):
    """(path, call) of the next page of each output read so far that names one."""
    def following(path, text):
        name = path[len(base) + 1:-len(".json")]
        match = _PAGE.match(name)
        stem, page = (match.group(1), int(match.group(2))) if match else (name, 1)
        link = (json_document(text) or {}).get("@odata.nextLink") if isinstance(json_document(text), dict) else None
        return (f"{base}/{stem}-{page + 1}.json", _get(link, output_kind(name))) if isinstance(link, str) else None
    return tuple(x for p, t in sorted(done.items()) if p.startswith(f"{base}/") and p.endswith(".json")
                 for x in (following(p, t),) if x)


def _flow_ids(base, done):
    return tuple(dict.fromkeys(f.get("id") for p, t in sorted(done.items())
                               if re.fullmatch(re.escape(base) + r"/sign-in-flows(-[0-9]+)?\.json", p)
                               for f in (json_document(t) or {}).get("value") or () if isinstance(f, dict)
                               and isinstance(f.get("id"), str) and re.fullmatch(r"[A-Za-z0-9-]+", f["id"])))


def graph_steps(d, m, done, options):
    """The Graph reads still to make (core.contract Collector.steps): every read, every page each names next, then
    each flow's applications."""
    if not graph_target(m):
        return ()
    base = f"{m.label}/{FOLDER}"
    calls = (*((f"{base}/{name}.json", _get(f"{GRAPH}/{path}" + (f"?$select={select}" if select else ""), name))
               for name, path, select in READS),
             *_next_pages(base, done),
             *((f"{base}/flow-{f}-applications.json",
                _get(f"{GRAPH}/identity/authenticationEventsFlows/{f}/conditions/applications/includeApplications",
                     FLOW_APPS)) for f in _flow_ids(base, done)))
    return tuple((p, c) for p, c in calls if p not in done)


def tenant_check(d, m):
    """`az account show`, and whether its tenant is the external tenant environment m's target records, in Azure's
    public cloud."""
    want = next((one(b, "ciamProviderRef") for b in graph_target(m)), None)

    def check(out):
        seen = json_document(out or "{}", dict) or {}
        if seen.get("tenantId") != want:
            return (f"signed in to tenant {seen.get('tenantId')}, the record's external tenant is {want} (az login "
                    f"--tenant {want} --allow-no-subscriptions)")
        return None if seen.get("environmentName") == "AzureCloud" else \
            f"signed in to cloud {seen.get('environmentName')}: external tenants exist in AzureCloud only"
    return Command(("az", "account", "show", "-o", "json")), check


GRAPH_COLLECTOR = Collector("external-id", "environment", graph_steps, tenant_check, graph_problems)


# ------------------------------------------------------------------ importer
def _items(docs, stem):
    """The items of every page of an output, in page order."""
    pages = sorted((int(_PAGE.match(n).group(2)) if _PAGE.match(n) and _PAGE.sub(r"\1", n) == stem else 1, n)
                   for n in docs if n == stem or (_PAGE.match(n) and _PAGE.sub(r"\1", n) == stem))
    return tuple(x for _, n in pages for x in project(output_kind(n), docs[n])["value"])


def _slug(text, taken):
    base = re.sub(r"[^a-z0-9]+", "-", (text or "").lower()).strip("-") or "unnamed"
    return next(n for n in (base, *(f"{base}-{i}" for i in range(2, 1000))) if n not in taken)


def _registered(app, sp):
    """(protocol, the attributes Graph says of an application): saml2-sp in SAML mode, else oidc-client."""
    web = app["web"]["redirectUris"]
    if (sp or {}).get("preferredSingleSignOnMode") == "saml":
        return "saml2-sp", {"ciamEntityId": tuple(app["identifierUris"][:1]), "ciamAcsUrl": tuple(web[:1])}
    uris = tuple(dict.fromkeys((*web, *app["spa"]["redirectUris"], *app["publicClient"]["redirectUris"])))
    return "oidc-client", {"ciamClientId": (app["appId"],), "ciamRedirectUri": uris}


def _matched(d, app, protocol):
    """The integration the record holds for an application: by client ID, then entity ID, then name."""
    held = integrations(d)
    return (next((i for i in held if app.get("appId") and one(i, "ciamClientId") == app["appId"]), None)
            or next((i for i in held if protocol == "saml2-sp" and one(i, "ciamEntityId")
                     and one(i, "ciamEntityId") in app["identifierUris"]), None)
            or next((i for i in held if rdn_value(i).lower() == (app.get("displayName") or "").lower()), None))


def _integration(d, service, label, app, sp, taken):
    """(entry, notices) of one application read: the record's integration with what Graph says, or a new one."""
    protocol, said = _registered(app, sp)
    held = _matched(d, app, protocol)
    name = app.get("displayName") or app.get("appId")
    if held is None:
        cn = _slug(name, taken)
        return make_entry(f"cn={cn},{INTEGRATIONS}", ("top", "ciamIntegration"), {
            "cn": (cn,), "ciamProtocolType": (protocol,), **{k: v for k, v in said.items() if v},
            "ciamServedBy": (service.dn,),
            "description": (f"Registered in external tenant {label} as {name}",)}), \
            (f"{label}: integration {cn} ({protocol}) added: registered in the tenant as {name}",)
    kept = {**said}
    notices = []
    if protocol == "oidc-client" and one(held, "ciamClientId") not in (None, app.get("appId")):
        kept.pop("ciamClientId")
        notices.append(f"{label}: {rdn_value(held)} is registered in the tenant as client {app.get('appId')}; the "
                       f"record's client ID is {one(held, 'ciamClientId')}: Entra assigns client IDs, so the "
                       "application switches to the tenant's when it moves (record it then)")
    if protocol == "oidc-client":
        kept["ciamRedirectUri"] = tuple(dict.fromkeys((*said["ciamRedirectUri"],
                                                       *(u for u in values(held, "ciamRedirectUri") if hostless(u)))))
    if one(held, "ciamServedBy") and one(held, "ciamServedBy").lower() != service.dn.lower():
        notices.append(f"{label}: {rdn_value(held)} is registered with {one(held, 'ciamServedBy')} in the record, "
                       f"and in the tenant of `{rdn_value(service)}`")
    if protocol != one(held, "ciamProtocolType"):
        notices.append(f"{label}: {rdn_value(held)} is {one(held, 'ciamProtocolType')} in the record and {protocol} "
                       "in the tenant: the record's protocol is kept")
        return held, tuple(notices)
    attrs = {**{a: v for a, v in held.attrs.items() if a not in kept}, **{k: v for k, v in kept.items() if v}}
    return make_entry(held.dn, held.classes, attrs), tuple(notices)


def _methods(flow):
    providers = flow["onAuthenticationMethodLoadStart"]["identityProviders"]
    return (tuple(dict.fromkeys((*(EMAIL_METHODS[p["id"]] for p in providers if p.get("id") in EMAIL_METHODS),
                                 *(("federated",) if any(p.get("id") not in EMAIL_METHODS for p in providers)
                                   else ()),
                                 *(("sign-up",) if flow["onInteractiveAuthFlowStart"]["isSignUpAllowed"] else ())))),
            tuple(p.get("displayName") or p.get("id") for p in providers if p.get("id") not in EMAIL_METHODS))


def _flow(b, flow, cn, apps, extensions):
    methods, upstream = _methods(flow)
    calls = tuple(dict.fromkeys(extensions[x] for x in (
        flow["onAttributeCollectionStart"].get("handler", {}).get("customExtension", {}).get("id"),
        flow["onAttributeCollectionSubmit"].get("handler", {}).get("customExtension", {}).get("id"))
        if x in extensions))
    return make_entry(f"cn={cn},{b.dn}", ("top", "ciamSignInFlow"), {k: v for k, v in {
        "cn": (cn,), "description": (flow.get("description") or flow.get("displayName"),),
        "ciamFlowApplications": apps, "ciamSignInMethod": methods, "ciamUpstreamProvider": upstream,
        "ciamCollectedAttribute": tuple(a["id"] for a in flow["onAttributeCollection"]["attributes"] if a.get("id")),
        "ciamFlowExtension": calls}.items() if any(v)})


def _extension(b, x, cn):
    return make_entry(f"cn={cn},{b.dn}", ("top", "ciamAuthExtension"), {k: v for k, v in {
        "cn": (cn,), "description": (x.get("description") or x.get("displayName"),),
        "ciamExtensionEvent": (EVENTS[(x.get("@odata.type") or "").rsplit(".", 1)[-1]],),
        "ciamExtensionResource": (x["authenticationConfiguration"].get("resourceId"),),
        "ciamExtensionClaim": tuple(c["claimIdInApiResponse"] for c in x["claimsForTokenConfiguration"]
                                    if c.get("claimIdInApiResponse"))}.items() if any(v)})


def _target(d, spec, tenant):
    env = get(d, env_dn(spec))
    if env is None:
        return None
    return next((b for b in children(d, f"ou=bindings,{env.dn}", "ciamManagedIdentity")
                 if one(b, "ciamManagedService") == SERVICE and is_target(b) and one(b, "ciamProviderRef") == tenant),
                None)


def _withheld(entry, patterns):
    """An entry without the values that look like secret material, and a notice per value withheld."""
    found = value_findings(entry.dn, entry.attrs, patterns)
    gone = {(a, v) for _, a, _ in found for v in entry.attrs[a]}
    attrs = {a: tuple(v for v in vs if (a, v) not in gone) for a, vs in entry.attrs.items()}
    return (make_entry(entry.dn, entry.classes, {a: vs for a, vs in attrs.items() if vs}),
            tuple(f"{entry.dn}: {a} withheld: it looks like secret material ({p})" for _, a, p in found))


def _environment(d, spec, docs, patterns):
    """(groups, notices) of one environment's Graph outputs."""
    tenant = next((o.get("id") for o in _items(docs, "organization")), None)
    b = _target(d, spec, tenant) if tenant else None
    if b is None:
        return (), (f"{spec}: no External ID target records tenant {tenant} (ciamProviderRef); not imported"
                    if tenant else f"{spec}: no organization.json names the tenant read; not imported",)
    service, label = realized_service(d, b), f"{spec} {rdn_value(b)}"
    if service is None:
        return (), (f"{label} realizes `{one(b, 'ciamRealizes')}`, which isn't an identity service; not imported",)
    sps = {s.get("appId"): s for s in _items(docs, "service-principals")}
    apps = tuple(a for a in _items(docs, "applications") if a.get("appId")
                 and not (a.get("displayName") or "").startswith(MICROSOFT_APPS))

    def integrate(acc, app):
        entries, notices, taken = acc
        entry, said = _integration(d, service, label, app, sps.get(app["appId"]), taken)
        return (*entries, (app["appId"], entry)), (*notices, *said), taken | {rdn_value(entry).lower()}
    found, notices, _ = reduce(integrate, apps, ((), (), frozenset(rdn_value(i).lower() for i in integrations(d))))
    by_app = dict(found)
    known = tuple(x for x in _items(docs, "extensions") if (x.get("@odata.type") or "").rsplit(".", 1)[-1] in EVENTS)
    names = _names((*(x.get("displayName") or x.get("id") for x in known),
                    *(f.get("displayName") or f.get("id") for f in _items(docs, "sign-in-flows"))))
    extensions = tuple(_extension(b, x, names[i]) for i, x in enumerate(known))
    ids = {x.get("id"): e.dn for x, e in zip(known, extensions)}
    flows = tuple(_flow(b, f, names[len(known) + i], tuple(by_app[a["appId"]].dn for a in _items(
        docs, f"flow-{f.get('id')}-applications") if a.get("appId") in by_app), extensions=ids)
        for i, f in enumerate(_items(docs, "sign-in-flows")))
    cleaned = [_withheld(e, patterns) for e in (*(e for _, e in found), *extensions, *flows)]
    entries = {e.dn.lower(): e for e, _ in cleaned}
    beneath = tuple(entries[x.dn.lower()] for x in (*extensions, *flows))
    providers = [p.get("displayName") or p.get("id") for p in _items(docs, "identity-providers")]
    return ((*((e.dn, (entries[e.dn.lower()], *(x for x in subtree(d, e.dn) if x.norm != e.norm)))
               for _, e in found), (b.dn, (b, *beneath))),
            (*notices, *(n for _, ns in cleaned for n in ns),
             *(f"{label}: extension {x.get('displayName') or x.get('id')} ({x.get('@odata.type')}) answers no event "
               "the record names; not imported" for x in _items(docs, "extensions") if x not in known),
             *((f"{label}: upstream identity providers in the tenant (named in its flows, not recorded as "
                f"integrations): {', '.join(providers)}",) if providers else ())))


def _names(texts):
    """A unique cn per text, in order."""
    def add(acc, t):
        return (*acc, _slug(t, set(acc)))
    return reduce(add, texts, ())


def read_graph(files, d, patterns=(), at=None):
    """Imported: each <cloud>/<env>/external-id/ folder's Graph outputs read into that environment's External ID
    target (by the tenant organization.json names): integrations, the binding's sign-in flows and extensions."""
    found = {p: t for p, t in files.items() if re.fullmatch(rf"[^/]+/[^/]+/{FOLDER}/[^/]+\.json", p)}
    specs = sorted({"/".join(p.split("/")[:2]) for p in found})
    read = [_environment(d, spec, {p.split("/")[3][:-len(".json")]: json_document(t) or {}
                                   for p, t in found.items() if p.startswith(f"{spec}/")}, patterns)
            for spec in specs]
    return Imported(containers=(ou_entry(INTEGRATIONS),) if specs else (),
                    groups=tuple(g for groups, _ in read for g in groups),
                    notices=(*(n for _, ns in read for n in ns),
                             *(() if specs else (f"no Graph outputs found (<cloud>/<env>/{FOLDER}/*.json)",))))


GRAPH_IMPORTER = Importer("external-id", "Microsoft Entra External ID's Graph configuration under "
                                         f"<cloud>/<env>/{FOLDER}/ (applications, service principals, user flows, "
                                         "custom authentication extensions), as the integrations, sign-in flows and "
                                         "extensions of the environment's external tenant", read_graph)

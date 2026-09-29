"""PingAM adapter: render every realm AM serves as Amster-importable entities and, on the SAML and OIDC bases, the
standard documents at AM's endpoint paths (all environment-neutral).

  am/global/Realms/<name>.json                   each realm below the root
  am/realms/<realm>/OAuth2Clients/<id>.json      the OIDC clients registered with the realm (standard integrations)
  am/realms/<realm>/AuthTree/<tree>.json         each journey, and one file per node: <NodeType>/<node id>.json
  am/realms/<realm>/Applications/<set>.json      each policy set, and its policies: Policies/<name>.json
  saml/, oidc/                                   standard metadata, client registrations, discovery per realm

The JSON follows the shape of Amster exports (metadata + data) but is not validated against a live AM (milestone
7.2). Client secrets and withheld node settings are never rendered: each environment supplies them.
"""
import json
from urllib.parse import urlsplit

from opsdir.core.directory import children, one, rdn_value, values
from opsdir.domains.federation.services import claims, integrations_served
from opsdir_base_oidc.discovery import OidcEndpoints
from opsdir_base_oidc.render import oidc_files
from opsdir_base_saml.render import SamlEndpoints, saml_files
from .naming import JOURNEYS, POLICY_SETS, realm_container
from .realms import ROOT, export_dir, meta_alias, oauth2_path, realm_path, realms

FORMATS = (("am/*.json", "json"),)


def _json(value):
    return json.dumps(value, indent=2) + "\n"


def _config(e, attr):
    return json.loads(one(e, attr)) if one(e, attr) else {}


def entity(path, entity_type, entity_id, data):
    """An Amster entity: its metadata (realm, type, id) and its data."""
    return {"metadata": {"realm": path, "entityType": entity_type, "entityId": entity_id, "pathParams": {}},
            "data": {"_id": entity_id, **data}}


def _set(value):
    """AM's form of a client setting: set on the client, not inherited from the realm's defaults."""
    return {"inherited": False, "value": value}


def oauth2_client(d, i, path):
    auth = one(i, "ciamTokenAuthMethod")
    return entity(path, "OAuth2Clients", one(i, "ciamClientId"), {
        "coreOAuth2ClientConfig": {"clientType": _set("Public" if auth == "none" else "Confidential"),
                                   "clientName": _set([rdn_value(i)]),
                                   "redirectionUris": _set(list(values(i, "ciamRedirectUri"))),
                                   "scopes": _set(list(values(i, "ciamScope")))},
        "advancedOAuth2ClientConfig": {"grantTypes": _set(list(values(i, "ciamGrantType"))),
                                       **({"tokenEndpointAuthMethod": _set(auth)} if auth else {})},
        "coreOpenIDClientConfig": {"postLogoutRedirectUri": _set(list(values(i, "ciamPostLogoutRedirectUri")))},
        "x-opsdir": {"claims": {name: attr for name, attr, _ in claims(d, i)},
                     "pkceRequired": one(i, "ciamPkceRequired") == "TRUE",
                     "mfaRequired": one(i, "ciamMfaRequired") == "TRUE"}})


def _page_children(nodes):
    """Ids of nodes that sit inside a page node (they have no place in the tree's own node map)."""
    return {c.get("_id") for n in nodes for c in _config(n, "pingamNodeConfig").get("nodes", ())}


def _tree_node(n):
    return {"nodeType": one(n, "pingamNodeType"), "displayName": one(n, "pingamDisplayName", ""),
            "connections": dict(o.split("=", 1) for o in values(n, "pingamOutcome"))}


def _node(path, n):
    withheld = list(values(n, "pingamWithheld"))
    return entity(path, one(n, "pingamNodeType"), rdn_value(n), {
        **_config(n, "pingamNodeConfig"), "_type": {"_id": one(n, "pingamNodeType")},
        **({"x-opsdir": {"withheld": withheld}} if withheld else {})})


def journey_files(d, service, path):
    base = f"am/{export_dir(path)}"
    return {path_: text for j in children(d, realm_container(JOURNEYS, rdn_value(service)), "pingamJourney")
            for path_, text in _journey(d, j, base, path).items()}


def _journey(d, j, base, path):
    nodes = children(d, j.dn, "pingamNode")
    inside = _page_children(nodes)
    tree = entity(path, "AuthTree", rdn_value(j), {
        "entryNodeId": one(j, "pingamEntryNode"), "enabled": one(j, "pingamEnabled", "TRUE") == "TRUE",
        "nodes": {rdn_value(n): _tree_node(n) for n in nodes if rdn_value(n) not in inside},
        **_config(j, "pingamTreeConfig")})
    return {f"{base}/AuthTree/{rdn_value(j)}.json": _json(tree),
            **{f"{base}/{one(n, 'pingamNodeType')}/{rdn_value(n)}.json": _json(_node(path, n)) for n in nodes}}


def policy_files(d, service, path):
    base = f"am/{export_dir(path)}"
    sets = children(d, realm_container(POLICY_SETS, rdn_value(service)), "pingamPolicySet")
    return {**{f"{base}/Applications/{rdn_value(s)}.json": _json(entity(path, "Applications", rdn_value(s), {
                "name": rdn_value(s), **({"applicationType": one(s, "pingamApplicationType")}
                                         if one(s, "pingamApplicationType") else {}),
                **_config(s, "pingamSetConfig")})) for s in sets},
            **{f"{base}/Policies/{rdn_value(p)}.json": _json(entity(path, "Policies", rdn_value(p), {
                "name": rdn_value(p), "applicationName": rdn_value(s), **_config(p, "pingamPolicyConfig")}))
               for s in sets for p in children(d, s.dn, "pingamPolicy")}}


def realm_file(service, path):
    """The realm's own entity (below the root only): its name, parent and the host names it answers on."""
    *parent, name = path.strip("/").split("/")
    host = urlsplit(one(service, "ciamBaseUrl")).hostname
    return {f"am/global/Realms/{name}.json": _json(entity(None, "Realms", name, {
        "name": name, "parentPath": "/" + "/".join(parent), "active": True, "aliases": [host] if host else []}))}


def saml_endpoints(path):
    return SamlEndpoints(sso=(("HTTP-Redirect", meta_alias(path, "SSORedirect")),
                              ("HTTP-POST", meta_alias(path, "SSOPOST"))),
                         slo=(("HTTP-Redirect", meta_alias(path, "IDPSloRedirect")),
                              ("HTTP-POST", meta_alias(path, "IDPSloPOST"))))


def oidc_endpoints(path):
    b = oauth2_path(path)
    return OidcEndpoints(authorization=f"{b}/authorize", token=f"{b}/access_token", userinfo=f"{b}/userinfo",
                         jwks=f"{b}/connect/jwk_uri", end_session=f"{b}/connect/endSession")


def realm_files(d, service):
    path = realm_path(service)
    clients = integrations_served(d, (service,), "oidc-client")
    return {**(realm_file(service, path) if path != ROOT else {}),
            **{f"am/{export_dir(path)}/OAuth2Clients/{one(i, 'ciamClientId')}.json": _json(oauth2_client(d, i, path))
               for i in clients},
            **journey_files(d, service, path), **policy_files(d, service, path),
            **saml_files(d, (service,), saml_endpoints(path)), **oidc_files(d, (service,), oidc_endpoints(path))}


def render_neutral(d):
    """Every realm AM serves: its Amster entities and its standard documents."""
    return {path: text for s in realms(d) for path, text in realm_files(d, s).items()}

"""Amster import: an AM configuration export (a directory of entity files, each {"metadata": {realm, entityType,
entityId}, "data": {...}}) read into the record. Pure.

  OAuth2Clients        -> OIDC client integrations (the standard layer), registered with the realm's identity service;
                          an integration the record already has keeps what AM doesn't hold (owners, claims, ...)
  AuthTree + its nodes -> journeys (pingamJourney) and their nodes (pingamNode)
  Applications, Policies -> policy sets and their policies
  every other entity   -> a captured config file (its settings held one by one, rebuilt byte for byte)

A realm's entities are imported only when the record has the realm: an identity service with pingamRealmPath. Values
that may be secret are withheld and named (client secrets are never read); the environment supplies them.
"""
import json

from opsdir.core.contract import Imported, Importer
from opsdir.core.directory import make_entry, one, subtree
from opsdir.core.formats import JSON
from opsdir.core.jsondata import canonical, without_secrets
from opsdir.domains.configuration.naming import CONFIG_FILES, file_dn
from opsdir.domains.configuration.record import file_entries
from opsdir.domains.federation.naming import INTEGRATIONS
from opsdir.domains.federation.schema import GRANT_TYPES, TOKEN_AUTH_METHODS
from opsdir.domains.federation.services import integrations
from .naming import (JOURNEYS, PINGAM, POLICY_SETS, dn_safe, journey_dn, node_dn, policy_dn, policy_set_dn,
                     realm_container)
from .realms import ROOT, SERVER_ROLES, realm_named

# identity and bookkeeping fields (and opsdir's own annotations in rendered files): not settings
VOLATILE = ("_id", "_rev", "_type", "createdBy", "creationDate", "lastModifiedBy", "lastModifiedDate", "x-opsdir")
OWNED_CLIENT_ATTRS = ("ciamProtocolType", "ciamClientId", "ciamRedirectUri", "ciamGrantType", "ciamTokenAuthMethod",
                      "ciamScope", "ciamPostLogoutRedirectUri", "ciamServedBy")


# ------------------------------------------------------------------ reading the export
def _parse(text):
    try:
        value = json.loads(text)
    except ValueError:
        return None
    return value if isinstance(value, dict) and isinstance(value.get("metadata"), dict) \
        and isinstance(value.get("data"), dict) else None


def entities(files):
    """(relative path, realm path or None, entity type, data) for every Amster entity file, in path order."""
    parsed = ((p, _parse(t)) for p, t in sorted(files.items()) if p.endswith(".json"))
    return tuple((p, e["metadata"].get("realm"), e["metadata"].get("entityType"), e["data"]) for p, e in parsed if e)


def _setting(section, key):
    """A setting as AM writes it: {"inherited": ..., "value": v}, or the value itself."""
    v = section.get(key)
    return v.get("value") if isinstance(v, dict) and "value" in v else v


def _list(v):
    return list(v) if isinstance(v, (list, tuple)) else ([] if v in (None, "") else [v])


def _settings(data, patterns, drop=()):
    """(An entity's own settings (identity and bookkeeping fields dropped) with secrets withheld, the pointers
    withheld: now, or already when the file was rendered from the record (its x-opsdir annotation says which))."""
    settings, held = without_secrets({k: v for k, v in data.items() if k not in (*VOLATILE, *drop)}, patterns)
    earlier = tuple((data.get("x-opsdir") or {}).get("withheld") or ())
    return settings, tuple(dict.fromkeys((*held, *earlier)))


def _entry(dn, classes, **attrs):
    return make_entry(dn, ("top", *classes), {k: tuple(v) if isinstance(v, (list, tuple)) else (v,)
                                              for k, v in attrs.items() if v not in (None, "", [], ())})


# ------------------------------------------------------------------ OAuth2 clients -> integrations
def _client(d, service, data):
    """(scope, entries, notices) for one OAuth2 client: its integration (merged with the record's), children kept."""
    cid = data["_id"]
    core, adv, oidc = (data.get(k) or {} for k in ("coreOAuth2ClientConfig", "advancedOAuth2ClientConfig",
                                                    "coreOpenIDClientConfig"))
    grants = _list(_setting(adv, "grantTypes"))
    auth = _setting(adv, "tokenEndpointAuthMethod")
    imported = {"ciamProtocolType": ("oidc-client",), "ciamClientId": (cid,),
                "ciamRedirectUri": tuple(_list(_setting(core, "redirectionUris"))),
                "ciamGrantType": tuple(g for g in grants if g in GRANT_TYPES),
                "ciamTokenAuthMethod": (auth,) if auth in TOKEN_AUTH_METHODS else (),
                "ciamScope": tuple(s.split("|", 1)[0] for s in _list(_setting(core, "scopes"))),
                "ciamPostLogoutRedirectUri": tuple(_list(_setting(oidc, "postLogoutRedirectUri"))),
                "ciamServedBy": (service.dn,)}
    existing = next((i for i in integrations(d, "oidc-client") if one(i, "ciamClientId") == cid), None)
    dn = existing.dn if existing else f"cn={cid},{INTEGRATIONS}"
    kept = {k: v for k, v in (existing.attrs.items() if existing else (("cn", (cid,)),)) if k not in OWNED_CLIENT_ATTRS}
    entry = make_entry(dn, existing.classes if existing else ("top", "ciamIntegration"),
                       {**kept, **{k: v for k, v in imported.items() if v}})
    children = tuple(e for e in subtree(d, dn) if e.norm != entry.norm) if existing else ()
    unknown = [g for g in grants if g not in GRANT_TYPES]
    notices = (*((f"client {cid}: grant types not in the standard vocabulary, not imported: {', '.join(unknown)}",)
                 if unknown else ()),
               *((f"client {cid}: its secret is not imported; each environment binds it",)
                 if _setting(core, "userpassword") else ()))
    return dn, (entry, *children), notices


# ------------------------------------------------------------------ journeys
def _page_children(data):
    return tuple(c for c in data.get("nodes") or () if isinstance(c, dict) and c.get("_id"))


def _node(journey, node_id, node_type, display, outcomes, data, patterns):
    settings, held = _settings(data or {}, patterns)
    return _entry(node_dn(journey, node_id), ("ciamObject", "pingamNode"), cn=node_id, pingamNodeType=node_type,
                  pingamDisplayName=display, pingamNodeConfig=canonical(settings) if settings else None,
                  pingamOutcome=sorted(f"{k}={v}" for k, v in outcomes.items()), pingamWithheld=list(held))


def _journey(service, tree, by_id, patterns):
    """(scope, entries, notices) for one tree: the journey and every node it and its pages use."""
    name = tree["_id"]
    j = journey_dn(one(service, "cn"), name)
    listed = {nid: n for nid, n in (tree.get("nodes") or {}).items()}
    pages = tuple(c for nid in listed for c in _page_children(by_id.get(nid) or {}))
    nodes = (*(_node(j, nid, n.get("nodeType"), n.get("displayName"), n.get("connections") or {}, by_id.get(nid),
                     patterns) for nid, n in listed.items()),
             *(_node(j, c["_id"], c.get("nodeType"), c.get("displayName"), {}, by_id.get(c["_id"]), patterns)
               for c in pages))
    missing = [nid for nid in (*listed, *(c["_id"] for c in pages)) if nid not in by_id]
    settings, _ = _settings(tree, patterns, drop=("entryNodeId", "nodes", "enabled"))
    journey = _entry(j, ("ciamObject", "pingamJourney"), cn=name, pingamRealm=service.dn,
                     pingamEntryNode=tree.get("entryNodeId"), pingamEnabled="FALSE" if tree.get("enabled") is False
                     else "TRUE", pingamTreeConfig=canonical(settings) if settings else None)
    notices = tuple(f"journey {name}: node {nid} has no exported settings" for nid in missing)
    return j, (journey, *nodes), notices


# ------------------------------------------------------------------ policy sets
def _policy_set(service, data, policies, patterns):
    name = data["_id"]
    s = policy_set_dn(one(service, "cn"), name)
    settings, _ = _settings(data, patterns, drop=("name", "applicationType"))
    policy_entries = tuple(_policy(s, p, patterns) for p in policies if p.get("applicationName") == name)
    return s, (_entry(s, ("ciamObject", "pingamPolicySet"), cn=name, pingamRealm=service.dn,
                      pingamApplicationType=data.get("applicationType"),
                      pingamSetConfig=canonical(settings) if settings else None), *policy_entries), ()


def _policy(set_dn, data, patterns):
    settings, held = _settings(data, patterns, drop=("name", "applicationName"))
    return _entry(policy_dn(set_dn, data["_id"]), ("ciamObject", "pingamPolicy"), cn=data["_id"],
                  pingamPolicyConfig=canonical(settings), pingamWithheld=list(held))


# ------------------------------------------------------------------ everything else: captured config files
def _captured(path, text, patterns):
    name = "am." + path.replace("/", ".")
    entries, notices = file_entries(JSON, text, name, f"am/{path}", patterns, SERVER_ROLES[0])
    return file_dn(name), entries, notices


# ------------------------------------------------------------------ composing
READ_AS = ("OAuth2Clients", "AuthTree", "Applications", "Policies", "Realms")


def _realm_paths(found):
    """Every realm the export mentions: those its entities live in, and the ones it defines (global Realms)."""
    defined = ((data.get("parentPath") or ROOT).rstrip("/") + "/" + data.get("name", "")
               for _, realm, kind, data in found if kind == "Realms")
    return tuple(dict.fromkeys((*(r for _, r, _, _ in found if r), *defined)))


def _in_realm(d, service, path, found, files, patterns):
    """(groups, notices) for one realm the record has."""
    mine = tuple(x for x in found if x[1] == path)
    by_id = {data.get("_id"): data for _, _, kind, data in mine if kind not in READ_AS}
    trees = tuple(data for _, _, kind, data in mine if kind == "AuthTree")
    used = {nid for t in trees for nid in (*(t.get("nodes") or {}),
                                           *(c["_id"] for nid in (t.get("nodes") or {})
                                             for c in _page_children(by_id.get(nid) or {})))}
    policies = tuple(data for _, _, kind, data in mine if kind == "Policies")
    parts = (*(_client(d, service, data) for _, _, kind, data in mine if kind == "OAuth2Clients"),
             *(_journey(service, t, by_id, patterns) for t in trees),
             *(_policy_set(service, data, policies, patterns) for _, _, kind, data in mine if kind == "Applications"),
             *(_captured(p, files[p], patterns) for p, _, kind, data in mine
               if kind not in READ_AS and data.get("_id") not in used))
    unsafe = [data.get("_id") for _, _, kind, data in mine if kind in ("OAuth2Clients", "AuthTree", "Applications")
              and not dn_safe(data.get("_id") or "")]
    kept = tuple(p for p in parts if dn_safe(p[0].split(",", 1)[0].split("=", 1)[1]))
    return (tuple((scope, entries) for scope, entries, _ in kept),
            (*(n for _, _, notices in kept for n in notices),
             *(f"{path}: {name!r} can't be a record name (it holds a DN special character); not imported"
               for name in unsafe)))


def _ou(dn):
    return make_entry(dn, ("top", "organizationalUnit"), {"ou": (dn.split(",", 1)[0].split("=", 1)[1],)})


def _containers(d, services):
    return tuple(_ou(dn) for dn in (PINGAM, JOURNEYS, POLICY_SETS, INTEGRATIONS, CONFIG_FILES,
                                   *(realm_container(b, one(s, "cn")) for s in services for b in (JOURNEYS, POLICY_SETS))))


def read_export(files, d, patterns):
    """Imported from an Amster export: every realm the record has; the others named in notices."""
    found = entities(files)
    paths = _realm_paths(found)
    placed = {p: realm_named(d, p) for p in paths}
    results = tuple(_in_realm(d, s, p, found, files, patterns) for p, s in placed.items() if s is not None)
    global_files = tuple(_captured(p, files[p], patterns) for p, realm, kind, _ in found
                         if realm is None and kind != "Realms")
    unplaced = [p for p, s in placed.items() if s is None]
    return Imported(
        containers=_containers(d, tuple(s for s in placed.values() if s is not None)),
        groups=(*(g for groups, _ in results for g in groups), *((scope, entries) for scope, entries, _ in global_files)),
        notices=(*(n for _, notices in results for n in notices), *(n for _, _, notices in global_files for n in notices),
                 *(f"realm {p}: no identity service in the record is this realm (record one with pingamRealmPath "
                   f"{p}); its entities are not imported" for p in unplaced),
                 *(f"not an Amster entity, not imported: {p}" for p in sorted(files)
                   if p.endswith(".json") and _parse(files[p]) is None)))


AMSTER = Importer("amster", "an AM configuration exported with Amster (export-config)", read_export)

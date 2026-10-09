"""PingFederate's configuration read into the record. Pure.

Reads the Admin API bulk export (GET /pf-admin-api/v1/bulk/export: {"metadata": {"pfVersion"}, "operations":
[{"operationType", "resourceType", "items"}]}) and this adapter's own rendered requests
(pingfederate/admin-api/requests.json: each request's body an item of the resource type its path names), so a render
reads back as it was.

  /idp/spConnections              -> SAML service providers (saml2-sp integrations): entity ID, default ACS URL and
                                     binding, the claims of the attribute contract (linked to user-schema records),
                                     the certificate its assertions are signed with
  /sp/idpConnections              -> partner identity providers (saml2-idp integrations): entity ID, JIT base DN,
                                     the partner's signing certificates, the id PingFederate knows the connection by
                                     (auxiliary class pingfedConnection: what authentication policies name it by)
  /oauth/clients                  -> OAuth/OIDC clients (oidc-client integrations): client ID, redirect URIs, grant
                                     types, PKCE, token endpoint authentication, restricted scopes
  /keyPairs/signing, /sslServer   -> certificate facts of PingFederate's own keys (never the keys), carrying the key
                                     pair's id (pingfedKeyPair: what token managers sign with)
  /oauth/accessTokenManagers,      -> access token managers (plugins), OIDC policies, the authorization server's
    /oauth/openIdConnect/policies,    settings (opsdir_adapter_pingfederate.oauth); a client is linked to the token
    /oauth/authServerSettings         manager and OIDC policy it names
  /dataStores                     -> data stores (pingfedDataStore, opsdir_adapter_pingfederate.datastores): hosts that
                                     are a service name become its role, the bind account its consumer record,
                                     credentials withheld
  /passwordCredentialValidators,  -> plugin instances (pingfedPlugin, opsdir_adapter_pingfederate.plugins), linked to
    /idp/adapters,                   the objects their settings name, secrets withheld
    /authenticationSelectors
  /authenticationPolicyContracts, -> policy contracts, the default policy's trees, fragments
    /authenticationPolicies/default,  (opsdir_adapter_pingfederate.policies), linked to what they run
    /authenticationPolicies/fragments
Integrations are matched by entity ID or client ID, certificates by fingerprint, data stores by id; what the record
holds beyond the export (owners, criticality, populations, what a claim is transformed with, a data store's credential
role) is kept. Where PingFederate's names are coarser than the standard ones (SECRET for three client authentication
methods), the record's value is kept when it is one of them. Client secrets and data store passwords are never read.
Adapters, token managers, policies and where clients, grants and sessions are stored are named, read later.
"""
import re
from functools import reduce
from types import MappingProxyType

from opsdir.core.contract import Imported, Importer
from opsdir.core.directory import (fingerprint, get, gtime_of_iso, make_entry, norm_dn, one, ou_entry,
                                   rdn_value, subtree, values, within)
from opsdir.core.sources import json_document
from opsdir.domains.directory.user_schema import attribute_records
from opsdir.domains.federation.naming import INTEGRATIONS
from opsdir.domains.federation.services import identity_services, integrations
from opsdir.domains.messaging.naming import EXTERNAL_SERVICES, MAIL_SENDERS
from opsdir.domains.pki.credentials import certificates_by_fingerprint
from opsdir.domains.pki.naming import CERTIFICATES
from opsdir.core.jsondata import canonical
from .datastores import data_store_groups
from .withheld import withheld_settings
from .naming import (CAPTCHA_PROVIDERS, CONTRACTS, DATA_STORES, FRAGMENTS, IDP_ADAPTERS, NOTIFICATION_PUBLISHERS,
                     OIDC_POLICIES, PINGFEDERATE, POLICIES, SELECTORS, SETTINGS, TOKEN_MANAGERS, VALIDATORS)
from .generic import resource_groups
from .naming import RESOURCES as RESOURCES_BRANCH, STORAGE
from .oauth import client_links, oauth_groups
from .messaging import messaging_groups
from .objects import CONNECTION, KEY_PAIR, ref_dn
from .plugins import KINDS, plugin_groups
from .policies import policy_groups
from .naming import SERVER_ROLES
from .admin_api import request_type
from .connections import BINDINGS, CLIENT_AUTH, GRANT_TYPES

RESOURCES = MappingProxyType({
    "/idp/spConnections": "sp", "/sp/idpConnections": "idp", "/oauth/clients": "client",
    "/keyPairs/signing": "signing", "/keyPairs/sslServer": "ssl", "/dataStores": "datastore",
    **{k.resource: kind for kind, k in KINDS.items()}, "/authenticationPolicyContracts": "contract",
    "/authenticationPolicies/default": "policy", "/authenticationPolicies/fragments": "fragment",
    "/oauth/openIdConnect/policies": "oidc-policy", "/oauth/authServerSettings": "auth-server"})
# the kinds of objects other objects name by id (opsdir_adapter_pingfederate.objects)
NAMED_KINDS = ("datastore", *KINDS, "contract", "fragment", "oidc-policy")
KEY_ROLES = MappingProxyType({"signing": ("saml-signing", "pf-signing-key"), "ssl": ("tls-server", "sso-tls-keystore")})
OWNED = MappingProxyType({
    "saml2-sp": ("ciamProtocolType", "ciamEntityId", "ciamAcsUrl", "ciamSamlBinding"),
    "saml2-idp": ("ciamProtocolType", "ciamEntityId"),
    "oidc-client": ("ciamProtocolType", "ciamClientId", "ciamRedirectUri", "ciamGrantType", "ciamPkceRequired",
                    "ciamTokenAuthMethod", "ciamScope")})
_UNSAFE = re.compile(r"[^A-Za-z0-9._-]")


def _inverse(mapping):
    return {pf: tuple(std for std, v in mapping.items() if v == pf) for pf in dict.fromkeys(mapping.values())}


PF_GRANTS, PF_AUTH, PF_BINDINGS = _inverse(GRANT_TYPES), _inverse(CLIENT_AUTH), _inverse(BINDINGS)
# where one PingFederate name stands for several standard ones and the record says nothing yet: the standard's default
# (RFC 7591 section 2: client_secret_basic when a client doesn't say; RFC 8705: tls_client_auth, PKI-bound)
DEFAULTS = MappingProxyType({"SECRET": "client_secret_basic", "CLIENT_CERT": "tls_client_auth"})


# ------------------------------------------------------------------ reading the export
def _operations(doc):
    """A document's operations: a bulk export's, or a rendered requests document's (one per request)."""
    if isinstance(doc.get("requests"), list):                     # a key pair's import holds no record fact
        return [{"operationType": "SAVE", "resourceType": request_type(r), "items": [r.get("body")]}
                for r in doc["requests"] if isinstance(r, dict) and not str(r.get("path", "")).endswith("/import")]
    return [op for op in doc.get("operations") or () if isinstance(op, dict)]


def resources(files):
    """({kind: items}, {resource type not modeled: items}, PingFederate version, unreadable paths) from the export."""
    parsed = {p: json_document(t) for p, t in files.items() if p.endswith(".json")}
    bulk = [op for doc in parsed.values() if isinstance(doc, dict) for op in _operations(doc)]
    found = ((RESOURCES.get(op.get("resourceType")), item) for op in bulk if op.get("operationType", "SAVE") == "SAVE"
             for item in op.get("items") or ())
    pairs = [(k, i) for k, i in found if k and isinstance(i, dict)]
    return ({kind: tuple(i for k, i in pairs if k == kind) for kind in (*RESOURCES.values(),)},
            {t: tuple(i for op in bulk if op.get("resourceType") == t and op.get("operationType", "SAVE") == "SAVE"
                      for i in op.get("items") or () if isinstance(i, dict))
             for t in dict.fromkeys(op.get("resourceType") for op in bulk)
             if isinstance(t, str) and t not in RESOURCES},
            next((doc["metadata"].get("pfVersion") if isinstance(doc.get("metadata"), dict) else doc["pingFederate"]
                  for doc in parsed.values() if isinstance(doc, dict)
                  and (isinstance(doc.get("metadata"), dict) or doc.get("pingFederate"))), None),
            tuple(p for p, doc in parsed.items() if doc is None))


def _name(v, taken):
    base = _UNSAFE.sub("-", v or "").strip("-") or "pingfederate"
    return next(n for n in (base, *(f"{base}-{i}" for i in range(2, 1000))) if n.lower() not in taken)


def _standard(pf_values, table, held):
    """Standard values for PingFederate's names: the record's value when it is one they stand for, else the only one,
    else the standard's default; names with none of these are returned apart."""
    def one_of(pf):
        options = table.get(pf, ())
        kept = [h for h in held if h in options]
        return kept or (list(options[:1]) if len(options) == 1 else [DEFAULTS[pf]] if pf in DEFAULTS else [])
    return tuple(dict.fromkeys(s for pf in pf_values for s in one_of(pf))), [pf for pf in pf_values if not one_of(pf)]


# ------------------------------------------------------------------ certificates
def _cert_facts(view):
    """Certificate facts from a PingFederate certificate or key pair view (None without fingerprint or expiry)."""
    fp, expires = fingerprint(view.get("sha256Fingerprint")), gtime_of_iso(view.get("expires"))
    if not fp or not expires:
        return None
    subject, issuer = view.get("subjectDN"), view.get("issuerDN")
    return {"ciamFingerprint": (fp,), "ciamNotAfter": (expires,),
            "ciamNotBefore": tuple(filter(None, (gtime_of_iso(view.get("validFrom")),))),
            "ciamSubject": tuple(filter(None, (subject,))),
            "ciamIssuer": ("self-signed",) if issuer and issuer == subject else tuple(filter(None, (issuer,))),
            "ciamSubjectAltName": tuple(view.get("subjectAlternativeNames") or ())}


def _certificate(d, held, facts, name, purpose, key_role=None, key_pair=None):
    """The certificate entry: the record's (by fingerprint) with the facts the export gives replacing its own (facts it
    doesn't give are kept), or a new one; key_pair: the id of the PingFederate key pair it is the certificate of."""
    facts = {**facts, **({"pingfedKeyPairId": (key_pair,)} if key_pair else {})}
    aux = ("pingfedKeyPair",) if key_pair else ()
    given = same_order(held, {k: v for k, v in facts.items() if v})
    if held is not None:
        return make_entry(held.dn, tuple(dict.fromkeys((*held.classes, *aux))),
                          {**{k: v for k, v in held.attrs.items() if k not in given}, **given})
    return make_entry(f"cn={name},{CERTIFICATES}", ("top", "ciamCertificate", *aux),
                      {"cn": (name,), "ciamCertPurpose": (purpose,),
                       **({"ciamKeyRole": (key_role,)} if key_role else {}),
                       **{k: v for k, v in facts.items() if v}})


def certificate_entries(d, found):
    """{fingerprint: certificate entry} for PingFederate's own key pairs (carrying the key pair's id: pingfedKeyPair)
    and the certificates of its connections (a partner identity provider's signing certificates; a service provider's
    own signing or encryption certificates)."""
    held = certificates_by_fingerprint(d)
    views = (*((kp, *KEY_ROLES[kind], f"pf-{kp.get('id')}", kp.get("id")) for kind in ("signing", "ssl")
               for kp in found[kind]),
             *((c.get("certView") or {}, "partner-signing", None, f"{conn.get('id') or conn.get('name')}-signing", None)
               for conn in found["idp"] for c in ((conn.get("credentials") or {}).get("certs") or ())
               if not c.get("encryptionCert")),
             *((c.get("certView") or {}, "saml-encryption" if c.get("encryptionCert") else "saml-signing", None,
                f"{conn.get('id') or conn.get('name')}-sp-"
                f"{'encryption' if c.get('encryptionCert') else 'signing'}", None)
               for conn in found["sp"] for c in ((conn.get("credentials") or {}).get("certs") or ())))
    facts = [(f, purpose, role, name, kp) for view, purpose, role, name, kp in views for f in (_cert_facts(view),) if f]

    def add(made, fact):
        f, purpose, role, name, kp = fact
        fp = f["ciamFingerprint"][0]
        if fp in made:
            return made
        taken = {one(c, "cn").lower() for c in (*held.values(), *made.values())}
        return {**made, fp: _certificate(d, held.get(fp), f, _name(name, taken), purpose, role, kp)}
    return reduce(add, facts, {})


# ------------------------------------------------------------------ integrations
def linked(held, found):
    """The certificates an integration uses: the record's links, then those the export adds (an export can't tell that a
    link the record holds is gone: the server's TLS certificate, say, is linked by the record, not by a connection)."""
    return tuple(dict.fromkeys((*(values(held, "ciamUsesCertificate") if held is not None else ()), *found)))


def same_order(held, attrs):
    """attrs, each multi-valued attribute in the record's order when it holds the same values (values are a set)."""
    return {k: (values(held, k) if held is not None and set(values(held, k)) == set(v) else v)
            for k, v in attrs.items()}


def _merged(held, dn, name, protocol, imported, owned, served, aux=()):
    """The integration: the record's with what the export says (attributes it owns replaced), or a new one; aux: the
    auxiliary classes the export says it has."""
    kept = {k: v for k, v in (held.attrs.items() if held else ()) if k not in owned}
    base = kept or {"cn": (name,), **({"ciamServedBy": (served.dn,)} if served else {})}
    return make_entry(dn, tuple(dict.fromkeys((*(held.classes if held else ("top", "ciamIntegration")), *aux))),
                      {**base, "ciamProtocolType": (protocol,),
                       **same_order(held, {k: v for k, v in imported.items() if v})})


def _claims(d, dn, held, contract, fulfillment, user_attrs, label):
    """(claim entries, notices): the attribute contract's claims, each linked to the attribute it is fulfilled from."""
    names = [a.get("name") for a in (contract.get("extendedAttributes") or ()) if a.get("name")]
    source = {n: (fulfillment.get(n) or {}) for n in names}
    placed = [(n, user_attrs.get((source[n].get("value") or "").lower())) for n in names]
    base = f"ou=claims,{dn}"
    old = {e.norm: e for e in subtree(d, base)} if held else {}
    entries = tuple(make_entry(cdn, ("top", "ciamClaimMap"),
                               {**{k: v for k, v in (old[norm_dn(cdn)].attrs.items() if norm_dn(cdn) in old else ())
                                   if k not in ("ciamClaimName", "ciamSourceAttribute")},
                                "cn": (n,), "ciamClaimName": (n,), "ciamSourceAttribute": (attr.dn,),
                                **({"ciamTransform": (source[n]["x-opsdir-transform"],)}
                                   if source[n].get("x-opsdir-transform") else {})})
                    for n, attr in placed if attr is not None and not _UNSAFE.search(n)
                    for cdn in (f"cn={n},{base}",))
    container = old.get(norm_dn(base)) or ou_entry(base)
    missing = [f"{n} ({source[n].get('value') or 'no source attribute'})" for n, attr in placed if attr is None]
    return ((container, *entries) if entries else ()), \
        ((f"{label}: claims from values the record has no user-schema record for, not recorded: "
          f"{', '.join(missing)}",) if missing else ())


def signing_of(sp, keys):
    """Fingerprint of the key pair an SP connection signs with (credentials.signingSettings.signingKeyPairRef)."""
    ref = (((sp.get("credentials") or {}).get("signingSettings") or {}).get("signingKeyPairRef") or {}).get("id")
    return tuple(filter(None, (keys.get(ref),)))


HELD = ("pingfedConfig", "pingfedWithheld")


def held_settings(item, patterns):
    """The attributes holding a connection's or client's own PingFederate settings (secrets withheld), as the Admin API
    writes them: what a render puts the record's standard facts back into."""
    config, withheld = withheld_settings(item, patterns)
    return {"pingfedConfig": (canonical(config),), "pingfedWithheld": withheld}


def _held_notice(label, imported, held):
    return ((f"{label}: its secrets are withheld; set pingfedCredentialRole to the secret role that holds them",)
            if imported["pingfedWithheld"] and not (held is not None and one(held, "pingfedCredentialRole")) else ())


def _sp(d, sp, certs, keys, user_attrs, held, dn, name, served, patterns):
    browser = sp.get("spBrowserSso") or {}
    endpoints = browser.get("ssoServiceEndpoints") or ()
    acs = next((e for e in endpoints if e.get("isDefault")), endpoints[0] if endpoints else {})
    binding, _ = _standard([acs.get("binding")] if acs.get("binding") else [], PF_BINDINGS,
                           values(held, "ciamSamlBinding") if held else ())
    used = linked(held, (certs[fp].dn for fp in (*signing_of(sp, keys), *certs_of(sp)) if fp in certs))
    imported = {"ciamEntityId": (sp.get("entityId"),), "ciamAcsUrl": tuple(filter(None, (acs.get("url"),))),
                "ciamSamlBinding": binding, "ciamUsesCertificate": used, **held_settings(sp, patterns)}
    entry = _merged(held, dn, name, "saml2-sp", imported, (*OWNED["saml2-sp"], "ciamUsesCertificate", *HELD), served,
                    ("pingfedHeldSettings",))
    mapping = next(iter(browser.get("adapterMappings") or ()), {})
    claims, notices = _claims(d, dn, held, browser.get("attributeContract") or {},
                              mapping.get("attributeContractFulfillment") or {}, user_attrs, f"SP connection {name}")
    rest = _others(d, dn, held, claims)
    return (entry, *claims, *rest), (*notices, *_held_notice(f"SP connection {name}", imported, held))


def certs_of(conn):
    """Fingerprints of the certificates a connection names (its credentials, or this adapter's own annotation)."""
    return (*(fingerprint((c.get("certView") or {}).get("sha256Fingerprint"))
              for c in ((conn.get("credentials") or {}).get("certs") or ())),
            *(fingerprint(f) for f in ((conn.get("x-opsdir") or {}).get("certificateFingerprints") or ())))


def _others(d, dn, held, replaced):
    """The record's entries under an integration that the import doesn't replace (kept as they are)."""
    mine = {e.norm for e in replaced}
    claims_base = norm_dn(f"ou=claims,{dn}")
    return tuple(e for e in (subtree(d, dn) if held else ()) if e.norm != norm_dn(dn) and e.norm not in mine
                 and not (replaced and within(e.norm, claims_base)))


def _idp(d, idp, certs, held, dn, name, served, patterns):
    browser = idp.get("idpBrowserSso") or {}
    jit = ((browser.get("jitProvisioning") or {}).get("userRepository") or {}).get("baseDn")
    used = linked(held, (certs[fp].dn for fp in certs_of(idp) if fp in certs))
    cid = idp.get("id")
    imported = {"ciamEntityId": (idp.get("entityId"),), "ciamJitBaseDn": tuple(filter(None, (jit,))),
                "ciamUsesCertificate": used, "pingfedConnectionId": tuple(filter(None, (cid,))),
                **held_settings(idp, patterns)}
    owned = (*OWNED["saml2-idp"], *(("ciamJitBaseDn",) if jit else ()), "ciamUsesCertificate", "pingfedConnectionId",
             *HELD)
    return (_merged(held, dn, name, "saml2-idp", imported, owned, served,
                    (*(("pingfedConnection",) if cid else ()), "pingfedHeldSettings")),
            *_others(d, dn, held, ())), _held_notice(f"IdP connection {name}", imported, held)


def _client(d, client, held, dn, name, served, exported, patterns):
    grants, odd_grants = _standard(client.get("grantTypes") or (), PF_GRANTS,
                                   values(held, "ciamGrantType") if held else ())
    auth_type = (client.get("clientAuth") or {}).get("type")
    auth, _ = _standard([auth_type] if auth_type else [], PF_AUTH, values(held, "ciamTokenAuthMethod") if held else ())
    imported = {"ciamClientId": (client.get("clientId"),), "ciamRedirectUri": tuple(client.get("redirectUris") or ()),
                "ciamGrantType": grants, "ciamTokenAuthMethod": auth[:1],
                "ciamPkceRequired": ("TRUE",) if client.get("requireProofKeyForCodeExchange") else (),
                "ciamScope": tuple(client.get("restrictedScopes") or ()) if client.get("restrictScopes") else ()}
    uses, unlinked = client_links(d, client, exported)
    imported = {**imported, "pingfedUses": uses, **held_settings(client, patterns)}
    entry = _merged(held, dn, name, "oidc-client", imported, (*OWNED["oidc-client"], "pingfedUses", *HELD), served,
                    (*(("pingfedClient",) if uses else ()), "pingfedHeldSettings"))
    secret = client.get("clientAuth") or {}
    notices = (*unlinked, *((f"client {client.get('clientId')}: grant types with no single standard name, "
                  f"not recorded: {', '.join(odd_grants)}",) if odd_grants else ()),
               *((f"client {client.get('clientId')}: its secret is not imported; set pingfedCredentialRole to the "
                   "secret role each environment binds it with",)
                 if (secret.get("secret") or secret.get("encryptedSecret"))
                 and not (held is not None and one(held, "pingfedCredentialRole")) else ()))
    return (entry, *_others(d, dn, held, ())), notices


def integration_groups(d, found, certs, exported, patterns=()):
    """(groups, notices, {("idp-connection", id): DN}): an integration for every SP connection, IdP connection and
    OAuth client in the export (a client linked to the token manager and OIDC policy it names: exported {(kind, id):
    DN}), and where each IdP connection's is (what policies that name it link to)."""
    user_attrs = attribute_records(d)
    pf_services = identity_services(d, SERVER_ROLES)
    served = pf_services[0] if len(pf_services) == 1 else None
    by_entity = {(one(i, "ciamProtocolType"), one(i, "ciamEntityId")): i
                 for i in integrations(d) if one(i, "ciamEntityId")}
    by_client = {one(i, "ciamClientId"): i for i in integrations(d, "oidc-client") if one(i, "ciamClientId")}
    wanted = (*(("sp", x, by_entity.get(("saml2-sp", x.get("entityId"))), x.get("id") or x.get("name"))
                for x in found["sp"]),
              *(("idp", x, by_entity.get(("saml2-idp", x.get("entityId"))), x.get("id") or x.get("name"))
                for x in found["idp"]),
              *(("client", x, by_client.get(x.get("clientId")), x.get("clientId")) for x in found["client"]))

    def place(acc, w):
        kind, item, held, raw = w
        taken = {rdn_value(i).lower() for i in integrations(d)} | {n.lower() for _, _, _, n, _ in acc}
        name = rdn_value(held) if held else _name(raw, taken)
        return (*acc, (kind, item, held, name, held.dn if held else f"cn={name},{INTEGRATIONS}"))
    placed = reduce(place, wanted, ())
    keys = {kp.get("id"): fingerprint(kp.get("sha256Fingerprint")) for kp in found["signing"]}
    built = tuple(_sp(d, item, certs, keys, user_attrs, held, dn, name, served, patterns) if kind == "sp"
                  else _idp(d, item, certs, held, dn, name, served, patterns) if kind == "idp"
                  else _client(d, item, held, dn, name, served, exported, patterns)
                  for kind, item, held, name, dn in placed)
    return (tuple((dn, entries) for (_, _, _, _, dn), (entries, _) in zip(placed, built)),
            (*(n for _, ns in built for n in ns),
             *(f"new integration {name} ({kind}), not in the record before: give it an owner"
               for kind, _, held, name, _ in placed if held is None)),
            {(CONNECTION, item.get("id")): dn for kind, item, _, _, dn in placed if kind == "idp" and item.get("id")})


# ------------------------------------------------------------------ the importer
def read_export(files, d, patterns, at=None):
    """Imported from a PingFederate bulk export (or this adapter's rendered files)."""
    found, unread, version, unreadable = resources(files)
    certs = certificate_entries(d, found)
    keys = {fingerprint(kp.get("sha256Fingerprint")): kp.get("id") for k in ("signing", "ssl") for kp in found[k]}
    named_ = {**{(kind, item.get("id")): ref_dn(kind, item.get("id")) for kind in NAMED_KINDS for item in found[kind]},
              **{(KEY_PAIR, keys[fp]): c.dn for fp, c in certs.items() if fp in keys}}
    groups, notices, connections = integration_groups(d, found, certs, named_, patterns)
    exported = {**named_, **connections}
    stores, store_notices = data_store_groups(d, found["datastore"], patterns)
    plugins, plugin_notices = plugin_groups(d, found, patterns, exported)
    policies, policy_notices = policy_groups(d, found, exported)
    oauth, oauth_notices = oauth_groups(d, found, patterns, exported)
    held, held_notices = resource_groups(d, unread, patterns)
    messages, message_notices = messaging_groups(d, found)
    nothing = not any(found.values()) and not unread
    branches = (*((VALIDATORS,) if found["validator"] else ()), *((IDP_ADAPTERS,) if found["idp-adapter"] else ()),
                *((SELECTORS,) if found["selector"] else ()), *((CONTRACTS,) if found["contract"] else ()),
                *((POLICIES,) if found["policy"] else ()), *((FRAGMENTS,) if found["fragment"] else ()),
                *((TOKEN_MANAGERS,) if found["access-token-manager"] else ()),
                *((NOTIFICATION_PUBLISHERS,) if found["notification-publisher"] else ()),
                *((CAPTCHA_PROVIDERS,) if found["captcha-provider"] else ()),
                *((EXTERNAL_SERVICES,) if messages else ()),
                *((MAIL_SENDERS,) if any(dn.endswith(MAIL_SENDERS) for dn, _ in messages) else ()),
                *((OIDC_POLICIES,) if found["oidc-policy"] else ()), *((SETTINGS,) if found["auth-server"] else ()),
                *((RESOURCES_BRANCH,) if unread else ()))
    return Imported(
        containers=tuple(ou_entry(b) for b in (INTEGRATIONS, CERTIFICATES, PINGFEDERATE, DATA_STORES, *branches)),
        groups=(*((c.dn, (c,)) for c in certs.values()), *groups, *stores, *plugins, *policies, *oauth, *held,
                *messages),
        notices=(*((f"exported from PingFederate {version}",) if version else ()), *notices, *store_notices,
                 *plugin_notices, *policy_notices, *oauth_notices, *message_notices,
                 *held_notices,
                 *(("where PingFederate keeps OAuth clients, grants and sessions is set in its nodes' hivemodule.xml, "
                    "not the Admin API: import the nodes' files with pingfederate/node-files",)
                   if found["client"] and get(d, STORAGE) is None else ()),
                 *(f"not JSON, not read: {p}" for p in unreadable),
                 *(("no PingFederate configuration found (a bulk export, or pingfederate/*.json)",)
                   if nothing else ())))


BULK = Importer("bulk", "a PingFederate Admin API bulk export (/bulk/export), or this adapter's rendered files",
                read_export)

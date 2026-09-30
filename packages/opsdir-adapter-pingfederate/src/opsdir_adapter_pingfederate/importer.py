"""PingFederate's configuration read into the record. Pure.

Reads the Admin API bulk export (GET /pf-admin-api/v1/bulk/export: {"metadata": {"pfVersion"}, "operations":
[{"operationType", "resourceType", "items"}]}) and this adapter's own rendered files (pingfederate/*.json), so a
render reads back as it was.

  /idp/spConnections              -> SAML service providers (saml2-sp integrations): entity ID, default ACS URL and
                                     binding, the claims of the attribute contract (linked to user-schema records),
                                     the certificate its assertions are signed with
  /sp/idpConnections              -> partner identity providers (saml2-idp integrations): entity ID, JIT base DN,
                                     the partner's signing certificates
  /oauth/clients                  -> OAuth/OIDC clients (oidc-client integrations): client ID, redirect URIs, grant
                                     types, PKCE, token endpoint authentication, restricted scopes
  /keyPairs/signing, /sslServer   -> certificate facts of PingFederate's own keys (never the keys)
Integrations are matched by entity ID or client ID, certificates by fingerprint; what the record holds beyond the
export (owners, criticality, populations, what a claim is transformed with) is kept. Where PingFederate's names are
coarser than the standard ones (SECRET for three client authentication methods), the record's value is kept when it
is one of them. Client secrets and data store passwords are never read. Data stores are checked against the record
(the directory account PingFederate binds as, the names it reaches the directory by); adapters, token managers,
policies and where clients, grants and sessions are stored are PingFederate depth, read later.
"""
import datetime as dt
import json
import re
from collections import Counter
from functools import reduce

from opsdir.core.contract import Imported, Importer
from opsdir.core.directory import children, get, make_entry, norm_dn, one, rdn_value, subtree, values
from opsdir.domains.directory.naming import CONSUMERS
from opsdir.domains.directory.user_schema import attribute_records
from opsdir.domains.federation.naming import INTEGRATIONS
from opsdir.domains.federation.services import identity_services, integrations
from opsdir.domains.pki.naming import CERTIFICATES
from .render import BINDINGS, CLIENT_AUTH, GRANT_TYPES, SERVER_ROLES

RESOURCES = {"/idp/spConnections": "sp", "/sp/idpConnections": "idp", "/oauth/clients": "client",
             "/keyPairs/signing": "signing", "/keyPairs/sslServer": "ssl", "/dataStores": "datastore"}
RENDERED = {"sp-connections.json": "sp", "idp-connections.json": "idp", "oidc-clients.json": "client"}
KEY_ROLES = {"signing": ("saml-signing", "pf-signing-key"), "ssl": ("tls-server", "sso-tls-keystore")}
OWNED = {"saml2-sp": ("ciamProtocolType", "ciamEntityId", "ciamAcsUrl", "ciamSamlBinding"),
         "saml2-idp": ("ciamProtocolType", "ciamEntityId"),
         "oidc-client": ("ciamProtocolType", "ciamClientId", "ciamRedirectUri", "ciamGrantType", "ciamPkceRequired",
                         "ciamTokenAuthMethod", "ciamScope")}
_UNSAFE = re.compile(r"[^A-Za-z0-9._-]")


def _inverse(mapping):
    return {pf: tuple(std for std, v in mapping.items() if v == pf) for pf in dict.fromkeys(mapping.values())}


PF_GRANTS, PF_AUTH, PF_BINDINGS = _inverse(GRANT_TYPES), _inverse(CLIENT_AUTH), _inverse(BINDINGS)
# where one PingFederate name stands for several standard ones and the record says nothing yet: the standard's default
# (RFC 7591 section 2: client_secret_basic when a client doesn't say; RFC 8705: tls_client_auth, PKI-bound)
DEFAULTS = {"SECRET": "client_secret_basic", "CLIENT_CERT": "tls_client_auth"}


# ------------------------------------------------------------------ reading the export
def _json(text):
    try:
        return json.loads(text)
    except ValueError:
        return None


def resources(files):
    """({kind: items}, {resource type not read: count}, PingFederate version, unreadable paths) from the export."""
    parsed = {p: _json(t) for p, t in files.items() if p.endswith(".json")}
    bulk = [op for doc in parsed.values() if isinstance(doc, dict)
            for op in doc.get("operations") or () if isinstance(op, dict)]
    rendered = [(RENDERED[p.rsplit("/", 1)[-1]], item) for p, doc in parsed.items()
                if p.rsplit("/", 1)[-1] in RENDERED and isinstance(doc, list) for item in doc]
    found = ((RESOURCES.get(op.get("resourceType")), item) for op in bulk if op.get("operationType", "SAVE") == "SAVE"
             for item in op.get("items") or ())
    pairs = [(k, i) for k, i in (*found, *rendered) if k and isinstance(i, dict)]
    return ({kind: tuple(i for k, i in pairs if k == kind) for kind in (*RESOURCES.values(),)},
            Counter(op.get("resourceType") for op in bulk if op.get("resourceType") not in RESOURCES),
            next((doc["metadata"].get("pfVersion") for doc in parsed.values()
                  if isinstance(doc, dict) and isinstance(doc.get("metadata"), dict)), None),
            tuple(p for p, doc in parsed.items() if doc is None))


# ------------------------------------------------------------------ values
def fingerprint(v):
    """A fingerprint as the record writes it: uppercase hex pairs joined by colons."""
    h = re.sub(r"[^0-9A-Fa-f]", "", v or "").upper()
    return ":".join(h[i:i + 2] for i in range(0, len(h), 2))


def _gtime(v):
    try:
        return dt.datetime.fromisoformat((v or "").replace("Z", "+00:00")).astimezone(dt.timezone.utc) \
            .strftime("%Y%m%d%H%M%SZ")
    except ValueError:
        return None


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
    fp, expires = fingerprint(view.get("sha256Fingerprint")), _gtime(view.get("expires"))
    if not fp or not expires:
        return None
    subject, issuer = view.get("subjectDN"), view.get("issuerDN")
    return {"ciamFingerprint": (fp,), "ciamNotAfter": (expires,),
            "ciamNotBefore": tuple(filter(None, (_gtime(view.get("validFrom")),))),
            "ciamSubject": tuple(filter(None, (subject,))),
            "ciamIssuer": ("self-signed",) if issuer and issuer == subject else tuple(filter(None, (issuer,))),
            "ciamSubjectAltName": tuple(view.get("subjectAlternativeNames") or ())}


def _certificate(d, held, facts, name, purpose, key_role=None):
    """The certificate entry: the record's (by fingerprint) with the facts the export gives replacing its own (facts it
    doesn't give are kept), or a new one."""
    given = same_order(held, {k: v for k, v in facts.items() if v})
    if held is not None:
        return make_entry(held.dn, held.classes, {**{k: v for k, v in held.attrs.items() if k not in given}, **given})
    return make_entry(f"cn={name},{CERTIFICATES}", ("top", "ciamCertificate"),
                      {"cn": (name,), "ciamCertPurpose": (purpose,), **({"ciamKeyRole": (key_role,)} if key_role else {}),
                       **{k: v for k, v in facts.items() if v}})


def certificate_entries(d, found):
    """{fingerprint: certificate entry} for PingFederate's own key pairs and the certificates of its connections (a
    partner identity provider's signing certificates; a service provider's own signing or encryption certificates)."""
    held = {fingerprint(one(c, "ciamFingerprint")): c for c in children(d, CERTIFICATES, "ciamCertificate")}
    views = (*((kp, *KEY_ROLES[kind], f"pf-{kp.get('id')}") for kind in ("signing", "ssl") for kp in found[kind]),
             *((c.get("certView") or {}, "partner-signing", None, f"{conn.get('id') or conn.get('name')}-signing")
               for conn in found["idp"] for c in ((conn.get("credentials") or {}).get("certs") or ())
               if not c.get("encryptionCert")),
             *((c.get("certView") or {}, "saml-encryption" if c.get("encryptionCert") else "saml-signing", None,
                f"{conn.get('id') or conn.get('name')}-sp-{'encryption' if c.get('encryptionCert') else 'signing'}")
               for conn in found["sp"] for c in ((conn.get("credentials") or {}).get("certs") or ())))
    facts = [(f, purpose, role, name) for view, purpose, role, name in views for f in (_cert_facts(view),) if f]

    def add(made, fact):
        f, purpose, role, name = fact
        fp = f["ciamFingerprint"][0]
        if fp in made:
            return made
        taken = {one(c, "cn").lower() for c in (*held.values(), *made.values())}
        return {**made, fp: _certificate(d, held.get(fp), f, _name(name, taken), purpose, role)}
    return reduce(add, facts, {})


# ------------------------------------------------------------------ integrations
def linked(held, found):
    """The certificates an integration uses: the record's links, then those the export adds (an export can't tell that a
    link the record holds is gone: the server's TLS certificate, say, is linked by the record, not by a connection)."""
    return tuple(dict.fromkeys((*(values(held, "ciamUsesCertificate") if held is not None else ()), *found)))


def same_order(held, attrs):
    """attrs, each multi-valued attribute in the record's order when it holds the same values (values are a set)."""
    return {k: (values(held, k) if held is not None and set(values(held, k)) == set(v) else v) for k, v in attrs.items()}


def _merged(held, dn, name, protocol, imported, owned, served):
    """The integration: the record's with what the export says (attributes it owns replaced), or a new one."""
    kept = {k: v for k, v in (held.attrs.items() if held else ()) if k not in owned}
    base = kept or {"cn": (name,), **({"ciamServedBy": (served.dn,)} if served else {})}
    return make_entry(dn, held.classes if held else ("top", "ciamIntegration"),
                      {**base, "ciamProtocolType": (protocol,), **same_order(held, {k: v for k, v in imported.items() if v})})


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
    container = old.get(norm_dn(base)) or make_entry(base, ("top", "organizationalUnit"), {"ou": ("claims",)})
    missing = [f"{n} ({source[n].get('value') or 'no source attribute'})" for n, attr in placed if attr is None]
    return ((container, *entries) if entries else ()), \
        ((f"{label}: claims from values the record has no user-schema record for, not recorded: "
          f"{', '.join(missing)}",) if missing else ())


def signing_of(sp, keys):
    """Fingerprint of the key pair an SP connection signs with (credentials.signingSettings.signingKeyPairRef)."""
    ref = (((sp.get("credentials") or {}).get("signingSettings") or {}).get("signingKeyPairRef") or {}).get("id")
    return tuple(filter(None, (keys.get(ref),)))


def _sp(d, sp, certs, keys, user_attrs, held, dn, name, served):
    browser = sp.get("spBrowserSso") or {}
    endpoints = browser.get("ssoServiceEndpoints") or ()
    acs = next((e for e in endpoints if e.get("isDefault")), endpoints[0] if endpoints else {})
    binding, _ = _standard([acs.get("binding")] if acs.get("binding") else [], PF_BINDINGS,
                           values(held, "ciamSamlBinding") if held else ())
    used = linked(held, (certs[fp].dn for fp in (*signing_of(sp, keys), *certs_of(sp)) if fp in certs))
    imported = {"ciamEntityId": (sp.get("entityId"),), "ciamAcsUrl": tuple(filter(None, (acs.get("url"),))),
                "ciamSamlBinding": binding, "ciamUsesCertificate": used}
    entry = _merged(held, dn, name, "saml2-sp", imported, (*OWNED["saml2-sp"], "ciamUsesCertificate"), served)
    mapping = next(iter(browser.get("adapterMappings") or ()), {})
    claims, notices = _claims(d, dn, held, browser.get("attributeContract") or {},
                              mapping.get("attributeContractFulfillment") or {}, user_attrs, f"SP connection {name}")
    rest = _others(d, dn, held, claims)
    return (entry, *claims, *rest), notices


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
                 and not (replaced and (e.norm == claims_base or e.norm.endswith("," + claims_base))))


def _idp(d, idp, certs, held, dn, name, served):
    browser = idp.get("idpBrowserSso") or {}
    jit = ((browser.get("jitProvisioning") or {}).get("userRepository") or {}).get("baseDn")
    used = linked(held, (certs[fp].dn for fp in certs_of(idp) if fp in certs))
    imported = {"ciamEntityId": (idp.get("entityId"),), "ciamJitBaseDn": tuple(filter(None, (jit,))),
                "ciamUsesCertificate": used}
    owned = (*OWNED["saml2-idp"], *(("ciamJitBaseDn",) if jit else ()), "ciamUsesCertificate")
    return (_merged(held, dn, name, "saml2-idp", imported, owned, served), *_others(d, dn, held, ())), ()


def _client(d, client, held, dn, name, served):
    grants, odd_grants = _standard(client.get("grantTypes") or (), PF_GRANTS, values(held, "ciamGrantType") if held else ())
    auth_type = (client.get("clientAuth") or {}).get("type")
    auth, _ = _standard([auth_type] if auth_type else [], PF_AUTH, values(held, "ciamTokenAuthMethod") if held else ())
    imported = {"ciamClientId": (client.get("clientId"),), "ciamRedirectUri": tuple(client.get("redirectUris") or ()),
                "ciamGrantType": grants, "ciamTokenAuthMethod": auth[:1],
                "ciamPkceRequired": ("TRUE",) if client.get("requireProofKeyForCodeExchange") else (),
                "ciamScope": tuple(client.get("restrictedScopes") or ()) if client.get("restrictScopes") else ()}
    entry = _merged(held, dn, name, "oidc-client", imported, OWNED["oidc-client"], served)
    secret = client.get("clientAuth") or {}
    notices = (*((f"client {client.get('clientId')}: grant types with no single standard name, not recorded: "
                  f"{', '.join(odd_grants)}",) if odd_grants else ()),
               *((f"client {client.get('clientId')}: its secret is not imported; each environment binds it",)
                 if secret.get("secret") or secret.get("encryptedSecret") else ()))
    return (entry, *_others(d, dn, held, ())), notices


def integration_groups(d, found, certs):
    """(groups, notices): an integration for every SP connection, IdP connection and OAuth client in the export."""
    user_attrs = attribute_records(d)
    pf_services = identity_services(d, SERVER_ROLES)
    served = pf_services[0] if len(pf_services) == 1 else None
    by_entity = {(one(i, "ciamProtocolType"), one(i, "ciamEntityId")): i for i in integrations(d) if one(i, "ciamEntityId")}
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
    built = tuple(_sp(d, item, certs, keys, user_attrs, held, dn, name, served) if kind == "sp"
                  else _idp(d, item, certs, held, dn, name, served) if kind == "idp"
                  else _client(d, item, held, dn, name, served)
                  for kind, item, held, name, dn in placed)
    return (tuple((dn, entries) for (_, _, _, _, dn), (entries, _) in zip(placed, built)),
            (*(n for _, ns in built for n in ns),
             *(f"new integration {name} ({kind}), not in the record before: give it an owner"
               for kind, _, held, name, _ in placed if held is None)))


# ------------------------------------------------------------------ data stores: checked, not recorded
def _host(hostport):
    return hostport.rsplit(":", 1)[0].lower() if hostport.count(":") == 1 else hostport.lower()


def datastore_notices(d, stores):
    """What the export's data stores say about the directory PingFederate uses, checked against the record."""
    consumers = {norm_dn(one(c, "ciamBindDn")): c for c in children(d, CONSUMERS, "ciamConsumer") if one(c, "ciamBindDn")}
    services = {one(e, "ciamFqdn").lower() for e in d.entries.values() if "ciamServiceName" in e.classes
                and one(e, "ciamFqdn")}
    servers = {one(e, "ciamHostname").lower() for e in d.entries.values() if "ciamServer" in e.classes
               and one(e, "ciamHostname")}

    def ldap(s):
        name, bind = s.get("name") or s.get("id"), s.get("userDN")
        hosts = [_host(h) for h in s.get("hostnames") or ()]
        consumer = consumers.get(norm_dn(bind)) if bind else None
        return (*((f"LDAP data store {name}: binds as consumer {one(consumer, 'cn')}",) if consumer else
                  (f"LDAP data store {name}: binds as {bind}, which no consumer records",) if bind else ()),
                *(f"LDAP data store {name}: reaches directory server {h} by its hostname, not a service name (it "
                  f"changes when servers are replaced or moved)" for h in hosts if h in servers),
                *(f"LDAP data store {name}: reaches {h}, which is neither a service name nor a server in the record"
                  for h in hosts if h not in servers and h not in services),
                *((f"LDAP data store {name}: connects without TLS",) if s.get("useSsl") is False else ()))
    return tuple(n for s in stores for n in (ldap(s) if s.get("type") == "LDAP" else
                                             (f"{s.get('type', 'unknown')} data store {s.get('name') or s.get('id')}: "
                                              f"not recorded yet (PingFederate depth)",)))


# ------------------------------------------------------------------ the importer
def read_export(files, d, patterns, at=None):
    """Imported from a PingFederate bulk export (or this adapter's rendered files)."""
    found, unread, version, unreadable = resources(files)
    certs = certificate_entries(d, found)
    groups, notices = integration_groups(d, found, certs)
    nothing = not any(found.values())
    return Imported(
        containers=tuple(make_entry(b, ("top", "organizationalUnit"), {"ou": (b.split(",", 1)[0].split("=", 1)[1],)})
                         for b in (INTEGRATIONS, CERTIFICATES)),
        groups=(*((c.dn, (c,)) for c in certs.values()), *groups),
        notices=(*((f"exported from PingFederate {version}",) if version else ()), *notices,
                 *datastore_notices(d, found["datastore"]),
                 *((f"not read yet (PingFederate depth): {', '.join(f'{r} ({n})' for r, n in sorted(unread.items()))}",)
                   if unread else ()),
                 *(("where PingFederate keeps OAuth clients, grants and sessions is set in its hivemodule.xml, not the "
                    "Admin API: hold it with opsdir capture",) if found["client"] else ()),
                 *(f"not JSON, not read: {p}" for p in unreadable),
                 *(("no PingFederate configuration found (a bulk export, or pingfederate/*.json)",) if nothing else ())))


BULK = Importer("bulk", "a PingFederate Admin API bulk export (/bulk/export), or this adapter's rendered files",
                read_export)

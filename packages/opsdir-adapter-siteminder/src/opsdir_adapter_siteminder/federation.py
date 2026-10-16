"""SiteMinder's federation partnerships read onto the standard federation domain. Pure.

  CA.FED::SPPartnership   (SiteMinder the identity provider, the partner a service provider) -> a saml2-sp
                          integration: the partner's entity ID, its ACS URL and binding, NameID formats, the claims
                          its assertions carry (each linked to the user-schema record of its attribute), the
                          certificate it is signed with (by fingerprint, when the record holds it)
  CA.FED::IDPPartnership  (SiteMinder the service provider) -> a saml2-idp integration: entity ID, SSO URL, binding
  CA.FED::OIDCClient      -> an oidc-client integration: client ID, redirect URIs, grant types, scopes, how it
                          authenticates (its secret withheld)
Integrations the record holds (matched by entity ID or client ID) keep what it says of them: SiteMinder federating
with them too is a notice. New ones are served by SiteMinder's own identity service: the one whose entity ID is the
partnerships' local entity, else cn=siteminder, made from the local entity (its base URL; the policy servers run it).
The generated runtime objects (CA.SM::SAMLv2SP) are the partnerships' own, not read twice.
"""
from functools import reduce

from opsdir.core.directory import fingerprint, get, make_entry, norm_dn, one, ou_entry, rdn_of, rdn_value
from opsdir.domains.directory.user_schema import attribute_records
from opsdir.domains.federation.naming import INTEGRATIONS
from opsdir.domains.federation.schema import GRANT_TYPES, NAMEID_FORMATS, SAML_BINDINGS, TOKEN_AUTH_METHODS
from opsdir.domains.federation.services import identity_services, integrations
from opsdir.domains.pki.credentials import certificates_by_fingerprint
from .entries import entry, sm_attrs, with_rest
from .naming import POLICY_SERVER, SERVICE, name_of
from .xps import is_true, link_of, name, value_of, values_of

PROTOCOLS = {"sp-partnership": "saml2-sp", "idp-partnership": "saml2-idp", "oidc-client": "oidc-client"}
_BINDING_URN = "urn:oasis:names:tc:SAML:2.0:bindings:"
_SHORT_BINDINGS = {"POST": "HTTP-POST", "REDIRECT": "HTTP-Redirect", "ARTIFACT": "HTTP-Artifact", "SOAP": "SOAP"}


def binding(v):
    """The standard binding a SiteMinder binding value names (a URN, HTTP-POST, POST, ...), or None."""
    short = (v or "").removeprefix(_BINDING_URN)
    return short if short in SAML_BINDINGS else _SHORT_BINDINGS.get(short.upper().removeprefix("HTTP-"))


def nameid(v):
    """The standard NameID format a value names (its URN's last part), or None."""
    last = (v or "").rsplit(":", 1)[-1]
    return last if last in NAMEID_FORMATS else None


def match_key(k, o):
    """What an integration is matched by: (protocol, entity ID) for SAML, the client ID for OIDC."""
    return (PROTOCOLS[k], value_of(o, "remote")) if k != "oidc-client" else ("oidc-client", value_of(o, "client_id"))


def held_integrations(d):
    """{match key: the integration the record holds}."""
    return {**{(one(i, "ciamProtocolType"), one(i, "ciamEntityId")): i for i in integrations(d)
               if one(i, "ciamEntityId")},
            **{("oidc-client", one(i, "ciamClientId")): i for i in integrations(d, "oidc-client")
               if one(i, "ciamClientId")}}


def local_entities(x, partnerships):
    """The local entity IDs of the SAML partnerships, each once."""
    return tuple(dict.fromkeys(value_of(o, "local") for o in partnerships if value_of(o, "local")))


def service_for(d, x, partnerships):
    """(the identity service new integrations are served by or None, its entry when the import makes it or None,
    notices)."""
    locals_ = local_entities(x, partnerships)
    known = next((s for s in identity_services(d) if one(s, "ciamEntityId") in locals_), None)
    if known is not None and norm_dn(known.dn) != norm_dn(SERVICE):
        return known.dn, None, ()
    if not locals_:
        return None, None, ()
    base = next((value_of(o, "base_url") for o in partnerships if value_of(o, "base_url")), None)
    old = get(d, SERVICE)
    if base is None and old is None:
        return None, None, ((f"SiteMinder's local entity {locals_[0]}: no base URL in the export, so no identity "
                             "service is made for it; the new integrations are served by none until one is "
                             "recorded (ciamServedBy)"),)
    owned = {"cn": ("siteminder",), "ciamBaseUrl": (base or one(old, "ciamBaseUrl"),), "ciamEntityId": (locals_[0],),
             **({} if old is not None and one(old, "ciamTargetRole") else {"ciamTargetRole": (POLICY_SERVER,)})}
    more = tuple(f"SiteMinder's local entity {e} is another identity service: only {locals_[0]} is recorded"
                 for e in locals_[1:])
    return SERVICE, entry(d, SERVICE, ("top", "ciamIdentityService"), owned), more


def place(d, objects):
    """({XID: (integration DN,)} for every partnership and client ((kind, object), ...), {XID: the integration the
    record holds}): a held one keeps its DN, a new one is named after the partnership (unique among integrations)."""
    held = held_integrations(d)
    names = {rdn_value(i).lower() for i in integrations(d)}

    def step(acc, ko):
        k, o = ko
        found = held.get(match_key(k, o))
        if found is not None:
            return {**acc, o.xid: (found.dn,)}
        used = names | {rdn_of(v[0]).lower() for v in acc.values()}
        base = name_of(name(o)) or "partner"
        n = next(c for c in (base, *(f"{base}-{i}" for i in range(2, 1000))) if c.lower() not in used)
        return {**acc, o.xid: (f"cn={n},{INTEGRATIONS}",)}
    return reduce(step, objects, {}), {o.xid: held[match_key(k, o)] for k, o in objects if match_key(k, o) in held}


def _claims(d, x, o, dn, user_attrs):
    """(claim entries, notices) of an SP partnership's assertion attributes ("<claim>=<user attribute>")."""
    pairs = tuple(v.split("=", 1) for v in values_of(o, "attributes") if "=" in v)
    placed = tuple((c.strip(), user_attrs.get(a.strip().lower())) for c, a in pairs)
    base = f"ou=claims,{dn}"
    entries = tuple(make_entry(f"cn={c},{base}", ("top", "ciamClaimMap"),
                               {"cn": (c,), "ciamClaimName": (c,), "ciamSourceAttribute": (attr.dn,)})
                    for c, attr in placed if attr is not None and name_of(c) == c.lower() and c)
    missing = tuple(f"{c} ({a.strip()})" for (c, attr), (_, a) in zip(placed, pairs) if attr is None)
    return ((ou_entry(base), *entries) if entries else ()), \
        ((f"partnership {name(o)}: claims from attributes the record has no user-schema record for, not recorded: "
          f"{', '.join(missing)}",) if missing else ())


def _certificate(x, o, certs):
    """(certificate DNs, notices): the certificate a partnership names, when the record holds it."""
    cert = x.objects.get(link_of(o, "certificate"))
    if cert is None:
        return (), ()
    fp = fingerprint(value_of(cert, "fingerprint"))
    if fp in certs:
        return (certs[fp].dn,), ()
    return (), (f"partnership {name(o)}: its certificate {value_of(cert, 'alias') or cert.xid} isn't in the record "
                "(certificates are recorded as facts, never their keys): record it, then link it",)


def _owned(k, o, x, certs):
    if k == "sp-partnership":
        used, notices = _certificate(x, o, certs)
        return {"ciamEntityId": (value_of(o, "remote"),), "ciamAcsUrl": (value_of(o, "acs"),),
                "ciamSamlBinding": (binding(value_of(o, "binding")),),
                "ciamNameIdFormat": tuple(filter(None, map(nameid, values_of(o, "nameid")))) or (None,),
                "ciamUsesCertificate": used or (None,)}, notices
    if k == "idp-partnership":
        used, notices = _certificate(x, o, certs)
        return {"ciamEntityId": (value_of(o, "remote"),), "ciamSsoUrl": (value_of(o, "sso"),),
                "ciamSamlBinding": (binding(value_of(o, "binding")),),
                "ciamNameIdFormat": tuple(filter(None, map(nameid, values_of(o, "nameid")))) or (None,),
                "ciamUsesCertificate": used or (None,)}, notices
    return {"ciamClientId": (value_of(o, "client_id"),), "ciamRedirectUri": values_of(o, "redirects") or (None,),
            "ciamGrantType": tuple(g for g in values_of(o, "grants") if g in GRANT_TYPES) or (None,),
            "ciamScope": values_of(o, "scopes") or (None,),
            "ciamTokenAuthMethod": tuple(m for m in values_of(o, "auth") if m in TOKEN_AUTH_METHODS) or (None,)}, ()


def _served_by(d, i):
    service = get(d, one(i, "ciamServedBy")) if one(i, "ciamServedBy") else None
    return rdn_value(service) if service is not None else "every identity service"


def _integration(d, x, k, o, held, served, certs, user_attrs):
    """(group, notices) for one partnership or client."""
    dn = x.placed[o.xid][0]
    label = f"{'client' if k == 'oidc-client' else 'partnership'} {name(o)}"
    inactive = (f"{label}: inactive in SiteMinder",) if value_of(o, "active") is not None \
        and not is_true(value_of(o, "active")) else ()
    if o.xid in held:
        kept = entry(d, dn, ("top", "ciamIntegration", "smObject"), sm_attrs(x, o))
        return with_rest(d, dn, (kept,)), (*inactive, f"{label}: SiteMinder federates with integration "
                                           f"{rdn_value(held[o.xid])}, which the record already holds (served by "
                                           f"{_served_by(d, held[o.xid])}): kept as it is")
    owned, more = _owned(k, o, x, certs)
    claims, claim_notices = _claims(d, x, o, dn, user_attrs) if k == "sp-partnership" else ((), ())
    made = entry(d, dn, ("top", "ciamIntegration", "smObject"),
                 {"cn": (rdn_of(dn),), "ciamProtocolType": (PROTOCOLS[k],), **owned, "ciamServedBy": (served,),
                  **sm_attrs(x, o)})
    return with_rest(d, dn, (made, *claims)), \
        (*inactive, *more, *claim_notices,
         f"new integration {rdn_of(dn)} ({PROTOCOLS[k]}), not in the record before: give it an owner")


def integration_groups(d, x, objects, held, served):
    """(groups, notices): an integration for every partnership and client ((kind, object), ...), the record's own
    kept as they are."""
    certs, user_attrs = certificates_by_fingerprint(d), attribute_records(d)
    built = tuple(_integration(d, x, k, o, held, served, certs, user_attrs) for k, o in objects)
    return tuple(g for g, _ in built), tuple(n for _, ns in built for n in ns)

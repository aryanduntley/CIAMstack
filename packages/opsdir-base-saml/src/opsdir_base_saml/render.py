"""SAML 2.0 metadata rendered from the federation domain, environment-neutral:

  saml/sp/<integration>.xml           each SAML service provider we federate with, as the record describes it
  saml/partner-idp/<integration>.xml  each partner identity provider, as the record describes it
  saml/idp/<service>.xml              the platform's own identity provider(s), at the product's endpoint paths

The first two are the partners' contracts in the standard's form (importable into any SAML product); the last is
what partners are given. A product adapter supplies its endpoint paths (SamlEndpoints) and which services it serves.
"""
from typing import NamedTuple

from opsdir.core.directory import get, one, rdn_value, values
from opsdir.domains.federation.services import claims, endpoint, integrations_served
from .metadata import DEFAULT_ACS_BINDING, DEFAULT_SSO_BINDING, idp_descriptor, sp_descriptor
from .xmltext import document

FORMATS = (("saml/*.xml", "xml"),)        # the format of every file saml_files renders
# A product's SAML endpoints: ((binding, path under the service's base URL), ...)
SamlEndpoints = NamedTuple("SamlEndpoints", [("sso", tuple), ("slo", tuple)])


def certificates(d, e):
    """(name, key role, SHA-256 fingerprint) of every certificate an entry uses."""
    return tuple((rdn_value(c), one(c, "ciamKeyRole"), one(c, "ciamFingerprint"))
                 for c in (get(d, dn) for dn in values(e, "ciamUsesCertificate")))


def sp_metadata(d, i):
    return document(sp_descriptor(one(i, "ciamEntityId"),
                                  ((one(i, "ciamSamlBinding", DEFAULT_ACS_BINDING), one(i, "ciamAcsUrl")),),
                                  values(i, "ciamNameIdFormat"), tuple(name for name, _, _ in claims(d, i)),
                                  certificates(d, i), rdn_value(i)))


def partner_idp_metadata(d, i):
    sso = ((one(i, "ciamSamlBinding", DEFAULT_SSO_BINDING), one(i, "ciamSsoUrl")),) if one(i, "ciamSsoUrl") else ()
    return document(idp_descriptor(one(i, "ciamEntityId"), sso, (), values(i, "ciamNameIdFormat"), certificates(d, i)))


def _at(service, paths):
    return tuple((binding, endpoint(service, path)) for binding, path in paths)


def idp_metadata(d, service, endpoints):
    return document(idp_descriptor(one(service, "ciamEntityId"), _at(service, endpoints.sso),
                                   _at(service, endpoints.slo), values(service, "ciamNameIdFormat"),
                                   certificates(d, service)))


def saml_files(d, services, endpoints):
    """{path: XML text} for every SAML partner the given identity services serve and each of them with an entity
    ID."""
    return {**{f"saml/sp/{rdn_value(i)}.xml": sp_metadata(d, i) for i in integrations_served(d, services, "saml2-sp")},
            **{f"saml/partner-idp/{rdn_value(i)}.xml": partner_idp_metadata(d, i)
               for i in integrations_served(d, services, "saml2-idp")},
            **{f"saml/idp/{rdn_value(s)}.xml": idp_metadata(d, s, endpoints)
               for s in services if one(s, "ciamEntityId")}}

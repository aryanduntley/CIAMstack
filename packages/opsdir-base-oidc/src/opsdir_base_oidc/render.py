"""OpenID Connect documents rendered from the federation domain, environment-neutral:

  oidc/clients/<integration>.json    each recorded OIDC client's registration metadata (RFC 7591)
  oidc/discovery/<service>.json      each given identity service's provider metadata (the document it serves at
                                     /.well-known/openid-configuration), at the product's endpoint paths

A product adapter supplies its endpoint paths (OidcEndpoints) and which services it serves.
"""

from opsdir.core.directory import one, rdn_value
from opsdir.core.jsondata import indented
from opsdir.domains.federation.services import integrations_served, serves
from .discovery import discovery_document
from .registration import client_metadata


FORMATS = (("oidc/*.json", "json"),)       # the format of every file oidc_files renders


def oidc_files(d, services, endpoints):
    """{path: JSON text}: every OIDC client the given identity services serve, and each of them that has an issuer
    (its discovery document reflects the clients it serves)."""
    clients = integrations_served(d, services, "oidc-client")
    return {**{f"oidc/clients/{rdn_value(i)}.json": indented(client_metadata(i)) for i in clients},
            **{f"oidc/discovery/{rdn_value(s)}.json":
               indented(discovery_document(d, s, endpoints, tuple(c for c in clients if serves(s, c))))
               for s in services if one(s, "ciamOidcIssuer")}}

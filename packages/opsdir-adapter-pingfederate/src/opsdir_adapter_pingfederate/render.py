"""PingFederate adapter: render PingFederate's configuration for each environment, and, on the SAML and OIDC bases,
the standard documents at PingFederate's endpoint paths (environment-neutral).

  saml/, oidc/              standard metadata, client registrations and discovery (opsdir-base-saml, -oidc), neutral
  pingfederate/admin-api/requests.json
                            per environment: every object the record holds for PingFederate as Admin API requests in
                            the order PingFederate needs them, checked against the spec of the environment's version
                            (opsdir_adapter_pingfederate.admin_api)
  pingfederate/terraform/*.tf
                            per environment: the same configuration as Terraform for Ping's pingidentity/pingfederate
                            provider, pinned by the environment's version (opsdir_adapter_pingfederate.terraform_target)
  pingfederate/cluster/jgroups.properties
                            per environment: the nodes' discovery lines from its pf-cluster-discovery binding

Endpoint paths are PingFederate's defaults.
"""
from opsdir.core.contract import Endpoint
from opsdir.domains.federation.services import identity_services
from opsdir_base_oidc.discovery import OidcEndpoints
from opsdir_base_oidc.render import oidc_files
from opsdir_base_saml.render import SamlEndpoints, saml_files
from .admin_api import admin_api_files
from .discovery import discovery_file
from .terraform_target import terraform_files, terraform_import_files
from .naming import SERVER_ROLES

SAML_ENDPOINTS = SamlEndpoints(sso=(("HTTP-Redirect", "/idp/SSO.saml2"), ("HTTP-POST", "/idp/SSO.saml2")),
                               slo=(("HTTP-Redirect", "/idp/SLO.saml2"), ("HTTP-POST", "/idp/SLO.saml2")))
OIDC_ENDPOINTS = OidcEndpoints(authorization="/as/authorization.oauth2", token="/as/token.oauth2",
                               userinfo="/idp/userinfo.openid", jwks="/pf/JWKS", end_session="/idp/startSLO.ping")
# What the edge treats specially (contract.Endpoint): sign-in and token from the endpoints above, SAML posts (the IdP's
# and, as a service provider, its assertion consumer), self-service password reset, and the heartbeat
ENDPOINTS = tuple(Endpoint(kind, path, "pf-engine") for kind, path in (
    ("login", OIDC_ENDPOINTS.authorization), *(("login", p) for b, p in SAML_ENDPOINTS.sso if b == "HTTP-Redirect"),
    ("token", OIDC_ENDPOINTS.token), *(("saml-post", p) for b, p in SAML_ENDPOINTS.sso if b == "HTTP-POST"),
    ("saml-post", "/sp/ACS.saml2"), ("password-reset", "/ext/pwdreset/*"), ("health", "/pf/heartbeat.ping")))


def render_neutral(d):
    """The standard SAML and OIDC documents for the services PingFederate serves."""
    served = identity_services(d, SERVER_ROLES)
    return {**saml_files(d, served, SAML_ENDPOINTS), **oidc_files(d, served, OIDC_ENDPOINTS)}


# what an operator may choose to render (`opsdir render --target pingfederate=...`): admin-api and terraform by
# default; terraform-imports only when asked (it adopts what an existing PingFederate holds, and fails on a fresh one)
TARGETS = (("admin-api", "Admin API requests checked against the version's spec (pingfederate/admin-api/)"),
           ("terraform", "Terraform for the pingidentity/pingfederate provider (pingfederate/terraform/)"),
           ("terraform-imports", "import blocks adopting the objects an existing PingFederate already holds "
                                 "(pingfederate/terraform/imports.tf; with terraform)", False))


def render_env(m, services, targets=tuple(t[0] for t in TARGETS if len(t) < 3)):
    """PingFederate's configuration for environment m in the render targets chosen: as Admin API requests and/or as
    Terraform (with that environment's hosts and secret references), with import blocks adopting an existing
    PingFederate's objects when asked, and its cluster's discovery."""
    if "terraform-imports" in targets and "terraform" not in targets:
        raise SystemExit("pingfederate=terraform-imports adopts what the terraform target renders: choose both")
    return {**(admin_api_files(m) if "admin-api" in targets else {}),
            **(terraform_files(m) if "terraform" in targets else {}),
            **(terraform_import_files(m) if "terraform-imports" in targets else {}), **discovery_file(m)}

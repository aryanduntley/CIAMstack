"""Federation domain: vendor-neutral SAML/OIDC integrations (SP connections, OIDC clients, partner IdPs) and
the claim mappings they release. Product adapters render and import it."""
from ...core.contract import Domain
from .schema import FRAGMENT

DOMAIN = Domain(name="federation", schema=FRAGMENT, required_roles=(), sql=(), reports={}, checks=(), order=30,
                vocabulary={})

"""Federation domain: vendor-neutral SAML/OIDC integrations (SP connections, OIDC clients, partner IdPs) and
the claim mappings they release. Product adapters (e.g. PingFederate) render and import it."""
from ...core.contract import Domain
from ...core.naming import branch
from .schema import FRAGMENT

INTEGRATIONS = branch("integrations")

DOMAIN = Domain(name="federation", schema=FRAGMENT, required_roles=(), sql=(), reports={})
